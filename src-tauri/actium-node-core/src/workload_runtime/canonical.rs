use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use std::collections::{BTreeMap, HashSet};
use super::WorkloadError;

pub const DOMAIN_DESIRED_STATE: &[u8] = b"ACTIUM_WORKLOAD_DESIRED_STATE_V1\0";
pub const DOMAIN_RECEIPT: &[u8] = b"ACTIUM_WORKLOAD_RECEIPT_V1\0";
pub const DOMAIN_RUNTIME_INSTANCE: &[u8] = b"ACTIUM_WORKLOAD_RUNTIME_INSTANCE_V1\0";
pub const DOMAIN_COMPOSE_PROJECT: &[u8] = b"ACTIUM_WORKLOAD_COMPOSE_PROJECT_V1\0";

/// Computes raw SHA-256 over bytes.
pub fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Formats raw 32-byte digest as `sha256:<64 lowercase hex>`.
pub fn format_sha256_hex(digest: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:02x}", byte);
    }
    hex
}

/// Computes formatted `sha256:<64 hex>` string from bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    format_sha256_hex(&sha256_raw(data))
}

/// Parses a `sha256:<64 hex>` string into a raw 32-byte array.
pub fn parse_sha256_hex(digest_str: &str) -> Result<[u8; 32], WorkloadError> {
    let hex_part = digest_str
        .strip_prefix("sha256:")
        .ok_or_else(|| WorkloadError::InvalidDigestFormat(format!("Missing 'sha256:' prefix in '{}'", digest_str)))?;

    if hex_part.len() != 64 {
        return Err(WorkloadError::InvalidDigestFormat(format!(
            "Expected 64 hex characters, got {} in '{}'",
            hex_part.len(),
            digest_str
        )));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex_part.as_bytes().chunks_exact(2).enumerate() {
        let h1 = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| WorkloadError::InvalidDigestFormat(format!("Invalid hex character in '{}'", digest_str)))?;
        let h2 = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| WorkloadError::InvalidDigestFormat(format!("Invalid hex character in '{}'", digest_str)))?;
        bytes[i] = ((h1 << 4) | h2) as u8;
    }
    Ok(bytes)
}

/// Constant-time comparison of two `sha256:<hex>` strings over their 32-byte binary representation.
pub fn constant_time_digest_eq(left: &str, right: &str) -> Result<bool, WorkloadError> {
    let left_bytes = parse_sha256_hex(left)?;
    let right_bytes = parse_sha256_hex(right)?;
    Ok(left_bytes.ct_eq(&right_bytes).into())
}

/// Canonical JSON serialization conforming strictly to RFC 8785 / JCS.
pub fn rfc8785_canonical_json(value: &Value) -> Result<String, WorkloadError> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true".to_string() } else { "false".to_string() }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.to_string())
            } else if let Some(u) = n.as_u64() {
                Ok(u.to_string())
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(WorkloadError::SerializationError("Infinite or NaN float not allowed in JCS".into()));
                }
                let s = serde_json::to_string(n)
                    .map_err(|e| WorkloadError::SerializationError(format!("Failed to format number: {}", e)))?;
                Ok(s)
            } else {
                Err(WorkloadError::SerializationError("Invalid JSON number".into()))
            }
        }
        Value::String(s) => serde_json::to_string(s)
            .map_err(|e| WorkloadError::SerializationError(format!("String escaping error: {}", e))),
        Value::Array(items) => {
            let mut out = String::from("[");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&rfc8785_canonical_json(item)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::Object(map) => {
            let sorted_map: BTreeMap<&String, &Value> = map.iter().collect();
            let mut out = String::from("{");
            for (idx, (k, v)) in sorted_map.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                let escaped_key = serde_json::to_string(k)
                    .map_err(|e| WorkloadError::SerializationError(format!("Key escaping error: {}", e)))?;
                out.push_str(&escaped_key);
                out.push(':');
                out.push_str(&rfc8785_canonical_json(v)?);
            }
            out.push('}');
            Ok(out)
        }
    }
}

/// Normalizes a JSON Value semantically prior to canonical serialization:
/// - Sorts arrays of named entities by their unique identifiers.
/// - Validates that no duplicate identifiers exist (fail-closed).
/// - Preserves executionOrder untouched (while checking for duplicates).
pub fn semantic_normalize_value(value: &mut Value) -> Result<(), WorkloadError> {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k == "modules" {
                    if let Value::Array(items) = v {
                        normalize_keyed_array(items, "moduleId", "module")?;
                    }
                } else if k == "secretRefs" {
                    if let Value::Array(items) = v {
                        normalize_secret_refs_array(items)?;
                    }
                } else if k == "volumeClaims" || k == "volumes" {
                    if let Value::Array(items) = v {
                        normalize_keyed_array(items, "volumeId", "volume")?;
                    }
                } else if k == "networkPolicies" || k == "networks" {
                    if let Value::Array(items) = v {
                        normalize_keyed_array(items, "networkId", "network")?;
                    }
                } else if k == "components" {
                    if let Value::Array(items) = v {
                        normalize_keyed_array(items, "componentId", "component")?;
                    }
                } else if k == "executionOrder" {
                    if let Value::Array(items) = v {
                        let mut seen = HashSet::new();
                        for item in items.iter() {
                            if let Value::String(id) = item {
                                if !seen.insert(id.clone()) {
                                    return Err(WorkloadError::DuplicateIdentifierRejected {
                                        entity_type: "executionOrder",
                                        identifier: id.clone(),
                                    });
                                }
                            }
                        }
                    }
                } else {
                    semantic_normalize_value(v)?;
                }
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                semantic_normalize_value(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn normalize_keyed_array(items: &mut Vec<Value>, key_name: &str, entity_type: &'static str) -> Result<(), WorkloadError> {
    let mut seen = HashSet::new();
    for item in items.iter() {
        if let Some(val) = item.get(key_name).and_then(|v| v.as_str()) {
            if !seen.insert(val.to_string()) {
                return Err(WorkloadError::DuplicateIdentifierRejected {
                    entity_type,
                    identifier: val.to_string(),
                });
            }
        }
    }
    items.sort_by(|a, b| {
        let ka = a.get(key_name).and_then(|v| v.as_str()).unwrap_or("");
        let kb = b.get(key_name).and_then(|v| v.as_str()).unwrap_or("");
        ka.cmp(kb)
    });
    for item in items.iter_mut() {
        semantic_normalize_value(item)?;
    }
    Ok(())
}

fn normalize_secret_refs_array(items: &mut Vec<Value>) -> Result<(), WorkloadError> {
    let mut seen = HashSet::new();
    for item in items.iter() {
        let secret_id = item.get("secretId").and_then(|v| v.as_str()).unwrap_or("");
        let purpose = item.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
        let compound = format!("{}:{}", secret_id, purpose);
        if !seen.insert(compound) {
            return Err(WorkloadError::DuplicateIdentifierRejected {
                entity_type: "secretRef",
                identifier: format!("{}:{}", secret_id, purpose),
            });
        }
    }
    items.sort_by(|a, b| {
        let ida = a.get("secretId").and_then(|v| v.as_str()).unwrap_or("");
        let idb = b.get("secretId").and_then(|v| v.as_str()).unwrap_or("");
        let cmp_id = ida.cmp(idb);
        if cmp_id != std::cmp::Ordering::Equal {
            return cmp_id;
        }
        let pa = a.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
        let pb = b.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
        let cmp_p = pa.cmp(pb);
        if cmp_p != std::cmp::Ordering::Equal {
            return cmp_p;
        }
        let ga = a.get("generation").and_then(|v| v.as_u64()).unwrap_or(0);
        let gb = b.get("generation").and_then(|v| v.as_u64()).unwrap_or(0);
        ga.cmp(&gb)
    });
    for item in items.iter_mut() {
        semantic_normalize_value(item)?;
    }
    Ok(())
}

/// Normalizes AST and calculates JCS canonical digest.
pub fn canonical_digest_for_value(value: &Value) -> Result<String, WorkloadError> {
    let mut normalized = value.clone();
    semantic_normalize_value(&mut normalized)?;
    let jcs = rfc8785_canonical_json(&normalized)?;
    Ok(sha256_hex(jcs.as_bytes()))
}

/// Computes domain-separated hash: `sha256(domain || jcs_payload)`.
pub fn domain_separated_hash(domain: &[u8], payload_jcs: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload_jcs.as_bytes());
    let raw: [u8; 32] = hasher.finalize().into();
    format_sha256_hex(&raw)
}

/// Derives a deterministic runtime instance ID with 128-bit collision resistance:
/// `actium-<32 lowercase hex>` derived from domain `ACTIUM_WORKLOAD_RUNTIME_INSTANCE_V1\0`.
pub fn deterministic_runtime_instance_id(deployment_id: &str, generation: u64, component_id: &str) -> Result<String, WorkloadError> {
    let obj = serde_json::json!({
        "componentId": component_id,
        "deploymentId": deployment_id,
        "generation": generation,
    });
    let jcs = rfc8785_canonical_json(&obj)?;
    let hash = domain_separated_hash(DOMAIN_RUNTIME_INSTANCE, &jcs);
    let hex_part = hash.strip_prefix("sha256:").unwrap_or(&hash);
    Ok(format!("actium-{}", &hex_part[..32]))
}

/// Derives a deterministic compose project ID with 128-bit collision resistance:
/// `actium-<32 lowercase hex>` derived from domain `ACTIUM_WORKLOAD_COMPOSE_PROJECT_V1\0`.
pub fn deterministic_compose_project_id(deployment_id: &str, generation: u64) -> Result<String, WorkloadError> {
    let obj = serde_json::json!({
        "deploymentId": deployment_id,
        "generation": generation,
    });
    let jcs = rfc8785_canonical_json(&obj)?;
    let hash = domain_separated_hash(DOMAIN_COMPOSE_PROJECT, &jcs);
    let hex_part = hash.strip_prefix("sha256:").unwrap_or(&hash);
    Ok(format!("actium-{}", &hex_part[..32]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc8785_canonical_json_against_shared_vectors() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let vectors_path = std::path::Path::new(manifest_dir)
            .join("../../contracts/workload/v1/workload-digest-vectors.v1.json");
        let embedded = include_str!("../../../../contracts/workload/v1/workload-digest-vectors.v1.json");
        let content = std::fs::read_to_string(&vectors_path)
            .unwrap_or_else(|_| embedded.to_string());

        let root: Value = serde_json::from_str(&content).expect("Valid JSON vectors");
        let vectors = root.get("vectors").and_then(|v| v.as_array()).expect("Vectors array");

        for vec in vectors {
            let id = vec.get("id").and_then(|v| v.as_str()).unwrap();
            if let Some(raw_input) = vec.get("rawInput") {
                let expected_jcs = vec.get("canonicalJcs").and_then(|v| v.as_str()).unwrap();
                let expected_digest = vec.get("expectedDigest").and_then(|v| v.as_str()).unwrap();

                let mut norm = raw_input.clone();
                semantic_normalize_value(&mut norm).unwrap();
                let computed_jcs = rfc8785_canonical_json(&norm).unwrap();
                assert_eq!(computed_jcs, expected_jcs, "JCS mismatch for vector '{}'", id);

                let computed_digest = sha256_hex(computed_jcs.as_bytes());
                assert_eq!(computed_digest, expected_digest, "Digest mismatch for vector '{}'", id);
            } else if id == "domain_separated_desired_state" {
                let expected_digest = vec.get("expectedDigest").and_then(|v| v.as_str()).unwrap();
                let payload = vec.get("payloadJcs").and_then(|v| v.as_str()).unwrap();
                let computed = domain_separated_hash(DOMAIN_DESIRED_STATE, payload);
                assert_eq!(computed, expected_digest);
            } else if id == "domain_separated_receipt" {
                let expected_digest = vec.get("expectedDigest").and_then(|v| v.as_str()).unwrap();
                let payload = vec.get("payloadJcs").and_then(|v| v.as_str()).unwrap();
                let computed = domain_separated_hash(DOMAIN_RECEIPT, payload);
                assert_eq!(computed, expected_digest);
            } else if id == "deterministic_runtime_ids" {
                let inst_id = deterministic_runtime_instance_id("dep-1", 1, "api").unwrap();
                assert_eq!(inst_id, "actium-58f17e744b54a8e18d01d295f21bbd07");
                assert_eq!(inst_id.len(), 39); // "actium-" (7) + 32 hex = 39

                let proj_id = deterministic_compose_project_id("dep-1", 1).unwrap();
                assert_eq!(proj_id, "actium-8bf74133d31cd41cd91dbfde48f51fc2");
                assert_eq!(proj_id.len(), 39);
            }
        }
    }

    #[test]
    fn test_semantic_normalization_rejects_duplicates() {
        // Duplicate moduleId
        let mut dup_modules = serde_json::json!({
            "modules": [
                { "moduleId": "auth" },
                { "moduleId": "auth" }
            ]
        });
        match semantic_normalize_value(&mut dup_modules) {
            Err(WorkloadError::DuplicateIdentifierRejected { entity_type, identifier }) => {
                assert_eq!(entity_type, "module");
                assert_eq!(identifier, "auth");
            }
            other => panic!("Expected DuplicateIdentifierRejected, got {:?}", other),
        }

        // Duplicate secretRef (same secretId and purpose)
        let mut dup_secrets = serde_json::json!({
            "secretRefs": [
                { "secretId": "sec.1", "purpose": "env" },
                { "secretId": "sec.1", "purpose": "env" }
            ]
        });
        match semantic_normalize_value(&mut dup_secrets) {
            Err(WorkloadError::DuplicateIdentifierRejected { entity_type, identifier }) => {
                assert_eq!(entity_type, "secretRef");
                assert_eq!(identifier, "sec.1:env");
            }
            other => panic!("Expected DuplicateIdentifierRejected, got {:?}", other),
        }

        // Duplicate volumeId
        let mut dup_vols = serde_json::json!({
            "volumeClaims": [
                { "volumeId": "vol.1" },
                { "volumeId": "vol.1" }
            ]
        });
        match semantic_normalize_value(&mut dup_vols) {
            Err(WorkloadError::DuplicateIdentifierRejected { entity_type, identifier }) => {
                assert_eq!(entity_type, "volume");
                assert_eq!(identifier, "vol.1");
            }
            other => panic!("Expected DuplicateIdentifierRejected, got {:?}", other),
        }

        // Duplicate componentId
        let mut dup_comp = serde_json::json!({
            "components": [
                { "componentId": "c1" },
                { "componentId": "c1" }
            ]
        });
        match semantic_normalize_value(&mut dup_comp) {
            Err(WorkloadError::DuplicateIdentifierRejected { entity_type, identifier }) => {
                assert_eq!(entity_type, "component");
                assert_eq!(identifier, "c1");
            }
            other => panic!("Expected DuplicateIdentifierRejected, got {:?}", other),
        }

        // Duplicate executionOrder
        let mut dup_exec = serde_json::json!({
            "executionOrder": ["c1", "c2", "c1"]
        });
        match semantic_normalize_value(&mut dup_exec) {
            Err(WorkloadError::DuplicateIdentifierRejected { entity_type, identifier }) => {
                assert_eq!(entity_type, "executionOrder");
                assert_eq!(identifier, "c1");
            }
            other => panic!("Expected DuplicateIdentifierRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_constant_time_raw_32_byte_digest_matching() {
        let d1 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let d2 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let d3 = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856";

        assert!(constant_time_digest_eq(d1, d2).unwrap());
        assert!(!constant_time_digest_eq(d1, d3).unwrap());

        // Invalid format
        assert!(constant_time_digest_eq("md5:123", d1).is_err());
        assert!(constant_time_digest_eq("sha256:short", d1).is_err());
        assert!(constant_time_digest_eq("sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", d1).is_err());
    }
}
