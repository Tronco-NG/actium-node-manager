use rusqlite::{params, Connection};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::canonical::{canonical_digest_for_value, constant_time_digest_eq};
use super::WorkloadError;
use crate::workload::profile_json_has_inline_secret_values;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadProfileRecord {
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub schema_version: String,
    pub manifest_json: String,
    pub created_at: u64, // Unix epoch milliseconds UTC
}

pub const WORKLOAD_PROFILE_SCHEMA_STR: &str = include_str!("../../../../contracts/workload/v1/actium-workload-profile.schema.json");

static PROFILE_SCHEMA_VALIDATOR: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();

/// Validates a workload profile manifest against the canonical actium-workload-profile@1.0.0 JSON Schema.
pub fn validate_profile_manifest_schema(parsed: &Value) -> Result<(), WorkloadError> {
    let validator = PROFILE_SCHEMA_VALIDATOR.get_or_init(|| {
        let schema_val: Value = serde_json::from_str(WORKLOAD_PROFILE_SCHEMA_STR)
            .expect("Invalid embedded actium-workload-profile.schema.json");
        jsonschema::validator_for(&schema_val)
            .expect("Failed to compile actium-workload-profile JSON schema")
    });

    let mut errors = validator.iter_errors(parsed);
    if let Some(err) = errors.next() {
        return Err(WorkloadError::ValidationFailed(format!(
            "Profile manifest violates canonical JSON schema: {} at {}",
            err, err.instance_path()
        )));
    }

    // Additional cross-field semantic invariants
    if let Some(components) = parsed.get("components").and_then(|v| v.as_array()) {
        for comp in components {
            let cid = comp.get("componentId").and_then(|v| v.as_str()).unwrap_or("");
            // Pinned image digest parity check: if image contains @sha256:..., it must match imageDigest
            let img = comp.get("image").and_then(|v| v.as_str()).unwrap_or("");
            let digest = comp.get("imageDigest").and_then(|v| v.as_str()).unwrap_or("");
            if let Some((_, img_hash)) = img.split_once("@sha256:") {
                let full_expected = format!("sha256:{}", img_hash);
                if full_expected != digest {
                    return Err(WorkloadError::ValidationFailed(format!(
                        "Component '{}' image tag digest '{}' conflicts with imageDigest '{}'",
                        cid, full_expected, digest
                    )));
                }
            }
        }
    }

    Ok(())
}

pub struct WorkloadProfileRegistry {
    conn: Mutex<Connection>,
}

impl WorkloadProfileRegistry {
    pub fn new(conn: Connection) -> Result<Self, WorkloadError> {
        let registry = Self {
            conn: Mutex::new(conn),
        };
        registry.init_schema()?;
        Ok(registry)
    }

    pub fn open(path: &std::path::Path) -> Result<Self, WorkloadError> {
        let conn = Connection::open(path)
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to open SQLite profile registry at {:?}: {}", path, e)))?;
        
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;"
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to configure SQLite pragmas: {}", e)))?;

        Self::new(conn)
    }

    pub fn in_memory() -> Result<Self, WorkloadError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to open in-memory SQLite: {}", e)))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;"
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to configure SQLite pragmas: {}", e)))?;
        Self::new(conn)
    }

    fn init_schema(&self) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS workload_profiles (
                profile_id TEXT NOT NULL,
                profile_version TEXT NOT NULL,
                profile_digest TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (profile_id, profile_version)
            )",
            [],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to initialize workload_profiles table: {}", e)))?;
        Ok(())
    }

    pub fn register_profile(&self, manifest_json: &str) -> Result<WorkloadProfileRecord, WorkloadError> {
        if profile_json_has_inline_secret_values(manifest_json) {
            return Err(WorkloadError::ValidationFailed("Inline secret values detected in profile manifest".into()));
        }

        let parsed: Value = serde_json::from_str(manifest_json)
            .map_err(|e| WorkloadError::ValidationFailed(format!("Invalid profile JSON: {}", e)))?;

        validate_profile_manifest_schema(&parsed)?;

        let schema = parsed.get("schema")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let profile_id = parsed.get("profileId")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let profile_version = parsed.get("profileVersion")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        let computed_digest = canonical_digest_for_value(&parsed)?;

        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT profile_digest, schema_version, manifest_json, created_at
             FROM workload_profiles
             WHERE profile_id = ?1 AND profile_version = ?2"
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let existing = stmt.query_row(
            params![&profile_id, &profile_version],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            }
        );

        match existing {
            Ok((existing_digest, schema_ver, manifest, created_at)) => {
                if constant_time_digest_eq(&existing_digest, &computed_digest)? {
                    Ok(WorkloadProfileRecord {
                        profile_id,
                        profile_version,
                        profile_digest: existing_digest,
                        schema_version: schema_ver,
                        manifest_json: manifest,
                        created_at,
                    })
                } else {
                    Err(WorkloadError::ProfileVersionDigestConflict {
                        profile_id,
                        profile_version,
                        existing_digest,
                        new_digest: computed_digest,
                    })
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                conn.execute(
                    "INSERT INTO workload_profiles (profile_id, profile_version, profile_digest, schema_version, manifest_json, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        &profile_id,
                        &profile_version,
                        &computed_digest,
                        schema,
                        manifest_json,
                        now,
                    ],
                ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to insert profile record: {}", e)))?;

                Ok(WorkloadProfileRecord {
                    profile_id,
                    profile_version,
                    profile_digest: computed_digest,
                    schema_version: schema.to_string(),
                    manifest_json: manifest_json.to_string(),
                    created_at: now,
                })
            }
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }

    pub fn get_profile(&self, profile_id: &str, profile_version: &str) -> Result<Option<WorkloadProfileRecord>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT profile_digest, schema_version, manifest_json, created_at
             FROM workload_profiles
             WHERE profile_id = ?1 AND profile_version = ?2"
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let res = stmt.query_row(
            params![profile_id, profile_version],
            |row| {
                Ok(WorkloadProfileRecord {
                    profile_id: profile_id.to_string(),
                    profile_version: profile_version.to_string(),
                    profile_digest: row.get(0)?,
                    schema_version: row.get(1)?,
                    manifest_json: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        );

        match res {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest(id: &str, ver: &str, digest_salt: &str) -> String {
        let hex_suffix = format!("{:02x}", digest_salt.len() % 256);
        serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": id,
            "profileVersion": ver,
            "runtimeKind": "OCI_CONTAINER",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "app",
                    "image": "docker.io/library/alpine",
                    "imageDigest": format!("sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b294104296{}", hex_suffix),
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "http", "path": "/health", "port": 8080, "timeoutSeconds": 5 }
                }
            ],
            "secretRequirements": [],
            "healthChecks": [],
            "readinessChecks": [],
            "upgradePolicy": {
                "strategy": "replace",
                "requiresSnapshot": true,
                "databaseMigration": "none",
                "rollbackCompatibility": "runtime-only"
            },
            "rollbackPolicy": {
                "runtimeRollback": "previous-profile",
                "databaseRollback": "previous-snapshot"
            }
        }).to_string()
    }

    #[test]
    fn test_profile_registry_sqlite_unique_identity_and_conflict() {
        let registry = WorkloadProfileRegistry::in_memory().unwrap();

        // 1. Initial registration succeeds
        let m1 = valid_manifest("test-service", "1.0.0", "first description");
        let rec1 = registry.register_profile(&m1).unwrap();
        assert_eq!(rec1.profile_id, "test-service");
        assert_eq!(rec1.profile_version, "1.0.0");
        assert!(rec1.profile_digest.starts_with("sha256:"));

        // 2. Lookup works
        let fetched = registry.get_profile("test-service", "1.0.0").unwrap().expect("Should exist");
        assert_eq!(fetched.profile_digest, rec1.profile_digest);

        // 3. Idempotent re-registration of exact same manifest succeeds
        let rec2 = registry.register_profile(&m1).unwrap();
        assert_eq!(rec2.profile_digest, rec1.profile_digest);

        // 4. Digest conflict fails closed: same profileId and version, different description
        let m2 = valid_manifest("test-service", "1.0.0", "tampered description");
        match registry.register_profile(&m2) {
            Err(WorkloadError::ProfileVersionDigestConflict { profile_id, profile_version, existing_digest, new_digest }) => {
                assert_eq!(profile_id, "test-service");
                assert_eq!(profile_version, "1.0.0");
                assert_eq!(existing_digest, rec1.profile_digest);
                assert_ne!(new_digest, existing_digest);
            }
            other => panic!("Expected ProfileVersionDigestConflict, got {:?}", other),
        }

        // 5. Different version for same profile succeeds
        let m3 = valid_manifest("test-service", "1.1.0", "version 1.1");
        let rec3 = registry.register_profile(&m3).unwrap();
        assert_eq!(rec3.profile_version, "1.1.0");
        assert_ne!(rec3.profile_digest, rec1.profile_digest);

        // 6. Inline secret rejection
        let secret_manifest = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "bad-profile",
            "profileVersion": "1.0.0",
            "password": "supersecretpassword"
        }).to_string();
        assert!(matches!(registry.register_profile(&secret_manifest), Err(WorkloadError::ValidationFailed(_))));

        // 7. Schema mismatch rejection
        let bad_schema = serde_json::json!({
            "schema": "actium-workload-profile@0.9.0",
            "profileId": "bad-profile",
            "profileVersion": "1.0.0"
        }).to_string();
        assert!(matches!(registry.register_profile(&bad_schema), Err(WorkloadError::ValidationFailed(_))));
    }

    #[test]
    fn test_exact_schema_validator_rejects_non_canonical_fields() {
        let registry = WorkloadProfileRegistry::in_memory().unwrap();
        let base_valid: serde_json::Value = serde_json::from_str(&valid_manifest("test-schema", "1.0.0", "a")).unwrap();

        // 1. Rejects networkMode (additionalProperties: false)
        let mut t1 = base_valid.clone();
        t1["components"][0].as_object_mut().unwrap().insert("networkMode".into(), serde_json::json!("INTERNAL"));
        assert!(matches!(registry.register_profile(&t1.to_string()), Err(WorkloadError::ValidationFailed(_))));

        // 2. Rejects network: "INTERNAL" (enum violation)
        let mut t2 = base_valid.clone();
        t2["components"][0]["network"] = serde_json::json!("INTERNAL");
        assert!(matches!(registry.register_profile(&t2.to_string()), Err(WorkloadError::ValidationFailed(_))));

        // 3. Rejects missing restartPolicy (required field)
        let mut t3 = base_valid.clone();
        t3["components"][0].as_object_mut().unwrap().remove("restartPolicy");
        assert!(matches!(registry.register_profile(&t3.to_string()), Err(WorkloadError::ValidationFailed(_))));

        // 4. Rejects missing healthCheck (required field)
        let mut t4 = base_valid.clone();
        t4["components"][0].as_object_mut().unwrap().remove("healthCheck");
        assert!(matches!(registry.register_profile(&t4.to_string()), Err(WorkloadError::ValidationFailed(_))));

        // 5. Rejects missing imageDigest (required field)
        let mut t5 = base_valid.clone();
        t5["components"][0].as_object_mut().unwrap().remove("imageDigest");
        assert!(matches!(registry.register_profile(&t5.to_string()), Err(WorkloadError::ValidationFailed(_))));

        // 6. Rejects unknown root property (root additionalProperties: false)
        let mut t6 = base_valid.clone();
        t6.as_object_mut().unwrap().insert("unsupportedField".into(), serde_json::json!("malicious"));
        assert!(matches!(registry.register_profile(&t6.to_string()), Err(WorkloadError::ValidationFailed(_))));
    }
}
