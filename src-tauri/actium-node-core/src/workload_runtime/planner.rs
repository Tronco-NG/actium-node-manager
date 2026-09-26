use std::collections::{BTreeMap, HashMap, VecDeque};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::canonical::{
    canonical_digest_for_value, constant_time_digest_eq, deterministic_compose_project_id,
    deterministic_runtime_instance_id,
};
use super::executor::sanitize_yaml_key;
use super::WorkloadError;

pub const CANONICAL_WORKLOAD_PLAN_SCHEMA: &str = "actium-canonical-workload-plan@1.0.0";
pub const DESIRED_WORKLOAD_STATE_SCHEMA_STR: &str =
    include_str!("../../../../contracts/workload/v1/actium-desired-workload-state.schema.json");

static DESIRED_STATE_SCHEMA_VALIDATOR: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();

/// Validates a desired workload state manifest against the canonical actium-desired-workload-state@1.0.0 JSON Schema.
pub fn validate_desired_state_schema(parsed: &Value) -> Result<(), WorkloadError> {
    let validator = DESIRED_STATE_SCHEMA_VALIDATOR.get_or_init(|| {
        let schema_val: Value = serde_json::from_str(DESIRED_WORKLOAD_STATE_SCHEMA_STR)
            .expect("Invalid embedded actium-desired-workload-state.schema.json");
        jsonschema::validator_for(&schema_val)
            .expect("Failed to compile actium-desired-workload-state JSON schema")
    });

    let mut errors = validator.iter_errors(parsed);
    if let Some(err) = errors.next() {
        return Err(WorkloadError::ValidationFailed(format!(
            "Desired workload state violates canonical JSON schema: {} at {}",
            err, err.instance_path()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedSecretMount {
    pub secret_id: String,
    pub purpose: String,
    pub mount_path: String,
    pub injection_mode: String, // "TMPFS_FILE" or "ENV"
    pub secret_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedIngressRoute {
    pub component_id: String,
    pub hostname: String,
    pub service_port: u16,
    pub tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedVolumeMount {
    pub volume_id: String,
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedPortMapping {
    pub container_port: u16,
    pub protocol: String,
    pub ingress_managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedHealthCheck {
    pub probe_type: String, // "http", "tcp", "exec", "none"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedComponent {
    pub component_id: String,
    pub runtime_instance_id: String,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub secret_mounts: Vec<PlannedSecretMount>,
    pub volume_mounts: Vec<PlannedVolumeMount>,
    pub network_mode: String,
    pub port_mappings: Vec<PlannedPortMapping>,
    pub depends_on: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<PlannedHealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedUpgradePolicy {
    pub strategy: String,
    pub requires_snapshot: bool,
    pub database_migration: String,
    pub rollback_compatibility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedRollbackPolicy {
    pub runtime_rollback: String,
    pub database_rollback: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkloadPlan {
    pub schema: String,
    pub deployment_id: String,
    pub generation: u64,
    pub desired_state: String,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub desired_digest: String,
    pub host_capabilities_digest: String,
    pub compose_project_id: String,
    pub runtime_kind: String,
    pub upgrade_policy: PlannedUpgradePolicy,
    pub rollback_policy: PlannedRollbackPolicy,
    pub execution_order: Vec<String>,
    pub components: Vec<PlannedComponent>,
    pub plan_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness_checks: Option<Vec<PlannedHealthCheck>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_routes: Option<Vec<PlannedIngressRoute>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planner_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planned_at: Option<u64>,
}

/// Validates that a hostPath is confined and does not escape or mount sensitive host locations.
pub fn validate_host_path(path: &str) -> Result<(), WorkloadError> {
    if path.is_empty() {
        return Err(WorkloadError::ValidationFailed("Empty hostPath is not allowed".into()));
    }
    // Prevent directory traversal
    if path.contains("..") || path.contains("./") || path.contains(".\\") {
        return Err(WorkloadError::ValidationFailed(format!(
            "Directory traversal in hostPath is strictly forbidden: '{}'",
            path
        )));
    }
    let p = path.replace('\\', "/");
    let forbidden_prefixes = [
        "/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/bin", "/sbin",
        "/lib", "/usr", "/var/run", "/run", "/var/lib/docker", "/var/run/docker.sock",
    ];
    for f in &forbidden_prefixes {
        if p == *f || p.starts_with(&format!("{}/", f)) {
            return Err(WorkloadError::ValidationFailed(format!(
                "Host path '{}' accesses forbidden system location '{}'",
                path, f
            )));
        }
    }
    if p == "/" {
        return Err(WorkloadError::ValidationFailed("Mounting host root '/' is strictly forbidden".into()));
    }
    Ok(())
}

pub struct WorkloadPlanner;

impl WorkloadPlanner {
    pub fn plan(
        desired_state_json: &str,
        profile_manifest_json: &str,
        host_capabilities_digest: &str,
        planner_version: Option<&str>,
        planned_at: Option<u64>,
    ) -> Result<CanonicalWorkloadPlan, WorkloadError> {
        let desired_val: Value = serde_json::from_str(desired_state_json)
            .map_err(|e| WorkloadError::ValidationFailed(format!("Invalid desired state JSON: {}", e)))?;
        let profile_val: Value = serde_json::from_str(profile_manifest_json)
            .map_err(|e| WorkloadError::ValidationFailed(format!("Invalid profile manifest JSON: {}", e)))?;

        // Validate profile manifest against canonical Draft 2020-12 schema if schema is declared
        if profile_val.get("schema").and_then(|v| v.as_str()) == Some(crate::workload::WORKLOAD_PROFILE_SCHEMA) {
            crate::workload_runtime::registry::validate_profile_manifest_schema(&profile_val)?;
        }

        // 1. Verify claimed desired_digest by local recomputation
        let claimed_desired_digest = desired_val
            .get("desiredDigest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'desiredDigest' in desired state".into()))?;

        let site_id_opt = desired_val.get("siteId").and_then(|v| v.as_str()).map(String::from);
        let product_id_opt = desired_val.get("productId").and_then(|v| v.as_str()).map(String::from);

        // Recompute locally over the desired payload (excluding signatures, desiredDigest, and envelope transport metadata)
        let mut clean_desired = desired_val.clone();
        if let Value::Object(ref mut map) = clean_desired {
            map.remove("desiredDigest");
            map.remove("hostSignature");
            map.remove("authoritySignature");
            map.remove("clientId");
            map.remove("organizationId");
            map.remove("hostId");
            map.remove("nonce");
            map.remove("issuedAt");
            map.remove("expiresAt");
            map.remove("purpose");
            map.remove("authorityKeyId");
            if !map.contains_key("targetState") && !map.contains_key("desiredState") {
                map.insert("desiredState".into(), Value::String("RUNNING".into()));
            }
        }
        let mut computed_desired_digest = canonical_digest_for_value(&clean_desired)?;
        if !constant_time_digest_eq(claimed_desired_digest, &computed_desired_digest).unwrap_or(false) {
            // Check fallback where siteId/productId were envelope-level transport fields excluded from payload
            let mut alt_clean = clean_desired.clone();
            if let Value::Object(ref mut map) = alt_clean {
                map.remove("siteId");
                map.remove("productId");
            }
            if let Ok(alt_digest) = canonical_digest_for_value(&alt_clean) {
                if constant_time_digest_eq(claimed_desired_digest, &alt_digest).unwrap_or(false) {
                    computed_desired_digest = alt_digest;
                    clean_desired = alt_clean;
                }
            }
        }
        if !constant_time_digest_eq(claimed_desired_digest, &computed_desired_digest).unwrap_or(false) {
            // Check fallback for legacy envelopes where profileDigest was envelope-level
            let mut alt_clean = clean_desired.clone();
            if let Value::Object(ref mut map) = alt_clean {
                map.remove("siteId");
                map.remove("productId");
                map.remove("profileDigest");
                if let Some(ds) = map.remove("desiredState") {
                    if !map.contains_key("targetState") {
                        let mapped = match ds.as_str().unwrap_or("RUNNING") {
                            "RUNNING" => "ACTIVE",
                            other => other,
                        };
                        map.insert("targetState".into(), Value::String(mapped.into()));
                    }
                }
            }
            if let Ok(alt_digest) = canonical_digest_for_value(&alt_clean) {
                if constant_time_digest_eq(claimed_desired_digest, &alt_digest).unwrap_or(false) {
                    computed_desired_digest = alt_digest;
                    clean_desired = alt_clean;
                }
            }
        }
        if !constant_time_digest_eq(claimed_desired_digest, &computed_desired_digest)? {
            return Err(WorkloadError::ValidationFailed(format!(
                "Claimed desiredDigest '{}' does not match locally recomputed digest '{}'",
                claimed_desired_digest, computed_desired_digest
            )));
        }

        // Validate desired state schema against canonical draft 2020-12
        if clean_desired.get("schema").and_then(|v| v.as_str()) == Some(crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA) {
            let mut schema_val = clean_desired.clone();
            if let Value::Object(ref mut map) = schema_val {
                map.insert("desiredDigest".into(), Value::String(claimed_desired_digest.to_string()));
            }
            validate_desired_state_schema(&schema_val)?;
        }

        // Validate desiredState contract if present
        let desired_state = desired_val
            .get("desiredState")
            .and_then(|v| v.as_str())
            .unwrap_or("RUNNING")
            .to_string();

        if desired_state != "RUNNING" && desired_state != "STOPPED" {
            return Err(WorkloadError::ValidationFailed(format!(
                "Invalid desiredState '{}': must be RUNNING or STOPPED",
                desired_state
            )));
        }

        // 2. Extract deployment metadata
        let deployment_id = desired_val
            .get("deploymentId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'deploymentId' in desired state".into()))?
            .to_string();

        let generation = desired_val
            .get("generation")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing or invalid 'generation' in desired state".into()))?;

        let profile_id = profile_val
            .get("profileId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'profileId' in profile".into()))?
            .to_string();

        let profile_version = profile_val
            .get("profileVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'profileVersion' in profile".into()))?
            .to_string();

        let profile_digest = canonical_digest_for_value(&profile_val)?;

        // 3. Security hardening validations
        if let Some(components_arr) = profile_val.get("components").and_then(|v| v.as_array()) {
            for comp in components_arr {
                // Check privileged / host namespaces
                if comp.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false) {
                    return Err(WorkloadError::ValidationFailed(
                        "Privileged mode is strictly forbidden for generic workloads".into(),
                    ));
                }
                if comp.get("hostNetwork").and_then(|v| v.as_bool()).unwrap_or(false)
                    || comp.get("hostPid").and_then(|v| v.as_bool()).unwrap_or(false)
                    || comp.get("hostIpc").and_then(|v| v.as_bool()).unwrap_or(false)
                {
                    return Err(WorkloadError::ValidationFailed(
                        "Host namespaces (network/pid/ipc) are strictly forbidden".into(),
                    ));
                }

                // Image pinning check: must contain @sha256: or imageDigest
                let image = comp
                    .get("image")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'image' in component".into()))?;

                let has_pin = image.contains("@sha256:")
                    || comp.get("imageDigest").and_then(|v| v.as_str()).map(|d| d.starts_with("sha256:")).unwrap_or(false);

                if !has_pin {
                    return Err(WorkloadError::ValidationFailed(format!(
                        "Component image '{}' must be pinned by sha256 digest (@sha256:<hex>)",
                        image
                    )));
                }
            }
        }

        // 4. DAG & Topological Sort for execution_order
        let components_arr = profile_val
            .get("components")
            .and_then(|v| v.as_array())
            .ok_or_else(|| WorkloadError::ValidationFailed("Profile missing 'components' array".into()))?;

        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut all_comp_ids = Vec::new();

        for comp in components_arr {
            let cid = comp
                .get("componentId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'componentId'".into()))?
                .to_string();

            all_comp_ids.push(cid.clone());
            adj.entry(cid.clone()).or_default();
            in_degree.entry(cid.clone()).or_insert(0);

            let deps = comp.get("dependencies").or_else(|| comp.get("dependsOn")).and_then(|v| v.as_array());
            if let Some(deps) = deps {
                for d in deps {
                    if let Some(dep_id) = d.as_str() {
                        adj.entry(dep_id.to_string()).or_default().push(cid.clone());
                        *in_degree.entry(cid.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        // Kahn's algorithm
        let queue: VecDeque<String> = all_comp_ids
            .iter()
            .filter(|id| in_degree.get(*id).copied().unwrap_or(0) == 0)
            .cloned()
            .collect();

        // Sort initial zero-in-degree elements deterministically
        let mut sorted_zeroes: Vec<String> = queue.into_iter().collect();
        sorted_zeroes.sort();
        let mut queue = VecDeque::from(sorted_zeroes);

        let mut execution_order = Vec::new();
        while let Some(node) = queue.pop_front() {
            execution_order.push(node.clone());
            if let Some(neighbors) = adj.get(&node) {
                let mut ready_neighbors = Vec::new();
                for next in neighbors {
                    if let Some(deg) = in_degree.get_mut(next) {
                        *deg -= 1;
                        if *deg == 0 {
                            ready_neighbors.push(next.clone());
                        }
                    }
                }
                ready_neighbors.sort();
                for r in ready_neighbors {
                    queue.push_back(r);
                }
            }
        }

        if execution_order.len() != all_comp_ids.len() {
            return Err(WorkloadError::ValidationFailed(
                "Cyclic component dependency detected in workload profile DAG".into(),
            ));
        }

        // 5. Deterministic runtime and project identifiers
        let compose_project_id = deterministic_compose_project_id(&deployment_id, generation)?;

        // Extract secret references declared in desired state
        #[derive(Debug, Clone)]
        struct DesiredSecretRef {
            secret_id: String,
            purpose: String,
            generation: u64,
            component_id: Option<String>,
            #[allow(dead_code)]
            scope: Option<String>,
        }

        let desired_secret_refs: Vec<DesiredSecretRef> = clean_desired
            .get("secretRefs")
            .or_else(|| desired_val.get("secretRefs"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|item| {
                    let s_id = item.get("secretId")?.as_str()?.to_string();
                    let purp = item.get("purpose")?.as_str()?.to_string();
                    let gen = item.get("generation").and_then(|g| g.as_u64()).unwrap_or(generation);
                    let comp_id = item.get("componentId").and_then(|c| c.as_str()).map(String::from);
                    let scope = item.get("scope").and_then(|s| s.as_str()).map(String::from);
                    Some(DesiredSecretRef {
                        secret_id: s_id,
                        purpose: purp,
                        generation: gen,
                        component_id: comp_id,
                        scope,
                    })
                }).collect()
            })
            .unwrap_or_default();

        let any_comp_declares_secrets = components_arr.iter().any(|c| {
            c.get("secretMounts").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false)
                || c.get("secrets").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false)
        });

        let mut planned_components = Vec::new();
        for comp in components_arr {
            let cid = comp.get("componentId").and_then(|v| v.as_str()).unwrap();
            let runtime_instance_id = deterministic_runtime_instance_id(&deployment_id, generation, cid)?;
            let mut image = comp.get("image").and_then(|v| v.as_str()).unwrap().to_string();
            if !image.contains("@sha256:") {
                if let Some(digest) = comp.get("imageDigest").and_then(|v| v.as_str()) {
                    image = format!("{}@{}", image, digest);
                }
            }

            let command = comp
                .get("command")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let args = comp
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let mut env = BTreeMap::new();
            if let Some(env_obj) = comp.get("env").and_then(|v| v.as_object()) {
                for (ek, ev) in env_obj {
                    if let Some(ev_str) = ev.as_str() {
                        env.insert(ek.clone(), ev_str.to_string());
                    }
                }
            }

            // Secret binding: least privilege & exact generation from desired state secretRefs
            let mut secret_mounts = Vec::new();
            if let Some(secs) = comp.get("secretMounts").and_then(|v| v.as_array()) {
                for s in secs {
                    let sec_id = s.get("secretId").and_then(|v| v.as_str()).unwrap_or("");
                    let matching_ref = desired_secret_refs.iter().find(|r| {
                        r.secret_id == sec_id && (r.component_id.is_none() || r.component_id.as_deref() == Some(cid))
                    })
                        .ok_or_else(|| WorkloadError::ValidationFailed(format!(
                            "Required secret '{}' in secretMounts of component '{}' not found in desired state secretRefs (fail-closed)",
                            sec_id, cid
                        )))?;
                    secret_mounts.push(PlannedSecretMount {
                        secret_id: sec_id.to_string(),
                        purpose: matching_ref.purpose.clone(),
                        mount_path: s.get("mountPath").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        injection_mode: s.get("injectionMode").and_then(|v| v.as_str()).unwrap_or("TMPFS_FILE").to_string(),
                        secret_generation: matching_ref.generation,
                    });
                }
            } else if let Some(secs) = comp.get("secrets").and_then(|v| v.as_array()) {
                for s in secs {
                    let sec_id = s.as_str().unwrap_or("");
                    let matching_ref = desired_secret_refs.iter().find(|r| {
                        r.secret_id == sec_id && (r.component_id.is_none() || r.component_id.as_deref() == Some(cid))
                    })
                        .ok_or_else(|| WorkloadError::ValidationFailed(format!(
                            "Declared secret '{}' for component '{}' not found in desired state secretRefs (fail-closed)",
                            sec_id, cid
                        )))?;
                    secret_mounts.push(PlannedSecretMount {
                        secret_id: sec_id.to_string(),
                        purpose: matching_ref.purpose.clone(),
                        mount_path: format!("/run/secrets/{}", sec_id),
                        injection_mode: "TMPFS_FILE".to_string(),
                        secret_generation: matching_ref.generation,
                    });
                }
            } else if !any_comp_declares_secrets {
                if let Some(reqs) = profile_val.get("secretRequirements").and_then(|v| v.as_array()) {
                    for r in reqs {
                        let sec_id = r.get("secretId").and_then(|v| v.as_str()).unwrap_or("");
                        let target_c = r.get("componentId").and_then(|v| v.as_str());
                        if target_c.is_none() || target_c == Some(cid) {
                            if let Some(matching_ref) = desired_secret_refs.iter().find(|ref_item| {
                                ref_item.secret_id == sec_id && (ref_item.component_id.is_none() || ref_item.component_id.as_deref() == Some(cid))
                            }) {
                                secret_mounts.push(PlannedSecretMount {
                                    secret_id: sec_id.to_string(),
                                    purpose: matching_ref.purpose.clone(),
                                    mount_path: format!("/run/secrets/{}", sec_id),
                                    injection_mode: "TMPFS_FILE".to_string(),
                                    secret_generation: matching_ref.generation,
                                });
                            }
                        }
                    }
                }
            }

            let mut volume_mounts = Vec::new();
            if let Some(vols) = comp.get("volumeMounts").and_then(|v| v.as_array()) {
                for vol in vols {
                    let host_path = vol.get("hostPath").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    validate_host_path(&host_path)?;
                    volume_mounts.push(PlannedVolumeMount {
                        volume_id: vol.get("volumeId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        host_path,
                        container_path: vol.get("containerPath").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        read_only: vol.get("readOnly").and_then(|v| v.as_bool()).unwrap_or(false),
                    });
                }
            } else if let Some(vols) = comp.get("volumes").and_then(|v| v.as_array()) {
                for v in vols {
                    if let Some(vid) = v.as_str() {
                        let host_path = format!("volumes/{}/{}", deployment_id, vid);
                        volume_mounts.push(PlannedVolumeMount {
                            volume_id: vid.to_string(),
                            host_path,
                            container_path: format!("/var/lib/actium/data/{}", vid),
                            read_only: false,
                        });
                    }
                }
            }

            let raw_network = comp
                .get("network")
                .and_then(|v| v.as_str())
                .or_else(|| comp.get("networkMode").and_then(|v| v.as_str()))
                .unwrap_or("PRODUCT_INTERNAL");

            let mut port_mappings = Vec::new();
            if let Some(ports) = comp.get("portMappings").and_then(|v| v.as_array()) {
                for p in ports {
                    let container_port = p.get("containerPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let protocol = p.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
                    let ingress_managed = p.get("ingressManaged").and_then(|v| v.as_bool()).unwrap_or(true);
                    port_mappings.push(PlannedPortMapping {
                        container_port,
                        protocol,
                        ingress_managed,
                    });
                }
            } else if let Some(ports) = profile_val.get("ports").and_then(|v| v.as_array()) {
                for p in ports {
                    let port_policy = p.get("policy").and_then(|v| v.as_str());
                    if port_policy.is_none() || port_policy == Some(raw_network) {
                        let container_port = p.get("containerPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                        port_mappings.push(PlannedPortMapping {
                            container_port,
                            protocol: "tcp".to_string(),
                            ingress_managed: true,
                        });
                    }
                }
            }

            let depends_on = comp
                .get("dependencies")
                .or_else(|| comp.get("dependsOn"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let site_slug = sanitize_yaml_key(
                site_id_opt.as_deref()
                    .or_else(|| profile_val.get("siteId").and_then(|v| v.as_str()))
                    .unwrap_or("default-site")
            )?;
            let product_slug = sanitize_yaml_key(
                product_id_opt.as_deref()
                    .or_else(|| profile_val.get("productId").and_then(|v| v.as_str()))
                    .unwrap_or_else(|| profile_id.as_str())
            )?;
            let dep_slug = sanitize_yaml_key(&deployment_id)?;

            let network_mode = match raw_network {
                "ISOLATED" | "none" => "none".to_string(),
                "PRODUCT_INTERNAL" | "INTERNAL" => format!("actium-product-{}", product_slug),
                "SITE_INTERNAL" => format!("actium-site-{}", site_slug),
                "PUBLIC_HTTPS" => format!("actium-ingress-{}", dep_slug),
                other => {
                    if other.starts_with("actium-") || other == "managed_bridge" {
                        other.to_string()
                    } else {
                        return Err(WorkloadError::ValidationFailed(format!(
                            "Invalid component network policy '{}': must be ISOLATED, SITE_INTERNAL, PRODUCT_INTERNAL, or PUBLIC_HTTPS",
                            other
                        )));
                    }
                }
            };

            let health_check = if let Some(hc) = comp.get("healthCheck").and_then(|v| v.as_object()) {
                let p_type = hc.get("type").and_then(|v| v.as_str()).unwrap_or("none").to_string();
                if p_type == "none" {
                    None
                } else {
                    let cmd = hc.get("command").and_then(|v| v.as_array()).map(|arr| {
                        arr.iter().filter_map(|s| s.as_str().map(String::from)).collect()
                    });
                    if p_type == "exec" && cmd.as_ref().map(|c: &Vec<String>| c.is_empty()).unwrap_or(true) {
                        return Err(WorkloadError::ValidationFailed(format!(
                            "Component '{}' exec healthCheck requires non-empty command vector", cid
                        )));
                    }
                    Some(PlannedHealthCheck {
                        probe_type: p_type,
                        component_id: Some(cid.to_string()),
                        path: hc.get("path").and_then(|v| v.as_str()).map(String::from),
                        port: hc.get("port").and_then(|v| v.as_u64()).map(|p| p as u16),
                        timeout_seconds: hc.get("timeoutSeconds").and_then(|v| v.as_u64()).map(|t| t as u32),
                        command: cmd,
                    })
                }
            } else {
                None
            };

            planned_components.push(PlannedComponent {
                component_id: cid.to_string(),
                runtime_instance_id,
                image,
                command,
                args,
                env,
                secret_mounts,
                volume_mounts,
                network_mode,
                port_mappings,
                depends_on,
                health_check,
            });
        }

        // Sort components deterministically by component_id
        planned_components.sort_by(|a, b| a.component_id.cmp(&b.component_id));

        // Readiness Checks with target component enforcement
        let readiness_checks = if let Some(rc_arr) = profile_val.get("readinessChecks").and_then(|v| v.as_array()) {
            let mut checks = Vec::new();
            for rc in rc_arr {
                let p_type = rc.get("type").and_then(|v| v.as_str()).unwrap_or("none").to_string();
                if p_type != "none" {
                    let cmd = rc.get("command").and_then(|v| v.as_array()).map(|arr| {
                        arr.iter().filter_map(|s| s.as_str().map(String::from)).collect()
                    });
                    if p_type == "exec" && cmd.as_ref().map(|c: &Vec<String>| c.is_empty()).unwrap_or(true) {
                        return Err(WorkloadError::ValidationFailed("Exec readinessCheck requires non-empty command vector".into()));
                    }

                    let target_cid = if let Some(target) = rc.get("componentId").and_then(|v| v.as_str()) {
                        if !all_comp_ids.iter().any(|id| id == target) {
                            return Err(WorkloadError::ValidationFailed(format!(
                                "Readiness check targets unknown componentId '{}'", target
                            )));
                        }
                        target.to_string()
                    } else if all_comp_ids.len() == 1 {
                        all_comp_ids[0].clone()
                    } else {
                        return Err(WorkloadError::ValidationFailed(
                            "Readiness check missing 'componentId' when multiple components exist in profile (fail-closed)".into()
                        ));
                    };

                    checks.push(PlannedHealthCheck {
                        probe_type: p_type,
                        component_id: Some(target_cid),
                        path: rc.get("path").and_then(|v| v.as_str()).map(String::from),
                        port: rc.get("port").and_then(|v| v.as_u64()).map(|p| p as u16),
                        timeout_seconds: rc.get("timeoutSeconds").and_then(|v| v.as_u64()).map(|t| t as u32),
                        command: cmd,
                    });
                }
            }
            if checks.is_empty() { None } else { Some(checks) }
        } else {
            None
        };

        // Ingress Routes Planning
        let dep_slug = sanitize_yaml_key(&deployment_id)?;
        let mut ingress_routes = Vec::new();
        for comp in &planned_components {
            if comp.network_mode.starts_with("actium-ingress") {
                let port = comp.port_mappings.first().map(|p| p.container_port).unwrap_or(443);
                ingress_routes.push(PlannedIngressRoute {
                    component_id: comp.component_id.clone(),
                    hostname: format!("{}.actium.local", dep_slug),
                    service_port: port,
                    tls: true,
                });
            } else {
                for pm in &comp.port_mappings {
                    if pm.ingress_managed {
                        ingress_routes.push(PlannedIngressRoute {
                            component_id: comp.component_id.clone(),
                            hostname: format!("{}.actium.local", dep_slug),
                            service_port: pm.container_port,
                            tls: true,
                        });
                    }
                }
            }
        }
        let ingress_routes_opt = if ingress_routes.is_empty() { None } else { Some(ingress_routes) };

        // 6. Runtime kind & upgrade/rollback policies
        let runtime_kind = profile_val
            .get("runtimeKind")
            .and_then(|v| v.as_str())
            .unwrap_or("OCI_COMPOSE")
            .to_string();

        if runtime_kind == "VM" {
            return Err(WorkloadError::ValidationFailed("Runtime kind 'VM' is not supported (fail-closed)".into()));
        }

        let upgrade_policy = if let Some(up) = profile_val.get("upgradePolicy") {
            serde_json::from_value::<PlannedUpgradePolicy>(up.clone())
                .map_err(|e| WorkloadError::ValidationFailed(format!("Invalid upgradePolicy in profile manifest: {}", e)))?
        } else {
            PlannedUpgradePolicy {
                strategy: "replace".to_string(),
                requires_snapshot: false,
                database_migration: "none".to_string(),
                rollback_compatibility: "runtime-only".to_string(),
            }
        };

        let rollback_policy = if let Some(rp) = profile_val.get("rollbackPolicy") {
            serde_json::from_value::<PlannedRollbackPolicy>(rp.clone())
                .map_err(|e| WorkloadError::ValidationFailed(format!("Invalid rollbackPolicy in profile manifest: {}", e)))?
        } else {
            PlannedRollbackPolicy {
                runtime_rollback: "previous-generation".to_string(),
                database_rollback: "none".to_string(),
            }
        };

        // 7. Calculate deterministic plan_digest
        let canonical_plan_val = serde_json::json!({
            "schema": CANONICAL_WORKLOAD_PLAN_SCHEMA,
            "deploymentId": deployment_id,
            "generation": generation,
            "desiredState": desired_state,
            "profileId": profile_id,
            "profileVersion": profile_version,
            "profileDigest": profile_digest,
            "desiredDigest": claimed_desired_digest,
            "hostCapabilitiesDigest": host_capabilities_digest,
            "composeProjectId": compose_project_id,
            "runtimeKind": runtime_kind,
            "upgradePolicy": upgrade_policy,
            "rollbackPolicy": rollback_policy,
            "executionOrder": execution_order,
            "components": planned_components,
        });

        let plan_digest = canonical_digest_for_value(&canonical_plan_val)?;

        Ok(CanonicalWorkloadPlan {
            schema: CANONICAL_WORKLOAD_PLAN_SCHEMA.to_string(),
            deployment_id,
            generation,
            desired_state,
            profile_id,
            profile_version,
            profile_digest,
            desired_digest: claimed_desired_digest.to_string(),
            host_capabilities_digest: host_capabilities_digest.to_string(),
            compose_project_id,
            runtime_kind,
            upgrade_policy,
            rollback_policy,
            execution_order,
            components: planned_components,
            plan_digest,
            readiness_checks,
            ingress_routes: ingress_routes_opt,
            planner_version: planner_version.map(String::from),
            planned_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_test_profile(cycle: bool, unpinned_image: bool) -> String {
        let (image, digest) = if unpinned_image {
            ("docker.io/library/redis:latest", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
        } else {
            (
                "docker.io/library/redis@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            )
        };

        let deps_b = if cycle { vec!["app"] } else { vec![] };
        let deps_app = vec!["db"];

        serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "web-stack",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "db",
                    "image": image,
                    "imageDigest": digest,
                    "dependencies": deps_b,
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "tcp", "port": 6379, "timeoutSeconds": 5 }
                },
                {
                    "componentId": "app",
                    "image": "docker.io/library/node@sha256:45b41b35b1e30d6660b9271ea349d8e402b2941042960577af4d6b9f0213b293",
                    "imageDigest": "sha256:45b41b35b1e30d6660b9271ea349d8e402b2941042960577af4d6b9f0213b293",
                    "dependencies": deps_app,
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "http", "path": "/health", "port": 3000, "timeoutSeconds": 5 }
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

    fn valid_test_desired(dep_id: &str, gen: u64, profile_id: &str, profile_ver: &str) -> String {
        let body = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": dep_id,
            "profileId": profile_id,
            "profileVersion": profile_ver,
            "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "secretRefs": [],
            "desiredState": "RUNNING",
            "generation": gen,
        });
        let digest = canonical_digest_for_value(&body).unwrap();
        let mut envelope = body;
        envelope["desiredDigest"] = serde_json::Value::String(digest);
        envelope.to_string()
    }

    #[test]
    fn test_planner_deterministic_plan_digest_with_host_capabilities() {
        let profile = valid_test_profile(false, false);
        let desired = valid_test_desired("dep-prod-1", 1, "web-stack", "1.0.0");
        let host_caps_1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let host_caps_2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

        // Execution with host_caps_1 at t=100
        let plan_a1 = WorkloadPlanner::plan(&desired, &profile, host_caps_1, Some("v1.0"), Some(100)).unwrap();
        // Execution with same host_caps_1 at t=200 and different planner version
        let plan_a2 = WorkloadPlanner::plan(&desired, &profile, host_caps_1, Some("v2.0"), Some(200)).unwrap();

        // INVARIANT: planDigest must be identical despite timestamps or planner version
        assert_eq!(plan_a1.plan_digest, plan_a2.plan_digest);
        assert_eq!(plan_a1.execution_order, vec!["db", "app"]);

        // INVARIANT: Different host_capabilities_digest must produce different planDigest
        let plan_b = WorkloadPlanner::plan(&desired, &profile, host_caps_2, Some("v1.0"), Some(100)).unwrap();
        assert_ne!(plan_a1.plan_digest, plan_b.plan_digest);
    }

    #[test]
    fn test_planner_rejects_cyclic_dag() {
        let profile_cyclic = valid_test_profile(true, false);
        let desired = valid_test_desired("dep-cyclic", 1, "web-stack", "1.0.0");
        let host_caps = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let err = WorkloadPlanner::plan(&desired, &profile_cyclic, host_caps, None, None).unwrap_err();
        match err {
            WorkloadError::ValidationFailed(msg) => {
                assert!(msg.contains("Cyclic component dependency detected"));
            }
            other => panic!("Expected ValidationFailed for cycle, got {:?}", other),
        }
    }

    #[test]
    fn test_planner_rejects_unpinned_image() {
        let mut profile_val: Value = serde_json::from_str(&valid_test_profile(false, false)).unwrap();
        profile_val["components"][0].as_object_mut().unwrap().remove("imageDigest");
        profile_val["components"][0]["image"] = serde_json::json!("docker.io/library/redis:latest");
        let desired = valid_test_desired("dep-unpinned", 1, "web-stack", "1.0.0");
        let host_caps = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let err = WorkloadPlanner::plan(&desired, &profile_val.to_string(), host_caps, None, None).unwrap_err();
        match err {
            WorkloadError::ValidationFailed(msg) => {
                assert!(msg.contains("must be pinned by sha256 digest") || msg.contains("imageDigest") || msg.contains("violates canonical JSON schema"));
            }
            other => panic!("Expected ValidationFailed for unpinned image, got {:?}", other),
        }
    }

    #[test]
    fn test_planner_rejects_privileged_mode() {
        let mut profile_val: Value = serde_json::from_str(&valid_test_profile(false, false)).unwrap();
        profile_val["components"][0]["privileged"] = serde_json::json!(true);
        let desired = valid_test_desired("dep-priv", 1, "web-stack", "1.0.0");
        let host_caps = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let err = WorkloadPlanner::plan(&desired, &profile_val.to_string(), host_caps, None, None).unwrap_err();
        match err {
            WorkloadError::ValidationFailed(msg) => {
                assert!(msg.contains("Privileged mode is strictly forbidden") || msg.contains("violates canonical JSON schema"));
            }
            other => panic!("Expected ValidationFailed for privileged mode, got {:?}", other),
        }
    }

    #[test]
    fn test_planner_recomputes_desired_digest_claim() {
        let profile = valid_test_profile(false, false);
        let mut desired_obj: Value = serde_json::from_str(&valid_test_desired("dep-1", 1, "web-stack", "1.0.0")).unwrap();
        // Tamper with claimed desiredDigest
        desired_obj["desiredDigest"] = Value::String("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into());
        let host_caps = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let err = WorkloadPlanner::plan(&desired_obj.to_string(), &profile, host_caps, None, None).unwrap_err();
        match err {
            WorkloadError::ValidationFailed(msg) => {
                assert!(msg.contains("does not match locally recomputed digest"));
            }
            other => panic!("Expected ValidationFailed for tampered desiredDigest claim, got {:?}", other),
        }
    }

    #[test]
    fn test_exact_desired_state_schema_rejects_non_canonical_fields() {
        let valid_desired: Value = serde_json::from_str(&valid_test_desired("dep-test", 1, "web-stack", "1.0.0")).unwrap();
        assert!(validate_desired_state_schema(&valid_desired).is_ok());

        // 1. Rejects unknown property due to additionalProperties: false
        let mut with_extra = valid_desired.clone();
        with_extra["unexpectedField"] = serde_json::json!("forbidden");
        assert!(validate_desired_state_schema(&with_extra).is_err());

        // 2. Rejects invalid desiredState enum
        let mut invalid_state = valid_desired.clone();
        invalid_state["desiredState"] = serde_json::json!("PAUSED");
        assert!(validate_desired_state_schema(&invalid_state).is_err());

        // 3. Rejects missing required field (e.g. configurationDigest)
        let mut missing_config = valid_desired.clone();
        if let Value::Object(ref mut map) = missing_config {
            map.remove("configurationDigest");
        }
        assert!(validate_desired_state_schema(&missing_config).is_err());
    }

    #[test]
    fn test_secret_least_privilege_and_generation_binding() {
        let profile = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "multi-sec",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "db",
                    "image": "docker.io/library/postgres@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "secrets": ["sec-db-master"],
                    "healthCheck": { "type": "tcp", "port": 5432, "timeoutSeconds": 5 }
                },
                {
                    "componentId": "web",
                    "image": "docker.io/library/node@sha256:45b41b35b1e30d6660b9271ea349d8e402b2941042960577af4d6b9f0213b293",
                    "imageDigest": "sha256:45b41b35b1e30d6660b9271ea349d8e402b2941042960577af4d6b9f0213b293",
                    "network": "PUBLIC_HTTPS",
                    "restartPolicy": "unless-stopped",
                    "secrets": [],
                    "healthCheck": { "type": "http", "path": "/health", "port": 80, "timeoutSeconds": 5 }
                }
            ],
            "secretRequirements": [
                { "secretId": "sec-db-master", "purpose": "database-password" }
            ],
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
        }).to_string();

        let desired_body = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": "dep-sec-test",
            "profileId": "multi-sec",
            "profileVersion": "1.0.0",
            "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "secretRefs": [
                {
                    "secretId": "sec-db-master",
                    "purpose": "database-password",
                    "generation": 42
                }
            ],
            "desiredState": "RUNNING",
            "generation": 1,
        });
        let digest = canonical_digest_for_value(&desired_body).unwrap();
        let mut envelope = desired_body;
        envelope["desiredDigest"] = serde_json::Value::String(digest);

        let plan = WorkloadPlanner::plan(
            &envelope.to_string(),
            &profile,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            None,
            None,
        ).unwrap();

        let db_comp = plan.components.iter().find(|c| c.component_id == "db").unwrap();
        assert_eq!(db_comp.secret_mounts.len(), 1);
        assert_eq!(db_comp.secret_mounts[0].secret_id, "sec-db-master");
        assert_eq!(db_comp.secret_mounts[0].secret_generation, 42);

        let web_comp = plan.components.iter().find(|c| c.component_id == "web").unwrap();
        // LEAST PRIVILEGE: web declared no secrets, receives zero secret mounts
        assert!(web_comp.secret_mounts.is_empty());
    }

    #[test]
    fn test_site_and_product_network_scoping() {
        let profile = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "net-scope-prof",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "c-prod",
                    "image": "docker.io/library/redis@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "tcp", "port": 6379, "timeoutSeconds": 5 }
                },
                {
                    "componentId": "c-site",
                    "image": "docker.io/library/redis@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "SITE_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "tcp", "port": 6379, "timeoutSeconds": 5 }
                },
                {
                    "componentId": "c-ingress",
                    "image": "docker.io/library/redis@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "PUBLIC_HTTPS",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "tcp", "port": 6379, "timeoutSeconds": 5 }
                },
                {
                    "componentId": "c-isolated",
                    "image": "docker.io/library/redis@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "ISOLATED",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "tcp", "port": 6379, "timeoutSeconds": 5 }
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
        }).to_string();

        let desired_body = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": "dep-net-test",
            "productId": "prod-alpha",
            "siteId": "site-bravo",
            "profileId": "net-scope-prof",
            "profileVersion": "1.0.0",
            "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "secretRefs": [],
            "desiredState": "RUNNING",
            "generation": 1,
        });
        let digest = canonical_digest_for_value(&desired_body).unwrap();
        let mut envelope = desired_body;
        envelope["desiredDigest"] = serde_json::Value::String(digest);

        let plan = WorkloadPlanner::plan(
            &envelope.to_string(),
            &profile,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            None,
            None,
        ).unwrap();

        let c_prod = plan.components.iter().find(|c| c.component_id == "c-prod").unwrap();
        assert_eq!(c_prod.network_mode, "actium-product-prod-alpha");

        let c_site = plan.components.iter().find(|c| c.component_id == "c-site").unwrap();
        assert_eq!(c_site.network_mode, "actium-site-site-bravo");

        let c_ingress = plan.components.iter().find(|c| c.component_id == "c-ingress").unwrap();
        assert_eq!(c_ingress.network_mode, "actium-ingress-dep-net-test");

        let c_isolated = plan.components.iter().find(|c| c.component_id == "c-isolated").unwrap();
        assert_eq!(c_isolated.network_mode, "none");
    }

    #[test]
    fn test_planner_rejects_forbidden_host_paths() {
        assert!(validate_host_path("/data/app").is_ok());
        assert!(validate_host_path("/var/lib/actium/workloads").is_ok());
        assert!(validate_host_path("relative/path").is_ok());

        assert!(validate_host_path("/etc/shadow").is_err());
        assert!(validate_host_path("/etc").is_err());
        assert!(validate_host_path("/var/run/docker.sock").is_err());
        assert!(validate_host_path("/proc/cpuinfo").is_err());
        assert!(validate_host_path("/sys/kernel").is_err());
        assert!(validate_host_path("/").is_err());
        assert!(validate_host_path("/data/../etc/passwd").is_err());
    }

    #[test]
    fn test_planner_rejects_vm_runtime_kind() {
        let profile = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "vm-profile",
            "profileVersion": "1.0.0",
            "runtimeKind": "VM",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "vm-comp",
                    "image": "docker.io/library/alpine@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "ISOLATED",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "none" }
                }
            ],
            "secretRequirements": [],
            "healthChecks": [],
            "readinessChecks": [],
            "upgradePolicy": {
                "strategy": "replace",
                "requiresSnapshot": false,
                "databaseMigration": "none",
                "rollbackCompatibility": "runtime-only"
            },
            "rollbackPolicy": {
                "runtimeRollback": "previous-generation",
                "databaseRollback": "none"
            }
        }).to_string();

        let desired_body = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": "dep-vm-test",
            "profileId": "vm-profile",
            "profileVersion": "1.0.0",
            "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "secretRefs": [],
            "desiredState": "RUNNING",
            "generation": 1,
        });
        let digest = canonical_digest_for_value(&desired_body).unwrap();
        let mut envelope = desired_body;
        envelope["desiredDigest"] = serde_json::Value::String(digest);

        let err = WorkloadPlanner::plan(
            &envelope.to_string(),
            &profile,
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            None,
            None,
        );
        assert!(err.is_err());
        assert!(format!("{:?}", err).contains("Runtime kind 'VM'"));
    }
}
