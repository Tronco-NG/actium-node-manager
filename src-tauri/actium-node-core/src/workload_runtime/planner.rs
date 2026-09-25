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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlannedSecretMount {
    pub secret_id: String,
    pub purpose: String,
    pub mount_path: String,
    pub injection_mode: String, // "TMPFS_FILE" or "ENV"
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
    pub execution_order: Vec<String>,
    pub components: Vec<PlannedComponent>,
    pub plan_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness_checks: Option<Vec<PlannedHealthCheck>>,
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

        // 1. Verify claimed desired_digest by local recomputation
        let claimed_desired_digest = desired_val
            .get("desiredDigest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing 'desiredDigest' in desired state".into()))?;

        // Recompute locally over the desired payload (excluding signatures, desiredDigest, and envelope transport metadata)
        let mut clean_desired = desired_val.clone();
        if let Value::Object(ref mut map) = clean_desired {
            map.remove("desiredDigest");
            map.remove("hostSignature");
            map.remove("authoritySignature");
            map.remove("clientId");
            map.remove("organizationId");
            map.remove("siteId");
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
            // Check fallback for legacy envelopes where profileDigest was envelope-level
            let mut alt_clean = clean_desired.clone();
            if let Value::Object(ref mut map) = alt_clean {
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
                }
            }
        }
        if !constant_time_digest_eq(claimed_desired_digest, &computed_desired_digest)? {
            return Err(WorkloadError::ValidationFailed(format!(
                "Claimed desiredDigest '{}' does not match locally recomputed digest '{}'",
                claimed_desired_digest, computed_desired_digest
            )));
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

            let mut secret_mounts = Vec::new();
            if let Some(secs) = comp.get("secretMounts").and_then(|v| v.as_array()) {
                for s in secs {
                    secret_mounts.push(PlannedSecretMount {
                        secret_id: s.get("secretId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        purpose: s.get("purpose").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        mount_path: s.get("mountPath").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        injection_mode: s.get("injectionMode").and_then(|v| v.as_str()).unwrap_or("TMPFS_FILE").to_string(),
                    });
                }
            } else if let Some(reqs) = profile_val.get("secretRequirements").and_then(|v| v.as_array()) {
                for r in reqs {
                    let sec_id = r.get("secretId").and_then(|v| v.as_str()).unwrap_or("");
                    let purpose = r.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
                    let scope = r.get("scope").and_then(|v| v.as_str()).unwrap_or("deployment");
                    if scope == "deployment" || scope == "component" {
                        secret_mounts.push(PlannedSecretMount {
                            secret_id: sec_id.to_string(),
                            purpose: purpose.to_string(),
                            mount_path: format!("/run/secrets/{}", sec_id),
                            injection_mode: "TMPFS_FILE".to_string(),
                        });
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
                    let container_port = p.get("containerPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    port_mappings.push(PlannedPortMapping {
                        container_port,
                        protocol: "tcp".to_string(),
                        ingress_managed: true,
                    });
                }
            }

            let depends_on = comp
                .get("dependencies")
                .or_else(|| comp.get("dependsOn"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let raw_network = comp
                .get("network")
                .and_then(|v| v.as_str())
                .or_else(|| comp.get("networkMode").and_then(|v| v.as_str()))
                .unwrap_or("PRODUCT_INTERNAL");

            let net_slug = sanitize_yaml_key(&deployment_id).unwrap_or("workload");
            let network_mode = match raw_network {
                "ISOLATED" | "none" => "none".to_string(),
                "PRODUCT_INTERNAL" => format!("actium-product-{}", net_slug),
                "SITE_INTERNAL" => format!("actium-site-{}", net_slug),
                "PUBLIC_HTTPS" => format!("actium-ingress-{}", net_slug),
                "INTERNAL" => format!("actium-product-{}", net_slug),
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
                    checks.push(PlannedHealthCheck {
                        probe_type: p_type,
                        component_id: rc.get("componentId").and_then(|v| v.as_str()).map(String::from),
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

        // 6. Calculate deterministic plan_digest
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
            execution_order,
            components: planned_components,
            plan_digest,
            readiness_checks,
            planner_version: planner_version.map(String::from),
            planned_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_test_profile(cycle: bool, unpinned_image: bool, privileged: bool) -> String {
        let image = if unpinned_image {
            "docker.io/library/redis:latest"
        } else {
            "docker.io/library/redis@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605"
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
                    "privileged": privileged,
                    "dependencies": deps_b,
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": { "type": "tcp", "port": 6379, "timeoutSeconds": 5 }
                },
                {
                    "componentId": "app",
                    "image": "docker.io/library/node@sha256:45b41b35b1e30d6660b9271ea349d8e402b2941042960577af4d6b9f0213b293",
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
            "generation": gen,
            "profileId": profile_id,
            "profileVersion": profile_ver,
            "targetState": "ACTIVE",
            "environment": { "ENV": "production" }
        });
        let digest = canonical_digest_for_value(&body).unwrap();
        let mut envelope = body;
        envelope["desiredDigest"] = serde_json::Value::String(digest);
        envelope.to_string()
    }

    #[test]
    fn test_planner_deterministic_plan_digest_with_host_capabilities() {
        let profile = valid_test_profile(false, false, false);
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
        let profile_cyclic = valid_test_profile(true, false, false);
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
        let profile_unpinned = valid_test_profile(false, true, false);
        let desired = valid_test_desired("dep-unpinned", 1, "web-stack", "1.0.0");
        let host_caps = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let err = WorkloadPlanner::plan(&desired, &profile_unpinned, host_caps, None, None).unwrap_err();
        match err {
            WorkloadError::ValidationFailed(msg) => {
                assert!(msg.contains("must be pinned by sha256 digest"));
            }
            other => panic!("Expected ValidationFailed for unpinned image, got {:?}", other),
        }
    }

    #[test]
    fn test_planner_rejects_privileged_mode() {
        let profile_priv = valid_test_profile(false, false, true);
        let desired = valid_test_desired("dep-priv", 1, "web-stack", "1.0.0");
        let host_caps = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

        let err = WorkloadPlanner::plan(&desired, &profile_priv, host_caps, None, None).unwrap_err();
        match err {
            WorkloadError::ValidationFailed(msg) => {
                assert!(msg.contains("Privileged mode is strictly forbidden"));
            }
            other => panic!("Expected ValidationFailed for privileged mode, got {:?}", other),
        }
    }

    #[test]
    fn test_planner_recomputes_desired_digest_claim() {
        let profile = valid_test_profile(false, false, false);
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
}
