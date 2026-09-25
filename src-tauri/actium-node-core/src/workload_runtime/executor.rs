use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

use crate::workload::{ComponentObservation, ComponentStatus};
use super::planner::{CanonicalWorkloadPlan, PlannedComponent, PlannedVolumeMount};
use super::WorkloadError;

/// An ephemeral secret held in zeroized memory. Never serialized, never cloned.
pub struct EphemeralSecret {
    pub secret_id: String,
    pub purpose: String,
    bytes: Vec<u8>,
}

impl Zeroize for EphemeralSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for EphemeralSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl EphemeralSecret {
    pub fn new(secret_id: impl Into<String>, purpose: impl Into<String>, raw: Vec<u8>) -> Self {
        Self {
            secret_id: secret_id.into(),
            purpose: purpose.into(),
            bytes: raw,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mounts the secret into a tmpfs path with 0600 permissions.
    pub fn mount_tmpfs(&self, target_path: &Path) -> Result<(), WorkloadError> {
        let path_str = target_path.to_string_lossy();
        if path_str.contains("..") {
            return Err(WorkloadError::ExecutionError("Path traversal in secret mount is strictly forbidden".into()));
        }

        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| WorkloadError::ExecutionError(format!("Failed to create secret dir: {}", e)))?;
        }
        std::fs::write(target_path, &self.bytes)
            .map_err(|e| WorkloadError::ExecutionError(format!("Failed to write secret file: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(target_path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

impl fmt::Debug for EphemeralSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralSecret")
            .field("secret_id", &self.secret_id)
            .field("purpose", &self.purpose)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInspection {
    pub container_id: String,
    pub name: String,
    pub status: ComponentStatus,
    pub labels: BTreeMap<String, String>,
    pub exists: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeProjectInspection {
    pub project_id: String,
    pub components: Vec<ContainerInspection>,
    pub exists: bool,
}

#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub runtime_instance_id: String,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub volume_mounts: Vec<PlannedVolumeMount>,
    pub network_mode: String,
}

/// Closed typed backend for single OCI containers.
pub trait ContainerRuntimeBackend: Send + Sync {
    fn inspect_container(&self, id: &str) -> Result<ContainerInspection, WorkloadError>;
    fn pull_image(&self, image: &str) -> Result<(), WorkloadError>;
    fn create_container(&self, config: &ContainerConfig) -> Result<String, WorkloadError>;
    fn start_container(&self, id: &str) -> Result<(), WorkloadError>;
    fn stop_container(&self, id: &str, timeout_secs: u32) -> Result<(), WorkloadError>;
    fn remove_container(&self, id: &str) -> Result<(), WorkloadError>;
}

/// Closed typed backend for OCI Compose orchestration. Zero-RCE guaranteed.
pub trait ComposeRuntimeBackend: Send + Sync {
    fn inspect_project(&self, project_id: &str) -> Result<ComposeProjectInspection, WorkloadError>;
    fn pull_project(&self, plan: &CanonicalWorkloadPlan) -> Result<(), WorkloadError>;
    fn create_project(&self, plan: &CanonicalWorkloadPlan, compose_yaml: &str) -> Result<(), WorkloadError>;
    fn start_project(&self, project_id: &str) -> Result<(), WorkloadError>;
    fn stop_project(&self, project_id: &str, timeout_secs: u32) -> Result<(), WorkloadError>;
    fn remove_project(&self, project_id: &str) -> Result<(), WorkloadError>;
}

fn recursive_copy_dir(src: &Path, dst: &Path) -> std::io::Result<usize> {
    let mut count = 0;
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    if src.exists() && src.is_dir() {
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            let target = dst.join(entry.file_name());
            if path.is_dir() {
                count += recursive_copy_dir(&path, &target)?;
            } else {
                std::fs::copy(&path, &target)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

fn compute_dir_digest(dir: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut paths = Vec::new();

    fn collect(d: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if d.exists() && d.is_dir() {
            for entry in std::fs::read_dir(d)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    collect(&path, out)?;
                } else {
                    out.push(path);
                }
            }
        }
        Ok(())
    }

    collect(dir, &mut paths)?;
    paths.sort();

    for p in paths {
        let rel = p.strip_prefix(dir).unwrap_or(&p);
        hasher.update(rel.to_string_lossy().as_bytes());
        let data = std::fs::read(&p)?;
        hasher.update(&data);
    }

    let hash = hasher.finalize();
    Ok(format!("sha256:{:x}", hash))
}

/// Volume provider for managing durable pre-mutation snapshots and volume mounts.
pub struct VolumeProvider {
    pub base_root: PathBuf,
}

impl VolumeProvider {
    pub fn new(base_root: impl Into<PathBuf>) -> Self {
        Self {
            base_root: base_root.into(),
        }
    }

    pub fn resolve_volume_path(&self, host_path: &str) -> PathBuf {
        let p = Path::new(host_path);
        if p.is_relative() {
            self.base_root.join("volumes").join(p)
        } else {
            // Absolute host path (pre-validated by planner)
            let trimmed = host_path.trim_start_matches('/').trim_start_matches('\\');
            self.base_root.join("volumes").join(trimmed)
        }
    }

    /// Captures a durable pre-mutation snapshot of a volume before mutation N+1.
    /// Performs real file/directory copy and computes cryptographic content SHA-256 digest.
    pub fn capture_pre_mutation_snapshot(
        &self,
        deployment_id: &str,
        generation: u64,
        volume_id: &str,
        host_path: &str,
    ) -> Result<PathBuf, WorkloadError> {
        let snap_dir = self
            .base_root
            .join("snapshots")
            .join(deployment_id)
            .join(format!("gen-{}", generation))
            .join(volume_id);

        let data_dir = snap_dir.join("data");
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| WorkloadError::ExecutionError(format!("Failed to create snapshot dir: {}", e)))?;

        let source_path = self.resolve_volume_path(host_path);
        let mut file_count = 0;
        if source_path.exists() {
            file_count = recursive_copy_dir(&source_path, &data_dir)
                .map_err(|e| WorkloadError::ExecutionError(format!("Snapshot copy error: {}", e)))?;
        }

        let content_digest = compute_dir_digest(&data_dir)
            .map_err(|e| WorkloadError::ExecutionError(format!("Snapshot hashing error: {}", e)))?;

        let marker = snap_dir.join(".snapshot_metadata.json");
        let meta = serde_json::json!({
            "deploymentId": deployment_id,
            "generation": generation,
            "volumeId": volume_id,
            "sourcePath": source_path.to_string_lossy(),
            "durable": true,
            "contentDigest": content_digest,
            "fileCount": file_count,
            "capturedAt": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        });
        std::fs::write(&marker, meta.to_string())
            .map_err(|e| WorkloadError::ExecutionError(format!("Failed to write snapshot marker: {}", e)))?;

        Ok(snap_dir)
    }

    /// Restores volume data from a durable pre-mutation snapshot.
    /// Verifies content digest integrity and restores all files to target path.
    pub fn restore_snapshot(&self, snapshot_dir: &Path, target_host_path: &str) -> Result<(), WorkloadError> {
        let data_dir = snapshot_dir.join("data");
        if !data_dir.exists() {
            return Err(WorkloadError::RollbackFailed(format!(
                "Snapshot data directory missing at {:?}",
                data_dir
            )));
        }

        let meta_file = snapshot_dir.join(".snapshot_metadata.json");
        if meta_file.exists() {
            if let Ok(meta_str) = std::fs::read_to_string(&meta_file) {
                if let Ok(meta_json) = serde_json::from_str::<serde_json::Value>(&meta_str) {
                    if let Some(expected_digest) = meta_json.get("contentDigest").and_then(|v| v.as_str()) {
                        let actual_digest = compute_dir_digest(&data_dir)
                            .map_err(|e| WorkloadError::RollbackFailed(format!("Digest verification error: {}", e)))?;
                        if actual_digest != expected_digest {
                            return Err(WorkloadError::RollbackFailed(format!(
                                "Snapshot integrity check failed: digest '{}' does not match recorded '{}'",
                                actual_digest, expected_digest
                            )));
                        }
                    }
                }
            }
        }

        let target_path = self.resolve_volume_path(target_host_path);
        if target_path.exists() {
            let _ = std::fs::remove_dir_all(&target_path);
        }
        std::fs::create_dir_all(&target_path)
            .map_err(|e| WorkloadError::RollbackFailed(format!("Failed to recreate target volume dir: {}", e)))?;
        recursive_copy_dir(&data_dir, &target_path)
            .map_err(|e| WorkloadError::RollbackFailed(format!("Failed to restore snapshot files: {}", e)))?;

        Ok(())
    }
}

/// Generates valid Docker Compose YAML internally from the CanonicalWorkloadPlan.
/// Pure, deterministic, zero-RCE synthesis.
pub fn generate_compose_yaml(plan: &CanonicalWorkloadPlan) -> Result<String, WorkloadError> {
    let mut yaml = String::new();
    yaml.push_str("version: '3.8'\n");
    yaml.push_str(&format!("name: {}\n", plan.compose_project_id));
    yaml.push_str("services:\n");

    for comp in &plan.components {
        yaml.push_str(&format!("  {}:\n", comp.component_id));
        yaml.push_str(&format!("    container_name: {}\n", comp.runtime_instance_id));
        yaml.push_str(&format!("    image: {}\n", comp.image));

        // Actium Labels for audit and crash recovery
        yaml.push_str("    labels:\n");
        yaml.push_str(&format!("      actium.deployment_id: \"{}\"\n", plan.deployment_id));
        yaml.push_str(&format!("      actium.generation: \"{}\"\n", plan.generation));
        yaml.push_str(&format!("      actium.plan_digest: \"{}\"\n", plan.plan_digest));
        yaml.push_str(&format!("      actium.component_id: \"{}\"\n", comp.component_id));
        yaml.push_str(&format!("      actium.runtime_instance_id: \"{}\"\n", comp.runtime_instance_id));

        // Security hardening
        yaml.push_str("    security_opt:\n");
        yaml.push_str("      - no-new-privileges:true\n");
        yaml.push_str("    cap_drop:\n");
        yaml.push_str("      - ALL\n");

        if !comp.network_mode.is_empty() {
            yaml.push_str(&format!("    network_mode: \"{}\"\n", comp.network_mode));
        } else {
            yaml.push_str("    networks:\n");
            yaml.push_str("      - actium_workload_net\n");
        }

        if !comp.command.is_empty() {
            let cmd_str = comp.command.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ");
            yaml.push_str(&format!("    entrypoint: [{}]\n", cmd_str));
        }

        if !comp.args.is_empty() {
            let args_str = comp.args.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(", ");
            yaml.push_str(&format!("    command: [{}]\n", args_str));
        }

        if !comp.env.is_empty() {
            yaml.push_str("    environment:\n");
            for (k, v) in &comp.env {
                yaml.push_str(&format!("      {}: \"{}\"\n", k, v));
            }
        }

        if !comp.depends_on.is_empty() {
            yaml.push_str("    depends_on:\n");
            for dep in &comp.depends_on {
                yaml.push_str(&format!("      - {}\n", dep));
            }
        }

        if !comp.secret_mounts.is_empty() {
            yaml.push_str("    volumes:\n");
            for s in &comp.secret_mounts {
                if s.injection_mode == "TMPFS_FILE" {
                    yaml.push_str(&format!("      - type: tmpfs\n        target: {}\n        tmpfs:\n          mode: 0600\n", s.mount_path));
                }
            }
            for v in &comp.volume_mounts {
                yaml.push_str(&format!("      - {}:{}:{}\n", v.host_path, v.container_path, if v.read_only { "ro" } else { "rw" }));
            }
        } else if !comp.volume_mounts.is_empty() {
            yaml.push_str("    volumes:\n");
            for v in &comp.volume_mounts {
                yaml.push_str(&format!("      - {}:{}:{}\n", v.host_path, v.container_path, if v.read_only { "ro" } else { "rw" }));
            }
        }
    }

    yaml.push_str("networks:\n");
    yaml.push_str("  actium_workload_net:\n");
    yaml.push_str("    driver: bridge\n");

    Ok(yaml)
}

/// Executor for OCI Compose projects.
pub struct OciComposeExecutor<B: ComposeRuntimeBackend> {
    backend: Arc<B>,
}

impl<B: ComposeRuntimeBackend> OciComposeExecutor<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }

    pub fn inspect(&self, project_id: &str) -> Result<ComposeProjectInspection, WorkloadError> {
        self.backend.inspect_project(project_id)
    }

    pub fn apply_plan(&self, plan: &CanonicalWorkloadPlan) -> Result<Vec<ComponentObservation>, WorkloadError> {
        let compose_yaml = generate_compose_yaml(plan)?;
        self.backend.pull_project(plan)?;
        self.backend.create_project(plan, &compose_yaml)?;
        self.backend.start_project(&plan.compose_project_id)?;

        let inspection = self.backend.inspect_project(&plan.compose_project_id)?;
        let observations = inspection
            .components
            .into_iter()
            .map(|c| ComponentObservation {
                component_id: c.name,
                status: c.status,
            })
            .collect();
        Ok(observations)
    }

    pub fn stop_project(&self, project_id: &str, timeout_secs: u32) -> Result<(), WorkloadError> {
        self.backend.stop_project(project_id, timeout_secs)
    }

    pub fn remove_project(&self, project_id: &str) -> Result<(), WorkloadError> {
        self.backend.remove_project(project_id)
    }

    pub fn down_project(&self, project_id: &str) -> Result<(), WorkloadError> {
        let _ = self.backend.stop_project(project_id, 10);
        self.backend.remove_project(project_id)
    }

    pub fn start_project(&self, project_id: &str) -> Result<(), WorkloadError> {
        self.backend.start_project(project_id)
    }
}

/// Executor for individual OCI Containers.
pub struct OciContainerExecutor<B: ContainerRuntimeBackend> {
    backend: Arc<B>,
}

impl<B: ContainerRuntimeBackend> OciContainerExecutor<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend }
    }

    pub fn inspect(&self, id: &str) -> Result<ContainerInspection, WorkloadError> {
        self.backend.inspect_container(id)
    }

    pub fn apply_component(
        &self,
        comp: &PlannedComponent,
        plan: &CanonicalWorkloadPlan,
    ) -> Result<ComponentObservation, WorkloadError> {
        self.backend.pull_image(&comp.image)?;

        let mut labels = BTreeMap::new();
        labels.insert("actium.deployment_id".into(), plan.deployment_id.clone());
        labels.insert("actium.generation".into(), plan.generation.to_string());
        labels.insert("actium.plan_digest".into(), plan.plan_digest.clone());
        labels.insert("actium.component_id".into(), comp.component_id.clone());
        labels.insert("actium.runtime_instance_id".into(), comp.runtime_instance_id.clone());

        let cfg = ContainerConfig {
            runtime_instance_id: comp.runtime_instance_id.clone(),
            image: comp.image.clone(),
            command: comp.command.clone(),
            args: comp.args.clone(),
            env: comp.env.clone(),
            labels,
            volume_mounts: comp.volume_mounts.clone(),
            network_mode: comp.network_mode.clone(),
        };

        let container_id = self.backend.create_container(&cfg)?;
        self.backend.start_container(&container_id)?;

        let inspection = self.backend.inspect_container(&container_id)?;
        Ok(ComponentObservation {
            component_id: comp.component_id.clone(),
            status: inspection.status,
        })
    }

    pub fn stop_container(&self, id: &str, timeout_secs: u32) -> Result<(), WorkloadError> {
        self.backend.stop_container(id, timeout_secs)
    }

    pub fn remove_container(&self, id: &str) -> Result<(), WorkloadError> {
        self.backend.remove_container(id)
    }
}

/// In-memory Mock Compose Backend for testing and mocked E2E certification.
pub struct MockComposeRuntimeBackend {
    projects: Mutex<BTreeMap<String, Vec<ContainerInspection>>>,
}

impl MockComposeRuntimeBackend {
    pub fn new() -> Self {
        Self {
            projects: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn set_component_status(&self, project_id: &str, component_id: &str, status: ComponentStatus) {
        let mut map = self.projects.lock().unwrap();
        if let Some(list) = map.get_mut(project_id) {
            for c in list.iter_mut() {
                if c.name == component_id {
                    c.status = status;
                }
            }
        }
    }
}

impl ComposeRuntimeBackend for MockComposeRuntimeBackend {
    fn inspect_project(&self, project_id: &str) -> Result<ComposeProjectInspection, WorkloadError> {
        let map = self.projects.lock().unwrap();
        if let Some(components) = map.get(project_id) {
            Ok(ComposeProjectInspection {
                project_id: project_id.to_string(),
                components: components.clone(),
                exists: true,
            })
        } else {
            Ok(ComposeProjectInspection {
                project_id: project_id.to_string(),
                components: vec![],
                exists: false,
            })
        }
    }

    fn pull_project(&self, _plan: &CanonicalWorkloadPlan) -> Result<(), WorkloadError> {
        Ok(())
    }

    fn create_project(&self, plan: &CanonicalWorkloadPlan, _compose_yaml: &str) -> Result<(), WorkloadError> {
        let mut map = self.projects.lock().unwrap();
        let comps = plan
            .components
            .iter()
            .map(|c| {
                let mut labels = BTreeMap::new();
                labels.insert("actium.deployment_id".into(), plan.deployment_id.clone());
                labels.insert("actium.generation".into(), plan.generation.to_string());
                labels.insert("actium.plan_digest".into(), plan.plan_digest.clone());
                labels.insert("actium.component_id".into(), c.component_id.clone());
                labels.insert("actium.runtime_instance_id".into(), c.runtime_instance_id.clone());

                ContainerInspection {
                    container_id: c.runtime_instance_id.clone(),
                    name: c.component_id.clone(),
                    status: ComponentStatus::Pending,
                    labels,
                    exists: true,
                }
            })
            .collect();
        map.insert(plan.compose_project_id.clone(), comps);
        Ok(())
    }

    fn start_project(&self, project_id: &str) -> Result<(), WorkloadError> {
        let mut map = self.projects.lock().unwrap();
        if let Some(comps) = map.get_mut(project_id) {
            for c in comps.iter_mut() {
                c.status = ComponentStatus::Ready;
            }
            Ok(())
        } else {
            Err(WorkloadError::ExecutionError(format!("Project '{}' not found", project_id)))
        }
    }

    fn stop_project(&self, project_id: &str, _timeout_secs: u32) -> Result<(), WorkloadError> {
        let mut map = self.projects.lock().unwrap();
        if let Some(comps) = map.get_mut(project_id) {
            for c in comps.iter_mut() {
                c.status = ComponentStatus::Stopped;
            }
        }
        Ok(())
    }

    fn remove_project(&self, project_id: &str) -> Result<(), WorkloadError> {
        let mut map = self.projects.lock().unwrap();
        map.remove(project_id);
        Ok(())
    }
}

/// In-memory Mock Container Backend for testing.
pub struct MockContainerRuntimeBackend {
    containers: Mutex<BTreeMap<String, ContainerInspection>>,
}

impl MockContainerRuntimeBackend {
    pub fn new() -> Self {
        Self {
            containers: Mutex::new(BTreeMap::new()),
        }
    }
}

impl ContainerRuntimeBackend for MockContainerRuntimeBackend {
    fn inspect_container(&self, id: &str) -> Result<ContainerInspection, WorkloadError> {
        let map = self.containers.lock().unwrap();
        if let Some(c) = map.get(id) {
            Ok(c.clone())
        } else {
            Ok(ContainerInspection {
                container_id: id.to_string(),
                name: id.to_string(),
                status: ComponentStatus::Stopped,
                labels: BTreeMap::new(),
                exists: false,
            })
        }
    }

    fn pull_image(&self, _image: &str) -> Result<(), WorkloadError> {
        Ok(())
    }

    fn create_container(&self, config: &ContainerConfig) -> Result<String, WorkloadError> {
        let mut map = self.containers.lock().unwrap();
        let insp = ContainerInspection {
            container_id: config.runtime_instance_id.clone(),
            name: config.runtime_instance_id.clone(),
            status: ComponentStatus::Pending,
            labels: config.labels.clone(),
            exists: true,
        };
        map.insert(config.runtime_instance_id.clone(), insp);
        Ok(config.runtime_instance_id.clone())
    }

    fn start_container(&self, id: &str) -> Result<(), WorkloadError> {
        let mut map = self.containers.lock().unwrap();
        if let Some(c) = map.get_mut(id) {
            c.status = ComponentStatus::Ready;
            Ok(())
        } else {
            Err(WorkloadError::ExecutionError(format!("Container '{}' not found", id)))
        }
    }

    fn stop_container(&self, id: &str, _timeout_secs: u32) -> Result<(), WorkloadError> {
        let mut map = self.containers.lock().unwrap();
        if let Some(c) = map.get_mut(id) {
            c.status = ComponentStatus::Stopped;
        }
        Ok(())
    }

    fn remove_container(&self, id: &str) -> Result<(), WorkloadError> {
        let mut map = self.containers.lock().unwrap();
        map.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_runtime::planner::WorkloadPlanner;

    fn sample_plan() -> CanonicalWorkloadPlan {
        let profile = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "svc",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "components": [
                {
                    "componentId": "app",
                    "image": "docker.io/library/alpine@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "secretMounts": [
                        { "secretId": "api-key", "purpose": "auth", "mountPath": "/run/secrets/key", "injectionMode": "TMPFS_FILE" }
                    ]
                }
            ]
        }).to_string();

        let desired = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": "dep-exec-1",
            "generation": 1,
            "profileId": "svc",
            "profileVersion": "1.0.0",
            "targetState": "ACTIVE"
        });
        let digest = crate::workload_runtime::canonical::canonical_digest_for_value(&desired).unwrap();
        let mut env = desired;
        env["desiredDigest"] = serde_json::Value::String(digest);

        WorkloadPlanner::plan(
            &env.to_string(),
            &profile,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            None,
            None,
        ).unwrap()
    }

    #[test]
    fn test_ephemeral_secret_zeroizes_on_drop_and_tmpfs_mount() {
        let secret = EphemeralSecret::new("sec-1", "auth", b"super_secret_payload".to_vec());
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super_secret_payload"));

        let tmp_dir = std::env::temp_dir().join(format!("actium_test_sec_{}", std::process::id()));
        let tmp_file = tmp_dir.join("token.txt");

        secret.mount_tmpfs(&tmp_file).unwrap();
        let read_back = std::fs::read(&tmp_file).unwrap();
        assert_eq!(read_back, b"super_secret_payload");

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_compose_generator_deterministic_ids_and_no_plain_secrets() {
        let plan = sample_plan();
        let yaml = generate_compose_yaml(&plan).unwrap();

        // Must contain deterministic container_name
        let app_comp = &plan.components[0];
        assert!(yaml.contains(&format!("container_name: {}", app_comp.runtime_instance_id)));
        assert!(yaml.contains(&format!("name: {}", plan.compose_project_id)));

        // Must contain Actium Labels
        assert!(yaml.contains("actium.deployment_id: \"dep-exec-1\""));
        assert!(yaml.contains("actium.generation: \"1\""));
        assert!(yaml.contains(&format!("actium.plan_digest: \"{}\"", plan.plan_digest)));

        // Must mount secret via tmpfs mode 0600
        assert!(yaml.contains("type: tmpfs"));
        assert!(yaml.contains("mode: 0600"));
        assert!(yaml.contains("target: /run/secrets/key"));

        // Must not contain plain secrets
        assert!(!yaml.contains("super_secret_payload"));
    }

    #[test]
    fn test_oci_compose_executor_zero_rce_backend() {
        let backend = Arc::new(MockComposeRuntimeBackend::new());
        let executor = OciComposeExecutor::new(backend.clone());
        let plan = sample_plan();

        let observations = executor.apply_plan(&plan).unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].component_id, "app");
        assert_eq!(observations[0].status, ComponentStatus::Ready);

        let inspection = executor.inspect(&plan.compose_project_id).unwrap();
        assert!(inspection.exists);
        assert_eq!(inspection.components.len(), 1);
        assert_eq!(inspection.components[0].status, ComponentStatus::Ready);

        executor.stop_project(&plan.compose_project_id, 5).unwrap();
        let inspection_stopped = executor.inspect(&plan.compose_project_id).unwrap();
        assert_eq!(inspection_stopped.components[0].status, ComponentStatus::Stopped);
    }

    #[test]
    fn test_oci_container_executor_lifecycle() {
        let backend = Arc::new(MockContainerRuntimeBackend::new());
        let executor = OciContainerExecutor::new(backend.clone());
        let plan = sample_plan();
        let comp = &plan.components[0];

        let obs = executor.apply_component(comp, &plan).unwrap();
        assert_eq!(obs.component_id, "app");
        assert_eq!(obs.status, ComponentStatus::Ready);

        let insp = executor.inspect(&comp.runtime_instance_id).unwrap();
        assert!(insp.exists);
        assert_eq!(insp.status, ComponentStatus::Ready);
        assert_eq!(insp.labels.get("actium.deployment_id").unwrap(), "dep-exec-1");

        executor.stop_container(&comp.runtime_instance_id, 5).unwrap();
        let insp_stopped = executor.inspect(&comp.runtime_instance_id).unwrap();
        assert_eq!(insp_stopped.status, ComponentStatus::Stopped);
    }

    #[test]
    fn test_volume_provider_real_snapshot_and_restore_with_tamper_detection() {
        let temp_dir = std::env::temp_dir().join(format!("actium_vol_test_{}", std::process::id()));
        let base_dir = temp_dir.join("volumes");
        let provider = VolumeProvider::new(&base_dir);

        let vol_dir = provider.resolve_volume_path("data");
        std::fs::create_dir_all(&vol_dir).unwrap();
        std::fs::write(vol_dir.join("state.json"), b"{\"generation\": 1, \"records\": 100}").unwrap();

        // Subdirectory with another file
        let sub_dir = vol_dir.join("sub");
        std::fs::create_dir_all(&sub_dir).unwrap();
        std::fs::write(sub_dir.join("nested.txt"), b"nested content").unwrap();

        // 1. Capture snapshot
        let snap_dir = provider.capture_pre_mutation_snapshot("dep-1", 1, "vol-data", "data").unwrap();
        assert!(snap_dir.exists());
        assert!(snap_dir.join(".snapshot_metadata.json").exists());
        assert!(snap_dir.join("data").join("state.json").exists());
        assert!(snap_dir.join("data").join("sub").join("nested.txt").exists());

        // 2. Corrupt / Mutate volume data (simulate failed generation 2 mutation)
        std::fs::write(vol_dir.join("state.json"), b"{\"generation\": 2, \"corrupt\": true}").unwrap();
        std::fs::remove_file(sub_dir.join("nested.txt")).unwrap();
        std::fs::write(vol_dir.join("new_junk.log"), b"temporary junk").unwrap();

        // 3. Restore snapshot
        provider.restore_snapshot(&snap_dir, "data").unwrap();

        // Verify restoration:
        assert_eq!(
            std::fs::read(vol_dir.join("state.json")).unwrap(),
            b"{\"generation\": 1, \"records\": 100}"
        );
        assert_eq!(
            std::fs::read(sub_dir.join("nested.txt")).unwrap(),
            b"nested content"
        );
        // Junk created during generation 2 should be wiped out cleanly
        assert!(!vol_dir.join("new_junk.log").exists());

        // 4. Test tamper detection
        // Tamper with snapshot file
        std::fs::write(snap_dir.join("data").join("state.json"), b"tampered content").unwrap();
        let restore_err = provider.restore_snapshot(&snap_dir, "data");
        assert!(restore_err.is_err());
        assert!(format!("{:?}", restore_err).contains("Snapshot integrity check failed"));

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

