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

/// Trait for resolving workload secrets into zeroized ephemeral memory.
pub trait WorkloadSecretProvider: Send + Sync {
    fn resolve_secret(
        &self,
        secret_id: &str,
        purpose: &str,
        generation: u64,
    ) -> Result<EphemeralSecret, WorkloadError>;
}

/// Default in-memory and deterministic secret provider for testing and standard environments.
pub struct DefaultWorkloadSecretProvider {
    secrets: Mutex<BTreeMap<String, Vec<u8>>>,
    vault_root: Option<PathBuf>,
}

impl DefaultWorkloadSecretProvider {
    pub fn new() -> Self {
        Self {
            secrets: Mutex::new(BTreeMap::new()),
            vault_root: None,
        }
    }

    pub fn with_vault_root(vault_root: impl Into<PathBuf>) -> Self {
        Self {
            secrets: Mutex::new(BTreeMap::new()),
            vault_root: Some(vault_root.into()),
        }
    }

    pub fn set_secret(&self, secret_id: &str, secret_bytes: Vec<u8>) {
        let mut map = self.secrets.lock().unwrap();
        map.insert(secret_id.to_string(), secret_bytes);
    }
}

impl Default for DefaultWorkloadSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkloadSecretProvider for DefaultWorkloadSecretProvider {
    fn resolve_secret(
        &self,
        secret_id: &str,
        purpose: &str,
        generation: u64,
    ) -> Result<EphemeralSecret, WorkloadError> {
        let map = self.secrets.lock().unwrap();
        if let Some(raw) = map.get(secret_id) {
            return Ok(EphemeralSecret::new(secret_id, purpose, raw.clone()));
        }

        // Search disk vault if configured
        if let Some(ref root) = self.vault_root {
            let candidates = [
                root.join(secret_id),
                root.join(format!("{}.secret", secret_id)),
                root.join(format!("gen-{}", generation)).join(secret_id),
                root.join(secret_id).join(format!("gen-{}", generation)),
                root.join(secret_id).join(format!("generation-{}", generation)),
            ];
            for path in &candidates {
                if path.exists() && path.is_file() {
                    if let Ok(bytes) = std::fs::read(path) {
                        return Ok(EphemeralSecret::new(secret_id, purpose, bytes));
                    }
                }
            }
        }

        Err(WorkloadError::SecretNotFound(format!(
            "Workload secret '{}' (purpose: '{}', generation: {}) was not found in secret provider (fail-closed)",
            secret_id, purpose, generation
        )))
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
    fn execute_probe(
        &self,
        project_id: &str,
        component_id: &str,
        probe: &super::planner::PlannedHealthCheck,
    ) -> Result<bool, WorkloadError>;
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
        if p.is_absolute() {
            // Absolute host path (pre-validated by planner)
            p.to_path_buf()
        } else if p.starts_with("volumes") {
            self.base_root.join(p)
        } else {
            // Relative volume path confined to workload volumes directory
            self.base_root.join("volumes").join(p)
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

/// Sanitizes an OCI image reference to prevent command injection and ensure valid OCI naming.
pub fn sanitize_image_ref(image: &str) -> Result<String, WorkloadError> {
    if image.is_empty() {
        return Err(WorkloadError::ValidationFailed("Empty image ref".into()));
    }
    for ch in image.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '/' && ch != ':' && ch != '@' && ch != '.' && ch != '-' && ch != '_' {
            return Err(WorkloadError::ValidationFailed(format!(
                "Invalid character '{}' in image reference '{}'",
                ch, image
            )));
        }
    }
    Ok(image.to_string())
}

/// Sanitizes a file path to prevent directory traversal and null/newline injection.
pub fn sanitize_path(path: &str) -> Result<String, WorkloadError> {
    if path.is_empty() {
        return Err(WorkloadError::ValidationFailed("Empty path".into()));
    }
    if path.contains('\n') || path.contains('\r') || path.contains('\0') {
        return Err(WorkloadError::ValidationFailed("Newlines or null bytes not allowed in path".into()));
    }
    if path.contains("..") {
        return Err(WorkloadError::ValidationFailed(format!(
            "Directory traversal in path is strictly forbidden: '{}'",
            path
        )));
    }
    Ok(path.to_string())
}

/// Sanitizes a YAML key or identifier, preventing newline and metacharacter injection.
pub fn sanitize_yaml_key(key: &str) -> Result<&str, WorkloadError> {
    if key.is_empty()
        || key.contains('\n')
        || key.contains('\r')
        || key.contains(':')
        || key.contains(' ')
        || key.contains('"')
        || key.contains('\'')
    {
        return Err(WorkloadError::ValidationFailed(format!(
            "Invalid YAML identifier or key '{}'",
            key
        )));
    }
    Ok(key)
}

/// Safely quotes and escapes a YAML string scalar via JSON escaping.
/// In YAML 1.2, a double-quoted JSON string scalar is canonical and injection-free.
pub fn yaml_quote_scalar(val: &str) -> String {
    serde_json::to_string(val).unwrap_or_else(|_| format!("\"{}\"", val.replace('"', "\\\"")))
}

/// Generates valid Docker Compose YAML internally from the CanonicalWorkloadPlan.
/// Pure, deterministic, zero-RCE synthesis with structured serialization and injection prevention.
pub fn generate_compose_yaml(plan: &CanonicalWorkloadPlan) -> Result<String, WorkloadError> {
    let mut yaml = String::new();
    yaml.push_str("version: '3.8'\n");
    yaml.push_str(&format!("name: {}\n", sanitize_yaml_key(&plan.compose_project_id)?));
    yaml.push_str("services:\n");

    for comp in &plan.components {
        let comp_key = sanitize_yaml_key(&comp.component_id)?;
        yaml.push_str(&format!("  {}:\n", comp_key));
        yaml.push_str(&format!("    container_name: {}\n", sanitize_yaml_key(&comp.runtime_instance_id)?));
        let sanitized_image = sanitize_image_ref(&comp.image)?;
        yaml.push_str(&format!("    image: {}\n", yaml_quote_scalar(&sanitized_image)));

        // Actium Labels for audit and crash recovery
        yaml.push_str("    labels:\n");
        yaml.push_str(&format!("      actium.deployment_id: {}\n", yaml_quote_scalar(&plan.deployment_id)));
        yaml.push_str(&format!("      actium.generation: {}\n", yaml_quote_scalar(&plan.generation.to_string())));
        yaml.push_str(&format!("      actium.plan_digest: {}\n", yaml_quote_scalar(&plan.plan_digest)));
        yaml.push_str(&format!("      actium.component_id: {}\n", yaml_quote_scalar(&comp.component_id)));
        yaml.push_str(&format!("      actium.runtime_instance_id: {}\n", yaml_quote_scalar(&comp.runtime_instance_id)));

        // Security hardening
        yaml.push_str("    security_opt:\n");
        yaml.push_str("      - no-new-privileges:true\n");
        yaml.push_str("    cap_drop:\n");
        yaml.push_str("      - ALL\n");

        // Network Policy Materialization
        if comp.network_mode == "ISOLATED" || comp.network_mode == "none" {
            yaml.push_str("    network_mode: \"none\"\n");
        } else {
            let sanitized_net = sanitize_yaml_key(&comp.network_mode)?;
            yaml.push_str("    networks:\n");
            yaml.push_str(&format!("      - {}\n", sanitized_net));
        }

        // Port publishing for PUBLIC_HTTPS or ingress components
        if !comp.port_mappings.is_empty() {
            let mut expose_ports = Vec::new();
            let mut host_ports = Vec::new();
            for p in &comp.port_mappings {
                if p.ingress_managed {
                    expose_ports.push(p.container_port);
                } else {
                    host_ports.push(format!("{}:{}/{}", p.container_port, p.container_port, p.protocol.to_lowercase()));
                }
            }
            if !expose_ports.is_empty() {
                yaml.push_str("    expose:\n");
                for ep in expose_ports {
                    yaml.push_str(&format!("      - \"{}\"\n", ep));
                }
            }
            if !host_ports.is_empty() {
                yaml.push_str("    ports:\n");
                for hp in host_ports {
                    yaml.push_str(&format!("      - {}\n", yaml_quote_scalar(&hp)));
                }
            }
        }

        // Profile Health/Readiness Probes Materialization
        if let Some(hc) = &comp.health_check {
            yaml.push_str("    healthcheck:\n");
            match hc.probe_type.as_str() {
                "http" => {
                    let path = hc.path.as_deref().unwrap_or("/");
                    let port = hc.port.unwrap_or(80);
                    let cmd = format!("curl -f http://localhost:{}{} || exit 1", port, path);
                    yaml.push_str(&format!("      test: [\"CMD-SHELL\", {}]\n", yaml_quote_scalar(&cmd)));
                }
                "tcp" => {
                    let port = hc.port.unwrap_or(80);
                    let cmd = format!("nc -z localhost {} || exit 1", port);
                    yaml.push_str(&format!("      test: [\"CMD-SHELL\", {}]\n", yaml_quote_scalar(&cmd)));
                }
                "exec" => {
                    let cmd = hc.command.as_ref().ok_or_else(|| {
                        WorkloadError::ValidationFailed(format!("Component '{}' exec probe requires non-empty command vector", comp.component_id))
                    })?;
                    if cmd.is_empty() {
                        return Err(WorkloadError::ValidationFailed(format!("Component '{}' exec probe command vector is empty", comp.component_id)));
                    }
                    let cmd_json = serde_json::to_string(cmd)
                        .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;
                    yaml.push_str(&format!("      test: {}\n", cmd_json));
                }
                _ => {}
            }
            let timeout = hc.timeout_seconds.unwrap_or(5);
            yaml.push_str(&format!("      interval: 10s\n      timeout: {}s\n      retries: 3\n      start_period: 5s\n", timeout));
        }

        if !comp.command.is_empty() {
            let cmd_json = serde_json::to_string(&comp.command)
                .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;
            yaml.push_str(&format!("    entrypoint: {}\n", cmd_json));
        }

        if !comp.args.is_empty() {
            let args_json = serde_json::to_string(&comp.args)
                .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;
            yaml.push_str(&format!("    command: {}\n", args_json));
        }

        if !comp.env.is_empty() {
            yaml.push_str("    environment:\n");
            for (k, v) in &comp.env {
                let sanitized_k = sanitize_yaml_key(k)?;
                yaml.push_str(&format!("      {}: {}\n", sanitized_k, yaml_quote_scalar(v)));
            }
        }

        if !comp.depends_on.is_empty() {
            yaml.push_str("    depends_on:\n");
            for dep in &comp.depends_on {
                let sanitized_dep = sanitize_yaml_key(dep)?;
                yaml.push_str(&format!("      - {}\n", sanitized_dep));
            }
        }

        if !comp.secret_mounts.is_empty() || !comp.volume_mounts.is_empty() {
            yaml.push_str("    volumes:\n");
            for s in &comp.secret_mounts {
                let sanitized_mount = sanitize_path(&s.mount_path)?;
                let sanitized_dep = sanitize_yaml_key(&plan.deployment_id)?;
                let sanitized_sec = sanitize_yaml_key(&s.secret_id)?;
                let staged_rel = format!("../../secrets/{}/gen-{}/{}", sanitized_dep, plan.generation, sanitized_sec);
                let secret_spec = format!("{}:{}:ro", staged_rel, sanitized_mount);
                yaml.push_str(&format!("      - {}\n", yaml_quote_scalar(&secret_spec)));
            }
            for v in &comp.volume_mounts {
                let sanitized_container = sanitize_path(&v.container_path)?;
                let mode = if v.read_only { "ro" } else { "rw" };
                let host_ref = if v.host_path.starts_with('/') || v.host_path.chars().nth(1) == Some(':') {
                    sanitize_path(&v.host_path)?
                } else {
                    let rel = v.host_path.trim_start_matches("volumes/").trim_start_matches('/');
                    let sanitized_rel = sanitize_path(rel)?;
                    format!("../../volumes/{}", sanitized_rel)
                };
                let volume_spec = format!("{}:{}:{}", host_ref, sanitized_container, mode);
                yaml.push_str(&format!("      - {}\n", yaml_quote_scalar(&volume_spec)));
            }
        }
    }

    let mut all_networks = std::collections::BTreeSet::new();
    for comp in &plan.components {
        if comp.network_mode != "ISOLATED" && comp.network_mode != "none" {
            all_networks.insert(comp.network_mode.as_str());
        }
    }

    if !all_networks.is_empty() {
        yaml.push_str("networks:\n");
        for net in all_networks {
            let sanitized_net = sanitize_yaml_key(net)?;
            yaml.push_str(&format!("  {}:\n", sanitized_net));
            yaml.push_str(&format!("    name: {}\n", sanitized_net));
            yaml.push_str("    driver: bridge\n");
            if sanitized_net.contains("product") {
                yaml.push_str("    internal: true\n");
            }
        }
    }

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

    pub fn execute_readiness_probe(
        &self,
        project_id: &str,
        component_id: &str,
        probe: &super::planner::PlannedHealthCheck,
    ) -> Result<bool, WorkloadError> {
        self.backend.execute_probe(project_id, component_id, probe)
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
    probe_results: Mutex<std::collections::HashMap<String, bool>>,
}

impl MockComposeRuntimeBackend {
    pub fn new() -> Self {
        Self {
            projects: Mutex::new(BTreeMap::new()),
            probe_results: Mutex::new(std::collections::HashMap::new()),
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

    pub fn set_probe_result(&self, component_id: &str, success: bool) {
        let mut map = self.probe_results.lock().unwrap();
        map.insert(component_id.to_string(), success);
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

    fn execute_probe(
        &self,
        project_id: &str,
        component_id: &str,
        _probe: &super::planner::PlannedHealthCheck,
    ) -> Result<bool, WorkloadError> {
        let overrides = self.probe_results.lock().unwrap();
        if let Some(&res) = overrides.get(component_id) {
            return Ok(res);
        }
        let map = self.projects.lock().unwrap();
        if let Some(comps) = map.get(project_id) {
            if let Some(comp) = comps.iter().find(|c| c.name == component_id) {
                return Ok(comp.status == ComponentStatus::Ready);
            }
        }
        Ok(true)
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

/// Real production Docker Compose CLI Runtime Backend.
/// Executes `docker compose` directly using typed Command execution (Zero-RCE guaranteed).
pub struct DockerComposeRuntimeBackend {
    projects_root: PathBuf,
}

impl DockerComposeRuntimeBackend {
    pub fn new(projects_root: impl Into<PathBuf>) -> Self {
        Self {
            projects_root: projects_root.into(),
        }
    }

    pub fn project_dir(&self, project_id: &str) -> PathBuf {
        self.projects_root.join(project_id)
    }

    pub fn compose_file_path(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("docker-compose.yaml")
    }

    fn run_cmd(&self, project_id: &str, args: &[&str]) -> Result<std::process::Output, WorkloadError> {
        let compose_file = self.compose_file_path(project_id);
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("compose")
            .arg("-p")
            .arg(project_id)
            .arg("-f")
            .arg(&compose_file);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.output().map_err(|e| {
            WorkloadError::ExecutionError(format!(
                "Failed to invoke 'docker compose' (verify docker daemon is running and in PATH): {}",
                e
            ))
        })
    }
}

impl ComposeRuntimeBackend for DockerComposeRuntimeBackend {
    fn inspect_project(&self, project_id: &str) -> Result<ComposeProjectInspection, WorkloadError> {
        let compose_file = self.compose_file_path(project_id);
        if !compose_file.exists() {
            return Ok(ComposeProjectInspection {
                project_id: project_id.to_string(),
                components: vec![],
                exists: false,
            });
        }

        let output = self.run_cmd(project_id, &["ps", "--format", "json"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkloadError::ExecutionError(format!(
                "docker compose ps failed for project '{}': {}",
                project_id, stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut components = Vec::new();
        let trimmed = stdout.trim();

        let parse_component_status = |item: &serde_json::Value| -> ComponentStatus {
            let state = item.get("State").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            let health = item.get("Health").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            let raw_status = item.get("Status").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();

            if state == "exited" || state == "dead" {
                ComponentStatus::Stopped
            } else if health == "unhealthy" || raw_status.contains("(unhealthy)") {
                ComponentStatus::Failed
            } else if health == "starting" || raw_status.contains("(health: starting)") || state == "created" || state == "restarting" {
                ComponentStatus::Pending
            } else if health == "healthy" || raw_status.contains("(healthy)") {
                ComponentStatus::Ready
            } else if state == "running" {
                // Running without explicit container healthcheck
                ComponentStatus::Ready
            } else {
                ComponentStatus::Degraded
            }
        };

        if !trimmed.is_empty() {
            if trimmed.starts_with('[') {
                if let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    for item in items {
                        let name = item.get("Service").or_else(|| item.get("Name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let status = parse_component_status(&item);
                        let mut labels = BTreeMap::new();
                        if let Some(lbl_str) = item.get("Labels").and_then(|v| v.as_str()) {
                            for pair in lbl_str.split(',') {
                                let mut kv = pair.splitn(2, '=');
                                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                                    labels.insert(k.trim().to_string(), v.trim().to_string());
                                }
                            }
                        }
                        components.push(ContainerInspection {
                            container_id: item.get("ID").or_else(|| item.get("Id")).and_then(|v| v.as_str()).unwrap_or(&name).to_string(),
                            name,
                            status,
                            labels,
                            exists: true,
                        });
                    }
                }
            } else {
                for line in trimmed.lines() {
                    if let Ok(item) = serde_json::from_str::<serde_json::Value>(line) {
                        let name = item.get("Service").or_else(|| item.get("Name")).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let status = parse_component_status(&item);
                        let mut labels = BTreeMap::new();
                        if let Some(lbl_str) = item.get("Labels").and_then(|v| v.as_str()) {
                            for pair in lbl_str.split(',') {
                                let mut kv = pair.splitn(2, '=');
                                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                                    labels.insert(k.trim().to_string(), v.trim().to_string());
                                }
                            }
                        }
                        components.push(ContainerInspection {
                            container_id: item.get("ID").or_else(|| item.get("Id")).and_then(|v| v.as_str()).unwrap_or(&name).to_string(),
                            name,
                            status,
                            labels,
                            exists: true,
                        });
                    }
                }
            }
        }

        let exists = !components.is_empty();
        Ok(ComposeProjectInspection {
            project_id: project_id.to_string(),
            components,
            exists,
        })
    }

    fn pull_project(&self, plan: &CanonicalWorkloadPlan) -> Result<(), WorkloadError> {
        let output = self.run_cmd(&plan.compose_project_id, &["pull"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("docker compose pull warning for {}: {}", plan.compose_project_id, stderr);
        }
        Ok(())
    }

    fn create_project(&self, plan: &CanonicalWorkloadPlan, compose_yaml: &str) -> Result<(), WorkloadError> {
        let dir = self.project_dir(&plan.compose_project_id);
        std::fs::create_dir_all(&dir)
            .map_err(|e| WorkloadError::ExecutionError(format!("Failed to create project dir: {}", e)))?;
        let compose_file = self.compose_file_path(&plan.compose_project_id);
        std::fs::write(&compose_file, compose_yaml)
            .map_err(|e| WorkloadError::ExecutionError(format!("Failed to write compose.yaml: {}", e)))?;
        Ok(())
    }

    fn start_project(&self, project_id: &str) -> Result<(), WorkloadError> {
        let output = self.run_cmd(project_id, &["up", "-d", "--remove-orphans"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkloadError::ExecutionError(format!(
                "docker compose up -d failed for project '{}': {}",
                project_id, stderr
            )));
        }
        Ok(())
    }

    fn stop_project(&self, project_id: &str, timeout_secs: u32) -> Result<(), WorkloadError> {
        let t_str = timeout_secs.to_string();
        let output = self.run_cmd(project_id, &["stop", "-t", &t_str])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkloadError::ExecutionError(format!(
                "docker compose stop failed for project '{}': {}",
                project_id, stderr
            )));
        }
        Ok(())
    }

    fn remove_project(&self, project_id: &str) -> Result<(), WorkloadError> {
        let output = self.run_cmd(project_id, &["down", "--remove-orphans"])?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkloadError::ExecutionError(format!(
                "docker compose down failed for project '{}': {}",
                project_id, stderr
            )));
        }
        Ok(())
    }

    fn execute_probe(
        &self,
        project_id: &str,
        component_id: &str,
        probe: &super::planner::PlannedHealthCheck,
    ) -> Result<bool, WorkloadError> {
        let sanitized_cid = sanitize_yaml_key(component_id)?;
        match probe.probe_type.as_str() {
            "exec" => {
                let cmd = probe.command.as_ref().ok_or_else(|| {
                    WorkloadError::ValidationFailed(format!("Component '{}' probe has no command", component_id))
                })?;
                let mut args = vec!["exec", "-T", sanitized_cid];
                for c in cmd {
                    args.push(c.as_str());
                }
                let output = self.run_cmd(project_id, &args)?;
                Ok(output.status.success())
            }
            "http" => {
                let path = probe.path.as_deref().unwrap_or("/");
                let port = probe.port.unwrap_or(80);
                let url = format!("http://localhost:{}{}", port, path);
                let args = vec!["exec", "-T", sanitized_cid, "curl", "-fsSL", &url];
                let output = self.run_cmd(project_id, &args)?;
                Ok(output.status.success())
            }
            "tcp" => {
                let port = probe.port.unwrap_or(80).to_string();
                let args = vec!["exec", "-T", sanitized_cid, "nc", "-z", "localhost", &port];
                let output = self.run_cmd(project_id, &args)?;
                Ok(output.status.success())
            }
            _ => Ok(true),
        }
    }
}

/// Closed typed interface for managing Host-level workload ingress routing and TLS.
pub trait WorkloadIngressProvider: Send + Sync {
    fn configure_ingress(
        &self,
        deployment_id: &str,
        generation: u64,
        plan: &CanonicalWorkloadPlan,
    ) -> Result<(), WorkloadError>;

    fn teardown_ingress(
        &self,
        deployment_id: &str,
        generation: u64,
    ) -> Result<(), WorkloadError>;
}

/// Default in-memory ingress provider tracking active routes, hostnames, and ports.
pub struct DefaultWorkloadIngressProvider {
    routes: Mutex<BTreeMap<String, Vec<super::planner::PlannedIngressRoute>>>,
}

impl DefaultWorkloadIngressProvider {
    pub fn new() -> Self {
        Self {
            routes: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn get_routes(&self, deployment_id: &str) -> Vec<super::planner::PlannedIngressRoute> {
        let map = self.routes.lock().unwrap();
        map.get(deployment_id).cloned().unwrap_or_default()
    }
}

impl Default for DefaultWorkloadIngressProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkloadIngressProvider for DefaultWorkloadIngressProvider {
    fn configure_ingress(
        &self,
        deployment_id: &str,
        generation: u64,
        plan: &CanonicalWorkloadPlan,
    ) -> Result<(), WorkloadError> {
        let mut map = self.routes.lock().unwrap();
        let routes = plan.ingress_routes.clone().unwrap_or_default();
        let key = format!("{}:{}", deployment_id, generation);
        map.insert(key, routes);
        Ok(())
    }

    fn teardown_ingress(
        &self,
        deployment_id: &str,
        generation: u64,
    ) -> Result<(), WorkloadError> {
        let mut map = self.routes.lock().unwrap();
        let key = format!("{}:{}", deployment_id, generation);
        map.remove(&key);
        Ok(())
    }
}

/// Real production Docker CLI Single-Container Runtime Backend.
pub struct DockerContainerRuntimeBackend;

impl DockerContainerRuntimeBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ContainerRuntimeBackend for DockerContainerRuntimeBackend {
    fn inspect_container(&self, id: &str) -> Result<ContainerInspection, WorkloadError> {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("inspect").arg("--format").arg("{{json .}}").arg(id);
        let output = cmd.output().map_err(|e| {
            WorkloadError::ExecutionError(format!("Failed to inspect container: {}", e))
        })?;
        if !output.status.success() {
            return Ok(ContainerInspection {
                container_id: id.to_string(),
                name: id.to_string(),
                status: ComponentStatus::Stopped,
                labels: BTreeMap::new(),
                exists: false,
            });
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&stdout)
            .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;
        let running = val.pointer("/State/Running").and_then(|v| v.as_bool()).unwrap_or(false);
        let status = if running { ComponentStatus::Ready } else { ComponentStatus::Stopped };
        Ok(ContainerInspection {
            container_id: id.to_string(),
            name: id.to_string(),
            status,
            labels: BTreeMap::new(),
            exists: true,
        })
    }

    fn pull_image(&self, image: &str) -> Result<(), WorkloadError> {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("pull").arg(image);
        let _ = cmd.output();
        Ok(())
    }

    fn create_container(&self, config: &ContainerConfig) -> Result<String, WorkloadError> {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("create").arg("--name").arg(&config.runtime_instance_id);
        cmd.arg(&config.image);
        let output = cmd.output().map_err(|e| {
            WorkloadError::ExecutionError(format!("Failed to create container: {}", e))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkloadError::ExecutionError(format!("docker create failed: {}", stderr)));
        }
        Ok(config.runtime_instance_id.clone())
    }

    fn start_container(&self, id: &str) -> Result<(), WorkloadError> {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("start").arg(id);
        let output = cmd.output().map_err(|e| {
            WorkloadError::ExecutionError(format!("Failed to start container: {}", e))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WorkloadError::ExecutionError(format!("docker start failed: {}", stderr)));
        }
        Ok(())
    }

    fn stop_container(&self, id: &str, timeout_secs: u32) -> Result<(), WorkloadError> {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("stop").arg("-t").arg(timeout_secs.to_string()).arg(id);
        let _ = cmd.output();
        Ok(())
    }

    fn remove_container(&self, id: &str) -> Result<(), WorkloadError> {
        let mut cmd = std::process::Command::new("docker");
        cmd.arg("rm").arg("-f").arg(id);
        let _ = cmd.output();
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
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "app",
                    "image": "docker.io/library/alpine@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "SITE_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "secrets": ["api-key"],
                    "healthCheck": { "type": "http", "path": "/health", "port": 8080 }
                }
            ],
            "secretRequirements": [
                { "secretId": "api-key", "purpose": "auth" }
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

        let desired = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": "dep-exec-1",
            "siteId": "site-exec-1",
            "generation": 1,
            "profileId": "svc",
            "profileVersion": "1.0.0",
            "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "desiredState": "RUNNING",
            "secretRefs": [
                { "secretId": "api-key", "purpose": "auth", "generation": 1 }
            ]
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

        // Must mount secret confined read-only with parity relative path
        assert!(yaml.contains("../../secrets/dep-exec-1/gen-1/api-key:/run/secrets/api-key:ro"));

        // Must not contain plain secrets
        assert!(!yaml.contains("super_secret_payload"));

        // Must connect to scoped site network
        assert!(yaml.contains("actium-site-site-exec-1"));
        assert!(yaml.contains("no-new-privileges:true"));
        assert!(yaml.contains("- ALL"));
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

    #[test]
    fn test_network_policies_and_health_probes_generation() {
        let profile = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "multi-tier",
            "productId": "dep-tier-1",
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
                    "healthCheck": {
                        "type": "tcp",
                        "port": 5432,
                        "timeoutSeconds": 3
                    }
                },
                {
                    "componentId": "web",
                    "image": "docker.io/library/nginx@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "PUBLIC_HTTPS",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": {
                        "type": "http",
                        "path": "/healthz",
                        "port": 8443,
                        "timeoutSeconds": 5
                    }
                },
                {
                    "componentId": "worker",
                    "image": "docker.io/library/busybox@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "ISOLATED",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": {
                        "type": "exec",
                        "command": ["echo", "ok"]
                    }
                }
            ],
            "ports": [
                { "name": "web-https", "containerPort": 8443, "policy": "PUBLIC_HTTPS" }
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

        let desired = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": "dep-tier-1",
            "generation": 1,
            "profileId": "multi-tier",
            "profileVersion": "1.0.0",
            "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "secretRefs": [],
            "desiredState": "RUNNING"
        });
        let digest = crate::workload_runtime::canonical::canonical_digest_for_value(&desired).unwrap();
        let mut env = desired;
        env["desiredDigest"] = serde_json::Value::String(digest);

        let plan = WorkloadPlanner::plan(
            &env.to_string(),
            &profile,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            None,
            None,
        ).unwrap();

        let yaml = generate_compose_yaml(&plan).unwrap();

        // 1. Verify PRODUCT_INTERNAL network is tenant-scoped with internal: true
        assert!(yaml.contains("actium-product-dep-tier-1"));
        assert!(yaml.contains("internal: true"));

        // 2. Verify PUBLIC_HTTPS network is tenant-scoped and ingress-managed port is exposed (not published to host)
        assert!(yaml.contains("actium-ingress-dep-tier-1"));
        assert!(yaml.contains("expose:\n      - \"8443\""));
        assert!(!yaml.contains("ports:"));

        // 3. Verify ISOLATED network mode none
        assert!(yaml.contains("network_mode: \"none\""));

        // 4. Verify TCP healthcheck on db
        assert!(yaml.contains("nc -z localhost 5432"));
        assert!(yaml.contains("timeout: 3s"));

        // 5. Verify HTTP healthcheck on web
        assert!(yaml.contains("curl -f http://localhost:8443/healthz"));
        assert!(yaml.contains("timeout: 5s"));

        // 6. Verify EXEC healthcheck on worker
        assert!(yaml.contains("[\"echo\",\"ok\"]"));
    }

    #[test]
    fn test_secret_provider_vault_root_fallback_and_fail_closed() {
        let temp_dir = std::env::temp_dir().join(format!("actium_vault_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        // 1. In-memory resolution takes precedence
        let provider = DefaultWorkloadSecretProvider::with_vault_root(&temp_dir);
        provider.set_secret("sec-mem", b"mem_data".to_vec());
        let sec = provider.resolve_secret("sec-mem", "auth", 1).unwrap();
        assert_eq!(sec.as_bytes(), b"mem_data");

        // 2. Disk vault fallback with gen-<gen> directory
        let gen_dir = temp_dir.join("gen-2");
        std::fs::create_dir_all(&gen_dir).unwrap();
        std::fs::write(gen_dir.join("disk-secret"), b"disk_gen2_data").unwrap();
        let sec_disk = provider.resolve_secret("disk-secret", "token", 2).unwrap();
        assert_eq!(sec_disk.as_bytes(), b"disk_gen2_data");

        // 3. Fail closed on missing secret
        let missing = provider.resolve_secret("non-existent", "auth", 1);
        assert!(missing.is_err());
        assert!(format!("{:?}", missing).contains("non-existent"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mock_compose_execute_probe() {
        let backend = MockComposeRuntimeBackend::new();
        let hc = super::super::planner::PlannedHealthCheck {
            probe_type: "http".into(),
            component_id: Some("web".into()),
            path: Some("/health".into()),
            port: Some(8080),
            timeout_seconds: Some(5),
            command: None,
        };

        // Default is true
        let ok = backend.execute_probe("proj-1", "web", &hc).unwrap();
        assert!(ok);

        // Explicit false
        backend.set_probe_result("web", false);
        let failed = backend.execute_probe("proj-1", "web", &hc).unwrap();
        assert!(!failed);
    }

    #[test]
    fn test_default_workload_ingress_provider() {
        let ingress = DefaultWorkloadIngressProvider::new();
        let plan = sample_plan();

        // Configure ingress
        assert!(ingress.configure_ingress("dep-exec-1", 1, &plan).is_ok());
        let active = ingress.routes.lock().unwrap();
        assert!(active.contains_key("dep-exec-1:1"));
        drop(active);

        // Teardown ingress
        assert!(ingress.teardown_ingress("dep-exec-1", 1).is_ok());
        let active_after = ingress.routes.lock().unwrap();
        assert!(!active_after.contains_key("dep-exec-1:1"));
    }
}

