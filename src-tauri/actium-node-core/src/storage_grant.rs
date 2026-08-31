use crate::EnrolledAuthority;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::{Path, PathBuf}};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn unknown_freshness() -> String { "unknown".to_string() }
fn pending_state() -> String { "pending".to_string() }

/// Snapshot emitted by real Supervisor/Manager discovery.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageMount {
    pub mountpoint: String,
    pub source: String,
    pub filesystem_uuid: Option<String>,
    pub label: Option<String>,
    pub filesystem: String,
    pub readonly: bool,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub root: bool,
    #[serde(default)] pub observed_at_unix_seconds: u64,
    #[serde(default)] pub report_generation: u64,
    #[serde(default = "unknown_freshness")] pub freshness_state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentState {
    pub enrolled: Option<EnrolledAuthority>,
    pub consumed_nonces: Vec<String>,
    pub consumed_jtis: Vec<String>,
}

/// deployment_id is still the Node identity. Optional fields only exist so
/// old on-disk grants can be read; new grants are always populated by the
/// Supervisor from the enrolled authority and preflight binding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageGrant {
    pub grant_id: String,
    pub capability: String,
    pub canonical_mountpoint: String,
    pub canonical_path: String,
    pub filesystem_uuid: String,
    pub binding_epoch: u64,
    #[serde(default = "pending_state")] pub state: String,
    pub degraded_reason: Option<String>,
    #[serde(default)] pub client_id: Option<String>,
    #[serde(default)] pub organization_id: Option<String>,
    #[serde(default)] pub site_id: Option<String>,
    #[serde(default)] pub host_id: Option<String>,
    #[serde(default)] pub host_installation_id: Option<String>,
    #[serde(default)] pub deployment_id: Option<String>,
    #[serde(default)] pub intent_id: Option<String>,
    #[serde(default)] pub idempotency_key: Option<String>,
    #[serde(default)] pub transaction_id: Option<String>,
    #[serde(default)] pub policy_hash: Option<String>,
    #[serde(default)] pub applied_at_unix_seconds: Option<u64>,
    #[serde(default)] pub confirmed_at_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageGrantPreflight {
    pub intent_id: String,
    pub deployment_id: String,
    pub capability: String,
    pub canonical_mountpoint: String,
    pub canonical_path: String,
    pub filesystem_uuid: String,
    pub policy_hash: String,
    #[serde(default)] pub client_id: Option<String>,
    #[serde(default)] pub organization_id: Option<String>,
    #[serde(default)] pub site_id: Option<String>,
    #[serde(default)] pub host_id: Option<String>,
    #[serde(default)] pub host_installation_id: Option<String>,
    #[serde(default)] pub idempotency_key: Option<String>,
    #[serde(default)] pub created_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageTransaction {
    pub transaction_id: String,
    pub grant_id: String,
    pub phase: String,
    pub previous_dropin: Option<String>,
    pub target_dropin: String,
    pub error: Option<String>,
    #[serde(default)] pub intent_id: Option<String>,
    #[serde(default)] pub idempotency_key: Option<String>,
    #[serde(default)] pub started_at_unix_seconds: u64,
    #[serde(default)] pub applied_at_unix_seconds: Option<u64>,
    #[serde(default)] pub health_at_unix_seconds: Option<u64>,
    #[serde(default)] pub rollback_at_unix_seconds: Option<u64>,
    #[serde(default)] pub rollback_reason: Option<String>,
}

pub struct StorageGrantStore { root: PathBuf }
impl StorageGrantStore {
    pub fn open(root: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        #[cfg(unix)] fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        Ok(Self { root })
    }
    fn file(&self, name: &str) -> PathBuf { self.root.join(name) }
    fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<(), String> {
        let path = self.file(name);
        let temporary = path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
        let mut file = fs::File::create(&temporary).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        #[cfg(unix)] fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        fs::rename(temporary, path).map_err(|e| e.to_string())
    }
    pub fn enrollment(&self) -> Result<EnrollmentState, String> {
        let path = self.file("enrollment.json");
        if !path.exists() { return Ok(EnrollmentState { enrolled: None, consumed_nonces: vec![], consumed_jtis: vec![] }); }
        let mut state: EnrollmentState = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if state.consumed_jtis.is_empty() { state.consumed_jtis = vec![]; }
        Ok(state)
    }
    pub fn save_enrollment(&self, state: &EnrollmentState) -> Result<(), String> { self.write("enrollment.json", state) }
    pub fn grants(&self) -> Result<Vec<StorageGrant>, String> {
        let path = self.file("grants.json");
        if !path.exists() { return Ok(vec![]); }
        serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
    }
    pub fn save_grants(&self, grants: &[StorageGrant]) -> Result<(), String> { self.write("grants.json", &grants) }
    pub fn save_preflight(&self, preflight: &StorageGrantPreflight) -> Result<(), String> { self.write("preflight.json", preflight) }
    pub fn preflight(&self) -> Result<Option<StorageGrantPreflight>, String> {
        let path = self.file("preflight.json");
        if !path.exists() { return Ok(None); }
        Ok(Some(serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?))
    }
    pub fn save_transaction(&self, transaction: &StorageTransaction) -> Result<(), String> { self.write("transaction.json", transaction) }
    pub fn transaction(&self) -> Result<Option<StorageTransaction>, String> {
        let path = self.file("transaction.json");
        if !path.exists() { return Ok(None); }
        Ok(Some(serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?))
    }
}

/// Resolve a grant path against the real mount. Absolute subpaths, traversal,
/// NULs and symlink escapes are rejected; the canonical result is the identity.
pub fn canonical_path(mount: &Path, subpath: &str) -> Result<PathBuf, String> {
    if subpath.is_empty() || subpath.contains('\0') || Path::new(subpath).is_absolute() { return Err("STORAGE_GRANT_PATH_INVALID".into()); }
    if subpath.split('/').any(|part| part == "..") { return Err("STORAGE_GRANT_PATH_TRAVERSAL".into()); }
    let real_mount = fs::canonicalize(mount).map_err(|_| "STORAGE_GRANT_MOUNT_ABSENT")?;
    let candidate = real_mount.join(subpath);
    let mut existing = candidate.as_path();
    let mut suffix = Vec::new();
    while !existing.exists() {
        suffix.push(existing.file_name().ok_or("STORAGE_GRANT_PATH_INVALID")?.to_owned());
        existing = existing.parent().ok_or("STORAGE_GRANT_PARENT_UNAVAILABLE")?;
    }
    let mut resolved = fs::canonicalize(existing).map_err(|_| "STORAGE_GRANT_PARENT_UNAVAILABLE")?;
    for component in suffix.iter().rev() { resolved.push(component); }
    if !resolved.starts_with(&real_mount) { return Err("STORAGE_GRANT_PATH_ESCAPE".into()); }
    Ok(resolved)
}

pub fn validate_filesystem_uuid(value: &str) -> Result<(), String> {
    Uuid::parse_str(value).map(|_| ()).map_err(|_| "STORAGE_GRANT_UUID_INVALID".into())
}

pub fn policy_hash(capability: &str, mount: &str, path: &str, uuid: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [capability, mount, path, uuid] { hasher.update(part.as_bytes()); hasher.update([0]); }
    format!("{:x}", hasher.finalize())
}

pub fn render_dropin(grants: &[StorageGrant]) -> String {
    let mut output = String::from("# Managed by Actium Node Supervisor; exact grants only\n[Service]\n");
    for grant in grants.iter().filter(|grant| matches!(grant.state.as_str(), "approved" | "applied" | "committed")) {
        output.push_str("ReadWritePaths=");
        output.push_str(&grant.canonical_path);
        output.push('\n');
    }
    output
}

pub fn write_dropin(root: &Path, service: &str, grants: &[StorageGrant]) -> Result<(), String> {
    if service.is_empty() || service.contains('/') || service.contains('\\') { return Err("STORAGE_DROPIN_SERVICE_INVALID".into()); }
    let directory = root.join("etc/systemd/system").join(format!("{service}.service.d"));
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let path = directory.join("50-storage-grants.conf");
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, render_dropin(grants)).map_err(|e| e.to_string())?;
    fs::rename(temporary, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transaction_and_path_guards() {
        let root = std::env::temp_dir().join(format!("actium-sg-{}", Uuid::new_v4()));
        let mount = root.join("mount");
        fs::create_dir_all(mount.join("telemetry")).unwrap();
        let store = StorageGrantStore::open(root.join("state")).unwrap();
        let grant = StorageGrant {
            grant_id: "g".into(), capability: "telemetry".into(),
            canonical_mountpoint: mount.to_string_lossy().into(), canonical_path: mount.join("telemetry").to_string_lossy().into(),
            filesystem_uuid: "550e8400-e29b-41d4-a716-446655440000".into(), binding_epoch: 1,
            state: "applied".into(), degraded_reason: None, client_id: None, organization_id: None,
            site_id: None, host_id: None, host_installation_id: None, deployment_id: Some("deployment".into()),
            intent_id: None, idempotency_key: None, transaction_id: None, policy_hash: None, applied_at_unix_seconds: None, confirmed_at_unix_seconds: None,
        };
        store.save_grants(std::slice::from_ref(&grant)).unwrap();
        store.save_transaction(&StorageTransaction {
            transaction_id: "t".into(), grant_id: "g".into(), phase: "apply".into(), previous_dropin: None,
            target_dropin: render_dropin(std::slice::from_ref(&grant)), error: None, intent_id: None,
            idempotency_key: None, started_at_unix_seconds: 1, applied_at_unix_seconds: None,
            health_at_unix_seconds: None, rollback_at_unix_seconds: None, rollback_reason: None,
        }).unwrap();
        assert!(canonical_path(&mount, "../x").is_err());
        assert!(canonical_path(&mount, "/etc").is_err());
        assert_eq!(validate_filesystem_uuid(&grant.filesystem_uuid), Ok(()));
        assert!(validate_filesystem_uuid("not-a-uuid").is_err());
        write_dropin(&root, "actium-node-supervisor", &store.grants().unwrap()).unwrap();
        assert!(fs::read_to_string(root.join("etc/systemd/system/actium-node-supervisor.service.d/50-storage-grants.conf")).unwrap().contains("ReadWritePaths="));
        let _ = fs::remove_dir_all(root);
    }
}
