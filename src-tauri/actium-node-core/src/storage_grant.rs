use crate::EnrolledAuthority;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write, path::{Path, PathBuf}};
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
    /// Relative path requested by the capability, retained for Center and
    /// approval binding. The canonical path remains the effective identity.
    #[serde(default)] pub subpath: String,
    #[serde(default)] pub filesystem: String,
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
    #[serde(default)] pub report_generation: u64,
    #[serde(default)] pub snapshot_hash: String,
    #[serde(default)] pub applied_at_unix_seconds: Option<u64>,
    #[serde(default)] pub confirmed_at_unix_seconds: Option<u64>,
    /// Public metadata of the Center approval that was verified before this
    /// grant was applied.  Private signing material never enters this model.
    #[serde(default)] pub approval_signer_key_id: Option<String>,
    #[serde(default)] pub approval_signer_fingerprint: Option<String>,
    #[serde(default)] pub approval_verified_at_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageGrantPreflight {
    pub intent_id: String,
    pub deployment_id: String,
    pub capability: String,
    pub canonical_mountpoint: String,
    pub canonical_path: String,
    #[serde(default)] pub subpath: String,
    #[serde(default)] pub filesystem: String,
    pub filesystem_uuid: String,
    pub policy_hash: String,
    #[serde(default)] pub client_id: Option<String>,
    #[serde(default)] pub organization_id: Option<String>,
    #[serde(default)] pub site_id: Option<String>,
    #[serde(default)] pub host_id: Option<String>,
    #[serde(default)] pub host_installation_id: Option<String>,
    #[serde(default)] pub idempotency_key: Option<String>,
    #[serde(default)] pub report_generation: u64,
    #[serde(default)] pub snapshot_hash: String,
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
    #[serde(default)] pub report_generation: u64,
    #[serde(default)] pub snapshot_hash: String,
}

/// Return the newest observed grant per intent/grant identity.  State files
/// can contain historical rollback/retry rows; readiness must evaluate only
/// the effective row and never let an old rollback poison the Host forever.
pub fn latest_effective_grants(values: &[StorageGrant]) -> Vec<StorageGrant> {
    let mut seen = BTreeMap::<String, ()>::new();
    values
        .iter()
        .rev()
        .filter_map(|value| {
            let key = value
                .intent_id
                .clone()
                .unwrap_or_else(|| format!("grant:{}", value.grant_id));
            if seen.insert(key, ()).is_none() { Some(value.clone()) } else { None }
        })
        .collect()
}

/// Return the newest observed transaction per intent/transaction identity.
pub fn latest_effective_transactions(values: &[StorageTransaction]) -> Vec<StorageTransaction> {
    let mut seen = BTreeMap::<String, ()>::new();
    values
        .iter()
        .rev()
        .filter_map(|value| {
            let key = value
                .intent_id
                .clone()
                .unwrap_or_else(|| format!("transaction:{}", value.transaction_id));
            if seen.insert(key, ()).is_none() { Some(value.clone()) } else { None }
        })
        .collect()
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
    /// Persist every capability intent. The legacy singular file is still
    /// read below so upgrades do not discard an in-flight request.
    pub fn save_preflight(&self, preflight: &StorageGrantPreflight) -> Result<(), String> {
        let mut all = self.preflights()?;
        if let Some(existing) = all.iter_mut().find(|value| value.intent_id == preflight.intent_id) {
            *existing = preflight.clone();
        } else {
            all.push(preflight.clone());
        }
        self.write("preflights.json", &all)
    }
    pub fn preflights(&self) -> Result<Vec<StorageGrantPreflight>, String> {
        let path = self.file("preflights.json");
        if path.exists() {
            return serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string());
        }
        let legacy = self.file("preflight.json");
        if !legacy.exists() { return Ok(vec![]); }
        Ok(vec![serde_json::from_slice(&fs::read(legacy).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?])
    }
    pub fn preflight(&self) -> Result<Option<StorageGrantPreflight>, String> {
        Ok(self.preflights()?.into_iter().max_by_key(|value| value.created_at_unix_seconds))
    }
    pub fn save_transaction(&self, transaction: &StorageTransaction) -> Result<(), String> {
        let mut all = self.transactions()?;
        if let Some(existing) = all.iter_mut().find(|value| value.transaction_id == transaction.transaction_id) {
            *existing = transaction.clone();
        } else {
            all.push(transaction.clone());
        }
        self.write("transactions.json", &all)
    }
    pub fn transactions(&self) -> Result<Vec<StorageTransaction>, String> {
        let path = self.file("transactions.json");
        if path.exists() {
            return serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string());
        }
        let legacy = self.file("transaction.json");
        if !legacy.exists() { return Ok(vec![]); }
        Ok(vec![serde_json::from_slice(&fs::read(legacy).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?])
    }
    pub fn transaction(&self) -> Result<Option<StorageTransaction>, String> {
        Ok(self.transactions()?.into_iter().max_by_key(|value| value.started_at_unix_seconds))
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

const NON_GRANTABLE_FILESYSTEMS: &[&str] = &[
    "tmpfs", "overlay", "nsfs", "sysfs", "proc", "procfs", "cgroup", "cgroup2",
    "devpts", "devtmpfs", "squashfs", "ramfs", "pstore", "debugfs", "tracefs", "bpf",
    "binfmt_misc", "fuse.portal", "fusectl", "rpc_pipefs", "configfs", "efivarfs", "securityfs",
    "hugetlbfs", "mqueue", "autofs",
];

fn normalized_absolute_mountpoint(target: &str) -> Option<PathBuf> {
    if !target.starts_with('/') || target.contains("//") { return None; }
    let mut normalized = PathBuf::from("/");
    for component in target.split('/').filter(|part| !part.is_empty()) {
        if component == "." || component == ".." { return None; }
        normalized.push(component);
    }
    Some(normalized)
}

/// Parse the complete `findmnt --json` tree. `findmnt` nests mounts below
/// their parent filesystem, so callers must not only inspect `filesystems`.
/// Invalid UUIDs and pseudo-filesystems are rejected before a mount can be
/// offered to the grant flow.
pub fn discover_mounts_from_findmnt(value: &serde_json::Value, observed: u64) -> Vec<StorageMount> {
    let mut candidates: BTreeMap<String, StorageMount> = BTreeMap::new();
    fn visit(node: &serde_json::Value, observed: u64, candidates: &mut BTreeMap<String, StorageMount>) {
        let target = node.get("target").and_then(serde_json::Value::as_str).unwrap_or("");
        if let Some(normalized) = normalized_absolute_mountpoint(target) {
            let canonical = fs::canonicalize(&normalized).unwrap_or(normalized);
            let filesystem = node.get("fstype").and_then(serde_json::Value::as_str).unwrap_or("").trim().to_ascii_lowercase();
            if !filesystem.is_empty() && !NON_GRANTABLE_FILESYSTEMS.iter().any(|item| *item == filesystem) {
                let uuid = node.get("uuid").and_then(serde_json::Value::as_str).map(str::trim).filter(|item| !item.is_empty()).map(str::to_string);
                let uuid_valid = uuid.as_deref().map(validate_filesystem_uuid).map(|result| result.is_ok()).unwrap_or(true);
                if uuid_valid {
                    let options = node.get("options").and_then(serde_json::Value::as_str).unwrap_or("");
                    let readonly = options.split(',').any(|option| option.trim() == "ro");
                    let mount = StorageMount {
                        mountpoint: canonical.to_string_lossy().into_owned(),
                        source: node.get("source").and_then(serde_json::Value::as_str).unwrap_or("").to_string(),
                        filesystem_uuid: uuid,
                        label: node.get("label").and_then(serde_json::Value::as_str).map(str::to_string),
                        filesystem,
                        readonly,
                        total_bytes: node.get("size").and_then(serde_json::Value::as_u64).unwrap_or(0),
                        free_bytes: node.get("avail").and_then(serde_json::Value::as_u64).unwrap_or(0),
                        root: canonical == Path::new("/"),
                        observed_at_unix_seconds: observed,
                        report_generation: observed,
                        freshness_state: "fresh".to_string(),
                    };
                    let key = mount.mountpoint.clone();
                    let score = |item: &StorageMount| usize::from(!item.source.is_empty()) + usize::from(item.filesystem_uuid.is_some());
                    if candidates.get(&key).map(score).unwrap_or(0) < score(&mount) { candidates.insert(key, mount); }
                }
            }
        }
        // A pseudo filesystem can still be a parent in findmnt's tree. Walk
        // its children regardless of whether the parent itself is grantable.
        if let Some(children) = node.get("children").and_then(serde_json::Value::as_array) {
            for child in children { visit(child, observed, candidates); }
        }
    }
    if let Some(filesystems) = value.get("filesystems").and_then(serde_json::Value::as_array) {
        for filesystem in filesystems { visit(filesystem, observed, &mut candidates); }
    }
    candidates.into_values().collect()
}

pub fn policy_hash(capability: &str, mount: &str, path: &str, uuid: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [capability, mount, path, uuid] { hasher.update(part.as_bytes()); hasher.update([0]); }
    format!("{:x}", hasher.finalize())
}

/// Stable content hash for a discovery snapshot. Volatile timestamps and
/// freshness markers are intentionally excluded so repeating discovery with
/// unchanged mount identity produces the same snapshot identity.
pub fn discovery_snapshot_hash(mounts: &[StorageMount]) -> String {
    let canonical: Vec<_> = mounts.iter().map(|mount| serde_json::json!({
        "mountpoint": mount.mountpoint,
        "source": mount.source,
        "filesystem_uuid": mount.filesystem_uuid,
        "label": mount.label,
        "filesystem": mount.filesystem,
        "readonly": mount.readonly,
        "total_bytes": mount.total_bytes,
        "free_bytes": mount.free_bytes,
        "root": mount.root,
    })).collect();
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
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
            subpath: "telemetry".into(), filesystem: "ext4".into(),
            filesystem_uuid: "550e8400-e29b-41d4-a716-446655440000".into(), binding_epoch: 1,
            state: "applied".into(), degraded_reason: None, client_id: None, organization_id: None,
            site_id: None, host_id: None, host_installation_id: None, deployment_id: Some("deployment".into()),
            intent_id: None, idempotency_key: None, transaction_id: None, policy_hash: None, report_generation: 1, snapshot_hash: "snapshot".into(), applied_at_unix_seconds: None, confirmed_at_unix_seconds: None,
            approval_signer_key_id: None, approval_signer_fingerprint: None, approval_verified_at_unix_seconds: None,
        };
        store.save_grants(std::slice::from_ref(&grant)).unwrap();
        store.save_transaction(&StorageTransaction {
            transaction_id: "t".into(), grant_id: "g".into(), phase: "apply".into(), previous_dropin: None,
            target_dropin: render_dropin(std::slice::from_ref(&grant)), error: None, intent_id: None,
            idempotency_key: None, started_at_unix_seconds: 1, applied_at_unix_seconds: None,
            health_at_unix_seconds: None, rollback_at_unix_seconds: None, rollback_reason: None,
            report_generation: 1, snapshot_hash: "snapshot".into(),
        }).unwrap();
        assert!(canonical_path(&mount, "../x").is_err());
        assert!(canonical_path(&mount, "/etc").is_err());
        assert_eq!(validate_filesystem_uuid(&grant.filesystem_uuid), Ok(()));
        assert!(validate_filesystem_uuid("not-a-uuid").is_err());
        write_dropin(&root, "actium-node-supervisor", &store.grants().unwrap()).unwrap();
        assert!(fs::read_to_string(root.join("etc/systemd/system/actium-node-supervisor.service.d/50-storage-grants.conf")).unwrap().contains("ReadWritePaths="));
        let _ = fs::remove_dir_all(root);
    }

    fn grant(id: &str, intent: &str, state: &str) -> StorageGrant {
        StorageGrant {
            grant_id: id.into(), capability: "telemetry".into(), canonical_mountpoint: "/srv/actium-lab".into(),
            canonical_path: "/srv/actium-lab/telemetry".into(), subpath: "telemetry".into(), filesystem: "ext4".into(),
            filesystem_uuid: "550e8400-e29b-41d4-a716-446655440000".into(), binding_epoch: 1, state: state.into(), degraded_reason: None,
            client_id: None, organization_id: Some("org".into()), site_id: Some("site".into()), host_id: Some("host".into()),
            host_installation_id: Some("installation".into()), deployment_id: Some("deployment".into()), intent_id: Some(intent.into()),
            idempotency_key: None, transaction_id: Some(format!("tx-{id}")), policy_hash: None, report_generation: 1,
            snapshot_hash: "snapshot".into(), applied_at_unix_seconds: None, confirmed_at_unix_seconds: None,
            approval_signer_key_id: Some("center-key".into()), approval_signer_fingerprint: Some("sha256:test".into()),
            approval_verified_at_unix_seconds: Some(10),
        }
    }

    #[test]
    fn latest_effective_state_ignores_historical_rollback() {
        let values = vec![grant("g-1", "intent-1", "rollback"), grant("g-2", "intent-1", "applied")];
        let effective = latest_effective_grants(&values);
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].state, "applied");
        assert_eq!(effective[0].approval_signer_key_id.as_deref(), Some("center-key"));
    }

    #[test]
    fn latest_effective_transactions_keeps_phase_distinctions() {
        let base = |phase: &str| StorageTransaction {
            transaction_id: format!("tx-{phase}"), grant_id: "g".into(), phase: phase.into(), previous_dropin: None,
            target_dropin: String::new(), error: None, intent_id: Some("intent-1".into()), idempotency_key: None,
            started_at_unix_seconds: 1, applied_at_unix_seconds: None, health_at_unix_seconds: None,
            rollback_at_unix_seconds: None, rollback_reason: None, report_generation: 1, snapshot_hash: "snapshot".into(),
        };
        let values = vec![base("pending"), base("approved"), base("applied"), base("committed")];
        let effective = latest_effective_transactions(&values);
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].phase, "committed");
    }

    #[cfg(unix)]
    #[test]
    fn findmnt_discovers_nested_rw_mounts_and_filters_pseudo_filesystems() {
        let root = std::env::temp_dir().join(format!("actium-findmnt-{}", Uuid::new_v4()));
        let lab = root.join("srv/actium-lab");
        fs::create_dir_all(&lab).unwrap();
        let alias = root.join("srv/actium");
        #[cfg(unix)] std::os::unix::fs::symlink(&lab, &alias).unwrap();
        let external_uuid = "e0aca9ce-07a5-4d89-aa7f-cac467879f0a";
        let fixture = serde_json::json!({"filesystems":[
            {"target":root,"source":"/dev/sda1","fstype":"ext4","options":"rw,relatime,errors=remount-ro","uuid":"a9a32d2d-0257-4fac-a16d-0ab40aa3f5a5","size":100,"avail":50,"children":[
                {"target":lab,"source":"/dev/sdb1","fstype":"ext4","options":"rw,relatime","uuid":external_uuid,"label":"ACTIUM_LAB","size":200,"avail":150,"children":[
                    {"target":lab.join("overlay"),"source":"overlay","fstype":"overlay","options":"rw","children":[]}
                ]},
                {"target":alias,"source":"/dev/sdb1","fstype":"ext4","options":"rw","uuid":external_uuid,"label":"ACTIUM_LAB","size":200,"avail":150,"children":[]}
            ]}
        ]});
        let mounts = discover_mounts_from_findmnt(&fixture, 42);
        let canonical_lab = fs::canonicalize(&lab).unwrap().to_string_lossy().into_owned();
        assert!(mounts.iter().any(|mount| mount.mountpoint == fs::canonicalize(&root).unwrap().to_string_lossy() && !mount.readonly));
        let labs: Vec<_> = mounts.iter().filter(|mount| mount.mountpoint == canonical_lab).collect();
        assert_eq!(labs.len(), 1);
        assert_eq!(labs[0].filesystem_uuid.as_deref(), Some(external_uuid));
        assert_eq!(labs[0].label.as_deref(), Some("ACTIUM_LAB"));
        assert_eq!(labs[0].filesystem, "ext4");
        assert!(!mounts.iter().any(|mount| mount.filesystem == "overlay"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn findmnt_missing_options_are_not_readonly() {
        let fixture = serde_json::json!({"filesystems":[{"target":"/","source":"/dev/sda1","fstype":"ext4","uuid":"a9a32d2d-0257-4fac-a16d-0ab40aa3f5a5","children":[]}]});
        let mounts = discover_mounts_from_findmnt(&fixture, 1);
        assert_eq!(mounts.len(), 1);
        assert!(!mounts[0].readonly);
    }

    #[test]
    fn findmnt_walks_children_and_keeps_external_identity() {
        let fixture = serde_json::json!({"filesystems":[{"target":"/","source":"/dev/sda1","fstype":"ext4","options":"rw,relatime,errors=remount-ro","uuid":"a9a32d2d-0257-4fac-a16d-0ab40aa3f5a5","children":[{"target":"/srv/actium-lab","source":"/dev/sdb1","fstype":"ext4","options":"rw,relatime","uuid":"e0aca9ce-07a5-4d89-aa7f-cac467879f0a","label":"ACTIUM_LAB","size":200,"avail":150,"children":[{"target":"/srv/actium-lab/workload","source":"overlay","fstype":"overlay","options":"rw"}]}]}]});
        let mounts = discover_mounts_from_findmnt(&fixture, 7);
        let external = mounts.iter().find(|mount| mount.mountpoint.replace('\\', "/").ends_with("/srv/actium-lab")).expect("nested mount");
        assert!(!mounts.iter().any(|mount| mount.filesystem == "overlay"));
        assert!(!mounts.iter().any(|mount| mount.mountpoint == "/" && mount.readonly));
        assert_eq!(external.filesystem_uuid.as_deref(), Some("e0aca9ce-07a5-4d89-aa7f-cac467879f0a"));
        assert_eq!(external.label.as_deref(), Some("ACTIUM_LAB"));
    }

    #[test]
    fn findmnt_filters_kernel_and_portal_pseudo_filesystems() {
        let fixture = serde_json::json!({"filesystems":[
            {"target":"/","source":"/dev/sda1","fstype":"ext4","options":"rw","uuid":"a9a32d2d-0257-4fac-a16d-0ab40aa3f5a5","children":[
                {"target":"/sys/fs/bpf","source":"bpf","fstype":"bpf","options":"rw"},
                {"target":"/proc/sys/fs/binfmt_misc","source":"binfmt_misc","fstype":"binfmt_misc","options":"rw"},
                {"target":"/run/user/1000/doc","source":"portal","fstype":"fuse.portal","options":"rw"}
            ]}
        ]});
        let mounts = discover_mounts_from_findmnt(&fixture, 1);
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].source, "/dev/sda1");
        assert_eq!(mounts[0].filesystem, "ext4");
    }

    #[test]
    fn discovery_snapshot_hash_ignores_volatile_fields() {
        let mount = StorageMount {
            mountpoint: "/srv/actium-lab".into(), source: "/dev/sdb1".into(),
            filesystem_uuid: Some("e0aca9ce-07a5-4d89-aa7f-cac467879f0a".into()),
            label: Some("ACTIUM_LAB".into()), filesystem: "ext4".into(), readonly: false,
            total_bytes: 200, free_bytes: 150, root: false, observed_at_unix_seconds: 1,
            report_generation: 1, freshness_state: "fresh".into(),
        };
        let mut changed = mount.clone();
        changed.observed_at_unix_seconds = 999;
        changed.report_generation = 999;
        changed.freshness_state = "stale".into();
        assert_eq!(discovery_snapshot_hash(&[mount]), discovery_snapshot_hash(&[changed]));
    }
}
