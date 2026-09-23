//! Durable public Trust Fabric state owned by Supervisor.
//!
//! This store contains no private material. An absent store is a supported
//! first-trust state; a present store is verified before it is accepted and
//! cannot move backwards in trust epoch.

use actium_node_core::{center_authority_transition_digest, default_lifecycle_channel, normalize_lifecycle_channel, trust_bundle_digest, unix_now, validate_successor_activation_lineage, verify_center_authority_transition, verify_signed_trust_bundle, verify_signed_trust_bundle_with_bootstrap, CenterAuthorityTransitionV1, HostTrustActivationReceiptV1, HostTrustBundleRefreshRequestV1, ProductTrustRoot, SignedTrustBundle, AuthorityLifecyclePhase, HOST_TRUST_CONVERGENCE_CONTRACT};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustStoreFile {
    #[serde(alias = "schema")]
    schema_version: u8,
    #[serde(default = "default_lifecycle_channel")]
    channel: String,
    #[serde(rename = "trustEpoch", alias = "currentEpoch")]
    current_epoch: u64,
    #[serde(default)]
    trust_store_id: Option<String>,
    #[serde(default)]
    authority_binding: Option<String>,
    bundle: SignedTrustBundle,
    #[serde(default)]
    lkg_bundle: Option<SignedTrustBundle>,
    #[serde(default)]
    lkg_digest: Option<String>,
    #[serde(default)]
    center_authority_transitions: Vec<CenterAuthorityTransitionV1>,
}

#[derive(Debug, Clone)]
pub struct SupervisorTrustStore {
    path: PathBuf,
    channel: String,
    schema_version: u8,
    trust_store_id: Option<String>,
    authority_binding: Option<String>,
    bundle: Option<SignedTrustBundle>,
    current_epoch: u64,
    digest: Option<String>,
    lkg_bundle: Option<SignedTrustBundle>,
    lkg_digest: Option<String>,
    bootstrap_roots: Vec<ProductTrustRoot>,
    center_authority_transitions: Vec<CenterAuthorityTransitionV1>,
}

impl SupervisorTrustStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::open_with_bootstrap_roots(path, &[])
    }

    /// Open with the universal Product Trust bootstrap set. An empty set is
    /// safe for an uninitialized store, but it deliberately cannot accept or
    /// reopen a signed bundle presented by an unauthenticated Center.
    pub fn open_with_bootstrap_roots(path: impl Into<PathBuf>, bootstrap_roots: &[ProductTrustRoot]) -> Result<Self, String> {
        Self::open_with_channel_and_bootstrap_roots(path, "stable", bootstrap_roots)
    }

    pub fn open_with_channel_and_bootstrap_roots(
        path: impl Into<PathBuf>,
        channel: &str,
        bootstrap_roots: &[ProductTrustRoot],
    ) -> Result<Self, String> {
        let channel = normalize_lifecycle_channel(Some(channel))?;
        let path = path.into();
        super::effective_config::validate_trust_store_path(&channel, &path)?;
        validate_store_permissions(&path)?;
        if !path.exists() {
            return Ok(Self { path, channel, schema_version: 2, trust_store_id: None, authority_binding: None, bundle: None, current_epoch: 0, digest: None, lkg_bundle: None, lkg_digest: None, bootstrap_roots: bootstrap_roots.to_vec(), center_authority_transitions: Vec::new() });
        }
        let bytes = fs::read(&path).map_err(|e| format!("TRUST_STORE_READ_FAILED: {e}"))?;
        let file: TrustStoreFile = serde_json::from_slice(&bytes).map_err(|e| format!("TRUST_STORE_INVALID: {e}"))?;
        if file.schema_version == 1 {
            // Explicit, read-only compatibility for the original STABLE store.
            // LAB must never inherit or reinterpret a legacy STABLE resource.
            validate_legacy_stable_compatibility(&channel, &path)?;
        } else if file.schema_version != 2 {
            return Err("TRUST_STORE_SCHEMA_UNSUPPORTED".into());
        }
        if normalize_lifecycle_channel(Some(&file.channel))? != channel { return Err("TRUST_STORE_CHANNEL_MISMATCH".into()); }
        if file.current_epoch != file.bundle.bundle.trust_epoch {
            return Err("TRUST_STORE_EPOCH_MISMATCH".into());
        }
        verify_signed_trust_bundle_with_bootstrap(&file.bundle, unix_now(), file.current_epoch, bootstrap_roots)?;
        if let Some(lkg) = &file.lkg_bundle {
            verify_signed_trust_bundle_with_bootstrap(lkg, unix_now(), 0, bootstrap_roots)?;
            let lkg_digest = trust_bundle_digest(&lkg.bundle)?;
            if file.lkg_digest.as_deref() != Some(lkg_digest.as_str()) {
                return Err("TRUST_STORE_LKG_DIGEST_INVALID".into());
            }
        } else if file.lkg_digest.is_some() {
            return Err("TRUST_STORE_LKG_INVALID".into());
        }
        for transition in &file.center_authority_transitions { verify_center_authority_transition(transition, &file.bundle, unix_now())?; }
        let digest = trust_bundle_digest(&file.bundle.bundle)?;
        if file.schema_version == 2 {
            let id = file.trust_store_id.as_deref().ok_or_else(|| "TRUST_STORE_METADATA_REQUIRED".to_string())?;
            uuid::Uuid::parse_str(id).map_err(|_| "TRUST_STORE_METADATA_INVALID".to_string())?;
            let expected_binding = authority_binding(&file.bundle);
            if file.authority_binding.as_deref() != Some(expected_binding.as_str()) {
                return Err("AUTHORITY_BINDING_MISMATCH".into());
            }
        }
        let authority_binding = file.authority_binding.clone()
            .or_else(|| Some(authority_binding(&file.bundle)));
        Ok(Self { path, channel, schema_version: file.schema_version, trust_store_id: file.trust_store_id, authority_binding, bundle: Some(file.bundle), current_epoch: file.current_epoch, digest: Some(digest), lkg_bundle: file.lkg_bundle, lkg_digest: file.lkg_digest, bootstrap_roots: bootstrap_roots.to_vec(), center_authority_transitions: file.center_authority_transitions })
    }

    pub fn status(&self) -> TrustStoreStatus {
        TrustStoreStatus { state: if self.bundle.is_some() { "READY" } else { "UNINITIALIZED" }.into(), schema_version: self.schema_version, trust_store_id: self.trust_store_id.clone(), trust_bundle_id: self.bundle.as_ref().map(|bundle| bundle.bundle.trust_bundle_id.clone()), channel: self.channel.clone(), authority_binding: self.authority_binding.clone(), current_epoch: self.current_epoch, bundle_digest: self.digest.clone(), lkg_digest: self.lkg_digest.clone(), bootstrap_anchor_count: self.bootstrap_roots.len(), path: self.path.to_string_lossy().into_owned() }
    }

    pub fn bundle(&self) -> Option<&SignedTrustBundle> { self.bundle.as_ref() }

    /// Explicitly upgrade the original STABLE file envelope without changing
    /// its signed bundle, trust epoch, LKG material, or Authority custody.
    /// This is called only from a deployment transaction, never by --check.
    pub fn migrate_legacy_stable_metadata(&mut self) -> Result<TrustStoreStatus, String> {
        if self.trust_store_id.is_some() {
            return Ok(self.status());
        }
        if self.channel != "stable" {
            return Err("TRUST_STORE_CHANNEL_MISMATCH".into());
        }
        let bundle = self.bundle.clone().ok_or_else(|| "TRUST_STORE_METADATA_REQUIRED".to_string())?;
        let mut next = self.clone();
        let file = next.file_for_bundle(&bundle, self.current_epoch, self.lkg_bundle.clone(), self.lkg_digest.clone())?;
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        write_atomic(&self.path, &bytes)?;
        *self = next;
        Ok(self.status())
    }

    pub fn install(&mut self, bundle: SignedTrustBundle, now: u64) -> Result<TrustStoreStatus, String> {
        verify_signed_trust_bundle_with_bootstrap(&bundle, now, self.current_epoch, &self.bootstrap_roots)?;
        let digest = trust_bundle_digest(&bundle.bundle)?;
        if bundle.bundle.trust_epoch == self.current_epoch && self.digest.as_deref() != Some(digest.as_str()) { return Err("TRUST_EPOCH_SAME_DIGEST_MISMATCH".into()); }
        if bundle.bundle.trust_epoch < self.current_epoch { return Err("TRUST_EPOCH_ROLLBACK".into()); }
        let mut next = self.clone();
        let previous = self.bundle.clone();
        let previous_digest = self.digest.clone();
        let next_lkg_bundle = previous.clone().or_else(|| self.lkg_bundle.clone());
        let next_lkg_digest = previous_digest.clone().or_else(|| self.lkg_digest.clone());
        if let (Some(lkg), Some(digest)) = (&next_lkg_bundle, &next_lkg_digest) {
            let lkg_path = self.lkg_path();
            let lkg_file = serde_json::to_vec_pretty(lkg).map_err(|e| format!("TRUST_STORE_LKG_SERIALIZE_FAILED: {e}"))?;
            write_atomic(&lkg_path, &lkg_file)?;
            if trust_bundle_digest(&lkg.bundle)? != *digest { return Err("TRUST_STORE_LKG_DIGEST_INVALID".into()); }
        }
        let file = next.file_for_bundle(&bundle, bundle.bundle.trust_epoch, next_lkg_bundle.clone(), next_lkg_digest.clone())?;
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        write_atomic(&self.path, &bytes)?;
        next.current_epoch = bundle.bundle.trust_epoch;
        next.digest = Some(digest);
        next.bundle = Some(bundle);
        next.lkg_bundle = next_lkg_bundle;
        next.lkg_digest = next_lkg_digest;
        *self = next;
        Ok(self.status())
    }

    pub fn activate_successor(
        &mut self,
        request: &HostTrustBundleRefreshRequestV1,
        now: u64,
    ) -> Result<(TrustStoreStatus, HostTrustActivationReceiptV1), String> {
        if request.contract != HOST_TRUST_CONVERGENCE_CONTRACT || request.authority_generation == 0 || request.activation_generation == 0 {
            return Err("HOST_TRUST_CONVERGENCE_CONTRACT_INVALID".into());
        }
        let channel = normalize_lifecycle_channel(Some(&request.channel))?;
        let previous = self.bundle.clone().ok_or_else(|| "AUTHORITY_SUCCESSOR_PREDECESSOR_NOT_SERVED".to_string())?;
        let previous_digest = self.digest.clone().ok_or_else(|| "TRUST_STORE_DIGEST_MISSING".to_string())?;
        let candidate_digest = trust_bundle_digest(&request.bundle.bundle)?;
        if request.expected_digest != candidate_digest {
            return Err("HOST_TRUST_CONVERGENCE_DIGEST_MISMATCH".into());
        }
        verify_center_authority_transition(&request.transition, &previous, now)?;
        verify_signed_trust_bundle_with_bootstrap(&request.bundle, now, self.current_epoch, &self.bootstrap_roots)?;
        let already_served = self.digest.as_deref() == Some(candidate_digest.as_str())
            && self.current_epoch == request.bundle.bundle.trust_epoch;
        if !already_served {
            validate_successor_activation_lineage(&request.transition, &previous, &request.bundle)?;
        }
        let started_at = unix_now();
        if !already_served {
            self.install(request.bundle.clone(), now)?;
        }
        let completed_at = unix_now();
        let receipt = HostTrustActivationReceiptV1 {
            contract: HOST_TRUST_CONVERGENCE_CONTRACT.into(),
            phase: AuthorityLifecyclePhase::ServedReady,
            transition_id: request.transition.transition_id.clone(),
            predecessor_authority_id: request.transition.predecessor_authority_id.clone(),
            successor_authority_id: request.transition.successor_authority_id.clone(),
            previous_digest,
            served_digest: candidate_digest,
            previous_trust_epoch: previous.bundle.trust_epoch,
            trust_epoch: request.bundle.bundle.trust_epoch,
            authority_generation: request.authority_generation,
            activation_generation: request.activation_generation,
            started_at,
            completed_at,
            result: if already_served { "ALREADY_SERVED" } else { "ACTIVATED" }.into(),
            lkg_path: self.lkg_path().to_string_lossy().into_owned(),
            receipt_digest: String::new(),
            channel,
        }.with_receipt_digest()?;
        Ok((self.status(), receipt))
    }

    fn lkg_path(&self) -> PathBuf {
        self.path.with_file_name("trust-bundle.lkg.json")
    }

    pub fn center_authority_transitions(&self) -> &[CenterAuthorityTransitionV1] { &self.center_authority_transitions }

    /// Accept only a verified additive Center transition.  This does not
    /// replace the active bundle or reenroll the Host; it records the signed
    /// successor proof until a newer Owner-published bundle is installed.
    pub fn accept_center_authority_transition(&mut self, transition: CenterAuthorityTransitionV1, now: u64) -> Result<TrustStoreStatus, String> {
        let bundle = self.bundle.clone().ok_or_else(|| "TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE".to_string())?;
        verify_center_authority_transition(&transition, &bundle, now)?;
        let digest = center_authority_transition_digest(&transition)?;
        if let Some(existing) = self.center_authority_transitions.iter().find(|candidate| candidate.transition_id == transition.transition_id) {
            let existing_digest = center_authority_transition_digest(existing)?;
            if existing_digest != digest { return Err("TRUST_CENTER_TRANSITION_REPLAY".into()); }
            return Ok(self.status());
        }
        if let Some(existing) = self.center_authority_transitions.iter().find(|candidate| candidate.activation_epoch == transition.activation_epoch) {
            if center_authority_transition_digest(existing)? != digest { return Err("TRUST_CENTER_TRANSITION_SAME_EPOCH_MISMATCH".into()); }
        }
        if self.center_authority_transitions.iter().any(|candidate| candidate.activation_epoch > transition.activation_epoch) { return Err("TRUST_CENTER_TRANSITION_ROLLBACK".into()); }
        let mut next = self.clone();
        next.center_authority_transitions.push(transition);
        let file = next.file_for_bundle(&bundle, self.current_epoch, self.lkg_bundle.clone(), self.lkg_digest.clone())?;
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        write_atomic(&self.path, &bytes)?;
        *self = next;
        Ok(self.status())
    }

    /// Establish first trust only as the final local step of the explicit
    /// Owner ceremony.  This is intentionally not the normal install path:
    /// it requires an Owner confirmation and an exact fingerprint that was
    /// reviewed outside the transport.  A Center response, URL or public key
    /// received by itself can never create the first anchor.
    pub fn install_from_owner_ceremony(
        &mut self,
        bundle: SignedTrustBundle,
        expected_root_fingerprint: &str,
        owner_confirmed: bool,
        now: u64,
    ) -> Result<TrustStoreStatus, String> {
        if !owner_confirmed {
            return Err("TRUST_OWNER_CONFIRMATION_REQUIRED".into());
        }
        let expected = expected_root_fingerprint.trim();
        if expected.is_empty() {
            return Err("TRUST_ROOT_FINGERPRINT_REQUIRED".into());
        }
        let digest = trust_bundle_digest(&bundle.bundle)?;
        if let Some(existing) = &self.bundle {
            let existing_digest = trust_bundle_digest(&existing.bundle)?;
            if existing_digest == digest && existing.bundle.trust_epoch == bundle.bundle.trust_epoch {
                return Ok(self.status());
            }
            return Err("TRUST_STORE_ALREADY_INITIALIZED".into());
        }
        if self.current_epoch != 0 {
            return Err("TRUST_STORE_ALREADY_INITIALIZED".into());
        }
        verify_signed_trust_bundle(&bundle, now, 0)?;
        let root = bundle
            .bundle
            .product_roots
            .iter()
            .find(|candidate| candidate.authority.key_id == bundle.signing_key_id)
            .ok_or_else(|| "TRUST_BUNDLE_ROOT_UNKNOWN".to_string())?;
        if root.authority.fingerprint != expected {
            return Err("TRUST_ROOT_FINGERPRINT_MISMATCH".into());
        }
        if bundle.bundle.trust_epoch == 0 {
            return Err("TRUST_EPOCH_INVALID".into());
        }
        let mut next = self.clone();
        let file = next.file_for_bundle(&bundle, bundle.bundle.trust_epoch, None, None)?;
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        write_atomic(&self.path, &bytes)?;
        next.current_epoch = bundle.bundle.trust_epoch;
        next.digest = Some(digest);
        next.bundle = Some(bundle);
        *self = next;
        Ok(self.status())
    }

    fn file_for_bundle(
        &mut self,
        bundle: &SignedTrustBundle,
        current_epoch: u64,
        lkg_bundle: Option<SignedTrustBundle>,
        lkg_digest: Option<String>,
    ) -> Result<TrustStoreFile, String> {
        let trust_store_id = self.trust_store_id.get_or_insert_with(|| uuid::Uuid::new_v4().to_string()).clone();
        let binding = authority_binding(bundle);
        self.authority_binding = Some(binding.clone());
        self.schema_version = 2;
        Ok(TrustStoreFile {
            schema_version: 2,
            channel: self.channel.clone(),
            current_epoch,
            trust_store_id: Some(trust_store_id),
            authority_binding: Some(binding),
            bundle: bundle.clone(),
            lkg_bundle,
            lkg_digest,
            center_authority_transitions: self.center_authority_transitions.clone(),
        })
    }
}

fn authority_binding(bundle: &SignedTrustBundle) -> String {
    bundle.bundle.center_authority.as_ref()
        .map(|authority| authority.authority_id.clone())
        .unwrap_or_else(|| bundle.bundle.issuer.clone())
}

fn validate_legacy_stable_compatibility(channel: &str, path: &Path) -> Result<(), String> {
    let stable_path = super::effective_config::canonical_trust_store_path("stable");
    let stable_root = stable_path.parent().unwrap_or(Path::new("/"));
    if channel != "stable" || !path.starts_with(stable_root) {
        return Err("TRUST_STORE_SCHEMA_UNSUPPORTED".into());
    }
    Ok(())
}

fn validate_store_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let expected_owner = nix::unistd::geteuid().as_raw();
        let parent = path
            .parent()
            .ok_or_else(|| "TRUST_STORE_PERMISSION_INVALID".to_string())?;
        let mut ancestors: Vec<_> = path.ancestors().collect();
        ancestors.reverse();
        for ancestor in ancestors {
            let metadata = match fs::symlink_metadata(ancestor) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err("TRUST_STORE_PERMISSION_INVALID".into()),
            };
            if metadata.file_type().is_symlink() {
                return Err("TRUST_STORE_PERMISSION_INVALID".into());
            }
            if ancestor == path {
                if !metadata.is_file()
                    || metadata.uid() != expected_owner
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err("TRUST_STORE_PERMISSION_INVALID".into());
                }
            } else if ancestor == parent
                && (!metadata.is_dir()
                    || metadata.uid() != expected_owner
                    || metadata.permissions().mode() & 0o077 != 0)
            {
                return Err("TRUST_STORE_PERMISSION_INVALID".into());
            } else if ancestor != parent && !metadata.is_dir() {
                return Err("TRUST_STORE_PERMISSION_INVALID".into());
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Recover the public Product Trust anchor for installations created by the
/// pre-anchor Owner ceremony.  This is deliberately a one-time compatibility
/// bridge: it requires a self-validating bundle plus a durable ceremony
/// journal whose Owner-confirmed output has the exact root fingerprint and
/// bundle digest.  An arbitrary local bundle, a Center response, or a URL can
/// never become a bootstrap anchor through this function.
pub fn owner_ceremony_bootstrap_anchor(
    trust_store_path: &Path,
    ceremony_journal_dir: &Path,
) -> Result<Option<ProductTrustRoot>, String> {
    if !trust_store_path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(trust_store_path).map_err(|_| "TRUST_STORE_READ_FAILED".to_string())?;
    let file: TrustStoreFile =
        serde_json::from_slice(&bytes).map_err(|_| "TRUST_STORE_INVALID".to_string())?;
    verify_signed_trust_bundle(&file.bundle, unix_now(), 0)
        .map_err(|_| "TRUST_STORE_INVALID".to_string())?;
    let root = file
        .bundle
        .bundle
        .product_roots
        .iter()
        .find(|candidate| candidate.authority.key_id == file.bundle.signing_key_id)
        .ok_or_else(|| "TRUST_BUNDLE_ROOT_UNKNOWN".to_string())?;
    let digest = trust_bundle_digest(&file.bundle.bundle)?;
    if !ceremony_journal_dir.is_dir() {
        return Ok(None);
    }
    for entry in fs::read_dir(ceremony_journal_dir)
        .map_err(|_| "TRUST_BOOTSTRAP_JOURNAL_UNAVAILABLE".to_string())?
    {
        let entry = entry.map_err(|_| "TRUST_BOOTSTRAP_JOURNAL_UNAVAILABLE".to_string())?;
        if !entry.path().is_file() {
            continue;
        }
        let journal: serde_json::Value = match serde_json::from_slice(&fs::read(entry.path()).unwrap_or_default()) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let state = journal.get("state").and_then(serde_json::Value::as_str);
        let recovery = journal
            .get("recoveryStatus")
            .and_then(serde_json::Value::as_str);
        let journal_root = journal
            .get("rootFingerprint")
            .and_then(serde_json::Value::as_str);
        let journal_digest = journal
            .get("trustBundleDigest")
            .and_then(serde_json::Value::as_str);
        if matches!(state, Some("EXECUTED" | "ACTIVATED"))
            && recovery == Some("VERIFIED")
            && journal_root == Some(root.authority.fingerprint.as_str())
            && journal_digest == Some(digest.as_str())
        {
            return Ok(Some(root.clone()));
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustStoreStatus {
    pub state: String,
    pub schema_version: u8,
    pub trust_store_id: Option<String>,
    pub trust_bundle_id: Option<String>,
    pub channel: String,
    pub authority_binding: Option<String>,
    pub current_epoch: u64,
    pub bundle_digest: Option<String>,
    pub lkg_digest: Option<String>,
    pub bootstrap_anchor_count: usize,
    pub path: String,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        let parent_existed = parent.exists();
        fs::create_dir_all(parent).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?;
        #[cfg(unix)]
        if !parent_existed {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| "TRUST_STORE_PERMISSION_INVALID".to_string())?;
        }
        validate_store_permissions(path)?;
    }
    let parent = path
        .parent()
        .ok_or_else(|| "TRUST_STORE_WRITE_FAILED: invalid path".to_string())?;
    let file_name = path
        .file_name()
        .ok_or_else(|| "TRUST_STORE_WRITE_FAILED: invalid path".to_string())?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?;
    use std::io::Write;
    if let Err(error) = file.write_all(bytes) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("TRUST_STORE_WRITE_FAILED: {error}"));
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(format!("TRUST_STORE_SYNC_FAILED: {error}"));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("TRUST_STORE_COMMIT_FAILED: {error}"));
    }
    if let Some(parent) = path.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            directory.sync_all().map_err(|_| "TRUST_STORE_SYNC_FAILED".to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actium_node_core::{authority_capability, AuthorityKind, AuthorityService, CenterAuthorityReissueOwnerApprovalV1, CenterAuthorityReissueRequestV1, TestEphemeralKeyProvider, CENTER_AUTHORITY_REISSUE_CONTRACT, REMOTE_OPERATIONS_SIGNING_CAPABILITY};

    fn bundle() -> SignedTrustBundle {
        let mut service = AuthorityService::new(TestEphemeralKeyProvider::default(), "set");
        service.initialize_root("root", 1).unwrap();
        service.trust_bundle("root", 1, None).unwrap()
    }

    fn private_test_dir(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    #[test]
    fn empty_store_is_supported_and_install_is_persistent() {
        let root = private_test_dir("actium-trust-store");
        let path = root.join("trust.json");
        let signed = bundle();
        let roots = signed.bundle.product_roots.clone();
        let mut store = SupervisorTrustStore::open_with_bootstrap_roots(&path, &roots).unwrap();
        assert_eq!(store.status().state, "UNINITIALIZED");
        store.install(signed.clone(), 2).unwrap();
        let reloaded = SupervisorTrustStore::open_with_bootstrap_roots(&path, &roots).unwrap();
        assert_eq!(reloaded.status().state, "READY");
        assert_eq!(reloaded.bundle().unwrap(), &signed);
        assert_eq!(reloaded.status().schema_version, 2);
        assert!(reloaded.status().trust_store_id.as_deref().is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()));
        assert_eq!(reloaded.status().channel, "stable");
        assert_eq!(reloaded.status().authority_binding.as_deref(), Some(authority_binding(&signed).as_str()));
        let persisted: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted["schemaVersion"], 2);
        assert_eq!(persisted["trustStoreId"], reloaded.status().trust_store_id.as_deref().unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_epoch_different_digest_is_rejected() {
        let root = private_test_dir("actium-trust-store");
        let path = root.join("trust.json");
        let first = bundle();
        let roots = first.bundle.product_roots.clone();
        let mut store = SupervisorTrustStore::open_with_bootstrap_roots(&path, &roots).unwrap();
        store.install(first, 2).unwrap();
        let mut other = bundle();
        other.bundle.trust_bundle_id = "different".into();
        assert!(store.install(other, 2).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn first_trust_without_bootstrap_anchor_is_rejected() {
        let root = private_test_dir("actium-trust-store");
        let path = root.join("trust.json");
        let mut store = SupervisorTrustStore::open(&path).unwrap();
        assert_eq!(store.install(bundle(), 2).unwrap_err(), "TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn first_trust_requires_exact_owner_reviewed_fingerprint() {
        let root = private_test_dir("actium-owner-trust-store");
        let path = root.join("trust.json");
        let signed = bundle();
        let fingerprint = signed.bundle.product_roots[0].authority.fingerprint.clone();
        let mut store = SupervisorTrustStore::open(&path).unwrap();
        assert_eq!(store.install_from_owner_ceremony(signed.clone(), "sha256:wrong", true, unix_now()).unwrap_err(), "TRUST_ROOT_FINGERPRINT_MISMATCH");
        store.install_from_owner_ceremony(signed.clone(), &fingerprint, true, unix_now()).unwrap();
        let reloaded = SupervisorTrustStore::open_with_bootstrap_roots(&path, &signed.bundle.product_roots).unwrap();
        assert_eq!(reloaded.status().state, "READY");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn verified_center_successor_is_persisted_without_reenrollment_and_old_bundle_cannot_replay() {
        let root = private_test_dir("actium-center-transition");
        let path = root.join("trust.json");
        let mut service = AuthorityService::new(TestEphemeralKeyProvider::default(), "set");
        let root_authority = service.initialize_root("root", 100).unwrap();
        service.issue_subordinate("root", "deployment", AuthorityKind::DeploymentAuthority, vec![authority_capability(AuthorityKind::DeploymentAuthority).into()], 100, None).unwrap();
        service.issue_subordinate("deployment", "deployment-root", AuthorityKind::DeploymentRoot, vec![authority_capability(AuthorityKind::DeploymentRoot).into()], 100, None).unwrap();
        service.issue_subordinate("deployment-root", "center", AuthorityKind::CenterAuthority, vec![authority_capability(AuthorityKind::CenterAuthority).into()], 100, None).unwrap();
        service.issue_subordinate("center", "enrollment", AuthorityKind::EnrollmentAuthority, vec!["host_enrollment".into()], 100, None).unwrap();
        let center_key = service.authorities().find(|authority| authority.authority_id == "center").unwrap().key_id.clone();
        let old_bundle = service.trust_bundle("root", 120, None).unwrap();
        let request = CenterAuthorityReissueRequestV1 { contract: CENTER_AUTHORITY_REISSUE_CONTRACT.into(), operation: "AUTHORIZE_CENTER_AUTHORITY_REISSUE".into(), transition_id: "00000000-0000-4000-8000-000000000002".into(), predecessor_authority_id: "center".into(), predecessor_key_id: center_key, trust_root_set: "set".into(), expected_trust_epoch: 1, requested_capability: REMOTE_OPERATIONS_SIGNING_CAPABILITY.into(), activation_epoch: Some(2), owner_approval: Some(CenterAuthorityReissueOwnerApprovalV1 { owner_id: "owner-1".into(), aal: "aal2".into(), reason: "controlled successor".into(), confirmation: "AUTHORIZE_CENTER_AUTHORITY_REISSUE".into() }) };
        let transition = service.authorize_center_authority_reissue(&request, 120).unwrap();
        let mut store = SupervisorTrustStore::open_with_bootstrap_roots(&path, &old_bundle.bundle.product_roots).unwrap();
        store.install(old_bundle.clone(), 120).unwrap();
        store.accept_center_authority_transition(transition.clone(), 120).unwrap();
        assert_eq!(store.center_authority_transitions().len(), 1);
        store.accept_center_authority_transition(transition.clone(), 120).unwrap();
        assert_eq!(store.center_authority_transitions().len(), 1);
        let mut tampered = transition.clone();
        tampered.signatures[0].signature = String::new();
        assert!(store.accept_center_authority_transition(tampered, 120).is_err());
        service.advance_trust_epoch(2).unwrap();
        let newer_bundle = service.trust_bundle("root", 200, None).unwrap();
        store.install(newer_bundle, 200).unwrap();
        assert_eq!(store.install(old_bundle, 200).unwrap_err(), "TRUST_EPOCH_ROLLBACK");
        let _ = root_authority;
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lab_never_accepts_legacy_untyped_trust_store() {
        let root = private_test_dir("actium-trust-legacy-lab");
        let path = root.join("trust.json");
        let signed = bundle();
        let legacy = serde_json::json!({
            "schema": 1,
            "channel": "lab",
            "currentEpoch": signed.bundle.trust_epoch,
            "bundle": signed,
        });
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            SupervisorTrustStore::open_with_channel_and_bootstrap_roots(
                &path,
                "lab",
                &signed.bundle.product_roots,
            )
            .err().unwrap(),
            "TRUST_STORE_SCHEMA_UNSUPPORTED"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn trust_store_metadata_binding_mismatch_is_rejected() {
        let root = private_test_dir("actium-trust-binding");
        let path = root.join("trust.json");
        let signed = bundle();
        let mut store = SupervisorTrustStore::open_with_bootstrap_roots(
            &path,
            &signed.bundle.product_roots,
        )
        .unwrap();
        store.install(signed.clone(), 2).unwrap();
        let mut persisted: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        persisted["authorityBinding"] = serde_json::Value::String("wrong-authority".into());
        fs::write(&path, serde_json::to_vec(&persisted).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            SupervisorTrustStore::open_with_bootstrap_roots(&path, &signed.bundle.product_roots)
                .err().unwrap(),
            "AUTHORITY_BINDING_MISMATCH"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn persisted_channel_and_epoch_mismatches_are_rejected() {
        let signed = bundle();
        let roots = signed.bundle.product_roots.clone();
        let channel_root = private_test_dir("actium-trust-channel-metadata");
        let channel_path = channel_root.join("trust.json");
        let mut store = SupervisorTrustStore::open_with_channel_and_bootstrap_roots(
            &channel_path,
            "lab",
            &roots,
        )
        .unwrap();
        store.install(signed.clone(), 2).unwrap();
        let mut persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&channel_path).unwrap()).unwrap();
        persisted["channel"] = serde_json::Value::String("stable".into());
        fs::write(&channel_path, serde_json::to_vec(&persisted).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&channel_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            SupervisorTrustStore::open_with_channel_and_bootstrap_roots(
                &channel_path,
                "lab",
                &roots,
            )
            .err()
            .unwrap(),
            "TRUST_STORE_CHANNEL_MISMATCH"
        );

        let epoch_root = private_test_dir("actium-trust-epoch-metadata");
        let epoch_path = epoch_root.join("trust.json");
        let mut store = SupervisorTrustStore::open_with_channel_and_bootstrap_roots(
            &epoch_path,
            "lab",
            &roots,
        )
        .unwrap();
        store.install(signed, 2).unwrap();
        let mut persisted: serde_json::Value =
            serde_json::from_slice(&fs::read(&epoch_path).unwrap()).unwrap();
        persisted["trustEpoch"] = serde_json::Value::from(999u64);
        fs::write(&epoch_path, serde_json::to_vec(&persisted).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&epoch_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            SupervisorTrustStore::open_with_channel_and_bootstrap_roots(
                &epoch_path,
                "lab",
                &roots,
            )
            .err()
            .unwrap(),
            "TRUST_STORE_EPOCH_MISMATCH"
        );
        let _ = fs::remove_dir_all(channel_root);
        let _ = fs::remove_dir_all(epoch_root);
    }

    #[test]
    fn legacy_compatibility_is_stable_namespace_only() {
        let stable_path = crate::effective_config::canonical_trust_store_path("stable");
        let stable_root = stable_path.parent().unwrap();
        assert!(validate_legacy_stable_compatibility(
            "stable",
            &stable_root.join("legacy.json")
        )
        .is_ok());
        assert_eq!(
            validate_legacy_stable_compatibility("lab", &stable_root.join("legacy.json"))
                .unwrap_err(),
            "TRUST_STORE_SCHEMA_UNSUPPORTED"
        );
        assert_eq!(
            validate_legacy_stable_compatibility("stable", Path::new("/tmp/legacy.json"))
                .unwrap_err(),
            "TRUST_STORE_SCHEMA_UNSUPPORTED"
        );
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_rejects_world_or_group_access() {
        use std::os::unix::fs::PermissionsExt;
        let root = private_test_dir("actium-trust-permissions");
        let path = root.join("trust.json");
        let signed = bundle();
        let mut store = SupervisorTrustStore::open_with_bootstrap_roots(
            &path,
            &signed.bundle.product_roots,
        )
        .unwrap();
        store.install(signed, 2).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            SupervisorTrustStore::open_with_bootstrap_roots(&path, &[]).err().unwrap(),
            "TRUST_STORE_PERMISSION_INVALID"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_rejects_wrong_owner() {
        use nix::unistd::{chown, geteuid, Uid};
        use std::os::unix::fs::PermissionsExt;
        if !geteuid().is_root() {
            return;
        }
        let root = private_test_dir("actium-trust-owner");
        let path = root.join("trust.json");
        let signed = bundle();
        let mut store = SupervisorTrustStore::open_with_bootstrap_roots(
            &path,
            &signed.bundle.product_roots,
        )
        .unwrap();
        store.install(signed, 2).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        chown(&path, Some(Uid::from_raw(65534)), None).unwrap();
        assert_eq!(
            SupervisorTrustStore::open_with_bootstrap_roots(&path, &[])
                .err()
                .unwrap(),
            "TRUST_STORE_PERMISSION_INVALID"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn trust_store_rejects_symlinked_ancestors_and_writes_private_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = private_test_dir("actium-trust-symlink");
        let actual = root.join("actual");
        let alias = root.join("alias");
        fs::create_dir(&actual).unwrap();
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&actual, &alias).unwrap();

        let path = alias.join("trust.json");
        assert_eq!(
            SupervisorTrustStore::open_with_channel_and_bootstrap_roots(&path, "lab", &[])
                .unwrap_err(),
            "TRUST_STORE_PERMISSION_INVALID"
        );

        let trusted_path = actual.join("trust.json");
        let signed = bundle();
        let mut store = SupervisorTrustStore::open_with_channel_and_bootstrap_roots(
            &trusted_path,
            "lab",
            &signed.bundle.product_roots,
        )
        .unwrap();
        store.install(signed, 2).unwrap();
        let mode = fs::metadata(&trusted_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(root);
    }
}
