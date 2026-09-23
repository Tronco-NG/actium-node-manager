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
    schema: u8,
    #[serde(default = "default_lifecycle_channel")]
    channel: String,
    current_epoch: u64,
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
        if !path.exists() {
            return Ok(Self { path, channel, bundle: None, current_epoch: 0, digest: None, lkg_bundle: None, lkg_digest: None, bootstrap_roots: bootstrap_roots.to_vec(), center_authority_transitions: Vec::new() });
        }
        let bytes = fs::read(&path).map_err(|e| format!("TRUST_STORE_READ_FAILED: {e}"))?;
        let file: TrustStoreFile = serde_json::from_slice(&bytes).map_err(|e| format!("TRUST_STORE_INVALID: {e}"))?;
        if file.schema != 1 { return Err("TRUST_STORE_SCHEMA_UNSUPPORTED".into()); }
        if normalize_lifecycle_channel(Some(&file.channel))? != channel { return Err("TRUST_STORE_CHANNEL_MISMATCH".into()); }
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
        if file.current_epoch != file.bundle.bundle.trust_epoch { return Err("TRUST_STORE_EPOCH_INVALID".into()); }
        Ok(Self { path, channel, bundle: Some(file.bundle), current_epoch: file.current_epoch, digest: Some(digest), lkg_bundle: file.lkg_bundle, lkg_digest: file.lkg_digest, bootstrap_roots: bootstrap_roots.to_vec(), center_authority_transitions: file.center_authority_transitions })
    }

    pub fn status(&self) -> TrustStoreStatus {
        TrustStoreStatus { state: if self.bundle.is_some() { "READY" } else { "UNINITIALIZED" }.into(), current_epoch: self.current_epoch, bundle_digest: self.digest.clone(), lkg_digest: self.lkg_digest.clone(), bootstrap_anchor_count: self.bootstrap_roots.len(), path: self.path.to_string_lossy().into_owned() }
    }

    pub fn bundle(&self) -> Option<&SignedTrustBundle> { self.bundle.as_ref() }

    pub fn install(&mut self, bundle: SignedTrustBundle, now: u64) -> Result<TrustStoreStatus, String> {
        verify_signed_trust_bundle_with_bootstrap(&bundle, now, self.current_epoch, &self.bootstrap_roots)?;
        let digest = trust_bundle_digest(&bundle.bundle)?;
        if bundle.bundle.trust_epoch == self.current_epoch && self.digest.as_deref() != Some(digest.as_str()) { return Err("TRUST_EPOCH_SAME_DIGEST_MISMATCH".into()); }
        if bundle.bundle.trust_epoch < self.current_epoch { return Err("TRUST_EPOCH_ROLLBACK".into()); }
        if let Some(parent) = self.path.parent() { fs::create_dir_all(parent).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?; }
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
        let file = TrustStoreFile { schema: 1, channel: self.channel.clone(), current_epoch: bundle.bundle.trust_epoch, bundle: bundle.clone(), lkg_bundle: next_lkg_bundle.clone(), lkg_digest: next_lkg_digest.clone(), center_authority_transitions: self.center_authority_transitions.clone() };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        write_atomic(&self.path, &bytes)?;
        self.current_epoch = bundle.bundle.trust_epoch;
        self.digest = Some(digest);
        self.bundle = Some(bundle);
        self.lkg_bundle = next_lkg_bundle;
        self.lkg_digest = next_lkg_digest;
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
        let bundle = self.bundle.as_ref().ok_or_else(|| "TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE".to_string())?;
        verify_center_authority_transition(&transition, bundle, now)?;
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
        self.center_authority_transitions.push(transition);
        let file = TrustStoreFile { schema: 1, channel: self.channel.clone(), current_epoch: self.current_epoch, bundle: bundle.clone(), lkg_bundle: self.lkg_bundle.clone(), lkg_digest: self.lkg_digest.clone(), center_authority_transitions: self.center_authority_transitions.clone() };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        let temporary = self.path.with_extension("transition.tmp");
        fs::write(&temporary, bytes).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?;
        if let Err(error) = fs::rename(&temporary, &self.path) { let _ = fs::remove_file(&temporary); return Err(format!("TRUST_STORE_COMMIT_FAILED: {error}")); }
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
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?;
        }
        let file = TrustStoreFile { schema: 1, channel: self.channel.clone(), current_epoch: bundle.bundle.trust_epoch, bundle: bundle.clone(), lkg_bundle: None, lkg_digest: None, center_authority_transitions: Vec::new() };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        let temporary = self.path.with_extension("owner-ceremony.tmp");
        if temporary.exists() { let _ = fs::remove_file(&temporary); }
        fs::write(&temporary, bytes).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?;
        if let Err(error) = fs::rename(&temporary, &self.path) {
            let _ = fs::remove_file(&temporary);
            return Err(format!("TRUST_STORE_COMMIT_FAILED: {error}"));
        }
        self.current_epoch = bundle.bundle.trust_epoch;
        self.digest = Some(digest);
        self.bundle = Some(bundle);
        Ok(self.status())
    }
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
    pub current_epoch: u64,
    pub bundle_digest: Option<String>,
    pub lkg_digest: Option<String>,
    pub bootstrap_anchor_count: usize,
    pub path: String,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?; }
    let temporary = path.with_extension("atomic.tmp");
    if temporary.exists() { let _ = fs::remove_file(&temporary); }
    fs::write(&temporary, bytes).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?;
    let file = fs::OpenOptions::new().write(true).open(&temporary).map_err(|e| format!("TRUST_STORE_SYNC_FAILED: {e}"))?;
    file.sync_all().map_err(|e| format!("TRUST_STORE_SYNC_FAILED: {e}"))?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) { let _ = fs::remove_file(&temporary); return Err(format!("TRUST_STORE_COMMIT_FAILED: {error}")); }
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

    #[test]
    fn empty_store_is_supported_and_install_is_persistent() {
        let root = std::env::temp_dir().join(format!("actium-trust-store-{}", uuid::Uuid::new_v4()));
        let path = root.join("trust.json");
        let signed = bundle();
        let roots = signed.bundle.product_roots.clone();
        let mut store = SupervisorTrustStore::open_with_bootstrap_roots(&path, &roots).unwrap();
        assert_eq!(store.status().state, "UNINITIALIZED");
        store.install(signed.clone(), 2).unwrap();
        let reloaded = SupervisorTrustStore::open_with_bootstrap_roots(&path, &roots).unwrap();
        assert_eq!(reloaded.status().state, "READY");
        assert_eq!(reloaded.bundle().unwrap(), &signed);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_epoch_different_digest_is_rejected() {
        let root = std::env::temp_dir().join(format!("actium-trust-store-{}", uuid::Uuid::new_v4()));
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
        let root = std::env::temp_dir().join(format!("actium-trust-store-{}", uuid::Uuid::new_v4()));
        let path = root.join("trust.json");
        let mut store = SupervisorTrustStore::open(&path).unwrap();
        assert_eq!(store.install(bundle(), 2).unwrap_err(), "TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn first_trust_requires_exact_owner_reviewed_fingerprint() {
        let root = std::env::temp_dir().join(format!("actium-owner-trust-store-{}", uuid::Uuid::new_v4()));
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
        let root = std::env::temp_dir().join(format!("actium-center-transition-{}", uuid::Uuid::new_v4()));
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
}
