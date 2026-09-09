//! Durable public Trust Fabric state owned by Supervisor.
//!
//! This store contains no private material. An absent store is a supported
//! first-trust state; a present store is verified before it is accepted and
//! cannot move backwards in trust epoch.

use actium_node_core::{trust_bundle_digest, unix_now, verify_signed_trust_bundle, verify_signed_trust_bundle_with_bootstrap, ProductTrustRoot, SignedTrustBundle};
use serde::{Deserialize, Serialize};
use std::{fs, path::{Path, PathBuf}};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustStoreFile {
    schema: u8,
    current_epoch: u64,
    bundle: SignedTrustBundle,
}

#[derive(Debug, Clone)]
pub struct SupervisorTrustStore {
    path: PathBuf,
    bundle: Option<SignedTrustBundle>,
    current_epoch: u64,
    digest: Option<String>,
    bootstrap_roots: Vec<ProductTrustRoot>,
}

impl SupervisorTrustStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::open_with_bootstrap_roots(path, &[])
    }

    /// Open with the universal Product Trust bootstrap set. An empty set is
    /// safe for an uninitialized store, but it deliberately cannot accept or
    /// reopen a signed bundle presented by an unauthenticated Center.
    pub fn open_with_bootstrap_roots(path: impl Into<PathBuf>, bootstrap_roots: &[ProductTrustRoot]) -> Result<Self, String> {
        let path = path.into();
        if !path.exists() {
            return Ok(Self { path, bundle: None, current_epoch: 0, digest: None, bootstrap_roots: bootstrap_roots.to_vec() });
        }
        let bytes = fs::read(&path).map_err(|e| format!("TRUST_STORE_READ_FAILED: {e}"))?;
        let file: TrustStoreFile = serde_json::from_slice(&bytes).map_err(|e| format!("TRUST_STORE_INVALID: {e}"))?;
        if file.schema != 1 { return Err("TRUST_STORE_SCHEMA_UNSUPPORTED".into()); }
        verify_signed_trust_bundle_with_bootstrap(&file.bundle, unix_now(), file.current_epoch, bootstrap_roots)?;
        let digest = trust_bundle_digest(&file.bundle.bundle)?;
        if file.current_epoch != file.bundle.bundle.trust_epoch { return Err("TRUST_STORE_EPOCH_INVALID".into()); }
        Ok(Self { path, bundle: Some(file.bundle), current_epoch: file.current_epoch, digest: Some(digest), bootstrap_roots: bootstrap_roots.to_vec() })
    }

    pub fn status(&self) -> TrustStoreStatus {
        TrustStoreStatus { state: if self.bundle.is_some() { "READY" } else { "UNINITIALIZED" }.into(), current_epoch: self.current_epoch, bundle_digest: self.digest.clone(), bootstrap_anchor_count: self.bootstrap_roots.len(), path: self.path.to_string_lossy().into_owned() }
    }

    pub fn bundle(&self) -> Option<&SignedTrustBundle> { self.bundle.as_ref() }

    pub fn install(&mut self, bundle: SignedTrustBundle, now: u64) -> Result<TrustStoreStatus, String> {
        verify_signed_trust_bundle_with_bootstrap(&bundle, now, self.current_epoch, &self.bootstrap_roots)?;
        let digest = trust_bundle_digest(&bundle.bundle)?;
        if bundle.bundle.trust_epoch == self.current_epoch && self.digest.as_deref() != Some(digest.as_str()) { return Err("TRUST_EPOCH_SAME_DIGEST_MISMATCH".into()); }
        if bundle.bundle.trust_epoch < self.current_epoch { return Err("TRUST_EPOCH_ROLLBACK".into()); }
        if let Some(parent) = self.path.parent() { fs::create_dir_all(parent).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?; }
        let file = TrustStoreFile { schema: 1, current_epoch: bundle.bundle.trust_epoch, bundle: bundle.clone() };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| format!("TRUST_STORE_SERIALIZE_FAILED: {e}"))?;
        let temporary = self.path.with_extension("tmp");
        fs::write(&temporary, bytes).map_err(|e| format!("TRUST_STORE_WRITE_FAILED: {e}"))?;
        if let Err(error) = fs::rename(&temporary, &self.path) { let _ = fs::remove_file(&temporary); return Err(format!("TRUST_STORE_COMMIT_FAILED: {error}")); }
        self.current_epoch = bundle.bundle.trust_epoch;
        self.digest = Some(digest);
        self.bundle = Some(bundle);
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
        let file = TrustStoreFile { schema: 1, current_epoch: bundle.bundle.trust_epoch, bundle: bundle.clone() };
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
    pub bootstrap_anchor_count: usize,
    pub path: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use actium_node_core::{AuthorityService, TestEphemeralKeyProvider};

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
}
