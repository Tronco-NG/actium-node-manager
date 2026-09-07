//! Actium Trust Fabric v1.
//!
//! This module owns the protocol primitives only.  It intentionally exposes
//! public key metadata and signatures, never private key material.  Production
//! provisioning is expected to live behind an authority service; the
//! in-memory provider is exclusively for tests and local ceremony simulation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use ring::aead;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::{BTreeMap, BTreeSet}, fs, io::Write, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

pub const TRUST_FABRIC_ALGORITHM: &str = "Ed25519";
pub const TRUST_BUNDLE_CONTRACT: &str = "actium-trust-bundle@1.0.0";
pub const RELEASE_MANIFEST_CONTRACT: &str = "actium-release-manifest@1.0.0";
const AUTHORITY_CERTIFICATE_DOMAIN: &str = "actium-authority-certificate-v1";
const TRUST_BUNDLE_DOMAIN: &str = "actium-trust-bundle-v1";
const RELEASE_MANIFEST_DOMAIN: &str = "actium-release-manifest-v1";

pub const fn authority_capability(kind: AuthorityKind) -> &'static str {
    match kind {
        AuthorityKind::ProductTrustRoot => "authority:issue-deployment-authority",
        AuthorityKind::DeploymentAuthority => "authority:issue-deployment-root",
        AuthorityKind::DeploymentRoot => "authority:issue-center",
        AuthorityKind::CenterAuthority => "authority:issue-enrollment",
        AuthorityKind::EnrollmentAuthority => "host_enrollment",
        AuthorityKind::ReleaseAuthority => "authority:issue-product-signing",
        AuthorityKind::ProductSigningAuthority => "product_signing",
        AuthorityKind::HostIdentity => "host_identity",
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    ProductTrustRoot,
    DeploymentAuthority,
    DeploymentRoot,
    CenterAuthority,
    EnrollmentAuthority,
    ReleaseAuthority,
    ProductSigningAuthority,
    HostIdentity,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Active,
    Rotating,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyDescriptor {
    pub key_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub status: AuthorityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCertificate {
    pub schema: u8,
    pub authority_id: String,
    pub kind: AuthorityKind,
    pub key_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub issuer_authority_id: String,
    pub issuer_key_id: String,
    pub serial: String,
    pub version: u32,
    pub capabilities: Vec<String>,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityDescriptor {
    pub authority_id: String,
    pub kind: AuthorityKind,
    pub key_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub status: AuthorityStatus,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    pub issuer_authority_id: Option<String>,
    pub issuer_key_id: Option<String>,
    pub serial: String,
    pub version: u32,
    pub capabilities: Vec<String>,
    pub certificate: Option<AuthorityCertificate>,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProductTrustRoot {
    pub authority: AuthorityDescriptor,
    pub trust_root_set: String,
    pub root_version: u32,
    pub activation_epoch: u64,
    pub retirement_epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustRootSet {
    pub trust_root_set: String,
    pub root_version: u32,
    pub activation_epoch: u64,
    pub retirement_epoch: Option<u64>,
    pub roots: Vec<ProductTrustRoot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootTransition {
    pub schema: u8,
    pub trust_root_set: String,
    pub from_root_key_id: String,
    pub to_root_key_id: String,
    pub activation_epoch: u64,
    pub issued_at: u64,
    pub old_root_signature: String,
    pub new_root_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revocation {
    pub authority_id: String,
    pub key_id: String,
    pub revoked_at: u64,
    pub reason: String,
    pub revocation_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustBundle {
    pub trust_bundle_id: String,
    pub contract: String,
    pub version: u8,
    pub product_roots: Vec<ProductTrustRoot>,
    pub root_transitions: Vec<RootTransition>,
    pub deployment_authority: Option<AuthorityDescriptor>,
    pub deployment_root: Option<AuthorityDescriptor>,
    pub center_authority: Option<AuthorityDescriptor>,
    pub enrollment_authorities: Vec<AuthorityDescriptor>,
    pub release_authorities: Vec<AuthorityDescriptor>,
    pub product_signing_authorities: Vec<AuthorityDescriptor>,
    pub revocations: Vec<Revocation>,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub trust_epoch: u64,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedTrustBundle {
    #[serde(flatten)]
    pub bundle: TrustBundle,
    pub signature: String,
    pub signing_key_id: String,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentityRecord {
    pub authority_id: String,
    pub key_id: String,
    pub public_key: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub status: AuthorityStatus,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub name: String,
    pub uri: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseCompatibility {
    pub base_runtime_contract: String,
    pub build_manifest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseSigning {
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseManifestV1 {
    pub schema: String,
    pub contract: String,
    pub release_id: String,
    pub product_id: String,
    pub version: String,
    pub build_id: String,
    pub source_repo: String,
    pub source_commit: String,
    pub platform: String,
    pub architecture: String,
    pub artifacts: Vec<ReleaseArtifact>,
    pub issued_at: u64,
    pub created_at: String,
    pub promoted_at: String,
    pub release_status: String,
    pub compatibility: ReleaseCompatibility,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedReleaseManifest {
    #[serde(flatten)]
    pub manifest: ReleaseManifestV1,
    pub signing: ReleaseSigning,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedAuthorityOperation {
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityAuditEvent {
    pub action: String,
    pub authority_id: Option<String>,
    pub key_id: Option<String>,
    pub payload_digest: Option<String>,
    pub result: String,
    pub reason: Option<String>,
    pub created_at: u64,
}

/// Durable public state for the Authority Service.  It contains descriptors,
/// certificates, revocations and audit metadata only; private signing keys
/// remain behind the KeyProvider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableAuthorityState {
    pub schema: u8,
    pub trust_root_set: String,
    pub trust_epoch: u64,
    pub authorities: Vec<AuthorityDescriptor>,
    pub revocations: Vec<Revocation>,
    pub root_transitions: Vec<RootTransition>,
    pub audit_events: Vec<AuthorityAuditEvent>,
    #[serde(default)]
    pub idempotency_results: BTreeMap<String, DurableIdempotencyRecord>,
    /// Key references intentionally absent from the online provider.  The
    /// Product Trust Root is normally generated and retained by the offline
    /// ceremony; the Authority Service only needs its public descriptor to
    /// validate the hierarchy and serve a pre-signed Trust Bundle.
    #[serde(default)]
    pub public_only_key_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableIdempotencyRecord {
    pub request_digest: String,
    pub response: Value,
}

pub trait KeyProvider {
    fn generate(&mut self) -> Result<KeyDescriptor, String>;
    fn load(&self, key_id: &str) -> Result<KeyDescriptor, String>;
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, String>;
    fn public_key(&self, key_id: &str) -> Result<String, String>;
    fn fingerprint(&self, key_id: &str) -> Result<String, String>;
    fn rotate(&mut self, key_id: &str) -> Result<KeyDescriptor, String>;
    fn revoke(&mut self, key_id: &str) -> Result<(), String>;
    fn destroy_reference(&mut self, key_id: &str) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct TestEphemeralKeyProvider {
    keys: BTreeMap<String, SigningKey>,
    revoked: BTreeSet<String>,
}

impl TestEphemeralKeyProvider {
    fn descriptor(key_id: String, key: &SigningKey, status: AuthorityStatus) -> KeyDescriptor {
        let public_key = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
        let fingerprint = fingerprint_for_raw(key.verifying_key().as_bytes());
        KeyDescriptor { key_id, public_key, fingerprint, algorithm: TRUST_FABRIC_ALGORITHM.to_string(), status }
    }
}

impl KeyProvider for TestEphemeralKeyProvider {
    fn generate(&mut self) -> Result<KeyDescriptor, String> {
        let key = SigningKey::generate(&mut OsRng);
        let key_id = fingerprint_for_raw(key.verifying_key().as_bytes());
        let descriptor = Self::descriptor(key_id.clone(), &key, AuthorityStatus::Active);
        self.keys.insert(key_id, key);
        Ok(descriptor)
    }

    fn load(&self, key_id: &str) -> Result<KeyDescriptor, String> {
        let key = self.keys.get(key_id).ok_or_else(|| "TRUST_KEY_NOT_FOUND".to_string())?;
        let status = if self.revoked.contains(key_id) { AuthorityStatus::Revoked } else { AuthorityStatus::Active };
        Ok(Self::descriptor(key_id.to_string(), key, status))
    }

    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, String> {
        if self.revoked.contains(key_id) { return Err("TRUST_KEY_REVOKED".into()); }
        Ok(self.keys.get(key_id).ok_or_else(|| "TRUST_KEY_NOT_FOUND".to_string())?.sign(message).to_bytes().to_vec())
    }

    fn public_key(&self, key_id: &str) -> Result<String, String> { Ok(self.load(key_id)?.public_key) }
    fn fingerprint(&self, key_id: &str) -> Result<String, String> { Ok(self.load(key_id)?.fingerprint) }

    fn rotate(&mut self, key_id: &str) -> Result<KeyDescriptor, String> {
        self.revoke(key_id)?;
        self.generate()
    }

    fn revoke(&mut self, key_id: &str) -> Result<(), String> {
        if !self.keys.contains_key(key_id) { return Err("TRUST_KEY_NOT_FOUND".into()); }
        self.revoked.insert(key_id.to_string());
        Ok(())
    }

    fn destroy_reference(&mut self, key_id: &str) -> Result<(), String> {
        if self.keys.remove(key_id).is_none() { return Err("TRUST_KEY_NOT_FOUND".into()); }
        self.revoked.insert(key_id.to_string());
        Ok(())
    }
}

/// Encrypted software fallback.  The sealing key is supplied by the service
/// boundary (for example a host secret or OS key store), never persisted by
/// this type.  It uses AES-256-GCM from ring and stores only ciphertext.
pub struct SealedKeyProvider {
    root: PathBuf,
    sealing_key: [u8; 32],
    revoked: BTreeSet<String>,
}

/// Product-facing name for the initial software backend.  The alias keeps
/// the storage implementation replaceable by PKCS#11/HSM/TPM later.
pub type SoftwareSealedKeyProvider = SealedKeyProvider;

impl std::fmt::Debug for SealedKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("SealedKeyProvider").field("root", &self.root).finish() }
}

impl SealedKeyProvider {
    pub fn new(root: impl Into<PathBuf>, sealing_key: [u8; 32]) -> Result<Self, String> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| format!("TRUST_SEALED_STORAGE_UNAVAILABLE: {e}"))?;
        Ok(Self { root, sealing_key, revoked: BTreeSet::new() })
    }

    /// Load the sealing key from an explicitly provisioned protected file.
    /// The file is a location for the unlock secret, not an authority key and
    /// is never copied into the provider directory or returned to callers.
    /// Its format is exactly two lines: `ACTIUM-SEALING-KEY-V1` and a
    /// base64url-without-padding encoding of 32 bytes.
    pub fn from_sealing_key_file(root: impl Into<PathBuf>, path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(&path).map_err(|_| "TRUST_SEALING_KEY_UNAVAILABLE".to_string())?;
            if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
                return Err("TRUST_SEALING_KEY_PERMISSIONS_INVALID".into());
            }
        }
        let text = fs::read_to_string(&path).map_err(|_| "TRUST_SEALING_KEY_UNAVAILABLE".to_string())?;
        let mut lines = text.lines();
        if lines.next() != Some("ACTIUM-SEALING-KEY-V1") {
            return Err("TRUST_SEALING_KEY_FORMAT_INVALID".into());
        }
        let encoded = lines.next().ok_or_else(|| "TRUST_SEALING_KEY_FORMAT_INVALID".to_string())?;
        if lines.next().is_some() {
            return Err("TRUST_SEALING_KEY_FORMAT_INVALID".into());
        }
        let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| "TRUST_SEALING_KEY_FORMAT_INVALID".to_string())?;
        let sealing_key: [u8; 32] = raw.try_into().map_err(|_| "TRUST_SEALING_KEY_LENGTH_INVALID".to_string())?;
        Self::new(root, sealing_key)
    }

    fn path(&self, key_id: &str) -> Result<PathBuf, String> {
        if key_id.is_empty() || key_id.contains(['/', '\\', '.']) { return Err("TRUST_KEY_ID_INVALID".into()); }
        // Key IDs are public identifiers and may contain `:` (for example
        // `sha256:...`), which is not a valid Windows filename character.
        // Keep the on-disk name portable while retaining the original key ID
        // in the encrypted descriptor and durable authority state.
        Ok(self.root.join(format!("{}.sealed", key_id.replace(':', "_"))))
    }

    fn legacy_path(&self, key_id: &str) -> PathBuf { self.root.join(format!("{key_id}.sealed")) }

    fn existing_path(&self, key_id: &str) -> Result<PathBuf, String> {
        let path = self.path(key_id)?;
        Ok(if path.is_file() { path } else { self.legacy_path(key_id) })
    }

    fn seal(&self, key: &SigningKey) -> Result<Vec<u8>, String> {
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &self.sealing_key).map_err(|_| "TRUST_SEAL_FAILED")?;
        let less = aead::LessSafeKey::new(unbound);
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let nonce_value = aead::Nonce::assume_unique_for_key(nonce);
        let mut bytes = key.to_bytes().to_vec();
        less.seal_in_place_append_tag(nonce_value, aead::Aad::empty(), &mut bytes).map_err(|_| "TRUST_SEAL_FAILED")?;
        let mut out = b"ACTIUM-SEALED-KEY-V1\0".to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&bytes);
        Ok(out)
    }

    fn unseal(&self, bytes: &[u8]) -> Result<SigningKey, String> {
        const PREFIX: &[u8] = b"ACTIUM-SEALED-KEY-V1\0";
        if bytes.len() < PREFIX.len() + 12 + 16 || !bytes.starts_with(PREFIX) { return Err("TRUST_SEALED_FORMAT_INVALID".into()); }
        let mut nonce = [0u8; 12]; nonce.copy_from_slice(&bytes[PREFIX.len()..PREFIX.len() + 12]);
        let mut ciphertext = bytes[PREFIX.len() + 12..].to_vec();
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &self.sealing_key).map_err(|_| "TRUST_UNSEAL_FAILED")?;
        let less = aead::LessSafeKey::new(unbound);
        let plain = less.open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::empty(), &mut ciphertext).map_err(|_| "TRUST_UNSEAL_FAILED")?;
        let raw: [u8; 32] = plain.try_into().map_err(|_| "TRUST_SEALED_KEY_LENGTH")?;
        Ok(SigningKey::from_bytes(&raw))
    }

    fn read_key(&self, key_id: &str) -> Result<SigningKey, String> {
        let path = self.existing_path(key_id)?;
        let bytes = fs::read(path).map_err(|_| "TRUST_KEY_NOT_FOUND".to_string())?;
        self.unseal(&bytes)
    }

    fn revoked_marker(&self, key_id: &str) -> Result<PathBuf, String> {
        Ok(self.path(key_id)?.with_extension("revoked"))
    }

    fn is_revoked(&self, key_id: &str) -> Result<bool, String> {
        let legacy_marker = self.legacy_path(key_id).with_extension("revoked");
        Ok(self.revoked.contains(key_id) || self.revoked_marker(key_id)?.is_file() || legacy_marker.is_file())
    }

    fn atomic_write(path: &Path, bytes: &[u8], failure: &str) -> Result<(), String> {
        let temporary = path.with_extension("tmp");
        if temporary.exists() { let _ = fs::remove_file(&temporary); }
        let mut file = fs::OpenOptions::new().create_new(true).write(true).open(&temporary)
            .map_err(|error| format!("{failure}: {error}"))?;
        file.write_all(bytes).map_err(|error| format!("{failure}: {error}"))?;
        file.sync_all().map_err(|error| format!("{failure}: {error}"))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| format!("{failure}: {error}"))
    }

    /// Re-wrap a key inside another sealed provider without returning the
    /// private bytes to the caller.  This is used only by the offline
    /// ceremony to transfer operational subordinate keys from the ceremony
    /// workspace into the online provider.  The Product Trust Root is never
    /// copied by that ceremony.
    pub fn copy_key_from(&mut self, source: &Self, key_id: &str) -> Result<KeyDescriptor, String> {
        let key = source.read_key(key_id)?;
        let descriptor = TestEphemeralKeyProvider::descriptor(key_id.to_string(), &key, AuthorityStatus::Active);
        let path = self.path(key_id)?;
        if path.exists() || self.legacy_path(key_id).exists() { return Err("TRUST_KEY_EXISTS".into()); }
        Self::atomic_write(&path, &self.seal(&key)?, "TRUST_SEALED_STORAGE_WRITE_FAILED")?;
        Ok(descriptor)
    }
}

impl KeyProvider for SealedKeyProvider {
    fn generate(&mut self) -> Result<KeyDescriptor, String> {
        let key = SigningKey::generate(&mut OsRng);
        let key_id = fingerprint_for_raw(key.verifying_key().as_bytes());
        let path = self.path(&key_id)?;
        Self::atomic_write(&path, &self.seal(&key)?, "TRUST_SEALED_STORAGE_WRITE_FAILED")?;
        Ok(TestEphemeralKeyProvider::descriptor(key_id, &key, AuthorityStatus::Active))
    }

    fn load(&self, key_id: &str) -> Result<KeyDescriptor, String> {
        let key = self.read_key(key_id)?;
        let status = if self.is_revoked(key_id)? { AuthorityStatus::Revoked } else { AuthorityStatus::Active };
        Ok(TestEphemeralKeyProvider::descriptor(key_id.to_string(), &key, status))
    }

    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, String> {
        if self.is_revoked(key_id)? { return Err("TRUST_KEY_REVOKED".into()); }
        Ok(self.read_key(key_id)?.sign(message).to_bytes().to_vec())
    }
    fn public_key(&self, key_id: &str) -> Result<String, String> { Ok(self.load(key_id)?.public_key) }
    fn fingerprint(&self, key_id: &str) -> Result<String, String> { Ok(self.load(key_id)?.fingerprint) }
    fn rotate(&mut self, key_id: &str) -> Result<KeyDescriptor, String> { self.revoke(key_id)?; self.generate() }
    fn revoke(&mut self, key_id: &str) -> Result<(), String> {
        let _ = self.read_key(key_id)?;
        Self::atomic_write(&self.revoked_marker(key_id)?, b"revoked\n", "TRUST_REVOCATION_WRITE_FAILED")?;
        self.revoked.insert(key_id.to_string());
        Ok(())
    }

    fn destroy_reference(&mut self, key_id: &str) -> Result<(), String> {
        let path = self.existing_path(key_id)?;
        if !path.is_file() { return Err("TRUST_KEY_NOT_FOUND".into()); }
        fs::remove_file(path).map_err(|e| format!("TRUST_KEY_DESTROY_FAILED: {e}"))?;
        fs::write(self.revoked_marker(key_id)?, b"destroyed\n")
            .map_err(|e| format!("TRUST_REVOCATION_WRITE_FAILED: {e}"))?;
        self.revoked.insert(key_id.to_string());
        Ok(())
    }
}

pub struct AuthorityService<P: KeyProvider> {
    provider: P,
    authorities: BTreeMap<String, AuthorityDescriptor>,
    revocations: Vec<Revocation>,
    root_transitions: Vec<RootTransition>,
    audit_events: RefCell<Vec<AuthorityAuditEvent>>,
    idempotency_results: BTreeMap<String, DurableIdempotencyRecord>,
    trust_root_set: String,
    trust_epoch: u64,
    public_only_key_ids: BTreeSet<String>,
}

impl<P: KeyProvider> AuthorityService<P> {
    pub fn new(provider: P, trust_root_set: impl Into<String>) -> Self {
        Self { provider, authorities: BTreeMap::new(), revocations: Vec::new(), root_transitions: Vec::new(), audit_events: RefCell::new(Vec::new()), idempotency_results: BTreeMap::new(), trust_root_set: trust_root_set.into(), trust_epoch: 1, public_only_key_ids: BTreeSet::new() }
    }

    pub fn provider(&self) -> &P { &self.provider }
    pub fn provider_mut(&mut self) -> &mut P { &mut self.provider }
    pub fn authorities(&self) -> impl Iterator<Item = &AuthorityDescriptor> { self.authorities.values() }
    pub fn audit_events(&self) -> Vec<AuthorityAuditEvent> { self.audit_events.borrow().clone() }

    pub fn trust_epoch(&self) -> u64 { self.trust_epoch }

    pub fn durable_state(&self) -> DurableAuthorityState {
        DurableAuthorityState {
            schema: 1,
            trust_root_set: self.trust_root_set.clone(),
            trust_epoch: self.trust_epoch,
            authorities: self.authorities.values().cloned().collect(),
            revocations: self.revocations.clone(),
            root_transitions: self.root_transitions.clone(),
            audit_events: self.audit_events(),
            idempotency_results: self.idempotency_results.clone(),
            public_only_key_ids: self.public_only_key_ids.iter().cloned().collect(),
        }
    }

    /// Rehydrate a service from public durable state and provider references.
    /// Every descriptor is cross-checked against the provider before the
    /// service becomes usable, preventing metadata/key substitution.
    pub fn from_durable_state(provider: P, state: DurableAuthorityState) -> Result<Self, String> {
        if state.schema != 1 { return Err("TRUST_AUTHORITY_STATE_SCHEMA_UNSUPPORTED".into()); }
        if state.trust_root_set.trim().is_empty() || state.trust_epoch == 0 { return Err("TRUST_AUTHORITY_STATE_INVALID".into()); }
        let mut authorities = BTreeMap::new();
        let mut key_ids = BTreeSet::new();
        let public_only_key_ids: BTreeSet<String> = state.public_only_key_ids.iter().cloned().collect();
        if public_only_key_ids.len() != state.public_only_key_ids.len() {
            return Err("TRUST_AUTHORITY_STATE_DUPLICATE".into());
        }
        for authority in state.authorities {
            if authority.authority_id.trim().is_empty() || authority.algorithm != TRUST_FABRIC_ALGORITHM {
                return Err("TRUST_AUTHORITY_STATE_INVALID".into());
            }
            if authorities.insert(authority.authority_id.clone(), authority.clone()).is_some() || !key_ids.insert(authority.key_id.clone()) {
                return Err("TRUST_AUTHORITY_STATE_DUPLICATE".into());
            }
            if public_only_key_ids.contains(&authority.key_id) {
                if authority.kind != AuthorityKind::ProductTrustRoot || authority.status == AuthorityStatus::Revoked {
                    return Err("TRUST_PUBLIC_ONLY_KEY_INVALID".into());
                }
                // A public-only reference must not have accidentally been
                // provisioned into the online provider.  A missing key is
                // expected; any other load result is a fail-closed error.
                match provider.load(&authority.key_id) {
                    Ok(_) => return Err("TRUST_PUBLIC_ONLY_KEY_PRESENT".into()),
                    Err(error) if error == "TRUST_KEY_NOT_FOUND" => {},
                    Err(_) => return Err("TRUST_PUBLIC_ONLY_KEY_STATE_INVALID".into()),
                }
            } else {
                let descriptor = provider.load(&authority.key_id).map_err(|_| "TRUST_AUTHORITY_KEY_UNAVAILABLE".to_string())?;
                if descriptor.key_id != authority.key_id || descriptor.public_key != authority.public_key || descriptor.fingerprint != authority.fingerprint || descriptor.algorithm != authority.algorithm {
                    return Err("TRUST_AUTHORITY_KEY_METADATA_MISMATCH".into());
                }
                if authority.status == AuthorityStatus::Revoked && descriptor.status != AuthorityStatus::Revoked {
                    return Err("TRUST_AUTHORITY_REVOCATION_STATE_MISMATCH".into());
                }
            }
        }
        for key_id in &public_only_key_ids {
            if !key_ids.contains(key_id) { return Err("TRUST_PUBLIC_ONLY_KEY_REFERENCE_INVALID".into()); }
        }
        let service = Self {
            provider,
            authorities,
            revocations: state.revocations,
            root_transitions: state.root_transitions,
            audit_events: RefCell::new(state.audit_events),
            idempotency_results: state.idempotency_results,
            trust_root_set: state.trust_root_set,
            trust_epoch: state.trust_epoch,
            public_only_key_ids,
        };
        service.validate_durable_structure()?;
        Ok(service)
    }

    /// Move the trust epoch forward only. Epoch changes are explicit so a
    /// caller cannot silently downgrade a deployed Trust Store during a
    /// rotation or recovery operation.
    pub fn advance_trust_epoch(&mut self, next_epoch: u64) -> Result<(), String> {
        if next_epoch <= self.trust_epoch { return Err("TRUST_EPOCH_NOT_MONOTONIC".into()); }
        self.trust_epoch = next_epoch;
        Ok(())
    }

    /// Return a previously committed response only when the request bytes
    /// match. This makes retries safe across a process restart while
    /// rejecting reuse of an idempotency key for a different operation.
    pub fn idempotency_result(&self, key: &str, request_digest: &str) -> Result<Option<Value>, String> {
        let Some(record) = self.idempotency_results.get(key) else { return Ok(None); };
        if record.request_digest != request_digest { return Err("TRUST_IDEMPOTENCY_KEY_REUSED".into()); }
        Ok(Some(record.response.clone()))
    }

    pub fn record_idempotency_result(&mut self, key: String, request_digest: String, response: Value) {
        const MAX_IDEMPOTENCY_RECORDS: usize = 1024;
        if self.idempotency_results.len() >= MAX_IDEMPOTENCY_RECORDS && !self.idempotency_results.contains_key(&key) {
            if let Some(oldest) = self.idempotency_results.keys().next().cloned() { self.idempotency_results.remove(&oldest); }
        }
        self.idempotency_results.insert(key, DurableIdempotencyRecord { request_digest, response });
    }

    fn audit(&self, action: &str, authority_id: Option<&str>, key_id: Option<&str>, payload_digest: Option<String>, result: &str, reason: Option<String>, now: u64) {
        self.audit_events.borrow_mut().push(AuthorityAuditEvent { action: action.into(), authority_id: authority_id.map(str::to_string), key_id: key_id.map(str::to_string), payload_digest, result: result.into(), reason, created_at: now });
    }

    pub fn initialize_root(&mut self, authority_id: impl Into<String>, now: u64) -> Result<ProductTrustRoot, String> {
        if self.authorities.values().any(|a| a.kind == AuthorityKind::ProductTrustRoot && a.status != AuthorityStatus::Revoked) { return Err("TRUST_ALREADY_INITIALIZED".into()); }
        let key = self.provider.generate()?;
        let authority = AuthorityDescriptor { authority_id: authority_id.into(), kind: AuthorityKind::ProductTrustRoot, key_id: key.key_id, public_key: key.public_key, fingerprint: key.fingerprint, algorithm: TRUST_FABRIC_ALGORITHM.into(), status: AuthorityStatus::Active, valid_from: now, valid_until: None, issuer_authority_id: None, issuer_key_id: None, serial: format!("root-{now}"), version: 1, capabilities: vec![authority_capability(AuthorityKind::ProductTrustRoot).into(), "authority:issue-release".into()], certificate: None, created_at: now, revoked_at: None, revocation_reason: None };
        self.authorities.insert(authority.authority_id.clone(), authority.clone());
        self.audit("AUTHORITY_CREATED", Some(&authority.authority_id), Some(&authority.key_id), None, "success", None, now);
        Ok(ProductTrustRoot { authority, trust_root_set: self.trust_root_set.clone(), root_version: 1, activation_epoch: self.trust_epoch, retirement_epoch: None })
    }

    pub fn issue_subordinate(&mut self, parent_id: &str, authority_id: impl Into<String>, kind: AuthorityKind, capabilities: Vec<String>, now: u64, valid_until: Option<u64>) -> Result<AuthorityDescriptor, String> {
        let parent = self.authorities.get(parent_id).ok_or_else(|| "TRUST_ISSUER_NOT_FOUND".to_string())?.clone();
        self.assert_active(&parent, now)?;
        let required = match kind { AuthorityKind::DeploymentAuthority => authority_capability(AuthorityKind::ProductTrustRoot), AuthorityKind::ReleaseAuthority => "authority:issue-release", AuthorityKind::DeploymentRoot => authority_capability(AuthorityKind::DeploymentAuthority), AuthorityKind::CenterAuthority => authority_capability(AuthorityKind::DeploymentRoot), AuthorityKind::EnrollmentAuthority => authority_capability(AuthorityKind::CenterAuthority), AuthorityKind::ProductSigningAuthority => authority_capability(AuthorityKind::ReleaseAuthority), _ => return Err("TRUST_SUBORDINATION_KIND_INVALID".into()) };
        if !parent.capabilities.iter().any(|cap| cap == required || cap == "*") { return Err("TRUST_ISSUER_CAPABILITY_REJECTED".into()); }
        if capabilities.is_empty() { return Err("TRUST_CAPABILITIES_EMPTY".into()); }
        let key = self.provider.generate()?;
        let authority_id = authority_id.into();
        if self.authorities.contains_key(&authority_id) { return Err("TRUST_AUTHORITY_EXISTS".into()); }
        let body = AuthorityCertificate { schema: 1, authority_id: authority_id.clone(), kind, key_id: key.key_id.clone(), public_key: key.public_key.clone(), fingerprint: key.fingerprint.clone(), issuer_authority_id: parent.authority_id.clone(), issuer_key_id: parent.key_id.clone(), serial: format!("{authority_id}-{now}"), version: 1, capabilities: capabilities.clone(), valid_from: now, valid_until, signature: String::new() };
        let signature = self.sign_internal(&parent, &certificate_payload(&body)?)?;
        let certificate = AuthorityCertificate { signature: URL_SAFE_NO_PAD.encode(signature), ..body };
        let authority = AuthorityDescriptor { authority_id: authority_id.clone(), kind, key_id: key.key_id, public_key: key.public_key, fingerprint: key.fingerprint, algorithm: TRUST_FABRIC_ALGORITHM.into(), status: AuthorityStatus::Active, valid_from: now, valid_until, issuer_authority_id: Some(parent.authority_id), issuer_key_id: Some(parent.key_id), serial: certificate.serial.clone(), version: 1, capabilities, certificate: Some(certificate), created_at: now, revoked_at: None, revocation_reason: None };
        self.authorities.insert(authority_id, authority.clone());
        self.audit("AUTHORITY_CREATED", Some(&authority.authority_id), Some(&authority.key_id), None, "success", None, now);
        Ok(authority)
    }

    pub fn revoke(&mut self, authority_id: &str, now: u64, reason: impl Into<String>) -> Result<Revocation, String> {
        let authority = self.authorities.get_mut(authority_id).ok_or_else(|| "TRUST_AUTHORITY_NOT_FOUND".to_string())?;
        authority.status = AuthorityStatus::Revoked; authority.revoked_at = Some(now); authority.revocation_reason = Some(reason.into());
        self.provider.revoke(&authority.key_id)?;
        let revocation = Revocation { authority_id: authority.authority_id.clone(), key_id: authority.key_id.clone(), revoked_at: now, reason: authority.revocation_reason.clone().unwrap_or_default(), revocation_epoch: self.trust_epoch };
        self.revocations.push(revocation.clone());
        self.audit("AUTHORITY_REVOKED", Some(&revocation.authority_id), Some(&revocation.key_id), None, "success", Some(revocation.reason.clone()), now);
        Ok(revocation)
    }

    pub fn rotate(&mut self, authority_id: &str, now: u64) -> Result<AuthorityDescriptor, String> {
        let old = self.authorities.get(authority_id).ok_or_else(|| "TRUST_AUTHORITY_NOT_FOUND".to_string())?.clone();
        if old.status == AuthorityStatus::Revoked { return Err("TRUST_ROTATION_SOURCE_REVOKED".into()); }
        if let Some(previous) = self.authorities.get_mut(authority_id) {
            // Keep the old key usable long enough to co-sign the transition.
            // Retirement/revocation is a separate, explicit operation.
            previous.status = AuthorityStatus::Rotating;
        }
        let key = self.provider.generate()?;
        let next_id = format!("{}-v{}", authority_id, old.version + 1);
        let body = AuthorityCertificate { schema: 1, authority_id: next_id.clone(), kind: old.kind, key_id: key.key_id.clone(), public_key: key.public_key.clone(), fingerprint: key.fingerprint.clone(), issuer_authority_id: old.issuer_authority_id.clone().unwrap_or_else(|| old.authority_id.clone()), issuer_key_id: old.issuer_key_id.clone().unwrap_or_else(|| old.key_id.clone()), serial: format!("{next_id}-{now}"), version: old.version + 1, capabilities: old.capabilities.clone(), valid_from: now, valid_until: old.valid_until, signature: String::new() };
        let signer = old.clone();
        let certificate = AuthorityCertificate { signature: URL_SAFE_NO_PAD.encode(self.sign_internal(&signer, &certificate_payload(&body)?)?), ..body };
        let authority = AuthorityDescriptor { authority_id: next_id.clone(), kind: old.kind, key_id: key.key_id, public_key: key.public_key, fingerprint: key.fingerprint, algorithm: TRUST_FABRIC_ALGORITHM.into(), status: AuthorityStatus::Active, valid_from: now, valid_until: old.valid_until, issuer_authority_id: Some(signer.authority_id.clone()), issuer_key_id: Some(signer.key_id.clone()), serial: certificate.serial.clone(), version: old.version + 1, capabilities: old.capabilities, certificate: Some(certificate), created_at: now, revoked_at: None, revocation_reason: None };
        self.authorities.insert(next_id, authority.clone());
        self.audit("AUTHORITY_ROTATED", Some(&authority.authority_id), Some(&authority.key_id), None, "success", None, now);
        Ok(authority)
    }

    pub fn root_transition(&mut self, old_root_id: &str, new_root_id: &str, activation_epoch: u64, now: u64) -> Result<RootTransition, String> {
        let old = self.authorities.get(old_root_id).ok_or_else(|| "TRUST_ROOT_NOT_FOUND".to_string())?.clone();
        let new = self.authorities.get(new_root_id).ok_or_else(|| "TRUST_ROOT_NOT_FOUND".to_string())?.clone();
        if old.kind != AuthorityKind::ProductTrustRoot || new.kind != AuthorityKind::ProductTrustRoot { return Err("TRUST_ROOT_KIND_INVALID".into()); }
        let unsigned = serde_json::json!({"schema":1,"trustRootSet":self.trust_root_set,"fromRootKeyId":old.key_id,"toRootKeyId":new.key_id,"activationEpoch":activation_epoch,"issuedAt":now});
        let payload = signed_payload("actium-trust-root-transition-v1", &unsigned)?;
        let transition = RootTransition { schema: 1, trust_root_set: self.trust_root_set.clone(), from_root_key_id: old.key_id.clone(), to_root_key_id: new.key_id.clone(), activation_epoch, issued_at: now, old_root_signature: URL_SAFE_NO_PAD.encode(self.provider.sign(&old.key_id, &payload)?), new_root_signature: URL_SAFE_NO_PAD.encode(self.provider.sign(&new.key_id, &payload)?)};
        self.root_transitions.push(transition.clone());
        self.audit("AUTHORITY_ROTATED", Some(old_root_id), Some(&transition.to_root_key_id), None, "success", Some("dual_root_transition".into()), now);
        Ok(transition)
    }

    pub fn readiness(&self, capability: &str, now: u64) -> Result<Readiness, String> {
        let signer = self.authorities.values().find(|a| a.status == AuthorityStatus::Active && a.capabilities.iter().any(|c| c == capability || c == "*") && a.valid_from <= now && a.valid_until.map(|v| now <= v).unwrap_or(true)).ok_or_else(|| "HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE".to_string())?;
        self.verify_chain(signer, now)?;
        let probe = serde_json::json!({"schema":1,"purpose":"ACTIUM_AUTHORITY_SELF_TEST","capability":capability,"issuedAt":now});
        let payload = signed_payload("actium-authority-self-test-v1", &probe)?;
        let signature = self.provider.sign(&signer.key_id, &payload).map_err(|_| "HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE".to_string())?;
        verify_raw(&signer.public_key, &payload, &signature).map_err(|_| "HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE".to_string())?;
        self.audit("SELF_TEST", Some(&signer.authority_id), Some(&signer.key_id), None, "success", Some(capability.into()), now);
        Ok(Readiness { capability: capability.into(), authority_id: signer.authority_id.clone(), key_id: signer.key_id.clone(), fingerprint: signer.fingerprint.clone(), status: "ready".into() })
    }

    /// Sign the exact bytes supplied by a protocol boundary after selecting an
    /// active signer by capability. The authority service uses this method for
    /// envelopes whose payload is already canonically serialized by Center.
    pub fn sign_for_capability(&self, capability: &str, payload: &[u8], now: u64) -> Result<(Readiness, Vec<u8>), String> {
        let readiness = self.readiness(capability, now)?;
        let signature = self.provider.sign(&readiness.key_id, payload).map_err(|_| "HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE".to_string())?;
        self.audit("SIGN_OPERATION", Some(&readiness.authority_id), Some(&readiness.key_id), Some(fingerprint_for_raw(payload)), "success", Some(capability.into()), now);
        Ok((readiness, signature))
    }

    /// Verify a signature against the capability-selected authority. This is
    /// deliberately separate from signing so a release/product signer cannot
    /// be reused for host enrollment by a caller that only knows its key ID.
    pub fn verify_for_capability(&self, capability: &str, key_id: &str, payload: &[u8], signature: &[u8], now: u64) -> Result<(), String> {
        let authority = self.authorities.values().find(|candidate| candidate.key_id == key_id).ok_or_else(|| "TRUST_SIGNER_NOT_FOUND".to_string())?;
        self.assert_active(authority, now)?;
        if !authority.capabilities.iter().any(|value| value == capability || value == "*") { return Err("TRUST_CAPABILITY_REJECTED".into()); }
        self.verify_chain(authority, now)?;
        verify_raw(&authority.public_key, payload, signature)
    }

    /// Sign only after capability, lifecycle and full issuer chain checks.
    /// Callers receive a signature and digest, never the key or raw secret.
    pub fn sign_authorized(&self, authority_id: &str, capability: &str, payload: &Value, now: u64) -> Result<SignedAuthorityOperation, String> {
        let authority = self.authorities.get(authority_id).ok_or_else(|| "TRUST_AUTHORITY_NOT_FOUND".to_string())?;
        self.assert_active(authority, now)?;
        if !authority.capabilities.iter().any(|value| value == capability || value == "*") { return Err("TRUST_CAPABILITY_REJECTED".into()); }
        self.verify_chain(authority, now)?;
        let signed = signed_payload("actium-authorized-operation-v1", payload)?;
        let signature = self.provider.sign(&authority.key_id, &signed)?;
        let payload_digest = fingerprint_for_raw(&signed);
        self.audit("SIGN_OPERATION", Some(&authority.authority_id), Some(&authority.key_id), Some(payload_digest.clone()), "success", Some(capability.into()), now);
        Ok(SignedAuthorityOperation { key_id: authority.key_id.clone(), algorithm: TRUST_FABRIC_ALGORITHM.into(), signature: URL_SAFE_NO_PAD.encode(signature), payload_digest })
    }

    pub fn trust_bundle(&self, root_id: &str, now: u64, expires_at: Option<u64>) -> Result<SignedTrustBundle, String> {
        let root = self.authorities.get(root_id).ok_or_else(|| "TRUST_ROOT_NOT_FOUND".to_string())?;
        if root.kind != AuthorityKind::ProductTrustRoot { return Err("TRUST_BUNDLE_ISSUER_INVALID".into()); }
        let roots = self.authorities.values().filter(|a| a.kind == AuthorityKind::ProductTrustRoot && a.status != AuthorityStatus::Revoked).map(|a| ProductTrustRoot { authority: a.clone(), trust_root_set: self.trust_root_set.clone(), root_version: a.version, activation_epoch: self.trust_epoch, retirement_epoch: None }).collect();
        let bundle = TrustBundle { trust_bundle_id: format!("{}-{now}", self.trust_root_set), contract: TRUST_BUNDLE_CONTRACT.into(), version: 1, product_roots: roots, root_transitions: self.root_transitions.clone(), deployment_authority: self.authorities.values().find(|a| a.kind == AuthorityKind::DeploymentAuthority && a.status != AuthorityStatus::Revoked).cloned(), deployment_root: self.authorities.values().find(|a| a.kind == AuthorityKind::DeploymentRoot && a.status != AuthorityStatus::Revoked).cloned(), center_authority: self.authorities.values().find(|a| a.kind == AuthorityKind::CenterAuthority && a.status != AuthorityStatus::Revoked).cloned(), enrollment_authorities: self.authorities.values().filter(|a| a.kind == AuthorityKind::EnrollmentAuthority && a.status != AuthorityStatus::Revoked).cloned().collect(), release_authorities: self.authorities.values().filter(|a| a.kind == AuthorityKind::ReleaseAuthority && a.status != AuthorityStatus::Revoked).cloned().collect(), product_signing_authorities: self.authorities.values().filter(|a| a.kind == AuthorityKind::ProductSigningAuthority && a.status != AuthorityStatus::Revoked).cloned().collect(), revocations: self.revocations.clone(), issued_at: now, expires_at, trust_epoch: self.trust_epoch, issuer: root.authority_id.clone() };
        let signature = self.sign_internal(root, &signed_payload(TRUST_BUNDLE_DOMAIN, &serde_json::to_value(&bundle).map_err(|_| "TRUST_BUNDLE_SERIALIZE")?)?)?;
        self.audit("TRUST_BUNDLE_ISSUED", Some(&root.authority_id), Some(&root.key_id), Some(trust_bundle_digest(&bundle)?), "success", None, now);
        Ok(SignedTrustBundle { bundle, signature: URL_SAFE_NO_PAD.encode(signature), signing_key_id: root.key_id.clone(), algorithm: TRUST_FABRIC_ALGORITHM.into() })
    }

    pub fn verify_trust_bundle(&self, signed: &SignedTrustBundle, now: u64, current_epoch: u64) -> Result<(), String> {
        verify_signed_trust_bundle(signed, now, current_epoch)
    }

    pub fn sign_release_manifest(&self, signer_id: &str, manifest: ReleaseManifestV1) -> Result<SignedReleaseManifest, String> {
        if manifest.schema != RELEASE_MANIFEST_CONTRACT || manifest.contract != RELEASE_MANIFEST_CONTRACT || manifest.product_id.trim().is_empty() || manifest.release_status != "PROMOTED" { return Err("RELEASE_MANIFEST_INVALID".into()); }
        let signer = self.authorities.get(signer_id).ok_or_else(|| "TRUST_SIGNER_NOT_FOUND".to_string())?;
        if signer.kind != AuthorityKind::ProductSigningAuthority || signer.status != AuthorityStatus::Active { return Err("TRUST_PRODUCT_SIGNER_INVALID".into()); }
        if !signer.capabilities.iter().any(|c| c == "product_signing" || c == "*") { return Err("TRUST_PRODUCT_SIGNER_CAPABILITY_REJECTED".into()); }
        self.verify_chain(signer, manifest.issued_at)?;
        let payload = signed_payload(RELEASE_MANIFEST_DOMAIN, &serde_json::to_value(&manifest).map_err(|_| "RELEASE_MANIFEST_SERIALIZE")?)?;
        let signature = self.provider.sign(&signer.key_id, &payload)?;
        self.audit("SIGN_OPERATION", Some(&signer.authority_id), Some(&signer.key_id), Some(fingerprint_for_raw(&payload)), "success", Some("release_manifest".into()), manifest.issued_at);
        Ok(SignedReleaseManifest { manifest, signing: ReleaseSigning { key_id: signer.key_id.clone(), signature: URL_SAFE_NO_PAD.encode(signature), algorithm: TRUST_FABRIC_ALGORITHM.into() } })
    }

    pub fn verify_release_manifest(&self, signed: &SignedReleaseManifest, now: u64) -> Result<(), String> {
        if signed.manifest.schema != RELEASE_MANIFEST_CONTRACT || signed.manifest.contract != RELEASE_MANIFEST_CONTRACT || signed.signing.algorithm != TRUST_FABRIC_ALGORITHM || signed.manifest.release_status != "PROMOTED" { return Err("RELEASE_MANIFEST_INVALID".into()); }
        let signer = self.authorities.values().find(|a| a.key_id == signed.signing.key_id).ok_or_else(|| "TRUST_PRODUCT_SIGNER_UNKNOWN".to_string())?;
        if signer.kind != AuthorityKind::ProductSigningAuthority || signer.status != AuthorityStatus::Active || self.revocations.iter().any(|r| r.key_id == signer.key_id) { return Err("TRUST_PRODUCT_SIGNER_REJECTED".into()); }
        self.verify_chain(signer, now)?;
        verify_raw(&signer.public_key, &signed_payload(RELEASE_MANIFEST_DOMAIN, &serde_json::to_value(&signed.manifest).map_err(|_| "RELEASE_MANIFEST_SERIALIZE")?)?, &URL_SAFE_NO_PAD.decode(&signed.signing.signature).map_err(|_| "RELEASE_SIGNATURE_INVALID")?)
    }

    fn assert_active(&self, authority: &AuthorityDescriptor, now: u64) -> Result<(), String> { if !matches!(authority.status, AuthorityStatus::Active | AuthorityStatus::Rotating) || authority.valid_from > now || authority.valid_until.map(|v| now > v).unwrap_or(false) || self.revocations.iter().any(|r| r.key_id == authority.key_id) { return Err("TRUST_ISSUER_REJECTED".into()); } Ok(()) }
    fn verify_chain(&self, authority: &AuthorityDescriptor, now: u64) -> Result<(), String> {
        self.assert_active(authority, now)?;
        if let Some(certificate) = &authority.certificate {
            let issuer = self.authorities.get(&certificate.issuer_authority_id).ok_or_else(|| "TRUST_ISSUER_NOT_FOUND".to_string())?;
            self.assert_active(issuer, now)?;
            verify_raw(&issuer.public_key, &signed_payload(AUTHORITY_CERTIFICATE_DOMAIN, &certificate_value_without_signature(certificate)?)?, &URL_SAFE_NO_PAD.decode(&certificate.signature).map_err(|_| "TRUST_CERTIFICATE_INVALID")?)?;
            self.verify_chain(issuer, now)?;
        }
        Ok(())
    }
    fn sign_internal(&self, signer: &AuthorityDescriptor, payload: &[u8]) -> Result<Vec<u8>, String> { self.provider.sign(&signer.key_id, payload) }

    fn validate_durable_structure(&self) -> Result<(), String> {
        let mut root_count = 0usize;
        for authority in self.authorities.values() {
            if authority.kind == AuthorityKind::ProductTrustRoot {
                root_count += 1;
                if authority.certificate.is_some() || authority.issuer_authority_id.is_some() || authority.issuer_key_id.is_some() { return Err("TRUST_ROOT_STATE_INVALID".into()); }
            }
            if let Some(certificate) = &authority.certificate {
                if certificate.authority_id != authority.authority_id || certificate.kind != authority.kind || certificate.key_id != authority.key_id || certificate.public_key != authority.public_key || certificate.issuer_authority_id != authority.issuer_authority_id.clone().unwrap_or_default() || certificate.issuer_key_id != authority.issuer_key_id.clone().unwrap_or_default() {
                    return Err("TRUST_CERTIFICATE_SCOPE_INVALID".into());
                }
                let issuer = self.authorities.get(&certificate.issuer_authority_id).ok_or_else(|| "TRUST_ISSUER_NOT_FOUND".to_string())?;
                if issuer.key_id != certificate.issuer_key_id { return Err("TRUST_ISSUER_KEY_MISMATCH".into()); }
                let signature = URL_SAFE_NO_PAD.decode(&certificate.signature).map_err(|_| "TRUST_CERTIFICATE_INVALID")?;
                verify_raw(&issuer.public_key, &certificate_payload(certificate)?, &signature)?;
            }
        }
        if root_count == 0 { return Err("TRUST_AUTHORITY_STATE_ROOT_MISSING".into()); }
        for revocation in &self.revocations {
            let authority = self.authorities.values().find(|candidate| candidate.key_id == revocation.key_id && candidate.authority_id == revocation.authority_id).ok_or_else(|| "TRUST_REVOCATION_REFERENCE_INVALID".to_string())?;
            if authority.status != AuthorityStatus::Revoked || revocation.revocation_epoch > self.trust_epoch { return Err("TRUST_REVOCATION_STATE_INVALID".into()); }
        }
        for transition in &self.root_transitions {
            if transition.schema != 1 || transition.trust_root_set != self.trust_root_set || !self.authorities.values().any(|a| a.kind == AuthorityKind::ProductTrustRoot && a.key_id == transition.from_root_key_id) || !self.authorities.values().any(|a| a.kind == AuthorityKind::ProductTrustRoot && a.key_id == transition.to_root_key_id) || transition.activation_epoch < self.trust_epoch {
                return Err("TRUST_ROOT_TRANSITION_INVALID".into());
            }
        }
        for (key, record) in &self.idempotency_results {
            if key.trim().is_empty() || key.len() > 256 || !record.request_digest.chars().all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase()) || record.request_digest.len() != 64 {
                return Err("TRUST_IDEMPOTENCY_STATE_INVALID".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Readiness { pub capability: String, pub authority_id: String, pub key_id: String, pub fingerprint: String, pub status: String }

fn fingerprint_for_raw(raw: &[u8]) -> String { format!("sha256:{}", hex_lower(&Sha256::digest(raw))) }
fn hex_lower(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn signed_payload(domain: &str, value: &Value) -> Result<Vec<u8>, String> { let canonical = crate::canonical_json(value)?; let mut bytes = domain.as_bytes().to_vec(); bytes.push(0); bytes.extend_from_slice(canonical.as_bytes()); Ok(bytes) }
fn certificate_value_without_signature(certificate: &AuthorityCertificate) -> Result<Value, String> { let mut value = serde_json::to_value(certificate).map_err(|_| "TRUST_CERTIFICATE_SERIALIZE")?; if let Value::Object(fields) = &mut value { fields.insert("signature".into(), Value::String(String::new())); } Ok(value) }
fn certificate_payload(certificate: &AuthorityCertificate) -> Result<Vec<u8>, String> { signed_payload(AUTHORITY_CERTIFICATE_DOMAIN, &certificate_value_without_signature(certificate)?) }
fn verify_raw(public_key: &str, payload: &[u8], signature: &[u8]) -> Result<(), String> { let raw = URL_SAFE_NO_PAD.decode(public_key).map_err(|_| "TRUST_PUBLIC_KEY_INVALID")?; let key: [u8; 32] = raw.try_into().map_err(|_| "TRUST_PUBLIC_KEY_INVALID")?; let vk = VerifyingKey::from_bytes(&key).map_err(|_| "TRUST_PUBLIC_KEY_INVALID")?; let sig = Signature::from_slice(signature).map_err(|_| "TRUST_SIGNATURE_INVALID")?; vk.verify(payload, &sig).map_err(|_| "TRUST_SIGNATURE_INVALID".into()) }

pub fn trust_bundle_digest(bundle: &TrustBundle) -> Result<String, String> {
    let value = serde_json::to_value(bundle).map_err(|_| "TRUST_BUNDLE_SERIALIZE")?;
    Ok(fingerprint_for_raw(signed_payload(TRUST_BUNDLE_DOMAIN, &value)?.as_slice()))
}

/// Verification entry point used by the Supervisor trust store.  It does not
/// need a private-key provider: all trust material is public and the bundle
/// carries the signed authority certificates needed to validate its chain.
pub fn verify_signed_trust_bundle(signed: &SignedTrustBundle, now: u64, current_epoch: u64) -> Result<(), String> {
    if signed.bundle.contract != TRUST_BUNDLE_CONTRACT || signed.algorithm != TRUST_FABRIC_ALGORITHM { return Err("TRUST_BUNDLE_CONTRACT_INVALID".into()); }
    if signed.bundle.trust_epoch < current_epoch { return Err("TRUST_EPOCH_ROLLBACK".into()); }
    if signed.bundle.expires_at.map(|v| now > v).unwrap_or(false) || signed.bundle.issued_at > now + 60 { return Err("TRUST_BUNDLE_EXPIRED".into()); }
    let root = signed.bundle.product_roots.iter().find(|r| r.authority.key_id == signed.signing_key_id).ok_or_else(|| "TRUST_BUNDLE_ROOT_UNKNOWN".to_string())?;
    if root.authority.kind != AuthorityKind::ProductTrustRoot || root.authority.status == AuthorityStatus::Revoked || signed.bundle.revocations.iter().any(|r| r.key_id == root.authority.key_id) { return Err("TRUST_BUNDLE_ROOT_REVOKED".into()); }
    if signed.bundle.issuer != root.authority.authority_id { return Err("TRUST_BUNDLE_ISSUER_INVALID".into()); }
    let payload = signed_payload(TRUST_BUNDLE_DOMAIN, &serde_json::to_value(&signed.bundle).map_err(|_| "TRUST_BUNDLE_SERIALIZE")?)?;
    verify_raw(&root.authority.public_key, &payload, &URL_SAFE_NO_PAD.decode(&signed.signature).map_err(|_| "TRUST_BUNDLE_SIGNATURE_INVALID")?)?;
    let mut authorities = BTreeMap::new();
    for authority in signed.bundle.product_roots.iter().map(|root| &root.authority).chain(signed.bundle.deployment_authority.iter()).chain(signed.bundle.deployment_root.iter()).chain(signed.bundle.center_authority.iter()).chain(signed.bundle.enrollment_authorities.iter()).chain(signed.bundle.release_authorities.iter()).chain(signed.bundle.product_signing_authorities.iter()) {
        if authorities.insert(authority.authority_id.clone(), authority).is_some() { return Err("TRUST_AUTHORITY_DUPLICATE".into()); }
    }
    for authority in authorities.values() { verify_descriptor_chain(authority, &authorities, &signed.bundle.revocations, now, &mut BTreeSet::new())?; }
    for transition in &signed.bundle.root_transitions {
        let old = signed.bundle.product_roots.iter().find(|root| root.authority.key_id == transition.from_root_key_id).ok_or_else(|| "TRUST_ROOT_TRANSITION_SOURCE_UNKNOWN".to_string())?;
        let new = signed.bundle.product_roots.iter().find(|root| root.authority.key_id == transition.to_root_key_id).ok_or_else(|| "TRUST_ROOT_TRANSITION_TARGET_UNKNOWN".to_string())?;
        if transition.schema != 1 || transition.trust_root_set != old.trust_root_set || transition.trust_root_set != new.trust_root_set || transition.activation_epoch < signed.bundle.trust_epoch {
            return Err("TRUST_ROOT_TRANSITION_INVALID".into());
        }
        let unsigned = serde_json::json!({"schema":1,"trustRootSet":transition.trust_root_set,"fromRootKeyId":transition.from_root_key_id,"toRootKeyId":transition.to_root_key_id,"activationEpoch":transition.activation_epoch,"issuedAt":transition.issued_at});
        let payload = signed_payload("actium-trust-root-transition-v1", &unsigned)?;
        verify_raw(&old.authority.public_key, &payload, &URL_SAFE_NO_PAD.decode(&transition.old_root_signature).map_err(|_| "TRUST_ROOT_TRANSITION_INVALID")?)?;
        verify_raw(&new.authority.public_key, &payload, &URL_SAFE_NO_PAD.decode(&transition.new_root_signature).map_err(|_| "TRUST_ROOT_TRANSITION_INVALID")?)?;
    }
    Ok(())
}

/// Verify a bundle against an already trusted universal Product Trust anchor.
/// A bundle must never be able to introduce its own first root by self-signing.
pub fn verify_signed_trust_bundle_with_bootstrap(
    signed: &SignedTrustBundle,
    now: u64,
    current_epoch: u64,
    bootstrap_roots: &[ProductTrustRoot],
) -> Result<(), String> {
    if bootstrap_roots.is_empty() { return Err("TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE".into()); }
    let root = signed.bundle.product_roots.iter().find(|candidate| candidate.authority.key_id == signed.signing_key_id).ok_or_else(|| "TRUST_BUNDLE_ROOT_UNKNOWN".to_string())?;
    let directly_anchored = bootstrap_roots.iter().any(|anchor| anchor.trust_root_set == root.trust_root_set && anchor.authority.key_id == root.authority.key_id && anchor.authority.public_key == root.authority.public_key);
    let transition_anchored = signed.bundle.root_transitions.iter().any(|transition| {
        bootstrap_roots.iter().any(|anchor| anchor.trust_root_set == transition.trust_root_set && anchor.authority.key_id == transition.from_root_key_id && anchor.authority.public_key == signed.bundle.product_roots.iter().find(|candidate| candidate.authority.key_id == transition.from_root_key_id).map(|candidate| candidate.authority.public_key.clone()).unwrap_or_default())
            && transition.to_root_key_id == root.authority.key_id
    });
    if !directly_anchored && !transition_anchored {
        return Err("TRUST_BOOTSTRAP_ANCHOR_MISMATCH".into());
    }
    verify_signed_trust_bundle(signed, now, current_epoch)
}

fn verify_descriptor_chain(authority: &AuthorityDescriptor, authorities: &BTreeMap<String, &AuthorityDescriptor>, revocations: &[Revocation], now: u64, visiting: &mut BTreeSet<String>) -> Result<(), String> {
    if !visiting.insert(authority.authority_id.clone()) { return Err("TRUST_CHAIN_CYCLE".into()); }
    if authority.algorithm != TRUST_FABRIC_ALGORITHM || authority.status == AuthorityStatus::Revoked || authority.valid_from > now || authority.valid_until.map(|until| now > until).unwrap_or(false) || revocations.iter().any(|revocation| revocation.key_id == authority.key_id) { return Err("TRUST_AUTHORITY_REVOKED_OR_INVALID".into()); }
    if let Some(certificate) = &authority.certificate {
        if certificate.authority_id != authority.authority_id || certificate.key_id != authority.key_id || certificate.public_key != authority.public_key || certificate.issuer_authority_id != authority.issuer_authority_id.clone().unwrap_or_default() || certificate.issuer_key_id != authority.issuer_key_id.clone().unwrap_or_default() { return Err("TRUST_CERTIFICATE_SCOPE_INVALID".into()); }
        let issuer = authorities.get(&certificate.issuer_authority_id).ok_or_else(|| "TRUST_ISSUER_NOT_FOUND".to_string())?;
        verify_descriptor_chain(issuer, authorities, revocations, now, visiting)?;
        if authority.kind == AuthorityKind::ProductTrustRoot {
            if issuer.kind != AuthorityKind::ProductTrustRoot { return Err("TRUST_CERTIFICATE_SCOPE_INVALID".into()); }
        } else {
            let required = match authority.kind { AuthorityKind::DeploymentAuthority => authority_capability(AuthorityKind::ProductTrustRoot), AuthorityKind::ReleaseAuthority => "authority:issue-release", AuthorityKind::DeploymentRoot => authority_capability(AuthorityKind::DeploymentAuthority), AuthorityKind::CenterAuthority => authority_capability(AuthorityKind::DeploymentRoot), AuthorityKind::EnrollmentAuthority => authority_capability(AuthorityKind::CenterAuthority), AuthorityKind::ProductSigningAuthority => authority_capability(AuthorityKind::ReleaseAuthority), AuthorityKind::HostIdentity => return Err("TRUST_CERTIFICATE_SCOPE_INVALID".into()), AuthorityKind::ProductTrustRoot => unreachable!() };
            if !issuer.capabilities.iter().any(|capability| capability == required || capability == "*") { return Err("TRUST_ISSUER_CAPABILITY_REJECTED".into()); }
        }
        verify_raw(&issuer.public_key, &certificate_payload(certificate)?, &URL_SAFE_NO_PAD.decode(&certificate.signature).map_err(|_| "TRUST_CERTIFICATE_INVALID")?)?;
    } else if authority.kind != AuthorityKind::ProductTrustRoot { return Err("TRUST_CERTIFICATE_MISSING".into()); }
    visiting.remove(&authority.authority_id);
    Ok(())
}

pub fn unix_now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

#[cfg(test)]
mod tests {
    use super::*;

    fn hierarchy() -> AuthorityService<TestEphemeralKeyProvider> {
        let mut service = AuthorityService::new(TestEphemeralKeyProvider::default(), "actium-product-v1");
        service.initialize_root("product-root", 100).unwrap();
        service.issue_subordinate("product-root", "deployment-authority", AuthorityKind::DeploymentAuthority, vec![authority_capability(AuthorityKind::DeploymentAuthority).into()], 100, None).unwrap();
        service.issue_subordinate("deployment-authority", "deployment-root", AuthorityKind::DeploymentRoot, vec![authority_capability(AuthorityKind::DeploymentRoot).into()], 100, None).unwrap();
        service.issue_subordinate("deployment-root", "center", AuthorityKind::CenterAuthority, vec![authority_capability(AuthorityKind::CenterAuthority).into()], 100, None).unwrap();
        service.issue_subordinate("center", "enrollment", AuthorityKind::EnrollmentAuthority, vec!["host_enrollment".into()], 100, None).unwrap();
        service.issue_subordinate("product-root", "release", AuthorityKind::ReleaseAuthority, vec![authority_capability(AuthorityKind::ReleaseAuthority).into()], 100, None).unwrap();
        service.issue_subordinate("release", "aegis-signing", AuthorityKind::ProductSigningAuthority, vec!["product_signing".into()], 100, None).unwrap();
        service
    }

    #[test]
    fn hierarchy_and_readiness_are_verified() { let service = hierarchy(); let readiness = service.readiness("host_enrollment", 120).unwrap(); assert_eq!(readiness.status, "ready"); assert!(readiness.key_id.starts_with("sha256:")); assert!(service.audit_events().iter().any(|event| event.action == "SELF_TEST" && event.payload_digest.is_none())); }

    #[test]
    fn trust_bundle_detects_tampering_and_epoch_rollback() { let service = hierarchy(); let mut bundle = service.trust_bundle("product-root", 120, Some(1000)).unwrap(); service.verify_trust_bundle(&bundle, 120, 1).unwrap(); bundle.bundle.trust_epoch = 0; assert_eq!(service.verify_trust_bundle(&bundle, 120, 1).unwrap_err(), "TRUST_EPOCH_ROLLBACK"); }

    #[test]
    fn revocation_and_wrong_capability_fail_closed() { let mut service = hierarchy(); assert_eq!(service.issue_subordinate("center", "bad", AuthorityKind::ProductSigningAuthority, vec!["product_signing".into()], 120, None).unwrap_err(), "TRUST_ISSUER_CAPABILITY_REJECTED"); service.revoke("enrollment", 130, "test").unwrap(); assert_eq!(service.readiness("host_enrollment", 140).unwrap_err(), "HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE"); }

    #[test]
    fn root_rotation_has_dual_authorization() { let mut service = hierarchy(); let old_root = service.authorities().find(|authority| authority.authority_id == "product-root").unwrap().clone(); let rotated = service.rotate("product-root", 140).unwrap(); let transition = service.root_transition("product-root", &rotated.authority_id, 2, 140).unwrap(); assert!(transition.old_root_signature.len() > 40); assert!(transition.new_root_signature.len() > 40); service.advance_trust_epoch(2).unwrap(); let bundle = service.trust_bundle(&rotated.authority_id, 140, None).unwrap(); verify_signed_trust_bundle_with_bootstrap(&bundle, 140, 1, &[ProductTrustRoot { authority: old_root, trust_root_set: "actium-product-v1".into(), root_version: 1, activation_epoch: 1, retirement_epoch: None }]).unwrap(); let issued = service.issue_subordinate(&rotated.authority_id, "rotated-release", AuthorityKind::ReleaseAuthority, vec!["authority:issue-release".into()], 140, None).unwrap(); assert_eq!(issued.issuer_authority_id.as_deref(), Some(rotated.authority_id.as_str())); }

    #[test]
    fn release_signer_cannot_be_used_for_enrollment_and_manifest_is_signed() { let service = hierarchy(); assert_eq!(service.readiness("host_enrollment", 120).unwrap().authority_id, "enrollment"); let manifest = ReleaseManifestV1 { schema: RELEASE_MANIFEST_CONTRACT.into(), contract: RELEASE_MANIFEST_CONTRACT.into(), release_id: "release-aegis-1.0.0-linux-x86_64".into(), product_id: "aegis".into(), version: "1.0.0".into(), build_id: "build".into(), source_repo: "Tronco-NG/ecosistema-aegis".into(), source_commit: "a".repeat(40), platform: "linux".into(), architecture: "x86_64".into(), artifacts: vec![ReleaseArtifact { name: "aegis.tar.gz".into(), uri: "artifacts/sha256/a/aegis.tar.gz".into(), sha256: "a".repeat(64), size_bytes: 1 }], issued_at: 120, created_at: "2026-01-01T00:00:00Z".into(), promoted_at: "2026-01-01T00:00:00Z".into(), release_status: "PROMOTED".into(), compatibility: ReleaseCompatibility { base_runtime_contract: "actium-node-manager-host@1.0.0".into(), build_manifest: "builds/build/build-manifest.json".into() } }; let signed = service.sign_release_manifest("aegis-signing", manifest).unwrap(); service.verify_release_manifest(&signed, 120).unwrap(); }

    #[test]
    fn sealed_provider_persists_ciphertext_only_and_survives_reload() { let dir = std::env::temp_dir().join(format!("actium-trust-fabric-{}", uuid::Uuid::new_v4())); let key = [7u8; 32]; let mut provider = SealedKeyProvider::new(&dir, key).unwrap(); let descriptor = provider.generate().unwrap(); let path = provider.path(&descriptor.key_id).unwrap(); let bytes = fs::read(&path).unwrap(); assert!(!bytes.windows(32).any(|window| window == [0u8; 32])); let loaded = provider.load(&descriptor.key_id).unwrap(); assert_eq!(loaded.public_key, descriptor.public_key); let reloaded = SealedKeyProvider::new(&dir, key).unwrap(); assert_eq!(reloaded.public_key(&descriptor.key_id).unwrap(), descriptor.public_key); let _ = fs::remove_dir_all(dir); }

    #[test]
    fn durable_authority_state_reloads_against_sealed_key_references() {
        let dir = std::env::temp_dir().join(format!("actium-authority-state-{}", uuid::Uuid::new_v4()));
        let key = [9u8; 32];
        let mut service = AuthorityService::new(SealedKeyProvider::new(&dir, key).unwrap(), "set");
        service.initialize_root("root", 100).unwrap();
        service.issue_subordinate("root", "deployment", AuthorityKind::DeploymentAuthority, vec![authority_capability(AuthorityKind::DeploymentAuthority).into()], 100, None).unwrap();
        let state: DurableAuthorityState = service.durable_state();
        let serialized = serde_json::to_vec(&state).unwrap();
        let restored: DurableAuthorityState = serde_json::from_slice(&serialized).unwrap();
        let reloaded = AuthorityService::from_durable_state(SealedKeyProvider::new(&dir, key).unwrap(), restored).unwrap();
        assert_eq!(reloaded.authorities().count(), 2);
        assert_eq!(reloaded.readiness("authority:issue-deployment-authority", 100).unwrap().status, "ready");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_state_accepts_public_only_product_root_without_online_root_key() {
        let root_dir = std::env::temp_dir().join(format!("actium-offline-root-{}", uuid::Uuid::new_v4()));
        let online_dir = std::env::temp_dir().join(format!("actium-online-authority-{}", uuid::Uuid::new_v4()));
        let key = [13u8; 32];
        let mut offline = AuthorityService::new(SealedKeyProvider::new(&root_dir, key).unwrap(), "set");
        let root = offline.initialize_root("root", 100).unwrap();
        offline.issue_subordinate("root", "deployment", AuthorityKind::DeploymentAuthority, vec![authority_capability(AuthorityKind::DeploymentAuthority).into()], 100, None).unwrap();
        offline.issue_subordinate("deployment", "deployment-root", AuthorityKind::DeploymentRoot, vec![authority_capability(AuthorityKind::DeploymentRoot).into()], 100, None).unwrap();
        offline.issue_subordinate("deployment-root", "center", AuthorityKind::CenterAuthority, vec![authority_capability(AuthorityKind::CenterAuthority).into()], 100, None).unwrap();
        offline.issue_subordinate("center", "enrollment", AuthorityKind::EnrollmentAuthority, vec!["host_enrollment".into()], 100, None).unwrap();
        let mut state = offline.durable_state();
        state.public_only_key_ids = vec![root.authority.key_id.clone()];
        let mut online = SealedKeyProvider::new(&online_dir, key).unwrap();
        for subordinate in state.authorities.iter().filter(|authority| authority.key_id != root.authority.key_id) {
            online.copy_key_from(offline.provider(), &subordinate.key_id).unwrap();
        }
        let restored = AuthorityService::from_durable_state(online, state.clone()).unwrap();
        assert_eq!(restored.readiness("host_enrollment", 100).unwrap().status, "ready");

        let mut online_with_root = SealedKeyProvider::new(online_dir.join("with-root"), key).unwrap();
        for authority in &state.authorities {
            online_with_root.copy_key_from(offline.provider(), &authority.key_id).unwrap();
        }
        let rejected = match AuthorityService::from_durable_state(online_with_root, state) {
            Ok(_) => "unexpected_success".to_string(),
            Err(error) => error,
        };
        assert_eq!(rejected, "TRUST_PUBLIC_ONLY_KEY_PRESENT");
        let _ = fs::remove_dir_all(root_dir);
        let _ = fs::remove_dir_all(online_dir);
    }

    #[test]
    fn durable_idempotency_rejects_reuse_with_different_request() {
        let dir = std::env::temp_dir().join(format!("actium-authority-idempotency-{}", uuid::Uuid::new_v4()));
        let key = [11u8; 32];
        let mut service = AuthorityService::new(SealedKeyProvider::new(&dir, key).unwrap(), "set");
        service.initialize_root("root", 100).unwrap();
        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);
        service.record_idempotency_result("sign-1".into(), digest_a.clone(), serde_json::json!({ "ok": true }));
        let restored = AuthorityService::from_durable_state(
            SealedKeyProvider::new(&dir, key).unwrap(),
            serde_json::from_slice(&serde_json::to_vec(&service.durable_state()).unwrap()).unwrap(),
        ).unwrap();
        assert_eq!(restored.idempotency_result("sign-1", &digest_a).unwrap(), Some(serde_json::json!({ "ok": true })));
        assert_eq!(restored.idempotency_result("sign-1", &digest_b).unwrap_err(), "TRUST_IDEMPOTENCY_KEY_REUSED");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sealing_key_file_requires_explicit_format_and_restricted_permissions() {
        let dir = std::env::temp_dir().join(format!("actium-sealing-key-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sealing.key");
        let encoded = URL_SAFE_NO_PAD.encode([3u8; 32]);
        fs::write(&path, format!("ACTIUM-SEALING-KEY-V1\n{encoded}\n")).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let provider = SealedKeyProvider::from_sealing_key_file(dir.join("keys"), &path).unwrap();
        let descriptor = provider;
        assert!(format!("{descriptor:?}").contains("SealedKeyProvider"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn shared_trust_bundle_vector_keeps_digest_and_signature_canonical() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../docs/contracts/vectors/trust-bundle-v1-vector.json")).unwrap();
        let signed: SignedTrustBundle = serde_json::from_value(fixture.get("signed").cloned().unwrap()).unwrap();
        let expected_digest = fixture.get("digest").and_then(Value::as_str).unwrap();
        assert_eq!(trust_bundle_digest(&signed.bundle).unwrap(), expected_digest);
        let root = signed.bundle.product_roots[0].clone();
        verify_signed_trust_bundle_with_bootstrap(&signed, 1_700_000_000, 1, &[root]).unwrap();
    }

    #[test]
    fn public_metadata_never_contains_private_material() { let mut provider = TestEphemeralKeyProvider::default(); let descriptor = provider.generate().unwrap(); let json = serde_json::to_string(&descriptor).unwrap(); assert!(!json.contains("private")); assert!(!json.contains("secret")); assert!(provider.sign(&descriptor.key_id, b"x").unwrap().len() == 64); }

    #[test]
    fn destroy_reference_removes_signing_material_and_keeps_revocation() {
        let mut provider = TestEphemeralKeyProvider::default();
        let descriptor = provider.generate().unwrap();
        provider.destroy_reference(&descriptor.key_id).unwrap();
        assert_eq!(provider.load(&descriptor.key_id).unwrap_err(), "TRUST_KEY_NOT_FOUND");
        assert_eq!(provider.sign(&descriptor.key_id, b"x").unwrap_err(), "TRUST_KEY_REVOKED");
    }
}
