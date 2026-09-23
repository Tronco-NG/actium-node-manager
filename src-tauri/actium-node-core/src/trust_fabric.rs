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
pub const CENTER_AUTHORITY_REISSUE_CONTRACT: &str = "actium-center-authority-reissue@1.0.0";
pub const REMOTE_OPERATIONS_SIGNING_CAPABILITY: &str = "remote_operations_signing";
const AUTHORITY_CERTIFICATE_DOMAIN: &str = "actium-authority-certificate-v1";
const TRUST_BUNDLE_DOMAIN: &str = "actium-trust-bundle-v1";
const RELEASE_MANIFEST_DOMAIN: &str = "actium-release-manifest-v1";
const CENTER_AUTHORITY_TRANSITION_DOMAIN: &str = "actium-center-authority-transition-v1";

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CenterAuthorityTransitionStatus {
    Prepared,
    Issued,
    Published,
    HostsConverging,
    Active,
    PredecessorRetiring,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CenterAuthorityTransitionSignatureV1 {
    pub authority_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

/// Public, signed transition proof.  It contains no private key material;
/// the successor key is generated and retained by the Authority Service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CenterAuthorityTransitionV1 {
    pub contract: String,
    pub transition_id: String,
    pub trust_root_set: String,
    pub predecessor_authority_id: String,
    pub predecessor_key_id: String,
    pub successor_authority_id: String,
    pub successor_key_id: String,
    pub successor_certificate_version: u32,
    pub required_capabilities: Vec<String>,
    pub issued_at: u64,
    pub activation_epoch: u64,
    pub status: CenterAuthorityTransitionStatus,
    pub issuer_authority_id: String,
    pub issuer_key_id: String,
    pub signatures: Vec<CenterAuthorityTransitionSignatureV1>,
    pub proof: Value,
    #[serde(default)]
    pub request_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CenterAuthorityReissueOwnerApprovalV1 {
    pub owner_id: String,
    pub aal: String,
    pub reason: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CenterAuthorityReissueRequestV1 {
    pub contract: String,
    pub operation: String,
    pub transition_id: String,
    pub predecessor_authority_id: String,
    pub predecessor_key_id: String,
    pub trust_root_set: String,
    pub expected_trust_epoch: u64,
    pub requested_capability: String,
    #[serde(default)]
    pub activation_epoch: Option<u64>,
    #[serde(default)]
    pub owner_approval: Option<CenterAuthorityReissueOwnerApprovalV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CenterAuthorityReissueMaterialV1 {
    pub authority_id: String,
    pub key_id: Option<String>,
    pub certificate_version: u32,
    pub issuer_authority_id: String,
    pub issuer_key_id: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CenterAuthorityReissuePreviewV1 {
    pub contract: String,
    pub operation: String,
    pub transition_id: String,
    pub decision: String,
    pub same_key_reissue_supported: bool,
    pub successor_key_required: bool,
    pub trust_root_set: String,
    pub current_trust_epoch: u64,
    pub activation_epoch: u64,
    pub before: CenterAuthorityReissueMaterialV1,
    pub after: CenterAuthorityReissueMaterialV1,
    pub host_transition: String,
    pub private_key_handling: String,
    pub product_root_changed: bool,
    pub expected_host_action: String,
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
    /// Active predecessor Center authorities are retained so a successor
    /// bundle can still validate enrollment certificates issued by the old
    /// Center during the convergence window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predecessor_center_authorities: Vec<AuthorityDescriptor>,
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
    #[serde(default)]
    pub center_authority_transitions: Vec<CenterAuthorityTransitionV1>,
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
            let metadata = fs::symlink_metadata(&path).map_err(|_| "TRUST_SEALING_KEY_UNAVAILABLE".to_string())?;
            let effective_uid = nix::unistd::geteuid().as_raw();
            let effective_gid = nix::unistd::getegid().as_raw();
            let owner_can_read = metadata.uid() == effective_uid && metadata.mode() & 0o400 != 0;
            let group_can_read = metadata.gid() == effective_gid && metadata.mode() & 0o040 != 0;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || (!owner_can_read && !group_can_read)
                || metadata.mode() & 0o007 != 0
            {
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

    /// Read-only counterpart for privileged validation boundaries.  Unlike
    /// `from_sealing_key_file`, this never calls `create_dir_all`; the caller
    /// must prove that the sealed-key root already exists and is a directory.
    pub fn from_sealing_key_file_read_only(
        root: impl Into<PathBuf>,
        path: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        let root = root.into();
        let metadata = fs::symlink_metadata(&root)
            .map_err(|_| "TRUST_SEALED_STORAGE_UNAVAILABLE".to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("TRUST_SEALED_STORAGE_UNAVAILABLE".into());
        }
        let path = path.into();
        let raw = fs::read_to_string(&path).map_err(|_| "TRUST_SEALING_KEY_UNAVAILABLE".to_string())?;
        let mut lines = raw.lines();
        if lines.next() != Some("ACTIUM-SEALING-KEY-V1") {
            return Err("TRUST_SEALING_KEY_FORMAT_INVALID".into());
        }
        let encoded = lines
            .next()
            .ok_or_else(|| "TRUST_SEALING_KEY_FORMAT_INVALID".to_string())?;
        if lines.next().is_some() {
            return Err("TRUST_SEALING_KEY_FORMAT_INVALID".into());
        }
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "TRUST_SEALING_KEY_FORMAT_INVALID".to_string())?;
        let sealing_key: [u8; 32] = raw
            .try_into()
            .map_err(|_| "TRUST_SEALING_KEY_LENGTH_INVALID".to_string())?;
        Ok(Self {
            root,
            sealing_key,
            revoked: BTreeSet::new(),
        })
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
    center_authority_transitions: Vec<CenterAuthorityTransitionV1>,
    audit_events: RefCell<Vec<AuthorityAuditEvent>>,
    idempotency_results: BTreeMap<String, DurableIdempotencyRecord>,
    trust_root_set: String,
    trust_epoch: u64,
    public_only_key_ids: BTreeSet<String>,
}

impl<P: KeyProvider> AuthorityService<P> {
    pub fn new(provider: P, trust_root_set: impl Into<String>) -> Self {
        Self { provider, authorities: BTreeMap::new(), revocations: Vec::new(), root_transitions: Vec::new(), center_authority_transitions: Vec::new(), audit_events: RefCell::new(Vec::new()), idempotency_results: BTreeMap::new(), trust_root_set: trust_root_set.into(), trust_epoch: 1, public_only_key_ids: BTreeSet::new() }
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
            center_authority_transitions: self.center_authority_transitions.clone(),
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
            center_authority_transitions: state.center_authority_transitions,
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
        self.issue_subordinate_versioned(parent_id, authority_id, kind, capabilities, 1, now, valid_until)
    }

    pub fn issue_subordinate_versioned(&mut self, parent_id: &str, authority_id: impl Into<String>, kind: AuthorityKind, capabilities: Vec<String>, version: u32, now: u64, valid_until: Option<u64>) -> Result<AuthorityDescriptor, String> {
        let parent = self.authorities.get(parent_id).ok_or_else(|| "TRUST_ISSUER_NOT_FOUND".to_string())?.clone();
        self.assert_active(&parent, now)?;
        let required = match kind { AuthorityKind::DeploymentAuthority => authority_capability(AuthorityKind::ProductTrustRoot), AuthorityKind::ReleaseAuthority => "authority:issue-release", AuthorityKind::DeploymentRoot => authority_capability(AuthorityKind::DeploymentAuthority), AuthorityKind::CenterAuthority => authority_capability(AuthorityKind::DeploymentRoot), AuthorityKind::EnrollmentAuthority => authority_capability(AuthorityKind::CenterAuthority), AuthorityKind::ProductSigningAuthority => authority_capability(AuthorityKind::ReleaseAuthority), _ => return Err("TRUST_SUBORDINATION_KIND_INVALID".into()) };
        if !parent.capabilities.iter().any(|cap| cap == required || cap == "*") { return Err("TRUST_ISSUER_CAPABILITY_REJECTED".into()); }
        if capabilities.is_empty() || version == 0 { return Err("TRUST_CAPABILITIES_EMPTY".into()); }
        let key = self.provider.generate()?;
        let authority_id = authority_id.into();
        if self.authorities.contains_key(&authority_id) { return Err("TRUST_AUTHORITY_EXISTS".into()); }
        let body = AuthorityCertificate { schema: 1, authority_id: authority_id.clone(), kind, key_id: key.key_id.clone(), public_key: key.public_key.clone(), fingerprint: key.fingerprint.clone(), issuer_authority_id: parent.authority_id.clone(), issuer_key_id: parent.key_id.clone(), serial: format!("{authority_id}-{version}-{now}"), version, capabilities: capabilities.clone(), valid_from: now, valid_until, signature: String::new() };
        let signature = self.sign_internal(&parent, &certificate_payload(&body)?)?;
        let certificate = AuthorityCertificate { signature: URL_SAFE_NO_PAD.encode(signature), ..body };
        let authority = AuthorityDescriptor { authority_id: authority_id.clone(), kind, key_id: key.key_id, public_key: key.public_key, fingerprint: key.fingerprint, algorithm: TRUST_FABRIC_ALGORITHM.into(), status: AuthorityStatus::Active, valid_from: now, valid_until, issuer_authority_id: Some(parent.authority_id), issuer_key_id: Some(parent.key_id), serial: certificate.serial.clone(), version, capabilities, certificate: Some(certificate), created_at: now, revoked_at: None, revocation_reason: None };
        self.authorities.insert(authority_id, authority.clone());
        self.audit("AUTHORITY_CREATED", Some(&authority.authority_id), Some(&authority.key_id), None, "success", None, now);
        Ok(authority)
    }

    pub fn center_authority_transitions(&self) -> &[CenterAuthorityTransitionV1] {
        &self.center_authority_transitions
    }

    pub fn prepare_center_authority_reissue(&self, request: &CenterAuthorityReissueRequestV1, now: u64) -> Result<CenterAuthorityReissuePreviewV1, String> {
        let (predecessor, issuer, capabilities, activation_epoch) = self.validate_center_authority_reissue_request(request, now, false)?;
        let successor_id = format!("{}-v{}", predecessor.authority_id, predecessor.version + 1);
        let existing = self.authorities.get(&successor_id);
        let successor_key_id = existing.map(|authority| authority.key_id.clone());
        if let Some(successor) = existing {
            if successor.kind != AuthorityKind::CenterAuthority || successor.issuer_authority_id.as_deref() != Some(issuer.authority_id.as_str()) || successor.issuer_key_id.as_deref() != Some(issuer.key_id.as_str()) || !capabilities.iter().all(|capability| successor.capabilities.contains(capability)) {
                return Err("TRUST_CENTER_SUCCESSOR_CONFLICT".into());
            }
        }
        Ok(CenterAuthorityReissuePreviewV1 {
            contract: CENTER_AUTHORITY_REISSUE_CONTRACT.into(),
            operation: "PREPARE_CENTER_AUTHORITY_REISSUE".into(),
            transition_id: request.transition_id.clone(),
            decision: "OWNER_ACTION_READY".into(),
            same_key_reissue_supported: false,
            successor_key_required: true,
            trust_root_set: self.trust_root_set.clone(),
            current_trust_epoch: self.trust_epoch,
            activation_epoch,
            before: CenterAuthorityReissueMaterialV1 {
                authority_id: predecessor.authority_id.clone(),
                key_id: Some(predecessor.key_id.clone()),
                certificate_version: predecessor.version,
                issuer_authority_id: issuer.authority_id.clone(),
                issuer_key_id: issuer.key_id.clone(),
                capabilities: predecessor.capabilities.clone(),
            },
            after: CenterAuthorityReissueMaterialV1 {
                authority_id: successor_id,
                key_id: successor_key_id,
                certificate_version: predecessor.version + 1,
                issuer_authority_id: issuer.authority_id.clone(),
                issuer_key_id: issuer.key_id.clone(),
                capabilities,
            },
            host_transition: "TRUST_BUNDLE_REFRESH_NO_REENROLLMENT".into(),
            private_key_handling: "GENERATED_AND_RETAINED_BY_AUTHORITY_SERVICE".into(),
            product_root_changed: false,
            expected_host_action: "ACCEPT_VERIFIED_SUCCESSOR_TRANSITION_THEN_REFRESH_TRUST_BUNDLE".into(),
        })
    }

    pub fn authorize_center_authority_reissue(&mut self, request: &CenterAuthorityReissueRequestV1, now: u64) -> Result<CenterAuthorityTransitionV1, String> {
        if request.operation != "AUTHORIZE_CENTER_AUTHORITY_REISSUE" { return Err("TRUST_TRANSITION_OPERATION_INVALID".into()); }
        let (predecessor, issuer, capabilities, activation_epoch) = self.validate_center_authority_reissue_request(request, now, true)?;
        let request_digest = request_digest_hex(request)?;
        if let Some(existing) = self.center_authority_transitions.iter().find(|transition| transition.transition_id == request.transition_id) {
            if existing.request_digest != request_digest { return Err("TRUST_TRANSITION_REPLAY_OR_CONFLICT".into()); }
            return Ok(existing.clone());
        }
        let successor_id = format!("{}-v{}", predecessor.authority_id, predecessor.version + 1);
        if self.authorities.contains_key(&successor_id) { return Err("TRUST_CENTER_SUCCESSOR_CONFLICT".into()); }
        let successor = self.issue_subordinate_versioned(&issuer.authority_id, successor_id.clone(), AuthorityKind::CenterAuthority, capabilities.clone(), predecessor.version + 1, now, predecessor.valid_until)?;
        let certificate = successor.certificate.clone().ok_or_else(|| "TRUST_CERTIFICATE_MISSING".to_string())?;
        let mut transition = CenterAuthorityTransitionV1 {
            contract: CENTER_AUTHORITY_REISSUE_CONTRACT.into(),
            transition_id: request.transition_id.clone(),
            trust_root_set: self.trust_root_set.clone(),
            predecessor_authority_id: predecessor.authority_id.clone(),
            predecessor_key_id: predecessor.key_id.clone(),
            successor_authority_id: successor.authority_id.clone(),
            successor_key_id: successor.key_id.clone(),
            successor_certificate_version: successor.version,
            required_capabilities: capabilities,
            issued_at: now,
            activation_epoch,
            status: CenterAuthorityTransitionStatus::Issued,
            issuer_authority_id: issuer.authority_id.clone(),
            issuer_key_id: issuer.key_id.clone(),
            signatures: Vec::new(),
            proof: serde_json::json!({
                "certificate": certificate,
                "predecessorPreserved": true,
                "productRootChanged": false,
                "publication": "EXPLICIT_TRUST_BUNDLE_PUBLICATION_REQUIRED"
            }),
            request_digest,
        };
        let signature = self.provider.sign(&issuer.key_id, &center_transition_payload(&transition)?)?;
        transition.signatures.push(CenterAuthorityTransitionSignatureV1 {
            authority_id: issuer.authority_id.clone(),
            key_id: issuer.key_id.clone(),
            algorithm: TRUST_FABRIC_ALGORITHM.into(),
            signature: URL_SAFE_NO_PAD.encode(signature),
        });
        self.center_authority_transitions.push(transition.clone());
        self.audit("CENTER_AUTHORITY_REISSUE_ISSUED", Some(&successor.authority_id), Some(&successor.key_id), Some(request_digest_hex(request)?), "success", Some("predecessor_preserved".into()), now);
        Ok(transition)
    }

    fn validate_center_authority_reissue_request(&self, request: &CenterAuthorityReissueRequestV1, now: u64, require_authorization: bool) -> Result<(AuthorityDescriptor, AuthorityDescriptor, Vec<String>, u64), String> {
        if request.contract != CENTER_AUTHORITY_REISSUE_CONTRACT { return Err("TRUST_TRANSITION_CONTRACT_INVALID".into()); }
        if request.operation != "PREPARE_CENTER_AUTHORITY_REISSUE" && request.operation != "AUTHORIZE_CENTER_AUTHORITY_REISSUE" { return Err("TRUST_TRANSITION_OPERATION_INVALID".into()); }
        if request.transition_id.trim().is_empty() || request.transition_id.len() > 128 { return Err("TRUST_TRANSITION_ID_INVALID".into()); }
        if request.predecessor_authority_id.trim().is_empty() || request.predecessor_key_id.trim().is_empty() { return Err("TRUST_PREDECESSOR_REQUIRED".into()); }
        if request.trust_root_set != self.trust_root_set { return Err("TRUST_ROOT_SET_MISMATCH".into()); }
        if request.expected_trust_epoch < self.trust_epoch { return Err("TRUST_EPOCH_STALE".into()); }
        if request.expected_trust_epoch > self.trust_epoch { return Err("TRUST_EPOCH_FUTURE".into()); }
        if request.requested_capability != REMOTE_OPERATIONS_SIGNING_CAPABILITY { return Err("TRUST_CAPABILITY_NOT_ALLOWLISTED".into()); }
        let owner = request.owner_approval.as_ref().ok_or_else(|| "OWNER_AAL2_REQUIRED".to_string())?;
        if owner.aal != "aal2" { return Err("OWNER_AAL2_REQUIRED".into()); }
        if owner.owner_id.trim().is_empty() || owner.owner_id.eq_ignore_ascii_case("service_role") || owner.owner_id.eq_ignore_ascii_case("role:service_role") { return Err("OWNER_IDENTITY_INVALID".into()); }
        if owner.reason.trim().is_empty() || owner.reason.len() > 2_000 { return Err("OWNER_REASON_REQUIRED".into()); }
        if require_authorization && owner.confirmation != "AUTHORIZE_CENTER_AUTHORITY_REISSUE" { return Err("OWNER_CONFIRMATION_REQUIRED".into()); }
        if owner.reason.to_ascii_lowercase().contains("private key") || owner.reason.to_ascii_lowercase().contains("secret") { return Err("OWNER_REASON_SENSITIVE".into()); }
        if request.operation == "AUTHORIZE_CENTER_AUTHORITY_REISSUE" && !require_authorization { return Err("TRUST_TRANSITION_OPERATION_INVALID".into()); }
        let predecessor = self.authorities.get(&request.predecessor_authority_id).ok_or_else(|| "TRUST_PREDECESSOR_NOT_FOUND".to_string())?.clone();
        if predecessor.kind != AuthorityKind::CenterAuthority || predecessor.key_id != request.predecessor_key_id || !matches!(predecessor.status, AuthorityStatus::Active | AuthorityStatus::Rotating) { return Err("TRUST_PREDECESSOR_INVALID".into()); }
        self.verify_chain(&predecessor, now)?;
        let issuer_id = predecessor.issuer_authority_id.clone().ok_or_else(|| "TRUST_ISSUER_NOT_FOUND".to_string())?;
        let issuer = self.authorities.get(&issuer_id).ok_or_else(|| "TRUST_ISSUER_NOT_FOUND".to_string())?.clone();
        if issuer.kind != AuthorityKind::DeploymentRoot || predecessor.issuer_key_id.as_deref() != Some(issuer.key_id.as_str()) || !issuer.capabilities.iter().any(|capability| capability == authority_capability(AuthorityKind::DeploymentRoot) || capability == "*") { return Err("TRUST_ISSUER_NOT_AUTHORIZED".into()); }
        self.verify_chain(&issuer, now)?;
        let mut capabilities = predecessor.capabilities.clone();
        if !capabilities.iter().any(|capability| capability == REMOTE_OPERATIONS_SIGNING_CAPABILITY) { capabilities.push(REMOTE_OPERATIONS_SIGNING_CAPABILITY.into()); }
        capabilities.sort();
        capabilities.dedup();
        let activation_epoch = request.activation_epoch.unwrap_or(self.trust_epoch + 1);
        if activation_epoch <= self.trust_epoch { return Err("TRUST_ACTIVATION_EPOCH_INVALID".into()); }
        Ok((predecessor, issuer, capabilities, activation_epoch))
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
        let signer = self.authorities.values().filter(|a| a.status == AuthorityStatus::Active && a.capabilities.iter().any(|c| c == capability || c == "*") && a.valid_from <= now && a.valid_until.map(|v| now <= v).unwrap_or(true)).max_by_key(|a| (a.version, a.authority_id.as_str())).ok_or_else(|| "HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE".to_string())?;
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
        let mut center_authorities: Vec<AuthorityDescriptor> = self.authorities.values().filter(|a| a.kind == AuthorityKind::CenterAuthority && a.status != AuthorityStatus::Revoked).cloned().collect();
        center_authorities.sort_by_key(|authority| authority.version);
        let center_authority = center_authorities.pop();
        let predecessor_center_authorities = center_authorities;
        let bundle = TrustBundle { trust_bundle_id: format!("{}-{now}", self.trust_root_set), contract: TRUST_BUNDLE_CONTRACT.into(), version: 1, product_roots: roots, root_transitions: self.root_transitions.clone(), deployment_authority: self.authorities.values().find(|a| a.kind == AuthorityKind::DeploymentAuthority && a.status != AuthorityStatus::Revoked).cloned(), deployment_root: self.authorities.values().find(|a| a.kind == AuthorityKind::DeploymentRoot && a.status != AuthorityStatus::Revoked).cloned(), center_authority, predecessor_center_authorities, enrollment_authorities: self.authorities.values().filter(|a| a.kind == AuthorityKind::EnrollmentAuthority && a.status != AuthorityStatus::Revoked).cloned().collect(), release_authorities: self.authorities.values().filter(|a| a.kind == AuthorityKind::ReleaseAuthority && a.status != AuthorityStatus::Revoked).cloned().collect(), product_signing_authorities: self.authorities.values().filter(|a| a.kind == AuthorityKind::ProductSigningAuthority && a.status != AuthorityStatus::Revoked).cloned().collect(), revocations: self.revocations.clone(), issued_at: now, expires_at, trust_epoch: self.trust_epoch, issuer: root.authority_id.clone() };
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
        for transition in &self.center_authority_transitions {
            let predecessor = self.authorities.get(&transition.predecessor_authority_id).ok_or_else(|| "TRUST_CENTER_TRANSITION_PREDECESSOR_UNKNOWN".to_string())?;
            let successor = self.authorities.get(&transition.successor_authority_id).ok_or_else(|| "TRUST_CENTER_TRANSITION_SUCCESSOR_UNKNOWN".to_string())?;
            let issuer = self.authorities.get(&transition.issuer_authority_id).ok_or_else(|| "TRUST_CENTER_TRANSITION_ISSUER_UNKNOWN".to_string())?;
            if transition.contract != CENTER_AUTHORITY_REISSUE_CONTRACT || transition.trust_root_set != self.trust_root_set || transition.predecessor_key_id != predecessor.key_id || transition.successor_key_id != successor.key_id || successor.kind != AuthorityKind::CenterAuthority || successor.version != transition.successor_certificate_version || issuer.kind != AuthorityKind::DeploymentRoot || transition.issuer_key_id != issuer.key_id || transition.request_digest.len() != 64 || !transition.request_digest.chars().all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase()) {
                return Err("TRUST_CENTER_TRANSITION_STATE_INVALID".into());
            }
            if transition.signatures.is_empty() || !transition.signatures.iter().any(|signature| signature.authority_id == issuer.authority_id && signature.key_id == issuer.key_id && signature.algorithm == TRUST_FABRIC_ALGORITHM) {
                return Err("TRUST_CENTER_TRANSITION_SIGNATURE_INVALID".into());
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
fn request_digest_hex(request: &CenterAuthorityReissueRequestV1) -> Result<String, String> {
    let canonical = crate::canonical_json(&serde_json::to_value(request).map_err(|_| "TRUST_TRANSITION_SERIALIZE")?)?;
    Ok(hex_lower(&Sha256::digest(canonical.as_bytes())))
}

fn signed_payload(domain: &str, value: &Value) -> Result<Vec<u8>, String> { let canonical = crate::canonical_json(value)?; let mut bytes = domain.as_bytes().to_vec(); bytes.push(0); bytes.extend_from_slice(canonical.as_bytes()); Ok(bytes) }
fn certificate_value_without_signature(certificate: &AuthorityCertificate) -> Result<Value, String> { let mut value = serde_json::to_value(certificate).map_err(|_| "TRUST_CERTIFICATE_SERIALIZE")?; if let Value::Object(fields) = &mut value { fields.insert("signature".into(), Value::String(String::new())); } Ok(value) }
fn certificate_payload(certificate: &AuthorityCertificate) -> Result<Vec<u8>, String> { signed_payload(AUTHORITY_CERTIFICATE_DOMAIN, &certificate_value_without_signature(certificate)?) }
fn center_transition_payload(transition: &CenterAuthorityTransitionV1) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(transition).map_err(|_| "TRUST_TRANSITION_SERIALIZE")?;
    if let Value::Object(fields) = &mut value { fields.insert("signatures".into(), Value::Array(Vec::new())); }
    signed_payload(CENTER_AUTHORITY_TRANSITION_DOMAIN, &value)
}
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
    for authority in signed.bundle.product_roots.iter().map(|root| &root.authority).chain(signed.bundle.deployment_authority.iter()).chain(signed.bundle.deployment_root.iter()).chain(signed.bundle.center_authority.iter()).chain(signed.bundle.predecessor_center_authorities.iter()).chain(signed.bundle.enrollment_authorities.iter()).chain(signed.bundle.release_authorities.iter()).chain(signed.bundle.product_signing_authorities.iter()) {
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

pub fn center_authority_transition_digest(transition: &CenterAuthorityTransitionV1) -> Result<String, String> {
    let value = serde_json::to_value(transition).map_err(|_| "TRUST_TRANSITION_SERIALIZE")?;
    let canonical = crate::canonical_json(&value)?;
    Ok(fingerprint_for_raw(canonical.as_bytes()))
}

/// Verify a Center successor proof against the already trusted bundle.  This
/// is an additive transition: the old Center and its enrollment authority
/// remain valid until an explicit convergence/retirement operation.
pub fn verify_center_authority_transition(signed: &CenterAuthorityTransitionV1, bundle: &SignedTrustBundle, now: u64) -> Result<(), String> {
    if signed.contract != CENTER_AUTHORITY_REISSUE_CONTRACT || signed.status != CenterAuthorityTransitionStatus::Issued && signed.status != CenterAuthorityTransitionStatus::Published && signed.status != CenterAuthorityTransitionStatus::HostsConverging && signed.status != CenterAuthorityTransitionStatus::Active {
        return Err("TRUST_CENTER_TRANSITION_INVALID".into());
    }
    if signed.trust_root_set != bundle.bundle.product_roots.iter().find(|root| root.authority.key_id == bundle.signing_key_id).map(|root| root.trust_root_set.as_str()).unwrap_or_default() || signed.activation_epoch < bundle.bundle.trust_epoch || signed.issued_at > now + 60 {
        return Err("TRUST_CENTER_TRANSITION_EPOCH_INVALID".into());
    }
    let predecessor = bundle.bundle.center_authority.as_ref().filter(|authority| authority.authority_id == signed.predecessor_authority_id && authority.key_id == signed.predecessor_key_id).or_else(|| bundle.bundle.predecessor_center_authorities.iter().find(|authority| authority.authority_id == signed.predecessor_authority_id && authority.key_id == signed.predecessor_key_id)).ok_or_else(|| "TRUST_CENTER_PREDECESSOR_UNKNOWN".to_string())?;
    if !matches!(predecessor.status, AuthorityStatus::Active | AuthorityStatus::Rotating) { return Err("TRUST_CENTER_PREDECESSOR_NOT_CONVERGED".into()); }
    let issuer = bundle.bundle.deployment_root.as_ref().filter(|authority| authority.authority_id == signed.issuer_authority_id && authority.key_id == signed.issuer_key_id).ok_or_else(|| "TRUST_CENTER_TRANSITION_ISSUER_UNKNOWN".to_string())?;
    if !issuer.capabilities.iter().any(|capability| capability == authority_capability(AuthorityKind::DeploymentRoot) || capability == "*") { return Err("TRUST_CENTER_TRANSITION_ISSUER_UNAUTHORIZED".into()); }
    let certificate = signed.proof.get("certificate").ok_or_else(|| "TRUST_CENTER_TRANSITION_PROOF_MISSING".to_string())?;
    let certificate: AuthorityCertificate = serde_json::from_value(certificate.clone()).map_err(|_| "TRUST_CENTER_TRANSITION_PROOF_INVALID")?;
    if certificate.authority_id != signed.successor_authority_id || certificate.key_id != signed.successor_key_id || certificate.key_id == signed.predecessor_key_id || certificate.version != signed.successor_certificate_version || certificate.issuer_authority_id != issuer.authority_id || certificate.issuer_key_id != issuer.key_id || certificate.kind != AuthorityKind::CenterAuthority || certificate.capabilities != signed.required_capabilities {
        return Err("TRUST_CENTER_TRANSITION_SCOPE_INVALID".into());
    }
    if signed.proof.get("predecessorPreserved").and_then(Value::as_bool) != Some(true) || signed.proof.get("productRootChanged").and_then(Value::as_bool) != Some(false) {
        return Err("TRUST_CENTER_TRANSITION_BOUNDARY_INVALID".into());
    }
    verify_raw(&issuer.public_key, &certificate_payload(&certificate)?, &URL_SAFE_NO_PAD.decode(&certificate.signature).map_err(|_| "TRUST_CENTER_TRANSITION_PROOF_INVALID")?)?;
    if !signed.required_capabilities.iter().any(|capability| capability == REMOTE_OPERATIONS_SIGNING_CAPABILITY) || signed.required_capabilities.iter().any(|capability| !predecessor.capabilities.contains(capability) && capability != REMOTE_OPERATIONS_SIGNING_CAPABILITY) {
        return Err("TRUST_CENTER_TRANSITION_CAPABILITY_INVALID".into());
    }
    let signature = signed.signatures.iter().find(|signature| signature.authority_id == issuer.authority_id && signature.key_id == issuer.key_id && signature.algorithm == TRUST_FABRIC_ALGORITHM).ok_or_else(|| "TRUST_CENTER_TRANSITION_SIGNATURE_MISSING".to_string())?;
    verify_raw(&issuer.public_key, &center_transition_payload(signed)?, &URL_SAFE_NO_PAD.decode(&signature.signature).map_err(|_| "TRUST_CENTER_TRANSITION_SIGNATURE_INVALID")?)
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

/// Verify a release manifest using the product-signing authorities carried by
/// the already channel-bound Trust Store. The Trust Bundle itself is checked
/// against the caller's bootstrap anchors so a self-signed bundle cannot
/// introduce its own release signer.
pub fn verify_signed_release_manifest_with_bootstrap(
    signed: &SignedReleaseManifest,
    trusted_bundle: &SignedTrustBundle,
    now: u64,
    current_epoch: u64,
    bootstrap_roots: &[ProductTrustRoot],
) -> Result<(), String> {
    verify_signed_trust_bundle_with_bootstrap(
        trusted_bundle,
        now,
        current_epoch,
        bootstrap_roots,
    )?;

    let manifest = &signed.manifest;
    if manifest.schema != RELEASE_MANIFEST_CONTRACT
        || manifest.contract != RELEASE_MANIFEST_CONTRACT
        || manifest.release_id.trim().is_empty()
        || manifest.product_id.trim().is_empty()
        || manifest.version.trim().is_empty()
        || manifest.build_id.trim().is_empty()
        || manifest.source_repo.trim().is_empty()
        || manifest.platform.trim().is_empty()
        || manifest.architecture.trim().is_empty()
        || manifest.artifacts.is_empty()
        || manifest.release_status != "PROMOTED"
        || manifest.issued_at > now.saturating_add(60)
        || signed.signing.algorithm != TRUST_FABRIC_ALGORITHM
    {
        return Err("RELEASE_MANIFEST_INVALID".into());
    }

    let signer = trusted_bundle
        .bundle
        .product_signing_authorities
        .iter()
        .find(|authority| authority.key_id == signed.signing.key_id)
        .ok_or_else(|| "TRUST_PRODUCT_SIGNER_UNKNOWN".to_string())?;
    if signer.kind != AuthorityKind::ProductSigningAuthority
        || signer.status != AuthorityStatus::Active
        || signer.valid_from > manifest.issued_at
        || signer
            .valid_until
            .is_some_and(|valid_until| manifest.issued_at > valid_until)
        || trusted_bundle
            .bundle
            .revocations
            .iter()
            .any(|revocation| revocation.key_id == signer.key_id)
    {
        return Err("TRUST_PRODUCT_SIGNER_REJECTED".into());
    }
    if !signer
        .capabilities
        .iter()
        .any(|capability| capability == "product_signing" || capability == "*")
    {
        return Err("TRUST_PRODUCT_SIGNER_CAPABILITY_REJECTED".into());
    }

    let payload = signed_payload(
        RELEASE_MANIFEST_DOMAIN,
        &serde_json::to_value(manifest).map_err(|_| "RELEASE_MANIFEST_SERIALIZE")?,
    )?;
    let signature = URL_SAFE_NO_PAD
        .decode(&signed.signing.signature)
        .map_err(|_| "RELEASE_SIGNATURE_INVALID")?;
    verify_raw(&signer.public_key, &payload, &signature)
        .map_err(|_| "RELEASE_SIGNATURE_INVALID".into())
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

    fn signed_release_fixture() -> (SignedReleaseManifest, SignedTrustBundle, Vec<ProductTrustRoot>) {
        let service = hierarchy();
        let bundle = service
            .trust_bundle("product-root", 120, Some(1000))
            .unwrap();
        let bootstrap = bundle.bundle.product_roots.clone();
        let manifest = ReleaseManifestV1 {
            schema: RELEASE_MANIFEST_CONTRACT.into(),
            contract: RELEASE_MANIFEST_CONTRACT.into(),
            release_id: "release-actium-node-manager-1.0.0-linux-x86_64".into(),
            product_id: "actium-node-manager".into(),
            version: "1.0.0".into(),
            build_id: "build-1".into(),
            source_repo: "Tronco-NG/actium-node-manager".into(),
            source_commit: "a".repeat(40),
            platform: "linux".into(),
            architecture: "x86_64".into(),
            artifacts: vec![ReleaseArtifact {
                name: "actium-node-manager_1.0.0_amd64.deb".into(),
                uri: format!("artifacts/sha256/{}/actium-node-manager_1.0.0_amd64.deb", "a".repeat(64)),
                sha256: "a".repeat(64),
                size_bytes: 1024,
            }],
            issued_at: 120,
            created_at: "2026-01-01T00:00:00Z".into(),
            promoted_at: "2026-01-01T00:00:00Z".into(),
            release_status: "PROMOTED".into(),
            compatibility: ReleaseCompatibility {
                base_runtime_contract: "actium-node-manager-host@1.0.0".into(),
                build_manifest: "builds/build-1/build-manifest.json".into(),
            },
        };
        let signed = service
            .sign_release_manifest("aegis-signing", manifest)
            .unwrap();
        (signed, bundle, bootstrap)
    }

    #[test]
    fn release_manifest_verifies_against_bootstrapped_product_signer() {
        let (signed, bundle, bootstrap) = signed_release_fixture();
        verify_signed_release_manifest_with_bootstrap(
            &signed,
            &bundle,
            120,
            bundle.bundle.trust_epoch,
            &bootstrap,
        )
        .unwrap();
    }

    #[test]
    fn release_manifest_rejects_tampering_and_unanchored_bundle() {
        let (mut signed, bundle, bootstrap) = signed_release_fixture();
        signed.manifest.version = "2.0.0".into();
        assert_eq!(
            verify_signed_release_manifest_with_bootstrap(
                &signed,
                &bundle,
                120,
                bundle.bundle.trust_epoch,
                &bootstrap,
            )
            .unwrap_err(),
            "RELEASE_SIGNATURE_INVALID"
        );

        let (signed, bundle, _) = signed_release_fixture();
        assert_eq!(
            verify_signed_release_manifest_with_bootstrap(
                &signed,
                &bundle,
                120,
                bundle.bundle.trust_epoch,
                &[],
            )
            .unwrap_err(),
            "TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE"
        );
    }

    #[test]
    fn release_manifest_rejects_signer_unknown_or_trust_epoch_rollback() {
        let (mut signed, bundle, bootstrap) = signed_release_fixture();
        signed.signing.key_id = "sha256:unknown".into();
        assert_eq!(
            verify_signed_release_manifest_with_bootstrap(
                &signed,
                &bundle,
                120,
                bundle.bundle.trust_epoch,
                &bootstrap,
            )
            .unwrap_err(),
            "TRUST_PRODUCT_SIGNER_UNKNOWN"
        );

        let (signed, bundle, bootstrap) = signed_release_fixture();
        assert_eq!(
            verify_signed_release_manifest_with_bootstrap(
                &signed,
                &bundle,
                120,
                bundle.bundle.trust_epoch + 1,
                &bootstrap,
            )
            .unwrap_err(),
            "TRUST_EPOCH_ROLLBACK"
        );
    }

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

    fn center_reissue_request(operation: &str) -> CenterAuthorityReissueRequestV1 {
        CenterAuthorityReissueRequestV1 {
            contract: CENTER_AUTHORITY_REISSUE_CONTRACT.into(),
            operation: operation.into(),
            transition_id: "00000000-0000-4000-8000-000000000001".into(),
            predecessor_authority_id: "center".into(),
            predecessor_key_id: String::new(),
            trust_root_set: "actium-product-v1".into(),
            expected_trust_epoch: 1,
            requested_capability: REMOTE_OPERATIONS_SIGNING_CAPABILITY.into(),
            activation_epoch: Some(2),
            owner_approval: Some(CenterAuthorityReissueOwnerApprovalV1 { owner_id: "owner-1".into(), aal: "aal2".into(), reason: "Autorizar la capacidad de Remote Operations para la transición del Center".into(), confirmation: if operation == "AUTHORIZE_CENTER_AUTHORITY_REISSUE" { "AUTHORIZE_CENTER_AUTHORITY_REISSUE".into() } else { String::new() } }),
        }
    }

    #[test]
    fn center_reissue_is_successor_only_owner_ready_and_preserves_product_root() {
        let mut service = hierarchy();
        let center_key = service.authorities().find(|authority| authority.authority_id == "center").unwrap().key_id.clone();
        let mut request = center_reissue_request("PREPARE_CENTER_AUTHORITY_REISSUE");
        request.predecessor_key_id = center_key;
        let preview = service.prepare_center_authority_reissue(&request, 120).unwrap();
        assert_eq!(preview.decision, "OWNER_ACTION_READY");
        assert!(!preview.same_key_reissue_supported);
        assert!(preview.successor_key_required);
        assert_eq!(preview.after.key_id, None);
        assert!(!preview.product_root_changed);
        assert_eq!(preview.host_transition, "TRUST_BUNDLE_REFRESH_NO_REENROLLMENT");

        let mut aal1 = request.clone();
        aal1.owner_approval.as_mut().unwrap().aal = "aal1".into();
        assert_eq!(service.prepare_center_authority_reissue(&aal1, 120).unwrap_err(), "OWNER_AAL2_REQUIRED");
        let mut unsupported = request.clone();
        unsupported.requested_capability = "authority:issue-release".into();
        assert_eq!(service.prepare_center_authority_reissue(&unsupported, 120).unwrap_err(), "TRUST_CAPABILITY_NOT_ALLOWLISTED");
        let mut stale = request.clone();
        stale.expected_trust_epoch = 0;
        assert_eq!(service.prepare_center_authority_reissue(&stale, 120).unwrap_err(), "TRUST_EPOCH_STALE");
    }

    #[test]
    fn center_reissue_issues_verified_successor_and_rejects_replay() {
        let mut service = hierarchy();
        let center_key = service.authorities().find(|authority| authority.authority_id == "center").unwrap().key_id.clone();
        let mut request = center_reissue_request("AUTHORIZE_CENTER_AUTHORITY_REISSUE");
        request.predecessor_key_id = center_key;
        let old_bundle = service.trust_bundle("product-root", 120, None).unwrap();
        let transition = service.authorize_center_authority_reissue(&request, 120).unwrap();
        assert_eq!(transition.status, CenterAuthorityTransitionStatus::Issued);
        assert_eq!(service.authorities().find(|authority| authority.authority_id == "center").unwrap().status, AuthorityStatus::Active);
        assert_eq!(transition.predecessor_authority_id, "center");
        assert_eq!(transition.successor_authority_id, "center-v2");
        assert_ne!(transition.predecessor_key_id, transition.successor_key_id);
        assert!(!serde_json::to_string(&transition).unwrap().contains("private"));
        assert!(!serde_json::to_string(&transition).unwrap().contains("secret"));
        verify_center_authority_transition(&transition, &old_bundle, 120).unwrap();
        let new_bundle = service.trust_bundle("product-root", 120, None).unwrap();
        verify_signed_trust_bundle(&new_bundle, 120, 1).unwrap();
        assert_eq!(new_bundle.bundle.center_authority.as_ref().unwrap().authority_id, "center-v2");
        assert_eq!(new_bundle.bundle.predecessor_center_authorities.len(), 1);
        verify_center_authority_transition(&transition, &new_bundle, 120).unwrap();

        let duplicate = service.authorize_center_authority_reissue(&request, 120).unwrap();
        assert_eq!(duplicate, transition);
        let mut replay = request.clone();
        replay.owner_approval.as_mut().unwrap().reason = "Different approval intent".into();
        assert_eq!(service.authorize_center_authority_reissue(&replay, 120).unwrap_err(), "TRUST_TRANSITION_REPLAY_OR_CONFLICT");

        let mut retired_bundle = old_bundle.clone();
        retired_bundle.bundle.center_authority.as_mut().unwrap().status = AuthorityStatus::Retired;
        assert_eq!(verify_center_authority_transition(&transition, &retired_bundle, 120).unwrap_err(), "TRUST_CENTER_PREDECESSOR_NOT_CONVERGED");

        let mut boundary_tamper = transition.clone();
        boundary_tamper.proof["productRootChanged"] = Value::Bool(true);
        assert_eq!(verify_center_authority_transition(&boundary_tamper, &old_bundle, 120).unwrap_err(), "TRUST_CENTER_TRANSITION_BOUNDARY_INVALID");

        let mut wrong_issuer = transition.clone();
        wrong_issuer.issuer_authority_id = "attacker-authority".into();
        assert_eq!(verify_center_authority_transition(&wrong_issuer, &old_bundle, 120).unwrap_err(), "TRUST_CENTER_TRANSITION_ISSUER_UNKNOWN");
    }
}
