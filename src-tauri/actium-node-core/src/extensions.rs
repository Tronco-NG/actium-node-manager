use base64::{engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as URL_BASE64}, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const EXTENSION_CONTRACT: &str = "actium-product-extension-bundle@1.0.0";
pub const EXTENSION_MANIFEST_FILE: &str = "manifest.json";
pub const EXTENSION_REGISTRY_FILE: &str = "registry.json";
pub const EXTENSION_STATES: [&str; 10] = [
    "DISCOVERED",
    "STAGED",
    "VERIFIED",
    "INSTALLED",
    "ACTIVE",
    "DEGRADED",
    "DISABLED",
    "FAILED",
    "ROLLED_BACK",
    "REVOKED",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionBundleManifest {
    pub contract_name: String,
    pub contract_version: String,
    pub schema: u8,
    pub bundle_id: String,
    pub product: ExtensionProduct,
    pub bundle_version: String,
    pub platform: String,
    pub architecture: String,
    pub capabilities: Vec<ExtensionCapability>,
    pub artifacts: Vec<ExtensionArtifact>,
    pub dependencies: Vec<ExtensionDependency>,
    pub compatibility: ExtensionCompatibility,
    pub issued_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
    pub manifest_digest: String,
    pub signing: ExtensionSigning,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionProduct {
    pub product_id: String,
    pub product_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionCapability {
    pub id: String,
    pub version: String,
    pub runtime: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub health_contract: Option<String>,
    #[serde(default)]
    pub activation_requirements: Vec<String>,
    #[serde(default)]
    pub configuration_schema: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionArtifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionDependency {
    pub product_id: String,
    pub bundle_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionCompatibility {
    pub base_runtime_contract: String,
    #[serde(default)]
    pub min_manager_version: Option<String>,
    #[serde(default)]
    pub required_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionSigning {
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionSummary {
    pub bundle_id: String,
    pub product_id: String,
    pub bundle_version: Option<String>,
    pub product_version: Option<String>,
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub capabilities: Vec<String>,
    pub installed_at: Option<u64>,
    pub state: String,
    pub status: String,
    pub health: String,
    pub manifest_digest: Option<String>,
    pub artifact_digests: BTreeMap<String, String>,
    pub signature_status: String,
    pub key_id: Option<String>,
    pub desired_version: Option<String>,
    pub observed_version: Option<String>,
    pub source: String,
    pub manifest_path: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionRegistry {
    pub registry_version: u8,
    pub extensions: Vec<ExtensionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionRegistrySnapshot {
    pub base_runtime_state: String,
    pub extension_count: usize,
    pub extensions: Vec<ExtensionSummary>,
    pub extension_registry_state: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionHealth {
    pub product_id: String,
    pub state: String,
    pub detail: String,
    pub signature_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionCapabilities {
    pub product_id: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionVerification {
    pub manifest_digest: String,
    pub signature_status: String,
}

#[derive(Debug, Clone, Default)]
pub struct ExtensionBundleVerifier {
    trusted_keys: BTreeMap<String, VerifyingKey>,
    revoked_keys: BTreeSet<String>,
}

impl ExtensionBundleVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_trusted_key(mut self, key_id: impl Into<String>, key: VerifyingKey) -> Self {
        self.trusted_keys.insert(key_id.into(), key);
        self
    }

    pub fn with_revoked_key(mut self, key_id: impl Into<String>) -> Self {
        self.revoked_keys.insert(key_id.into());
        self
    }

    /// Build the software signer set from a verified Trust Fabric bundle.
    /// Enrollment and Center authorities can never become extension signers.
    pub fn from_trust_bundle(bundle: &crate::trust_fabric::SignedTrustBundle) -> Result<Self, String> {
        let mut verifier = Self::new();
        for authority in &bundle.bundle.product_signing_authorities {
            if authority.kind != crate::trust_fabric::AuthorityKind::ProductSigningAuthority {
                return Err("EXTENSION_TRUST_AUTHORITY_KIND_INVALID".into());
            }
            let raw = URL_BASE64
                .decode(&authority.public_key)
                .map_err(|_| "EXTENSION_TRUST_KEY_INVALID")?;
            let key_bytes: [u8; 32] = raw.try_into().map_err(|_| "EXTENSION_TRUST_KEY_INVALID")?;
            let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| "EXTENSION_TRUST_KEY_INVALID")?;
            if authority.status == crate::trust_fabric::AuthorityStatus::Revoked
                || bundle.bundle.revocations.iter().any(|revocation| revocation.key_id == authority.key_id)
            {
                verifier.revoked_keys.insert(authority.key_id.clone());
            } else {
                verifier.trusted_keys.insert(authority.key_id.clone(), key);
            }
        }
        Ok(verifier)
    }

    /// Loads public trust records only. Trust Fabric will provide production
    /// material; no private key or customer-specific environment value is read.
    pub fn from_trust_dir(root: &Path) -> Result<Self, String> {
        let mut verifier = Self::new();
        if !root.exists() {
            return Ok(verifier);
        }
        let entries =
            fs::read_dir(root).map_err(|error| format!("EXTENSION_TRUST_UNREADABLE: {error}"))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("EXTENSION_TRUST_UNREADABLE: {error}"))?
                .path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let record: TrustRecord = serde_json::from_slice(
                &fs::read(&path).map_err(|error| format!("EXTENSION_TRUST_UNREADABLE: {error}"))?,
            )
            .map_err(|error| format!("EXTENSION_TRUST_INVALID: {error}"))?;
            let bytes = BASE64
                .decode(record.public_key)
                .map_err(|_| "EXTENSION_TRUST_KEY_INVALID".to_string())?;
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "EXTENSION_TRUST_KEY_INVALID".to_string())?;
            let key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| "EXTENSION_TRUST_KEY_INVALID".to_string())?;
            if record.revoked {
                verifier.revoked_keys.insert(record.key_id);
            } else {
                verifier.trusted_keys.insert(record.key_id, key);
            }
        }
        Ok(verifier)
    }

    pub fn verify(
        &self,
        manifest: &ExtensionBundleManifest,
    ) -> Result<ExtensionVerification, String> {
        let expected_digest = manifest_digest(manifest)?;
        if !constant_time_hex_eq(&expected_digest, &manifest.manifest_digest) {
            return Err("EXTENSION_MANIFEST_TAMPERED".to_string());
        }
        if self.revoked_keys.contains(&manifest.signing.key_id) {
            return Err("EXTENSION_KEY_REVOKED".to_string());
        }
        if manifest.signing.algorithm != "ed25519" {
            return Err("EXTENSION_SIGNATURE_ALGORITHM_UNSUPPORTED".to_string());
        }
        let key = self
            .trusted_keys
            .get(&manifest.signing.key_id)
            .ok_or_else(|| "EXTENSION_SIGNING_KEY_UNTRUSTED".to_string())?;
        let signature_bytes = BASE64
            .decode(&manifest.signing.signature)
            .map_err(|_| "EXTENSION_SIGNATURE_INVALID".to_string())?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| "EXTENSION_SIGNATURE_INVALID".to_string())?;
        key.verify(expected_digest.as_bytes(), &signature)
            .map_err(|_| "EXTENSION_SIGNATURE_INVALID".to_string())?;
        Ok(ExtensionVerification {
            manifest_digest: expected_digest,
            signature_status: "VERIFIED".to_string(),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TrustRecord {
    key_id: String,
    public_key: String,
    #[serde(default)]
    revoked: bool,
}

pub fn load_registry(root: &Path) -> ExtensionRegistrySnapshot {
    let registry = match read_registry(root) {
        Ok(registry) => registry,
        Err(error) if error == "EXTENSION_REGISTRY_NOT_FOUND" => ExtensionRegistry {
            registry_version: 1,
            extensions: Vec::new(),
        },
        Err(error) => return snapshot(Vec::new(), vec![error]),
    };
    let mut extensions = registry.extensions;
    extensions.sort_by(|left, right| left.product_id.cmp(&right.product_id));
    snapshot(extensions, Vec::new())
}

pub fn get_extension(root: &Path, product_id: &str) -> Result<ExtensionSummary, String> {
    load_registry(root)
        .extensions
        .into_iter()
        .find(|extension| extension.product_id == product_id)
        .ok_or_else(|| "EXTENSION_NOT_FOUND".to_string())
}

pub fn health(root: &Path, product_id: &str) -> Result<ExtensionHealth, String> {
    let extension = get_extension(root, product_id)?;
    Ok(ExtensionHealth {
        product_id: extension.product_id,
        state: extension.state,
        detail: extension.error.unwrap_or(extension.health),
        signature_status: extension.signature_status,
    })
}

pub fn capabilities(root: &Path, product_id: &str) -> Result<ExtensionCapabilities, String> {
    let extension = get_extension(root, product_id)?;
    Ok(ExtensionCapabilities {
        product_id: extension.product_id,
        capabilities: extension.capabilities,
    })
}

pub fn install_bundle(
    root: &Path,
    bundle_path: &Path,
    verifier: &ExtensionBundleVerifier,
) -> Result<ExtensionSummary, String> {
    install_bundle_with_health(root, bundle_path, verifier, |_| Ok(()))
}

pub fn install_bundle_with_health<F>(
    root: &Path,
    bundle_path: &Path,
    verifier: &ExtensionBundleVerifier,
    health_check: F,
) -> Result<ExtensionSummary, String>
where
    F: Fn(&ExtensionBundleManifest) -> Result<(), String>,
{
    prepare_roots(root)?;
    let manifest = read_bundle_manifest(bundle_path)?;
    validate_manifest(&manifest)?;
    validate_bundle_tree(bundle_path, &manifest)?;
    let verification = verifier.verify(&manifest)?;
    let mut registry = match read_registry(root) {
        Ok(registry) => registry,
        Err(error) if error == "EXTENSION_REGISTRY_NOT_FOUND" => ExtensionRegistry {
            registry_version: 1,
            extensions: Vec::new(),
        },
        Err(error) => return Err(error),
    };
    validate_dependencies(&registry, &manifest)?;

    let staging = root
        .join("staging")
        .join(format!("{}-{}", manifest.bundle_id, Uuid::new_v4()));
    copy_bundle_tree(bundle_path, &staging)?;
    let installed = root
        .join("installed")
        .join(&manifest.product.product_id)
        .join(&manifest.bundle_id);
    if installed.exists() {
        let previous = root
            .join("rollback")
            .join(&manifest.product.product_id)
            .join(format!("{}-replaced-{}", manifest.bundle_id, unix_now()));
        if let Some(parent) = previous.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("EXTENSION_INSTALL_REPLACE_FAILED: {error}"))?;
        }
        fs::rename(&installed, &previous)
            .map_err(|error| format!("EXTENSION_INSTALL_REPLACE_FAILED: {error}"))?;
    }
    if let Some(parent) = installed.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("EXTENSION_INSTALL_UNAVAILABLE: {error}"))?;
    }
    fs::rename(&staging, &installed)
        .map_err(|error| format!("EXTENSION_INSTALL_COMMIT_FAILED: {error}"))?;

    if let Err(error) = health_check(&manifest) {
        let rollback_path = root
            .join("rollback")
            .join(&manifest.product.product_id)
            .join(format!("{}-{}", manifest.bundle_id, unix_now()));
        if let Some(parent) = rollback_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::rename(&installed, &rollback_path);
        return Err(format!("EXTENSION_HEALTH_FAILED: {error}"));
    }

    let summary = summary_from_manifest(
        &manifest,
        &installed,
        verification.signature_status,
        "ACTIVE",
        "local_import",
    );
    registry
        .extensions
        .retain(|item| item.product_id != manifest.product.product_id);
    registry.extensions.push(summary.clone());
    write_registry(root, &registry)?;
    write_active_marker(root, &summary)?;
    Ok(summary)
}

pub fn disable(root: &Path, product_id: &str) -> Result<ExtensionSummary, String> {
    mutate_state(root, product_id, "DISABLED", "DISABLED")
}

pub fn enable(root: &Path, product_id: &str) -> Result<ExtensionSummary, String> {
    mutate_state(root, product_id, "ACTIVE", "HEALTHY")
}

pub fn rollback(
    root: &Path,
    product_id: &str,
    verifier: &ExtensionBundleVerifier,
) -> Result<ExtensionSummary, String> {
    let mut registry = read_registry(root)?;
    let current = registry
        .extensions
        .iter()
        .find(|item| item.product_id == product_id)
        .cloned()
        .ok_or_else(|| "EXTENSION_NOT_FOUND".to_string())?;
    let rollback_root = root.join("rollback").join(product_id);
    let candidate = newest_directory(&rollback_root)?
        .ok_or_else(|| "EXTENSION_ROLLBACK_UNAVAILABLE".to_string())?;
    let manifest = read_bundle_manifest(&candidate)?;
    validate_manifest(&manifest)?;
    if manifest.product.product_id != current.product_id {
        return Err("EXTENSION_ROLLBACK_PRODUCT_MISMATCH".to_string());
    }
    validate_bundle_tree(&candidate, &manifest)?;
    let verification = verifier.verify(&manifest)?;
    let installed = root
        .join("installed")
        .join(product_id)
        .join(&manifest.bundle_id);
    if installed.exists() {
        fs::remove_dir_all(&installed)
            .map_err(|error| format!("EXTENSION_ROLLBACK_FAILED: {error}"))?;
    }
    if let Some(parent) = installed.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("EXTENSION_ROLLBACK_FAILED: {error}"))?;
    }
    fs::rename(&candidate, &installed)
        .map_err(|error| format!("EXTENSION_ROLLBACK_FAILED: {error}"))?;
    let mut restored = summary_from_manifest(
        &manifest,
        &installed,
        verification.signature_status,
        "ROLLED_BACK",
        "rollback",
    );
    restored.health = "HEALTHY".to_string();
    registry
        .extensions
        .retain(|item| item.product_id != product_id);
    registry.extensions.push(restored.clone());
    write_registry(root, &registry)?;
    write_active_marker(root, &restored)?;
    Ok(restored)
}

pub fn remove(root: &Path, product_id: &str) -> Result<(), String> {
    let mut registry = read_registry(root)?;
    let current = registry
        .extensions
        .iter()
        .find(|item| item.product_id == product_id)
        .cloned()
        .ok_or_else(|| "EXTENSION_NOT_FOUND".to_string())?;
    let installed = root
        .join("installed")
        .join(product_id)
        .join(&current.bundle_id);
    if installed.exists() {
        let archive = root.join("rollback").join(product_id).join(format!(
            "removed-{}-{}",
            current.bundle_id,
            unix_now()
        ));
        if let Some(parent) = archive.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("EXTENSION_REMOVE_FAILED: {error}"))?;
        }
        fs::rename(installed, archive)
            .map_err(|error| format!("EXTENSION_REMOVE_FAILED: {error}"))?;
    }
    registry
        .extensions
        .retain(|item| item.product_id != product_id);
    write_registry(root, &registry)?;
    let marker = root.join("active").join(format!("{product_id}.json"));
    if marker.exists() {
        fs::remove_file(marker).map_err(|error| format!("EXTENSION_REMOVE_FAILED: {error}"))?;
    }
    Ok(())
}

fn prepare_roots(root: &Path) -> Result<(), String> {
    for directory in ["staging", "installed", "active", "rollback", "trust"] {
        fs::create_dir_all(root.join(directory))
            .map_err(|error| format!("EXTENSION_REGISTRY_UNAVAILABLE: {error}"))?;
    }
    Ok(())
}

fn read_registry(root: &Path) -> Result<ExtensionRegistry, String> {
    let path = root.join(EXTENSION_REGISTRY_FILE);
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "EXTENSION_REGISTRY_NOT_FOUND".to_string()
        } else {
            format!("EXTENSION_REGISTRY_UNREADABLE: {error}")
        }
    })?;
    let registry: ExtensionRegistry = serde_json::from_slice(&bytes)
        .map_err(|error| format!("EXTENSION_REGISTRY_INVALID: {error}"))?;
    if registry.registry_version != 1 {
        return Err("EXTENSION_REGISTRY_VERSION_UNSUPPORTED".to_string());
    }
    Ok(registry)
}

fn write_registry(root: &Path, registry: &ExtensionRegistry) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(registry)
        .map_err(|error| format!("EXTENSION_REGISTRY_SERIALIZE_FAILED: {error}"))?;
    atomic_write(&root.join(EXTENSION_REGISTRY_FILE), &bytes)
}

fn write_active_marker(root: &Path, summary: &ExtensionSummary) -> Result<(), String> {
    let marker = root
        .join("active")
        .join(format!("{}.json", summary.product_id));
    let bytes = serde_json::to_vec(summary)
        .map_err(|error| format!("EXTENSION_ACTIVATION_FAILED: {error}"))?;
    atomic_write(&marker, &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("EXTENSION_REGISTRY_WRITE_FAILED: {error}"))?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("EXTENSION_REGISTRY_WRITE_FAILED: {error}"));
    }
    Ok(())
}

fn read_bundle_manifest(bundle_path: &Path) -> Result<ExtensionBundleManifest, String> {
    let metadata = fs::symlink_metadata(bundle_path)
        .map_err(|error| format!("EXTENSION_BUNDLE_UNREADABLE: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("EXTENSION_SYMLINK_FORBIDDEN".to_string());
    }
    if !metadata.is_dir() {
        return Err("EXTENSION_BUNDLE_DIRECTORY_REQUIRED".to_string());
    }
    let manifest_path = bundle_path.join(EXTENSION_MANIFEST_FILE);
    let bytes = fs::read(&manifest_path)
        .map_err(|error| format!("EXTENSION_MANIFEST_UNREADABLE: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("EXTENSION_MANIFEST_INVALID_JSON: {error}"))
}

fn validate_manifest(manifest: &ExtensionBundleManifest) -> Result<(), String> {
    if manifest.contract_name != "actium-product-extension-bundle"
        || manifest.contract_version != "1.0.0"
        || manifest.schema != 1
        || manifest.bundle_id.trim().is_empty()
    {
        return Err("EXTENSION_SCHEMA_UNSUPPORTED".to_string());
    }
    if manifest.product.product_id != "aegis" && !valid_product_id(&manifest.product.product_id) {
        return Err("EXTENSION_PRODUCT_ID_INVALID".to_string());
    }
    if !valid_product_id(&manifest.product.product_id)
        || !valid_id(&manifest.bundle_id)
        || !valid_version(&manifest.product.product_version)
        || !valid_version(&manifest.bundle_version)
    {
        return Err("EXTENSION_MANIFEST_ID_OR_VERSION_INVALID".to_string());
    }
    if manifest.platform != "any" && manifest.platform != std::env::consts::OS {
        return Err("EXTENSION_PLATFORM_MISMATCH".to_string());
    }
    if manifest.architecture != "any" && manifest.architecture != std::env::consts::ARCH {
        return Err("EXTENSION_ARCHITECTURE_MISMATCH".to_string());
    }
    if manifest.compatibility.base_runtime_contract != "actium-node-manager-host@1.0.0" {
        return Err("EXTENSION_BASE_RUNTIME_INCOMPATIBLE".to_string());
    }
    if manifest.capabilities.is_empty() || manifest.artifacts.is_empty() {
        return Err("EXTENSION_CONTENT_EMPTY".to_string());
    }
    let mut capability_ids = BTreeSet::new();
    for capability in &manifest.capabilities {
        if !valid_capability(&capability.id)
            || !valid_version(&capability.version)
            || capability.runtime.trim().is_empty()
            || !capability_ids.insert(&capability.id)
        {
            return Err("EXTENSION_CAPABILITIES_INVALID".to_string());
        }
    }
    let mut artifact_paths = BTreeSet::new();
    for artifact in &manifest.artifacts {
        validate_relative_path(&artifact.path)?;
        if !artifact.path.starts_with("artifacts/") || !artifact_paths.insert(&artifact.path) {
            return Err("EXTENSION_ARTIFACT_PATH_INVALID".to_string());
        }
        validate_digest(&artifact.sha256, "EXTENSION_ARTIFACT_DIGEST_INVALID")?;
    }
    let mut dependency_ids = BTreeSet::new();
    for dependency in &manifest.dependencies {
        if !valid_product_id(&dependency.product_id)
            || !valid_version(&dependency.bundle_version)
            || !dependency_ids.insert(&dependency.product_id)
        {
            return Err("EXTENSION_DEPENDENCIES_INVALID".to_string());
        }
    }
    if manifest.issued_at == 0
        || manifest
            .expires_at
            .is_some_and(|expiry| expiry <= manifest.issued_at)
    {
        return Err("EXTENSION_ISSUED_AT_INVALID".to_string());
    }
    if manifest
        .expires_at
        .is_some_and(|expiry| expiry <= unix_now())
    {
        return Err("EXTENSION_EXPIRED".to_string());
    }
    validate_digest(
        &manifest.manifest_digest,
        "EXTENSION_MANIFEST_DIGEST_INVALID",
    )?;
    if manifest.signing.key_id.trim().is_empty()
        || manifest.signing.algorithm != "ed25519"
        || manifest.signing.signature.trim().is_empty()
    {
        return Err("EXTENSION_SIGNATURE_METADATA_INVALID".to_string());
    }
    Ok(())
}

fn validate_bundle_tree(
    bundle_path: &Path,
    manifest: &ExtensionBundleManifest,
) -> Result<(), String> {
    let mut actual_artifacts = BTreeSet::new();
    collect_files(bundle_path, bundle_path, &mut actual_artifacts)?;
    if !actual_artifacts.contains(EXTENSION_MANIFEST_FILE) {
        return Err("EXTENSION_MANIFEST_MISSING".to_string());
    }
    for artifact in &manifest.artifacts {
        if !actual_artifacts.contains(&artifact.path) {
            return Err(format!("EXTENSION_ARTIFACT_MISSING: {}", artifact.path));
        }
        let path = bundle_path.join(&artifact.path);
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("EXTENSION_ARTIFACT_UNREADABLE: {error}"))?;
        if metadata.len() != artifact.size {
            return Err(format!(
                "EXTENSION_ARTIFACT_SIZE_MISMATCH: {}",
                artifact.path
            ));
        }
        let digest = sha256_file(&path)?;
        if !constant_time_hex_eq(&digest, &artifact.sha256) {
            return Err(format!(
                "EXTENSION_ARTIFACT_DIGEST_MISMATCH: {}",
                artifact.path
            ));
        }
    }
    let declared = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    if actual_artifacts
        .iter()
        .any(|path| path.starts_with("artifacts/") && !declared.contains(path.as_str()))
    {
        return Err("EXTENSION_UNEXPECTED_ARTIFACT".to_string());
    }
    Ok(())
}

fn collect_files(root: &Path, current: &Path, files: &mut BTreeSet<String>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(current)
        .map_err(|error| format!("EXTENSION_BUNDLE_UNREADABLE: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("EXTENSION_SYMLINK_FORBIDDEN".to_string());
    }
    if metadata.is_file() {
        let relative = current
            .strip_prefix(root)
            .map_err(|_| "EXTENSION_PATH_INVALID".to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        validate_relative_path(&relative)?;
        files.insert(relative);
        return Ok(());
    }
    for entry in
        fs::read_dir(current).map_err(|error| format!("EXTENSION_BUNDLE_UNREADABLE: {error}"))?
    {
        collect_files(
            root,
            &entry
                .map_err(|error| format!("EXTENSION_BUNDLE_UNREADABLE: {error}"))?
                .path(),
            files,
        )?;
    }
    Ok(())
}

fn copy_bundle_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|error| format!("EXTENSION_STAGE_FAILED: {error}"))?;
    for entry in fs::read_dir(source).map_err(|error| format!("EXTENSION_STAGE_FAILED: {error}"))? {
        let entry = entry.map_err(|error| format!("EXTENSION_STAGE_FAILED: {error}"))?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| format!("EXTENSION_STAGE_FAILED: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("EXTENSION_SYMLINK_FORBIDDEN".to_string());
        }
        if metadata.is_dir() {
            copy_bundle_tree(&source_path, &target_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &target_path)
                .map_err(|error| format!("EXTENSION_STAGE_FAILED: {error}"))?;
        } else {
            return Err("EXTENSION_BUNDLE_ENTRY_UNSUPPORTED".to_string());
        }
    }
    Ok(())
}

fn validate_dependencies(
    registry: &ExtensionRegistry,
    manifest: &ExtensionBundleManifest,
) -> Result<(), String> {
    for dependency in &manifest.dependencies {
        let found = registry.extensions.iter().any(|item| {
            item.product_id != manifest.product.product_id
                && item.state == "ACTIVE"
                && item.bundle_version.as_deref() == Some(dependency.bundle_version.as_str())
                && item.product_id == dependency.product_id
        });
        if !found {
            return Err(format!(
                "EXTENSION_DEPENDENCY_UNSATISFIED: {}",
                dependency.product_id
            ));
        }
    }
    Ok(())
}

fn summary_from_manifest(
    manifest: &ExtensionBundleManifest,
    installed: &Path,
    signature_status: String,
    state: &str,
    source: &str,
) -> ExtensionSummary {
    let artifact_digests = manifest
        .artifacts
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact.sha256.clone()))
        .collect();
    let capabilities = manifest
        .capabilities
        .iter()
        .map(|capability| capability.id.clone())
        .collect();
    let product_version = manifest.product.product_version.clone();
    ExtensionSummary {
        bundle_id: manifest.bundle_id.clone(),
        product_id: manifest.product.product_id.clone(),
        bundle_version: Some(manifest.bundle_version.clone()),
        product_version: Some(product_version.clone()),
        version: Some(product_version),
        sha256: Some(manifest.manifest_digest.clone()),
        capabilities,
        installed_at: Some(unix_now()),
        state: state.to_string(),
        status: state.to_string(),
        health: "HEALTHY".to_string(),
        manifest_digest: Some(manifest.manifest_digest.clone()),
        artifact_digests,
        signature_status,
        key_id: Some(manifest.signing.key_id.clone()),
        desired_version: Some(manifest.bundle_version.clone()),
        observed_version: Some(manifest.bundle_version.clone()),
        source: source.to_string(),
        manifest_path: installed
            .join(EXTENSION_MANIFEST_FILE)
            .to_string_lossy()
            .into_owned(),
        error: None,
    }
}

fn mutate_state(
    root: &Path,
    product_id: &str,
    state: &str,
    health: &str,
) -> Result<ExtensionSummary, String> {
    let mut registry = read_registry(root)?;
    let item = registry
        .extensions
        .iter_mut()
        .find(|item| item.product_id == product_id)
        .ok_or_else(|| "EXTENSION_NOT_FOUND".to_string())?;
    if state == "ACTIVE"
        && (item.state == "REVOKED" || item.signature_status != "VERIFIED")
    {
        return Err("EXTENSION_ACTIVATION_NOT_AUTHORIZED".to_string());
    }
    item.state = state.to_string();
    item.status = state.to_string();
    item.health = health.to_string();
    let result = item.clone();
    write_registry(root, &registry)?;
    if state == "DISABLED" {
        let marker = root.join("active").join(format!("{product_id}.json"));
        if marker.exists() {
            fs::remove_file(marker)
                .map_err(|error| format!("EXTENSION_DISABLE_FAILED: {error}"))?;
        }
    } else {
        write_active_marker(root, &result)?;
    }
    Ok(result)
}

fn newest_directory(root: &Path) -> Result<Option<PathBuf>, String> {
    if !root.is_dir() {
        return Ok(None);
    }
    let mut entries = fs::read_dir(root)
        .map_err(|error| format!("EXTENSION_ROLLBACK_UNAVAILABLE: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries.pop())
}

fn manifest_digest(manifest: &ExtensionBundleManifest) -> Result<String, String> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_digest.clear();
    unsigned.signing.signature.clear();
    let value = serde_json::to_value(unsigned)
        .map_err(|error| format!("EXTENSION_MANIFEST_SERIALIZE_FAILED: {error}"))?;
    let canonical = crate::canonical_json(&value)?;
    Ok(hex_digest(canonical.as_bytes()))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("EXTENSION_ARTIFACT_UNREADABLE: {error}"))?;
    Ok(hex_digest(&bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_digest(value: &str, error: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(error.to_string())
    } else {
        Ok(())
    }
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn validate_relative_path(value: &str) -> Result<(), String> {
    if value.is_empty() || value.contains('\0') || value.contains('\\') || value.contains(':') {
        return Err("EXTENSION_PATH_INVALID".to_string());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err("EXTENSION_PATH_TRAVERSAL".to_string());
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=96).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'.'
        })
}

fn valid_product_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_capability(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=96).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || *byte == b'-'
                || *byte == b'_'
                || *byte == b'.'
        })
}

fn valid_version(value: &str) -> bool {
    let mut pieces = value.splitn(2, '-');
    let Some(core) = pieces.next() else {
        return false;
    };
    let numbers = core.split('.').collect::<Vec<_>>();
    numbers.len() == 3
        && numbers.iter().all(|part| {
            !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
        })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn snapshot(extensions: Vec<ExtensionSummary>, errors: Vec<String>) -> ExtensionRegistrySnapshot {
    let has_invalid = extensions.iter().any(|extension| {
        extension.state == "FAILED" || extension.state == "DEGRADED" || extension.state == "REVOKED"
    });
    let extension_registry_state = if errors.is_empty() && extensions.is_empty() {
        "NO_EXTENSIONS"
    } else if errors.is_empty() && !has_invalid {
        "READY"
    } else {
        "DEGRADED"
    };
    let base_runtime_state = if has_invalid || extension_registry_state == "DEGRADED" {
        "EXTENSION_DEGRADED"
    } else if extensions.is_empty() {
        "BASE_RUNTIME_READY"
    } else {
        "EXTENSIONS_READY"
    };
    ExtensionRegistrySnapshot {
        base_runtime_state: base_runtime_state.to_string(),
        extension_count: extensions.len(),
        extensions,
        extension_registry_state: extension_registry_state.to_string(),
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("actium-extension-m2-2-{label}-{}", Uuid::new_v4()))
    }

    fn make_bundle(root: &Path, key_id: &str, signing_key: &SigningKey) -> PathBuf {
        let bundle = root.join("aegis-1.0.0.actium-extension");
        let artifact = bundle.join("artifacts").join("aegis").join("people.js");
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let contents = b"export const capability = 'aegis.people';\n";
        fs::write(&artifact, contents).unwrap();
        let mut manifest = ExtensionBundleManifest {
            contract_name: "actium-product-extension-bundle".to_string(),
            contract_version: "1.0.0".to_string(),
            schema: 1,
            bundle_id: "aegis-1.0.0".to_string(),
            product: ExtensionProduct {
                product_id: "aegis".to_string(),
                product_version: "1.0.0".to_string(),
            },
            bundle_version: "1.0.0".to_string(),
            platform: "any".to_string(),
            architecture: "any".to_string(),
            capabilities: vec![ExtensionCapability {
                id: "aegis.people".to_string(),
                version: "1.0.0".to_string(),
                runtime: "node".to_string(),
                dependencies: Vec::new(),
                health_contract: Some("aegis.people.health@1".to_string()),
                activation_requirements: Vec::new(),
                configuration_schema: None,
            }],
            artifacts: vec![ExtensionArtifact {
                path: "artifacts/aegis/people.js".to_string(),
                sha256: hex_digest(contents),
                size: contents.len() as u64,
            }],
            dependencies: Vec::new(),
            compatibility: ExtensionCompatibility {
                base_runtime_contract: "actium-node-manager-host@1.0.0".to_string(),
                min_manager_version: None,
                required_features: Vec::new(),
            },
            issued_at: unix_now().saturating_sub(1),
            expires_at: None,
            manifest_digest: String::new(),
            signing: ExtensionSigning {
                key_id: key_id.to_string(),
                algorithm: "ed25519".to_string(),
                signature: String::new(),
            },
        };
        manifest.manifest_digest = manifest_digest(&manifest).unwrap();
        manifest.signing.signature = BASE64.encode(
            signing_key
                .sign(manifest.manifest_digest.as_bytes())
                .to_bytes(),
        );
        fs::write(
            bundle.join(EXTENSION_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        bundle
    }

    #[test]
    fn ausencia_de_extensiones_deja_base_ready() {
        let root = temp_root("empty");
        let state = load_registry(&root);
        assert_eq!(state.base_runtime_state, "BASE_RUNTIME_READY");
        assert_eq!(state.extension_registry_state, "NO_EXTENSIONS");
        assert_eq!(state.extension_count, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn bundle_firmado_se_instala_y_persiste() {
        let root = temp_root("valid");
        let key = SigningKey::generate(&mut OsRng);
        let bundle = make_bundle(&root, "aegis-test-v1", &key);
        let verifier =
            ExtensionBundleVerifier::new().with_trusted_key("aegis-test-v1", key.verifying_key());
        let installed = install_bundle(&root.join("registry"), &bundle, &verifier).unwrap();
        assert_eq!(installed.state, "ACTIVE");
        assert_eq!(installed.signature_status, "VERIFIED");
        assert_eq!(load_registry(&root.join("registry")).extension_count, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tamper_de_manifest_y_artifact_es_rechazado() {
        let root = temp_root("tampered");
        let key = SigningKey::generate(&mut OsRng);
        let bundle = make_bundle(&root, "aegis-test-v1", &key);
        fs::write(bundle.join("artifacts/aegis/people.js"), b"tampered").unwrap();
        let verifier =
            ExtensionBundleVerifier::new().with_trusted_key("aegis-test-v1", key.verifying_key());
        let result = install_bundle(&root.join("registry"), &bundle, &verifier);
        assert!(result.unwrap_err().contains("MISMATCH"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn health_failure_no_deja_runtime_activo() {
        let root = temp_root("health");
        let key = SigningKey::generate(&mut OsRng);
        let bundle = make_bundle(&root, "aegis-test-v1", &key);
        let verifier =
            ExtensionBundleVerifier::new().with_trusted_key("aegis-test-v1", key.verifying_key());
        let result = install_bundle_with_health(&root.join("registry"), &bundle, &verifier, |_| {
            Err("health probe failed".to_string())
        });
        assert!(result.unwrap_err().contains("EXTENSION_HEALTH_FAILED"));
        assert_eq!(load_registry(&root.join("registry")).extension_count, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn clave_revocada_y_paths_peligrosos_fallan_cerrado() {
        let root = temp_root("security");
        let key = SigningKey::generate(&mut OsRng);
        let bundle = make_bundle(&root, "aegis-test-v1", &key);
        let verifier = ExtensionBundleVerifier::new()
            .with_trusted_key("aegis-test-v1", key.verifying_key())
            .with_revoked_key("aegis-test-v1");
        assert_eq!(
            install_bundle(&root.join("registry"), &bundle, &verifier).unwrap_err(),
            "EXTENSION_KEY_REVOKED"
        );
        assert!(validate_relative_path("../outside").is_err());
        assert!(validate_relative_path("C:/outside").is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn disable_enable_remove_persisten_el_lifecycle() {
        let root = temp_root("actions");
        let key = SigningKey::generate(&mut OsRng);
        let bundle = make_bundle(&root, "aegis-test-v1", &key);
        let registry_root = root.join("registry");
        let verifier =
            ExtensionBundleVerifier::new().with_trusted_key("aegis-test-v1", key.verifying_key());
        install_bundle(&registry_root, &bundle, &verifier).unwrap();
        assert_eq!(disable(&registry_root, "aegis").unwrap().state, "DISABLED");
        assert_eq!(enable(&registry_root, "aegis").unwrap().state, "ACTIVE");
        remove(&registry_root, "aegis").unwrap();
        assert_eq!(load_registry(&registry_root).extension_count, 0);
        let _ = fs::remove_dir_all(root);
    }
}
