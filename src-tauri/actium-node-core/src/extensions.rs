use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub const EXTENSION_CONTRACT: &str = "actium-product-extension-bundle@1.0.0";
pub const EXTENSION_MANIFEST_FILE: &str = "manifest.json";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionBundleManifest {
    pub contract_name: String,
    pub contract_version: String,
    pub product_id: String,
    pub version: String,
    pub sha256: String,
    pub capabilities: Vec<String>,
    pub compatibility: ExtensionCompatibility,
    pub signature: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExtensionCompatibility {
    pub base_runtime_contract: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionSummary {
    pub product_id: String,
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub capabilities: Vec<String>,
    pub status: String,
    pub signature_status: String,
    pub key_id: Option<String>,
    pub manifest_path: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionRegistrySnapshot {
    pub base_runtime_state: String,
    pub extension_count: usize,
    pub extensions: Vec<ExtensionSummary>,
    pub extension_registry_state: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionHealth {
    pub product_id: String,
    pub state: String,
    pub detail: String,
    pub signature_status: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionCapabilities {
    pub product_id: String,
    pub capabilities: Vec<String>,
}

pub fn load_registry(root: &Path) -> ExtensionRegistrySnapshot {
    let mut extensions = Vec::new();
    let mut errors = Vec::new();

    if let Err(error) = fs::create_dir_all(root) {
        errors.push(format!("EXTENSION_REGISTRY_UNAVAILABLE: {error}"));
        return snapshot(extensions, errors);
    }

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            errors.push(format!("EXTENSION_REGISTRY_UNREADABLE: {error}"));
            return snapshot(extensions, errors);
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let product_id = entry.file_name().to_string_lossy().into_owned();
        let manifest_path = path.join(EXTENSION_MANIFEST_FILE);
        match read_manifest(&manifest_path) {
            Ok(manifest) => match validate_manifest(&manifest) {
                Ok(()) => extensions.push(ExtensionSummary {
                    product_id: manifest.product_id,
                    version: Some(manifest.version),
                    sha256: Some(manifest.sha256),
                    capabilities: manifest.capabilities,
                    status: "registered".to_string(),
                    signature_status: "present_unverified".to_string(),
                    key_id: Some(manifest.key_id),
                    manifest_path: manifest_path.to_string_lossy().into_owned(),
                    error: None,
                }),
                Err(error) => {
                    errors.push(format!("{product_id}: {error}"));
                    extensions.push(invalid_summary(&product_id, &manifest_path, error));
                }
            },
            Err(error) => {
                errors.push(format!("{product_id}: {error}"));
                extensions.push(invalid_summary(&product_id, &manifest_path, error));
            }
        }
    }

    extensions.sort_by(|left, right| left.product_id.cmp(&right.product_id));
    snapshot(extensions, errors)
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
        state: extension.status.clone(),
        detail: extension
            .error
            .unwrap_or_else(|| "manifest_registered_signature_unverified".to_string()),
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

fn snapshot(extensions: Vec<ExtensionSummary>, errors: Vec<String>) -> ExtensionRegistrySnapshot {
    let has_invalid = extensions
        .iter()
        .any(|extension| extension.status == "invalid");
    let extension_registry_state = if errors.is_empty() && extensions.is_empty() {
        "NO_EXTENSIONS"
    } else if errors.is_empty() {
        "READY"
    } else {
        "DEGRADED"
    };
    let base_runtime_state = if extension_registry_state == "DEGRADED" || has_invalid {
        "EXTENSION_DEGRADED"
    } else if extensions.is_empty() {
        "BASE_RUNTIME_READY"
    } else {
        "EXTENSIONS_READY"
    };
    ExtensionRegistrySnapshot {
        base_runtime_state: base_runtime_state.to_string(),
        extension_count: extensions
            .iter()
            .filter(|extension| extension.status == "registered")
            .count(),
        extensions,
        extension_registry_state: extension_registry_state.to_string(),
        errors,
    }
}

fn read_manifest(path: &Path) -> Result<ExtensionBundleManifest, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("EXTENSION_MANIFEST_UNREADABLE: {error}"))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("EXTENSION_MANIFEST_INVALID_JSON: {error}"))
}

fn validate_manifest(manifest: &ExtensionBundleManifest) -> Result<(), String> {
    if manifest.contract_name != "actium-product-extension-bundle"
        || manifest.contract_version != "1.0.0"
    {
        return Err("EXTENSION_CONTRACT_UNSUPPORTED".to_string());
    }
    if !valid_product_id(&manifest.product_id) {
        return Err("EXTENSION_PRODUCT_ID_INVALID".to_string());
    }
    if !valid_version(&manifest.version) {
        return Err("EXTENSION_VERSION_INVALID".to_string());
    }
    if manifest.sha256.len() != 64 || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("EXTENSION_SHA256_INVALID".to_string());
    }
    if manifest.capabilities.is_empty()
        || manifest
            .capabilities
            .iter()
            .any(|capability| !valid_capability(capability))
    {
        return Err("EXTENSION_CAPABILITIES_INVALID".to_string());
    }
    let unique = manifest.capabilities.iter().collect::<BTreeSet<_>>();
    if unique.len() != manifest.capabilities.len() {
        return Err("EXTENSION_CAPABILITIES_DUPLICATED".to_string());
    }
    if manifest.compatibility.base_runtime_contract != "actium-node-manager-host@1.0.0" {
        return Err("EXTENSION_BASE_RUNTIME_INCOMPATIBLE".to_string());
    }
    if manifest.signature.trim().is_empty() || manifest.key_id.trim().is_empty() {
        return Err("EXTENSION_SIGNATURE_METADATA_MISSING".to_string());
    }
    Ok(())
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
    (2..=64).contains(&bytes.len())
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
    let mut parts = value.splitn(2, '-');
    let Some(core) = parts.next() else {
        return false;
    };
    let numbers = core.split('.').collect::<Vec<_>>();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn invalid_summary(product_id: &str, manifest_path: &PathBuf, error: String) -> ExtensionSummary {
    ExtensionSummary {
        product_id: product_id.to_string(),
        version: None,
        sha256: None,
        capabilities: Vec::new(),
        status: "invalid".to_string(),
        signature_status: "unavailable".to_string(),
        key_id: None,
        manifest_path: manifest_path.to_string_lossy().into_owned(),
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("actium-extension-registry-{label}-{nonce}"))
    }

    fn valid_manifest() -> &'static str {
        r#"{
          "contract_name": "actium-product-extension-bundle",
          "contract_version": "1.0.0",
          "product_id": "aegis",
          "version": "1.2.3",
          "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "capabilities": ["telemetry_v1", "radio.v1"],
          "compatibility": { "base_runtime_contract": "actium-node-manager-host@1.0.0" },
          "signature": "detached-signature",
          "key_id": "aegis-extension-v1"
        }"#
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
    fn manifest_valido_se_registra_sin_verificar_firma_aca() {
        let root = temp_root("valid");
        let extension = root.join("aegis");
        fs::create_dir_all(&extension).unwrap();
        fs::write(extension.join(EXTENSION_MANIFEST_FILE), valid_manifest()).unwrap();
        let state = load_registry(&root);
        assert_eq!(state.base_runtime_state, "EXTENSIONS_READY");
        assert_eq!(state.extension_count, 1);
        assert_eq!(state.extensions[0].signature_status, "present_unverified");
        assert_eq!(capabilities(&root, "aegis").unwrap().capabilities.len(), 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn manifest_invalido_degrada_solo_extension_registry() {
        let root = temp_root("invalid");
        let extension = root.join("broken");
        fs::create_dir_all(&extension).unwrap();
        fs::write(extension.join(EXTENSION_MANIFEST_FILE), "{}").unwrap();
        let state = load_registry(&root);
        assert_eq!(state.base_runtime_state, "EXTENSION_DEGRADED");
        assert_eq!(state.extension_registry_state, "DEGRADED");
        assert_eq!(state.extension_count, 0);
        let _ = fs::remove_dir_all(root);
    }
}
