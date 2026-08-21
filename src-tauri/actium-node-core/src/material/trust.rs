use super::types::{MATERIAL_TRUST_STORE_SCHEMA, MATERIAL_TRUST_STORE_TYP};
use super::verify::{decode_b64, key_id_for_spki_der, parse_ed25519_spki_der};
use crate::material_fs::{material_trust_store_path, MaterialFilesystemBackend};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialTrustEntry {
    pub key_id: String,
    pub public_key_spki_der_b64: String,
    pub signer_id: String,
    pub allowed_issuers: Vec<String>,
    pub allowed_capabilities: Vec<String>,
    #[serde(default)]
    pub allow_generation_advance: bool,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub deployment_id: Option<String>,
    pub valid_from: String,
    #[serde(default)]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub is_root: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct MaterialTrustStoreFile {
    schema: u8,
    typ: String,
    entries: Vec<MaterialTrustEntry>,
}

#[derive(Debug, Clone)]
pub struct MaterialTrustStore {
    entries: Vec<MaterialTrustEntry>,
}

impl MaterialTrustStore {
    pub fn from_entries(entries: Vec<MaterialTrustEntry>) -> Result<Self, String> {
        validate_entries(&entries)?;
        Ok(Self { entries })
    }

    /// Load a Supervisor-owned trust store from a path outside `state/agent`.
    ///
    /// Validates owner, permissions, schema, duplicate key_id, SPKI, key_id
    /// binding, issuer/capability lists, and key lifecycle fields.
    /// Operational rotation is not implemented in A1 — keys are loaded and
    /// lifecycle-checked only.
    pub fn load(path: &Path, fs: &dyn MaterialFilesystemBackend) -> Result<Self, String> {
        assert_supervisor_trust_path(path)?;
        let meta = fs.inspect_secure_file(path)?;
        if meta.is_symlink {
            return Err("MATERIAL_TRUST_SYMLINK".into());
        }
        #[cfg(unix)]
        {
            let euid = nix::unistd::Uid::effective().as_raw();
            if let Some(uid) = meta.unix_uid {
                if uid != 0 && uid != euid {
                    return Err("MATERIAL_TRUST_OWNER".into());
                }
            }
            if let Some(mode) = meta.unix_mode {
                if mode & 0o022 != 0 {
                    return Err("MATERIAL_TRUST_PERMISSIONS".into());
                }
            }
        }
        let bytes = fs.read_regular_file_bounded(path, 1024 * 1024)?;
        let file: MaterialTrustStoreFile =
            serde_json::from_slice(&bytes).map_err(|e| format!("MATERIAL_TRUST_SCHEMA: {e}"))?;
        if file.schema != MATERIAL_TRUST_STORE_SCHEMA {
            return Err("MATERIAL_TRUST_SCHEMA".into());
        }
        if file.typ != MATERIAL_TRUST_STORE_TYP {
            return Err("MATERIAL_TRUST_TYP".into());
        }
        Self::from_entries(file.entries)
    }

    pub fn load_from_node_root(
        node_root: &Path,
        fs: &dyn MaterialFilesystemBackend,
    ) -> Result<Self, String> {
        Self::load(&material_trust_store_path(node_root), fs)
    }

    pub fn resolve_and_authorize(
        &self,
        key_id: &str,
        issuer: &str,
        capability: &str,
        organization_id: &str,
        site_id: &str,
        deployment_id: &str,
        issued_at: &str,
        requires_generation_advance: bool,
    ) -> Result<MaterialTrustEntry, String> {
        let matches: Vec<_> = self.entries.iter().filter(|e| e.key_id == key_id).collect();
        if matches.len() > 1 {
            return Err("MATERIAL_TRUST_DUPLICATE_KEY_ID".into());
        }
        let entry = matches
            .first()
            .ok_or_else(|| "MATERIAL_TRUST_KEY_UNKNOWN".to_string())?;
        if entry.revoked_at.is_some() {
            return Err("MATERIAL_TRUST_KEY_REVOKED".into());
        }
        if issued_at < entry.valid_from.as_str() {
            return Err("MATERIAL_TRUST_KEY_NOT_YET_VALID".into());
        }
        if let Some(until) = &entry.valid_until {
            if issued_at > until.as_str() {
                return Err("MATERIAL_TRUST_KEY_EXPIRED".into());
            }
        }
        if !entry.allowed_issuers.iter().any(|v| v == issuer) {
            return Err("MATERIAL_TRUST_ISSUER_REJECTED".into());
        }
        if !entry
            .allowed_capabilities
            .iter()
            .any(|v| v == capability || v == "*")
        {
            return Err("MATERIAL_TRUST_CAPABILITY_REJECTED".into());
        }
        if let Some(expected) = &entry.organization_id {
            if expected != organization_id {
                return Err("MATERIAL_TRUST_ORG_MISMATCH".into());
            }
        }
        if let Some(expected) = &entry.site_id {
            if expected != site_id {
                return Err("MATERIAL_TRUST_SITE_MISMATCH".into());
            }
        }
        if let Some(expected) = &entry.deployment_id {
            if expected != deployment_id {
                return Err("MATERIAL_TRUST_DEPLOYMENT_MISMATCH".into());
            }
        }
        if requires_generation_advance && !entry.allow_generation_advance {
            return Err("MATERIAL_GENERATION_ADVANCE_UNAUTHORIZED".into());
        }
        Ok((*entry).clone())
    }
}

fn validate_entries(entries: &[MaterialTrustEntry]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for entry in entries {
        if entry.key_id.trim().is_empty() {
            return Err("MATERIAL_TRUST_KEY_ID_MISSING".into());
        }
        if !seen.insert(entry.key_id.clone()) {
            return Err("MATERIAL_TRUST_DUPLICATE_KEY_ID".into());
        }
        if entry.signer_id.trim().is_empty() {
            return Err("MATERIAL_TRUST_SIGNER_MISSING".into());
        }
        if entry.allowed_issuers.is_empty() {
            return Err("MATERIAL_TRUST_ISSUERS_EMPTY".into());
        }
        if entry.allowed_capabilities.is_empty() {
            return Err("MATERIAL_TRUST_CAPABILITIES_EMPTY".into());
        }
        if entry.valid_from.trim().is_empty() {
            return Err("MATERIAL_TRUST_VALID_FROM_MISSING".into());
        }
        if let Some(until) = &entry.valid_until {
            if until.as_str() < entry.valid_from.as_str() {
                return Err("MATERIAL_TRUST_LIFECYCLE".into());
            }
        }
        let der = decode_b64(&entry.public_key_spki_der_b64)?;
        parse_ed25519_spki_der(&der)?;
        if entry.key_id != key_id_for_spki_der(&der) {
            return Err("MATERIAL_TRUST_KEY_ID_MISMATCH".into());
        }
    }
    Ok(())
}

fn assert_supervisor_trust_path(path: &Path) -> Result<(), String> {
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.contains("/state/agent/")
        || normalized.ends_with("/state/agent")
        || normalized.contains("/state/agent")
    {
        return Err("MATERIAL_TRUST_PATH_AGENT_FORBIDDEN".into());
    }
    if !normalized.contains("/state/supervisor/") {
        return Err("MATERIAL_TRUST_PATH_NOT_SUPERVISOR".into());
    }
    Ok(())
}
