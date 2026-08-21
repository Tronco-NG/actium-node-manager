use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialTrustEntry {
    pub key_id: String,
    pub public_key_spki_b64: String,
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

#[derive(Debug, Clone)]
pub struct MaterialTrustStore {
    entries: Vec<MaterialTrustEntry>,
}

impl MaterialTrustStore {
    pub fn from_entries(entries: Vec<MaterialTrustEntry>) -> Self {
        Self { entries }
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
        let entry = self
            .entries
            .iter()
            .find(|e| e.key_id == key_id)
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
        Ok(entry.clone())
    }
}
