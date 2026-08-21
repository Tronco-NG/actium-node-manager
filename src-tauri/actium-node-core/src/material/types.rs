use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MATERIAL_PACKAGE_SCHEMA: u8 = 1;
pub const MATERIAL_STATE_SCHEMA: u8 = 1;
pub const MATERIAL_CONTENT_DIGEST_ALG: &str = "sha256-tree-v1";
pub const MATERIAL_MANIFEST_DIGEST_ALG: &str = "sha256-manifest-v1";
pub const MATERIAL_SIGNED_ENVELOPE_DIGEST_ALG: &str = "sha256-envelope-v1";
pub const SIGNED_ENVELOPE_V1: &str = "signed-envelope-v1";
pub const MATERIAL_TRUST_STORE_SCHEMA: u8 = 1;
pub const MATERIAL_TRUST_STORE_TYP: &str = "actium.material.trust-store.v1";
pub const ACTIVATION_VERIFY_ONLY: &str = "verify_only";
pub const ACTIVATION_HEALTH_RECEIPT: &str = "health_receipt";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialContentEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialSignature {
    pub alg: String,
    pub key_id: String,
    pub signature: String,
    /// Optional package-local copy of a public key. Never a trust anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialAntiRollback {
    pub min_authority_epoch: u64,
    pub min_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_material_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialPackageBodyV1 {
    pub schema: u8,
    pub material_id: String,
    pub capability: String,
    pub authority_epoch: u64,
    pub generation: u64,
    pub revision: u64,
    pub organization_id: String,
    pub site_id: String,
    pub deployment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_material_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_release: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<String>,
    pub material_content_digest: String,
    pub material_manifest_digest: String,
    pub content_digest_alg: String,
    pub manifest_digest_alg: String,
    pub issuer: String,
    pub audience: Vec<String>,
    pub typ: String,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub feature_requirements: Vec<String>,
    pub content_manifest: Vec<MaterialContentEntry>,
    #[serde(default)]
    pub extensions: BTreeMap<String, serde_json::Value>,
    pub anti_rollback: MaterialAntiRollback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialPackageV1 {
    #[serde(flatten)]
    pub body: MaterialPackageBodyV1,
    pub signature: MaterialSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialContract {
    pub capability: String,
    pub allowed_path_prefixes: Vec<String>,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_file_count: usize,
    pub activation_policy: String,
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MaterialContractRegistry {
    contracts: BTreeMap<String, MaterialContract>,
}

impl MaterialContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, contract: MaterialContract) {
        self.contracts.insert(contract.capability.clone(), contract);
    }
    pub fn get(&self, capability: &str) -> Result<&MaterialContract, String> {
        self.contracts
            .get(capability)
            .ok_or_else(|| format!("MATERIAL_CONTRACT_UNKNOWN:{capability}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialRef {
    pub material_id: String,
    pub authority_epoch: u64,
    pub generation: u64,
    pub revision: u64,
    pub material_content_digest: String,
    pub package_dir_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialStateV1 {
    pub schema: u8,
    pub state_revision: u64,
    pub capability: String,
    pub deployment_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<MaterialRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lkg: Option<MaterialRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<MaterialRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_base_state_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub updated_at: String,
}

/// Supervisor-owned identity used as the only authoritative material-plane scope.
///
/// Fields are private so IPC/Agent callers cannot construct a forged scope and
/// inject organization/site/deployment/node identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedNodeScope {
    organization_id: String,
    site_id: String,
    deployment_id: String,
    node_id: Option<String>,
    installation_id: String,
    active_payload_digest: Option<String>,
    active_runtime_release: Option<String>,
    supervisor_features: Vec<String>,
}

/// Evidence the Supervisor collected from installation identity, deployment
/// marker, Site binding, active release/payload, and trusted local config.
/// Material IPC must never populate this from client-supplied identifiers.
#[derive(Debug, Clone)]
pub struct SupervisorScopeEvidence {
    pub organization_id: String,
    pub site_id: String,
    pub deployment_id: String,
    pub node_id: Option<String>,
    pub installation_id: String,
    pub active_payload_digest: Option<String>,
    pub active_runtime_release: Option<String>,
    pub supervisor_features: Vec<String>,
}

impl TrustedNodeScope {
    pub fn from_supervisor_evidence(evidence: SupervisorScopeEvidence) -> Result<Self, String> {
        if evidence.organization_id.trim().is_empty() {
            return Err("MATERIAL_SCOPE_ORG_MISSING".into());
        }
        if evidence.site_id.trim().is_empty() {
            return Err("MATERIAL_SCOPE_SITE_MISSING".into());
        }
        if evidence.deployment_id.trim().is_empty() {
            return Err("MATERIAL_SCOPE_DEPLOYMENT_MISSING".into());
        }
        if evidence.installation_id.trim().is_empty() {
            return Err("MATERIAL_SCOPE_INSTALLATION_MISSING".into());
        }
        Ok(Self {
            organization_id: evidence.organization_id,
            site_id: evidence.site_id,
            deployment_id: evidence.deployment_id,
            node_id: evidence.node_id,
            installation_id: evidence.installation_id,
            active_payload_digest: evidence.active_payload_digest,
            active_runtime_release: evidence.active_runtime_release,
            supervisor_features: evidence.supervisor_features,
        })
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }
    pub fn site_id(&self) -> &str {
        &self.site_id
    }
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }
    pub fn node_id(&self) -> Option<&str> {
        self.node_id.as_deref()
    }
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
    pub fn active_payload_digest(&self) -> Option<&str> {
        self.active_payload_digest.as_deref()
    }
    pub fn active_runtime_release(&self) -> Option<&str> {
        self.active_runtime_release.as_deref()
    }
    pub fn supervisor_features(&self) -> &[String] {
        &self.supervisor_features
    }

    #[cfg(test)]
    pub fn for_tests(
        organization_id: impl Into<String>,
        site_id: impl Into<String>,
        deployment_id: impl Into<String>,
        node_id: Option<String>,
        supervisor_features: Vec<String>,
    ) -> Self {
        Self {
            organization_id: organization_id.into(),
            site_id: site_id.into(),
            deployment_id: deployment_id.into(),
            node_id,
            installation_id: "install-test".into(),
            active_payload_digest: None,
            active_runtime_release: None,
            supervisor_features,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthReceipt {
    pub capability: String,
    pub generation: u64,
    pub material_digest: String,
    pub checked_at: String,
    pub checker_identity: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
}

impl HealthReceipt {
    #[cfg(test)]
    pub fn verify_only_fixture(candidate: &MaterialRef, capability: &str) -> Self {
        Self {
            capability: capability.to_string(),
            generation: candidate.generation,
            material_digest: candidate.material_content_digest.clone(),
            checked_at: material_now_ts(),
            checker_identity: "fixture:verify_only".into(),
            result: "pass".into(),
            evidence_digest: Some("sha256:verify-only-fixture".into()),
        }
    }

    pub fn validate_for_candidate(
        &self,
        candidate: &MaterialRef,
        capability: &str,
    ) -> Result<(), String> {
        if self.capability != capability {
            return Err("MATERIAL_HEALTH_CAPABILITY_MISMATCH".into());
        }
        if self.generation != candidate.generation {
            return Err("MATERIAL_HEALTH_GENERATION_MISMATCH".into());
        }
        if self.material_digest != candidate.material_content_digest {
            return Err("MATERIAL_HEALTH_DIGEST_MISMATCH".into());
        }
        if self.checker_identity.trim().is_empty() {
            return Err("MATERIAL_HEALTH_CHECKER_MISSING".into());
        }
        if self.checked_at.trim().is_empty() {
            return Err("MATERIAL_HEALTH_CHECKED_AT_MISSING".into());
        }
        match self.result.as_str() {
            "pass" | "fail" => Ok(()),
            _ => Err("MATERIAL_HEALTH_RESULT_INVALID".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MaterialResourceLimits {
    pub max_pending_inbox_bytes: u64,
    pub max_pending_package_count: usize,
    pub max_generations: usize,
    pub max_global_material_bytes: u64,
}

impl Default for MaterialResourceLimits {
    fn default() -> Self {
        Self {
            max_pending_inbox_bytes: 64 * 1024 * 1024,
            max_pending_package_count: 32,
            max_generations: 64,
            max_global_material_bytes: 512 * 1024 * 1024,
        }
    }
}

pub(crate) fn material_now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs:020}")
}

pub(crate) fn package_content_bytes(package: &MaterialPackageV1) -> u64 {
    package
        .body
        .content_manifest
        .iter()
        .fold(0u64, |acc, entry| acc.saturating_add(entry.size))
}
