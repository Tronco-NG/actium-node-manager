use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MATERIAL_PACKAGE_SCHEMA: u8 = 1;
pub const MATERIAL_STATE_SCHEMA: u8 = 1;
pub const MATERIAL_CONTENT_DIGEST_ALG: &str = "sha256-tree-v1";
pub const MATERIAL_MANIFEST_DIGEST_ALG: &str = "sha256-manifest-v1";
pub const MATERIAL_SIGNED_ENVELOPE_DIGEST_ALG: &str = "sha256-envelope-v1";

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

#[derive(Debug, Clone)]
pub struct NodeScope {
    pub organization_id: String,
    pub site_id: String,
    pub deployment_id: String,
    pub node_id: Option<String>,
    pub active_payload_digest: Option<String>,
    pub active_runtime_release: Option<String>,
    pub supervisor_features: Vec<String>,
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
