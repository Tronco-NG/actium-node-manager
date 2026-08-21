use super::trust::MaterialTrustStore;
use super::types::{
    MaterialContract, MaterialContractRegistry, SupervisorScopeEvidence, TrustedNodeScope,
};
use crate::material_fs::{
    MaterialFilesystemBackend, StdMaterialFilesystem, MATERIAL_PLANE_FEATURE,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn trusted_scope_from_node_root(node_root: &Path) -> Result<TrustedNodeScope, String> {
    let env = load_node_env(node_root)?;
    let organization_id = required_env(&env, "ACTIUM_ORGANIZATION_ID")?;
    let site_id = required_env(&env, "ACTIUM_SITE_ID")?;
    let deployment_id = required_env(&env, "ACTIUM_DEPLOYMENT_ID")?;
    let installation_id = env
        .get("ACTIUM_NODE_INSTALLATION_ID")
        .cloned()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "MATERIAL_SCOPE_INSTALLATION_MISSING".to_string())?;
    let node_id = env
        .get("ACTIUM_NODE_ID")
        .cloned()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| Some(deployment_id.clone()));
    TrustedNodeScope::from_supervisor_evidence(SupervisorScopeEvidence {
        organization_id,
        site_id,
        deployment_id,
        node_id,
        installation_id,
        active_payload_digest: env.get("ACTIUM_PAYLOAD_DIGEST").cloned(),
        active_runtime_release: env
            .get("ACTIUM_RUNTIME_RELEASE")
            .cloned()
            .or_else(|| env.get("ACTIUM_INSTALLER_VERSION").cloned()),
        supervisor_features: vec![MATERIAL_PLANE_FEATURE.to_string()],
    })
}

pub fn load_contract_registry(node_root: &Path) -> Result<MaterialContractRegistry, String> {
    let path = node_root
        .join("state")
        .join("supervisor")
        .join("material")
        .join("contracts-v1.json");
    if !path.is_file() {
        return Ok(MaterialContractRegistry::new());
    }
    let bytes = StdMaterialFilesystem.read_regular_file_bounded(&path, 1024 * 1024)?;
    let file: ContractFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("MATERIAL_CONTRACT_SCHEMA: {e}"))?;
    if file.schema != 1 {
        return Err("MATERIAL_CONTRACT_SCHEMA".into());
    }
    let mut registry = MaterialContractRegistry::new();
    for contract in file.contracts {
        registry.insert(contract);
    }
    Ok(registry)
}

pub fn load_trust_store(node_root: &Path) -> Result<MaterialTrustStore, String> {
    MaterialTrustStore::load_from_node_root(node_root, &StdMaterialFilesystem)
}

pub fn resolve_package_dir(node_root: &Path, package_dir: &str) -> Result<PathBuf, String> {
    let candidate = PathBuf::from(package_dir);
    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        node_root.join(candidate)
    };
    let root = node_root
        .canonicalize()
        .unwrap_or_else(|_| node_root.to_path_buf());
    let resolved = absolute.canonicalize().unwrap_or(absolute);
    let root_s = root.to_string_lossy().replace('\\', "/");
    let resolved_s = resolved.to_string_lossy().replace('\\', "/");
    if resolved_s.contains("/state/agent/") {
        return Err("MATERIAL_PACKAGE_FROM_AGENT_STATE".into());
    }
    if !resolved_s.starts_with(&root_s) {
        return Err("MATERIAL_PACKAGE_PATH_ESCAPE".into());
    }
    Ok(resolved)
}

fn load_node_env(node_root: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = node_root.join("node.env");
    let contents =
        std::fs::read_to_string(&path).map_err(|e| format!("MATERIAL_SCOPE_NODE_ENV: {e}"))?;
    Ok(contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect())
}

fn required_env(env: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    env.get(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("MATERIAL_SCOPE_ENV_MISSING:{key}"))
}

#[derive(serde::Deserialize)]
struct ContractFile {
    schema: u8,
    contracts: Vec<MaterialContract>,
}
