use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const HOST_IDENTITY_FILE: &str = "host-identity.json";
pub const LEGACY_HOST_INSTALLATION_ID_FILE: &str = "host-installation-id";
pub const NODE_INSTALLATION_ENV_KEY: &str = "ACTIUM_NODE_INSTALLATION_ID";

pub const HOST_IDENTITY_ENV_KEYS: [&str; 5] = [
    "ACTIUM_HOST_INSTALLATION_ID",
    "ACTIUM_HOST_CODE",
    "ACTIUM_HOST_DISPLAY_NAME",
    "ACTIUM_HOST_PLATFORM",
    "ACTIUM_HOST_ARCHITECTURE",
];

pub const HOST_IDENTITY_CONFLICT: &str = "HOST_IDENTITY_CONFLICT";
pub const NODE_IDENTITY_MISSING: &str = "NODE_IDENTITY_MISSING";
pub const NODE_IDENTITY_CONFLICT: &str = "NODE_IDENTITY_CONFLICT";
pub const AMBIGUOUS_NODE_IDENTITY: &str = "AMBIGUOUS_NODE_IDENTITY";
pub const HOST_IDENTITY_MISSING: &str = "HOST_IDENTITY_MISSING";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostIdentity {
    pub host_installation_id: String,
    pub host_code: String,
    pub display_name: String,
    pub platform: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeInstallationIdentity {
    pub installation_id: String,
    pub deployment_id: String,
    pub deployment_code: String,
    pub project_name: String,
    pub manager_channel: String,
    pub install_dir: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIdentityScope {
    Fresh,
    PreTopologyLeftover,
    OperationalEnrolled,
}

impl HostIdentity {
    pub fn generate() -> Self {
        let host_installation_id = Uuid::new_v4().to_string();
        Self::from_installation_id(host_installation_id)
    }

    pub fn from_installation_id(host_installation_id: String) -> Self {
        let short = host_code_suffix(&host_installation_id);
        Self {
            host_installation_id,
            host_code: format!("actium-host-{short}"),
            display_name: default_display_name(),
            platform: current_platform(),
            architecture: current_architecture(),
        }
    }

    pub fn from_env(values: &BTreeMap<String, String>) -> Option<Self> {
        let host_installation_id = env_value(values, "ACTIUM_HOST_INSTALLATION_ID")?;
        let short = host_code_suffix(&host_installation_id);
        Some(Self {
            host_installation_id: host_installation_id.clone(),
            host_code: env_value(values, "ACTIUM_HOST_CODE")
                .unwrap_or_else(|| format!("actium-host-{short}")),
            display_name: env_value(values, "ACTIUM_HOST_DISPLAY_NAME")
                .unwrap_or_else(default_display_name),
            platform: env_value(values, "ACTIUM_HOST_PLATFORM").unwrap_or_else(current_platform),
            architecture: env_value(values, "ACTIUM_HOST_ARCHITECTURE")
                .unwrap_or_else(current_architecture),
        })
    }

    pub fn apply_to_env(&self, values: &mut BTreeMap<String, String>) {
        values.insert(
            "ACTIUM_HOST_INSTALLATION_ID".into(),
            self.host_installation_id.clone(),
        );
        values.insert("ACTIUM_HOST_CODE".into(), self.host_code.clone());
        values.insert("ACTIUM_HOST_DISPLAY_NAME".into(), self.display_name.clone());
        values.insert("ACTIUM_HOST_PLATFORM".into(), self.platform.clone());
        values.insert("ACTIUM_HOST_ARCHITECTURE".into(), self.architecture.clone());
    }
}

pub fn apply_node_installation_id(values: &mut BTreeMap<String, String>, installation_id: &str) {
    values.insert(
        NODE_INSTALLATION_ENV_KEY.to_string(),
        installation_id.to_string(),
    );
}

pub fn host_identity_path(state_dir: &Path) -> PathBuf {
    state_dir.join(HOST_IDENTITY_FILE)
}

pub fn legacy_host_installation_id_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LEGACY_HOST_INSTALLATION_ID_FILE)
}

pub fn load_host_identity(state_dir: &Path) -> Result<Option<HostIdentity>, String> {
    let path = host_identity_path(state_dir);
    if path.is_file() {
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
        let identity = serde_json::from_str::<HostIdentity>(&contents)
            .map_err(|error| format!("HostIdentity persistida invalida: {error}"))?;
        validate_host_identity(&identity)?;
        return Ok(Some(identity));
    }
    let legacy = legacy_host_installation_id_path(state_dir);
    if legacy.is_file() {
        let value = fs::read_to_string(&legacy)
            .map_err(|error| format!("No se pudo leer {}: {error}", legacy.display()))?;
        let host_installation_id = Uuid::parse_str(value.trim())
            .map(|value| value.to_string())
            .map_err(|_| "host-installation-id persistido no es UUID.".to_string())?;
        let identity = HostIdentity::from_installation_id(host_installation_id);
        persist_host_identity(state_dir, &identity)?;
        return Ok(Some(identity));
    }
    Ok(None)
}

pub fn persist_host_identity(state_dir: &Path, identity: &HostIdentity) -> Result<(), String> {
    validate_host_identity(identity)?;
    fs::create_dir_all(state_dir)
        .map_err(|error| format!("No se pudo crear estado de host: {error}"))?;
    let path = host_identity_path(state_dir);
    let value = serde_json::to_value(identity)
        .map_err(|error| format!("No se pudo serializar HostIdentity: {error}"))?;
    write_json_atomic(&path, &value)?;
    let legacy = legacy_host_installation_id_path(state_dir);
    write_text_atomic(&legacy, &format!("{}\n", identity.host_installation_id))?;
    Ok(())
}

pub fn load_or_create_host_identity(state_dir: &Path) -> Result<HostIdentity, String> {
    if let Some(identity) = load_host_identity(state_dir)? {
        return Ok(identity);
    }
    let identity = HostIdentity::generate();
    match persist_new_host_identity(state_dir, &identity) {
        Ok(()) => Ok(identity),
        Err(error) if error.contains("AlreadyExists") || error.contains("ya existe") => {
            load_host_identity(state_dir)?
                .ok_or_else(|| "HostIdentity concurrente no se pudo releer.".to_string())
        }
        Err(error) => Err(error),
    }
}

pub fn reconcile_host_identity(
    state_dir: &Path,
    leftover_env: &BTreeMap<String, String>,
    scope: HostIdentityScope,
) -> Result<HostIdentity, String> {
    let persisted = load_host_identity(state_dir)?;
    let leftover = HostIdentity::from_env(leftover_env);
    match (persisted, leftover, scope) {
        (Some(supervisor), _, HostIdentityScope::Fresh)
        | (Some(supervisor), _, HostIdentityScope::PreTopologyLeftover) => {
            persist_host_identity(state_dir, &supervisor)?;
            Ok(supervisor)
        }
        (None, _, HostIdentityScope::Fresh)
        | (None, _, HostIdentityScope::PreTopologyLeftover) => {
            load_or_create_host_identity(state_dir)
        }
        (Some(supervisor), Some(node), HostIdentityScope::OperationalEnrolled) => {
            if supervisor.host_installation_id != node.host_installation_id {
                return Err(format!(
                    "{HOST_IDENTITY_CONFLICT}: leftover={} supervisor={}.",
                    node.host_installation_id, supervisor.host_installation_id
                ));
            }
            persist_host_identity(state_dir, &supervisor)?;
            Ok(supervisor)
        }
        (None, Some(node), HostIdentityScope::OperationalEnrolled) => {
            validate_host_identity(&node)?;
            persist_host_identity(state_dir, &node)?;
            Ok(node)
        }
        (Some(_), None, HostIdentityScope::OperationalEnrolled) => Err(format!(
            "{HOST_IDENTITY_MISSING}: el nodo operativo no conserva ACTIUM_HOST_INSTALLATION_ID."
        )),
        (None, None, HostIdentityScope::OperationalEnrolled) => Err(format!(
            "{AMBIGUOUS_NODE_IDENTITY}: el nodo operativo no tiene HostIdentity y Supervisor tampoco."
        )),
    }
}

pub fn require_node_installation_id(
    marker_installation_id: Option<&str>,
    env_node_installation_id: Option<&str>,
) -> Result<String, String> {
    let marker = marker_installation_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let env_node = env_node_installation_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match (marker, env_node) {
        (Some(marker), Some(env_node)) if marker == env_node => Ok(marker.to_string()),
        (Some(marker), None) => Ok(marker.to_string()),
        (None, Some(_)) => Err(format!(
            "{NODE_IDENTITY_MISSING}: el marcador no conserva installationId; no se adopta ACTIUM_HOST_INSTALLATION_ID."
        )),
        (Some(marker), Some(env_node)) => Err(format!(
            "{NODE_IDENTITY_CONFLICT}: marker={marker} env={env_node}."
        )),
        (None, None) => Err(format!(
            "{NODE_IDENTITY_MISSING}: no hay installationId de nodo."
        )),
    }
}

pub fn current_platform() -> String {
    env::consts::OS.to_string()
}

pub fn current_architecture() -> String {
    match env::consts::ARCH {
        "x86_64" => "x86_64".into(),
        "aarch64" => "aarch64".into(),
        value => value.to_string(),
    }
}

fn persist_new_host_identity(state_dir: &Path, identity: &HostIdentity) -> Result<(), String> {
    fs::create_dir_all(state_dir)
        .map_err(|error| format!("No se pudo crear estado de host: {error}"))?;
    let path = host_identity_path(state_dir);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    match options.open(&path) {
        Ok(mut file) => {
            let bytes = serde_json::to_vec_pretty(identity)
                .map_err(|error| format!("No se pudo serializar HostIdentity: {error}"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("No se pudo persistir HostIdentity: {error}"))?;
            drop(file);
            persist_host_identity(state_dir, identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err("HostIdentity ya existe.".to_string())
        }
        Err(error) => Err(format!("No se pudo crear HostIdentity: {error}")),
    }
}

fn validate_host_identity(identity: &HostIdentity) -> Result<(), String> {
    Uuid::parse_str(identity.host_installation_id.trim())
        .map_err(|_| "hostInstallationId no es UUID.".to_string())?;
    if identity.host_code.trim().is_empty() || identity.display_name.trim().is_empty() {
        return Err("HostIdentity incompleta: hostCode/displayName vacios.".to_string());
    }
    if identity.host_code.contains('\n') || identity.display_name.contains('\n') {
        return Err("HostIdentity contiene saltos de linea.".to_string());
    }
    Ok(())
}

fn default_display_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !value.contains('\n'))
        .unwrap_or_else(|| "Actium Host".to_string())
}

fn host_code_suffix(host_installation_id: &str) -> String {
    host_installation_id
        .chars()
        .filter(|item| item.is_ascii_hexdigit())
        .take(8)
        .collect()
}

fn env_value(values: &BTreeMap<String, String>, key: &str) -> Option<String> {
    values
        .get(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("No se pudo serializar {}: {error}", path.display()))?;
    write_bytes_atomic(path, &bytes)
}

fn write_text_atomic(path: &Path, contents: &str) -> Result<(), String> {
    write_bytes_atomic(path, contents.as_bytes())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = fs::File::create(&temporary)
        .map_err(|error| format!("No se pudo crear {}: {error}", temporary.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo escribir {}: {error}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo promover {}: {error}", path.display()))?;
    Ok(())
}

use std::env;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!("actium-host-id-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn persistida_una_vez_se_reutiliza() {
        let root = temp_dir();
        let first = load_or_create_host_identity(&root).unwrap();
        let second = load_or_create_host_identity(&root).unwrap();
        assert_eq!(first, second);
        assert_ne!(first.host_code, "project-name");
        assert!(!first.display_name.contains("project"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn leftover_pre_topology_adopta_supervisor() {
        let root = temp_dir();
        let supervisor = load_or_create_host_identity(&root).unwrap();
        let leftover = BTreeMap::from([
            (
                "ACTIUM_HOST_INSTALLATION_ID".into(),
                "e0864698-6978-4481-bfb2-76df5d9032bf".into(),
            ),
            ("ACTIUM_HOST_CODE".into(), "actium-lab-node-01".into()),
            (
                "ACTIUM_HOST_DISPLAY_NAME".into(),
                "actium-lab-node-01".into(),
            ),
        ]);
        let resolved =
            reconcile_host_identity(&root, &leftover, HostIdentityScope::PreTopologyLeftover)
                .unwrap();
        assert_eq!(
            resolved.host_installation_id,
            supervisor.host_installation_id
        );
        assert_ne!(
            resolved.host_installation_id,
            "e0864698-6978-4481-bfb2-76df5d9032bf"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn operacional_conserva_host_enrolado_y_conflicto_falla_cerrado() {
        let root = temp_dir();
        let enrolled =
            HostIdentity::from_installation_id("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into());
        let leftover = {
            let mut values = BTreeMap::new();
            enrolled.apply_to_env(&mut values);
            values
        };
        let adopted =
            reconcile_host_identity(&root, &leftover, HostIdentityScope::OperationalEnrolled)
                .unwrap();
        assert_eq!(adopted.host_installation_id, enrolled.host_installation_id);

        let other = temp_dir();
        let supervisor = load_or_create_host_identity(&other).unwrap();
        let error =
            reconcile_host_identity(&other, &leftover, HostIdentityScope::OperationalEnrolled)
                .unwrap_err();
        assert!(error.contains(HOST_IDENTITY_CONFLICT), "{error}");
        assert_ne!(
            supervisor.host_installation_id,
            enrolled.host_installation_id
        );
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(other);
    }

    #[test]
    fn no_mezcla_marker_con_host_installation_id() {
        let error = require_node_installation_id(None, Some("node-from-env")).unwrap_err();
        assert!(error.contains(NODE_IDENTITY_MISSING), "{error}");
        let error = require_node_installation_id(None, None).unwrap_err();
        assert!(error.contains(NODE_IDENTITY_MISSING), "{error}");
        let ok = require_node_installation_id(Some("node-1"), Some("node-1")).unwrap();
        assert_eq!(ok, "node-1");
        let drifted = require_node_installation_id(Some("node-1"), Some("node-2")).unwrap_err();
        assert!(drifted.contains(NODE_IDENTITY_CONFLICT), "{drifted}");
    }

    #[test]
    fn host_code_no_se_deriva_del_proyecto() {
        let identity =
            HostIdentity::from_installation_id("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into());
        assert!(identity.host_code.starts_with("actium-host-"));
        assert!(!identity.host_code.contains("proyecto"));
        assert!(!identity.host_code.contains("actium-lab-node"));
    }
}
