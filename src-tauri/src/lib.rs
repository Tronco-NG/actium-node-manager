use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tauri::{path::BaseDirectory, AppHandle, Manager};

const MARKER_FILE: &str = ".actium-node-installation.json";
const TRUSTED_BOOTSTRAP_ISSUER: &str =
    "https://lgngdqgjmvmjplovvxqd.supabase.co/functions/v1/actium-data-plane-bootstrap";
const TRUSTED_BOOTSTRAP_AUDIENCE: &str = "actium-telemetry-node-installer";
const TRUSTED_BOOTSTRAP_KEY_REF: &str = "actium-ed25519-telemetry-20260722-v1";
const INSTALLER_VERSION: &str = "0.4.0";
const REGISTRY_FILE: &str = "nodes.json";
const TRUSTED_BOOTSTRAP_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl50wZ6t9RtKPkcSpbbntRyZxLdUgPuwPSqdHPyzpzQw=\n-----END PUBLIC KEY-----\n";
const KNOWN_PROFILES: [&str; 7] = [
    "telemetry",
    "radio-control",
    "radio-saf",
    "radio-turn",
    "radio-livekit",
    "observability",
    "connectivity",
];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    platform: String,
    architecture: String,
    default_install_dir: String,
    docker_cli: bool,
    docker_daemon: bool,
    compose_v2: bool,
    dependency_install_supported: bool,
    dependency_message: String,
    payload_version: String,
    suggested_public_base_url: String,
    managed_nodes_dir: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallationState {
    installed: bool,
    operational: bool,
    managed: bool,
    version: Option<String>,
    profiles: Vec<String>,
    config: BTreeMap<String, String>,
    marker_path: String,
    status: Option<String>,
    deployment_id: Option<String>,
    deployment_code: Option<String>,
    installation_id: Option<String>,
    recoverable_incomplete_preparation: bool,
    last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InspectRequest {
    install_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallRequest {
    install_dir: String,
    bootstrap_jws: String,
    profiles: Vec<String>,
    project_name: String,
    bind_address: String,
    public_base_url: String,
    cors_origins: String,
    telemetry_port: u16,
    radio_control_port: u16,
    prometheus_port: u16,
    grafana_port: u16,
    turn_realm: String,
    turn_external_ip: String,
    turn_min_port: u16,
    turn_max_port: u16,
    livekit_node_ip: String,
    livekit_public_url: String,
    connectivity_edge_control_url: String,
    connectivity_edge_enrollment_token: String,
    connectivity_internal_relay_token: String,
    connectivity_node_role: String,
    connectivity_node_priority: u16,
    connectivity_pull_limit: u16,
    connectivity_direct_data_plane_fallback_enabled: bool,
    connectivity_supabase_fallback_enabled: bool,
    connectivity_fallback_order: Vec<String>,
    use_published_images: bool,
    prepare_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapRequest {
    bootstrap_jws: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryRequest {
    install_dir: String,
    bootstrap_jws: String,
}

#[derive(Debug, Clone, Deserialize)]
struct BootstrapClaims {
    schema_version: u8,
    package_type: String,
    installer_min_version: String,
    enrollment_id: String,
    enrollment_token: String,
    deployment_id: String,
    deployment_code: String,
    deployment_name: String,
    client_id: Option<String>,
    organization_id: Option<String>,
    product_id: String,
    deployment_mode: String,
    orchestrator: String,
    region: Option<String>,
    generation: i64,
    checksum: String,
    control_endpoint: String,
    signing_key_ref: String,
    terminal_issuer: String,
    operator_issuer: String,
    terminal_public_key_pem: String,
    operator_public_key_pem: String,
    profiles: Vec<String>,
    #[serde(default)]
    connectivity_policy: Option<ConnectivityPolicy>,
    exp: usize,
    iss: String,
    aud: serde_json::Value,
    sub: String,
    jti: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectivityPolicy {
    edge_control_url: String,
    node_role: String,
    node_priority: u16,
    pull_limit: u16,
    direct_data_plane_fallback_enabled: bool,
    supabase_fallback_enabled: bool,
    fallback_order: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapValidationResult {
    valid: bool,
    deployment_id: String,
    deployment_code: String,
    deployment_name: String,
    organization_id: Option<String>,
    generation: i64,
    checksum: String,
    expires_at_unix_seconds: usize,
    profiles: Vec<String>,
    control_endpoint: String,
    signing_key_ref: String,
    installer_min_version: String,
    connectivity_policy: Option<ConnectivityPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeActionRequest {
    install_dir: String,
    action: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeRegistry {
    schema: u8,
    nodes: Vec<NodeRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeRegistryEntry {
    install_dir: String,
    last_discovered_at_unix_seconds: u64,
}

#[derive(Debug, Default)]
struct DockerNodeRuntime {
    project_name: Option<String>,
    total_services: usize,
    running_services: usize,
    unhealthy_services: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedNode {
    key: String,
    install_dir: String,
    display_name: String,
    project_name: Option<String>,
    deployment_id: Option<String>,
    deployment_code: Option<String>,
    installation_id: Option<String>,
    version: Option<String>,
    profiles: Vec<String>,
    status: String,
    operational: bool,
    recoverable: bool,
    archived: bool,
    can_manage: bool,
    last_error: Option<String>,
    total_services: usize,
    running_services: usize,
    unhealthy_services: usize,
    connectivity_configured: bool,
    connectivity_node_role: Option<String>,
    connectivity_node_priority: Option<u16>,
    connectivity_pull_limit: Option<u16>,
    connectivity_direct_data_plane_fallback_enabled: bool,
    connectivity_supabase_fallback_enabled: bool,
    connectivity_fallback_order: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallationTarget {
    install_dir: String,
    matched_existing: bool,
    installation: InstallationState,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionResult {
    ok: bool,
    message: String,
    output: String,
    installed_profiles: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallationMarker {
    schema: u8,
    version: String,
    profiles: Vec<String>,
    status: String,
    updated_at_unix_seconds: u64,
    #[serde(default)]
    deployment_id: Option<String>,
    #[serde(default)]
    deployment_code: Option<String>,
    #[serde(default)]
    installation_id: Option<String>,
    #[serde(default)]
    last_error: Option<String>,
}

fn command_exists(program: &str) -> bool {
    let mut command = if cfg!(target_os = "windows") {
        let mut value = Command::new("where.exe");
        value.arg(program);
        value
    } else {
        let mut value = Command::new("sh");
        value.args(["-c", &format!("command -v {} >/dev/null 2>&1", program)]);
        value
    };
    command
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn command_succeeds(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn actium_data_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        base.join("Actium")
    } else {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
            .unwrap_or_else(env::temp_dir);
        base.join("actium")
    }
}

fn default_install_dir() -> PathBuf {
    actium_data_root().join(if cfg!(target_os = "windows") {
        "TelemetryNode"
    } else {
        "telemetry-node"
    })
}

fn managed_nodes_dir() -> PathBuf {
    actium_data_root().join(if cfg!(target_os = "windows") {
        "TelemetryNodes"
    } else {
        "telemetry-nodes"
    })
}

fn recovery_root_dir() -> PathBuf {
    actium_data_root().join("ActiumTelemetryNode-Recovery")
}

fn registry_path() -> PathBuf {
    actium_data_root()
        .join("TelemetryNodeManager")
        .join(REGISTRY_FILE)
}

fn suggested_public_base_url() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("1.1.1.1:80")?;
            socket.local_addr()
        })
        .map(|address| format!("http://{}", address.ip()))
        .unwrap_or_else(|_| "http://127.0.0.1".to_string())
}

fn payload_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .resolve("node", BaseDirectory::Resource)
        .map_err(|error| format!("No se pudo resolver el payload del nodo: {error}"))
}

fn resource_file(app: &AppHandle, name: &str) -> Result<PathBuf, String> {
    app.path()
        .resolve(name, BaseDirectory::Resource)
        .map_err(|error| format!("No se pudo resolver {name}: {error}"))
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn read_env_file(path: &Path) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    let Ok(contents) = fs::read_to_string(path) else {
        return values;
    };
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            values.insert(
                key.trim().to_string(),
                value.trim().trim_matches(['"', '\'']).to_string(),
            );
        }
    }
    values
}

fn inspect_path(path: &Path) -> InstallationState {
    let marker_path = path.join(MARKER_FILE);
    let marker = fs::read_to_string(&marker_path)
        .ok()
        .and_then(|contents| serde_json::from_str::<InstallationMarker>(&contents).ok());
    let mut config = read_env_file(&path.join("node.env"));
    let runtime_config = read_env_file(&path.join("secrets/data-plane.env"));
    for (key, value) in runtime_config {
        config.entry(key).or_insert(value);
    }
    let mut profiles = BTreeSet::new();
    if let Some(value) = marker.as_ref() {
        profiles.extend(value.profiles.iter().cloned());
    }
    for key in ["ACTIUM_PROFILES", "ACTIUM_ACTIVE_PROFILES"] {
        if let Some(value) = config.get(key) {
            profiles.extend(split_profiles(value));
        }
    }
    let status = marker.as_ref().map(|value| value.status.clone());
    let recoverable_incomplete_preparation = is_recoverable_preparation_status(status.as_deref());
    let installed = marker.is_some() || path.join("secrets/data-plane.env").is_file();
    let operational = is_operational_installation(installed, status.as_deref());
    let deployment_id = marker
        .as_ref()
        .and_then(|value| value.deployment_id.clone())
        .or_else(|| config.get("ACTIUM_DEPLOYMENT_ID").cloned());
    let deployment_code = marker
        .as_ref()
        .and_then(|value| value.deployment_code.clone())
        .or_else(|| config.get("ACTIUM_DEPLOYMENT_CODE").cloned());
    let installation_id = marker
        .as_ref()
        .and_then(|value| value.installation_id.clone())
        .or_else(|| config.get("ACTIUM_HOST_INSTALLATION_ID").cloned());
    InstallationState {
        installed,
        operational,
        managed: marker.is_some(),
        version: marker
            .as_ref()
            .map(|value| value.version.clone())
            .or_else(|| read_trimmed(&path.join("VERSION"))),
        profiles: profiles.into_iter().collect(),
        config,
        marker_path: marker_path.to_string_lossy().into_owned(),
        status,
        deployment_id,
        deployment_code,
        installation_id,
        recoverable_incomplete_preparation,
        last_error: marker.and_then(|value| value.last_error),
    }
}

fn is_recoverable_preparation_status(status: Option<&str>) -> bool {
    matches!(status, Some("failed" | "installing" | "prepared"))
}

fn is_operational_installation(installed: bool, status: Option<&str>) -> bool {
    installed && matches!(status, None | Some("running" | "stopped"))
}

fn split_profiles(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn path_identity(path: &Path) -> String {
    let value = path.to_string_lossy().replace('/', "\\");
    if cfg!(target_os = "windows") {
        value.to_lowercase()
    } else {
        value
    }
}

fn read_registry() -> NodeRegistry {
    fs::read_to_string(registry_path())
        .ok()
        .and_then(|contents| serde_json::from_str::<NodeRegistry>(&contents).ok())
        .unwrap_or(NodeRegistry {
            schema: 1,
            nodes: Vec::new(),
        })
}

fn write_registry(registry: &NodeRegistry) -> Result<(), String> {
    let path = registry_path();
    let parent = path
        .parent()
        .ok_or_else(|| "El registro de nodos no tiene un directorio padre seguro.".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("No se pudo crear el registro local de nodos: {error}"))?;
    let contents = serde_json::to_string_pretty(registry)
        .map_err(|error| format!("No se pudo serializar el registro local de nodos: {error}"))?;
    fs::write(&path, format!("{contents}\n"))
        .map_err(|error| format!("No se pudo persistir el registro local de nodos: {error}"))
}

fn remember_node_path(path: &Path) -> Result<(), String> {
    let mut registry = read_registry();
    registry.schema = 1;
    let identity = path_identity(path);
    if let Some(entry) = registry
        .nodes
        .iter_mut()
        .find(|entry| path_identity(Path::new(&entry.install_dir)) == identity)
    {
        entry.last_discovered_at_unix_seconds = now_marker_timestamp();
    } else {
        registry.nodes.push(NodeRegistryEntry {
            install_dir: path.to_string_lossy().into_owned(),
            last_discovered_at_unix_seconds: now_marker_timestamp(),
        });
    }
    registry
        .nodes
        .sort_by(|left, right| left.install_dir.cmp(&right.install_dir));
    write_registry(&registry)
}

fn child_directories(path: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_dir())
                .map(|_| entry.path())
        })
        .collect()
}

fn docker_node_runtimes() -> BTreeMap<String, (PathBuf, DockerNodeRuntime)> {
    let mut runtimes = BTreeMap::new();
    let Ok(ids_output) = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.ID}}"])
        .output()
    else {
        return runtimes;
    };
    if !ids_output.status.success() {
        return runtimes;
    }
    let ids = String::from_utf8_lossy(&ids_output.stdout)
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return runtimes;
    }

    let Ok(inspect_output) = Command::new("docker").arg("inspect").args(&ids).output() else {
        return runtimes;
    };
    if !inspect_output.status.success() {
        return runtimes;
    }
    let Ok(containers) = serde_json::from_slice::<Vec<serde_json::Value>>(&inspect_output.stdout)
    else {
        return runtimes;
    };

    for container in containers {
        let labels = container
            .get("Config")
            .and_then(|value| value.get("Labels"))
            .and_then(serde_json::Value::as_object);
        let Some(labels) = labels else {
            continue;
        };
        let Some(working_dir) = labels
            .get("com.docker.compose.project.working_dir")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let state = container
            .get("State")
            .and_then(|value| value.get("Status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let workload = labels
            .get("com.actium.workload")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let exit_code = container
            .get("State")
            .and_then(|value| value.get("ExitCode"))
            .and_then(serde_json::Value::as_i64);
        if workload == "schema_migrator" && state == "exited" && exit_code == Some(0) {
            continue;
        }
        let path = PathBuf::from(working_dir);
        let identity = path_identity(&path);
        let runtime = runtimes
            .entry(identity)
            .or_insert_with(|| (path, DockerNodeRuntime::default()));
        runtime.1.total_services += 1;
        if state == "running" {
            runtime.1.running_services += 1;
        }
        let health = container
            .get("State")
            .and_then(|value| value.get("Health"))
            .and_then(|value| value.get("Status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if health == "unhealthy" {
            runtime.1.unhealthy_services += 1;
        }
        if runtime.1.project_name.is_none() {
            runtime.1.project_name = labels
                .get("com.docker.compose.project")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
        }
    }
    runtimes
}

fn discover_managed_nodes() -> Result<Vec<ManagedNode>, String> {
    let registry = read_registry();
    let registry_identities = registry
        .nodes
        .iter()
        .map(|entry| path_identity(Path::new(&entry.install_dir)))
        .collect::<BTreeSet<_>>();
    let runtimes = docker_node_runtimes();
    let mut candidates = BTreeMap::<String, PathBuf>::new();

    for entry in &registry.nodes {
        let path = PathBuf::from(&entry.install_dir);
        candidates.insert(path_identity(&path), path);
    }
    let default = default_install_dir();
    candidates.insert(path_identity(&default), default);
    for path in child_directories(&managed_nodes_dir())
        .into_iter()
        .chain(child_directories(&recovery_root_dir()))
    {
        candidates.insert(path_identity(&path), path);
    }
    for (identity, (path, _)) in &runtimes {
        candidates.insert(identity.clone(), path.clone());
    }

    let recovery_root = recovery_root_dir();
    let mut nodes = Vec::new();
    let mut remembered = Vec::new();
    for (identity, path) in candidates {
        let state = inspect_path(&path);
        let runtime = runtimes.get(&identity).map(|value| &value.1);
        let registered = registry_identities.contains(&identity);
        if !state.installed && runtime.is_none() && !registered {
            continue;
        }
        let archived = path.starts_with(&recovery_root);
        let project_name = state
            .config
            .get("ACTIUM_DATA_PLANE_PROJECT")
            .or_else(|| state.config.get("ACTIUM_PROJECT_NAME"))
            .cloned()
            .or_else(|| runtime.and_then(|value| value.project_name.clone()));
        let display_name = state
            .config
            .get("ACTIUM_HOST_DISPLAY_NAME")
            .cloned()
            .or_else(|| state.deployment_code.clone())
            .or_else(|| project_name.clone())
            .or_else(|| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "Nodo Actium".to_string());
        let status = if !path.exists() {
            "missing".to_string()
        } else if archived {
            state
                .status
                .clone()
                .unwrap_or_else(|| "archived".to_string())
        } else {
            state.status.clone().unwrap_or_else(|| {
                if runtime.is_some_and(|value| value.running_services > 0) {
                    "running".to_string()
                } else {
                    "detected".to_string()
                }
            })
        };
        let key = state
            .installation_id
            .clone()
            .or_else(|| state.deployment_id.clone())
            .unwrap_or_else(|| identity.clone());
        let can_manage = state.operational
            && !archived
            && path
                .join(if cfg!(target_os = "windows") {
                    "manage-node.ps1"
                } else {
                    "manage-node.sh"
                })
                .is_file();
        nodes.push(ManagedNode {
            key,
            install_dir: path.to_string_lossy().into_owned(),
            display_name,
            project_name,
            deployment_id: state.deployment_id.clone(),
            deployment_code: state.deployment_code.clone(),
            installation_id: state.installation_id.clone(),
            version: state.version.clone(),
            profiles: state.profiles.clone(),
            status,
            operational: state.operational,
            recoverable: state.recoverable_incomplete_preparation,
            archived,
            can_manage,
            last_error: state.last_error.clone(),
            total_services: runtime.map_or(0, |value| value.total_services),
            running_services: runtime.map_or(0, |value| value.running_services),
            unhealthy_services: runtime.map_or(0, |value| value.unhealthy_services),
            connectivity_configured: state
                .profiles
                .iter()
                .any(|profile| profile == "connectivity")
                && state
                    .config
                    .get("CONNECTIVITY_EDGE_CONTROL_URL")
                    .is_some_and(|value| value.starts_with("https://")),
            connectivity_node_role: state.config.get("CONNECTIVITY_NODE_ROLE").cloned(),
            connectivity_node_priority: state
                .config
                .get("CONNECTIVITY_NODE_PRIORITY")
                .and_then(|value| value.parse::<u16>().ok()),
            connectivity_pull_limit: state
                .config
                .get("CONNECTIVITY_PULL_LIMIT")
                .and_then(|value| value.parse::<u16>().ok()),
            connectivity_direct_data_plane_fallback_enabled: state
                .config
                .get("CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            connectivity_supabase_fallback_enabled: state
                .config
                .get("CONNECTIVITY_SUPABASE_FALLBACK_ENABLED")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
            connectivity_fallback_order: state
                .config
                .get("CONNECTIVITY_FALLBACK_ORDER")
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        });
        if path.exists() {
            remembered.push(path);
        }
    }

    for path in remembered {
        remember_node_path(&path)?;
    }
    nodes.sort_by(|left, right| {
        right
            .operational
            .cmp(&left.operational)
            .then_with(|| left.archived.cmp(&right.archived))
            .then_with(|| left.display_name.cmp(&right.display_name))
    });
    Ok(nodes)
}

fn dependency_support() -> (bool, String) {
    if cfg!(target_os = "windows") {
        (
            command_exists("winget.exe"),
            "Windows 10/11: WSL 2, Docker Desktop y Compose v2 mediante winget.".to_string(),
        )
    } else if cfg!(target_os = "linux") {
        let os_release = fs::read_to_string("/etc/os-release").unwrap_or_default();
        let supported = os_release
            .lines()
            .any(|line| line == "ID=debian" || line == "ID=ubuntu");
        (
            supported && command_exists("pkexec"),
            "Debian 13/Ubuntu: Docker Engine, Buildx y Compose v2 desde el repositorio APT oficial.".to_string(),
        )
    } else {
        (
            false,
            "La instalacion automatica de dependencias no esta disponible en esta plataforma."
                .to_string(),
        )
    }
}

#[tauri::command]
fn get_system_info(app: AppHandle) -> Result<SystemInfo, String> {
    let payload = payload_dir(&app)?;
    let (dependency_install_supported, dependency_message) = dependency_support();
    Ok(SystemInfo {
        platform: env::consts::OS.to_string(),
        architecture: env::consts::ARCH.to_string(),
        default_install_dir: default_install_dir().to_string_lossy().into_owned(),
        docker_cli: command_exists("docker"),
        docker_daemon: command_succeeds("docker", &["info"]),
        compose_v2: command_succeeds("docker", &["compose", "version"]),
        dependency_install_supported,
        dependency_message,
        payload_version: read_trimmed(&payload.join("VERSION"))
            .unwrap_or_else(|| "desconocida".to_string()),
        suggested_public_base_url: suggested_public_base_url(),
        managed_nodes_dir: managed_nodes_dir().to_string_lossy().into_owned(),
    })
}

#[tauri::command]
fn inspect_installation(request: InspectRequest) -> Result<InstallationState, String> {
    let path = validated_install_path(&request.install_dir)?;
    let state = inspect_path(&path);
    target_is_safe(&path, &state)?;
    Ok(state)
}

#[tauri::command]
async fn list_managed_nodes() -> Result<Vec<ManagedNode>, String> {
    tauri::async_runtime::spawn_blocking(discover_managed_nodes)
        .await
        .map_err(|error| format!("La deteccion local de nodos fallo: {error}"))?
}

#[tauri::command]
async fn suggest_installation_target(
    request: BootstrapRequest,
) -> Result<InstallationTarget, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bootstrap = validate_bootstrap_jws(&request.bootstrap_jws)?;
        let nodes = discover_managed_nodes()?;
        if let Some(node) = nodes
            .iter()
            .find(|node| node.deployment_id.as_deref() == Some(bootstrap.deployment_id.as_str()))
        {
            let path = validated_install_path(&node.install_dir)?;
            return Ok(InstallationTarget {
                install_dir: node.install_dir.clone(),
                matched_existing: true,
                installation: inspect_path(&path),
            });
        }

        let default = default_install_dir();
        let default_state = inspect_path(&default);
        let target = if default_state.installed {
            managed_nodes_dir().join(safe_archive_fragment(&bootstrap.deployment_code))
        } else {
            default
        };
        let state = inspect_path(&target);
        target_is_safe(&target, &state)?;
        Ok(InstallationTarget {
            install_dir: target.to_string_lossy().into_owned(),
            matched_existing: false,
            installation: state,
        })
    })
    .await
    .map_err(|error| format!("La seleccion del destino administrado fallo: {error}"))?
}

fn output_text(output: Output) -> Result<String, String> {
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    if combined.len() > 48_000 {
        combined = combined[combined.len() - 48_000..].to_string();
    }
    if output.status.success() {
        Ok(combined.trim().to_string())
    } else {
        Err(format!(
            "El proceso finalizo con codigo {}.\n{}",
            output
                .status
                .code()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "desconocido".to_string()),
            combined.trim()
        ))
    }
}

#[tauri::command]
async fn install_dependencies(app: AppHandle) -> Result<ActionResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let output = if cfg!(target_os = "windows") {
            let script = resource_file(&app, "install-dependencies-windows.ps1")?;
            Command::new("powershell.exe")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(script)
                .output()
                .map_err(|error| format!("No se pudo iniciar PowerShell: {error}"))?
        } else if cfg!(target_os = "linux") {
            if !command_exists("pkexec") {
                return Err("Falta pkexec/polkit. Instale policykit-1 o ejecute manualmente el script de dependencias como root.".to_string());
            }
            let script = resource_file(&app, "install-dependencies-debian.sh")?;
            let user = env::var("USER").unwrap_or_default();
            Command::new("pkexec")
                .arg("env")
                .arg(format!("ACTIUM_NODE_USER={user}"))
                .arg("/bin/sh")
                .arg(script)
                .output()
                .map_err(|error| format!("No se pudo solicitar elevacion con pkexec: {error}"))?
        } else {
            return Err("Plataforma no soportada para instalacion automatica de dependencias.".to_string());
        };
        let output = output_text(output)?;
        Ok(ActionResult {
            ok: true,
            message: "Dependencias instaladas. Actualice el diagnostico antes de desplegar el nodo.".to_string(),
            output,
            installed_profiles: Vec::new(),
        })
    })
    .await
    .map_err(|error| format!("La tarea de dependencias fallo: {error}"))?
}

fn validated_install_path(value: &str) -> Result<PathBuf, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Seleccione un directorio de instalacion.".to_string());
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() {
        return Err("El directorio de instalacion debe ser absoluto.".to_string());
    }
    if path.parent().is_none() {
        return Err("No se permite instalar en la raiz del sistema.".to_string());
    }
    Ok(path)
}

fn validate_request(
    request: &InstallRequest,
    existing: &InstallationState,
) -> Result<(Vec<String>, BootstrapClaims), String> {
    let bootstrap = validate_bootstrap_jws(&request.bootstrap_jws)?;
    if let Some(installed_deployment) = existing.deployment_id.as_ref() {
        if installed_deployment != &bootstrap.deployment_id {
            if existing.recoverable_incomplete_preparation {
                return Err(
                    "Existe una preparacion incompleta de otro despliegue. Archivela de forma segura antes de continuar."
                        .to_string(),
                );
            }
            return Err(
                "El paquete .adpe pertenece a otro despliegue y no puede ampliar este nodo."
                    .to_string(),
            );
        }
    }
    if request.profiles.is_empty() {
        return Err("Seleccione al menos un componente operativo.".to_string());
    }
    let mut profiles = BTreeSet::new();
    let existing_profiles = if existing.operational {
        existing.profiles.as_slice()
    } else {
        &[]
    };
    for profile in existing_profiles.iter().chain(request.profiles.iter()) {
        if !KNOWN_PROFILES.contains(&profile.as_str()) {
            return Err(format!("Perfil desconocido: {profile}."));
        }
        if !existing_profiles.contains(profile) && !bootstrap.profiles.contains(profile) {
            return Err(format!(
                "El perfil {profile} no fue autorizado por el paquete .adpe."
            ));
        }
        profiles.insert(profile.clone());
    }
    if profiles.contains("radio-turn") && request.turn_realm.trim().is_empty() {
        return Err("TURN requiere un realm o dominio publico.".to_string());
    }
    if profiles.contains("radio-livekit") {
        if request.livekit_node_ip.trim().is_empty() {
            return Err("LiveKit requiere la IP anunciada del nodo.".to_string());
        }
        if !request.livekit_public_url.trim().starts_with("wss://") {
            return Err("La URL publica de LiveKit debe usar wss://.".to_string());
        }
    }
    if profiles.contains("connectivity") {
        if !request
            .connectivity_edge_control_url
            .trim()
            .starts_with("https://")
        {
            return Err("Connectivity Edge requiere una URL de control https://.".to_string());
        }
        let already_installed = existing_profiles
            .iter()
            .any(|profile| profile == "connectivity");
        if !already_installed {
            let enrollment = request.connectivity_edge_enrollment_token.trim();
            let relay = request.connectivity_internal_relay_token.trim();
            if !enrollment.starts_with("acen_") || enrollment.len() < 45 {
                return Err("El token de enrolamiento Connectivity Edge no es valido.".to_string());
            }
            if !relay.starts_with("acer_") || relay.len() < 45 {
                return Err("El token de relay interno no es valido.".to_string());
            }
        }
        if request.connectivity_node_role != "primary"
            && request.connectivity_node_role != "replica"
        {
            return Err("El rol Connectivity debe ser primary o replica.".to_string());
        }
        if request.connectivity_node_priority > 1_000 {
            return Err("La prioridad Connectivity debe estar entre 0 y 1000.".to_string());
        }
        if !(1..=100).contains(&request.connectivity_pull_limit) {
            return Err("El limite de lectura Connectivity debe estar entre 1 y 100.".to_string());
        }
        validate_fallback_order(
            &request.connectivity_fallback_order,
            request.connectivity_direct_data_plane_fallback_enabled,
            request.connectivity_supabase_fallback_enabled,
        )?;
        if !profiles.contains("telemetry") {
            if !bootstrap
                .profiles
                .iter()
                .any(|profile| profile == "telemetry")
            {
                return Err(
                    "Connectivity Edge requiere que el paquete .adpe autorice tambien telemetry."
                        .to_string(),
                );
            }
            profiles.insert("telemetry".to_string());
        }
    }
    if request.turn_min_port > request.turn_max_port {
        return Err("El puerto TURN minimo no puede superar al maximo.".to_string());
    }
    if !request.public_base_url.starts_with("http://")
        && !request.public_base_url.starts_with("https://")
    {
        return Err("La URL accesible del nodo debe usar http:// o https://.".to_string());
    }
    if !is_host_code(&request.project_name) {
        return Err(
            "El nombre tecnico debe tener 3 a 80 caracteres: a-z, 0-9, punto, guion o guion bajo."
                .to_string(),
        );
    }
    let fixed_ports = [
        request.telemetry_port,
        request.radio_control_port,
        request.prometheus_port,
        request.grafana_port,
    ];
    if fixed_ports.iter().copied().collect::<BTreeSet<_>>().len() != fixed_ports.len() {
        return Err("Los puertos principales del nodo no pueden repetirse.".to_string());
    }
    for (label, value) in [
        ("nombre de proyecto", request.project_name.as_str()),
        ("direccion de escucha", request.bind_address.as_str()),
        ("URL accesible del nodo", request.public_base_url.as_str()),
        ("origenes CORS", request.cors_origins.as_str()),
        ("realm TURN", request.turn_realm.as_str()),
        ("IP TURN", request.turn_external_ip.as_str()),
        ("IP LiveKit", request.livekit_node_ip.as_str()),
        ("URL LiveKit", request.livekit_public_url.as_str()),
        (
            "URL Connectivity Edge",
            request.connectivity_edge_control_url.as_str(),
        ),
        ("rol Connectivity", request.connectivity_node_role.as_str()),
    ] {
        validate_env_value(label, value)?;
    }
    Ok((profiles.into_iter().collect(), bootstrap))
}

fn is_host_code(value: &str) -> bool {
    let value = value.trim();
    (3..=80).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn validate_env_value(label: &str, value: &str) -> Result<(), String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("{label} contiene saltos de linea no permitidos."));
    }
    Ok(())
}

fn validate_fallback_order(
    order: &[String],
    direct_data_plane_enabled: bool,
    supabase_enabled: bool,
) -> Result<(), String> {
    let expected = [
        (direct_data_plane_enabled, "direct_data_plane"),
        (supabase_enabled, "supabase"),
    ];
    let unique = order.iter().collect::<BTreeSet<_>>();
    if unique.len() != order.len()
        || order
            .iter()
            .any(|item| item != "direct_data_plane" && item != "supabase")
        || expected
            .iter()
            .any(|(enabled, name)| *enabled != order.iter().any(|item| item == name))
    {
        return Err(
            "El orden de fallback debe contener una vez cada transporte habilitado: direct_data_plane y/o supabase."
                .to_string(),
        );
    }
    Ok(())
}

fn validate_connectivity_policy(policy: &ConnectivityPolicy) -> Result<(), String> {
    if !policy.edge_control_url.starts_with("https://") {
        return Err("La politica Connectivity del .adpe requiere una URL https://.".to_string());
    }
    if policy.node_role != "primary" && policy.node_role != "replica" {
        return Err("La politica Connectivity del .adpe contiene un rol invalido.".to_string());
    }
    if policy.node_priority > 1_000 || !(1..=100).contains(&policy.pull_limit) {
        return Err("La politica Connectivity del .adpe contiene limites invalidos.".to_string());
    }
    validate_fallback_order(
        &policy.fallback_order,
        policy.direct_data_plane_fallback_enabled,
        policy.supabase_fallback_enabled,
    )
}

#[tauri::command]
fn validate_installation_request(request: InstallRequest) -> Result<ActionResult, String> {
    let install_dir = validated_install_path(&request.install_dir)?;
    let existing = inspect_path(&install_dir);
    target_is_safe(&install_dir, &existing)?;
    let (profiles, bootstrap) = validate_request(&request, &existing)?;
    Ok(ActionResult {
        ok: true,
        message: "Configuracion completa y validada por el instalador nativo.".to_string(),
        output: format!(
            "Despliegue {} · generacion {} · {} perfiles autorizados",
            bootstrap.deployment_code,
            bootstrap.generation,
            profiles.len()
        ),
        installed_profiles: profiles,
    })
}

fn is_enrollment_token(value: &str) -> bool {
    let value = value.trim();
    value.len() == 69
        && value.starts_with("adpe_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_public_key(value: &str, label: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if !trimmed.contains("-----BEGIN PUBLIC KEY-----")
        || !trimmed.contains("-----END PUBLIC KEY-----")
    {
        return Err(format!(
            "La clave publica de {label} no es un PEM PUBLIC KEY valido."
        ));
    }
    Ok(())
}

fn audience_contains(value: &serde_json::Value, expected: &str) -> bool {
    match value {
        serde_json::Value::String(candidate) => candidate == expected,
        serde_json::Value::Array(candidates) => candidates
            .iter()
            .any(|candidate| candidate.as_str() == Some(expected)),
        _ => false,
    }
}

fn validate_installer_min_version(minimum: &str, current: &str) -> Result<(), String> {
    let minimum = Version::parse(minimum.trim()).map_err(|_| {
        "El paquete .adpe declara una version minima de instalador invalida.".to_string()
    })?;
    let current = Version::parse(current.trim())
        .map_err(|_| format!("La version local del instalador ({current}) no es SemVer valida."))?;

    if current < minimum {
        return Err(format!(
            "El paquete .adpe requiere Actium Telemetry Node Installer {minimum} o posterior; la version instalada es {current}."
        ));
    }

    Ok(())
}

fn validate_bootstrap_jws(value: &str) -> Result<BootstrapClaims, String> {
    let compact = value.trim();
    if compact.is_empty() || compact.split('.').count() != 3 {
        return Err("Seleccione un paquete .adpe firmado por Actium Center.".to_string());
    }
    let header = decode_header(compact)
        .map_err(|_| "El paquete .adpe no contiene un encabezado JWS valido.".to_string())?;
    if header.alg != Algorithm::EdDSA
        || header.kid.as_deref() != Some(TRUSTED_BOOTSTRAP_KEY_REF)
        || header.typ.as_deref() != Some("actium-bootstrap+jwt")
    {
        return Err("El paquete .adpe no pertenece a una autoridad Actium confiable.".to_string());
    }
    let key = DecodingKey::from_ed_pem(TRUSTED_BOOTSTRAP_PUBLIC_KEY.as_bytes())
        .map_err(|error| format!("No se pudo cargar la autoridad publica embebida: {error}"))?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[TRUSTED_BOOTSTRAP_ISSUER]);
    validation.set_audience(&[TRUSTED_BOOTSTRAP_AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "jti"]);
    validation.leeway = 15;
    let claims = decode::<BootstrapClaims>(compact, &key, &validation)
        .map_err(|error| format!("Firma o vigencia del paquete .adpe invalida: {error}"))?
        .claims;
    if claims.schema_version != 1
        || claims.package_type != "actium-data-plane-enrollment"
        || claims.signing_key_ref != TRUSTED_BOOTSTRAP_KEY_REF
        || claims.iss != TRUSTED_BOOTSTRAP_ISSUER
        || !audience_contains(&claims.aud, TRUSTED_BOOTSTRAP_AUDIENCE)
        || claims.sub != format!("deployment:{}", claims.deployment_id)
        || claims.jti != claims.enrollment_id
        || claims.product_id.trim().is_empty()
        || (claims.client_id.is_none() && claims.organization_id.is_none())
        || claims.region.as_deref().is_some_and(str::is_empty)
    {
        return Err(format!(
            "El contrato soberano del paquete .adpe no coincide con Actium Telemetry Node Installer {INSTALLER_VERSION}."
        ));
    }
    validate_installer_min_version(&claims.installer_min_version, INSTALLER_VERSION)?;
    if !is_enrollment_token(&claims.enrollment_token) {
        return Err("El paquete .adpe no contiene un enrolamiento one-shot valido.".to_string());
    }
    if !matches!(claims.deployment_mode.as_str(), "edge" | "hybrid") {
        return Err("El paquete .adpe no corresponde a un despliegue local o hibrido.".to_string());
    }
    if claims.orchestrator != "docker_compose" {
        return Err("La prueba de Windows requiere un despliegue Docker Compose.".to_string());
    }
    if !claims.control_endpoint.starts_with("https://")
        || !claims.terminal_issuer.starts_with("https://")
        || !claims.operator_issuer.starts_with("https://")
    {
        return Err("El paquete .adpe contiene endpoints de autoridad inseguros.".to_string());
    }
    validate_public_key(&claims.terminal_public_key_pem, "terminal")?;
    validate_public_key(&claims.operator_public_key_pem, "operador")?;
    if claims.terminal_public_key_pem.trim() != TRUSTED_BOOTSTRAP_PUBLIC_KEY.trim()
        || claims.operator_public_key_pem.trim() != TRUSTED_BOOTSTRAP_PUBLIC_KEY.trim()
    {
        return Err(
            "Las claves publicas del paquete no coinciden con la autoridad Actium confiable."
                .to_string(),
        );
    }
    if claims.profiles.is_empty()
        || claims
            .profiles
            .iter()
            .any(|profile| !KNOWN_PROFILES.contains(&profile.as_str()))
    {
        return Err("El paquete .adpe no autoriza perfiles operativos validos.".to_string());
    }
    if let Some(policy) = claims.connectivity_policy.as_ref() {
        if !claims
            .profiles
            .iter()
            .any(|profile| profile == "connectivity")
        {
            return Err(
                "El paquete .adpe contiene una politica Connectivity sin autorizar ese perfil."
                    .to_string(),
            );
        }
        validate_connectivity_policy(policy)?;
    }
    Ok(claims)
}

#[tauri::command]
fn validate_bootstrap(request: BootstrapRequest) -> Result<BootstrapValidationResult, String> {
    let claims = validate_bootstrap_jws(&request.bootstrap_jws)?;
    Ok(BootstrapValidationResult {
        valid: true,
        deployment_id: claims.deployment_id,
        deployment_code: claims.deployment_code,
        deployment_name: claims.deployment_name,
        organization_id: claims.organization_id,
        generation: claims.generation,
        checksum: claims.checksum,
        expires_at_unix_seconds: claims.exp,
        profiles: claims.profiles,
        control_endpoint: claims.control_endpoint,
        signing_key_ref: claims.signing_key_ref,
        installer_min_version: claims.installer_min_version,
        connectivity_policy: claims.connectivity_policy,
    })
}

fn copy_payload(source: &Path, target: &Path) -> Result<(), String> {
    const PRESERVED: [&str; 5] = ["secrets", "keys", "node.env", MARKER_FILE, "dist"];
    fs::create_dir_all(target)
        .map_err(|error| format!("No se pudo crear {}: {error}", target.display()))?;
    for entry in
        fs::read_dir(source).map_err(|error| format!("No se pudo leer el payload: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Entrada de payload invalida: {error}"))?;
        let name = entry.file_name();
        let name_text = name.to_string_lossy();
        if PRESERVED.contains(&name_text.as_ref()) {
            continue;
        }
        let destination = target.join(&name);
        if entry.path().is_dir() {
            copy_payload(&entry.path(), &destination)?;
        } else {
            fs::copy(entry.path(), &destination)
                .map_err(|error| format!("No se pudo copiar {}: {error}", destination.display()))?;
        }
    }
    Ok(())
}

fn write_secure(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear {}: {error}", parent.display()))?;
    }
    fs::write(path, contents)
        .map_err(|error| format!("No se pudo escribir {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
            format!(
                "No se pudieron restringir permisos de {}: {error}",
                path.display()
            )
        })?;
    }
    Ok(())
}

fn write_node_env(
    path: &Path,
    request: &InstallRequest,
    bootstrap: &BootstrapClaims,
    profiles: &[String],
    installation_id: &str,
) -> Result<(), String> {
    let contents = format!(
        "# Generado por Actium Telemetry Node Installer. No almacenar secretos aqui.\n\
ACTIUM_CONTROL_ENDPOINT={}\n\
ACTIUM_ENROLLMENT_TOKEN=\n\
ACTIUM_HOST_INSTALLATION_ID={}\n\
ACTIUM_HOST_CODE={}\n\
ACTIUM_HOST_DISPLAY_NAME={}\n\
ACTIUM_HOST_PLATFORM={}\n\
ACTIUM_HOST_ARCHITECTURE={}\n\
ACTIUM_INSTALLER_VERSION={}\n\
ACTIUM_DEPLOYMENT_ID={}\n\
ACTIUM_DEPLOYMENT_CODE={}\n\
ACTIUM_TERMINAL_PUBLIC_KEY_PATH=./keys/actium-terminal-public.pem\n\
ACTIUM_OPERATOR_PUBLIC_KEY_PATH=./keys/actium-operator-public.pem\n\
ACTIUM_TERMINAL_ISSUER={}\n\
ACTIUM_OPERATOR_ISSUER={}\n\
ACTIUM_PROFILES={}\n\
ACTIUM_PROJECT_NAME={}\n\
ACTIUM_DATA_PLANE_PROJECT={}\n\
ACTIUM_USE_PUBLISHED_IMAGES={}\n\
DATA_PLANE_BIND_ADDRESS={}\n\
DATA_PLANE_PUBLIC_BASE_URL={}\n\
DATA_PLANE_CORS_ORIGINS={}\n\
TELEMETRY_PORT={}\n\
RADIO_CONTROL_PORT={}\n\
PROMETHEUS_PORT={}\n\
GRAFANA_PORT={}\n\
TURN_REALM={}\n\
TURN_EXTERNAL_IP={}\n\
TURN_MIN_PORT={}\n\
TURN_MAX_PORT={}\n\
LIVEKIT_NODE_IP={}\n\
LIVEKIT_PUBLIC_URL={}\n\
CONNECTIVITY_EDGE_CONTROL_URL={}\n\
CONNECTIVITY_NODE_ROLE={}\n\
CONNECTIVITY_NODE_PRIORITY={}\n\
CONNECTIVITY_PULL_LIMIT={}\n\
CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED={}\n\
CONNECTIVITY_SUPABASE_FALLBACK_ENABLED={}\n\
CONNECTIVITY_FALLBACK_ORDER={}\n",
        bootstrap.control_endpoint.trim_end_matches('/'),
        installation_id,
        request.project_name.trim(),
        request.project_name.trim(),
        env::consts::OS,
        match env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            value => value,
        },
        INSTALLER_VERSION,
        bootstrap.deployment_id,
        bootstrap.deployment_code,
        bootstrap.terminal_issuer.trim(),
        bootstrap.operator_issuer.trim(),
        profiles.join(","),
        request.project_name.trim(),
        request.project_name.trim(),
        request.use_published_images,
        request.bind_address.trim(),
        request.public_base_url.trim_end_matches('/'),
        request.cors_origins.trim(),
        request.telemetry_port,
        request.radio_control_port,
        request.prometheus_port,
        request.grafana_port,
        request.turn_realm.trim(),
        request.turn_external_ip.trim(),
        request.turn_min_port,
        request.turn_max_port,
        request.livekit_node_ip.trim(),
        request.livekit_public_url.trim(),
        request.connectivity_edge_control_url.trim_end_matches('/'),
        request.connectivity_node_role.trim(),
        request.connectivity_node_priority,
        request.connectivity_pull_limit,
        request.connectivity_direct_data_plane_fallback_enabled,
        request.connectivity_supabase_fallback_enabled,
        request.connectivity_fallback_order.join(","),
    );
    fs::write(path, contents).map_err(|error| format!("No se pudo escribir node.env: {error}"))
}

fn now_marker_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn write_marker(
    path: &Path,
    version: &str,
    profiles: &[String],
    status: &str,
    bootstrap: &BootstrapClaims,
    installation_id: &str,
    last_error: Option<&str>,
) -> Result<(), String> {
    let marker = InstallationMarker {
        schema: 2,
        version: version.to_string(),
        profiles: profiles.to_vec(),
        status: status.to_string(),
        updated_at_unix_seconds: now_marker_timestamp(),
        deployment_id: Some(bootstrap.deployment_id.clone()),
        deployment_code: Some(bootstrap.deployment_code.clone()),
        installation_id: Some(installation_id.to_string()),
        last_error: last_error.map(str::to_string),
    };
    let contents = serde_json::to_string_pretty(&marker)
        .map_err(|error| format!("No se pudo serializar el estado: {error}"))?;
    fs::write(path.join(MARKER_FILE), format!("{contents}\n"))
        .map_err(|error| format!("No se pudo guardar el estado administrado: {error}"))
}

fn update_existing_marker(
    path: &Path,
    status: Option<&str>,
    version: Option<&str>,
) -> Result<(), String> {
    let marker_path = path.join(MARKER_FILE);
    let contents = fs::read_to_string(&marker_path)
        .map_err(|error| format!("No se pudo leer el estado administrado: {error}"))?;
    let mut marker = serde_json::from_str::<InstallationMarker>(&contents)
        .map_err(|error| format!("El estado administrado local no es valido: {error}"))?;
    if let Some(value) = status {
        marker.status = value.to_string();
    }
    if let Some(value) = version {
        marker.version = value.to_string();
    }
    marker.profiles = inspect_path(path).profiles;
    marker.updated_at_unix_seconds = now_marker_timestamp();
    marker.last_error = None;
    let serialized = serde_json::to_string_pretty(&marker)
        .map_err(|error| format!("No se pudo serializar el estado administrado: {error}"))?;
    fs::write(marker_path, format!("{serialized}\n"))
        .map_err(|error| format!("No se pudo actualizar el estado administrado: {error}"))
}

fn target_is_safe(path: &Path, existing: &InstallationState) -> Result<(), String> {
    let recognized_cli_installation = existing.installed
        && path.join("compose.yml").is_file()
        && (path.join("bootstrap.ps1").is_file() || path.join("bootstrap.sh").is_file());
    if !path.exists() || existing.managed || recognized_cli_installation {
        return Ok(());
    }
    let is_empty = fs::read_dir(path)
        .map_err(|error| format!("No se pudo inspeccionar {}: {error}", path.display()))?
        .next()
        .is_none();
    if is_empty {
        return Ok(());
    }
    Err("El directorio contiene archivos y no pertenece a una instalacion administrada por Actium. Seleccione otro destino.".to_string())
}

fn safe_archive_fragment(value: &str) -> String {
    let fragment = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let trimmed = fragment.trim_matches('-');
    if trimmed.is_empty() {
        "despliegue-desconocido".to_string()
    } else {
        trimmed.chars().take(80).collect()
    }
}

fn project_container_ids(existing: &InstallationState) -> Result<Vec<String>, String> {
    let project_name = existing
        .config
        .get("ACTIUM_DATA_PLANE_PROJECT")
        .or_else(|| existing.config.get("ACTIUM_PROJECT_NAME"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "La preparacion incompleta no conserva el nombre de proyecto Docker; no puede archivarse automaticamente."
                .to_string()
        })?;
    let project_filter = format!("label=com.docker.compose.project={project_name}");
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            project_filter.as_str(),
            "--format",
            "{{.ID}}",
        ])
        .output()
        .map_err(|error| {
            format!(
                "No se pudo consultar Docker antes de archivar la preparacion incompleta: {error}"
            )
        })?;
    if !output.status.success() {
        let details = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Docker no pudo confirmar que la preparacion incompleta no tenga contenedores: {}",
            details.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect())
}

#[tauri::command]
async fn archive_incomplete_preparation(request: RecoveryRequest) -> Result<ActionResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let install_dir = validated_install_path(&request.install_dir)?;
        let target_bootstrap = validate_bootstrap_jws(&request.bootstrap_jws)?;
        let existing = inspect_path(&install_dir);
        if !existing.recoverable_incomplete_preparation {
            return Err(
                "El directorio no contiene una preparacion incompleta recuperable.".to_string(),
            );
        }
        let existing_deployment = existing.deployment_id.as_deref().ok_or_else(|| {
            "La preparacion incompleta no conserva el identificador del despliegue.".to_string()
        })?;
        if existing_deployment == target_bootstrap.deployment_id {
            return Err(
                "El paquete pertenece al mismo despliegue; vuelva a ejecutar la instalacion para reintentarlo sin archivar."
                    .to_string(),
            );
        }
        let containers = project_container_ids(&existing)?;
        if !containers.is_empty() {
            return Err(format!(
                "La preparacion incompleta conserva {} contenedor(es) Docker. Detengalos y eliminelos de forma controlada antes de reemplazar el despliegue.",
                containers.len()
            ));
        }

        let recovery_root = recovery_root_dir();
        fs::create_dir_all(&recovery_root).map_err(|error| {
            format!(
                "No se pudo crear el directorio de recuperacion {}: {error}",
                recovery_root.display()
            )
        })?;
        let original_name = install_dir
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("TelemetryNode");
        let source_code = existing
            .deployment_code
            .as_deref()
            .unwrap_or(existing_deployment);
        let archive_name = format!(
            "{}-{}-{}",
            safe_archive_fragment(original_name),
            now_marker_timestamp(),
            safe_archive_fragment(source_code)
        );
        let archive_path = recovery_root.join(archive_name);
        fs::rename(&install_dir, &archive_path).map_err(|error| {
            format!(
                "No se pudo archivar la preparacion incompleta en {}: {error}",
                archive_path.display()
            )
        })?;
        if let Err(error) = fs::create_dir_all(&install_dir) {
            let _ = fs::rename(&archive_path, &install_dir);
            return Err(format!(
                "No se pudo preparar un directorio limpio luego del archivo; se intento restaurar la preparacion anterior: {error}"
            ));
        }
        remember_node_path(&archive_path)?;

        Ok(ActionResult {
            ok: true,
            message:
                "Preparacion incompleta archivada. El nuevo despliegue puede instalarse sin perder la evidencia anterior."
                    .to_string(),
            output: archive_path.to_string_lossy().into_owned(),
            installed_profiles: Vec::new(),
        })
    })
    .await
    .map_err(|error| format!("La recuperacion de la preparacion fallo: {error}"))?
}

fn run_installer(path: &Path, token: &str, prepare_only: bool) -> Result<String, String> {
    let mut command = if cfg!(target_os = "windows") {
        let mut value = Command::new("powershell.exe");
        value
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(path.join("install-node.ps1"))
            .arg("-ConfigFile")
            .arg(path.join("node.env"));
        if prepare_only {
            value.arg("-PrepareOnly");
        }
        value
    } else {
        let mut value = Command::new("/bin/sh");
        value
            .arg(path.join("install-node.sh"))
            .arg("--config")
            .arg(path.join("node.env"));
        if prepare_only {
            value.arg("--prepare-only");
        }
        value
    };
    command.current_dir(path);
    if !token.trim().is_empty() {
        command.env("ACTIUM_ENROLLMENT_TOKEN_OVERRIDE", token.trim());
    }
    let output = command
        .output()
        .map_err(|error| format!("No se pudo ejecutar el instalador del nodo: {error}"))?;
    output_text(output)
}

#[tauri::command]
async fn apply_installation(
    app: AppHandle,
    request: InstallRequest,
) -> Result<ActionResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let install_dir = validated_install_path(&request.install_dir)?;
        let existing = inspect_path(&install_dir);
        target_is_safe(&install_dir, &existing)?;
        let (profiles, bootstrap) = validate_request(&request, &existing)?;
        let payload = payload_dir(&app)?;
        let version = read_trimmed(&payload.join("VERSION")).unwrap_or_else(|| "desconocida".to_string());

        copy_payload(&payload, &install_dir)?;
        fs::create_dir_all(install_dir.join("keys")).map_err(|error| format!("No se pudo crear keys: {error}"))?;
        fs::create_dir_all(install_dir.join("secrets"))
            .map_err(|error| format!("No se pudo crear secrets: {error}"))?;
        write_secure(
            &install_dir.join("keys/actium-terminal-public.pem"),
            &format!("{}\n", bootstrap.terminal_public_key_pem.trim()),
        )?;
        write_secure(
            &install_dir.join("keys/actium-operator-public.pem"),
            &format!("{}\n", bootstrap.operator_public_key_pem.trim()),
        )?;
        for key in ["keys/actium-terminal-public.pem", "keys/actium-operator-public.pem"] {
            if !install_dir.join(key).is_file() {
                return Err(format!("Falta {key}; cargue las autoridades publicas antes de instalar."));
            }
        }
        if profiles.iter().any(|profile| profile == "connectivity") {
            let enrollment_path = install_dir.join("secrets/connectivity_edge_enrollment_token");
            let relay_path = install_dir.join("secrets/connectivity_internal_relay_token");
            if !request.connectivity_edge_enrollment_token.trim().is_empty() {
                write_secure(
                    &enrollment_path,
                    &format!("{}\n", request.connectivity_edge_enrollment_token.trim()),
                )?;
            }
            if !request.connectivity_internal_relay_token.trim().is_empty() {
                write_secure(
                    &relay_path,
                    &format!("{}\n", request.connectivity_internal_relay_token.trim()),
                )?;
            }
            if !enrollment_path.is_file() || !relay_path.is_file() {
                return Err(
                    "Faltan secretos locales de Connectivity Edge; vuelva a importar el paquete y configure el enrolamiento."
                        .to_string(),
                );
            }
        }

        let installation_id = existing
            .installation_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        write_node_env(&install_dir.join("node.env"), &request, &bootstrap, &profiles, &installation_id)?;
        write_marker(
            &install_dir,
            &version,
            &profiles,
            "installing",
            &bootstrap,
            &installation_id,
            None,
        )?;
        remember_node_path(&install_dir)?;
        match run_installer(&install_dir, &bootstrap.enrollment_token, request.prepare_only) {
            Ok(output) => {
                write_marker(
                    &install_dir,
                    &version,
                    &profiles,
                    if request.prepare_only { "prepared" } else { "running" },
                    &bootstrap,
                    &installation_id,
                    None,
                )?;
                Ok(ActionResult {
                    ok: true,
                    message: if existing.operational {
                        "Nodo actualizado y componentes ampliados sin reemplazar secretos ni volumenes.".to_string()
                    } else {
                        "Nodo instalado y enrolado bajo autoridad Actium.".to_string()
                    },
                    output,
                    installed_profiles: profiles,
                })
            }
            Err(error) => {
                let _ = write_marker(
                    &install_dir,
                    &version,
                    &profiles,
                    "failed",
                    &bootstrap,
                    &installation_id,
                    Some(&error),
                );
                Err(error)
            }
        }
    })
    .await
    .map_err(|error| format!("La tarea de instalacion fallo: {error}"))?
}

fn run_node_action(path: &Path, action: &str) -> Result<String, String> {
    if action == "verify" {
        let output = if cfg!(target_os = "windows") {
            Command::new("powershell.exe")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(path.join("verify-node.ps1"))
                .arg("-EnvironmentFile")
                .arg(path.join("secrets/data-plane.env"))
                .current_dir(path)
                .output()
        } else {
            Command::new("/bin/sh")
                .arg(path.join("verify-node.sh"))
                .current_dir(path)
                .output()
        }
        .map_err(|error| format!("No se pudo verificar el nodo: {error}"))?;
        return output_text(output);
    }

    let output = if cfg!(target_os = "windows") {
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(path.join("manage-node.ps1"))
            .arg(action)
            .arg("-EnvironmentFile")
            .arg(path.join("secrets/data-plane.env"));
        if action == "logs" {
            command.arg("-NoFollow");
        }
        command.current_dir(path).output()
    } else {
        let mut command = Command::new("/bin/sh");
        command
            .arg(path.join("manage-node.sh"))
            .arg(action)
            .current_dir(path);
        if action == "logs" {
            command.env("ACTIUM_LOGS_FOLLOW", "false");
        }
        command.output()
    }
    .map_err(|error| format!("No se pudo administrar el nodo: {error}"))?;
    output_text(output)
}

#[tauri::command]
async fn node_operation(
    app: AppHandle,
    request: NodeActionRequest,
) -> Result<ActionResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if ![
            "status", "start", "stop", "restart", "update", "verify", "logs",
        ]
        .contains(&request.action.as_str())
        {
            return Err("Operacion de nodo no permitida.".to_string());
        }
        let path = validated_install_path(&request.install_dir)?;
        let state = inspect_path(&path);
        if !state.operational {
            return Err(
                "No existe un nodo operativo administrado en ese directorio. Una preparacion fallida debe reintentarse o archivarse desde Autoridad Actium."
                    .to_string(),
                );
        }
        let payload_version = if request.action == "update" {
            let payload = payload_dir(&app)?;
            copy_payload(&payload, &path)?;
            read_trimmed(&payload.join("VERSION"))
        } else {
            None
        };
        let output = run_node_action(&path, &request.action)?;
        let next_status = match request.action.as_str() {
            "stop" => Some("stopped"),
            "start" | "restart" | "update" => Some("running"),
            _ => None,
        };
        if next_status.is_some() || payload_version.is_some() {
            update_existing_marker(&path, next_status, payload_version.as_deref())?;
        }
        remember_node_path(&path)?;
        let refreshed = inspect_path(&path);
        Ok(ActionResult {
            ok: true,
            message: format!("Operacion {} completada.", request.action),
            output,
            installed_profiles: refreshed.profiles,
        })
    })
    .await
    .map_err(|error| format!("La operacion del nodo fallo: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::{
        is_operational_installation, is_recoverable_preparation_status,
        validate_connectivity_policy, validate_installer_min_version, ConnectivityPolicy,
    };

    #[test]
    fn acepta_un_minimo_anterior() {
        assert!(validate_installer_min_version("0.3.0", "0.4.0").is_ok());
    }

    #[test]
    fn acepta_el_mismo_minimo() {
        assert!(validate_installer_min_version("0.4.0", "0.4.0").is_ok());
    }

    #[test]
    fn rechaza_un_instalador_anterior_al_minimo() {
        let error = validate_installer_min_version("0.4.0", "0.3.0")
            .expect_err("un instalador anterior no debe aceptar el paquete");
        assert!(error.contains("0.4.0 o posterior"));
    }

    #[test]
    fn rechaza_un_minimo_que_no_es_semver() {
        let error = validate_installer_min_version("version-futura", "0.2.3")
            .expect_err("un minimo invalido no debe aceptarse");
        assert!(error.contains("version minima"));
    }

    #[test]
    fn acepta_politica_connectivity_firmable() {
        let policy = ConnectivityPolicy {
            edge_control_url: "https://connectivity.example.com".to_string(),
            node_role: "replica".to_string(),
            node_priority: 100,
            pull_limit: 25,
            direct_data_plane_fallback_enabled: true,
            supabase_fallback_enabled: true,
            fallback_order: vec!["supabase".to_string(), "direct_data_plane".to_string()],
        };
        assert!(validate_connectivity_policy(&policy).is_ok());
    }

    #[test]
    fn rechaza_politica_connectivity_con_orden_inconsistente() {
        let policy = ConnectivityPolicy {
            edge_control_url: "https://connectivity.example.com".to_string(),
            node_role: "replica".to_string(),
            node_priority: 100,
            pull_limit: 25,
            direct_data_plane_fallback_enabled: true,
            supabase_fallback_enabled: false,
            fallback_order: vec!["supabase".to_string()],
        };
        assert!(validate_connectivity_policy(&policy).is_err());
    }

    #[test]
    fn preparaciones_no_operativas_se_pueden_recuperar() {
        for status in ["failed", "installing", "prepared"] {
            assert!(is_recoverable_preparation_status(Some(status)));
            assert!(!is_operational_installation(true, Some(status)));
        }
    }

    #[test]
    fn solo_running_o_una_instalacion_legacy_son_operativos() {
        assert!(is_operational_installation(true, Some("running")));
        assert!(is_operational_installation(true, Some("stopped")));
        assert!(is_operational_installation(true, None));
        assert!(!is_operational_installation(false, Some("running")));
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            inspect_installation,
            list_managed_nodes,
            suggest_installation_target,
            validate_bootstrap,
            validate_installation_request,
            install_dependencies,
            archive_incomplete_preparation,
            apply_installation,
            node_operation
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar Actium Telemetry Node Installer");
}
