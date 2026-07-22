use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tauri::{path::BaseDirectory, AppHandle, Manager};

const MARKER_FILE: &str = ".actium-node-installation.json";
const KNOWN_PROFILES: [&str; 6] = [
    "telemetry",
    "radio-control",
    "radio-saf",
    "radio-turn",
    "radio-livekit",
    "observability",
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
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallationState {
    installed: bool,
    managed: bool,
    version: Option<String>,
    profiles: Vec<String>,
    config: BTreeMap<String, String>,
    marker_path: String,
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
    control_endpoint: String,
    enrollment_token: String,
    terminal_issuer: String,
    operator_issuer: String,
    terminal_public_key_pem: String,
    operator_public_key_pem: String,
    profiles: Vec<String>,
    project_name: String,
    bind_address: String,
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
    use_published_images: bool,
    prepare_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeActionRequest {
    install_dir: String,
    action: String,
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

fn default_install_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        base.join("Actium").join("TelemetryNode")
    } else {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
            .unwrap_or_else(env::temp_dir);
        base.join("actium").join("telemetry-node")
    }
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
    let profiles = marker
        .as_ref()
        .map(|value| value.profiles.clone())
        .or_else(|| {
            config
                .get("ACTIUM_PROFILES")
                .map(|value| split_profiles(value))
        })
        .or_else(|| {
            config
                .get("ACTIUM_ACTIVE_PROFILES")
                .map(|value| split_profiles(value))
        })
        .unwrap_or_default();
    InstallationState {
        installed: marker.is_some() || path.join("secrets/data-plane.env").is_file(),
        managed: marker.is_some(),
        version: marker
            .as_ref()
            .map(|value| value.version.clone())
            .or_else(|| read_trimmed(&path.join("VERSION"))),
        profiles,
        config,
        marker_path: marker_path.to_string_lossy().into_owned(),
    }
}

fn split_profiles(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
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
    })
}

#[tauri::command]
fn inspect_installation(request: InspectRequest) -> Result<InstallationState, String> {
    let path = validated_install_path(&request.install_dir)?;
    Ok(inspect_path(&path))
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
) -> Result<Vec<String>, String> {
    for (label, value) in [
        ("endpoint de Actium", request.control_endpoint.as_str()),
        ("issuer terminal", request.terminal_issuer.as_str()),
        ("issuer operador", request.operator_issuer.as_str()),
    ] {
        if !value.trim().starts_with("https://") {
            return Err(format!("El {label} debe usar HTTPS."));
        }
    }
    if !existing.installed && !is_enrollment_token(&request.enrollment_token) {
        return Err(
            "La primera instalacion requiere un token one-shot adpe_... valido.".to_string(),
        );
    }
    if !request.enrollment_token.trim().is_empty()
        && !is_enrollment_token(&request.enrollment_token)
    {
        return Err("El token de enrolamiento no tiene el formato adpe_... esperado.".to_string());
    }
    if !existing.installed {
        validate_public_key(&request.terminal_public_key_pem, "terminal")?;
        validate_public_key(&request.operator_public_key_pem, "operador")?;
    } else {
        if !request.terminal_public_key_pem.trim().is_empty() {
            validate_public_key(&request.terminal_public_key_pem, "terminal")?;
        }
        if !request.operator_public_key_pem.trim().is_empty() {
            validate_public_key(&request.operator_public_key_pem, "operador")?;
        }
    }
    if request.profiles.is_empty() {
        return Err("Seleccione al menos un componente operativo.".to_string());
    }
    let mut profiles = BTreeSet::new();
    for profile in existing.profiles.iter().chain(request.profiles.iter()) {
        if !KNOWN_PROFILES.contains(&profile.as_str()) {
            return Err(format!("Perfil desconocido: {profile}."));
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
    if request.turn_min_port > request.turn_max_port {
        return Err("El puerto TURN minimo no puede superar al maximo.".to_string());
    }
    for (label, value) in [
        ("nombre de proyecto", request.project_name.as_str()),
        ("direccion de escucha", request.bind_address.as_str()),
        ("origenes CORS", request.cors_origins.as_str()),
        ("realm TURN", request.turn_realm.as_str()),
        ("IP TURN", request.turn_external_ip.as_str()),
        ("IP LiveKit", request.livekit_node_ip.as_str()),
        ("URL LiveKit", request.livekit_public_url.as_str()),
    ] {
        validate_env_value(label, value)?;
    }
    Ok(profiles.into_iter().collect())
}

fn validate_env_value(label: &str, value: &str) -> Result<(), String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("{label} contiene saltos de linea no permitidos."));
    }
    Ok(())
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
    profiles: &[String],
) -> Result<(), String> {
    let contents = format!(
        "# Generado por Actium Telemetry Node Installer. No almacenar secretos aqui.\n\
ACTIUM_CONTROL_ENDPOINT={}\n\
ACTIUM_ENROLLMENT_TOKEN=\n\
ACTIUM_TERMINAL_PUBLIC_KEY_PATH=./keys/actium-terminal-public.pem\n\
ACTIUM_OPERATOR_PUBLIC_KEY_PATH=./keys/actium-operator-public.pem\n\
ACTIUM_TERMINAL_ISSUER={}\n\
ACTIUM_OPERATOR_ISSUER={}\n\
ACTIUM_PROFILES={}\n\
ACTIUM_PROJECT_NAME={}\n\
ACTIUM_USE_PUBLISHED_IMAGES={}\n\
DATA_PLANE_BIND_ADDRESS={}\n\
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
LIVEKIT_PUBLIC_URL={}\n",
        request.control_endpoint.trim_end_matches('/'),
        request.terminal_issuer.trim(),
        request.operator_issuer.trim(),
        profiles.join(","),
        request.project_name.trim(),
        request.use_published_images,
        request.bind_address.trim(),
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
) -> Result<(), String> {
    let marker = InstallationMarker {
        schema: 1,
        version: version.to_string(),
        profiles: profiles.to_vec(),
        status: status.to_string(),
        updated_at_unix_seconds: now_marker_timestamp(),
    };
    let contents = serde_json::to_string_pretty(&marker)
        .map_err(|error| format!("No se pudo serializar el estado: {error}"))?;
    fs::write(path.join(MARKER_FILE), format!("{contents}\n"))
        .map_err(|error| format!("No se pudo guardar el estado administrado: {error}"))
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
        let profiles = validate_request(&request, &existing)?;
        let payload = payload_dir(&app)?;
        let version = read_trimmed(&payload.join("VERSION")).unwrap_or_else(|| "desconocida".to_string());

        copy_payload(&payload, &install_dir)?;
        fs::create_dir_all(install_dir.join("keys")).map_err(|error| format!("No se pudo crear keys: {error}"))?;
        if !request.terminal_public_key_pem.trim().is_empty() {
            write_secure(
                &install_dir.join("keys/actium-terminal-public.pem"),
                &format!("{}\n", request.terminal_public_key_pem.trim()),
            )?;
        }
        if !request.operator_public_key_pem.trim().is_empty() {
            write_secure(
                &install_dir.join("keys/actium-operator-public.pem"),
                &format!("{}\n", request.operator_public_key_pem.trim()),
            )?;
        }
        for key in ["keys/actium-terminal-public.pem", "keys/actium-operator-public.pem"] {
            if !install_dir.join(key).is_file() {
                return Err(format!("Falta {key}; cargue las autoridades publicas antes de instalar."));
            }
        }

        write_node_env(&install_dir.join("node.env"), &request, &profiles)?;
        write_marker(&install_dir, &version, &profiles, "installing")?;
        match run_installer(&install_dir, &request.enrollment_token, request.prepare_only) {
            Ok(output) => {
                write_marker(
                    &install_dir,
                    &version,
                    &profiles,
                    if request.prepare_only { "prepared" } else { "running" },
                )?;
                Ok(ActionResult {
                    ok: true,
                    message: if existing.installed {
                        "Nodo actualizado y componentes ampliados sin reemplazar secretos ni volumenes.".to_string()
                    } else {
                        "Nodo instalado y enrolado bajo autoridad Actium.".to_string()
                    },
                    output,
                    installed_profiles: profiles,
                })
            }
            Err(error) => {
                let _ = write_marker(&install_dir, &version, &profiles, "failed");
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
            .arg(action);
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
async fn node_operation(request: NodeActionRequest) -> Result<ActionResult, String> {
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
        if !state.installed {
            return Err("No existe un nodo administrado en ese directorio.".to_string());
        }
        let output = run_node_action(&path, &request.action)?;
        Ok(ActionResult {
            ok: true,
            message: format!("Operacion {} completada.", request.action),
            output,
            installed_profiles: state.profiles,
        })
    })
    .await
    .map_err(|error| format!("La operacion del nodo fallo: {error}"))?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            inspect_installation,
            install_dependencies,
            apply_installation,
            node_operation
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar Actium Telemetry Node Installer");
}
