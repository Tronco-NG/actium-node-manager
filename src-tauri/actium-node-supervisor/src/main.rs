use actium_node_core::{
    canonical_path, center_public_key_fingerprint, current_binary_sha256, discovery_snapshot_hash,
    discovery_snapshot_payload,
    ipc::{load_ipc_key, read_framed_json, unix_timestamp, write_framed_json},
    latest_effective_grants, latest_effective_transactions, load_contract_registry,
    load_host_identity, load_trust_store, material_capability_root, network_inventory, policy_hash,
    redact_sensitive, render_dropin, resolve_package_dir, sign_storage_transport,
    trust_bundle_digest, trusted_scope_from_node_root, validate_filesystem_uuid, verify_payload,
    verify_signed_trust_bundle, verify_storage_approval, write_dropin, AttestationSigner,
    AuthorityCeremonyPathRequest, AuthorityCeremonyPathStatus, AuthorityCeremonyProgress,
    AuthorityCeremonyRequest, AuthorityService, CommissionNodeRequest,
    ConfigurationWriteRequest, DurableAuthorityState, EnqueueMaterialRequest, FabricIdentity,
    GetMaterialStateRequest, HostReadinessCheck, HostReadinessReport, JournalOperation,
    JournalUpdate, MaterialAttestationStatement, MaterialManager, MaterialResourceLimits,
    MaterialStateStore, OperationJournal, ReconcileMaterialRequest, RuntimeOperator,
    SealedKeyProvider, SignedTrustBundle, StorageGrantIntent, StorageGrantPreflight,
    StorageGrantStore, StorageMount, StorageTransaction, StorageTransportDiscoveryRequest,
    StorageTransportMessageType, StorageTransportScope, SupervisorClient, SupervisorCommand,
    SupervisorReply, SupervisorRequestEnvelope, SupervisorResponseEnvelope, VerifiedPayload,
    MUTATION_HEARTBEAT_SECONDS, SUPERVISOR_VERSION,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[cfg(unix)]
use nix::unistd::{chown, Gid, Group, Uid};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::{fs::{MetadataExt, PermissionsExt}, net::UnixListener};
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::sync::OnceLock;
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use uuid::Uuid;

const WINDOWS_SERVICE_NAME: &str = "ActiumNodeSupervisor";
#[cfg(windows)]
static WINDOWS_LOG_FILE: OnceLock<PathBuf> = OnceLock::new();

#[derive(Debug, Clone, Deserialize)]
struct SupervisorConfig {
    #[serde(default = "default_product_channel")]
    product_channel: String,
    #[serde(default = "default_socket_path")]
    #[cfg_attr(windows, allow(dead_code))]
    socket_path: PathBuf,
    #[serde(default = "default_pipe_name")]
    pipe_name: String,
    #[serde(default = "default_pipe_sddl")]
    #[cfg_attr(not(windows), allow(dead_code))]
    pipe_sddl: String,
    #[serde(default = "default_service_name")]
    service_name: String,
    #[serde(default = "default_key_path")]
    ipc_key_path: PathBuf,
    #[serde(default = "default_journal_path")]
    journal_path: PathBuf,
    /// HostIdentity is sovereign to the physical Host, not to a product
    /// channel. Stable and Lab therefore use one explicit shared root.
    #[serde(default = "default_host_identity_root")]
    host_identity_root: PathBuf,
    #[serde(default = "default_nodes_root")]
    authorized_nodes_root: PathBuf,
    #[serde(default = "default_fabrics_root")]
    authorized_fabrics_root: PathBuf,
    #[serde(default = "default_payload_root")]
    payload_root: PathBuf,
    /// Supervisor-owned lifecycle root for signed Product Extension Bundles.
    #[serde(default = "default_extensions_root")]
    extensions_root: PathBuf,
    /// Public trust records only; private signing material is never stored here.
    #[serde(default = "default_extension_trust_root")]
    extension_trust_root: PathBuf,
    /// Durable public Trust Fabric bundle. An absent file is a supported
    /// first-trust state; environment variables are not a fallback source.
    #[serde(default = "default_trust_store_path")]
    trust_store_path: PathBuf,
    /// Public universal Product Trust bootstrap set. Private keys never live
    /// here; absence is safe for startup but blocks first-trust installation.
    #[serde(default = "default_trust_bootstrap_path")]
    trust_bootstrap_path: PathBuf,
    /// Product Authority data root. It is shared by Stable/Lab and contains
    /// only the durable authority service state, never Owner material in the
    /// Manager UI.
    #[serde(default = "default_authority_data_root")]
    authority_data_root: PathBuf,
    /// Fixed packaged ceremony executable. Frontend input never becomes a
    /// command or executable path.
    #[serde(default = "default_authority_ceremony_binary")]
    authority_ceremony_binary: PathBuf,
    #[serde(default = "default_authority_service_name")]
    authority_service_name: String,
    #[serde(default = "default_authority_online_sealing_key_file")]
    authority_online_sealing_key_file: PathBuf,
    /// Shared arbitration root for Stable/Lab ceremony attempts. Channel
    /// data roots remain isolated, but a Product Root attempt is serialized
    /// on the physical Host.
    #[serde(default = "default_authority_ceremony_lock_root")]
    authority_ceremony_lock_root: PathBuf,
    /// Fixture mode is reserved for isolated lab/test state and can never be
    /// activated as the productive Authority Service.
    #[serde(default = "default_authority_ceremony_mode")]
    authority_ceremony_mode: String,
    #[serde(default = "default_log_dir")]
    log_dir: PathBuf,
    #[serde(default = "default_fabric_identity_path")]
    fabric_identity_path: PathBuf,
    #[serde(default = "default_fabric_id")]
    fabric_id: String,
    #[serde(default = "default_fabric_project")]
    fabric_project: String,
    #[serde(default = "default_fabric_network")]
    fabric_network: String,
    #[serde(default = "default_operator_group")]
    #[cfg_attr(windows, allow(dead_code))]
    operator_group: String,
    #[serde(default = "default_network_interval")]
    network_reconcile_interval_seconds: u64,
    #[serde(default = "default_runtime_interval")]
    runtime_reconcile_interval_seconds: u64,
    #[serde(default = "default_runtime_parallel")]
    runtime_reconcile_max_parallel_nodes: u64,
    #[serde(default = "default_root_ownership_marker")]
    root_ownership_marker: PathBuf,
    /// Optional filesystem root used by isolated test/service adapters.  The
    /// production default remains `/`; no generic mount is granted by this
    /// setting.
    #[serde(default = "default_systemd_root")]
    systemd_root: PathBuf,
    /// Command used for daemon-reload/restart/health.  Production defaults
    /// to the native systemctl binary; tests may provide an isolated adapter.
    #[serde(default = "default_systemctl_path")]
    systemctl_path: PathBuf,
}

impl SupervisorConfig {
    fn load(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
        toml::from_str(&contents)
            .map_err(|error| format!("Configuracion de Supervisor invalida: {error}"))
    }

    fn prepare_directories(&self) -> Result<(), String> {
        for path in [
            self.journal_path.parent(),
            Some(self.host_identity_root.as_path()),
            Some(self.log_dir.as_path()),
            self.fabric_identity_path.parent(),
            Some(self.extensions_root.as_path()),
            Some(self.extension_trust_root.as_path()),
            self.trust_store_path.parent(),
            self.trust_bootstrap_path.parent(),
            Some(self.authority_data_root.as_path()),
            Some(self.authority_ceremony_lock_root.as_path()),
        ]
        .into_iter()
        .flatten()
        {
            fs::create_dir_all(path)
                .map_err(|error| format!("No se pudo crear {}: {error}", path.display()))?;
        }
        self.migrate_legacy_host_identity()?;
        actium_node_core::load_or_create_host_identity(&self.host_identity_root)?;
        actium_node_core::ensure_extension_registry(&self.extensions_root)?;
        #[cfg(unix)]
        if let Some(path) = self.socket_path.parent() {
            fs::create_dir_all(path)
                .map_err(|error| format!("No se pudo crear {}: {error}", path.display()))?;
        }
        Ok(())
    }

    /// Move the pre-Gate-1.6 HostIdentity file into the shared physical-host
    /// root without deleting the legacy copy. Stable and Lab are checked
    /// together; divergent legacy identities fail closed instead of selecting
    /// one heuristically.
    fn migrate_legacy_host_identity(&self) -> Result<(), String> {
        const FILE: &str = "host-identity.json";
        let target = self.host_identity_root.join(FILE);
        if target.is_file() {
            return Ok(());
        }

        let mut candidate_dirs = Vec::new();
        if let Some(parent) = self.journal_path.parent() {
            candidate_dirs.push(parent.to_path_buf());
        }
        #[cfg(unix)]
        {
            candidate_dirs.push(PathBuf::from("/var/lib/actium/node-manager"));
            candidate_dirs.push(PathBuf::from("/var/lib/actium/node-manager-lab"));
        }
        #[cfg(windows)]
        {
            let program_data = program_data_root();
            candidate_dirs.push(program_data.join("NodeManager").join("state"));
            candidate_dirs.push(program_data.join("NodeManagerLab").join("state"));
        }

        let mut selected: Option<(PathBuf, String, actium_node_core::HostIdentity)> = None;
        for directory in candidate_dirs {
            let legacy = directory.join(FILE);
            if legacy == target || !legacy.is_file() {
                continue;
            }
            let contents = fs::read_to_string(&legacy)
                .map_err(|error| format!("No se pudo leer {}: {error}", legacy.display()))?;
            let identity = serde_json::from_str::<actium_node_core::HostIdentity>(&contents)
                .map_err(|error| {
                    format!(
                        "HostIdentity legacy invalida en {}: {error}",
                        legacy.display()
                    )
                })?;
            if let Some((existing_path, _, existing_identity)) = &selected {
                if existing_identity != &identity {
                    return Err(format!(
                        "HOST_IDENTITY_CONFLICT: {} y {} no representan el mismo Host",
                        existing_path.display(),
                        legacy.display()
                    ));
                }
            } else {
                selected = Some((legacy, contents, identity));
            }
        }

        let Some((source, contents, _)) = selected else {
            return Ok(());
        };
        let temporary = target.with_extension(format!("json.migrating.{}", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| {
                format!(
                    "No se pudo preparar {} desde {}: {error}",
                    target.display(),
                    source.display()
                )
            })?;
        file.write_all(contents.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("No se pudo persistir {}: {error}", temporary.display()))?;
        match fs::rename(&temporary, &target) {
            Ok(()) => {
                #[cfg(unix)]
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).map_err(
                    |error| format!("No se pudo proteger {}: {error}", target.display()),
                )?;
            }
            Err(_error) if target.is_file() => {
                let _ = fs::remove_file(&temporary);
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(format!("No se pudo instalar {}: {error}", target.display()));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        let prefix = actium_node_core::topology::channel_project_prefix(&self.product_channel)?;
        for (label, value) in [
            ("fabric_project", self.fabric_project.as_str()),
            ("fabric_network", self.fabric_network.as_str()),
        ] {
            if !value.starts_with(prefix) {
                return Err(format!("{label} debe pertenecer al namespace {prefix}."));
            }
        }
        if self.pipe_name.is_empty()
            || self.pipe_name.len() > 120
            || self
                .pipe_name
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
        {
            return Err("pipe_name contiene caracteres no permitidos.".to_string());
        }
        if self.service_name.is_empty()
            || self.service_name.len() > 80
            || self
                .service_name
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-'))
        {
            return Err("service_name contiene caracteres no permitidos.".to_string());
        }
        if self.authority_service_name != "actium-authority.service" {
            return Err("authority_service_name debe ser actium-authority.service.".to_string());
        }
        if !matches!(
            self.authority_ceremony_mode.as_str(),
            "production" | "fixture"
        ) {
            return Err("authority_ceremony_mode debe ser production o fixture.".to_string());
        }
        for path in [
            &self.authority_data_root,
            &self.authority_ceremony_binary,
            &self.authority_online_sealing_key_file,
            &self.authority_ceremony_lock_root,
        ] {
            if !path.is_absolute() {
                return Err(format!(
                    "La ruta de Authority debe ser absoluta: {}.",
                    path.display()
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RootOwnershipMarker {
    schema: u8,
    owner: String,
    product_channel: String,
    root_id: String,
    authorized_nodes_root: String,
    authorized_fabrics_root: String,
    #[serde(default)]
    confirmed_at: Option<String>,
    #[serde(default)]
    confirmed_by: Option<String>,
}

mod installer_cli;
mod trust_store;

fn main() {
    if let Err(error) = run() {
        eprintln!("actium-node-supervisor: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() == 1 {
        let default_config = default_config_path();
        if !default_config.is_file() {
            return installer_cli::run_interactive_menu();
        }
    }

    let mut arguments = raw_args.into_iter().skip(1);
    let mut config_path = default_config_path();
    let mut check_only = false;
    let mut ping_only = false;
    let mut self_test = false;
    let mut service_mode = false;
    let mut install_mode = false;
    let mut uninstall_mode = false;
    let mut remove_data = false;
    let mut no_start = false;
    let mut build_info_only = false;
    let mut channel: Option<String> = None;
    let mut verify_payload_path = None;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--config" => {
                config_path = arguments
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--config requiere una ruta.".to_string())?;
            }
            "--check" => check_only = true,
            "--ping" => ping_only = true,
            "--self-test" => self_test = true,
            "--service" => service_mode = true,
            "--install" | "--setup" => install_mode = true,
            "--uninstall" => uninstall_mode = true,
            "--remove-data" => remove_data = true,
            "--no-start" => no_start = true,
            "--build-info" => build_info_only = true,
            "--interactive" | "-i" => return installer_cli::run_interactive_menu(),
            "--channel" => {
                channel = arguments.next();
            }
            "--verify-payload" => {
                verify_payload_path = Some(
                    arguments
                        .next()
                        .map(PathBuf::from)
                        .ok_or_else(|| "--verify-payload requiere una ruta.".to_string())?,
                );
            }
            "--version" => {
                println!("actium-node-supervisor {SUPERVISOR_VERSION}");
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "Actium Node Supervisor {SUPERVISOR_VERSION} - Servicio e Instalador Autónomo"
                );
                println!("\nUso:");
                println!("  actium-node-supervisor [OPCIONES]");
                println!("\nOpciones de Instalación y Aprovisionamiento:");
                println!("  --install, --setup     Instala y registra el servicio del Supervisor en el sistema operativo");
                println!("  --uninstall            Detiene, deshabilita y elimina el servicio del Supervisor");
                println!("  --channel <canal>      Selecciona el canal: 'stable' (puertos 8xxx), 'lab' (puertos 18xxx), o 'both'");
                println!("  --interactive, -i      Inicia el asistente gráfico/TUI interactivo");
                println!("  --no-start             Instala el servicio sin iniciarlo de inmediato");
                println!("  --remove-data          En desinstalación, purga también las raíces de datos /srv");
                println!("\nOpciones de Operación y Diagnóstico:");
                println!("  --config <ruta>        Ruta al archivo supervisor.toml / supervisor.lab.toml");
                println!("  --ping                 Comprueba la conectividad con el daemon en ejecución mediante IPC");
                println!("  --check                Valida la configuración, los permisos y las raíces sin arrancar");
                println!("  --self-test            Ejecuta las pruebas internas de integridad y criptografía");
                println!(
                    "  --verify-payload <dir> Verifica un bundle de contratos Data Plane schema 3"
                );
                println!(
                    "  --service              Ejecuta el proceso en modo servicio en segundo plano"
                );
                println!("  --version              Muestra la versión del Supervisor");
                println!("  --build-info           Muestra identidad de build en JSON");
                println!("  --help, -h             Muestra esta ayuda");
                return Ok(());
            }
            unknown => return Err(format!(
                "Argumento no reconocido: {unknown}. Use --help para ver las opciones disponibles."
            )),
        }
    }

    if install_mode {
        let ch = match channel.as_deref() {
            Some("stable") => "stable",
            Some("lab") => "lab",
            Some("both") => "both",
            Some(other) => {
                return Err(format!("Canal no válido: {other}. Use stable, lab o both."))
            }
            None => {
                println!("No se especificó canal (--channel stable|lab|both). Iniciando asistente interactivo...");
                return installer_cli::run_interactive_menu();
            }
        };

        if ch == "both" {
            println!("=== Instalando Canal Stable ===");
            installer_cli::install_channel("stable", no_start)?;
            println!("\n=== Instalando Canal Lab ===");
            installer_cli::install_channel("lab", no_start)?;
            return Ok(());
        } else {
            return installer_cli::install_channel(ch, no_start);
        }
    }

    if uninstall_mode {
        let ch = channel.as_deref().unwrap_or("stable");
        if ch == "both" {
            installer_cli::uninstall_channel("stable", remove_data)?;
            installer_cli::uninstall_channel("lab", remove_data)?;
        } else {
            installer_cli::uninstall_channel(ch, remove_data)?;
        }
        return Ok(());
    }

    if self_test {
        return run_self_test();
    }
    if build_info_only {
        let value = serde_json::json!({
            "product": "actium-node-supervisor",
            "version": SUPERVISOR_VERSION,
            "source_commit": actium_node_core::build_info::SOURCE_COMMIT,
            "build_id": actium_node_core::build_info::BUILD_ID,
            "build_kind": actium_node_core::build_info::BUILD_KIND,
            "release_status": actium_node_core::build_info::RELEASE_STATUS,
            "binary_sha256": actium_node_core::current_binary_sha256(),
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if let Some(path) = verify_payload_path {
        return verify_schema3_payload(&path);
    }
    if service_mode {
        #[cfg(windows)]
        {
            return windows_service_host::dispatch(config_path);
        }
        #[cfg(not(windows))]
        {
            return Err("--service solo esta disponible en Windows.".to_string());
        }
    }
    let config = SupervisorConfig::load(&config_path)?;
    config.validate()?;
    if ping_only {
        return match SupervisorClient::new(supervisor_endpoint(&config), &config.ipc_key_path)
            .request(SupervisorCommand::Ping)?
        {
            SupervisorReply::Pong {
                supervisor_version,
                recovered_operations,
                protocol_version,
                features,
                source_commit,
                build_id,
                binary_sha256,
            } => {
                println!(
                    "Supervisor {supervisor_version} protocolo {protocol_version} features {} ; {recovered_operations} operacion(es) recuperadas al iniciar; source_commit={} build_id={} binary_sha256={}",
                    features.join(","),
                    source_commit.as_deref().unwrap_or("unknown"),
                    build_id.as_deref().unwrap_or("unknown"),
                    binary_sha256.as_deref().unwrap_or("unknown"),
                );
                Ok(())
            }
            _ => Err("Supervisor devolvio una respuesta inesperada al ping.".to_string()),
        };
    }
    if check_only {
        config.prepare_directories()?;
        verify_owner_confirmed_roots(&config)?;
        load_ipc_key(&config.ipc_key_path)?;
        OperationJournal::open(&config.journal_path)?;
        let _ = resolve_fabric_identity(&config)?;
        let bootstrap_roots = load_trust_bootstrap_roots(&config.trust_bootstrap_path)?;
        let trust_store = trust_store::SupervisorTrustStore::open_with_bootstrap_roots(
            &config.trust_store_path,
            &bootstrap_roots,
        )?;
        let extension_registry = actium_node_core::load_extension_registry(&config.extensions_root);
        let extension_state = if extension_registry.extensions.is_empty() {
            "NO_EXTENSIONS"
        } else {
            extension_registry.extension_registry_state.as_str()
        };
        println!(
            "Supervisor {SUPERVISOR_VERSION}: configuracion {}, canal {} y raices owner-confirmed OK; extensions={}.",
            config_path.display(),
            config.product_channel,
            extension_state
        );
        println!(
            "Trust Fabric: {} epoch={}",
            trust_store.status().state,
            trust_store.status().current_epoch
        );
        return Ok(());
    }
    run_daemon(config, Arc::new(AtomicBool::new(false)), false)
}

fn run_daemon(
    config: SupervisorConfig,
    shutdown: Arc<AtomicBool>,
    service_mode: bool,
) -> Result<(), String> {
    config.validate()?;
    config.prepare_directories()?;
    #[cfg(windows)]
    let _ = WINDOWS_LOG_FILE.set(config.log_dir.join("supervisor.log"));
    verify_owner_confirmed_roots(&config)?;
    let key = load_ipc_key(&config.ipc_key_path)?;
    let journal = OperationJournal::open(&config.journal_path)?;
    let fabric = resolve_fabric_identity(&config)?;
    let runtime = RuntimeOperator::new_with_fabric_and_channel_and_host_identity(
        &config.authorized_nodes_root,
        &config.authorized_fabrics_root,
        &config.payload_root,
        fabric,
        &config.fabric_identity_path,
        &config.product_channel,
        &config.host_identity_root,
    )?;
    let storage_signer = load_storage_transport_signer(&config)?;
    let bootstrap_roots = load_trust_bootstrap_roots(&config.trust_bootstrap_path)?;
    let trust_store = trust_store::SupervisorTrustStore::open_with_bootstrap_roots(
        &config.trust_store_path,
        &bootstrap_roots,
    )?;

    journal.recover_expired_leases(unix_timestamp() as i64)?;
    let recovered_at = unix_timestamp().to_string();
    let recovered_operations = journal.recover_interrupted(&recovered_at)?;
    recover_interrupted_operations(&journal, &runtime)?;
    let shared = Arc::new(SupervisorState {
        config: config.clone(),
        key,
        journal,
        runtime,
        nonces: Mutex::new(HashMap::new()),
        recovered_operations,
        storage_signer,
        trust_store: Mutex::new(trust_store),
    });
    reconcile_storage_grants(&shared)?;

    start_operation_worker(shared.clone());
    start_network_reconciler(shared.clone());
    start_attestation_reconciler(shared.clone());
    start_runtime_reconciler(shared.clone());
    serve_ipc(shared, &config, shutdown, service_mode)
}

fn reconcile_storage_grants(state: &SupervisorState) -> Result<(), String> {
    let store = StorageGrantStore::open(storage_state_root(state))?;
    let mut grants = store.grants()?;
    let mounts = storage_discover().unwrap_or_default();
    for g in &mut grants {
        let ok = mounts.iter().any(|m| {
            m.mountpoint == g.canonical_mountpoint
                && !m.readonly
                && m.filesystem_uuid.as_deref() == Some(g.filesystem_uuid.as_str())
        });
        if !ok {
            g.state = "degraded".into();
            g.degraded_reason = Some("mount_absent_or_identity_changed".into())
        }
    }
    store.save_grants(&grants)?;
    write_dropin(
        &state.config.systemd_root,
        &state.config.service_name,
        &grants,
    )?;
    Ok(())
}
fn reload_restart_health(config: &SupervisorConfig) -> Result<(), String> {
    let mut reload = std::process::Command::new(&config.systemctl_path);
    reload.args(["daemon-reload"]);
    reload.env("ACTIUM_SYSTEMD_ROOT", &config.systemd_root);
    let reload = reload.status().map_err(|e| e.to_string())?;
    if !reload.success() {
        return Err("STORAGE_SYSTEMD_RELOAD_FAILED".into());
    }
    let mut restart = std::process::Command::new(&config.systemctl_path);
    restart.args(["try-restart", &config.service_name]);
    restart.env("ACTIUM_SYSTEMD_ROOT", &config.systemd_root);
    let restart = restart.status().map_err(|e| e.to_string())?;
    if !restart.success() {
        return Err("STORAGE_SYSTEMD_RESTART_FAILED".into());
    }
    let mut health = std::process::Command::new(&config.systemctl_path);
    health.args(["is-active", "--quiet", &config.service_name]);
    health.env("ACTIUM_SYSTEMD_ROOT", &config.systemd_root);
    let health = health.status().map_err(|e| e.to_string())?;
    if !health.success() {
        return Err("STORAGE_SUPERVISOR_UNHEALTHY".into());
    }
    Ok(())
}

const AUTHORITY_CEREMONY_CONFIRMATION: &str = "OFFLINE_ROOT_OWNER_APPROVED";
const AUTHORITY_CEREMONY_TRUST_ROOT_SET: &str = "actium-product-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityCeremonyOperationMetadata {
    schema: u8,
    ceremony_id: String,
    host_id: String,
    channel: String,
    trust_root_set: String,
    actor: String,
    correlation_id: String,
    request: AuthorityCeremonyRequest,
}

fn authority_ceremony_lock_path(config: &SupervisorConfig) -> PathBuf {
    config.authority_ceremony_lock_root.join(".ceremony.lock")
}

fn authority_ceremony_paths(config: &SupervisorConfig) -> (PathBuf, PathBuf, PathBuf) {
    (
        config.authority_data_root.join("keys"),
        config.authority_data_root.join("authority-state.json"),
        config.authority_data_root.join("trust-bundle.json"),
    )
}

/// The offline sealing key belongs to the Owner-selected custody directory.
/// Keep this derivation centralized so preflight, execution and recovery never
/// escape to the selected directory's parent through filename replacement.
fn authority_ceremony_offline_sealing_key_path(offline_root: &Path) -> PathBuf {
    offline_root.join(".actium-root-sealing.key")
}

fn authority_ceremony_journal_path(config: &SupervisorConfig, ceremony_id: &str) -> PathBuf {
    config
        .authority_data_root
        .join("ceremonies")
        .join(format!("{ceremony_id}.json"))
}

fn ceremony_progress_base(
    config: &SupervisorConfig,
    request: &AuthorityCeremonyRequest,
) -> AuthorityCeremonyProgress {
    AuthorityCeremonyProgress {
        ceremony_id: request.ceremony_id.clone(),
        state: "NOT_STARTED".into(),
        code: None,
        provider: request.provider.clone(),
        offline_root_dir: request.offline_root_dir.clone(),
        recovery_dir: request.recovery_dir.clone(),
        online_data_dir: config.authority_data_root.to_string_lossy().into_owned(),
        root_key_id: None,
        root_fingerprint: None,
        trust_bundle_path: None,
        trust_bundle_digest: None,
        trust_epoch: None,
        subordinate_count: 0,
        public_only_key_count: 0,
        recovery_path: None,
        recovery_status: "PENDING".into(),
        authority_service_state: "UNINITIALIZED".into(),
        trust_store_state: "UNKNOWN".into(),
        updated_at: unix_timestamp(),
        operation_id: None,
        correlation_id: None,
    }
}

fn normalized_absolute_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("AUTHORITY_CEREMONY_PATH_INVALID".into());
    }
    Ok(path.to_path_buf())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    let left = left
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let right = right
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

fn forbidden_authority_path(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    normalized.ends_with("/payload.json")
        || normalized.contains("/resources/node/")
        || normalized.contains("/target/")
}

fn existing_parent(path: &Path) -> Option<PathBuf> {
    let mut candidate = path.to_path_buf();
    loop {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => return None,
            Ok(metadata) if metadata.is_dir() => return Some(candidate),
            Ok(_) | Err(_) => {
                if !candidate.pop() {
                    return None;
                }
            }
        }
    }
}

fn classify_write_probe_error(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "AUTHORITY_CEREMONY_PERMISSION_DENIED",
        std::io::ErrorKind::ReadOnlyFilesystem => "AUTHORITY_CEREMONY_FILESYSTEM_READONLY",
        std::io::ErrorKind::NotFound => "AUTHORITY_CEREMONY_PATH_UNAVAILABLE",
        _ => "AUTHORITY_CEREMONY_WRITE_PROBE_FAILED",
    }
}

/// Metadata permissions do not reveal the effective access inside a
/// ProtectSystem/mount namespace. Probe and remove a unique transient file
/// before any sealing or ceremony material is created.
fn effective_write_probe(path: &Path) -> Result<(), String> {
    let directory = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err("AUTHORITY_CEREMONY_PATH_INVALID".into());
        }
        Ok(metadata) if metadata.is_dir() => path.to_path_buf(),
        Ok(_) | Err(_) => existing_parent(path)
            .ok_or_else(|| "AUTHORITY_CEREMONY_PATH_UNAVAILABLE".to_string())?,
    };
    let probe = directory.join(format!(
        ".actium-write-probe-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|error| classify_write_probe_error(&error).to_string())?;
    file.write_all(b"actium-probe")
        .and_then(|_| file.sync_all())
        .map_err(|error| classify_write_probe_error(&error).to_string())?;
    drop(file);
    fs::remove_file(&probe).map_err(|error| classify_write_probe_error(&error).to_string())
}

/// Prepare an Owner-selected ceremony boundary without broadening the
/// Supervisor sandbox or touching its contents.  The Debian service runs as
/// uid 0 with CAP_CHOWN but without CAP_DAC_OVERRIDE, so an existing
/// user-owned 0700 directory is not writable from the real service context.
/// Only the selected directory itself is adopted as root:root 0700; no
/// recursive ownership or permission change is performed.
fn prepare_ceremony_directory(path: &Path, label: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| {
        format!(
            "{}:{}",
            classify_write_probe_error(&error),
            label
        )
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "{}:{}",
            classify_write_probe_error(&error),
            label
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("AUTHORITY_CEREMONY_PATH_INVALID:{label}"));
    }

    #[cfg(unix)]
    if Uid::effective().is_root()
        && (metadata.uid() != Uid::effective().as_raw()
            || metadata.gid() != Gid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o700)
    {
        chown(
            path,
            Some(Uid::effective()),
            Some(Gid::effective()),
        )
        .map_err(|_| format!("AUTHORITY_CEREMONY_PERMISSION_DENIED:{label}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| format!("AUTHORITY_CEREMONY_PERMISSION_DENIED:{label}"))?;
    }

    effective_write_probe(path).map_err(|error| format!("{error}:{label}"))
}

/// Validate one Owner-selected custody path without making the desktop
/// process enumerate a protected directory. This reuses the same preparation
/// boundary as the complete ceremony preflight.
fn authority_ceremony_path_preflight(
    config: &SupervisorConfig,
    request: AuthorityCeremonyPathRequest,
) -> AuthorityCeremonyPathStatus {
    let mut status = AuthorityCeremonyPathStatus {
        path: request.path.trim().to_string(),
        purpose: request.purpose.trim().to_string(),
        state: "BLOCKED".into(),
        code: None,
        exists: false,
        directory: false,
        writable: false,
    };
    let label = match status.purpose.as_str() {
        "offline_root" | "recovery_dir" => status.purpose.as_str(),
        _ => {
            status.code = Some("AUTHORITY_CEREMONY_PATH_PURPOSE_INVALID".into());
            return status;
        }
    };
    let path = match normalized_absolute_path(Path::new(&status.path)) {
        Ok(path) => path,
        Err(error) => {
            status.code = Some(error);
            return status;
        }
    };
    status.path = path.to_string_lossy().into_owned();
    status.exists = path.exists();
    status.directory = path.is_dir();
    if forbidden_authority_path(&path) {
        status.code = Some("AUTHORITY_CEREMONY_PATH_FORBIDDEN".into());
        return status;
    }
    let authority_root = match normalized_absolute_path(&config.authority_data_root) {
        Ok(root) => root,
        Err(error) => {
            status.code = Some(error);
            return status;
        }
    };
    if paths_overlap(&path, &authority_root) {
        status.code = Some("AUTHORITY_CEREMONY_PATH_OVERLAP".into());
        return status;
    }
    match prepare_ceremony_directory(&path, label) {
        Ok(()) => {
            status.state = "READY".into();
            status.exists = true;
            status.directory = true;
            status.writable = true;
        }
        Err(error) => status.code = Some(error),
    }
    status
}

fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Path::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

fn classify_existing_ceremony_lock(path: &Path) -> String {
    let Ok(bytes) = fs::read(path) else {
        return "AUTHORITY_CEREMONY_LOCK_STATE_UNKNOWN".into();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return "AUTHORITY_CEREMONY_LOCK_STATE_UNKNOWN".into();
    };
    let pid = value
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default() as u32;
    if pid != 0 && process_exists(pid) {
        "AUTHORITY_CEREMONY_ALREADY_RUNNING".into()
    } else {
        "AUTHORITY_CEREMONY_LOCK_STALE".into()
    }
}

fn validate_sealing_key_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "TRUST_SEALING_KEY_UNAVAILABLE".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("TRUST_SEALING_KEY_UNAVAILABLE".into());
    }
    let text = fs::read_to_string(path).map_err(|_| "TRUST_SEALING_KEY_UNAVAILABLE".to_string())?;
    let mut lines = text.lines();
    if lines.next() != Some("ACTIUM-SEALING-KEY-V1") {
        return Err("TRUST_SEALING_KEY_FORMAT_INVALID".into());
    }
    let encoded = lines
        .next()
        .ok_or_else(|| "TRUST_SEALING_KEY_FORMAT_INVALID".to_string())?;
    if lines.next().is_some() {
        return Err("TRUST_SEALING_KEY_FORMAT_INVALID".into());
    }
    let raw = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "TRUST_SEALING_KEY_FORMAT_INVALID".to_string())?;
    if raw.len() != 32 {
        return Err("TRUST_SEALING_KEY_LENGTH_INVALID".into());
    }
    Ok(())
}

fn validate_authority_ceremony_request(
    config: &SupervisorConfig,
    request: &AuthorityCeremonyRequest,
) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf), String> {
    Uuid::parse_str(&request.ceremony_id)
        .map_err(|_| "AUTHORITY_CEREMONY_ID_INVALID".to_string())?;
    if request.trust_root_set != AUTHORITY_CEREMONY_TRUST_ROOT_SET {
        return Err("AUTHORITY_TRUST_ROOT_SET_UNSUPPORTED".into());
    }
    if request.provider != "software_sealed" {
        return Err("AUTHORITY_PROVIDER_UNAVAILABLE".into());
    }
    let offline = normalized_absolute_path(Path::new(&request.offline_root_dir))?;
    let recovery = normalized_absolute_path(Path::new(&request.recovery_dir))?;
    if forbidden_authority_path(&offline) || forbidden_authority_path(&recovery) {
        return Err("AUTHORITY_CEREMONY_PATH_FORBIDDEN".into());
    }
    let (online_keys, state_path, bundle_path) = authority_ceremony_paths(config);
    let authority_root = normalized_absolute_path(&config.authority_data_root)?;
    if paths_overlap(&offline, &authority_root)
        || paths_overlap(&recovery, &authority_root)
        || paths_overlap(&offline, &recovery)
    {
        return Err("AUTHORITY_CEREMONY_PATH_OVERLAP".into());
    }
    prepare_ceremony_directory(&offline, "offline_root")?;
    prepare_ceremony_directory(&recovery, "recovery_dir")?;
    effective_write_probe(&config.authority_data_root)
        .map_err(|error| format!("{error}:authority_data_root"))?;
    effective_write_probe(&config.authority_online_sealing_key_file)
        .map_err(|error| format!("{error}:online_sealing_key"))?;
    effective_write_probe(&config.authority_ceremony_lock_root)
        .map_err(|error| format!("{error}:lock_root"))?;
    if !config.authority_ceremony_binary.is_file() {
        return Err("AUTHORITY_CEREMONY_BINARY_UNAVAILABLE".into());
    }
    let unit = config
        .systemd_root
        .join("etc/systemd/system")
        .join(&config.authority_service_name);
    if !unit.is_file() {
        return Err("AUTHORITY_SERVICE_UNIT_UNAVAILABLE".into());
    }
    if online_keys.exists() || state_path.exists() || bundle_path.exists() {
        return Err("AUTHORITY_CEREMONY_OUTPUT_ALREADY_EXISTS".into());
    }
    let offline_sealing = authority_ceremony_offline_sealing_key_path(&offline);
    validate_offline_ceremony_directory(&offline, &offline_sealing)?;
    effective_write_probe(&offline_sealing)
        .map_err(|error| format!("{error}:offline_sealing_key"))?;
    if offline_sealing.exists() {
        validate_sealing_key_file(&offline_sealing)?;
    }
    if config.authority_online_sealing_key_file.exists() {
        validate_sealing_key_file(&config.authority_online_sealing_key_file)?;
    }
    Ok((offline, recovery, online_keys, state_path))
}

fn authority_ceremony_preflight(
    config: &SupervisorConfig,
    state: &SupervisorState,
    request: AuthorityCeremonyRequest,
) -> AuthorityCeremonyProgress {
    let mut progress = ceremony_progress_base(config, &request);
    progress.trust_store_state = state
        .trust_store
        .lock()
        .map(|store| store.status().state)
        .unwrap_or_else(|_| "UNKNOWN".into());
    match validate_authority_ceremony_request(config, &request) {
        Ok(_) => {
            progress.state = "PREFLIGHT_OK".into();
        }
        Err(code) => {
            progress.state = "PREFLIGHT_BLOCKED".into();
            progress.code = Some(code);
        }
    }
    progress.updated_at = unix_timestamp();
    progress
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "AUTHORITY_CEREMONY_PATH_INVALID".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|_| "AUTHORITY_CEREMONY_JOURNAL_DIRECTORY_FAILED".to_string())?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| "AUTHORITY_CEREMONY_JOURNAL_SERIALIZE_FAILED".to_string())?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| "AUTHORITY_CEREMONY_JOURNAL_TEMP_FAILED".to_string())?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "AUTHORITY_CEREMONY_JOURNAL_WRITE_FAILED".to_string())?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("AUTHORITY_CEREMONY_JOURNAL_COMMIT_FAILED: {error}"));
    }
    Ok(())
}

fn write_sealing_key(path: &Path, role: &str) -> Result<(), String> {
    if path.exists() {
        return validate_sealing_key_file(path);
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("AUTHORITY_SEALING_KEY_PATH_INVALID:{role}"))?;
    fs::create_dir_all(parent)
        .map_err(|_| format!("AUTHORITY_SEALING_KEY_DIRECTORY_FAILED:{role}"))?;
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let contents = format!("ACTIUM-SEALING-KEY-V1\n{}\n", URL_SAFE_NO_PAD.encode(raw));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| format!("AUTHORITY_SEALING_KEY_CREATE_FAILED:{role}"))?;
    if file
        .write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .is_err()
    {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("AUTHORITY_SEALING_KEY_WRITE_FAILED:{role}"));
    }
    #[cfg(unix)]
    if fs::set_permissions(path, fs::Permissions::from_mode(0o600)).is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("AUTHORITY_SEALING_KEY_PERMISSIONS_FAILED:{role}"));
    }
    Ok(())
}

/// The Supervisor stages exactly one sealing key in the Owner-selected offline
/// directory before invoking the ceremony tool. That file is an allowed
/// precondition; every other entry is possible partial or foreign material and
/// fails closed.
fn validate_offline_ceremony_directory(
    offline_root: &Path,
    offline_sealing: &Path,
) -> Result<(), String> {
    let expected_name = offline_sealing
        .file_name()
        .ok_or_else(|| "AUTHORITY_CEREMONY_PATH_INVALID:offline_sealing_key".to_string())?;
    let sealing_parent = offline_sealing
        .parent()
        .ok_or_else(|| "AUTHORITY_CEREMONY_PATH_INVALID:offline_sealing_key".to_string())?;
    if sealing_parent != offline_root {
        return Err("AUTHORITY_CEREMONY_PATH_INVALID:offline_sealing_key".into());
    }

    for entry in fs::read_dir(offline_root)
        .map_err(|_| "AUTHORITY_OFFLINE_DIR_FAILED".to_string())?
    {
        let entry = entry.map_err(|_| "AUTHORITY_OFFLINE_DIR_FAILED".to_string())?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| "AUTHORITY_OFFLINE_DIR_FAILED".to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("AUTHORITY_CEREMONY_PATH_INVALID:offline_sealing_key".into());
        }
        if entry.file_name() != expected_name || !metadata.is_file() {
            return Err("AUTHORITY_OFFLINE_DIR_NOT_EMPTY".into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn authority_service_group() -> Result<Gid, String> {
    Group::from_name("actium-authority")
        .map_err(|_| "AUTHORITY_SERVICE_ACCOUNT_UNAVAILABLE".to_string())?
        .map(|group| group.gid)
        .ok_or_else(|| "AUTHORITY_SERVICE_ACCOUNT_UNAVAILABLE".to_string())
}

/// Keep the sealing key owned by the Supervisor boundary while granting the
/// Authority service its explicit group read access.  This is required by
/// both sides: Supervisor validates/reloads the ceremony output, while the
/// Authority service uses the same sealing key after activation.  No private
/// Product Root material is stored here.
#[cfg(unix)]
fn assign_authority_service_access(path: &Path) -> Result<(), String> {
    let group = authority_service_group()?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "AUTHORITY_SEALING_KEY_UNAVAILABLE".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("AUTHORITY_SEALING_KEY_PERMISSIONS_FAILED".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .map_err(|_| "AUTHORITY_SEALING_KEY_PERMISSIONS_FAILED".to_string())?;
    chown(path, Some(Uid::effective()), Some(group))
        .map_err(|_| "AUTHORITY_SEALING_KEY_OWNERSHIP_FAILED".to_string())?;
    Ok(())
}

#[cfg(not(unix))]
fn assign_authority_service_access(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn assign_authority_service_shared_tree(path: &Path, group: Gid) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "AUTHORITY_SHARED_OUTPUT_UNAVAILABLE".to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("AUTHORITY_SHARED_OUTPUT_INVALID".into());
    }
    if metadata.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o770))
            .map_err(|_| "AUTHORITY_SHARED_OUTPUT_PERMISSIONS_FAILED".to_string())?;
        chown(path, Some(Uid::effective()), Some(group))
            .map_err(|_| "AUTHORITY_SHARED_OUTPUT_OWNERSHIP_FAILED".to_string())?;
        for entry in fs::read_dir(path)
            .map_err(|_| "AUTHORITY_SHARED_OUTPUT_UNAVAILABLE".to_string())?
        {
            let entry = entry.map_err(|_| "AUTHORITY_SHARED_OUTPUT_INVALID".to_string())?;
            assign_authority_service_shared_tree(&entry.path(), group)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err("AUTHORITY_SHARED_OUTPUT_INVALID".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .map_err(|_| "AUTHORITY_SHARED_OUTPUT_PERMISSIONS_FAILED".to_string())?;
    chown(path, Some(Uid::effective()), Some(group))
        .map_err(|_| "AUTHORITY_SHARED_OUTPUT_OWNERSHIP_FAILED".to_string())?;
    Ok(())
}

#[cfg(unix)]
fn assign_authority_service_outputs(
    online_keys: &Path,
    state_path: &Path,
    bundle_path: &Path,
) -> Result<(), String> {
    let group = authority_service_group()?;
    assign_authority_service_shared_tree(online_keys, group)?;
    assign_authority_service_shared_tree(state_path, group)?;
    assign_authority_service_shared_tree(bundle_path, group)
}

#[cfg(not(unix))]
fn assign_authority_service_outputs(
    _online_keys: &Path,
    _state_path: &Path,
    _bundle_path: &Path,
) -> Result<(), String> {
    Ok(())
}

fn load_ceremony_outputs(
    config: &SupervisorConfig,
) -> Result<
    (
        DurableAuthorityState,
        SignedTrustBundle,
        String,
        String,
        usize,
        usize,
    ),
    String,
> {
    let (online_keys, state_path, bundle_path) = authority_ceremony_paths(config);
    let state: DurableAuthorityState = serde_json::from_slice(
        &fs::read(&state_path).map_err(|_| "AUTHORITY_STATE_READ_FAILED".to_string())?,
    )
    .map_err(|_| "AUTHORITY_STATE_INVALID".to_string())?;
    let bundle: SignedTrustBundle = serde_json::from_slice(
        &fs::read(&bundle_path).map_err(|_| "AUTHORITY_TRUST_BUNDLE_UNAVAILABLE".to_string())?,
    )
    .map_err(|_| "AUTHORITY_TRUST_BUNDLE_INVALID".to_string())?;
    verify_signed_trust_bundle(&bundle, unix_timestamp(), 0)
        .map_err(|_| "AUTHORITY_TRUST_BUNDLE_INVALID".to_string())?;
    let root_fingerprint = bundle
        .bundle
        .product_roots
        .iter()
        .find(|candidate| candidate.authority.key_id == bundle.signing_key_id)
        .map(|candidate| candidate.authority.fingerprint.clone())
        .ok_or_else(|| "AUTHORITY_TRUST_ROOT_MISSING".to_string())?;
    if !state
        .public_only_key_ids
        .iter()
        .any(|key_id| bundle.signing_key_id == *key_id)
    {
        return Err("AUTHORITY_ROOT_ONLINE_KEY_PRESENT".into());
    }
    let provider = SealedKeyProvider::from_sealing_key_file(
        &online_keys,
        &config.authority_online_sealing_key_file,
    )
    .map_err(|_| "AUTHORITY_ONLINE_PROVIDER_INVALID".to_string())?;
    AuthorityService::from_durable_state(provider, state.clone())
        .map_err(|_| "AUTHORITY_ONLINE_STATE_INVALID".to_string())?;
    let subordinate_count = bundle.bundle.deployment_authority.iter().count()
        + bundle.bundle.deployment_root.iter().count()
        + bundle.bundle.center_authority.iter().count()
        + bundle.bundle.enrollment_authorities.len()
        + bundle.bundle.release_authorities.len()
        + bundle.bundle.product_signing_authorities.len();
    let digest = trust_bundle_digest(&bundle.bundle)?;
    let public_only_count = state.public_only_key_ids.len();
    Ok((
        state,
        bundle,
        root_fingerprint,
        digest,
        subordinate_count,
        public_only_count,
    ))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|_| "AUTHORITY_RECOVERY_SOURCE_UNAVAILABLE".to_string())?;
    Ok(format!(
        "sha256:{}",
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityRecoveryManifest {
    schema: u8,
    ceremony_id: String,
    root_fingerprint: String,
    files: Vec<AuthorityRecoveryFile>,
    verified_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorityRecoveryFile {
    path: String,
    sha256: String,
}

fn copy_verified(source: &Path, destination: &Path) -> Result<String, String> {
    let source_meta = fs::symlink_metadata(source)
        .map_err(|_| "AUTHORITY_RECOVERY_SOURCE_UNAVAILABLE".to_string())?;
    if source_meta.file_type().is_symlink() || !source_meta.is_file() {
        return Err("AUTHORITY_RECOVERY_SOURCE_INVALID".into());
    }
    if destination.exists() {
        if fs::symlink_metadata(destination)
            .map_err(|_| "AUTHORITY_RECOVERY_TARGET_INVALID".to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("AUTHORITY_RECOVERY_TARGET_INVALID".into());
        }
        let source_digest = sha256_file(source)?;
        if sha256_file(destination)? != source_digest {
            return Err("AUTHORITY_RECOVERY_TARGET_CONFLICT".into());
        }
        return Ok(source_digest);
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|_| "AUTHORITY_RECOVERY_TARGET_UNAVAILABLE".to_string())?;
    }
    fs::copy(source, destination).map_err(|_| "AUTHORITY_RECOVERY_COPY_FAILED".to_string())?;
    #[cfg(unix)]
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))
        .map_err(|_| "AUTHORITY_RECOVERY_PERMISSIONS_FAILED".to_string())?;
    sha256_file(destination)
}

fn export_recovery(
    config: &SupervisorConfig,
    ceremony_id: &str,
    offline_root: &Path,
    recovery_dir: &Path,
    root_fingerprint: &str,
) -> Result<PathBuf, String> {
    let target = recovery_dir.join(format!("actium-authority-recovery-{ceremony_id}"));
    fs::create_dir_all(target.join("offline-root"))
        .map_err(|_| "AUTHORITY_RECOVERY_TARGET_UNAVAILABLE".to_string())?;
    #[cfg(unix)]
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
        .map_err(|_| "AUTHORITY_RECOVERY_PERMISSIONS_FAILED".to_string())?;
    let offline_sealing = authority_ceremony_offline_sealing_key_path(offline_root);
    let (_, state_path, bundle_path) = authority_ceremony_paths(config);
    let mut files = Vec::new();
    for entry in
        fs::read_dir(offline_root).map_err(|_| "AUTHORITY_OFFLINE_DIR_FAILED".to_string())?
    {
        let entry = entry.map_err(|_| "AUTHORITY_RECOVERY_SOURCE_INVALID".to_string())?;
        let source = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains('/')
            || name.contains('\\')
            || fs::symlink_metadata(&source)
                .map_err(|_| "AUTHORITY_RECOVERY_SOURCE_INVALID".to_string())?
                .file_type()
                .is_symlink()
        {
            return Err("AUTHORITY_RECOVERY_SOURCE_INVALID".into());
        }
        let digest = copy_verified(&source, &target.join("offline-root").join(&name))?;
        files.push(AuthorityRecoveryFile {
            path: format!("offline-root/{name}"),
            sha256: digest,
        });
    }
    files.push(AuthorityRecoveryFile {
        path: "offline-sealing.key".into(),
        sha256: copy_verified(&offline_sealing, &target.join("offline-sealing.key"))?,
    });
    files.push(AuthorityRecoveryFile {
        path: "authority-state.json".into(),
        sha256: copy_verified(&state_path, &target.join("authority-state.json"))?,
    });
    files.push(AuthorityRecoveryFile {
        path: "trust-bundle.json".into(),
        sha256: copy_verified(&bundle_path, &target.join("trust-bundle.json"))?,
    });
    let manifest = AuthorityRecoveryManifest {
        schema: 1,
        ceremony_id: ceremony_id.into(),
        root_fingerprint: root_fingerprint.into(),
        files,
        verified_at: unix_timestamp(),
    };
    write_json_atomic(&target.join("recovery-manifest.json"), &manifest)?;
    Ok(target)
}

fn safe_authority_ceremony_tool_failure(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    text.split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .find(|token| {
            !token.is_empty()
                && token.len() <= 96
                && (token.starts_with("AUTHORITY_") || token.starts_with("TRUST_"))
                && token
                    .chars()
                    .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')
        })
        .map(str::to_string)
        .unwrap_or_else(|| "AUTHORITY_CEREMONY_TOOL_FAILED".to_string())
}

fn authority_ceremony_execute(
    config: &SupervisorConfig,
    state: &SupervisorState,
    request: AuthorityCeremonyRequest,
) -> AuthorityCeremonyProgress {
    authority_ceremony_execute_with_context(config, state, request, None, None, None)
}

fn authority_ceremony_execute_with_context(
    config: &SupervisorConfig,
    state: &SupervisorState,
    request: AuthorityCeremonyRequest,
    operation_id: Option<&str>,
    correlation_id: Option<&str>,
    queue_progress: Option<&dyn Fn(&str, &str, Option<&str>)>,
) -> AuthorityCeremonyProgress {
    let journal_path = authority_ceremony_journal_path(config, &request.ceremony_id);
    if journal_path.is_file() {
        if let Ok(existing) = serde_json::from_slice::<AuthorityCeremonyProgress>(
            &fs::read(&journal_path).unwrap_or_default(),
        ) {
            let retrying_same_failed_operation = existing.state == "FAILED"
                && operation_id
                    .zip(existing.operation_id.as_deref())
                    .is_some_and(|(current, recorded)| current == recorded);
            if !retrying_same_failed_operation {
            return AuthorityCeremonyProgress {
                operation_id: operation_id
                    .map(str::to_string)
                    .or(existing.operation_id),
                correlation_id: correlation_id
                    .map(str::to_string)
                    .or(existing.correlation_id),
                ..existing
            };
            }
        }
    }
    let mut progress = authority_ceremony_preflight(config, state, request.clone());
    progress.operation_id = operation_id.map(str::to_string);
    progress.correlation_id = correlation_id.map(str::to_string);
    let report = |status: &str, step: &str, output: Option<&str>| {
        if let Some(queue_progress) = queue_progress {
            queue_progress(status, step, output);
        }
    };
    report(
        "validating",
        "authority_preflight",
        progress.code.as_deref(),
    );
    if progress.code.is_some() {
        return progress;
    }
    if !request.owner_confirmation {
        progress.state = "BLOCKED".into();
        progress.code = Some("AUTHORITY_OWNER_CONFIRMATION_REQUIRED".into());
        return progress;
    }
    if let Err(error) = fs::create_dir_all(&config.authority_data_root) {
        progress.state = "FAILED".into();
        progress.code = Some(format!("AUTHORITY_CEREMONY_STORAGE_FAILED: {error}"));
        return progress;
    }
    if let Err(error) = fs::create_dir_all(&config.authority_ceremony_lock_root) {
        progress.state = "FAILED".into();
        progress.code = Some(format!("AUTHORITY_CEREMONY_LOCK_STORAGE_FAILED: {error}"));
        return progress;
    }
    let lock_path = authority_ceremony_lock_path(config);
    let lock = match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            progress.state = "BLOCKED".into();
            progress.code = Some(classify_existing_ceremony_lock(&lock_path));
            return progress;
        }
        Err(error) => {
            progress.state = "FAILED".into();
            progress.code = Some(classify_write_probe_error(&error).into());
            return progress;
        }
    };
    let result = (|| {
        let lock_metadata = serde_json::json!({
            "schema": 1,
            "ceremonyId": &request.ceremony_id,
            "operationId": operation_id,
            "correlationId": correlation_id,
            "pid": std::process::id(),
            "startedAt": unix_timestamp(),
        });
        let lock_bytes = serde_json::to_vec(&lock_metadata)
            .map_err(|_| "AUTHORITY_CEREMONY_LOCK_SERIALIZE_FAILED".to_string())?;
        let mut lock = lock;
        lock.write_all(&lock_bytes)
            .and_then(|_| lock.sync_all())
            .map_err(|error| classify_write_probe_error(&error).to_string())?;
        drop(lock);
        progress.state = "PREPARING_CUSTODY".into();
        report("staging", "authority_lock_acquired", None);
        write_json_atomic(&journal_path, &progress)?;
        let (offline_root, recovery_dir, online_keys, state_path) =
            validate_authority_ceremony_request(config, &request)?;
        fs::create_dir_all(&offline_root)
            .map_err(|_| "AUTHORITY_OFFLINE_DIR_FAILED".to_string())?;
        let offline_sealing = authority_ceremony_offline_sealing_key_path(&offline_root);
        write_sealing_key(&offline_sealing, "offline_root")?;
        write_sealing_key(
            &config.authority_online_sealing_key_file,
            "online_authority",
        )?;
        report("staging", "authority_sealing_material_prepared", None);
        let bundle_path = authority_ceremony_paths(config).2;
        report("executing", "authority_tool_started", None);
        let output = Command::new(&config.authority_ceremony_binary)
            .args([
                "--offline-key-dir",
                offline_root.to_string_lossy().as_ref(),
                "--online-key-dir",
                online_keys.to_string_lossy().as_ref(),
                "--offline-sealing-key-file",
                offline_sealing.to_string_lossy().as_ref(),
                "--online-sealing-key-file",
                config
                    .authority_online_sealing_key_file
                    .to_string_lossy()
                    .as_ref(),
                "--state-out",
                state_path.to_string_lossy().as_ref(),
                "--trust-bundle-out",
                bundle_path.to_string_lossy().as_ref(),
                "--root-authority-id",
                "actium-product-root-v1",
                "--confirm",
                AUTHORITY_CEREMONY_CONFIRMATION,
            ])
            .stdin(Stdio::null())
            .output()
            .map_err(|_| "AUTHORITY_CEREMONY_EXECUTION_FAILED:reason=AUTHORITY_CEREMONY_TOOL_UNAVAILABLE".to_string())?;
        if !output.status.success() {
            let exit_code = output.status.code().unwrap_or(-1);
            let reason = safe_authority_ceremony_tool_failure(&output.stderr);
            return Err(format!(
                "AUTHORITY_CEREMONY_EXECUTION_FAILED:exit_code={exit_code}:reason={reason}"
            ));
        }
        report("promoting", "authority_tool_completed", None);
        let (_, bundle, root_fingerprint, digest, subordinate_count, public_only_count) =
            load_ceremony_outputs(config)?;
        // Persist the verified material metadata before exporting recovery. If
        // the removable/offline destination is unavailable, the journal still
        // contains enough information for an explicit recovery retry.
        progress.state = "MATERIAL_VERIFIED".into();
        progress.root_key_id = Some(bundle.signing_key_id.clone());
        progress.root_fingerprint = Some(root_fingerprint.clone());
        progress.trust_bundle_path = Some(bundle_path.to_string_lossy().into_owned());
        progress.trust_bundle_digest = Some(digest.clone());
        progress.trust_epoch = Some(bundle.bundle.trust_epoch);
        progress.subordinate_count = subordinate_count;
        progress.public_only_key_count = public_only_count;
        progress.authority_service_state = "UNINITIALIZED".into();
        progress.updated_at = unix_timestamp();
        write_json_atomic(&journal_path, &progress)?;
        let recovery_path = export_recovery(
            config,
            &request.ceremony_id,
            &offline_root,
            &recovery_dir,
            &root_fingerprint,
        )?;
        report("promoting", "authority_recovery_exported", None);
        assign_authority_service_access(&config.authority_online_sealing_key_file)?;
        assign_authority_service_outputs(&online_keys, &state_path, &bundle_path)?;
        progress.state = "EXECUTED".into();
        progress.recovery_path = Some(recovery_path.to_string_lossy().into_owned());
        progress.recovery_status = "VERIFIED".into();
        progress.updated_at = unix_timestamp();
        write_json_atomic(&journal_path, &progress)?;
        report(
            "promoting",
            "authority_ceremony_executed",
            Some("public material verified; activation remains Owner-controlled"),
        );
        Ok::<(), String>(())
    })();
    let _ = fs::remove_file(&lock_path);
    if let Err(error) = result {
        progress.state = "FAILED".into();
        progress.code = Some(error);
        progress.updated_at = unix_timestamp();
        let _ = write_json_atomic(&journal_path, &progress);
    }
    progress
}

fn authority_ceremony_export_recovery(
    config: &SupervisorConfig,
    state: &SupervisorState,
    ceremony_id: &str,
) -> Result<AuthorityCeremonyProgress, String> {
    let journal_path = authority_ceremony_journal_path(config, ceremony_id);
    let mut progress: AuthorityCeremonyProgress = serde_json::from_slice(
        &fs::read(&journal_path).map_err(|_| "AUTHORITY_CEREMONY_NOT_FOUND".to_string())?,
    )
    .map_err(|_| "AUTHORITY_CEREMONY_JOURNAL_INVALID".to_string())?;
    let offline = PathBuf::from(&progress.offline_root_dir);
    let recovery = PathBuf::from(&progress.recovery_dir);
    let root_fingerprint = progress
        .root_fingerprint
        .clone()
        .ok_or_else(|| "AUTHORITY_TRUST_ROOT_MISSING".to_string())?;
    let target = export_recovery(config, ceremony_id, &offline, &recovery, &root_fingerprint)?;
    progress.recovery_path = Some(target.to_string_lossy().into_owned());
    progress.recovery_status = "VERIFIED".into();
    progress.trust_store_state = state
        .trust_store
        .lock()
        .map(|store| store.status().state)
        .unwrap_or_else(|_| "UNKNOWN".into());
    progress.updated_at = unix_timestamp();
    write_json_atomic(&journal_path, &progress)?;
    Ok(progress)
}

fn restart_authority_service(config: &SupervisorConfig) -> Result<String, String> {
    let run = |args: &[&str]| -> Result<(), String> {
        let mut command = Command::new(&config.systemctl_path);
        command
            .args(args)
            .env("ACTIUM_SYSTEMD_ROOT", &config.systemd_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = command
            .status()
            .map_err(|_| "AUTHORITY_SERVICE_CONTROL_FAILED".to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("AUTHORITY_SERVICE_CONTROL_FAILED".into())
        }
    };
    run(["daemon-reload"].as_slice())?;
    run(["restart", &config.authority_service_name].as_slice())?;
    run(["is-active", "--quiet", &config.authority_service_name].as_slice())?;
    let address = "127.0.0.1:19443"
        .parse()
        .map_err(|_| "AUTHORITY_SERVICE_HEALTH_UNAVAILABLE".to_string())?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))
        .map_err(|_| "AUTHORITY_SERVICE_HEALTH_UNAVAILABLE".to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|_| "AUTHORITY_SERVICE_HEALTH_UNAVAILABLE".to_string())?;
    let mut response = vec![0u8; 8192];
    let length = stream
        .read(&mut response)
        .map_err(|_| "AUTHORITY_SERVICE_HEALTH_UNAVAILABLE".to_string())?;
    let body = String::from_utf8_lossy(&response[..length]);
    if !body.contains("\"authorityState\":\"INITIALIZED\"") {
        return Err("AUTHORITY_SERVICE_NOT_INITIALIZED".into());
    }
    Ok("INITIALIZED".into())
}

fn authority_ceremony_activate(
    config: &SupervisorConfig,
    state: &SupervisorState,
    ceremony_id: &str,
    expected_root_fingerprint: &str,
    owner_confirmation: bool,
) -> Result<AuthorityCeremonyProgress, String> {
    if config.authority_ceremony_mode == "fixture" {
        return Err("AUTHORITY_CEREMONY_FIXTURE_ACTIVATION_FORBIDDEN".into());
    }
    if !owner_confirmation {
        return Err("AUTHORITY_OWNER_CONFIRMATION_REQUIRED".into());
    }
    let journal_path = authority_ceremony_journal_path(config, ceremony_id);
    let mut progress: AuthorityCeremonyProgress = serde_json::from_slice(
        &fs::read(&journal_path).map_err(|_| "AUTHORITY_CEREMONY_NOT_FOUND".to_string())?,
    )
    .map_err(|_| "AUTHORITY_CEREMONY_JOURNAL_INVALID".to_string())?;
    if progress.recovery_status != "VERIFIED" {
        return Err("AUTHORITY_RECOVERY_REQUIRED".into());
    }
    let (_, bundle, root_fingerprint, digest, subordinate_count, public_only_count) =
        load_ceremony_outputs(config)?;
    if root_fingerprint != expected_root_fingerprint.trim()
        || progress.root_fingerprint.as_deref() != Some(expected_root_fingerprint.trim())
    {
        return Err("AUTHORITY_ROOT_FINGERPRINT_MISMATCH".into());
    }
    let trust_status = {
        let mut trust_store = state
            .trust_store
            .lock()
            .map_err(|_| "TRUST_STORE_LOCK_FAILED".to_string())?;
        trust_store.install_from_owner_ceremony(
            bundle.clone(),
            expected_root_fingerprint,
            true,
            unix_timestamp(),
        )?
    };
    let service_state = restart_authority_service(config)?;
    progress.state = "ACTIVATED".into();
    progress.code = None;
    progress.root_key_id = Some(bundle.signing_key_id);
    progress.root_fingerprint = Some(root_fingerprint);
    progress.trust_bundle_digest = Some(digest);
    progress.trust_epoch = Some(bundle.bundle.trust_epoch);
    progress.subordinate_count = subordinate_count;
    progress.public_only_key_count = public_only_count;
    progress.authority_service_state = service_state;
    progress.trust_store_state = trust_status.state;
    progress.updated_at = unix_timestamp();
    write_json_atomic(&journal_path, &progress)?;
    Ok(progress)
}

fn verify_schema3_payload(path: &Path) -> Result<(), String> {
    match verify_payload(path)? {
        VerifiedPayload::Schema3(manifest) => {
            println!(
                "Payload {} schema 3 verificado: {}.",
                manifest.release_version, manifest.tree_sha256
            );
            Ok(())
        }
        VerifiedPayload::LegacyUnverified { .. } => {
            Err("Supervisor rechazo un payload legacy-unverified.".to_string())
        }
    }
}

fn run_self_test() -> Result<(), String> {
    let key = b"actium-supervisor-self-test-key-0001";
    let request = SupervisorRequestEnvelope::signed(SupervisorCommand::Ping, key)?;
    request.verify(key, request.issued_at_unix_seconds)?;
    let mut frame = Vec::new();
    write_framed_json(&mut frame, &request)?;
    let decoded: SupervisorRequestEnvelope = read_framed_json(&mut std::io::Cursor::new(frame))?;
    if decoded != request {
        return Err("El framing IPC no preservo la solicitud.".to_string());
    }
    let root = std::env::temp_dir().join(format!("actium-supervisor-self-test-{}", Uuid::new_v4()));
    let signer = AttestationSigner::load_or_create(root.join("attestation-identity.key"))?;
    let signed = signer.sign(MaterialAttestationStatement {
        host_id: Uuid::new_v4().to_string(),
        deployment_id: Uuid::new_v4().to_string(),
        sequence: 1,
        generation: 1,
        runtime_release: Some("self-test".to_string()),
        payload_digest: Some("a".repeat(64)),
        material_digest: "b".repeat(64),
        observed_at: "2026-08-13T00:00:00Z".to_string(),
        runtime_units: Vec::new(),
        fabric: None,
        journal_id: String::new(),
        attestation_identity_id: String::new(),
        identity_epoch: 0,
        release_revision: 0,
        topology_digest: String::new(),
        configuration_digest: String::new(),
        observation_started_at: String::new(),
        observation_completed_at: String::new(),
        journal_chain: Default::default(),
    })?;
    if signed.algorithm != "Ed25519" || !signed.key_id.starts_with("sha256:") {
        return Err("La identidad Ed25519 de atestacion no supero self-test.".to_string());
    }
    let journal = OperationJournal::open(root.join("operations.sqlite3"))?;
    let now = unix_timestamp().to_string();
    let operation = JournalOperation {
        id: Uuid::new_v4().to_string(),
        idempotency_key: "self-test:status".to_string(),
        actor: "self-test".to_string(),
        target_node_id: "self-test".to_string(),
        install_dir: "/srv/actium-data/nodes/self-test".to_string(),
        node_label: "Self test".to_string(),
        terminal_id: None,
        action: "status".to_string(),
        requested_release: None,
        metadata_json: None,
        state: "queued".to_string(),
        queued_at: now.clone(),
        started_at: None,
        finished_at: None,
        current_step: "queued".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    };
    journal.enqueue(&operation)?;
    if journal.claim_next_queued(&now)?.is_none() {
        return Err("El journal no reclamo la operacion de prueba.".to_string());
    }
    journal.recover_interrupted(&now)?;
    let recovered = journal.list(1)?;
    if recovered.first().map(|item| item.state.as_str()) != Some("interrupted") {
        return Err("El recovery durable no marco interrupted.".to_string());
    }
    let _ = fs::remove_dir_all(root);
    println!(
        "Supervisor {SUPERVISOR_VERSION}: IPC autenticado, Ed25519, framing y recovery durable OK."
    );
    Ok(())
}

struct SupervisorState {
    config: SupervisorConfig,
    key: Vec<u8>,
    journal: OperationJournal,
    runtime: RuntimeOperator,
    nonces: Mutex<HashMap<String, u64>>,
    recovered_operations: usize,
    storage_signer: AttestationSigner,
    trust_store: Mutex<trust_store::SupervisorTrustStore>,
}

#[cfg(unix)]
fn bind_socket(config: &SupervisorConfig) -> Result<UnixListener, String> {
    if config.socket_path.exists() {
        match std::os::unix::net::UnixStream::connect(&config.socket_path) {
            Ok(_) => {
                return Err(format!(
                    "Ya existe un Supervisor activo en {}.",
                    config.socket_path.display()
                ))
            }
            Err(_) => fs::remove_file(&config.socket_path).map_err(|error| {
                format!(
                    "No se pudo retirar el socket obsoleto {}: {error}",
                    config.socket_path.display()
                )
            })?,
        }
    }
    let listener = UnixListener::bind(&config.socket_path).map_err(|error| {
        format!(
            "No se pudo crear el socket {}: {error}",
            config.socket_path.display()
        )
    })?;
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660))
        .map_err(|error| format!("No se pudo aplicar modo 0660 al socket: {error}"))?;
    let group = Group::from_name(&config.operator_group)
        .map_err(|error| format!("No se pudo resolver el grupo: {error}"))?
        .ok_or_else(|| format!("El grupo {} no existe.", config.operator_group))?;
    chown(
        &config.socket_path,
        None,
        Some(Gid::from_raw(group.gid.as_raw())),
    )
    .map_err(|error| format!("No se pudo asignar el grupo del socket: {error}"))?;
    Ok(listener)
}

fn serve_request(stream: &mut (impl Read + Write), state: &SupervisorState) -> Result<(), String> {
    let request: SupervisorRequestEnvelope = read_framed_json(stream)?;
    let request_id = request.request_id.clone();
    let reply = match authenticate_request(&request, state) {
        Ok(()) => dispatch(request.command, state).unwrap_or_else(|error| SupervisorReply::Error {
            code: "SUPERVISOR_COMMAND_FAILED".to_string(),
            message: redact_sensitive(&error),
        }),
        Err(error) => SupervisorReply::Error {
            code: "IPC_AUTHENTICATION_FAILED".to_string(),
            message: error,
        },
    };
    let response = SupervisorResponseEnvelope::signed(request_id, reply, &state.key)?;
    write_framed_json(stream, &response)
}

#[cfg(unix)]
fn supervisor_endpoint(config: &SupervisorConfig) -> PathBuf {
    config.socket_path.clone()
}

#[cfg(windows)]
fn supervisor_endpoint(config: &SupervisorConfig) -> PathBuf {
    PathBuf::from(&config.pipe_name)
}

#[cfg(unix)]
fn serve_ipc(
    state: Arc<SupervisorState>,
    config: &SupervisorConfig,
    shutdown: Arc<AtomicBool>,
    _service_mode: bool,
) -> Result<(), String> {
    let listener = bind_socket(config)?;
    log_message(format!(
        "Actium Node Supervisor {} escuchando en {} (canal {}).",
        SUPERVISOR_VERSION,
        config.socket_path.display(),
        config.product_channel
    ));
    listener.set_nonblocking(true).map_err(|error| {
        format!("No se pudo configurar el socket en modo no bloqueante: {error}")
    })?;
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let shared = state.clone();
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
                    if let Err(error) = serve_request(&mut stream, &shared) {
                        log_message(format!("Solicitud IPC rechazada: {error}"));
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => log_message(format!("No se pudo aceptar conexion IPC: {error}")),
        }
    }
    let _ = fs::remove_file(&config.socket_path);
    Ok(())
}

#[cfg(windows)]
fn serve_ipc(
    state: Arc<SupervisorState>,
    config: &SupervisorConfig,
    shutdown: Arc<AtomicBool>,
    service_mode: bool,
) -> Result<(), String> {
    use interprocess::{
        local_socket::{prelude::*, GenericNamespaced, ListenerNonblockingMode, ListenerOptions},
        os::windows::{local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor},
    };
    use widestring::U16CString;

    let name = config
        .pipe_name
        .as_str()
        .to_ns_name::<GenericNamespaced>()
        .map_err(|error| format!("Nombre de named pipe invalido: {error}"))?;
    let sddl = U16CString::from_str(&config.pipe_sddl)
        .map_err(|error| format!("SDDL del named pipe invalido: {error}"))?;
    let descriptor = SecurityDescriptor::deserialize(&sddl)
        .map_err(|error| format!("No se pudo materializar el ACL del named pipe: {error}"))?;
    let listener = ListenerOptions::new()
        .name(name)
        .security_descriptor(descriptor)
        .nonblocking(ListenerNonblockingMode::Accept)
        .create_sync()
        .map_err(|error| {
            format!(
                "No se pudo crear el named pipe {}: {error}",
                config.pipe_name
            )
        })?;
    log_message(format!(
        "Actium Node Supervisor {} escuchando en \\\\.\\pipe\\{} (canal {}, modo {}).",
        SUPERVISOR_VERSION,
        config.pipe_name,
        config.product_channel,
        if service_mode {
            "Windows Service"
        } else {
            "consola"
        }
    ));
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(mut stream) => {
                let shared = state.clone();
                thread::spawn(move || {
                    let _ = stream.set_recv_timeout(Some(Duration::from_secs(30)));
                    let _ = stream.set_send_timeout(Some(Duration::from_secs(30)));
                    if let Err(error) = serve_request(&mut stream, &shared) {
                        log_message(format!("Solicitud IPC rechazada: {error}"));
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                log_message(format!("No se pudo aceptar conexion named pipe: {error}"));
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Ok(())
}

fn authenticate_request(
    request: &SupervisorRequestEnvelope,
    state: &SupervisorState,
) -> Result<(), String> {
    let now = unix_timestamp();
    request.verify(&state.key, now)?;
    let mut nonces = state
        .nonces
        .lock()
        .map_err(|_| "El registro antireplay no esta disponible.".to_string())?;
    nonces.retain(|_, issued_at| now.saturating_sub(*issued_at) <= 120);
    if nonces.contains_key(&request.nonce) {
        return Err("Nonce IPC reutilizado; solicitud rechazada por antireplay.".to_string());
    }
    nonces.insert(request.nonce.clone(), request.issued_at_unix_seconds);
    Ok(())
}

fn dispatch(
    command: SupervisorCommand,
    state: &SupervisorState,
) -> Result<SupervisorReply, String> {
    match command {
        SupervisorCommand::Ping => Ok(SupervisorReply::Pong {
            supervisor_version: SUPERVISOR_VERSION.to_string(),
            recovered_operations: state.recovered_operations,
            protocol_version: actium_node_core::IPC_PROTOCOL_VERSION,
            features: actium_node_core::IPC_FEATURES
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            source_commit: Some(actium_node_core::build_info::SOURCE_COMMIT.to_string()),
            build_id: Some(actium_node_core::build_info::BUILD_ID.to_string()),
            binary_sha256: current_binary_sha256(),
        }),
        SupervisorCommand::ListOperations { limit } => Ok(SupervisorReply::Operations(
            state.journal.list(limit.clamp(1, 500))?,
        )),
        SupervisorCommand::CancelOperation { operation_id } => {
            Ok(SupervisorReply::Operation(Box::new(
                state
                    .journal
                    .cancel_queued(&operation_id, &unix_timestamp().to_string())?,
            )))
        }
        SupervisorCommand::MutationStatus => Ok(SupervisorReply::MutationStatus(
            state
                .journal
                .mutation_status(&unix_timestamp().to_string())?,
        )),
        SupervisorCommand::HostReadiness => {
            Ok(SupervisorReply::HostReadiness(host_readiness(state)?))
        }
        SupervisorCommand::NetworkInventory => {
            Ok(SupervisorReply::NetworkInventory(network_inventory()?))
        }
        SupervisorCommand::NodeRuntimeSummary { install_dir } => {
            Ok(SupervisorReply::NodeRuntimeSummary(
                state.runtime.runtime_summary(Path::new(&install_dir))?,
            ))
        }
        SupervisorCommand::RuntimeUnitInventory { install_dir } => {
            Ok(SupervisorReply::RuntimeUnitInventory(
                state
                    .runtime
                    .runtime_unit_inventory(Path::new(&install_dir))?,
            ))
        }
        SupervisorCommand::ExecuteRuntimeUnit(request) => Ok(SupervisorReply::RuntimeAction(
            state.runtime.execute_runtime_unit(&request)?,
        )),
        SupervisorCommand::CommissionNode(request) => Ok(SupervisorReply::RuntimeAction(
            execute_commission_journaled(state, request)?,
        )),
        SupervisorCommand::PersistConfiguration(request) => Ok(SupervisorReply::RuntimeAction(
            execute_configuration_write_journaled(state, request)?,
        )),
        SupervisorCommand::HealthGate { install_dir } => Ok(SupervisorReply::RuntimeAction(
            state.runtime.require_health(Path::new(&install_dir))?,
        )),
        SupervisorCommand::ExecuteAction {
            install_dir,
            action,
        } => Ok(SupervisorReply::RuntimeAction(
            execute_synchronous_journaled(state, &install_dir, &action)?,
        )),
        SupervisorCommand::ProjectAudit { install_dir } => Ok(SupervisorReply::ProjectAudit(
            state.runtime.project_audit(Path::new(&install_dir))?,
        )),
        SupervisorCommand::TelemetryAudit { install_dir } => Ok(SupervisorReply::Json {
            value: state.runtime.telemetry_audit(Path::new(&install_dir))?,
        }),
        SupervisorCommand::NodeAgentRuntime { install_dir } => Ok(SupervisorReply::Json {
            value: state.runtime.node_agent_runtime(Path::new(&install_dir))?,
        }),
        SupervisorCommand::EnqueueAuthorityCeremony(request) => Ok(SupervisorReply::Operation(
            Box::new(enqueue_authority_ceremony(state, request)?),
        )),
        SupervisorCommand::EnqueueOperation(request) => {
            RuntimeOperator::validate_action(&request.action)?;
            let path = state
                .runtime
                .validate_operation_target(Path::new(&request.install_dir))?;
            if request.target_node_id.trim().is_empty()
                || request.target_node_id.len() > 240
                || request.node_label.len() > 160
                || request.action.len() > 48
            {
                return Err("Solicitud de operacion fuera de limites.".to_string());
            }
            let queued_at = unix_timestamp().to_string();
            let operation = JournalOperation {
                id: Uuid::new_v4().to_string(),
                idempotency_key: format!(
                    "{}:{}",
                    path.to_string_lossy().to_ascii_lowercase(),
                    request.action
                ),
                actor: "local-ipc".to_string(),
                target_node_id: request.target_node_id,
                install_dir: path.to_string_lossy().into_owned(),
                node_label: request.node_label,
                terminal_id: request.terminal_id,
                action: request.action.clone(),
                requested_release: request.requested_release,
                metadata_json: None,
                state: "queued".to_string(),
                queued_at,
                started_at: None,
                finished_at: None,
                current_step: "queued_by_supervisor".to_string(),
                output_redacted: String::new(),
                recovery_policy: if request.action == "update" {
                    "rollback_to_lkg"
                } else {
                    "inspect_then_retry"
                }
                .to_string(),
                error_code: None,
                attempt_count: 0,
                lease_expires_at: None,
            };
            Ok(SupervisorReply::Operation(Box::new(
                state.journal.enqueue(&operation)?,
            )))
        }
        SupervisorCommand::EnqueueMaterial(request) => Ok(SupervisorReply::Operation(Box::new(
            enqueue_material(state, request)?,
        ))),
        SupervisorCommand::GetMaterialState(request) => get_material_state(state, request),
        SupervisorCommand::ReconcileMaterial(request) => Ok(SupervisorReply::Operation(Box::new(
            enqueue_material_reconcile(state, request)?,
        ))),
        SupervisorCommand::ExecuteConnectivityOperation(request) => {
            Ok(SupervisorReply::ConnectivityOperationResult(Box::new(
                execute_connectivity_operation(state, request)?,
            )))
        }
        SupervisorCommand::HostIdentity => Ok(SupervisorReply::HostIdentity {
            identity: actium_node_core::load_host_identity(&state.config.host_identity_root)?,
        }),
        SupervisorCommand::TrustStoreStatus => Ok(SupervisorReply::Json {
            value: serde_json::to_string(
                &state
                    .trust_store
                    .lock()
                    .map_err(|_| "TRUST_STORE_LOCK_FAILED".to_string())?
                    .status(),
            )
            .map_err(|_| "TRUST_STORE_STATUS_SERIALIZE_FAILED".to_string())?,
        }),
        SupervisorCommand::TrustStoreInstall { bundle } => {
            let status = state
                .trust_store
                .lock()
                .map_err(|_| "TRUST_STORE_LOCK_FAILED".to_string())?
                .install(bundle, unix_timestamp())?;
            Ok(SupervisorReply::Json {
                value: serde_json::to_string(&status)
                    .map_err(|_| "TRUST_STORE_STATUS_SERIALIZE_FAILED".to_string())?,
            })
        }
        SupervisorCommand::AuthorityCeremonyPreflight(request) => {
            Ok(SupervisorReply::AuthorityCeremony(
                authority_ceremony_preflight(&state.config, state, request),
            ))
        }
        SupervisorCommand::AuthorityCeremonyPathPreflight(request) => {
            Ok(SupervisorReply::AuthorityCeremonyPath(
                authority_ceremony_path_preflight(&state.config, request),
            ))
        }
        SupervisorCommand::AuthorityCeremonyExecute(request) => {
            Ok(SupervisorReply::AuthorityCeremony(
                authority_ceremony_execute(&state.config, state, request),
            ))
        }
        SupervisorCommand::AuthorityCeremonyExportRecovery { ceremony_id } => {
            Ok(SupervisorReply::AuthorityCeremony(
                authority_ceremony_export_recovery(&state.config, state, &ceremony_id)?,
            ))
        }
        SupervisorCommand::AuthorityCeremonyActivate {
            ceremony_id,
            expected_root_fingerprint,
            owner_confirmation,
        } => Ok(SupervisorReply::AuthorityCeremony(
            authority_ceremony_activate(
                &state.config,
                state,
                &ceremony_id,
                &expected_root_fingerprint,
                owner_confirmation,
            )?,
        )),
        SupervisorCommand::AuthorityCeremonyStatus { ceremony_id } => {
            let path = authority_ceremony_journal_path(
                &state.config,
                &Uuid::parse_str(&ceremony_id)
                    .map_err(|_| "AUTHORITY_CEREMONY_ID_INVALID".to_string())?
                    .to_string(),
            );
            let progress: AuthorityCeremonyProgress = serde_json::from_slice(
                &fs::read(path).map_err(|_| "AUTHORITY_CEREMONY_NOT_FOUND".to_string())?,
            )
            .map_err(|_| "AUTHORITY_CEREMONY_JOURNAL_INVALID".to_string())?;
            Ok(SupervisorReply::AuthorityCeremony(progress))
        }
        SupervisorCommand::StorageDiscover => {
            Ok(SupervisorReply::StorageInventory(storage_discover()?))
        }
        SupervisorCommand::EnrollmentStatus => {
            let state = StorageGrantStore::open(storage_state_root(state))?.enrollment()?;
            let binding = state
                .enrolled
                .as_ref()
                .map(|authority| &authority.enrollment);
            Ok(SupervisorReply::EnrollmentStatus {
                enrolled: binding.is_some(),
                code: if binding.is_some() {
                    None
                } else {
                    Some("ENROLLMENT_REQUIRED".into())
                },
                host_id: binding.and_then(|value| value.host_id.clone()),
                site_id: binding.and_then(|value| value.site_id.clone()),
                organization_id: binding.map(|value| value.organization_id.clone()),
                deployment_id: binding.and_then(|value| value.deployment_id.clone()),
                binding_epoch: binding.map(|value| value.binding_epoch),
            })
        }
        SupervisorCommand::EnrollmentProof(request) => enrollment_proof(state, request),
        SupervisorCommand::EnrollmentApplySignedPackage(request) => {
            enrollment_apply(state, request)
        }
        SupervisorCommand::StorageGrantList => Ok(SupervisorReply::StorageGrantList {
            grants: StorageGrantStore::open(storage_state_root(state))?.grants()?,
        }),
        SupervisorCommand::StorageGrantPreflight(request) => storage_preflight(state, request),
        SupervisorCommand::StorageGrantApplySignedApproval(request) => {
            storage_apply(state, request)
        }
        SupervisorCommand::StorageTransportSignDiscovery(request) => {
            storage_sign_discovery(state, request)
        }
        SupervisorCommand::StorageTransportSignIntent { intent_id } => {
            storage_sign_intent(state, &intent_id)
        }
        SupervisorCommand::ExtensionInstall { source_path } => {
            let trust_store = state
                .trust_store
                .lock()
                .map_err(|_| "TRUST_STORE_LOCK_FAILED".to_string())?;
            let verifier = if let Some(bundle) = trust_store.bundle() {
                actium_node_core::ExtensionBundleVerifier::from_trust_bundle(bundle)?
            } else {
                // Explicit compatibility bridge for M2.2 installations that
                // have not received their first Trust Fabric bundle yet.
                actium_node_core::ExtensionBundleVerifier::from_trust_dir(
                    &state.config.extension_trust_root,
                )?
            };
            let summary = actium_node_core::install_extension_bundle(
                &state.config.extensions_root,
                Path::new(&source_path),
                &verifier,
            )?;
            Ok(SupervisorReply::ExtensionResult(summary))
        }
        SupervisorCommand::ExtensionActivate { product_id } => {
            let summary =
                actium_node_core::enable_extension(&state.config.extensions_root, &product_id)?;
            Ok(SupervisorReply::ExtensionResult(summary))
        }
        SupervisorCommand::ExtensionRollback { product_id } => {
            let trust_store = state
                .trust_store
                .lock()
                .map_err(|_| "TRUST_STORE_LOCK_FAILED".to_string())?;
            let verifier = if let Some(bundle) = trust_store.bundle() {
                actium_node_core::ExtensionBundleVerifier::from_trust_bundle(bundle)?
            } else {
                actium_node_core::ExtensionBundleVerifier::from_trust_dir(
                    &state.config.extension_trust_root,
                )?
            };
            Ok(SupervisorReply::ExtensionResult(
                actium_node_core::rollback_extension(
                    &state.config.extensions_root,
                    &product_id,
                    &verifier,
                )?,
            ))
        }
        SupervisorCommand::ExtensionSetEnabled {
            product_id,
            enabled,
        } => {
            let summary = if enabled {
                actium_node_core::enable_extension(&state.config.extensions_root, &product_id)?
            } else {
                actium_node_core::disable_extension(&state.config.extensions_root, &product_id)?
            };
            Ok(SupervisorReply::ExtensionResult(summary))
        }
        SupervisorCommand::ExtensionRemove { product_id } => {
            actium_node_core::remove_extension(&state.config.extensions_root, &product_id)?;
            Ok(SupervisorReply::Json {
                value: "removed".to_string(),
            })
        }
        SupervisorCommand::ExtensionStatus => Ok(SupervisorReply::ExtensionStatus(
            actium_node_core::load_extension_registry(&state.config.extensions_root),
        )),
        SupervisorCommand::RuntimeDescriptorSign { descriptor } => {
            sign_runtime_descriptor(state, descriptor)
        }
    }
}

fn host_readiness(state: &SupervisorState) -> Result<HostReadinessReport, String> {
    let observed_at = unix_timestamp();
    let state_root = storage_state_root(state);
    let identity_record = actium_node_core::load_host_identity(&state.config.host_identity_root)?;
    let identity = match identity_record.as_ref() {
        Some(value) => HostReadinessCheck::ready(format!("Host {} observado", value.host_code)),
        None => HostReadinessCheck::blocked(
            "HOST_IDENTITY_MISSING",
            "No existe identidad persistida del Host",
        ),
    };
    let store = StorageGrantStore::open(state_root)?;
    let enrollment = store.enrollment()?;
    let host_binding = enrollment
        .enrolled
        .as_ref()
        .and_then(|value| value.host_binding().ok());
    let site_binding = match enrollment.enrolled.as_ref() {
        Some(value)
            if host_binding
                .as_ref()
                .is_some_and(|binding| binding.verified) =>
        {
            HostReadinessCheck::ready(format!(
                "Enrollment firmado · binding_epoch={} organization={} site={} host_id={}",
                value.enrollment.binding_epoch,
                value.enrollment.organization_id,
                value.enrollment.site_id.as_deref().unwrap_or("—"),
                value.enrollment.host_id.as_deref().unwrap_or("UNKNOWN")
            ))
        }
        Some(_) => HostReadinessCheck::unknown(
            "HOST_BINDING_INVALID",
            "El EnrollmentPackage no pudo proyectarse como binding verificable",
        ),
        None => HostReadinessCheck::warning(
            "ENROLLMENT_REQUIRED",
            "El Host todavía no posee un EnrollmentPackage aceptado",
        ),
    };
    let supervisor = HostReadinessCheck::ready(format!(
        "Actium Node Supervisor {} · Supervisor signer key_id={}",
        SUPERVISOR_VERSION,
        state.storage_signer.key_id()
    ));
    let ipc = HostReadinessCheck::ready("IPC autenticado y atendiendo solicitudes");
    let mutation = state.journal.mutation_status(&observed_at.to_string())?;
    let mutation_arbiter = match mutation.state.as_str() {
        "blocked" => HostReadinessCheck::blocked(
            mutation
                .blocked_reason
                .clone()
                .unwrap_or_else(|| "MUTATION_BLOCKED".into()),
            "Existe una mutación recuperable que requiere reconciliación",
        ),
        "running" | "queued" => HostReadinessCheck::warning(
            "MUTATION_BUSY",
            format!(
                "{} activas · {} en cola",
                mutation.active_operations, mutation.queued_operations
            ),
        ),
        _ => HostReadinessCheck::ready("Arbitraje de mutaciones sin bloqueo actual"),
    };
    let runtime = if state.config.authorized_nodes_root.is_dir() {
        HostReadinessCheck::warning(
            "RUNTIME_WORKLOADS_DEFERRED",
            "La raíz de nodos es accesible; el health de workloads se consulta por Node Runtime",
        )
    } else {
        HostReadinessCheck::degraded(
            "RUNTIME_ROOT_MISSING",
            format!("No existe {}", state.config.authorized_nodes_root.display()),
        )
    };
    let mounts = storage_discover();
    let storage = match &mounts {
        Ok(values) if !values.is_empty() => {
            HostReadinessCheck::ready(format!("{} mounts canónicos", values.len()))
        }
        Ok(_) => HostReadinessCheck::degraded(
            "NO_DISCOVERY",
            "El Supervisor no publicó mounts canónicos",
        ),
        Err(error) => HostReadinessCheck::degraded("STORAGE_DISCOVERY_FAILED", error),
    };
    let grants = store.grants()?;
    let effective_grants = latest_effective_grants(&grants);
    let storage_grants = if effective_grants.is_empty() {
        HostReadinessCheck::warning(
            "STORAGE_GRANTS_EMPTY",
            "No hay grants aplicados para capacidades",
        )
    } else if effective_grants.iter().any(|grant| {
        matches!(
            grant.state.as_str(),
            "degraded" | "rollback" | "rolled_back"
        )
    }) {
        HostReadinessCheck::degraded(
            "STORAGE_GRANT_DEGRADED",
            "Existe una degradación vigente en un grant efectivo",
        )
    } else if effective_grants
        .iter()
        .any(|grant| matches!(grant.state.as_str(), "pending" | "approved"))
    {
        HostReadinessCheck::warning(
            "STORAGE_GRANT_PENDING",
            "Hay grants efectivos pendientes de aplicación o confirmación",
        )
    } else if effective_grants
        .iter()
        .all(|grant| matches!(grant.state.as_str(), "applied" | "committed"))
    {
        HostReadinessCheck::ready(format!(
            "{} grants efectivos aplicados/confirmados",
            effective_grants.len()
        ))
    } else {
        HostReadinessCheck::unknown(
            "STORAGE_GRANT_STATE_UNKNOWN",
            "Existe un estado de grant no reconocido por el contrato",
        )
    };
    let transactions = store.transactions()?;
    let effective_transactions = latest_effective_transactions(&transactions);
    let transactions_check = if effective_transactions
        .iter()
        .any(|value| matches!(value.phase.as_str(), "rollback" | "rolled_back"))
    {
        HostReadinessCheck::degraded(
            "STORAGE_ROLLBACK_ACTIVE",
            "La última transacción efectiva de un intent está en rollback",
        )
    } else if effective_transactions.iter().any(|value| {
        matches!(
            value.phase.as_str(),
            "pending" | "approved" | "apply" | "staging"
        )
    }) {
        HostReadinessCheck::warning(
            "STORAGE_TRANSACTION_PENDING",
            "Hay transacciones efectivas aún no confirmadas",
        )
    } else if effective_transactions
        .iter()
        .all(|value| matches!(value.phase.as_str(), "committed" | "confirm" | "confirmed"))
    {
        HostReadinessCheck::ready(format!(
            "{} transacciones efectivas confirmadas",
            effective_transactions.len()
        ))
    } else if effective_transactions.is_empty() {
        HostReadinessCheck::ready("No hay transacciones Storage efectivas")
    } else {
        HostReadinessCheck::unknown(
            "STORAGE_TRANSACTION_STATE_UNKNOWN",
            "Existe una fase de transacción no reconocida por el contrato",
        )
    };
    let signing_trust = match enrollment.enrolled.as_ref() {
        Some(value) => HostReadinessCheck::ready(format!(
            "Center authority {} · binding_epoch={}",
            value.center.kid, value.enrollment.binding_epoch
        )),
        None => {
            HostReadinessCheck::warning("SIGNING_TRUST_UNVERIFIED", "Sin autoridad Center enlazada")
        }
    };
    let center_approval_signer = effective_grants
        .iter()
        .find_map(|grant| {
            match (
                &grant.approval_signer_key_id,
                &grant.approval_signer_fingerprint,
            ) {
                (Some(key_id), Some(fingerprint)) => Some(HostReadinessCheck::ready(format!(
                    "Center approval verificado · key_id={} fingerprint={} at={}",
                    key_id,
                    fingerprint,
                    grant
                        .approval_verified_at_unix_seconds
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "UNKNOWN".into())
                ))),
                _ => None,
            }
        })
        .unwrap_or_else(|| {
            HostReadinessCheck::unknown(
                "SIGNING_APPROVAL_NOT_OBSERVED",
                "No se observó metadata persistida de un approval Center verificado",
            )
        });
    let attestation_path = state
        .config
        .journal_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("material-attestation.json");
    let material_attestation = match fs::read_to_string(&attestation_path) {
        Ok(contents) => match serde_json::from_str::<serde_json::Value>(&contents) {
            Ok(_) => HostReadinessCheck::ready(format!(
                "{} válido y legible",
                attestation_path.display()
            )),
            Err(_) => HostReadinessCheck::degraded(
                "MATERIAL_ATTESTATION_INVALID",
                format!("{} no contiene JSON válido", attestation_path.display()),
            ),
        },
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            HostReadinessCheck::degraded(
                "MATERIAL_ATTESTATION_PERMISSION_DENIED",
                format!("Permission denied: {}", attestation_path.display()),
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => HostReadinessCheck::warning(
            "MATERIAL_ATTESTATION_MISSING",
            format!("No existe {}", attestation_path.display()),
        ),
        Err(error) => HostReadinessCheck::degraded(
            "MATERIAL_ATTESTATION_READ_FAILED",
            format!("{}: {error}", attestation_path.display()),
        ),
    };
    let system = system_readiness();
    let clock = clock_readiness();
    let network = network_readiness();
    let nats = HostReadinessCheck::unknown(
        "NATS_DIAGNOSTIC_ONLY",
        "NATS se observa aparte y no bloquea Storage automáticamente",
    );
    let mut report = HostReadinessReport::from_checks(
        observed_at,
        [
            identity,
            site_binding,
            supervisor,
            ipc,
            mutation_arbiter,
            runtime,
            storage,
            storage_grants,
            transactions_check,
            signing_trust,
            center_approval_signer,
            material_attestation,
            system,
            clock,
            network,
            nats,
        ],
    );
    report.host_binding = host_binding;
    Ok(report)
}

fn system_readiness() -> HostReadinessCheck {
    let platform = std::env::consts::OS;
    let architecture = std::env::consts::ARCH;
    let cpu = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(0);
    #[cfg(unix)]
    {
        match std::process::Command::new("uname").args(["-srmo"]).output() {
            Ok(output) if output.status.success() && !output.stdout.is_empty() => {
                return HostReadinessCheck::ready(format!(
                    "{} · {} · cpu={}",
                    String::from_utf8_lossy(&output.stdout).trim(),
                    architecture,
                    cpu
                ));
            }
            Ok(_) => {
                return HostReadinessCheck::unknown(
                    "SYSTEM_OBSERVATION_UNAVAILABLE",
                    "uname no devolvió una observación válida",
                )
            }
            Err(error) => {
                return HostReadinessCheck::unknown(
                    "SYSTEM_OBSERVATION_UNAVAILABLE",
                    format!("No se pudo observar el sistema: {error}"),
                )
            }
        }
    }
    if platform.is_empty() || architecture.is_empty() || cpu == 0 {
        HostReadinessCheck::unknown(
            "SYSTEM_OBSERVATION_INCOMPLETE",
            "La observación del sistema no está completa",
        )
    } else {
        HostReadinessCheck::ready(format!("{} / {} · cpu={}", platform, architecture, cpu))
    }
}

fn clock_readiness() -> HostReadinessCheck {
    #[cfg(target_os = "linux")]
    {
        match std::process::Command::new("timedatectl")
            .args(["show", "--property=NTPSynchronized", "--value"])
            .output()
        {
            Ok(output) if output.status.success() => {
                match String::from_utf8_lossy(&output.stdout).trim() {
                    "yes" => HostReadinessCheck::ready("NTP sincronizado por timedatectl"),
                    "no" => HostReadinessCheck::warning(
                        "CLOCK_NOT_SYNCHRONIZED",
                        "timedatectl observó NTP no sincronizado",
                    ),
                    value if !value.is_empty() => HostReadinessCheck::unknown(
                        "CLOCK_SYNC_UNKNOWN",
                        format!("NTPSynchronized={value}"),
                    ),
                    _ => HostReadinessCheck::unknown(
                        "CLOCK_SYNC_UNKNOWN",
                        "timedatectl no expuso NTPSynchronized",
                    ),
                }
            }
            Ok(_) => HostReadinessCheck::unknown(
                "CLOCK_SYNC_UNAVAILABLE",
                "timedatectl no pudo observar el estado NTP",
            ),
            Err(error) => HostReadinessCheck::unknown(
                "CLOCK_SYNC_UNAVAILABLE",
                format!("No se pudo consultar NTP: {error}"),
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        HostReadinessCheck::unknown(
            "CLOCK_SYNC_UNAVAILABLE",
            "Este Supervisor no tiene un contrato NTP implementado",
        )
    }
}

fn network_readiness() -> HostReadinessCheck {
    let interfaces = match network_inventory() {
        Ok(values) if !values.is_empty() => values,
        Ok(_) => {
            return HostReadinessCheck::unknown(
                "NETWORK_INVENTORY_EMPTY",
                "No se observaron interfaces",
            )
        }
        Err(error) => return HostReadinessCheck::unknown("NETWORK_INVENTORY_FAILED", error),
    };
    let route = default_route_present();
    let dns = dns_observed();
    let center = center_reachable();
    let mut missing = Vec::new();
    if route == Some(false) {
        missing.push("default_route");
    }
    if dns == Some(false) {
        missing.push("dns");
    }
    if center == Some(false) {
        missing.push("center");
    }
    if !missing.is_empty() {
        return HostReadinessCheck::warning(
            "NETWORK_CONNECTIVITY_DEGRADED",
            format!(
                "{} interfaces; no verificadas: {}",
                interfaces.len(),
                missing.join(", ")
            ),
        );
    }
    if route.is_none() || dns.is_none() || center.is_none() {
        return HostReadinessCheck::unknown(
            "NETWORK_OBSERVATION_INCOMPLETE",
            format!(
                "{} interfaces; route/dns/Center no están completamente observables",
                interfaces.len()
            ),
        );
    }
    HostReadinessCheck::ready(format!(
        "{} interfaces · default route · DNS · Center alcanzable",
        interfaces.len()
    ))
}

#[cfg(target_os = "linux")]
fn default_route_present() -> Option<bool> {
    std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()
        .map(|output| output.status.success() && !output.stdout.is_empty())
}
#[cfg(not(target_os = "linux"))]
fn default_route_present() -> Option<bool> {
    None
}

#[cfg(target_os = "linux")]
fn dns_observed() -> Option<bool> {
    fs::read_to_string("/etc/resolv.conf").ok().map(|value| {
        value
            .lines()
            .any(|line| line.trim_start().starts_with("nameserver "))
    })
}
#[cfg(not(target_os = "linux"))]
fn dns_observed() -> Option<bool> {
    None
}

fn center_reachable() -> Option<bool> {
    let raw = std::env::var("ACTIUM_CENTER_BASE_URL")
        .or_else(|_| std::env::var("ACTIUM_CENTER_URL"))
        .ok()?;
    let authority = raw
        .split_once("://")
        .map(|(_, value)| value)
        .unwrap_or(raw.as_str())
        .split('/')
        .next()?;
    let (host, port) = authority
        .rsplit_once(':')
        .map(|(host, port)| (host, port.parse::<u16>().unwrap_or(443)))
        .unwrap_or((authority, 443));
    let address = (host, port).to_socket_addrs().ok()?.next()?;
    Some(TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_ok())
}

fn load_storage_transport_signer(config: &SupervisorConfig) -> Result<AttestationSigner, String> {
    let key_path = config
        .fabric_identity_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("attestation-identity.key");
    let metadata_path = key_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("attestation-identity.json");
    if metadata_path.is_file() {
        AttestationSigner::load_existing(key_path)
    } else {
        // This is the host-local Supervisor signing identity. It is not a Root
        // Authority key and never manufactures Center/owner approvals.
        AttestationSigner::load_or_create(key_path)
    }
}

fn validate_storage_transport_scope(
    state: &SupervisorState,
    scope: &StorageTransportScope,
) -> Result<actium_node_core::EnrolledAuthority, String> {
    if scope.client_id.trim().is_empty()
        || scope.organization_id.trim().is_empty()
        || scope.site_id.trim().is_empty()
        || scope.host_id.trim().is_empty()
        || scope.host_installation_id.trim().is_empty()
    {
        return Err("STORAGE_TRANSPORT_SCOPE_INVALID".into());
    }
    let store = StorageGrantStore::open(storage_state_root(state))?;
    let enrollment = store.enrollment()?.enrolled.ok_or("ENROLLMENT_REQUIRED")?;
    if scope.organization_id != enrollment.enrollment.organization_id
        || scope.host_installation_id != enrollment.enrollment.host_installation_id
    {
        return Err("STORAGE_TRANSPORT_SCOPE_INVALID".into());
    }
    if let Some(enrolled_site) = enrollment.enrollment.site_id.as_deref() {
        if enrolled_site != scope.site_id {
            return Err("STORAGE_TRANSPORT_SITE_MISMATCH".into());
        }
    }
    Ok(enrollment)
}

fn storage_sign_discovery(
    state: &SupervisorState,
    request: StorageTransportDiscoveryRequest,
) -> Result<SupervisorReply, String> {
    let _enrollment = validate_storage_transport_scope(state, &request.scope)?;
    let host_identity = actium_node_core::load_host_identity(&state.config.host_identity_root)?
        .ok_or("HOST_IDENTITY_MISSING")?;
    if host_identity.host_installation_id != request.scope.host_installation_id {
        return Err("STORAGE_TRANSPORT_HOST_MISMATCH".into());
    }
    let mounts = storage_discover()?;
    let observed_at = unix_timestamp();
    let report_generation = mounts
        .iter()
        .map(|mount| mount.report_generation)
        .max()
        .unwrap_or(observed_at);
    let snapshot_hash = discovery_snapshot_hash(&mounts);
    let idempotency_key = request
        .idempotency_key
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "discovery:{}:{}:{}",
                request.scope.host_installation_id, report_generation, snapshot_hash
            )
        });
    let payload = discovery_snapshot_payload(
        &mounts,
        request.scope.client_id.clone(),
        request.scope.organization_id.clone(),
        request.scope.site_id.clone(),
        request.scope.host_id.clone(),
        request.scope.host_installation_id.clone(),
        report_generation,
        observed_at,
        snapshot_hash,
        idempotency_key.clone(),
    );
    let envelope = sign_storage_transport(
        &state.storage_signer,
        StorageTransportMessageType::DiscoverySnapshot,
        request.scope,
        idempotency_key,
        serde_json::to_value(payload)
            .map_err(|error| format!("STORAGE_TRANSPORT_SERIALIZATION_FAILED: {error}"))?,
        observed_at,
    )?;
    Ok(SupervisorReply::StorageTransport { envelope })
}

fn storage_sign_intent(
    state: &SupervisorState,
    intent_id: &str,
) -> Result<SupervisorReply, String> {
    if intent_id.trim().is_empty() {
        return Err("STORAGE_INTENT_ID_REQUIRED".into());
    }
    let store = StorageGrantStore::open(storage_state_root(state))?;
    let enrollment_state = store.enrollment()?;
    let enrollment = enrollment_state.enrolled.ok_or("ENROLLMENT_REQUIRED")?;
    let preflight = store
        .preflights()?
        .into_iter()
        .find(|value| value.intent_id == intent_id)
        .ok_or("STORAGE_INTENT_NOT_FOUND")?;
    let binding_epoch = enrollment.center.binding_epoch;
    let now = unix_timestamp();
    let intent = StorageGrantIntent::from_preflight(&preflight, binding_epoch, now)?;
    if intent.organization_id != enrollment.enrollment.organization_id
        || intent.host_installation_id != enrollment.enrollment.host_installation_id
        || enrollment
            .enrollment
            .site_id
            .as_deref()
            .is_some_and(|site| site != intent.site_id)
    {
        return Err("STORAGE_TRANSPORT_SCOPE_INVALID".into());
    }
    let scope = StorageTransportScope {
        client_id: intent.client_id.clone(),
        organization_id: intent.organization_id.clone(),
        site_id: intent.site_id.clone(),
        host_id: intent.host_id.clone(),
        host_installation_id: intent.host_installation_id.clone(),
        deployment_id: Some(intent.deployment_id.clone()),
        capability: Some(intent.capability.clone()),
    };
    let envelope = sign_storage_transport(
        &state.storage_signer,
        StorageTransportMessageType::StorageGrantIntent,
        scope,
        intent.idempotency_key.clone(),
        serde_json::to_value(&intent)
            .map_err(|error| format!("STORAGE_TRANSPORT_SERIALIZATION_FAILED: {error}"))?,
        now,
    )?;
    Ok(SupervisorReply::StorageTransport { envelope })
}

fn sign_runtime_descriptor(
    state: &SupervisorState,
    descriptor: serde_json::Value,
) -> Result<SupervisorReply, String> {
    let object = descriptor
        .as_object()
        .ok_or_else(|| "RUNTIME_DESCRIPTOR_INVALID".to_string())?;
    if object.get("schema").and_then(serde_json::Value::as_str)
        != Some("actium-node-runtime-descriptor@1.0.0")
        || object.get("productId").and_then(serde_json::Value::as_str)
            != Some("actium-node-manager")
    {
        return Err("RUNTIME_DESCRIPTOR_CONTRACT_INVALID".to_string());
    }
    let host = object
        .get("host")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "RUNTIME_DESCRIPTOR_HOST_REQUIRED".to_string())?;
    let identity = actium_node_core::load_host_identity(&state.config.host_identity_root)?
        .ok_or_else(|| "HOST_IDENTITY_MISSING".to_string())?;
    if host
        .get("hostInstallationId")
        .and_then(serde_json::Value::as_str)
        != Some(identity.host_installation_id.as_str())
    {
        return Err("RUNTIME_DESCRIPTOR_HOST_MISMATCH".to_string());
    }
    let enrolled = StorageGrantStore::open(storage_state_root(state))?
        .enrollment()?
        .enrolled;
    if enrolled.is_none() {
        return Err("RUNTIME_DESCRIPTOR_TRUST_REQUIRED".to_string());
    }
    let signature = state.storage_signer.sign_canonical_value(&descriptor)?;
    let payload = URL_SAFE_NO_PAD.encode(actium_node_core::canonical_json(&descriptor)?.as_bytes());
    Ok(SupervisorReply::RuntimeDescriptorSigned {
        descriptor,
        payload,
        signature,
        signer_key_id: state.storage_signer.key_id(),
        public_key: state.storage_signer.public_key(),
    })
}

fn storage_state_root(state: &SupervisorState) -> PathBuf {
    state
        .config
        .journal_path
        .parent()
        .unwrap_or(Path::new("/var/lib/actium/node-manager"))
        .join("storage-grants")
}
fn enrollment_proof(
    state: &SupervisorState,
    r: actium_node_core::EnrollmentProofRequest,
) -> Result<SupervisorReply, String> {
    let ticket = r.ticket.trim();
    if ticket.len() != 47
        || !ticket.starts_with("hen_")
        || !ticket[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("HOST_ENROLLMENT_TICKET_INVALID".into());
    }
    let host = actium_node_core::load_host_identity(&state.config.host_identity_root)?
        .ok_or("ENROLLMENT_REQUIRED: identidad de host ausente")?;
    let challenge = &r.challenge;
    let now = unix_timestamp();
    let hash = Sha256::digest(ticket.as_bytes());
    let ticket_hash = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if challenge.schema_version != 1
        || challenge.purpose != "HOST_ENROLL"
        || challenge.ticket_hash != ticket_hash
        || challenge.host_installation_id != host.host_installation_id
        || challenge.binding_epoch == 0
        || challenge.environment.trim().is_empty()
        || challenge.nonce.trim().len() < 16
        || challenge.issued_at > now + 60
        || challenge.expires_at <= now
        || challenge.expires_at > challenge.issued_at + 300
    {
        return Err("HOST_ENROLLMENT_CHALLENGE_INVALID".into());
    }
    let claims = serde_json::json!({
        "schemaVersion":challenge.schema_version,
        "purpose":challenge.purpose,
        "ticketHash":challenge.ticket_hash,
        "clientId":challenge.client_id,
        "organizationId":challenge.organization_id,
        "siteId":challenge.site_id,
        "hostId":challenge.host_id,
        "hostInstallationId":challenge.host_installation_id,
        "supervisorPublicKey":state.storage_signer.public_key(),
        "bindingEpoch":challenge.binding_epoch,
        "nonce":challenge.nonce,
        "environment":challenge.environment,
        "issuedAt":challenge.issued_at,
        "expiresAt":challenge.expires_at
    });
    let payload = actium_node_core::canonical_json(&claims)?;
    let signature = state.storage_signer.sign_canonical_value(&claims)?;
    Ok(SupervisorReply::EnrollmentProof(
        actium_node_core::EnrollmentProofResponse {
            proof: actium_node_core::SignedEnvelope {
                payload: URL_SAFE_NO_PAD.encode(payload.as_bytes()),
                signature,
            },
            host_identity: host,
            supervisor_public_key: state.storage_signer.public_key(),
            supervisor_key_id: state.storage_signer.key_id(),
            binding_epoch: challenge.binding_epoch,
        },
    ))
}
fn enrollment_apply(
    state: &SupervisorState,
    r: actium_node_core::EnrollmentApplyRequest,
) -> Result<SupervisorReply, String> {
    let trust_bundle = state
        .trust_store
        .lock()
        .map_err(|_| "TRUST_STORE_LOCK_FAILED")?
        .bundle()
        .cloned()
        .ok_or("ENROLLMENT_REQUIRED: Trust Bundle no instalado")?;
    let host = actium_node_core::load_host_identity(&state.config.host_identity_root)?
        .ok_or("ENROLLMENT_REQUIRED: identidad de host ausente")?;
    if r.node_public_key != state.storage_signer.public_key()
        || r.challenge.host_installation_id != host.host_installation_id
    {
        return Err("HOST_ENROLLMENT_SUPERVISOR_KEY_OR_HOST_MISMATCH".into());
    }
    let proof = r.proof.ok_or("HOST_ENROLLMENT_PROOF_REQUIRED")?;
    let enrollment: actium_node_core::EnrollmentPackage = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&r.enrollment_package.payload)
            .map_err(|_| "ENROLLMENT_PACKAGE_INVALID")?,
    )
    .map_err(|_| "ENROLLMENT_PACKAGE_INVALID")?;
    let proof_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&proof.payload)
        .map_err(|_| "HOST_ENROLLMENT_PROOF_INVALID")?;
    let proof_value: actium_node_core::EnrollmentProofClaims =
        serde_json::from_slice(&proof_payload).map_err(|_| "HOST_ENROLLMENT_PROOF_INVALID")?;
    let expected = actium_node_core::EnrollmentProofClaims {
        schema_version: r.challenge.schema_version,
        purpose: r.challenge.purpose.clone(),
        ticket_hash: r.challenge.ticket_hash.clone(),
        client_id: r.challenge.client_id.clone(),
        organization_id: r.challenge.organization_id.clone(),
        site_id: r.challenge.site_id.clone(),
        host_id: r.challenge.host_id.clone(),
        host_installation_id: r.challenge.host_installation_id.clone(),
        supervisor_public_key: r.node_public_key.clone(),
        binding_epoch: r.challenge.binding_epoch,
        nonce: r.challenge.nonce.clone(),
        environment: r.challenge.environment.clone(),
        issued_at: r.challenge.issued_at,
        expires_at: r.challenge.expires_at,
    };
    if proof_value != expected
        || enrollment.enrollment_nonce != r.enrollment_nonce
        || enrollment.node_public_key != r.node_public_key
    {
        return Err("HOST_ENROLLMENT_PROOF_SCOPE_INVALID".into());
    }
    let store = StorageGrantStore::open(storage_state_root(state))?;
    let mut s = store.enrollment()?;
    if s.enrolled.is_some() || s.consumed_nonces.contains(&r.enrollment_nonce) {
        return Err("ENROLLMENT_REPLAY".into());
    }
    let enrolled = actium_node_core::enroll_with_trust_bundle(
        &trust_bundle,
        &r.center_bundle,
        &r.enrollment_package,
        &proof,
        &host.host_installation_id,
        &r.enrollment_nonce,
        &r.node_public_key,
        &expected,
        unix_timestamp(),
    )?;
    let package_digest = actium_node_core::signed_envelope_digest(&r.enrollment_package)?;
    let applied_at = unix_timestamp();
    let ack_claims = serde_json::json!({
        "schemaVersion":1,
        "purpose":"HOST_ENROLL_ACK",
        "ticketHash":proof_value.ticket_hash,
        "clientId":proof_value.client_id,
        "organizationId":proof_value.organization_id,
        "siteId":proof_value.site_id,
        "hostId":proof_value.host_id,
        "hostInstallationId":proof_value.host_installation_id,
        "supervisorPublicKey":state.storage_signer.public_key(),
        "supervisorKeyId":state.storage_signer.key_id(),
        "bindingEpoch":proof_value.binding_epoch,
        "enrollmentNonce":r.enrollment_nonce,
        "packageDigest":package_digest,
        "appliedAt":applied_at,
        "status":"applied"
    });
    let ack_payload = actium_node_core::canonical_json(&ack_claims)?;
    let ack_signature = state.storage_signer.sign_canonical_value(&ack_claims)?;
    // Persist the applied enrollment only after the signed ACK has been
    // produced successfully. A signer/storage failure must not make the Host
    // look enrolled without evidence that Center can verify.
    s.consumed_nonces.push(r.enrollment_nonce.clone());
    s.enrolled = Some(enrolled);
    store.save_enrollment(&s)?;
    Ok(SupervisorReply::EnrollmentAck(
        actium_node_core::EnrollmentAckResponse {
            ack: actium_node_core::SignedEnvelope {
                payload: URL_SAFE_NO_PAD.encode(ack_payload.as_bytes()),
                signature: ack_signature,
            },
            supervisor_public_key: state.storage_signer.public_key(),
            supervisor_key_id: state.storage_signer.key_id(),
            enrollment_nonce: r.enrollment_nonce,
            package_digest,
            binding_epoch: proof_value.binding_epoch,
        },
    ))
}
fn storage_preflight(
    state: &SupervisorState,
    r: actium_node_core::StoragePreflightRequest,
) -> Result<SupervisorReply, String> {
    let store = StorageGrantStore::open(storage_state_root(state))?;
    let enrollment = match store.enrollment()?.enrolled {
        Some(value) => value,
        None => {
            return Ok(SupervisorReply::StoragePreflight {
                code: "ENROLLMENT_REQUIRED".into(),
                canonical_path: None,
                message: "El Host no posee un EnrollmentPackage válido.".into(),
                intent: None,
            })
        }
    };
    if r.deployment_id.trim().is_empty() {
        return Err("STORAGE_GRANT_NODE_REQUIRED".into());
    }
    let client_id = r
        .client_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("STORAGE_GRANT_CLIENT_REQUIRED")?;
    let organization_id = r
        .organization_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("STORAGE_GRANT_ORGANIZATION_REQUIRED")?;
    let site_id = r
        .site_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("STORAGE_GRANT_SITE_REQUIRED")?;
    let host_id = r
        .host_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("STORAGE_GRANT_HOST_REQUIRED")?;
    let host_installation_id = r
        .host_installation_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("STORAGE_GRANT_HOST_INSTALLATION_REQUIRED")?;
    if organization_id != enrollment.enrollment.organization_id.as_str() {
        return Err("STORAGE_GRANT_SCOPE_INVALID".into());
    }
    if host_installation_id != enrollment.enrollment.host_installation_id.as_str() {
        return Err("STORAGE_GRANT_HOST_MISMATCH".into());
    }
    if enrollment
        .enrollment
        .site_id
        .as_deref()
        .is_some_and(|enrolled_site| enrolled_site != site_id)
    {
        return Err("STORAGE_GRANT_SITE_MISMATCH".into());
    }
    if r.capability.trim().is_empty() {
        return Err("STORAGE_GRANT_CAPABILITY_REQUIRED".into());
    }
    let canonical_mount =
        fs::canonicalize(&r.mountpoint).map_err(|_| "STORAGE_GRANT_MOUNT_ABSENT")?;
    let mounts = storage_discover()?;
    let snapshot_hash = discovery_snapshot_hash(&mounts);
    let mount = mounts
        .into_iter()
        .find(|value| value.mountpoint == canonical_mount.to_string_lossy());
    let mount = match mount {
        Some(value) => value,
        None => {
            return Ok(SupervisorReply::StoragePreflight {
                code: "NO_DISCOVERY".into(),
                canonical_path: None,
                message: "El mount no está presente en el discovery real.".into(),
                intent: None,
            })
        }
    };
    if mount.readonly {
        return Ok(SupervisorReply::StoragePreflight {
            code: "STORAGE_FILESYSTEM_READONLY".into(),
            canonical_path: None,
            message: "El filesystem descubierto está montado en readonly.".into(),
            intent: None,
        });
    };
    let uuid = mount
        .filesystem_uuid
        .ok_or("STORAGE_GRANT_UUID_UNAVAILABLE")?;
    validate_filesystem_uuid(&uuid)?;
    let path = canonical_path(Path::new(&mount.mountpoint), &r.subpath)?
        .to_string_lossy()
        .into_owned();
    let hash = policy_hash(&r.capability, &mount.mountpoint, &path, &uuid);
    let intent_id = Uuid::new_v4().to_string();
    let idempotency_key = r
        .idempotency_key
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("storage:{}:{}:{}", r.deployment_id, r.capability, hash));
    if let Some(previous_key) = store
        .preflights()?
        .into_iter()
        .find(|previous| previous.idempotency_key.as_deref() == Some(idempotency_key.as_str()))
    {
        let same_intent = previous_key.deployment_id == r.deployment_id
            && previous_key.capability == r.capability
            && previous_key.canonical_mountpoint == mount.mountpoint
            && previous_key.canonical_path == path
            && previous_key.filesystem_uuid == uuid
            && previous_key.subpath == r.subpath
            && previous_key.filesystem == mount.filesystem;
        if !same_intent {
            return Err("STORAGE_GRANT_IDEMPOTENCY_REPLAY".into());
        }
        return Ok(SupervisorReply::StoragePreflight {
            code: "STORAGE_GRANT_REQUIRED".into(),
            canonical_path: Some(previous_key.canonical_path.clone()),
            message: "Se requiere aprobación firmada del owner para continuar.".into(),
            intent: Some(previous_key),
        });
    }
    let intent = StorageGrantPreflight {
        intent_id: intent_id,
        deployment_id: r.deployment_id,
        capability: r.capability,
        canonical_mountpoint: mount.mountpoint,
        canonical_path: path,
        subpath: r.subpath,
        filesystem: mount.filesystem,
        filesystem_uuid: uuid,
        policy_hash: hash,
        client_id: Some(client_id.to_string()),
        organization_id: Some(organization_id.to_string()),
        site_id: Some(site_id.to_string()),
        host_id: Some(host_id.to_string()),
        host_installation_id: Some(host_installation_id.to_string()),
        idempotency_key: Some(idempotency_key),
        report_generation: mount.report_generation,
        snapshot_hash,
        created_at_unix_seconds: unix_timestamp(),
    };
    store.save_preflight(&intent)?;
    Ok(SupervisorReply::StoragePreflight {
        code: "STORAGE_GRANT_REQUIRED".into(),
        canonical_path: Some(intent.canonical_path.clone()),
        message: "Se requiere aprobación firmada del owner para continuar.".into(),
        intent: Some(intent),
    })
}

fn persist_storage_failure(
    store: &StorageGrantStore,
    preflight: &StorageGrantPreflight,
    error: &str,
) {
    let _ = store.save_transaction(&StorageTransaction {
        transaction_id: Uuid::new_v4().to_string(),
        grant_id: String::new(),
        phase: "rollback".into(),
        previous_dropin: None,
        target_dropin: String::new(),
        error: Some(error.to_string()),
        intent_id: Some(preflight.intent_id.clone()),
        idempotency_key: preflight.idempotency_key.clone(),
        started_at_unix_seconds: unix_timestamp(),
        applied_at_unix_seconds: None,
        health_at_unix_seconds: None,
        rollback_at_unix_seconds: Some(unix_timestamp()),
        rollback_reason: Some("pre_apply_validation_failed".into()),
        report_generation: preflight.report_generation,
        snapshot_hash: preflight.snapshot_hash.clone(),
    });
}

fn storage_apply(
    state: &SupervisorState,
    r: actium_node_core::StorageGrantApprovalRequest,
) -> Result<SupervisorReply, String> {
    let store = StorageGrantStore::open(storage_state_root(state))?;
    let mut enrollment_state = store.enrollment()?;
    let enrollment = enrollment_state
        .enrolled
        .clone()
        .ok_or("ENROLLMENT_REQUIRED")?;
    if r.preflight
        .host_installation_id
        .as_ref()
        .map(|value| value != &enrollment.enrollment.host_installation_id)
        .unwrap_or(true)
    {
        return Err("STORAGE_GRANT_HOST_MISMATCH".into());
    }
    if r.preflight
        .organization_id
        .as_ref()
        .map(|value| value != &enrollment.enrollment.organization_id)
        .unwrap_or(true)
    {
        return Err("STORAGE_GRANT_SCOPE_INVALID".into());
    }
    if r.preflight
        .site_id
        .as_ref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
        || r.preflight
            .host_id
            .as_ref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
    {
        return Err("STORAGE_GRANT_SCOPE_INVALID".into());
    }
    if r.preflight.site_id.as_deref().is_some_and(|site| {
        enrollment
            .enrollment
            .site_id
            .as_deref()
            .is_some_and(|enrolled_site| enrolled_site != site)
    }) {
        return Err("STORAGE_GRANT_SITE_MISMATCH".into());
    }
    validate_filesystem_uuid(&r.preflight.filesystem_uuid)?;
    let existing = store.grants()?;
    if let Some(existing_grant_id) = existing
        .iter()
        .find(|grant| grant.intent_id.as_deref() == Some(r.preflight.intent_id.as_str()))
        .map(|grant| grant.grant_id.clone())
    {
        return Ok(SupervisorReply::StorageGrantList {
            grants: existing
                .into_iter()
                .filter(|value| value.grant_id == existing_grant_id || value.state != "rollback")
                .collect(),
        });
    }
    let current = match storage_discover()?
        .into_iter()
        .find(|value| value.mountpoint == r.preflight.canonical_mountpoint)
    {
        Some(value) => value,
        None => {
            persist_storage_failure(&store, &r.preflight, "STORAGE_MOUNT_DEGRADED");
            return Err("STORAGE_MOUNT_DEGRADED".into());
        }
    };
    if current.readonly
        || current.filesystem_uuid.as_deref() != Some(r.preflight.filesystem_uuid.as_str())
        || current.filesystem != r.preflight.filesystem
    {
        persist_storage_failure(&store, &r.preflight, "STORAGE_MOUNT_IDENTITY_MISMATCH");
        return Err("STORAGE_MOUNT_IDENTITY_MISMATCH".into());
    };
    let mount = Path::new(&r.preflight.canonical_mountpoint);
    let grant_path = Path::new(&r.preflight.canonical_path);
    let canonical_grant_path =
        canonical_path(mount, &r.preflight.subpath).map_err(|_| "STORAGE_GRANT_PATH_INVALID")?;
    if canonical_grant_path != grant_path || !grant_path.starts_with(mount) {
        return Err("STORAGE_GRANT_PATH_ESCAPE".into());
    };
    let claims = verify_storage_approval(
        &enrollment.center.center_public_key,
        &enrollment,
        &r.approval,
        &r.preflight,
        &enrollment_state.consumed_jtis,
        unix_timestamp(),
    )?;
    let target_existed = grant_path.exists();
    fs::create_dir_all(grant_path).map_err(|_| "STORAGE_GRANT_PATH_CREATE_FAILED")?;
    if fs::canonicalize(grant_path)
        .map_err(|_| "STORAGE_GRANT_PATH_INVALID")?
        .parent()
        .is_none()
    {
        return Err("STORAGE_GRANT_PATH_INVALID".into());
    };
    let grant_id = Uuid::new_v4().to_string();
    let transaction_id = Uuid::new_v4().to_string();
    let grant = actium_node_core::StorageGrant {
        grant_id: grant_id.clone(),
        capability: r.preflight.capability.clone(),
        canonical_mountpoint: r.preflight.canonical_mountpoint.clone(),
        canonical_path: r.preflight.canonical_path.clone(),
        subpath: r.preflight.subpath.clone(),
        filesystem: r.preflight.filesystem.clone(),
        filesystem_uuid: r.preflight.filesystem_uuid.clone(),
        binding_epoch: claims.binding_epoch,
        state: "approved".into(),
        degraded_reason: None,
        client_id: r.preflight.client_id.clone(),
        organization_id: r.preflight.organization_id.clone(),
        site_id: r.preflight.site_id.clone(),
        host_id: r.preflight.host_id.clone(),
        host_installation_id: r.preflight.host_installation_id.clone(),
        deployment_id: Some(r.preflight.deployment_id.clone()),
        intent_id: Some(r.preflight.intent_id.clone()),
        idempotency_key: r.preflight.idempotency_key.clone(),
        transaction_id: Some(transaction_id.clone()),
        policy_hash: Some(r.preflight.policy_hash.clone()),
        report_generation: r.preflight.report_generation,
        snapshot_hash: r.preflight.snapshot_hash.clone(),
        applied_at_unix_seconds: None,
        confirmed_at_unix_seconds: None,
        approval_signer_key_id: Some(enrollment.center.kid.clone()),
        approval_signer_fingerprint: Some(center_public_key_fingerprint(
            &enrollment.center.center_public_key,
        )?),
        approval_verified_at_unix_seconds: Some(unix_timestamp()),
    };
    let previous = render_dropin(&existing);
    let mut next = existing.clone();
    next.push(grant);
    let target = render_dropin(&next);
    let transaction = StorageTransaction {
        transaction_id: transaction_id.clone(),
        grant_id: grant_id.clone(),
        phase: "apply".into(),
        previous_dropin: Some(previous.clone()),
        target_dropin: target,
        error: None,
        intent_id: Some(r.preflight.intent_id.clone()),
        idempotency_key: r.preflight.idempotency_key.clone(),
        started_at_unix_seconds: unix_timestamp(),
        applied_at_unix_seconds: None,
        health_at_unix_seconds: None,
        rollback_at_unix_seconds: None,
        rollback_reason: None,
        report_generation: r.preflight.report_generation,
        snapshot_hash: r.preflight.snapshot_hash.clone(),
    };
    store.save_transaction(&transaction)?;
    let apply_result = write_dropin(
        &state.config.systemd_root,
        &state.config.service_name,
        &next,
    )
    .and_then(|_| reload_restart_health(&state.config))
    .and_then(|_| store.save_grants(&next));
    if let Err(error) = apply_result {
        let _ = write_dropin(
            &state.config.systemd_root,
            &state.config.service_name,
            &existing,
        )
        .and_then(|_| reload_restart_health(&state.config));
        if !target_existed {
            let _ = fs::remove_dir(grant_path);
        }
        let _ = store.save_transaction(&StorageTransaction {
            phase: "rolled_back".into(),
            error: Some(error.clone()),
            rollback_at_unix_seconds: Some(unix_timestamp()),
            rollback_reason: Some("apply_or_health_failed".into()),
            ..transaction
        });
        return Err(error);
    }
    let now = unix_timestamp();
    if let Some(applied) = next.iter_mut().find(|grant| grant.grant_id == grant_id) {
        applied.state = "applied".into();
        applied.applied_at_unix_seconds = Some(now);
    }
    store.save_grants(&next)?;
    enrollment_state.consumed_jtis.push(claims.jti);
    store.save_enrollment(&enrollment_state)?;
    store.save_transaction(&StorageTransaction {
        phase: "confirm".into(),
        applied_at_unix_seconds: Some(now),
        health_at_unix_seconds: Some(now),
        ..transaction
    })?;
    Ok(SupervisorReply::StorageGrantList { grants: next })
}
#[cfg(target_os = "linux")]
fn storage_discover() -> Result<Vec<StorageMount>, String> {
    let output = std::process::Command::new("findmnt")
        .args([
            "--json",
            "--bytes",
            "-o",
            "TARGET,SOURCE,FSTYPE,OPTIONS,UUID,LABEL,SIZE,AVAIL",
        ])
        .output()
        .map_err(|e| format!("STORAGE_DISCOVERY_FAILED: {e}"))?;
    if !output.status.success() {
        return Err("STORAGE_DISCOVERY_FAILED".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "STORAGE_DISCOVERY_FAILED")?;
    Ok(actium_node_core::discover_mounts_from_findmnt(
        &value,
        unix_timestamp(),
    ))
}
#[cfg(not(target_os = "linux"))]
fn storage_discover() -> Result<Vec<StorageMount>, String> {
    Ok(vec![])
}

fn enqueue_authority_ceremony(
    state: &SupervisorState,
    request: AuthorityCeremonyRequest,
) -> Result<JournalOperation, String> {
    if !request.owner_confirmation {
        return Err("AUTHORITY_OWNER_CONFIRMATION_REQUIRED".into());
    }
    let idempotency_key = format!(
        "authority-ceremony:{}:{}",
        state.config.product_channel, request.ceremony_id
    );
    if let Some(existing) = state.journal.find_by_idempotency_key(&idempotency_key)? {
        if existing.state != "failed" {
            return Ok(existing);
        }
        authority_ceremony_retry_matches(&existing, &request)?;
        validate_authority_ceremony_request(&state.config, &request)?;
        return state
            .journal
            .requeue_failed(&existing.id)?
            .ok_or_else(|| "AUTHORITY_CEREMONY_RETRY_CONFLICT".to_string());
    }
    validate_authority_ceremony_request(&state.config, &request)?;
    let id = Uuid::new_v4().to_string();
    let correlation_id = Uuid::new_v4().to_string();
    let host_id = load_host_identity(&state.config.host_identity_root)
        .ok()
        .flatten()
        .map(|identity| identity.host_installation_id)
        .unwrap_or_else(|| "unknown-host".to_string());
    let metadata = AuthorityCeremonyOperationMetadata {
        schema: 1,
        ceremony_id: request.ceremony_id.clone(),
        host_id: host_id.clone(),
        channel: state.config.product_channel.clone(),
        trust_root_set: request.trust_root_set.clone(),
        actor: "local-manager-ui".to_string(),
        correlation_id: correlation_id.clone(),
        request,
    };
    let queued_at = unix_timestamp().to_string();
    let operation = JournalOperation {
        id: id.clone(),
        idempotency_key,
        actor: "local-manager-ui".to_string(),
        target_node_id: host_id,
        install_dir: state
            .config
            .authority_data_root
            .to_string_lossy()
            .into_owned(),
        node_label: format!("Authority Ceremony · {}", state.config.product_channel),
        terminal_id: None,
        action: "authority_ceremony".to_string(),
        requested_release: None,
        metadata_json: Some(
            serde_json::to_string(&metadata)
                .map_err(|_| "AUTHORITY_CEREMONY_METADATA_INVALID".to_string())?,
        ),
        state: "queued".to_string(),
        queued_at,
        started_at: None,
        finished_at: None,
        current_step: "queued_by_supervisor".to_string(),
        output_redacted: format!(
            "correlation_id={correlation_id}; ceremony_id={}",
            metadata.ceremony_id
        ),
        recovery_policy: "inspect_then_recover_same_ceremony".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    };
    Ok(state.journal.enqueue(&operation)?)
}

fn authority_ceremony_retry_matches(
    existing: &JournalOperation,
    request: &AuthorityCeremonyRequest,
) -> Result<(), String> {
    let metadata = existing
        .metadata_json
        .as_deref()
        .ok_or_else(|| "AUTHORITY_CEREMONY_RETRY_METADATA_MISSING".to_string())
        .and_then(|value| {
            serde_json::from_str::<AuthorityCeremonyOperationMetadata>(value)
                .map_err(|_| "AUTHORITY_CEREMONY_RETRY_METADATA_INVALID".to_string())
        })?;
    let original = metadata.request;
    let original_offline = normalized_absolute_path(Path::new(&original.offline_root_dir))?;
    let original_recovery = normalized_absolute_path(Path::new(&original.recovery_dir))?;
    let requested_offline = normalized_absolute_path(Path::new(&request.offline_root_dir))?;
    let requested_recovery = normalized_absolute_path(Path::new(&request.recovery_dir))?;
    if original.ceremony_id != request.ceremony_id
        || original.provider != request.provider
        || original.trust_root_set != request.trust_root_set
        || original_offline != requested_offline
        || original_recovery != requested_recovery
    {
        return Err("AUTHORITY_CEREMONY_RETRY_REQUEST_MISMATCH".into());
    }
    Ok(())
}

fn execute_authority_ceremony_operation(
    state: &SupervisorState,
    operation: &JournalOperation,
    progress: &dyn Fn(&str, &str, Option<&str>),
) -> Result<actium_node_core::RuntimeActionResult, String> {
    let metadata = operation
        .metadata_json
        .as_deref()
        .ok_or_else(|| "AUTHORITY_CEREMONY_METADATA_MISSING".to_string())
        .and_then(|value| {
            serde_json::from_str::<AuthorityCeremonyOperationMetadata>(value)
                .map_err(|_| "AUTHORITY_CEREMONY_METADATA_INVALID".to_string())
        })?;
    let ceremony = authority_ceremony_execute_with_context(
        &state.config,
        state,
        metadata.request,
        Some(&operation.id),
        Some(&metadata.correlation_id),
        Some(progress),
    );
    if let Some(code) = ceremony.code {
        return Err(format!(
            "{code} (ceremony_id={}; operation_id={})",
            ceremony.ceremony_id, operation.id
        ));
    }
    let output = serde_json::json!({
        "ceremonyId": ceremony.ceremony_id,
        "operationId": operation.id,
        "state": ceremony.state,
        "rootFingerprint": ceremony.root_fingerprint,
        "trustBundleDigest": ceremony.trust_bundle_digest,
        "trustEpoch": ceremony.trust_epoch,
        "recoveryStatus": ceremony.recovery_status,
        "nextAction": "Owner-controlled activation",
    })
    .to_string();
    Ok(actium_node_core::RuntimeActionResult {
        message: "Custodia preparada y verificada".to_string(),
        output,
        release_version: None,
    })
}

fn enqueue_material(
    state: &SupervisorState,
    request: EnqueueMaterialRequest,
) -> Result<JournalOperation, String> {
    if request.capability.trim().is_empty() || request.capability.len() > 64 {
        return Err("MATERIAL_CAPABILITY_INVALID".into());
    }
    let path = state
        .runtime
        .validate_operation_target(Path::new(&request.install_dir))?;
    let _scope = trusted_scope_from_node_root(&path)?;
    let _package = resolve_package_dir(&path, &request.package_dir)?;
    let queued_at = unix_timestamp().to_string();
    let payload = serde_json::json!({
        "capability": request.capability,
        "packageDir": request.package_dir,
    })
    .to_string();
    let operation = JournalOperation {
        id: Uuid::new_v4().to_string(),
        idempotency_key: format!(
            "material_stage:{}:{}:{}",
            path.to_string_lossy().to_ascii_lowercase(),
            request.capability,
            request.package_dir
        ),
        actor: "local-ipc".to_string(),
        target_node_id: path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("node")
            .to_string(),
        install_dir: path.to_string_lossy().into_owned(),
        node_label: request.capability.clone(),
        terminal_id: None,
        action: "material_stage".to_string(),
        requested_release: Some(payload),
        metadata_json: None,
        state: "queued".to_string(),
        queued_at,
        started_at: None,
        finished_at: None,
        current_step: "queued_material_stage".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    };
    state.journal.enqueue(&operation)
}

fn enqueue_material_reconcile(
    state: &SupervisorState,
    request: ReconcileMaterialRequest,
) -> Result<JournalOperation, String> {
    if request.capability.trim().is_empty() || request.capability.len() > 64 {
        return Err("MATERIAL_CAPABILITY_INVALID".into());
    }
    let path = state
        .runtime
        .validate_operation_target(Path::new(&request.install_dir))?;
    let _scope = trusted_scope_from_node_root(&path)?;
    let queued_at = unix_timestamp().to_string();
    let payload = serde_json::json!({ "capability": request.capability }).to_string();
    let operation = JournalOperation {
        id: Uuid::new_v4().to_string(),
        idempotency_key: format!(
            "material_reconcile:{}:{}",
            path.to_string_lossy().to_ascii_lowercase(),
            request.capability
        ),
        actor: "local-ipc".to_string(),
        target_node_id: path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("node")
            .to_string(),
        install_dir: path.to_string_lossy().into_owned(),
        node_label: request.capability.clone(),
        terminal_id: None,
        action: "material_reconcile".to_string(),
        requested_release: Some(payload),
        metadata_json: None,
        state: "queued".to_string(),
        queued_at,
        started_at: None,
        finished_at: None,
        current_step: "queued_material_reconcile".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    };
    state.journal.enqueue(&operation)
}

fn get_material_state(
    state: &SupervisorState,
    request: GetMaterialStateRequest,
) -> Result<SupervisorReply, String> {
    if request.capability.trim().is_empty() || request.capability.len() > 64 {
        return Err("MATERIAL_CAPABILITY_INVALID".into());
    }
    let path = state
        .runtime
        .validate_operation_target(Path::new(&request.install_dir))?;
    let store = MaterialStateStore::open(material_capability_root(&path, &request.capability))?;
    let loaded = store.load()?;
    Ok(SupervisorReply::MaterialState {
        capability: request.capability,
        state_json: serde_json::to_string(&loaded)
            .map_err(|e| format!("MATERIAL_STATE_SERIALIZE: {e}"))?,
    })
}

fn open_material_manager(node_root: &Path) -> Result<MaterialManager, String> {
    let trust = load_trust_store(node_root)?;
    let contracts = load_contract_registry(node_root)?;
    Ok(MaterialManager::new(
        node_root,
        trust,
        contracts,
        MaterialResourceLimits::default(),
    ))
}

fn execute_material_operation(
    node_root: &Path,
    action: &str,
    payload: Option<&str>,
) -> Result<actium_node_core::RuntimeActionResult, String> {
    let payload: serde_json::Value = serde_json::from_str(payload.unwrap_or("{}"))
        .map_err(|e| format!("MATERIAL_OP_PAYLOAD: {e}"))?;
    let capability = payload
        .get("capability")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "MATERIAL_CAPABILITY_INVALID".to_string())?;
    match action {
        "material_stage" => {
            let package_dir = payload
                .get("packageDir")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "MATERIAL_PACKAGE_DIR_MISSING".to_string())?;
            let scope = trusted_scope_from_node_root(node_root)?;
            let resolved = resolve_package_dir(node_root, package_dir)?;
            let manager = open_material_manager(node_root)?;
            let state = manager.stage_verify(&resolved, &scope)?;
            Ok(actium_node_core::RuntimeActionResult {
                message: format!("material staged {}", state.status),
                output: serde_json::to_string(&state).unwrap_or_default(),
                release_version: None,
            })
        }
        "material_reconcile" => {
            let store = MaterialStateStore::open(material_capability_root(node_root, capability))?;
            let state = store.load()?;
            Ok(actium_node_core::RuntimeActionResult {
                message: format!("material reconciled {}", state.status),
                output: serde_json::to_string(&state).unwrap_or_default(),
                release_version: None,
            })
        }
        other => Err(format!("MATERIAL_ACTION_UNKNOWN:{other}")),
    }
}

fn execute_connectivity_operation(
    state: &SupervisorState,
    request: actium_node_core::ipc::ConnectivityOperationRequest,
) -> Result<actium_node_core::ipc::ConnectivityOperationResult, String> {
    let id = Uuid::new_v4().to_string();
    let started_at = actium_node_core::ipc::unix_timestamp().to_string();
    let action_str = match request.operation {
        actium_node_core::ipc::ConnectivityOperation::Provision => "connectivity_provision",
        actium_node_core::ipc::ConnectivityOperation::Connect => "connectivity_connect",
        actium_node_core::ipc::ConnectivityOperation::Disconnect => "connectivity_disconnect",
        actium_node_core::ipc::ConnectivityOperation::Health => "connectivity_health",
        actium_node_core::ipc::ConnectivityOperation::Rotate => "connectivity_rotate",
        actium_node_core::ipc::ConnectivityOperation::Revoke => "connectivity_revoke",
        actium_node_core::ipc::ConnectivityOperation::Reconcile => "connectivity_reconcile",
    };

    let operation = JournalOperation {
        id: id.clone(),
        idempotency_key: format!("connectivity:{id}"),
        actor: "local-ipc-connectivity".to_string(),
        target_node_id: request.provider.clone(),
        install_dir: "connectivity_subsystem".to_string(),
        node_label: format!("Connectivity: {}", request.provider),
        terminal_id: None,
        action: action_str.to_string(),
        requested_release: Some(serde_json::to_string(&request).unwrap_or_default()),
        metadata_json: None,
        state: "running".to_string(),
        queued_at: started_at.clone(),
        started_at: Some(started_at.clone()),
        finished_at: None,
        current_step: "executing_connectivity".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    };

    state.journal.enqueue(&operation)?;

    // Delegate actual execution to the core connectivity module
    let result =
        actium_node_core::connectivity::execute_operation(&state.config.payload_root, &request);

    let finished_at = actium_node_core::ipc::unix_timestamp().to_string();
    match result {
        Ok(res) => {
            let output = format!("Connectivity {} {}: OK", request.provider, action_str);
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "completed",
                    current_step: "connectivity_completed",
                    output: &output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: None,
                },
            )?;
            Ok(res)
        }
        Err(e) => {
            let output = format!(
                "Connectivity {} {}: FAILED: {}",
                request.provider, action_str, e
            );
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "failed",
                    current_step: "connectivity_failed",
                    output: &output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: Some("CONNECTIVITY_OPERATION_FAILED"),
                },
            )?;
            Err(e)
        }
    }
}

fn execute_synchronous_journaled(
    state: &SupervisorState,
    install_dir: &str,
    action: &str,
) -> Result<actium_node_core::RuntimeActionResult, String> {
    RuntimeOperator::validate_action(action)?;
    if action == "update" {
        return Err("Update solo se admite mediante la cola durable.".to_string());
    }
    let path = state
        .runtime
        .validate_operation_target(Path::new(install_dir))?;
    let id = Uuid::new_v4().to_string();
    let started_at = unix_timestamp().to_string();
    let label = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("nodo-lab")
        .to_string();
    let operation = JournalOperation {
        id: id.clone(),
        idempotency_key: format!("synchronous:{id}"),
        actor: "local-ipc-synchronous".to_string(),
        target_node_id: label.clone(),
        install_dir: path.to_string_lossy().into_owned(),
        node_label: label,
        terminal_id: None,
        action: action.to_string(),
        requested_release: None,
        metadata_json: None,
        state: "running".to_string(),
        queued_at: started_at.clone(),
        started_at: Some(started_at.clone()),
        finished_at: None,
        current_step: "executing_synchronous".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    };
    state.journal.enqueue(&operation)?;
    let result = state.runtime.execute(&path, action, None);
    let finished_at = unix_timestamp().to_string();
    match result {
        Ok(mut result) => {
            result.output = redact_sensitive(&bounded_output(result.output));
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "completed",
                    current_step: &result.message,
                    output: &result.output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: None,
                },
            )?;
            Ok(result)
        }
        Err(error) => {
            let output = bounded_output(error.clone());
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "failed",
                    current_step: "synchronous_action_failed",
                    output: &output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: Some("OPERATION_FAILED"),
                },
            )?;
            Err(error)
        }
    }
}

fn execute_commission_journaled(
    state: &SupervisorState,
    request: CommissionNodeRequest,
) -> Result<actium_node_core::RuntimeActionResult, String> {
    let path = Path::new(&request.install_dir);
    let id = Uuid::new_v4().to_string();
    let started_at = unix_timestamp().to_string();
    let action = if request.resume_incomplete {
        if request.prepare_only {
            "resume_prepare"
        } else {
            "resume_commission"
        }
    } else if request.prepare_only {
        "prepare"
    } else {
        "commission"
    };
    let label = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("nodo-lab")
        .to_string();
    state.journal.enqueue(&JournalOperation {
        id: id.clone(),
        idempotency_key: format!("commissioning:{id}"),
        actor: "local-ipc-commissioning".to_string(),
        target_node_id: label.clone(),
        install_dir: request.install_dir.clone(),
        node_label: label,
        terminal_id: None,
        action: action.to_string(),
        requested_release: state.runtime.payload_release_version().ok(),
        metadata_json: None,
        state: "running".to_string(),
        queued_at: started_at.clone(),
        started_at: Some(started_at.clone()),
        finished_at: None,
        current_step: "commissioning".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    })?;
    let journal = state.journal.clone();
    let job_id = id.clone();
    let started_at_for_progress = started_at.clone();
    let progress = |status: &str, step: &str, output: Option<&str>| {
        let _ = journal.update(
            &job_id,
            JournalUpdate {
                state: status,
                current_step: step,
                output: output.unwrap_or(""),
                started_at: Some(&started_at_for_progress),
                finished_at: None,
                error_code: None,
            },
        );
    };
    let result = state
        .runtime
        .commission_node_with_progress(&request, Some(&progress));
    let finished_at = unix_timestamp().to_string();
    match result {
        Ok(mut result) => {
            result.output = redact_sensitive(&bounded_output(result.output));
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "completed",
                    current_step: &result.message,
                    output: &result.output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: None,
                },
            )?;
            Ok(result)
        }
        Err(error) => {
            let output = bounded_output(error.clone());
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "failed",
                    current_step: "commissioning_failed",
                    output: &output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: Some("COMMISSIONING_FAILED"),
                },
            )?;
            Err(error)
        }
    }
}

fn execute_configuration_write_journaled(
    state: &SupervisorState,
    request: ConfigurationWriteRequest,
) -> Result<actium_node_core::RuntimeActionResult, String> {
    let path = state
        .runtime
        .validate_operation_target(Path::new(&request.install_dir))?;
    let id = Uuid::new_v4().to_string();
    let started_at = unix_timestamp().to_string();
    let label = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("nodo-lab")
        .to_string();
    state.journal.enqueue(&JournalOperation {
        id: id.clone(),
        idempotency_key: format!("configuration-write:{id}"),
        actor: "local-ipc-configuration".to_string(),
        target_node_id: label.clone(),
        install_dir: path.to_string_lossy().into_owned(),
        node_label: label,
        terminal_id: None,
        action: "persist_configuration".to_string(),
        requested_release: None,
        metadata_json: None,
        state: "running".to_string(),
        queued_at: started_at.clone(),
        started_at: Some(started_at.clone()),
        finished_at: None,
        current_step: "persisting_configuration".to_string(),
        output_redacted: String::new(),
        recovery_policy: "restore_configuration_backup".to_string(),
        error_code: None,
        attempt_count: 0,
        lease_expires_at: None,
    })?;
    let result = state.runtime.persist_configuration(&request);
    let finished_at = unix_timestamp().to_string();
    match result {
        Ok(mut result) => {
            result.output = redact_sensitive(&bounded_output(result.output));
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "completed",
                    current_step: &result.message,
                    output: &result.output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: None,
                },
            )?;
            Ok(result)
        }
        Err(error) => {
            let output = bounded_output(error.clone());
            state.journal.update(
                &id,
                JournalUpdate {
                    state: "failed",
                    current_step: "configuration_write_failed",
                    output: &output,
                    started_at: Some(&started_at),
                    finished_at: Some(&finished_at),
                    error_code: Some("CONFIGURATION_WRITE_FAILED"),
                },
            )?;
            Err(error)
        }
    }
}

fn start_operation_worker(state: Arc<SupervisorState>) {
    thread::spawn(move || loop {
        let started_at = unix_timestamp().to_string();
        let operation = match state.journal.claim_next_queued(&started_at) {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            Err(error) => {
                log_message(format!("Worker durable: {error}"));
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let job_id = operation.id.clone();
        let journal = state.journal.clone();
        let heartbeat_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_stop_thread = heartbeat_stop.clone();
        let heartbeat_journal = state.journal.clone();
        let heartbeat_job_id = job_id.clone();
        thread::spawn(move || {
            while !heartbeat_stop_thread.load(Ordering::Acquire) {
                thread::sleep(Duration::from_secs(MUTATION_HEARTBEAT_SECONDS));
                if heartbeat_stop_thread.load(Ordering::Acquire) {
                    break;
                }
                match heartbeat_journal.renew_lease(&heartbeat_job_id) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => {
                        log_message(format!("Heartbeat durable {}: {error}", heartbeat_job_id))
                    }
                }
            }
        });
        let progress = |status: &str, step: &str, output: Option<&str>| {
            let _ = journal.update(
                &job_id,
                JournalUpdate {
                    state: status,
                    current_step: step,
                    output: output.unwrap_or(""),
                    started_at: Some(&started_at),
                    finished_at: None,
                    error_code: None,
                },
            );
        };
        let result = if operation.action == "authority_ceremony" {
            execute_authority_ceremony_operation(&state, &operation, &progress)
        } else if operation.action == "material_stage" || operation.action == "material_reconcile" {
            execute_material_operation(
                Path::new(&operation.install_dir),
                &operation.action,
                operation.requested_release.as_deref(),
            )
        } else if operation.action == "update" {
            let candidate = state.runtime.payload_release_version();
            match (operation.requested_release.as_deref(), candidate) {
                (Some(requested), Ok(candidate)) if requested != candidate => Err(format!(
                    "Manager solicito release {requested}, pero Supervisor posee {candidate}."
                )),
                (_, Err(error)) => Err(error),
                _ => state.runtime.execute(
                    Path::new(&operation.install_dir),
                    &operation.action,
                    Some(&progress),
                ),
            }
        } else {
            state.runtime.execute(
                Path::new(&operation.install_dir),
                &operation.action,
                Some(&progress),
            )
        };
        heartbeat_stop.store(true, Ordering::Release);
        let finished_at = unix_timestamp().to_string();
        let (status, message, output, error_code) = match result {
            Ok(result) => ("completed", result.message, result.output, None),
            Err(error) if error.starts_with("[ROLLED_BACK]") => (
                "rolled_back",
                "El candidato fallo y Supervisor restauro el LKG.".to_string(),
                error,
                Some("HEALTH_GATE_ROLLBACK"),
            ),
            Err(error) if error.starts_with("[MANUAL_INTERVENTION_REQUIRED]") => (
                "manual_intervention_required",
                "La recuperacion automatica no pudo cerrar la operacion.".to_string(),
                error,
                Some("MANUAL_INTERVENTION_REQUIRED"),
            ),
            Err(error) => (
                "failed",
                format!("No se pudo ejecutar {}.", operation.action),
                error,
                Some("OPERATION_FAILED"),
            ),
        };
        let output = bounded_output(output);
        if let Err(error) = state.journal.update(
            &operation.id,
            JournalUpdate {
                state: status,
                current_step: &message,
                output: &output,
                started_at: Some(&started_at),
                finished_at: Some(&finished_at),
                error_code,
            },
        ) {
            log_message(format!(
                "No se pudo cerrar la operacion {}: {error}",
                operation.id
            ));
        }
    });
}

fn bounded_output(value: String) -> String {
    const MAX_OUTPUT_CHARS: usize = 500_000;
    if value.chars().count() <= MAX_OUTPUT_CHARS {
        return value;
    }
    let tail = value
        .chars()
        .rev()
        .take(MAX_OUTPUT_CHARS)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("[Salida truncada a {MAX_OUTPUT_CHARS} caracteres]\n\n{tail}")
}

fn recover_interrupted_operations(
    journal: &OperationJournal,
    runtime: &RuntimeOperator,
) -> Result<(), String> {
    for operation in journal
        .list(500)?
        .into_iter()
        .filter(|operation| operation.state == "interrupted")
    {
        let finished_at = unix_timestamp().to_string();
        if matches!(
            operation.action.as_str(),
            "material_stage" | "material_reconcile"
        ) {
            match execute_material_operation(
                Path::new(&operation.install_dir),
                "material_reconcile",
                operation.requested_release.as_deref(),
            ) {
                Ok(result) => {
                    journal.update(
                        &operation.id,
                        JournalUpdate {
                            state: "completed",
                            current_step: "recovered_material_from_journal",
                            output: &result.output,
                            started_at: operation.started_at.as_deref(),
                            finished_at: Some(&finished_at),
                            error_code: None,
                        },
                    )?;
                }
                Err(error) => {
                    journal.update(
                        &operation.id,
                        JournalUpdate {
                            state: "manual_intervention_required",
                            current_step: "material_recovery_failed",
                            output: &error,
                            started_at: operation.started_at.as_deref(),
                            finished_at: Some(&finished_at),
                            error_code: Some("MATERIAL_RECOVERY_FAILED"),
                        },
                    )?;
                }
            }
            continue;
        }
        let recovery = match operation.action.as_str() {
            "update" => runtime.recover_after_reboot(Path::new(&operation.install_dir)),
            "apply_configuration" | "persist_configuration" => {
                runtime.recover_configuration_after_reboot(Path::new(&operation.install_dir))
            }
            _ => continue,
        };
        match recovery {
            Ok(Some(message)) => journal.update(
                &operation.id,
                JournalUpdate {
                    state: "rolled_back",
                    current_step: "recovered_after_reboot",
                    output: &message,
                    started_at: operation.started_at.as_deref(),
                    finished_at: Some(&finished_at),
                    error_code: Some("REBOOT_ROLLBACK"),
                },
            )?,
            Ok(None) => {}
            Err(error) => journal.update(
                &operation.id,
                JournalUpdate {
                    state: "manual_intervention_required",
                    current_step: "recovery_after_reboot_failed",
                    output: &error,
                    started_at: operation.started_at.as_deref(),
                    finished_at: Some(&finished_at),
                    error_code: Some("REBOOT_RECOVERY_FAILED"),
                },
            )?,
        }
    }
    Ok(())
}

fn start_network_reconciler(state: Arc<SupervisorState>) {
    let interval = state.config.network_reconcile_interval_seconds.max(5);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(interval));
        match state.runtime.reconcile_automatic_networks() {
            Ok(messages) => {
                for message in messages {
                    log_message(format!("Reconciliacion de red: {message}"));
                }
            }
            Err(error) => log_message(format!("Reconciliacion de red no disponible: {error}")),
        }
    });
}

fn start_attestation_reconciler(state: Arc<SupervisorState>) {
    thread::spawn(move || loop {
        match state.runtime.refresh_material_attestations() {
            Ok(messages) => {
                for message in messages {
                    log_message(format!("Atestacion material: {message}"));
                }
            }
            Err(error) => log_message(format!("Atestacion material no disponible: {error}")),
        }
        thread::sleep(Duration::from_secs(30));
    });
}

fn start_runtime_reconciler(state: Arc<SupervisorState>) {
    let interval = state.config.runtime_reconcile_interval_seconds.max(5);
    let max_parallel = actium_node_core::clamp_runtime_reconcile_parallelism(
        state.config.runtime_reconcile_max_parallel_nodes,
    );
    thread::spawn(move || loop {
        match state
            .runtime
            .reconcile_authorized_runtimes_bounded(max_parallel)
        {
            Ok(messages) => {
                for message in messages {
                    log_message(format!("Reconciliacion de runtime: {message}"));
                }
            }
            Err(error) => log_message(format!("Reconciliacion de runtime no disponible: {error}")),
        }
        thread::sleep(Duration::from_secs(interval));
    });
}

fn runtime_root_check(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("No se pudo inspeccionar {}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} no es un directorio.", path.display()));
    }
    Ok(())
}

fn log_message(message: String) {
    eprintln!("{message}");
    #[cfg(windows)]
    if let Some(path) = WINDOWS_LOG_FILE.get() {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{} {}", unix_timestamp(), redact_sensitive(&message));
        }
    }
}

fn verify_owner_confirmed_roots(config: &SupervisorConfig) -> Result<(), String> {
    let contents = fs::read_to_string(&config.root_ownership_marker).map_err(|error| {
        format!(
            "La raiz no fue confirmada por un operador: no se pudo leer {}: {error}",
            config.root_ownership_marker.display()
        )
    })?;
    let marker = serde_json::from_str::<RootOwnershipMarker>(&contents)
        .map_err(|error| format!("Marcador owner-confirmed invalido: {error}"))?;
    if marker.schema != 1 || marker.owner != "actium-node-supervisor" {
        return Err("Marcador owner-confirmed incompatible o con owner invalido.".to_string());
    }
    if marker.product_channel != config.product_channel {
        return Err(format!(
            "El marcador pertenece al canal {}, no a {}.",
            marker.product_channel, config.product_channel
        ));
    }
    Uuid::parse_str(&marker.root_id)
        .map_err(|_| "root_id del marcador owner-confirmed no es UUID.".to_string())?;
    let configured_nodes = canonical_directory(&config.authorized_nodes_root)?;
    let configured_fabrics = canonical_directory(&config.authorized_fabrics_root)?;
    let marked_nodes = canonical_directory(Path::new(&marker.authorized_nodes_root))?;
    let marked_fabrics = canonical_directory(Path::new(&marker.authorized_fabrics_root))?;
    if !same_path(&configured_nodes, &marked_nodes)
        || !same_path(&configured_fabrics, &marked_fabrics)
    {
        return Err(
            "Las raices configuradas no coinciden con el marcador owner-confirmed.".to_string(),
        );
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    runtime_root_check(path)?;
    fs::canonicalize(path)
        .map_err(|error| format!("No se pudo canonicalizar {}: {error}", path.display()))
}

#[cfg(windows)]
fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(windows))]
fn same_path(left: &Path, right: &Path) -> bool {
    left == right
}

fn resolve_fabric_identity(config: &SupervisorConfig) -> Result<FabricIdentity, String> {
    if config.fabric_identity_path.is_file() {
        let contents = fs::read_to_string(&config.fabric_identity_path).map_err(|error| {
            format!(
                "No se pudo leer {}: {error}",
                config.fabric_identity_path.display()
            )
        })?;
        let identity = serde_json::from_str::<FabricIdentity>(&contents)
            .map_err(|error| format!("Identidad Fabric persistida invalida: {error}"))?;
        if identity.compose_project != config.fabric_project
            || identity.network_name != config.fabric_network
        {
            return Err(
                "La configuracion intenta renombrar un Fabric ya materializado.".to_string(),
            );
        }
        return Ok(identity);
    }
    let fabric_id = if config.fabric_id == "auto" {
        Uuid::new_v4().to_string()
    } else {
        Uuid::parse_str(&config.fabric_id)
            .map_err(|_| "fabric_id debe ser auto o UUID.".to_string())?
            .to_string()
    };
    let identity = FabricIdentity {
        fabric_id,
        compose_project: config.fabric_project.clone(),
        network_name: config.fabric_network.clone(),
        host_id: None,
    };
    if let Some(parent) = config.fabric_identity_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear estado de Fabric: {error}"))?;
    }
    let temporary = config
        .fabric_identity_path
        .with_extension(format!("tmp-{}", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(&identity)
        .map_err(|error| format!("No se pudo serializar Fabric: {error}"))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("No se pudo preparar identidad Fabric: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo persistir identidad Fabric: {error}"))?;
    set_private_file_permissions(&temporary)?;
    fs::rename(&temporary, &config.fabric_identity_path)
        .map_err(|error| format!("No se pudo promover identidad Fabric: {error}"))?;
    Ok(identity)
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o640))
        .map_err(|error| format!("No se pudo restringir {}: {error}", path.display()))
}

#[cfg(windows)]
fn set_private_file_permissions(_path: &Path) -> Result<(), String> {
    // En Windows el ACL de ProgramData se establece durante la instalacion owner-confirmed.
    Ok(())
}

#[cfg(unix)]
fn default_config_path() -> PathBuf {
    PathBuf::from("/etc/actium/node-manager/supervisor.toml")
}

#[cfg(windows)]
fn program_data_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Actium")
        .join("NodeManager")
}

#[cfg(windows)]
fn default_config_path() -> PathBuf {
    program_data_root().join("config").join("supervisor.toml")
}

#[cfg(unix)]
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/actium/node-manager.sock")
}
#[cfg(windows)]
fn default_socket_path() -> PathBuf {
    PathBuf::new()
}
fn default_product_channel() -> String {
    "stable".to_string()
}
fn default_pipe_name() -> String {
    WINDOWS_SERVICE_NAME.to_string()
}
fn default_pipe_sddl() -> String {
    // Fallback deliberadamente restrictivo. El instalador agrega el SID del grupo operador.
    "D:P(A;;GA;;;SY)(A;;GA;;;BA)".to_string()
}
fn default_service_name() -> String {
    WINDOWS_SERVICE_NAME.to_string()
}
#[cfg(unix)]
fn default_key_path() -> PathBuf {
    PathBuf::from("/etc/actium/node-manager/ipc.key")
}
#[cfg(windows)]
fn default_key_path() -> PathBuf {
    program_data_root().join("config").join("ipc.key")
}
#[cfg(unix)]
fn default_journal_path() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/operations.sqlite3")
}
#[cfg(windows)]
fn default_journal_path() -> PathBuf {
    program_data_root().join("state").join("operations.sqlite3")
}
#[cfg(unix)]
fn default_nodes_root() -> PathBuf {
    PathBuf::from("/srv/actium-data/nodes")
}
#[cfg(windows)]
fn default_nodes_root() -> PathBuf {
    program_data_root().join("nodes")
}
#[cfg(unix)]
fn default_fabrics_root() -> PathBuf {
    PathBuf::from("/srv/actium-data/fabrics")
}
#[cfg(windows)]
fn default_fabrics_root() -> PathBuf {
    program_data_root().join("fabrics")
}
#[cfg(unix)]
fn default_payload_root() -> PathBuf {
    PathBuf::from("/usr/lib/actium/node-manager/payload")
}
#[cfg(windows)]
fn default_payload_root() -> PathBuf {
    program_data_root().join("payload")
}
#[cfg(unix)]
fn default_extensions_root() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/extensions")
}
#[cfg(windows)]
fn default_extensions_root() -> PathBuf {
    program_data_root().join("extensions")
}
#[cfg(unix)]
fn default_extension_trust_root() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/extension-trust")
}
#[cfg(windows)]
fn default_extension_trust_root() -> PathBuf {
    program_data_root().join("extension-trust")
}

fn load_trust_bootstrap_roots(
    path: &Path,
) -> Result<Vec<actium_node_core::ProductTrustRoot>, String> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(path).map_err(|error| format!("TRUST_BOOTSTRAP_READ_FAILED: {error}"))?;
    let roots: Vec<actium_node_core::ProductTrustRoot> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("TRUST_BOOTSTRAP_INVALID: {error}"))?;
    if roots.iter().any(|root| {
        root.authority.kind != actium_node_core::AuthorityKind::ProductTrustRoot
            || root.authority.algorithm != actium_node_core::TRUST_FABRIC_ALGORITHM
            || root.authority.certificate.is_some()
            || root.authority.public_key.is_empty()
    }) {
        return Err("TRUST_BOOTSTRAP_INVALID".into());
    }
    Ok(roots)
}

#[cfg(unix)]
fn default_trust_store_path() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/trust/trust-bundle.json")
}
#[cfg(unix)]
fn default_trust_bootstrap_path() -> PathBuf {
    PathBuf::from("/usr/share/actium/node-manager/trust/product-bootstrap.json")
}
#[cfg(windows)]
fn default_trust_store_path() -> PathBuf {
    program_data_root().join("trust").join("trust-bundle.json")
}
#[cfg(windows)]
fn default_trust_bootstrap_path() -> PathBuf {
    program_data_root()
        .join("trust")
        .join("product-bootstrap.json")
}
#[cfg(unix)]
fn default_authority_data_root() -> PathBuf {
    PathBuf::from("/var/lib/actium/authority")
}
#[cfg(windows)]
fn default_authority_data_root() -> PathBuf {
    program_data_root().join("authority")
}
#[cfg(unix)]
fn default_authority_ceremony_binary() -> PathBuf {
    PathBuf::from("/usr/lib/Actium Node Manager/authority/actium-authority-ceremony")
}
#[cfg(windows)]
fn default_authority_ceremony_binary() -> PathBuf {
    program_data_root()
        .join("authority")
        .join("actium-authority-ceremony.exe")
}
fn default_authority_service_name() -> String {
    "actium-authority.service".to_string()
}
#[cfg(unix)]
fn default_authority_online_sealing_key_file() -> PathBuf {
    PathBuf::from("/etc/actium/authority/sealing.key")
}
#[cfg(unix)]
fn default_authority_ceremony_lock_root() -> PathBuf {
    // Ceremony arbitration is Supervisor-owned state.  Keeping it outside
    // the Authority Service data root avoids a POSIX permission boundary
    // between the restricted Supervisor and actium-authority.
    PathBuf::from("/var/lib/actium/node-manager/authority-lock")
}
#[cfg(windows)]
fn default_authority_ceremony_lock_root() -> PathBuf {
    program_data_root().join("authority")
}
fn default_authority_ceremony_mode() -> String {
    "production".to_string()
}
#[cfg(windows)]
fn default_authority_online_sealing_key_file() -> PathBuf {
    program_data_root().join("authority").join("sealing.key")
}
#[cfg(unix)]
fn default_log_dir() -> PathBuf {
    PathBuf::from("/var/log/actium/node-manager")
}
#[cfg(windows)]
fn default_log_dir() -> PathBuf {
    program_data_root().join("logs")
}
#[cfg(unix)]
fn default_fabric_identity_path() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/fabric-identity.json")
}
#[cfg(windows)]
fn default_fabric_identity_path() -> PathBuf {
    program_data_root()
        .join("state")
        .join("fabric-identity.json")
}
#[cfg(unix)]
fn default_host_identity_root() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/identity")
}
#[cfg(windows)]
fn default_host_identity_root() -> PathBuf {
    program_data_root().join("identity")
}
fn default_fabric_id() -> String {
    "auto".to_string()
}
fn default_fabric_project() -> String {
    "actium-node-fabric-01".to_string()
}
fn default_fabric_network() -> String {
    "actium-node-fabric-01".to_string()
}
fn default_operator_group() -> String {
    "actium-node-operators".to_string()
}
fn default_network_interval() -> u64 {
    15
}
fn default_runtime_interval() -> u64 {
    10
}
fn default_runtime_parallel() -> u64 {
    4
}
#[cfg(unix)]
fn default_root_ownership_marker() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/root-ownership.json")
}
fn default_systemd_root() -> PathBuf {
    PathBuf::from("/")
}
fn default_systemctl_path() -> PathBuf {
    PathBuf::from("systemctl")
}
#[cfg(windows)]
fn default_root_ownership_marker() -> PathBuf {
    program_data_root()
        .join("state")
        .join("root-ownership.json")
}

#[cfg(windows)]
mod windows_service_host {
    use super::*;
    use std::{ffi::OsString, sync::OnceLock};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    static CONFIG: OnceLock<SupervisorConfig> = OnceLock::new();
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    pub(super) fn dispatch(config_path: PathBuf) -> Result<(), String> {
        let config = SupervisorConfig::load(&config_path)?;
        config.validate()?;
        let service_name = config.service_name.clone();
        CONFIG
            .set(config)
            .map_err(|_| "La configuracion del Windows Service ya fue inicializada.".to_string())?;
        service_dispatcher::start(service_name, ffi_service_main)
            .map_err(|error| format!("Windows SCM rechazo el dispatcher: {error}"))
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            log_message(format!("Actium Node Supervisor Windows Service: {error}"));
        }
    }

    fn run_service() -> Result<(), String> {
        let config = CONFIG
            .get()
            .cloned()
            .ok_or_else(|| "Windows Service sin configuracion cargada.".to_string())?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_signal = shutdown.clone();
        let event_handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_signal.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status = service_control_handler::register(&config.service_name, event_handler)
            .map_err(|error| format!("No se pudo registrar handler SCM: {error}"))?;
        status
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::StartPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
            .map_err(|error| format!("No se pudo publicar StartPending: {error}"))?;
        status
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(|error| format!("No se pudo publicar Running: {error}"))?;
        let result = run_daemon(config, shutdown, true);
        let exit_code = if result.is_ok() { 0 } else { 1 };
        status
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(exit_code),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(|error| format!("No se pudo publicar Stopped: {error}"))?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(root: &Path) -> SupervisorConfig {
        SupervisorConfig {
            product_channel: "lab".to_string(),
            socket_path: root.join("supervisor.sock"),
            pipe_name: "ActiumNodeSupervisorLabTest".to_string(),
            pipe_sddl: default_pipe_sddl(),
            service_name: "ActiumNodeSupervisorLabTest".to_string(),
            ipc_key_path: root.join("ipc.key"),
            journal_path: root.join("operations.sqlite3"),
            host_identity_root: root.join("identity"),
            authorized_nodes_root: root.join("nodes"),
            authorized_fabrics_root: root.join("fabrics"),
            payload_root: root.join("payload"),
            extensions_root: root.join("extensions"),
            extension_trust_root: root.join("extension-trust"),
            trust_store_path: root.join("trust").join("trust-bundle.json"),
            trust_bootstrap_path: root.join("trust").join("product-bootstrap.json"),
            authority_data_root: root.join("authority"),
            authority_ceremony_binary: root.join("authority-ceremony"),
            authority_service_name: "actium-authority.service".to_string(),
            authority_online_sealing_key_file: root.join("authority-sealing.key"),
            authority_ceremony_lock_root: root.join("authority-lock"),
            authority_ceremony_mode: "fixture".to_string(),
            log_dir: root.join("logs"),
            fabric_identity_path: root.join("fabric-identity.json"),
            fabric_id: "auto".to_string(),
            fabric_project: "actium-lab-fabric-test".to_string(),
            fabric_network: "actium-lab-fabric-test".to_string(),
            operator_group: "actium-node-operators".to_string(),
            network_reconcile_interval_seconds: 15,
            runtime_reconcile_interval_seconds: 10,
            runtime_reconcile_max_parallel_nodes: 4,
            root_ownership_marker: root.join("root-ownership.json"),
            systemd_root: root.join("systemd"),
            systemctl_path: PathBuf::from("systemctl"),
        }
    }

    #[test]
    fn migra_host_identity_legacy_a_raiz_compartida_sin_borrar_origen() {
        let root =
            std::env::temp_dir().join(format!("actium-host-identity-migration-{}", Uuid::new_v4()));
        let config = test_config(&root);
        fs::create_dir_all(config.journal_path.parent().unwrap()).unwrap();
        let identity =
            actium_node_core::HostIdentity::from_installation_id(Uuid::new_v4().to_string());
        let legacy = config
            .journal_path
            .parent()
            .unwrap()
            .join("host-identity.json");
        fs::write(&legacy, serde_json::to_vec(&identity).unwrap()).unwrap();

        config.prepare_directories().unwrap();

        assert_eq!(
            actium_node_core::load_host_identity(&config.host_identity_root)
                .unwrap()
                .as_ref(),
            Some(&identity)
        );
        assert!(
            legacy.is_file(),
            "la copia legacy debe conservarse para rollback"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owner_confirmed_ata_canal_y_raices_canonicales() {
        let root = std::env::temp_dir().join(format!("actium-root-owner-{}", Uuid::new_v4()));
        let config = test_config(&root);
        fs::create_dir_all(&config.authorized_nodes_root).unwrap();
        fs::create_dir_all(&config.authorized_fabrics_root).unwrap();
        let marker = RootOwnershipMarker {
            schema: 1,
            owner: "actium-node-supervisor".to_string(),
            product_channel: "lab".to_string(),
            root_id: Uuid::new_v4().to_string(),
            authorized_nodes_root: config.authorized_nodes_root.to_string_lossy().into_owned(),
            authorized_fabrics_root: config
                .authorized_fabrics_root
                .to_string_lossy()
                .into_owned(),
            confirmed_at: None,
            confirmed_by: None,
        };
        fs::write(
            &config.root_ownership_marker,
            serde_json::to_vec_pretty(&marker).unwrap(),
        )
        .unwrap();
        verify_owner_confirmed_roots(&config).unwrap();

        let mut stable = config.clone();
        stable.product_channel = "stable".to_string();
        let error = verify_owner_confirmed_roots(&stable).unwrap_err();
        assert!(error.contains("pertenece al canal lab"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_reconcile_interval_tiene_default_seguro() {
        let parsed: SupervisorConfig = toml::from_str(
            r#"
product_channel = "lab"
fabric_project = "actium-lab-fabric-01"
fabric_network = "actium-lab-fabric-01"
"#,
        )
        .unwrap();
        assert_eq!(parsed.runtime_reconcile_interval_seconds, 10);
        assert_eq!(parsed.runtime_reconcile_max_parallel_nodes, 4);
        assert!(parsed.runtime_reconcile_interval_seconds.max(5) >= 5);
    }

    #[test]
    fn prepara_boundary_de_ceremonia_sin_tocar_contenido() {
        let root = std::env::temp_dir()
            .join(format!("actium-ceremony-boundary-{}", Uuid::new_v4()));
        let selected = root.join("owner-selected").join("offline-root");
        prepare_ceremony_directory(&selected, "offline_root").unwrap();
        assert!(selected.is_dir());
        assert!(!selected
            .read_dir()
            .unwrap()
            .any(|entry| entry.is_ok()));
        #[cfg(unix)]
        if Uid::effective().is_root() {
            let metadata = fs::symlink_metadata(&selected).unwrap();
            assert_eq!(metadata.uid(), 0);
            assert_eq!(metadata.gid(), 0);
            assert_eq!(metadata.mode() & 0o777, 0o700);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn valida_ruta_seleccionada_sin_enumerar_contenido() {
        let root = std::env::temp_dir()
            .join(format!("actium-ceremony-path-status-{}", Uuid::new_v4()));
        let config = test_config(&root);
        let selected = root.join("owner-selected").join("offline-root");
        let status = authority_ceremony_path_preflight(
            &config,
            AuthorityCeremonyPathRequest {
                path: selected.to_string_lossy().into_owned(),
                purpose: "offline_root".into(),
            },
        );
        assert_eq!(status.state, "READY");
        assert_eq!(status.code, None);
        assert!(status.exists);
        assert!(status.directory);
        assert!(status.writable);
        assert!(selected.read_dir().unwrap().next().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sealing_key_offline_queda_dentro_de_la_custodia_seleccionada() {
        let root = std::env::temp_dir().join(format!("actium-ceremony-sealing-path-{}", Uuid::new_v4()));
        let selected = root.join("owner-selected").join("offline-root");
        let selected_with_trailing_separator = PathBuf::from(format!("{}{}", selected.display(), std::path::MAIN_SEPARATOR));
        let sealing = authority_ceremony_offline_sealing_key_path(&selected_with_trailing_separator);

        assert_eq!(sealing, selected.join(".actium-root-sealing.key"));
        assert_eq!(sealing.parent(), Some(selected.as_path()));
        assert_ne!(sealing, root.join(".actium-root-sealing.key"));
    }

    #[test]
    fn probe_de_archivo_existente_prueba_el_directorio_padre() {
        let root = std::env::temp_dir().join(format!("actium-ceremony-file-probe-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("sealing.key");
        fs::write(&file, "sensitive-test-placeholder").unwrap();

        effective_write_probe(&file).unwrap();

        assert_eq!(fs::read_to_string(&file).unwrap(), "sensitive-test-placeholder");
        assert!(!root
            .read_dir()
            .unwrap()
            .any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".actium-write-probe-")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn permite_unicamente_el_sealing_key_previamente_staged() {
        let root = std::env::temp_dir().join(format!("actium-ceremony-staged-key-{}", Uuid::new_v4()));
        let offline = root.join("offline-root");
        fs::create_dir_all(&offline).unwrap();
        let sealing = offline.join(".actium-root-sealing.key");
        fs::write(&sealing, "ACTIUM-SEALING-KEY-V1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
            .unwrap();

        validate_offline_ceremony_directory(&offline, &sealing).unwrap();
        fs::write(offline.join("unexpected-entry"), "not ceremony material").unwrap();
        assert_eq!(
            validate_offline_ceremony_directory(&offline, &sealing).unwrap_err(),
            "AUTHORITY_OFFLINE_DIR_NOT_EMPTY"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rechaza_ruta_de_ceremonia_prohibida_desde_selector() {
        let root = std::env::temp_dir()
            .join(format!("actium-ceremony-path-forbidden-{}", Uuid::new_v4()));
        let config = test_config(&root);
        let forbidden = root.join("target").join("debug").join("node");
        let status = authority_ceremony_path_preflight(
            &config,
            AuthorityCeremonyPathRequest {
                path: forbidden.to_string_lossy().into_owned(),
                purpose: "recovery_dir".into(),
            },
        );
        assert_eq!(status.state, "BLOCKED");
        assert_eq!(status.code.as_deref(), Some("AUTHORITY_CEREMONY_PATH_FORBIDDEN"));
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
    }
}
