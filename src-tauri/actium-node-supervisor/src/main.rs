use actium_node_core::{
    ipc::{load_ipc_key, read_framed_json, unix_timestamp, write_framed_json},
    network_inventory, redact_sensitive, verify_payload, AttestationSigner, CommissionNodeRequest,
    ConfigurationWriteRequest, FabricIdentity, JournalOperation, JournalUpdate,
    MaterialAttestationStatement, OperationJournal, RuntimeOperator, SupervisorClient,
    SupervisorCommand, SupervisorReply, SupervisorRequestEnvelope, SupervisorResponseEnvelope,
    VerifiedPayload, SUPERVISOR_VERSION,
};
#[cfg(unix)]
use nix::unistd::{chown, Gid, Group};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
#[cfg(windows)]
use std::sync::OnceLock;
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
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
    #[serde(default = "default_nodes_root")]
    authorized_nodes_root: PathBuf,
    #[serde(default = "default_fabrics_root")]
    authorized_fabrics_root: PathBuf,
    #[serde(default = "default_payload_root")]
    payload_root: PathBuf,
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
            Some(self.log_dir.as_path()),
            self.fabric_identity_path.parent(),
        ]
        .into_iter()
        .flatten()
        {
            fs::create_dir_all(path)
                .map_err(|error| format!("No se pudo crear {}: {error}", path.display()))?;
        }
        #[cfg(unix)]
        if let Some(path) = self.socket_path.parent() {
            fs::create_dir_all(path)
                .map_err(|error| format!("No se pudo crear {}: {error}", path.display()))?;
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

fn main() {
    if let Err(error) = run() {
        eprintln!("actium-node-supervisor: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let mut config_path = default_config_path();
    let mut check_only = false;
    let mut ping_only = false;
    let mut self_test = false;
    let mut service_mode = false;
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
            _ => return Err(format!("Argumento no reconocido: {argument}.")),
        }
    }
    if self_test {
        return run_self_test();
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
            } => {
                println!(
                    "Supervisor {supervisor_version} protocolo {protocol_version} features {} ; {recovered_operations} operacion(es) recuperadas al iniciar.",
                    features.join(",")
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
        verify_schema3_payload(&config.payload_root)?;
        let _ = resolve_fabric_identity(&config)?;
        println!(
            "Supervisor {SUPERVISOR_VERSION}: configuracion {}, canal {} y raices owner-confirmed OK.",
            config_path.display(),
            config.product_channel
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
    let runtime = RuntimeOperator::new_with_fabric_and_channel(
        &config.authorized_nodes_root,
        &config.authorized_fabrics_root,
        &config.payload_root,
        fabric,
        &config.fabric_identity_path,
        &config.product_channel,
    )?;

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
    });

    start_operation_worker(shared.clone());
    start_network_reconciler(shared.clone());
    start_attestation_reconciler(shared.clone());
    start_runtime_reconciler(shared.clone());
    serve_ipc(shared, &config, shutdown, service_mode)
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
        state: "queued".to_string(),
        queued_at: now.clone(),
        started_at: None,
        finished_at: None,
        current_step: "queued".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
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
            };
            Ok(SupervisorReply::Operation(Box::new(
                state.journal.enqueue(&operation)?,
            )))
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
        state: "running".to_string(),
        queued_at: started_at.clone(),
        started_at: Some(started_at.clone()),
        finished_at: None,
        current_step: "executing_synchronous".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
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
        state: "running".to_string(),
        queued_at: started_at.clone(),
        started_at: Some(started_at.clone()),
        finished_at: None,
        current_step: "commissioning".to_string(),
        output_redacted: String::new(),
        recovery_policy: "inspect_then_retry".to_string(),
        error_code: None,
    })?;
    let result = state.runtime.commission_node(&request);
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
        state: "running".to_string(),
        queued_at: started_at.clone(),
        started_at: Some(started_at.clone()),
        finished_at: None,
        current_step: "persisting_configuration".to_string(),
        output_redacted: String::new(),
        recovery_policy: "restore_configuration_backup".to_string(),
        error_code: None,
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
        let progress = |status: &str, step: &str| {
            let _ = journal.update(
                &job_id,
                JournalUpdate {
                    state: status,
                    current_step: step,
                    output: "",
                    started_at: Some(&started_at),
                    finished_at: None,
                    error_code: None,
                },
            );
        };
        let result = if operation.action == "update" {
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
            authorized_nodes_root: root.join("nodes"),
            authorized_fabrics_root: root.join("fabrics"),
            payload_root: root.join("payload"),
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
        }
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
}
