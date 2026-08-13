#[cfg(not(target_os = "linux"))]
compile_error!("actium-node-supervisor 0.2.0 solo se compila para Linux.");

use actium_node_core::{
    ipc::{load_ipc_key, read_framed_json, unix_timestamp, write_framed_json},
    network_inventory, redact_sensitive, verify_payload, CommissionNodeRequest,
    ConfigurationWriteRequest, FabricIdentity, JournalOperation, JournalUpdate, OperationJournal,
    RuntimeOperator, SupervisorClient, SupervisorCommand, SupervisorReply,
    SupervisorRequestEnvelope, SupervisorResponseEnvelope, VerifiedPayload, SUPERVISOR_VERSION,
};
use nix::unistd::{chown, Gid, Group};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use uuid::Uuid;

const DEFAULT_CONFIG_PATH: &str = "/etc/actium/node-manager/supervisor.toml";

#[derive(Debug, Clone, Deserialize)]
struct SupervisorConfig {
    #[serde(default = "default_socket_path")]
    socket_path: PathBuf,
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
    operator_group: String,
    #[serde(default = "default_network_interval")]
    network_reconcile_interval_seconds: u64,
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
            self.socket_path.parent(),
            Some(self.authorized_nodes_root.as_path()),
            Some(self.authorized_fabrics_root.as_path()),
            Some(self.log_dir.as_path()),
        ]
        .into_iter()
        .flatten()
        {
            fs::create_dir_all(path)
                .map_err(|error| format!("No se pudo crear {}: {error}", path.display()))?;
        }
        Ok(())
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("actium-node-supervisor: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut check_only = false;
    let mut ping_only = false;
    let mut self_test = false;
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
    let config = SupervisorConfig::load(&config_path)?;
    if ping_only {
        return match SupervisorClient::new(&config.socket_path, &config.ipc_key_path)
            .request(SupervisorCommand::Ping)?
        {
            SupervisorReply::Pong {
                supervisor_version,
                recovered_operations,
            } => {
                println!(
                    "Supervisor {supervisor_version} disponible; {recovered_operations} operacion(es) recuperadas al iniciar."
                );
                Ok(())
            }
            _ => Err("Supervisor devolvio una respuesta inesperada al ping.".to_string()),
        };
    }
    config.prepare_directories()?;
    let key = load_ipc_key(&config.ipc_key_path)?;
    let journal = OperationJournal::open(&config.journal_path)?;
    let fabric = resolve_fabric_identity(&config)?;
    let runtime = RuntimeOperator::new_with_fabric(
        &config.authorized_nodes_root,
        &config.authorized_fabrics_root,
        &config.payload_root,
        fabric,
        &config.fabric_identity_path,
    );
    if check_only {
        runtime_root_check(&config.authorized_nodes_root)?;
        verify_schema3_payload(&config.payload_root)?;
        println!("Supervisor {SUPERVISOR_VERSION}: configuracion, clave y journal validos.");
        return Ok(());
    }

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
    let listener = bind_socket(&config)?;
    eprintln!(
        "Actium Node Supervisor {SUPERVISOR_VERSION} listo en {} ({} operacion(es) recuperadas).",
        config.socket_path.display(),
        recovered_operations
    );
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let state = shared.clone();
                thread::spawn(move || {
                    if let Err(error) = serve_request(&mut stream, &state) {
                        eprintln!("Solicitud IPC rechazada: {error}");
                    }
                });
            }
            Err(error) => eprintln!("No se pudo aceptar IPC: {error}"),
        }
    }
    Ok(())
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
    println!("Supervisor {SUPERVISOR_VERSION}: IPC autenticado, framing y recovery durable OK.");
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

fn serve_request(
    stream: &mut std::os::unix::net::UnixStream,
    state: &SupervisorState,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| format!("No se pudo configurar timeout IPC: {error}"))?;
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
    let action = if request.prepare_only {
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
                eprintln!("Worker durable: {error}");
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
            eprintln!("No se pudo cerrar la operacion {}: {error}", operation.id);
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
                    eprintln!("Reconciliacion de red: {message}");
                }
            }
            Err(error) => eprintln!("Reconciliacion de red no disponible: {error}"),
        }
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
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640))
        .map_err(|error| format!("No se pudo restringir fabric-identity.json: {error}"))?;
    fs::rename(&temporary, &config.fabric_identity_path)
        .map_err(|error| format!("No se pudo promover identidad Fabric: {error}"))?;
    Ok(identity)
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/actium/node-manager.sock")
}
fn default_key_path() -> PathBuf {
    PathBuf::from("/etc/actium/node-manager/ipc.key")
}
fn default_journal_path() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/operations.sqlite3")
}
fn default_nodes_root() -> PathBuf {
    PathBuf::from("/srv/actium-data/nodes")
}
fn default_fabrics_root() -> PathBuf {
    PathBuf::from("/srv/actium-data/fabrics")
}
fn default_payload_root() -> PathBuf {
    PathBuf::from("/usr/lib/actium/node-manager/payload")
}
fn default_log_dir() -> PathBuf {
    PathBuf::from("/var/log/actium/node-manager")
}
fn default_fabric_identity_path() -> PathBuf {
    PathBuf::from("/var/lib/actium/node-manager/fabric-identity.json")
}
fn default_fabric_id() -> String {
    "auto".to_string()
}
fn default_fabric_project() -> String {
    "actium-lab-fabric-01".to_string()
}
fn default_fabric_network() -> String {
    "actium-lab-fabric-01".to_string()
}
fn default_operator_group() -> String {
    "actium-node-operators".to_string()
}
fn default_network_interval() -> u64 {
    15
}
