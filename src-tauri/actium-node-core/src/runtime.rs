use crate::topology::channel_project_prefix;
use crate::{
    attestation::{AttestedContainer, AttestedFabric, AttestedRuntimeUnit},
    canonical_json, continuity_gate_error, evaluate_continuity_status, evaluate_desired_payload_gate,
    evaluate_docker_inspect, host_deployment_attestation_dir, host_identities_have_canonical_journal,
    host_identities_root, host_identity_snapshot_dir, read_continuity_status, read_desired_payload_pin,
    reconcile_node_network, redact_json_sensitive,
    redact_sensitive, restore_attestation_identity, restore_attestation_journal,
    snapshot_attestation_identity, snapshot_attestation_journal, verify_payload,
    AttestationAuthorityState, AttestationJournal, AttestationSigner, CommissionNodeRequest,
    ConfigurationWriteRequest, FabricIdentity, MaterialAttestationStatement, NodeReleaseState,
    NodeRuntimeSummary, ProjectAuditSummary, ProjectServiceSummary, ReleaseManager,
    ReleasePromotion, ReleaseRecoveryHold, RuntimeStartupCohort, RuntimeStartupGate,
    RuntimeTopology, RuntimeUnitActionRequest, RuntimeUnitHealth, RuntimeUnitInventory,
    VerifiedPayload,
};
use crate::fabric_policy::{
    clamp_runtime_reconcile_parallelism, plan_fabric_release, FabricEnsureMode, FabricReleasePlan,
};
use crate::runtime_intent::{
    decide_runtime_reconcile, migrate_runtime_desired_state, RuntimeDesiredState, RuntimeIntent,
    RuntimeIntentSource, RuntimeReconcileDecision, RuntimeStartupMode,
    RUNTIME_INTENT_RELATIVE_PATH,
};
#[cfg(unix)]
use crate::RuntimeUnit;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Arc, Condvar, Mutex};

#[cfg(test)]
#[derive(Clone)]
struct ReconcileTestIntercept {
    healthy: bool,
    become_healthy_after_start: bool,
    start_count: Arc<AtomicU64>,
    stop_count: Arc<AtomicU64>,
    exercise_fabric: bool,
    fabric_modes: Arc<Mutex<Vec<FabricEnsureMode>>>,
    fabric_promotions: Arc<AtomicU64>,
    node_holds: Arc<Mutex<HashMap<String, Arc<NodeReconcileHold>>>>,
    finished_nodes: Arc<Mutex<Vec<String>>>,
    finished_signal: Arc<Condvar>,
}

#[cfg(test)]
struct NodeReconcileHold {
    released: Mutex<bool>,
    cvar: Condvar,
    entered: AtomicBool,
}

#[cfg(test)]
impl ReconcileTestIntercept {
    fn locally_healthy(&self) -> bool {
        self.healthy
            || (self.become_healthy_after_start && self.start_count.load(Ordering::SeqCst) > 0)
    }
}

#[cfg(test)]
thread_local! {
    static RECONCILE_TEST_INTERCEPT: RefCell<Option<ReconcileTestIntercept>> = const { RefCell::new(None) };
}

pub const WORKLOAD_SYMLINK_REJECTED: &str = "WORKLOAD_SYMLINK_REJECTED";
pub const WORKLOAD_SPECIAL_FILE_REJECTED: &str = "WORKLOAD_SPECIAL_FILE_REJECTED";

const MARKER_FILE: &str = ".actium-node-installation.json";
const ALLOWED_ACTIONS: [&str; 16] = [
    "status",
    "start",
    "stop",
    "restart",
    "update",
    "verify",
    "logs",
    "diagnostics",
    "audit_terminal",
    "audit_gps",
    "audit_dvr",
    "audit_ht",
    "logs_ht",
    "apply_configuration",
    "save_configuration",
    "purge",
];
const CONFIGURATION_KEYS: [&str; 70] = [
    "ACTIUM_INSTALLER_VERSION",
    "RADIO_SAF_ENABLED",
    "RADIO_LIVEKIT_ENABLED",
    "NODE_ROOT_PATH",
    "SITE_CORE_DATA_PATH",
    "TELEMETRY_DATA_PATH",
    "DVR_MEDIA_PATH",
    "PEOPLE_DATA_PATH",
    "CONTROL_RUNTIME_DATA_PATH",
    "RADIO_CONTROL_DATA_PATH",
    "RADIO_SAF_STORAGE_PATH",
    "TURN_DATA_PATH",
    "LIVEKIT_DATA_PATH",
    "PROMETHEUS_DATA_PATH",
    "GRAFANA_DATA_PATH",
    "CONNECTIVITY_SPOOL_PATH",
    "DATA_PLANE_NETWORK_MODE",
    "DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED",
    "ACTIUM_NETWORK_RECONCILIATION_POLICY",
    "ACTIUM_NETWORK_INTERFACE",
    "ACTIUM_NETWORK_ADDRESS",
    "ACTIUM_NETWORK_PLANE",
    "ACTIUM_NETWORK_PRIORITY",
    "DATA_PLANE_BIND_ADDRESS",
    "DATA_PLANE_PUBLIC_BASE_URL",
    "DATA_PLANE_CORS_ORIGINS",
    "TELEMETRY_INGRESS_PUBLIC_URL",
    "TELEMETRY_READ_PUBLIC_URL",
    "METRICS_PUBLIC_URL",
    "RADIO_CONTROL_PUBLIC_URL",
    "SITE_CORE_PUBLIC_URL",
    "PEOPLE_RESOLVE_PUBLIC_URL",
    "CONTROL_RUNTIME_PUBLIC_URL",
    "CONTROL_OBJECT_STORAGE_PUBLIC_URL",
    "TURN_URLS",
    "TELEMETRY_PORT",
    "GPS_STREAM_MAX_BYTES",
    "HEARTBEAT_STREAM_MAX_BYTES",
    "RADIO_CONTROL_PORT",
    "SITE_CORE_PORT",
    "PEOPLE_PORT",
    "CONTROL_RUNTIME_PORT",
    "CONTROL_OBJECT_STORAGE_PORT",
    "RADIO_ARCHIVE_HOST_PATH",
    "PROMETHEUS_PORT",
    "GRAFANA_PORT",
    "TURN_REALM",
    "TURN_EXTERNAL_IP",
    "TURN_PORT",
    "TURN_TLS_PORT",
    "TURN_MIN_PORT",
    "TURN_MAX_PORT",
    "LIVEKIT_NODE_IP",
    "LIVEKIT_PUBLIC_URL",
    "LIVEKIT_HTTP_PORT",
    "LIVEKIT_RTC_TCP_PORT",
    "LIVEKIT_UDP_MIN_PORT",
    "LIVEKIT_UDP_MAX_PORT",
    "CONNECTIVITY_EDGE_CONTROL_URL",
    "CONNECTIVITY_NODE_ROLE",
    "CONNECTIVITY_NODE_PRIORITY",
    "CONNECTIVITY_PULL_LIMIT",
    "CONNECTIVITY_SYNC_ENABLED",
    "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED",
    "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED",
    "CONNECTIVITY_FALLBACK_ORDER",
    "CONNECTIVITY_PREFERRED_TRANSPORT",
    "CONNECTIVITY_ALLOWED_TRANSPORTS",
    "CONNECTIVITY_GATEWAY_STRATEGY",
    "CONNECTIVITY_ROAMING_ALLOWED",
];

pub type RuntimeProgress<'a> = dyn Fn(&str, &str, Option<&str>) + 'a;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeActionResult {
    pub message: String,
    pub output: String,
    pub release_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReconcileReport {
    pub node: String,
    pub message: String,
    pub idle: bool,
    pub skipped_busy: bool,
}

#[derive(Debug, Clone)]
pub struct RuntimeOperator {
    authorized_nodes_root: PathBuf,
    authorized_fabrics_root: PathBuf,
    payload_root: PathBuf,
    fabric: FabricIdentity,
    fabric_identity_path: PathBuf,
    attestation_identity_path: PathBuf,
    manager_channel: String,
    project_prefix: String,
}

impl RuntimeOperator {
    pub fn validate_action(action: &str) -> Result<(), String> {
        if ALLOWED_ACTIONS.contains(&action) {
            Ok(())
        } else {
            Err(format!("Operacion no permitida por Supervisor: {action}."))
        }
    }

    pub fn new(
        authorized_nodes_root: impl Into<PathBuf>,
        payload_root: impl Into<PathBuf>,
    ) -> Self {
        let authorized_nodes_root = authorized_nodes_root.into();
        let root = authorized_nodes_root
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Self {
            authorized_nodes_root,
            authorized_fabrics_root: root.join("fabrics"),
            payload_root: payload_root.into(),
            fabric: FabricIdentity {
                fabric_id: "11111111-1111-4111-8111-111111111111".to_string(),
                compose_project: "actium-lab-fabric-01".to_string(),
                network_name: "actium-lab-fabric-01".to_string(),
                host_id: None,
            },
            fabric_identity_path: root.join("fabric-identity.json"),
            attestation_identity_path: root.join("attestation-identity.key"),
            manager_channel: "lab".to_string(),
            project_prefix: "actium-lab-".to_string(),
        }
    }

    pub fn new_with_fabric(
        authorized_nodes_root: impl Into<PathBuf>,
        authorized_fabrics_root: impl Into<PathBuf>,
        payload_root: impl Into<PathBuf>,
        fabric: FabricIdentity,
        fabric_identity_path: impl Into<PathBuf>,
    ) -> Self {
        Self::new_with_fabric_and_channel(
            authorized_nodes_root,
            authorized_fabrics_root,
            payload_root,
            fabric,
            fabric_identity_path,
            "lab",
        )
        .expect("el canal Lab embebido debe ser valido")
    }

    pub fn new_with_fabric_and_channel(
        authorized_nodes_root: impl Into<PathBuf>,
        authorized_fabrics_root: impl Into<PathBuf>,
        payload_root: impl Into<PathBuf>,
        fabric: FabricIdentity,
        fabric_identity_path: impl Into<PathBuf>,
        manager_channel: &str,
    ) -> Result<Self, String> {
        let project_prefix = channel_project_prefix(manager_channel)?.to_string();
        let fabric_identity_path = fabric_identity_path.into();
        let attestation_identity_path = fabric_identity_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("attestation-identity.key");
        Ok(Self {
            authorized_nodes_root: authorized_nodes_root.into(),
            authorized_fabrics_root: authorized_fabrics_root.into(),
            payload_root: payload_root.into(),
            fabric,
            fabric_identity_path,
            attestation_identity_path,
            manager_channel: manager_channel.to_string(),
            project_prefix,
        })
    }

    pub fn execute(
        &self,
        install_dir: &Path,
        action: &str,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<RuntimeActionResult, String> {
        Self::validate_action(action)?;
        if action == "purge" {
            return self.purge_node(install_dir, progress);
        }
        let node_root = self.validate_node_root(install_dir)?;
        revalidate_node_secret_acls(&node_root)?;
        let config = node_config(&node_root)?;
        let project = project_name(&config)?;
        if !project.starts_with(&self.project_prefix) {
            return Err(format!(
                "Supervisor {} rechazo el proyecto fuera del namespace {}: {project}.",
                self.manager_channel, self.project_prefix
            ));
        }
        let releases = ReleaseManager::new(&node_root);
        let mut node_mutation = matches!(
            action,
            "start" | "stop" | "restart" | "update" | "apply_configuration" | "save_configuration"
        )
        .then(|| releases.lock_mutation())
        .transpose()?;
        if matches!(action, "start" | "restart" | "apply_configuration") {
            let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
            let runtime = releases.active_runtime_dir()?;
            self.require_runtime_start_capabilities(&node_root, &runtime, &topology)?;
        }
        if action == "start" || action == "restart" {
            self.persist_runtime_intent(
                &node_root,
                RuntimeDesiredState::Running,
                RuntimeIntentSource::Operator,
            )?;
        } else if action == "stop" {
            self.persist_runtime_intent(
                &node_root,
                RuntimeDesiredState::Stopped,
                RuntimeIntentSource::Operator,
            )?;
        }

        if action == "start" || action == "restart" {
            if !test_reconcile_intercept_active() {
                let network = reconcile_node_network(&node_root, true)?;
                if network.changed {
                    eprintln!("{}", network.message);
                }
            }
            let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
            self.ensure_fabric(
                &node_root,
                &topology,
                FabricEnsureMode::ActiveReleaseOnly,
            )?;
        }

        if action == "update" {
            let intent = self.load_or_migrate_runtime_intent(&node_root)?;
            if intent.as_ref().map(|value| value.desired_state)
                == Some(RuntimeDesiredState::Stopped)
            {
                return Err(
                    "UPDATE_REQUIRES_RUNNING_INTENT: el nodo esta detenido; inícielo antes de promover una release."
                        .to_string(),
                );
            }
            if !test_reconcile_intercept_active() {
                let network = reconcile_node_network(&node_root, true)?;
                if network.changed {
                    eprintln!("{}", network.message);
                }
            }
            return self.transactional_update(
                &node_root,
                node_mutation
                    .take()
                    .ok_or_else(|| "Update no adquirio lock de nodo.".to_string())?,
                progress,
                intent,
            );
        }
        if action == "save_configuration" {
            let _ = self.load_or_migrate_runtime_intent(&node_root)?;
            return Ok(RuntimeActionResult {
                message: "Configuracion persistida; el runtime conserva su estado actual."
                    .to_string(),
                output: "Supervisor registro la configuracion pendiente sin ejecutar Docker."
                    .to_string(),
                release_version: None,
            });
        }
        if action == "apply_configuration" {
            let intent = self.load_or_migrate_runtime_intent(&node_root)?;
            if intent.as_ref().map(|value| value.desired_state)
                == Some(RuntimeDesiredState::Stopped)
            {
                commit_configuration_backup(&node_root)?;
                update_marker(&node_root, Some("stopped"), None, None)?;
                return Ok(RuntimeActionResult {
                    message: "Configuracion persistida; el intent stopped se conservo.".to_string(),
                    output: "Supervisor no inicio el runtime porque desiredState=stopped."
                        .to_string(),
                    release_version: None,
                });
            }

            if !test_reconcile_intercept_active() {
                let network = reconcile_node_network(&node_root, true)?;
                if network.changed {
                    eprintln!("{}", network.message);
                }
            }
            let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
            self.ensure_fabric(
                &node_root,
                &topology,
                FabricEnsureMode::ActiveReleaseOnly,
            )?;

            let candidate = self
                .restart_runtime_topology(&node_root)
                .and_then(|output| {
                    self.wait_health_gate(&node_root)
                        .map(|health| format!("{output}\n\n{health}"))
                });
            return match candidate {
                Ok(output) => {
                    commit_configuration_backup(&node_root)?;
                    update_marker(&node_root, Some("running"), None, None)?;
                    Ok(RuntimeActionResult {
                        message: "Configuracion aplicada y validada por Supervisor.".to_string(),
                        output,
                        release_version: None,
                    })
                }
                Err(candidate_error) => {
                    if let Err(restore_error) = restore_configuration_backup(&node_root) {
                        let message = format!(
                            "Configuracion candidata fallo ({candidate_error}) y su backup no pudo restaurarse ({restore_error})."
                        );
                        let _ = update_marker(&node_root, Some("failed"), None, Some(&message));
                        return Err(format!("[MANUAL_INTERVENTION_REQUIRED] {message}"));
                    }
                    let recovery = self
                        .restart_runtime_topology(&node_root)
                        .and_then(|output| {
                            self.wait_health_gate(&node_root)
                                .map(|health| format!("{output}\n\n{health}"))
                        });
                    match recovery {
                        Ok(output) => Err(format!(
                            "[ROLLED_BACK] La configuracion candidata fallo ({candidate_error}) y Supervisor restauro la anterior.\n\n{output}"
                        )),
                        Err(recovery_error) => Err(format!(
                            "[MANUAL_INTERVENTION_REQUIRED] La configuracion candidata fallo ({candidate_error}) y la anterior no recupero ({recovery_error})."
                        )),
                    }
                }
            };
        }
        let effective_action = match action {
            "audit_terminal" | "audit_gps" | "audit_dvr" | "audit_ht" => "verify",
            "logs_ht" => "logs",
            other => other,
        };
        let mut output = match effective_action {
            "start" => self.start_runtime_topology(&node_root)?,
            "restart" => self.restart_runtime_topology(&node_root)?,
            _ => self.run_action_with_progress(&node_root, effective_action, progress)?,
        };
        if matches!(action, "start" | "restart") {
            output = format!("{output}\n\n{}", self.wait_health_gate(&node_root)?);
            update_marker(&node_root, Some("running"), None, None)?;
        } else if action == "stop" {
            update_marker(&node_root, Some("stopped"), None, None)?;
        }
        Ok(RuntimeActionResult {
            message: format!("Operacion {action} completada por Supervisor."),
            output,
            release_version: None,
        })
    }

    pub fn purge_node(
        &self,
        install_dir: &Path,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<RuntimeActionResult, String> {
        let root = canonical_existing(&self.authorized_nodes_root)?;
        let node_path = canonical_existing(install_dir).or_else(|_| {
            let path = install_dir.to_path_buf();
            if path.exists() {
                Ok(path)
            } else {
                Err(format!("El directorio de nodo no existe: {}", install_dir.display()))
            }
        })?;
        if node_path == root || !node_path.starts_with(&root) {
            return Err(format!(
                "Ruta fuera de la raiz autorizada de Supervisor: {}.",
                node_path.display()
            ));
        }
        let node_name = node_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("nodo")
            .to_string();

        if let Some(report) = progress {
            report("running", "stopping_containers", None);
        }

        let mut output_lines = Vec::new();
        output_lines.push(format!("Iniciando purga de residuos para el nodo: {node_name}"));
        output_lines.push(format!("Ruta autorizada validada: {}", node_path.display()));

        let mut stopped_containers = false;
        let manage_script = if cfg!(windows) {
            node_path.join("manage-node.ps1")
        } else {
            node_path.join("manage-node.sh")
        };
        if manage_script.exists() {
            output_lines.push("Deteniendo servicios de runtime units existentes...".to_string());
            #[cfg(windows)]
            let mut cmd = Command::new("powershell.exe");
            #[cfg(windows)]
            cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", &manage_script.to_string_lossy(), "stop"]);
            #[cfg(not(windows))]
            let mut cmd = Command::new("/bin/sh");
            #[cfg(not(windows))]
            cmd.arg(&manage_script).arg("stop");
            cmd.current_dir(&node_path);
            if let Ok(out) = cmd.output() {
                output_lines.push(format!("manage-node stop finalizo (status={})", out.status));
                stopped_containers = true;
            }
        }

        if !stopped_containers {
            let compose_path = node_path.join("compose.yml");
            if compose_path.exists() {
                output_lines.push("Ejecutando docker compose down para el proyecto...".to_string());
                let mut cmd = Command::new("docker");
                cmd.args(["compose", "-f", &compose_path.to_string_lossy(), "down", "--remove-orphans", "-v"]);
                cmd.current_dir(&node_path);
                let _ = cmd.output();
            }
        }

        let mut filter_cmd = Command::new("docker");
        filter_cmd.args(["ps", "-a", "--filter", &format!("name={node_name}"), "--format", "{{.ID}}"]);
        if let Ok(out) = filter_cmd.output() {
            let ids = String::from_utf8_lossy(&out.stdout);
            let container_ids: Vec<&str> = ids.split_whitespace().collect();
            if !container_ids.is_empty() {
                output_lines.push(format!("Eliminando {} contenedor(es) Docker asociado(s)...", container_ids.len()));
                let mut rm_cmd = Command::new("docker");
                rm_cmd.args(["rm", "-f"]);
                rm_cmd.args(&container_ids);
                let _ = rm_cmd.output();
            }
        }

        if let Some(report) = progress {
            report("running", "purging_files", None);
        }

        output_lines.push(format!("Eliminando directorio y arbol de archivos en {}", node_path.display()));
        if cfg!(unix) {
            // Asegurar que archivos creados por containers/UIDs distintos pasen a ser propiedad del proceso
            let _ = Command::new("chown").args(["-R", "0:0", &node_path.to_string_lossy()]).output();
            let _ = Command::new("chmod").args(["-R", "u+rwX,go+rwX", &node_path.to_string_lossy()]).output();
        }
        if let Err(err) = fs::remove_dir_all(&node_path) {
            output_lines.push(format!("Advertencia inicial con fs::remove_dir_all: {err}"));
            if cfg!(unix) {
                let _ = Command::new("chmod").args(["-R", "777", &node_path.to_string_lossy()]).output();
                let _ = Command::new("rm").args(["-rf", &node_path.to_string_lossy()]).output();
                if node_path.exists() {
                    if let Err(e2) = fs::remove_dir_all(&node_path) {
                        return Err(format!("No se pudo eliminar el directorio {}: {e2}", node_path.display()));
                    }
                }
            } else {
                let _ = Command::new("attrib").args(["-R", "-S", "-H", &format!("{}\\*", node_path.display()), "/S", "/D"]).output();
                if let Err(e2) = fs::remove_dir_all(&node_path) {
                    let mut ps_cmd = Command::new("powershell.exe");
                    let script = format!("Remove-Item -Path '{}' -Recurse -Force", node_path.display());
                    ps_cmd.args([
                        "-NoProfile",
                        "-Command",
                        &format!("Start-Process powershell.exe -ArgumentList '-NoProfile -Command {}' -Verb RunAs -Wait", script),
                    ]);
                    let _ = ps_cmd.output();
                    if node_path.exists() {
                        return Err(format!("No se pudo eliminar el directorio {}: {e2}", node_path.display()));
                    }
                }
            }
        }
        output_lines.push("Directorio y residuos eliminados del disco satisfactoriamente.".to_string());

        if let Some(report) = progress {
            report("completed", "purge_completed", None);
        }

        Ok(RuntimeActionResult {
            message: format!("Residuos del nodo {node_name} eliminados exitosamente."),
            output: output_lines.join("\n"),
            release_version: None,
        })
    }

    pub fn validate_operation_target(&self, install_dir: &Path) -> Result<PathBuf, String> {
        let root = canonical_existing(&self.authorized_nodes_root)?;
        let node = canonical_existing(install_dir).or_else(|_| {
            let path = install_dir.to_path_buf();
            if path.exists() {
                Ok(path)
            } else {
                Err(format!("El nodo no existe: {}", install_dir.display()))
            }
        })?;
        if node == root || !node.starts_with(&root) {
            return Err(format!(
                "Ruta fuera de la raiz autorizada de Supervisor: {}.",
                node.display()
            ));
        }
        let marker_path = node.join(MARKER_FILE);
        if marker_path.exists() {
            if let Ok(marker_str) = fs::read_to_string(&marker_path) {
                if let Ok(marker) = serde_json::from_str::<serde_json::Value>(&marker_str) {
                    if marker
                        .get("managerChannel")
                        .and_then(serde_json::Value::as_str)
                        != Some(self.manager_channel.as_str())
                    {
                        return Err(format!(
                            "Supervisor {} solo administra nodos con managerChannel={}.",
                            self.manager_channel, self.manager_channel
                        ));
                    }
                }
            }
        }
        Ok(node)
    }

    pub fn payload_release_version(&self) -> Result<String, String> {
        match verify_payload(&self.payload_root)? {
            VerifiedPayload::Schema3(manifest) => Ok(manifest.release_version),
            VerifiedPayload::LegacyUnverified { .. } => {
                Err("Supervisor exige payload schema 3.".to_string())
            }
        }
    }

    pub fn commission_node(
        &self,
        request: &CommissionNodeRequest,
    ) -> Result<RuntimeActionResult, String> {
        self.commission_node_with_progress(request, None)
    }

    pub fn commission_node_with_progress(
        &self,
        request: &CommissionNodeRequest,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<RuntimeActionResult, String> {
        let candidate_manifest = match verify_payload(&self.payload_root)? {
            VerifiedPayload::Schema3(manifest) => manifest,
            VerifiedPayload::LegacyUnverified { .. } => {
                return Err("Supervisor exige payload schema 3.".to_string())
            }
        };
        let candidate_release = candidate_manifest.release_version.clone();
        if candidate_release != request.expected_release {
            return Err(format!(
                "Manager solicito {}, pero Supervisor posee {}.",
                request.expected_release, candidate_release
            ));
        }
        let node_root = if request.resume_incomplete {
            self.prepare_incomplete_commission_root(Path::new(&request.install_dir), request)?
        } else {
            self.prepare_new_node_root(Path::new(&request.install_dir))?
        };
        let marker = serde_json::from_str::<serde_json::Value>(&request.marker)
            .map_err(|error| format!("Marcador de commissioning invalido: {error}"))?;
        if marker
            .get("managerChannel")
            .and_then(serde_json::Value::as_str)
            != Some(self.manager_channel.as_str())
        {
            return Err(format!(
                "Commissioning rechazo un marcador que no pertenece a {}.",
                self.manager_channel
            ));
        }
        let mut config = parse_env_document(&request.node_env);
        let marker_installation_id = marker
            .get("installationId")
            .and_then(serde_json::Value::as_str);
        let node_installation_id = crate::require_node_installation_id(
            marker_installation_id,
            config
                .get(crate::NODE_INSTALLATION_ENV_KEY)
                .map(String::as_str),
        )?;
        crate::apply_node_installation_id(&mut config, &node_installation_id);
        let host_scope = if request.resume_incomplete {
            crate::HostIdentityScope::PreTopologyLeftover
        } else {
            crate::HostIdentityScope::Fresh
        };
        let leftover_for_host = if request.resume_incomplete {
            fs::read_to_string(node_root.join("node.env"))
                .map(|contents| parse_env_document(&contents))
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        let host_identity = self.resolve_host_identity(&leftover_for_host, host_scope)?;
        host_identity.apply_to_env(&mut config);
        let requested_profiles = config
            .get("ACTIUM_PROFILES")
            .map(|value| crate::parse_profile_list(value))
            .unwrap_or_default();
        candidate_manifest.require_supported_profiles(&requested_profiles)?;
        candidate_manifest.require_supported_features(&required_runtime_features(&config))?;
        crate::validate_active_configuration(&requested_profiles, &config)?;
        let project = project_name(&config)?;
        if !project.starts_with(&self.project_prefix) {
            return Err(format!(
                "Commissioning rechazo el proyecto fuera del namespace {}: {project}.",
                self.project_prefix
            ));
        }
        if let Some(path) = request.radio_archive_host_path.as_deref() {
            self.ensure_node_storage_path(&node_root, path)?;
        }
        for storage_key in [
            "SITE_CORE_DATA_PATH",
            "TELEMETRY_DATA_PATH",
            "DVR_MEDIA_PATH",
            "PEOPLE_DATA_PATH",
            "CONTROL_RUNTIME_DATA_PATH",
            "RADIO_CONTROL_DATA_PATH",
            "RADIO_SAF_STORAGE_PATH",
            "TURN_DATA_PATH",
            "LIVEKIT_DATA_PATH",
            "PROMETHEUS_DATA_PATH",
            "GRAFANA_DATA_PATH",
            "CONNECTIVITY_SPOOL_PATH",
        ] {
            if let Some(path) = config.get(storage_key).filter(|p| !p.trim().is_empty()) {
                self.ensure_node_storage_path(&node_root, path)?;
            }
        }
        if !requested_profiles
            .iter()
            .any(|profile| profile == "connectivity")
            && (request
                .connectivity_edge_enrollment_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
                || request
                    .connectivity_internal_relay_token
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()))
        {
            return Err(
                "Supervisor rechazo secretos Connectivity en un commissioning sin ese perfil."
                    .to_string(),
            );
        }
        let authored_env = render_env_document(&config);
        if let Some(report) = progress {
            report("running", "preparing_release", None);
        }

        let releases = ReleaseManager::new(&node_root);
        let prepared = releases.prepare(&self.payload_root)?;
        let transaction = releases.begin_promotion(prepared)?;
        let candidate = transaction
            .promoted_state()
            .active_release
            .as_ref()
            .map(|release| node_root.join(&release.relative_path))
            .ok_or_else(|| "Promocion no materializo release candidato.".to_string())?;
        let result = (|| {
            promotion_checkpoint("commission.before_topology")?;
            let node_env = if request.resume_incomplete {
                let leftover = fs::read_to_string(node_root.join("node.env"))
                    .map(|contents| parse_env_document(&contents))
                    .unwrap_or_default();
                let preserve_network = leftover
                    .get("DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED")
                    .map(String::as_str)
                    == Some("true")
                    || config
                        .get("DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED")
                        .map(String::as_str)
                        == Some("true");
                let mut merged = crate::merge_resume_env(
                    &leftover,
                    &config,
                    &requested_profiles,
                    preserve_network,
                )?;
                crate::apply_node_installation_id(&mut merged, &node_installation_id);
                host_identity.apply_to_env(&mut merged);
                crate::validate_active_configuration(&requested_profiles, &merged)?;
                render_env_document(&merged)
            } else {
                authored_env.clone()
            };
            write_managed_file(&node_root.join("node.env"), &node_env, 0o644)?;
            write_managed_file(&node_root.join(MARKER_FILE), &request.marker, 0o644)?;
            write_managed_file(
                &node_root.join("keys/actium-terminal-public.pem"),
                &request.terminal_public_key,
                0o644,
            )?;
            write_managed_file(
                &node_root.join("keys/actium-operator-public.pem"),
                &request.operator_public_key,
                0o644,
            )?;
            if let Some(value) = &request.site_runtime_public_key {
                write_managed_file(
                    &node_root.join("keys/actium-site-runtime-bundle-public.pem"),
                    value,
                    0o644,
                )?;
            }
            if let Some(value) = &request.initial_people_policy_cache {
                validate_initial_people_policy_cache(value, &config)?;
                write_managed_file(
                    &node_root.join("state/agent/people-policy.json"),
                    value,
                    0o600,
                )?;
            }
            if let Some(value) = &request.control_plane_ca_pem {
                if value.len() > 256 * 1024
                    || !value.contains("-----BEGIN CERTIFICATE-----")
                    || !value.contains("-----END CERTIFICATE-----")
                {
                    return Err("CONTROL_PLANE_CA_PEM_INVALID".to_string());
                }
                write_managed_file(
                    &node_root.join("secrets/control_plane_ca.pem"),
                    &format!("{}\n", value.trim()),
                    0o600,
                )?;
            }
            write_optional_secret(
                &node_root.join("secrets/connectivity_edge_enrollment_token"),
                request.connectivity_edge_enrollment_token.as_deref(),
            )?;
            write_optional_secret(
                &node_root.join("secrets/connectivity_internal_relay_token"),
                request.connectivity_internal_relay_token.as_deref(),
            )?;
            promotion_checkpoint("commission.topology")?;
            if let Some(report) = progress {
                report("running", "materializing_topology", None);
            }
            let topology = self.materialize_runtime_topology(&node_root)?;
            sync_release_marker(&node_root, transaction.promoted_state(), "installing", None)?;
            if !request.prepare_only {
                promotion_checkpoint("commission.fabric")?;
                self.ensure_fabric(
                    &node_root,
                    &topology,
                    FabricEnsureMode::AllowPayloadPromotion,
                )?;
            }
            self.run_installer_at(&node_root, &candidate, &request.enrollment_token, true, progress)
                .and_then(|output| {
                    if request.prepare_only {
                        Ok(output)
                    } else {
                        promotion_checkpoint("commission.before_runtime_start")?;
                        if let Some(report) = progress {
                            report("running", "starting_runtime", None);
                        }
                        self.start_runtime_topology_at(
                            &node_root,
                            &candidate,
                            RuntimeStartupMode::Commissioning,
                            progress,
                        )
                            .and_then(|bootstrap| {
                                promotion_checkpoint("commission.final_health")?;
                                self.wait_health_gate(&node_root)
                                    .map(|health| format!("{output}\n\n{bootstrap}\n\n{health}"))
                            })
                    }
                })
        })();
        match result {
            Ok(output) => {
                let active = transaction.commit()?;
                let status = if request.prepare_only {
                    "prepared"
                } else {
                    "running"
                };
                sync_release_marker(&node_root, &active, status, None)?;
                if !request.prepare_only {
                    self.persist_runtime_intent(
                        &node_root,
                        RuntimeDesiredState::Running,
                        RuntimeIntentSource::Commissioning,
                    )?;
                }
                Ok(RuntimeActionResult {
                    message: if request.resume_incomplete {
                        format!("Nodo {project} reanudado por Supervisor.")
                    } else {
                        format!("Nodo {project} creado por Supervisor.")
                    },
                    output,
                    release_version: active.active_release.map(|release| release.release_version),
                })
            }
            Err(error) => {
                let _ = self.run_action_at(&node_root, &candidate, "stop", None);
                Err(self.abort_node_promotion(&node_root, transaction, &error))
            }
        }
    }

    fn materialize_runtime_topology(&self, node_root: &Path) -> Result<RuntimeTopology, String> {
        let config = node_config(node_root)?;
        let required = |key: &str| {
            config
                .get(key)
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("Commissioning requiere {key}."))
        };
        let profiles = required("ACTIUM_PROFILES")?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        let host_identity = self.resolve_host_identity(&config, crate::HostIdentityScope::Fresh)?;
        let host_installation_id = host_identity.host_installation_id.clone();
        let mut topology = RuntimeTopology::materialize_for_channel(
            &self.manager_channel,
            &host_installation_id,
            required("ACTIUM_DEPLOYMENT_ID")?,
            required("ACTIUM_DEPLOYMENT_CODE")?,
            &profiles,
            self.fabric.clone(),
            node_root,
        )?;
        if config.get("SITE_CORE_RUNTIME_ROLE").map(String::as_str) == Some("standby") {
            let has_candidate_feature = required_runtime_features(&config)
                .iter()
                .any(|feature| feature == "site_core_candidate_v1");
            if !has_candidate_feature
                || config.get("SITE_CORE_FENCING_STATE").map(String::as_str) != Some("fenced")
                || config.get("SITE_CORE_AUTHORITY_MODE").map(String::as_str) != Some("disabled")
            {
                return Err("SITE_CORE_CANDIDATE_RUNTIME_INTENT_INVALID".to_string());
            }
            let site_core = topology
                .units
                .iter_mut()
                .find(|unit| unit.capability == "site-core")
                .ok_or_else(|| "SITE_CORE_CANDIDATE_PROFILE_REQUIRED".to_string())?;
            site_core.compose_file = "compose.site-core-candidate.yml".to_string();
        }
        prepare_agent_state_storage(node_root)?;
        let units_root = node_root.join("state/runtime-units");
        fs::create_dir_all(&units_root)
            .map_err(|error| format!("No se pudo crear runtime-units: {error}"))?;
        set_unix_mode(&units_root, 0o750)?;

        let telemetry_project = topology
            .units
            .iter()
            .find(|unit| unit.capability == "telemetry")
            .map(|unit| unit.compose_project.clone());
        let livekit_project = topology
            .units
            .iter()
            .find(|unit| unit.capability == "livekit")
            .map(|unit| unit.compose_project.clone());
        let radio_project = topology
            .units
            .iter()
            .find(|unit| unit.capability == "radio-control")
            .map(|unit| unit.compose_project.clone());
        for (index, unit) in topology.units.iter().enumerate() {
            let secrets = PathBuf::from(&unit.binding.secrets_directory);
            fs::create_dir_all(&secrets).map_err(|error| {
                format!(
                    "No se pudo crear secrets de runtime unit {}: {error}",
                    unit.runtime_unit_id
                )
            })?;
            set_unix_mode(&secrets, 0o700)?;
            if unit.binding.database_role.is_some() {
                write_secret_if_missing(&secrets.join("postgres_password"), &random_secret())?;
            }
            if unit.capability == "people" {
                write_secret_if_missing(
                    &secrets.join("people_migrator_password"),
                    &random_secret(),
                )?;
                write_secret_if_missing(&secrets.join("people_fingerprint_key"), &random_secret())?;
                make_node_service_readable_secret(&secrets.join("postgres_password"))?;
                make_node_service_readable_secret(&secrets.join("people_migrator_password"))?;
                make_node_service_readable_secret(&secrets.join("people_fingerprint_key"))?;
            }
            if unit.capability == "control" {
                write_secret_if_missing(
                    &secrets.join("control_migrator_password"),
                    &random_secret(),
                )?;
                write_secret_if_missing(
                    &secrets.join("control_idempotency_key"),
                    &random_secret(),
                )?;
                write_secret_if_missing(
                    &secrets.join("control_s3_access_key"),
                    &format!("ctl_{}", &short_digest(&unit.runtime_unit_id)[..20]),
                )?;
                write_secret_if_missing(
                    &secrets.join("control_s3_secret_key"),
                    &random_secret(),
                )?;
                write_secret_if_missing(
                    &secrets.join("control_s3_root_access_key"),
                    &format!("root_{}", &short_digest(&unit.runtime_unit_id)[..20]),
                )?;
                write_secret_if_missing(
                    &secrets.join("control_s3_root_secret_key"),
                    &random_secret(),
                )?;
                make_node_service_readable_secret(&secrets.join("postgres_password"))?;
                make_node_service_readable_secret(&secrets.join("control_migrator_password"))?;
                make_node_service_readable_secret(&secrets.join("control_idempotency_key"))?;
                make_node_service_readable_secret(&secrets.join("control_s3_access_key"))?;
                make_node_service_readable_secret(&secrets.join("control_s3_secret_key"))?;
                make_node_service_readable_secret(&secrets.join("control_s3_root_access_key"))?;
                make_node_service_readable_secret(&secrets.join("control_s3_root_secret_key"))?;
            }
            if unit.binding.nats_user.is_some() {
                write_secret_if_missing(&secrets.join("nats_password"), &random_secret())?;
            }
            if unit.capability == "radio-saf" {
                write_secret_if_missing(
                    &secrets.join("minio_root_user"),
                    &format!("saf_{}", &short_digest(&unit.runtime_unit_id)[..16]),
                )?;
                write_secret_if_missing(&secrets.join("minio_root_password"), &random_secret())?;
            }
            prepare_runtime_unit_storage(node_root, unit)?;

            let token = short_digest(&unit.runtime_unit_id);
            let mut values = BTreeMap::from([
                ("ACTIUM_RUNTIME_UNIT_ID", unit.runtime_unit_id.clone()),
                ("ACTIUM_RUNTIME_CAPABILITY", unit.capability.clone()),
                ("ACTIUM_RUNTIME_UNIT_PROJECT", unit.compose_project.clone()),
                ("ACTIUM_RUNTIME_COMPOSE_FILE", unit.compose_file.clone()),
                (
                    "ACTIUM_RUNTIME_UNIT_TOKEN",
                    token[..16].to_ascii_uppercase(),
                ),
                ("ACTIUM_NODE_ROOT", unix_path(node_root)),
                ("ACTIUM_SECRETS_DIR", unix_path(&node_root.join("secrets"))),
                (
                    "ACTIUM_RUNTIME_UNIT_SECRETS_DIR",
                    unix_path(&PathBuf::from(&unit.binding.secrets_directory)),
                ),
                (
                    "ACTIUM_RUNTIME_UNIT_CONFIG_DIR",
                    unix_path(
                        &node_root
                            .join("state/runtime-units")
                            .join(&unit.runtime_unit_id),
                    ),
                ),
                ("ACTIUM_FABRIC_ID", topology.fabric.fabric_id.clone()),
                (
                    "ACTIUM_FABRIC_PROJECT",
                    topology.fabric.compose_project.clone(),
                ),
                (
                    "ACTIUM_FABRIC_NETWORK",
                    topology.fabric.network_name.clone(),
                ),
                (
                    "ACTIUM_DEPLOYMENT_NETWORK",
                    topology.deployment_network_name.clone(),
                ),
                (
                    "ACTIUM_FABRIC_POSTGRES_HOST",
                    format!("{}-postgres", topology.fabric.compose_project),
                ),
                (
                    "ACTIUM_FABRIC_NATS_HOST",
                    format!("{}-nats", topology.fabric.compose_project),
                ),
                ("ACTIUM_UNIT_CPUS", unit.resources.cpus.clone()),
                (
                    "ACTIUM_UNIT_MEMORY_LIMIT",
                    unit.resources.memory_limit.clone(),
                ),
                (
                    "ACTIUM_UNIT_MEMORY_RESERVATION",
                    unit.resources.memory_reservation.clone(),
                ),
                (
                    "ACTIUM_UNIT_PIDS_LIMIT",
                    unit.resources.pids_limit.to_string(),
                ),
                (
                    "ACTIUM_UNIT_LOG_MAX_SIZE",
                    unit.resources.log_max_size.clone(),
                ),
                (
                    "ACTIUM_UNIT_LOG_MAX_FILES",
                    unit.resources.log_max_files.to_string(),
                ),
            ]);
            for key in crate::capability_surface::profile_env_keys(&unit.capability) {
                if let Some(val) = config.get(*key) {
                    values.insert(*key, val.clone());
                }
            }
            for key in [
                "ACTIUM_DEPLOYMENT_ID",
                "ACTIUM_SITE_ID",
                "ACTIUM_TERMINAL_ISSUER",
                "ACTIUM_OPERATOR_ISSUER",
                "SITE_RUNTIME_EXPECTED_ISSUER",
                "SITE_RUNTIME_SCHEMA_VERSION",
                "DATA_PLANE_CORS_ORIGINS",
                "DATA_PLANE_BIND_ADDRESS",
                "DATA_PLANE_PUBLIC_BASE_URL",
            ] {
                if let Some(val) = config.get(key) {
                    values.insert(key, val.clone());
                }
            }
            if let Some(value) = &unit.binding.database_role {
                values.insert("ACTIUM_RUNTIME_DB_USER", value.clone());
                if matches!(unit.capability.as_str(), "people" | "control") {
                    values.insert("ACTIUM_RUNTIME_DB_MIGRATOR_USER", format!("{value}_owner"));
                }
            }
            if let Some(value) = &unit.binding.database_schema {
                values.insert("ACTIUM_RUNTIME_DB_SCHEMA", value.clone());
            }
            if let Some(value) = &unit.binding.nats_account {
                values.insert("ACTIUM_RUNTIME_NATS_ACCOUNT", value.clone());
            }
            if let Some(value) = &unit.binding.nats_user {
                values.insert("ACTIUM_RUNTIME_NATS_USER", value.clone());
            }
            if let Some(value) = &unit.binding.nats_subject_prefix {
                values.insert("ACTIUM_RUNTIME_NATS_SUBJECT_PREFIX", value.clone());
            }
            if let Some(bucket) = unit.binding.storage_buckets.first() {
                values.insert("ACTIUM_STORAGE_BUCKET", bucket.clone());
            }
            if unit.capability == "telemetry" {
                values.insert(
                    "ACTIUM_NATS_STREAM",
                    format!("T_{}_GPS", &token[..12].to_ascii_uppercase()),
                );
                values.insert(
                    "ACTIUM_NATS_HEARTBEAT_STREAM",
                    format!("T_{}_HEARTBEAT", &token[..12].to_ascii_uppercase()),
                );
                values.insert(
                    "ACTIUM_NATS_CONSUMER",
                    format!("gps-projector-{}", &token[..12]),
                );
                values.insert(
                    "ACTIUM_NATS_HEARTBEAT_CONSUMER",
                    format!("heartbeat-projector-{}", &token[..12]),
                );
            }
            if unit.capability == "connectivity" {
                let project = telemetry_project.as_ref().ok_or_else(|| {
                    "Connectivity no pudo resolver su runtime unit Telemetry.".to_string()
                })?;
                values.insert(
                    "ACTIUM_TELEMETRY_INTERNAL_URL",
                    format!("http://{project}-gateway:8090"),
                );
                values.insert("ACTIUM_TELEMETRY_COMPOSE_PROJECT", project.clone());
            }
            if unit.capability == "radio-control" {
                if let Some(project) = &livekit_project {
                    values.insert(
                        "LIVEKIT_INTERNAL_URL",
                        format!("http://{project}-livekit:17880"),
                    );
                    values.insert("RADIO_LIVEKIT_ENABLED", "true".to_string());
                } else {
                    values.insert("RADIO_LIVEKIT_ENABLED", "false".to_string());
                }
            }
            if unit.capability == "observability" {
                let config_root = node_root
                    .join("state/runtime-units")
                    .join(&unit.runtime_unit_id);
                fs::create_dir_all(&config_root).map_err(|error| {
                    format!("No se pudo crear config de Observability: {error}")
                })?;
                let mut scrape = String::from(
                    "global:\n  scrape_interval: 15s\n  evaluation_interval: 15s\n\nscrape_configs:\n",
                );
                if let Some(project) = &telemetry_project {
                    scrape.push_str(&format!(
                        "  - job_name: telemetry-gateway\n    static_configs: [{{ targets: [\"{project}-gateway:8090\"] }}]\n  - job_name: telemetry-projector\n    static_configs: [{{ targets: [\"{project}-projector:8091\"] }}]\n"
                    ));
                }
                if let Some(project) = &radio_project {
                    scrape.push_str(&format!(
                        "  - job_name: radio-control\n    static_configs: [{{ targets: [\"{project}-radio-control:8100\"] }}]\n"
                    ));
                }
                if let Some(project) = &livekit_project {
                    scrape.push_str(&format!(
                        "  - job_name: livekit\n    static_configs: [{{ targets: [\"{project}-livekit:6789\"] }}]\n"
                    ));
                }
                write_managed_file(&config_root.join("prometheus.yml"), &scrape, 0o640)?;
            }
            let contents = values
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("\n");
            write_managed_file(
                &units_root.join(format!(
                    "{index:02}-{}-{}.env",
                    unit.capability,
                    &unit.runtime_unit_id[..8]
                )),
                &format!("{contents}\n"),
                0o640,
            )?;
        }
        write_runtime_topology_atomic(
            &node_root.join("state/runtime-topology.json"),
            &serde_json::to_value(&topology)
                .map_err(|error| format!("No se pudo serializar topologia: {error}"))?,
        )?;
        let env_path = node_root.join("node.env");
        let current = fs::read_to_string(&env_path)
            .map_err(|error| format!("No se pudo leer node.env: {error}"))?;
        let mut topology_env = BTreeMap::from([
            (
                "ACTIUM_FABRIC_ID".to_string(),
                topology.fabric.fabric_id.clone(),
            ),
            (
                "ACTIUM_FABRIC_PROJECT".to_string(),
                topology.fabric.compose_project.clone(),
            ),
            (
                "ACTIUM_FABRIC_NETWORK".to_string(),
                topology.fabric.network_name.clone(),
            ),
            (
                "ACTIUM_DEPLOYMENT_NETWORK".to_string(),
                topology.deployment_network_name.clone(),
            ),
            (
                "ACTIUM_RUNTIME_TOPOLOGY_SCHEMA".to_string(),
                crate::topology::RUNTIME_TOPOLOGY_SCHEMA.to_string(),
            ),
        ]);
        host_identity.apply_to_env(&mut topology_env);
        let updated = updated_env_document(&current, &topology_env);
        write_managed_file(&env_path, &updated, 0o640)?;
        Ok(topology)
    }

    fn host_identity_state_dir(&self) -> Result<PathBuf, String> {
        self.fabric_identity_path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "fabric_identity_path no tiene directorio padre.".to_string())
    }

    fn resolve_host_identity(
        &self,
        leftover_env: &BTreeMap<String, String>,
        scope: crate::HostIdentityScope,
    ) -> Result<crate::HostIdentity, String> {
        crate::reconcile_host_identity(&self.host_identity_state_dir()?, leftover_env, scope)
    }

    fn ensure_fabric(
        &self,
        node_root: &Path,
        topology: &RuntimeTopology,
        mode: FabricEnsureMode,
    ) -> Result<(), String> {
        record_fabric_ensure_mode(mode);
        let root = self.ensure_fabric_root(&topology.fabric)?;
        let releases = ReleaseManager::new(&root);
        let mut fabric_mutation = Some(releases.lock_mutation()?);
        let state = releases.load_state()?;

        if matches!(mode, FabricEnsureMode::ActiveReleaseOnly)
            && state.active_release.is_none()
        {
            return Err("FABRIC_ACTIVE_RELEASE_REQUIRED".to_string());
        }

        let skip_actuation = test_fabric_actuation_skipped();

        for directory in ["persistent/postgres", "secrets", "state"] {
            fs::create_dir_all(root.join(directory))
                .map_err(|error| format!("No se pudo preparar Fabric {directory}: {error}"))?;
        }
        if !skip_actuation {
            prepare_fabric_nats_storage(&root)?;
        }
        set_unix_mode(&root.join("secrets"), 0o700)?;
        write_secret_if_missing(
            &root.join("secrets/postgres_admin_password"),
            &random_secret(),
        )?;
        let config = node_config(node_root)?;
        let install_mode = if config
            .get("ACTIUM_USE_PUBLISHED_IMAGES")
            .is_some_and(|value| value == "true")
        {
            "published_images"
        } else {
            "local_build"
        };
        let fabric_env = format!(
            "ACTIUM_FABRIC_ID={}\nACTIUM_FABRIC_PROJECT={}\nACTIUM_FABRIC_NETWORK={}\nACTIUM_FABRIC_ROOT={}\nACTIUM_INSTALL_MODE={}\n",
            topology.fabric.fabric_id,
            topology.fabric.compose_project,
            topology.fabric.network_name,
            unix_path(&root),
            install_mode,
        );
        write_managed_file(&root.join("fabric.env"), &fabric_env, 0o640)?;
        write_json_atomic(
            &root.join("state/fabric-identity.json"),
            &serde_json::to_value(&topology.fabric)
                .map_err(|error| format!("No se pudo serializar Fabric: {error}"))?,
        )?;
        let nats_changed = if skip_actuation {
            false
        } else {
            self.write_nats_runtime_config(&root)?
        };
        if !skip_actuation {
            ensure_docker_network(&topology.fabric.network_name, &topology.fabric.fabric_id)?;
            ensure_deployment_docker_network(
                &topology.deployment_network_name,
                &topology.deployment_id,
            )?;
        }

        let active_matches_payload = if matches!(mode, FabricEnsureMode::AllowPayloadPromotion) {
            match verify_payload(&self.payload_root)? {
                VerifiedPayload::Schema3(manifest) => state.active_release.as_ref().is_some_and(|release| {
                    release.release_version == manifest.release_version
                        && release.release_digest == manifest.tree_sha256
                }),
                VerifiedPayload::LegacyUnverified { .. } => {
                    return Err("Supervisor exige payload schema 3 para Fabric.".to_string())
                }
            }
        } else {
            false
        };
        let plan = plan_fabric_release(
            mode,
            state.active_release.is_some(),
            active_matches_payload,
        )?;
        let transaction = if matches!(plan, FabricReleasePlan::PromoteSupervisorPayload) {
            record_fabric_promotion();
            let prepared = releases.prepare(&self.payload_root)?;
            Some(
                releases.begin_promotion_locked(
                    prepared,
                    fabric_mutation
                        .take()
                        .ok_or_else(|| "Fabric no conserva lock de promocion.".to_string())?,
                )?,
            )
        } else {
            None
        };
        let runtime = releases.active_runtime_dir()?;
        let start_result = (|| {
            promotion_checkpoint("fabric.before_start")?;
            if skip_actuation {
                return Ok("fabric_restored:intercepted".to_string());
            }
            run_fabric_compose(&root, &runtime, &topology.fabric, install_mode).and_then(|output| {
                promotion_checkpoint("fabric.provision")?;
                if nats_changed {
                    restart_healthy_container(&format!(
                        "{}-nats",
                        topology.fabric.compose_project
                    ))?;
                }
                self.provision_database_units(topology)?;
                Ok(output)
            })
        })();
        match start_result {
            Ok(_) => {
                if let Some(transaction) = transaction {
                    transaction.commit()?;
                }
                Ok(())
            }
            Err(error) => match transaction {
                None => Err(error),
                Some(transaction) => {
                    let aborted = transaction.abort().map_err(|abort_error| {
                        format!(
                            "[MANUAL_INTERVENTION_REQUIRED] Fabric fallo ({error}) y su aborto no persistio ({abort_error})."
                        )
                    })?;
                    if !aborted.recovery_required {
                        return Err(format!(
                            "[FIRST_INSTALL_ABORTED] Fabric candidato rechazado: {error}"
                        ));
                    }
                    let previous = aborted
                        .state
                        .active_release
                        .as_ref()
                        .map(|release| root.join(&release.relative_path))
                        .ok_or_else(|| "Fabric abortado no conserva LKG activo.".to_string())?;
                    match run_fabric_compose(&root, &previous, &topology.fabric, install_mode) {
                        Ok(_) => {
                            aborted.complete_recovery()?;
                            Err(format!("[ROLLED_BACK] Fabric candidato rechazado: {error}"))
                        }
                        Err(recovery_error) => {
                            let persistence = aborted.fail_recovery().map(|_| ()).map_err(|state_error| {
                                format!("; ademas no se pudo persistir intervencion manual ({state_error})")
                            });
                            Err(format!(
                                "[MANUAL_INTERVENTION_REQUIRED] Fabric fallo ({error}) y LKG no recupero ({recovery_error}){}.",
                                persistence.err().unwrap_or_default()
                            ))
                        }
                    }
                }
            },
        }
    }

    fn ensure_fabric_root(&self, fabric: &FabricIdentity) -> Result<PathBuf, String> {
        fs::create_dir_all(&self.authorized_fabrics_root).map_err(|error| {
            format!(
                "No se pudo crear {}: {error}",
                self.authorized_fabrics_root.display()
            )
        })?;
        let root = canonical_existing(&self.authorized_fabrics_root)?;
        let candidate = root.join(&fabric.fabric_id);
        if !candidate.exists() {
            fs::create_dir(&candidate)
                .map_err(|error| format!("No se pudo crear Fabric: {error}"))?;
        }
        let candidate = canonical_existing(&candidate)?;
        if candidate.parent() != Some(root.as_path()) {
            return Err("Fabric salio de authorized_fabrics_root.".to_string());
        }
        set_unix_mode(&candidate, 0o750)?;
        fs::create_dir_all(candidate.join("state"))
            .map_err(|error| format!("No se pudo crear state de Fabric: {error}"))?;
        Ok(candidate)
    }

    fn write_nats_runtime_config(&self, fabric_root: &Path) -> Result<bool, String> {
        let mut accounts = Vec::new();
        let nodes_root = canonical_existing(&self.authorized_nodes_root)?;
        for entry in fs::read_dir(&nodes_root)
            .map_err(|error| format!("No se pudo leer topologias: {error}"))?
        {
            let entry = entry.map_err(|error| format!("Entrada de topology invalida: {error}"))?;
            let topology_path = entry.path().join("state/runtime-topology.json");
            if !topology_path.is_file() {
                continue;
            }
            let topology = load_topology(&topology_path)?;
            if topology.fabric.fabric_id != self.fabric.fabric_id {
                return Err(format!(
                    "La topologia {} declara un Fabric ajeno al Supervisor.",
                    topology.deployment_id
                ));
            }
            for unit in topology
                .units
                .iter()
                .filter(|unit| unit.binding.nats_account.is_some())
            {
                let account = unit.binding.nats_account.as_deref().unwrap_or_default();
                let user = unit.binding.nats_user.as_deref().unwrap_or_default();
                let password = fs::read_to_string(
                    PathBuf::from(&unit.binding.secrets_directory).join("nats_password"),
                )
                .map_err(|error| format!("No se pudo leer password NATS de {user}: {error}"))?;
                accounts.push((
                    account.to_string(),
                    user.to_string(),
                    password.trim().to_string(),
                ));
            }
        }
        accounts.sort();
        accounts.dedup_by(|left, right| left.0 == right.0);
        let mut config = String::from(
            "port: 4222\nhttp_port: 8222\nmax_payload: 1048576\njetstream { store_dir: /data }\naccounts {\n",
        );
        if accounts.is_empty() {
            config.push_str("  FABRIC_SYSTEM: { jetstream: enabled }\n");
        }
        for (account, user, password) in accounts {
            config.push_str(&format!(
                "  {account}: {{\n    jetstream: enabled\n    users: [{{ user: \"{user}\", password: \"{password}\" }}]\n  }}\n"
            ));
        }
        config.push_str("}\n");
        let path = fabric_root.join("secrets/nats-runtime.conf");
        if fs::read_to_string(&path).ok().as_deref() == Some(config.as_str()) {
            return Ok(false);
        }
        write_managed_file(&path, &config, 0o600)?;
        Ok(true)
    }

    fn provision_database_units(&self, topology: &RuntimeTopology) -> Result<(), String> {
        for unit in topology
            .units
            .iter()
            .filter(|unit| unit.binding.database_role.is_some())
        {
            let role = unit.binding.database_role.as_deref().unwrap_or_default();
            let schema = unit.binding.database_schema.as_deref().unwrap_or_default();
            if !safe_sql_identifier(role) || !safe_sql_identifier(schema) {
                return Err("Identidad SQL de runtime unit invalida.".to_string());
            }
            let password = fs::read_to_string(
                PathBuf::from(&unit.binding.secrets_directory).join("postgres_password"),
            )
            .map_err(|error| format!("No se pudo leer password PostgreSQL de {role}: {error}"))?;
            let password = password.trim();
            if password.is_empty() || password.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
                return Err("Password PostgreSQL administrado no es hexadecimal.".to_string());
            }
            let sql = if matches!(unit.capability.as_str(), "people" | "control") {
                let owner_role = format!("{role}_owner");
                if !safe_sql_identifier(&owner_role) {
                    return Err(format!(
                        "Identidad SQL de migracion {} invalida.",
                        unit.capability
                    ));
                }
                let migrator_secret = format!("{}_migrator_password", unit.capability);
                let owner_password = fs::read_to_string(
                    PathBuf::from(&unit.binding.secrets_directory)
                        .join(&migrator_secret),
                )
                .map_err(|error| {
                    format!(
                        "No se pudo leer password PostgreSQL de migracion {}: {error}",
                        unit.capability
                    )
                })?;
                let owner_password = owner_password.trim();
                if owner_password.is_empty()
                    || owner_password
                        .bytes()
                        .any(|byte| !byte.is_ascii_hexdigit())
                {
                    return Err(
                        format!(
                            "Password PostgreSQL administrado de migracion {} no es hexadecimal.",
                            unit.capability
                        ),
                    );
                }
                format!(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN CREATE ROLE {role} LOGIN PASSWORD '{password}'; ELSE ALTER ROLE {role} WITH LOGIN PASSWORD '{password}'; END IF; END $$;\nALTER ROLE {role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nDO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{owner_role}') THEN CREATE ROLE {owner_role} LOGIN PASSWORD '{owner_password}'; ELSE ALTER ROLE {owner_role} WITH LOGIN PASSWORD '{owner_password}'; END IF; END $$;\nALTER ROLE {owner_role} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nREASSIGN OWNED BY {role} TO {owner_role};\nCREATE SCHEMA IF NOT EXISTS {schema} AUTHORIZATION {owner_role};\nALTER SCHEMA {schema} OWNER TO {owner_role};\nREVOKE ALL ON SCHEMA {schema} FROM PUBLIC;\nREVOKE ALL ON SCHEMA {schema} FROM {role};\nGRANT USAGE ON SCHEMA {schema} TO {role};\nREVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA {schema} FROM PUBLIC, {role};\nREVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA {schema} FROM PUBLIC, {role};\nREVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA {schema} FROM PUBLIC, {role};\nALTER DEFAULT PRIVILEGES FOR ROLE {owner_role} IN SCHEMA {schema} REVOKE ALL ON TABLES FROM PUBLIC;\nALTER DEFAULT PRIVILEGES FOR ROLE {owner_role} IN SCHEMA {schema} REVOKE ALL ON SEQUENCES FROM PUBLIC;\nALTER DEFAULT PRIVILEGES FOR ROLE {owner_role} IN SCHEMA {schema} REVOKE ALL ON FUNCTIONS FROM PUBLIC;\nALTER ROLE {role} IN DATABASE actium_fabric SET search_path TO {schema}, public;\nALTER ROLE {owner_role} IN DATABASE actium_fabric SET search_path TO {schema}, public;\nGRANT CONNECT ON DATABASE actium_fabric TO {role}, {owner_role};\n"
                )
            } else {
                format!(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN CREATE ROLE {role} LOGIN PASSWORD '{password}'; ELSE ALTER ROLE {role} WITH LOGIN PASSWORD '{password}'; END IF; END $$;\nCREATE SCHEMA IF NOT EXISTS {schema} AUTHORIZATION {role};\nALTER SCHEMA {schema} OWNER TO {role};\nALTER ROLE {role} IN DATABASE actium_fabric SET search_path TO {schema}, public;\nGRANT CONNECT ON DATABASE actium_fabric TO {role};\n"
                )
            };
            let mut child = Command::new("docker")
                .args([
                    "exec",
                    "-i",
                    &format!("{}-postgres", topology.fabric.compose_project),
                    "psql",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-U",
                    "actium_fabric_admin",
                    "-d",
                    "actium_fabric",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| format!("No se pudo provisionar PostgreSQL: {error}"))?;
            child
                .stdin
                .as_mut()
                .ok_or_else(|| "PostgreSQL no habilito stdin.".to_string())?
                .write_all(sql.as_bytes())
                .map_err(|error| format!("No se pudo enviar contrato SQL: {error}"))?;
            output_text(
                child
                    .wait_with_output()
                    .map_err(|error| format!("No se pudo esperar PostgreSQL: {error}"))?,
            )?;
        }
        Ok(())
    }

    pub fn persist_configuration(
        &self,
        request: &ConfigurationWriteRequest,
    ) -> Result<RuntimeActionResult, String> {
        let node_root = self.validate_node_root(Path::new(&request.install_dir))?;
        let _mutation = ReleaseManager::new(&node_root).lock_mutation()?;
        let current_profiles = fs::read_to_string(node_root.join("node.env"))
            .ok()
            .and_then(|contents| {
                contents
                    .lines()
                    .find_map(|line| line.strip_prefix("ACTIUM_PROFILES="))
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|item| !item.is_empty())
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
            })
            .unwrap_or_default();
        for key in request.env_updates.keys() {
            if !CONFIGURATION_KEYS.contains(&key.as_str()) {
                return Err(format!(
                    "Supervisor rechazo la clave de configuracion {key}."
                ));
            }
            if key != "ACTIUM_INSTALLER_VERSION"
                && !crate::key_is_authoritative(&current_profiles, key)
            {
                return Err(format!(
                    "Supervisor rechazo la clave inactiva {key} para los perfiles instalados."
                ));
            }
        }
        if let Some(path) = request.radio_archive_host_path.as_deref() {
            if !current_profiles
                .iter()
                .any(|profile| profile == "radio-saf")
            {
                return Err(
                    "Supervisor rechazo RADIO_ARCHIVE_HOST_PATH en un nodo sin radio-saf."
                        .to_string(),
                );
            }
            self.ensure_node_storage_path(&node_root, path)?;
        }
        for storage_key in [
            "SITE_CORE_DATA_PATH",
            "TELEMETRY_DATA_PATH",
            "DVR_MEDIA_PATH",
            "PEOPLE_DATA_PATH",
            "CONTROL_RUNTIME_DATA_PATH",
            "RADIO_CONTROL_DATA_PATH",
            "RADIO_SAF_STORAGE_PATH",
            "TURN_DATA_PATH",
            "LIVEKIT_DATA_PATH",
            "PROMETHEUS_DATA_PATH",
            "GRAFANA_DATA_PATH",
            "CONNECTIVITY_SPOOL_PATH",
        ] {
            if let Some(path) = request.env_updates.get(storage_key).filter(|p| !p.trim().is_empty()) {
                self.ensure_node_storage_path(&node_root, path)?;
            }
        }
        if !current_profiles
            .iter()
            .any(|profile| profile == "connectivity")
            && (request
                .connectivity_edge_enrollment_token
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
                || request
                    .connectivity_internal_relay_token
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()))
        {
            return Err(
                "Supervisor rechazo secretos Connectivity en un nodo sin ese perfil.".to_string(),
            );
        }
        let env_path = node_root.join("node.env");
        let current = fs::read_to_string(&env_path)
            .map_err(|error| format!("No se pudo leer {}: {error}", env_path.display()))?;
        if request.prepare_rollback {
            backup_configuration(&node_root, &current)?;
        } else {
            clear_configuration_backup(&node_root)?;
        }
        let updated = updated_env_document(&current, &request.env_updates);
        let updated_values = parse_env_document(&updated);
        crate::validate_active_configuration(&current_profiles, &updated_values)?;
        write_managed_file(&env_path, &updated, 0o644)?;
        write_optional_secret(
            &node_root.join("secrets/connectivity_edge_enrollment_token"),
            request.connectivity_edge_enrollment_token.as_deref(),
        )?;
        write_optional_secret(
            &node_root.join("secrets/connectivity_internal_relay_token"),
            request.connectivity_internal_relay_token.as_deref(),
        )?;
        Ok(RuntimeActionResult {
            message: "Configuracion persistida por Supervisor.".to_string(),
            output: if request.prepare_rollback {
                "Backup local preparado hasta superar restart y health gate."
            } else {
                "Configuracion guardada sin reiniciar servicios."
            }
            .to_string(),
            release_version: None,
        })
    }

    pub fn recover_after_reboot(&self, install_dir: &Path) -> Result<Option<String>, String> {
        let report = self.reconcile_node_runtime(install_dir)?;
        if report.idle {
            Ok(None)
        } else {
            Ok(Some(report.message))
        }
    }

    pub fn recover_configuration_after_reboot(
        &self,
        install_dir: &Path,
    ) -> Result<Option<String>, String> {
        let node_root = self.validate_node_root(install_dir)?;
        revalidate_node_secret_acls(&node_root)?;
        let _mutation = ReleaseManager::new(&node_root).lock_mutation()?;
        if !configuration_backup_root(&node_root)
            .join("node.env")
            .is_file()
        {
            return Ok(None);
        }
        restore_configuration_backup(&node_root)?;
        let intent = self.load_or_migrate_runtime_intent(&node_root)?;
        if intent.as_ref().map(|value| value.desired_state)
            == Some(RuntimeDesiredState::Stopped)
        {
            update_marker(&node_root, Some("stopped"), None, None)?;
            return Ok(Some(
                "Configuracion interrumpida revertida; desiredState=stopped y el runtime permanece detenido."
                    .to_string(),
            ));
        }

        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        self.ensure_fabric(
            &node_root,
            &topology,
            FabricEnsureMode::ActiveReleaseOnly,
        )?;
        let output = self.restart_runtime_topology(&node_root)?;
        let health = self.wait_health_gate(&node_root)?;
        update_marker(&node_root, Some("running"), None, None)?;
        Ok(Some(format!(
            "Configuracion interrumpida revertida despues del reboot. {output}\n{health}"
        )))
    }

    pub fn reconcile_authorized_runtimes(&self) -> Result<Vec<String>, String> {
        self.reconcile_authorized_runtimes_bounded(4)
    }

    pub fn reconcile_authorized_runtimes_bounded(
        &self,
        max_parallel: usize,
    ) -> Result<Vec<String>, String> {
        if !self.authorized_nodes_root.is_dir() {
            return Ok(Vec::new());
        }
        let root = match canonical_existing(&self.authorized_nodes_root) {
            Ok(root) => root,
            Err(error) => return Err(error),
        };
        let mut entries = fs::read_dir(&root)
            .map_err(|error| format!("No se pudo recorrer la raiz de nodos: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Entrada de nodo invalida: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        let nodes = entries
            .into_iter()
            .filter(|entry| {
                entry
                    .file_type()
                    .map(|kind| kind.is_dir())
                    .unwrap_or(false)
                    && entry.path().join(MARKER_FILE).is_file()
            })
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        if nodes.is_empty() {
            return Ok(Vec::new());
        }
        let workers = clamp_runtime_reconcile_parallelism(max_parallel as u64).min(nodes.len());
        let (tx, rx) = std::sync::mpsc::channel();
        for path in nodes {
            tx.send(path)
                .map_err(|error| format!("No se pudo encolar nodo para reconciliar: {error}"))?;
        }
        drop(tx);
        let rx = std::sync::Mutex::new(rx);
        let messages = std::sync::Mutex::new(Vec::new());
        #[cfg(test)]
        let intercept = RECONCILE_TEST_INTERCEPT.with(|cell| cell.borrow().clone());
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    #[cfg(test)]
                    if let Some(intercept) = intercept.clone() {
                        RECONCILE_TEST_INTERCEPT.with(|cell| {
                            *cell.borrow_mut() = Some(intercept);
                        });
                    }
                    loop {
                        let path = {
                            let receiver = match rx.lock() {
                                Ok(guard) => guard,
                                Err(_) => break,
                            };
                            match receiver.recv() {
                                Ok(path) => path,
                                Err(_) => break,
                            }
                        };
                        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            self.reconcile_node_runtime(&path)
                        }));
                        let message = match outcome {
                            Ok(Ok(report)) if report.idle && report.skipped_busy => {
                                Some(report.message)
                            }
                            Ok(Ok(report)) if report.idle => None,
                            Ok(Ok(report)) => Some(report.message),
                            Ok(Err(error)) => Some(format!(
                                "{}: reconciliacion de runtime no disponible: {error}",
                                path.file_name()
                                    .and_then(|value| value.to_str())
                                    .unwrap_or("node")
                            )),
                            Err(_) => Some(format!(
                                "{}: reconciliacion de runtime abortada por panic aislado.",
                                path.file_name()
                                    .and_then(|value| value.to_str())
                                    .unwrap_or("node")
                            )),
                        };
                        if let Some(message) = message {
                            if let Ok(mut messages) = messages.lock() {
                                messages.push(message);
                            }
                        }
                    }
                });
            }
        });
        Ok(messages.into_inner().unwrap_or_default())
    }

    pub fn reconcile_node_runtime(
        &self,
        install_dir: &Path,
    ) -> Result<RuntimeReconcileReport, String> {
        let node_root = match self.validate_node_root(install_dir) {
            Ok(path) => path,
            Err(error) => {
                return Ok(RuntimeReconcileReport {
                    node: install_dir.display().to_string(),
                    message: format!("nodo omitido: {error}"),
                    idle: true,
                    skipped_busy: false,
                });
            }
        };
        revalidate_node_secret_acls(&node_root)?;
        let label = node_root
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("node")
            .to_string();
        wait_for_reconcile_hold(&label);
        let releases = ReleaseManager::new(&node_root);
        let mutation = match releases.lock_mutation() {
            Ok(guard) => guard,
            Err(error) if error.contains("MUTATION_BUSY") => {
                mark_reconcile_finished(&label);
                return Ok(RuntimeReconcileReport {
                    node: label.clone(),
                    message: format!(
                        "{label}: reconciliacion omitida; mutacion exclusiva en curso."
                    ),
                    idle: true,
                    skipped_busy: true,
                });
            }
            Err(error) => {
                mark_reconcile_finished(&label);
                return Err(error);
            }
        };
        let result = self.reconcile_node_locked(&node_root, &releases, mutation, &label);
        mark_reconcile_finished(&label);
        result
    }

    fn reconcile_node_locked(
        &self,
        node_root: &Path,
        releases: &ReleaseManager,
        mutation: crate::releases::ReleaseMutationGuard,
        label: &str,
    ) -> Result<RuntimeReconcileReport, String> {
        let hold = releases.recover_interrupted_locked(mutation)?;
        match hold {
            ReleaseRecoveryHold::Aborted(abort) if !abort.recovery_required => {
                if node_root.join(MARKER_FILE).is_file() {
                    let _ = sync_release_marker(
                        node_root,
                        &abort.state,
                        "failed",
                        Some("Supervisor aborto una primera promocion interrumpida."),
                    );
                }
                let _ = self.load_or_migrate_runtime_intent(node_root)?;
                Ok(RuntimeReconcileReport {
                    node: label.to_string(),
                    message: format!(
                        "{label}: primera promocion interrumpida abortada sin candidato activo; no existia LKG."
                    ),
                    idle: false,
                    skipped_busy: false,
                })
            }
            ReleaseRecoveryHold::Aborted(abort) | ReleaseRecoveryHold::Pending(abort) => {
                self.complete_canonical_recovery(node_root, abort, label)
            }
            ReleaseRecoveryHold::Steady { lock: _lock, state } => {
                self.reconcile_steady_runtime(node_root, releases, &state, label)
            }
        }
    }

    fn complete_canonical_recovery(
        &self,
        node_root: &Path,
        abort: crate::PromotionAbort,
        label: &str,
    ) -> Result<RuntimeReconcileReport, String> {
        let intent = self.load_or_migrate_runtime_intent(node_root)?;
        if intent.as_ref().map(|value| value.desired_state) == Some(RuntimeDesiredState::Stopped) {
            if let Ok(runtime) = ReleaseManager::new(node_root).active_runtime_dir() {
                let _ = self.run_action_at(node_root, &runtime, "stop", None);
            }
            let recovered = abort.complete_recovery()?;
            sync_release_marker(node_root, &recovered, "stopped", None)?;
            return Ok(RuntimeReconcileReport {
                node: label.to_string(),
                message: format!("{label}: recovery canónico cerrado; desiredState=stopped."),
                idle: false,
                skipped_busy: false,
            });
        }
        if node_root.join(MARKER_FILE).is_file() {
            let _ = sync_release_marker(
                node_root,
                &abort.state,
                "recovering",
                Some("Supervisor reconcilia LKG localmente."),
            );
        }
        let runtime = ReleaseManager::new(node_root).active_runtime_dir()?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        self.require_runtime_start_capabilities(node_root, &runtime, &topology)?;
        let healthy = self.local_runtime_healthy(node_root);
        let mut output = String::new();
        if !healthy {
            if !test_reconcile_intercept_active() {
                let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
                let _ = reconcile_node_network(node_root, true);
                self.ensure_fabric(node_root, &topology, FabricEnsureMode::ActiveReleaseOnly)?;
            }
            output = self.start_runtime_topology_at(
                node_root,
                &runtime,
                RuntimeStartupMode::LocalOperational,
                None,
            )?;
            output = format!("{output}\n{}", self.wait_health_gate(node_root)?);
        } else if let Err(error) = self.health_gate(node_root) {
            output = error;
        }
        if !self.local_runtime_healthy(node_root) {
            let failed = abort.fail_recovery()?;
            let _ = sync_release_marker(node_root, &failed, "failed", Some(&output));
            return Err(format!(
                "[MANUAL_INTERVENTION_REQUIRED] Recovery de LKG no alcanzo health local: {output}"
            ));
        }
        let recovered = abort.complete_recovery()?;
        sync_release_marker(node_root, &recovered, "running", None)?;
        Ok(RuntimeReconcileReport {
            node: label.to_string(),
            message: format!(
                "{label}: LKG recuperado; promotionStatus={}. {output}",
                recovered.promotion_status
            ),
            idle: false,
            skipped_busy: false,
        })
    }

    fn reconcile_steady_runtime(
        &self,
        node_root: &Path,
        releases: &ReleaseManager,
        state: &NodeReleaseState,
        label: &str,
    ) -> Result<RuntimeReconcileReport, String> {
        let intent = self.load_or_migrate_runtime_intent(node_root)?;
        let healthy = self.local_runtime_healthy(node_root);
        match decide_runtime_reconcile(intent.as_ref().map(|value| value.desired_state), healthy) {
            RuntimeReconcileDecision::SkipNoIntent => Ok(RuntimeReconcileReport {
                node: label.to_string(),
                message: format!("{label}: sin RuntimeIntent durable; reconciliacion omitida."),
                idle: true,
                skipped_busy: false,
            }),
            RuntimeReconcileDecision::EnsureStopped => {
                if let Ok(runtime) = releases.active_runtime_dir() {
                    let _ = self.run_action_at(node_root, &runtime, "stop", None);
                }
                if node_root.join(MARKER_FILE).is_file() {
                    let _ = sync_release_marker(node_root, state, "stopped", None);
                }
                Ok(RuntimeReconcileReport {
                    node: label.to_string(),
                    message: format!("{label}: desiredState=stopped; runtime permanece detenido."),
                    idle: false,
                    skipped_busy: false,
                })
            }
            RuntimeReconcileDecision::AlreadyHealthy => {
                let runtime = releases.active_runtime_dir()?;
                let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
                self.require_runtime_start_capabilities(node_root, &runtime, &topology)?;
                if node_root.join(MARKER_FILE).is_file() {
                    let _ = sync_release_marker(node_root, state, "running", None);
                }
                Ok(RuntimeReconcileReport {
                    node: label.to_string(),
                    message: format!(
                        "{label}: activeRelease localmente healthy; sin recrear contenedores."
                    ),
                    idle: false,
                    skipped_busy: false,
                })
            }
            RuntimeReconcileDecision::StartActiveRelease => {
                if state.active_release.is_none() {
                    return Ok(RuntimeReconcileReport {
                        node: label.to_string(),
                        message: format!(
                            "{label}: desiredState=running sin activeRelease; reconciliacion omitida."
                        ),
                        idle: true,
                        skipped_busy: false,
                    });
                }
                if !test_reconcile_intercept_active() {
                    let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
                    let _ = reconcile_node_network(node_root, true);
                    self.ensure_fabric(node_root, &topology, FabricEnsureMode::ActiveReleaseOnly)?;
                }
                let runtime = releases.active_runtime_dir()?;
                let started = self.start_runtime_topology_at(
                    node_root,
                    &runtime,
                    RuntimeStartupMode::LocalOperational,
                    None,
                )?;
                let health = self.wait_health_gate(node_root)?;
                if node_root.join(MARKER_FILE).is_file() {
                    let _ = sync_release_marker(node_root, state, "running", None);
                }
                Ok(RuntimeReconcileReport {
                    node: label.to_string(),
                    message: format!("{label}: activeRelease iniciado.\n{started}\n{health}"),
                    idle: false,
                    skipped_busy: false,
                })
            }
        }
    }

    fn local_runtime_healthy(&self, node_root: &Path) -> bool {
        #[cfg(test)]
        if let Some(healthy) = RECONCILE_TEST_INTERCEPT.with(|cell| {
            cell.borrow()
                .as_ref()
                .map(ReconcileTestIntercept::locally_healthy)
        }) {
            return healthy;
        }
        self.health_gate(node_root).is_ok()
    }

    fn persist_runtime_intent(
        &self,
        node_root: &Path,
        desired_state: RuntimeDesiredState,
        source: RuntimeIntentSource,
    ) -> Result<RuntimeIntent, String> {
        let updated_at = utc_timestamp()?;
        let next = match self.read_runtime_intent(node_root)? {
            Some(current) => current.successor(desired_state, source, updated_at),
            None => RuntimeIntent::new(desired_state, source, updated_at),
        };
        self.write_runtime_intent(node_root, &next)?;
        Ok(next)
    }

    fn load_or_migrate_runtime_intent(
        &self,
        node_root: &Path,
    ) -> Result<Option<RuntimeIntent>, String> {
        if let Some(existing) = self.read_runtime_intent(node_root)? {
            return Ok(Some(existing));
        }
        let marker_status = marker(node_root)
            .ok()
            .and_then(|value| {
                value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            });
        let active_release_present = ReleaseManager::new(node_root)
            .load_state()
            .ok()
            .and_then(|state| state.active_release)
            .is_some();
        let Some(desired) =
            migrate_runtime_desired_state(marker_status.as_deref(), active_release_present)
        else {
            return Ok(None);
        };
        self.persist_runtime_intent(node_root, desired, RuntimeIntentSource::Migration)
            .map(Some)
    }

    fn read_runtime_intent(&self, node_root: &Path) -> Result<Option<RuntimeIntent>, String> {
        let path = node_root.join(RUNTIME_INTENT_RELATIVE_PATH);
        if !path.is_file() {
            return Ok(None);
        }
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
        let intent = serde_json::from_str::<RuntimeIntent>(&contents)
            .map_err(|error| format!("RuntimeIntent invalido: {error}"))?;
        intent.validate()?;
        Ok(Some(intent))
    }

    fn write_runtime_intent(
        &self,
        node_root: &Path,
        intent: &RuntimeIntent,
    ) -> Result<(), String> {
        intent.validate()?;
        let path = node_root.join(RUNTIME_INTENT_RELATIVE_PATH);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("No se pudo crear {}: {error}", parent.display()))?;
        }
        let value = serde_json::to_value(intent)
            .map_err(|error| format!("No se pudo serializar RuntimeIntent: {error}"))?;
        write_json_atomic(&path, &value)
    }

    pub fn reconcile_automatic_networks(&self) -> Result<Vec<String>, String> {
        let root = canonical_existing(&self.authorized_nodes_root)?;
        let mut results = Vec::new();
        for entry in fs::read_dir(&root)
            .map_err(|error| format!("No se pudo leer {}: {error}", root.display()))?
        {
            let entry = entry.map_err(|error| format!("Entrada de nodo invalida: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("No se pudo inspeccionar el nodo: {error}"))?
                .is_dir()
                || !entry.path().join(MARKER_FILE).is_file()
            {
                continue;
            }
            let _mutation = ReleaseManager::new(entry.path()).lock_mutation()?;
            match reconcile_node_network(&entry.path(), false) {
                Ok(result) if result.changed => {
                    self.restart_runtime_topology(&entry.path())?;
                    self.wait_health_gate(&entry.path())?;
                    results.push(result.message);
                }
                Ok(_) => {}
                Err(error) => results.push(format!("{}: {error}", entry.path().display())),
            }
        }
        Ok(results)
    }

    pub fn runtime_summary(&self, install_dir: &Path) -> Result<NodeRuntimeSummary, String> {
        let node_root = self.validate_node_root(install_dir)?;
        let config = node_config(&node_root)?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let mut summary = NodeRuntimeSummary {
            project_name: config
                .get("ACTIUM_DEPLOYMENT_CODE")
                .cloned()
                .unwrap_or_else(|| "deployment".to_string()),
            total_services: 0,
            running_services: 0,
            starting_services: 0,
            unhealthy_services: 0,
        };
        for unit in topology.units {
            let ids = docker_project_ids(&unit.compose_project)?;
            summary.total_services += ids.len();
            if ids.is_empty() {
                continue;
            }
            let inspect = Command::new("docker")
                .arg("inspect")
                .args(&ids)
                .output()
                .map_err(|error| format!("No se pudo inspeccionar Docker: {error}"))?;
            let raw = output_text(inspect)?;
            let containers = serde_json::from_str::<Vec<serde_json::Value>>(&raw)
                .map_err(|error| format!("Docker devolvio JSON invalido: {error}"))?;
            for container in containers {
                let state = container
                    .pointer("/State/Status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown");
                let health = container
                    .pointer("/State/Health/Status")
                    .and_then(serde_json::Value::as_str);
                if state == "running" {
                    summary.running_services += 1;
                }
                if state == "created" || state == "restarting" || health == Some("starting") {
                    summary.starting_services += 1;
                }
                if state == "dead" || health == Some("unhealthy") {
                    summary.unhealthy_services += 1;
                }
            }
        }
        Ok(summary)
    }

    pub fn runtime_unit_inventory(
        &self,
        install_dir: &Path,
    ) -> Result<RuntimeUnitInventory, String> {
        let node_root = self.validate_node_root(install_dir)?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let mut units = Vec::new();
        for unit in &topology.units {
            units.push(self.runtime_unit_health(unit)?);
        }
        Ok(RuntimeUnitInventory {
            fabric: topology.fabric,
            deployment_id: topology.deployment_id,
            units,
        })
    }

    pub fn refresh_material_attestations(&self) -> Result<Vec<String>, String> {
        if !self.authorized_nodes_root.is_dir() {
            return Ok(Vec::new());
        }
        let signer = AttestationSigner::load_for_authority(
            &self.attestation_identity_path,
            self.attestation_authority_state()?,
        )?;
        let mut messages = Vec::new();
        let mut entries = fs::read_dir(&self.authorized_nodes_root)
            .map_err(|error| format!("No se pudo recorrer la raiz de nodos: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Entrada de nodo invalida: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if !entry.path().is_dir() || !entry.path().join("state/runtime-topology.json").is_file()
            {
                continue;
            }
            let releases = ReleaseManager::new(entry.path());
            let mutation = match releases.lock_mutation() {
                Ok(guard) => guard,
                Err(error) if error.contains("MUTATION_BUSY") => {
                    messages.push(format!(
                        "{}: atestacion omitida; mutacion exclusiva en curso.",
                        entry.file_name().to_string_lossy()
                    ));
                    continue;
                }
                Err(error) => return Err(error),
            };
            match self.refresh_material_attestation_locked(&entry.path(), &signer, &mutation) {
                Ok(_) => {}
                Err(error) => messages.push(format!(
                    "{}: atestacion no disponible: {error}",
                    entry.file_name().to_string_lossy()
                )),
            }
        }
        Ok(messages)
    }

    fn refresh_material_attestation_locked(
        &self,
        node_root: &Path,
        signer: &AttestationSigner,
        mutation: &crate::releases::ReleaseMutationGuard,
    ) -> Result<String, String> {
        mutation.assert_root(node_root)?;
        let observation_started_at = utc_timestamp()?;
        let topology_for_lock = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let fabric_root = self.ensure_fabric_root(&topology_for_lock.fabric)?;
        let _fabric_authority =
            ReleaseManager::new(&fabric_root)
                .lock_mutation()
                .map_err(|error| {
                    if error.contains("MUTATION_BUSY") {
                        "ATTESTATION_BUSY: Fabric bajo mutacion exclusiva.".to_string()
                    } else {
                        error
                    }
                })?;
        let (before, units) = capture_coherent_snapshot(
            3,
            || read_attestation_snapshot_revision(node_root, &fabric_root),
            |input| observe_runtime_units(&input.topology),
            |left, right| left.revision == right.revision,
            |left, right| describe_attestation_material_drift(left, right),
        )?;
        let topology = before.topology.clone();
        let Some(host_id) = topology.host_id.clone() else {
            return Ok(format!(
                "{}: atestacion pendiente de host_id autoritativo.",
                topology.deployment_code
            ));
        };
        let material_value = stable_runtime_material_projection(&units);
        let material_digest = sha256_hex(canonical_json(&material_value)?.as_bytes());
        let fabric = build_attested_fabric(&before, &units)?;
        let observation_completed_at = utc_timestamp()?;
        let supervisor_state = node_root.join("state/supervisor");
        fs::create_dir_all(&supervisor_state)
            .map_err(|error| format!("No se pudo crear estado autoritativo: {error}"))?;
        set_unix_mode(&supervisor_state, 0o755)?;
        self.restore_durable_attestation(node_root)?;
        let journal = AttestationJournal::new(&supervisor_state);
        let result = journal.sign_and_publish_result(signer, |sequence| {
            Ok(MaterialAttestationStatement {
                host_id,
                deployment_id: topology.deployment_id.clone(),
                sequence,
                generation: before.revision.generation,
                runtime_release: before
                    .release
                    .active_release
                    .as_ref()
                    .map(|release| release.release_version.clone()),
                payload_digest: before
                    .release
                    .active_release
                    .as_ref()
                    .map(|release| release.release_digest.clone()),
                material_digest,
                observed_at: observation_completed_at.clone(),
                runtime_units: units,
                fabric: Some(fabric),
                journal_id: String::new(),
                attestation_identity_id: String::new(),
                identity_epoch: 0,
                release_revision: before.release.revision,
                topology_digest: before.revision.topology_digest.clone(),
                configuration_digest: before.revision.configuration_digest.clone(),
                observation_started_at,
                observation_completed_at,
                journal_chain: Default::default(),
            })
        })?;
        let path = supervisor_state.join("material-attestation.json");
        set_unix_mode(&path, 0o444)?;
        set_unix_mode(&supervisor_state.join("attestation-sequence"), 0o600)?;
        self.snapshot_durable_attestation(node_root, &result.envelope.statement.host_id, &topology.deployment_id)?;
        Ok(format!(
            "{}: atestacion material {} gen {} {:?} por {}; transporte {:?}{}.",
            topology.deployment_code,
            result.envelope.statement.material_digest,
            before.revision.generation,
            result.disposition,
            result.envelope.key_id,
            result.transport_status,
            result
                .transport_error
                .as_deref()
                .map(|error| format!(" ({error})"))
                .unwrap_or_default()
        ))
    }

    pub fn execute_runtime_unit(
        &self,
        request: &RuntimeUnitActionRequest,
    ) -> Result<RuntimeActionResult, String> {
        if !matches!(
            request.action.as_str(),
            "status" | "start" | "stop" | "restart" | "logs" | "update" | "verify"
        ) {
            return Err(format!(
                "Operacion de runtime unit no permitida: {}.",
                request.action
            ));
        }
        let node_root = self.validate_node_root(Path::new(&request.install_dir))?;
        let node_mutation = matches!(
            request.action.as_str(),
            "start" | "stop" | "restart" | "update"
        )
        .then(|| ReleaseManager::new(&node_root).lock_mutation())
        .transpose()?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let unit = topology.unit(&request.runtime_unit_id)?.clone();
        if matches!(request.action.as_str(), "start" | "restart" | "update") {
            let runtime = ReleaseManager::new(&node_root).active_runtime_dir()?;
            self.require_runtime_start_capabilities(&node_root, &runtime, &topology)?;
            self.ensure_fabric(&node_root, &topology, FabricEnsureMode::ActiveReleaseOnly)?;
            for dependency in &unit.depends_on {
                let dependency = topology.unit(dependency)?;
                let health = self.runtime_unit_health(dependency)?;
                if health.state != "ready" {
                    self.run_runtime_unit_action(&node_root, dependency, "start")?;
                    self.require_runtime_unit_health(dependency)?;
                }
            }
        }
        let output = if request.action == "verify" {
            self.require_runtime_unit_health(&unit)?.state
        } else {
            self.run_runtime_unit_action(&node_root, &unit, &request.action)?
        };
        if matches!(request.action.as_str(), "start" | "restart" | "update") {
            self.require_runtime_unit_health(&unit)?;
            self.adopt_authoritative_host_identity(&node_root)?;
            self.restore_durable_attestation(&node_root)?;
            let signer = AttestationSigner::load_for_authority(
                &self.attestation_identity_path,
                self.attestation_authority_state()?,
            )?;
            self.refresh_material_attestation_locked(
                &node_root,
                &signer,
                node_mutation
                    .as_ref()
                    .ok_or_else(|| "Runtime action no conserva authority del Node.".to_string())?,
            )?;
        }
        Ok(RuntimeActionResult {
            message: format!(
                "Runtime unit {} ({}) completo {}.",
                unit.capability, unit.runtime_unit_id, request.action
            ),
            output,
            release_version: None,
        })
    }

    fn attestation_authority_state(&self) -> Result<AttestationAuthorityState, String> {
        if !self.authorized_nodes_root.is_dir() {
            return Ok(AttestationAuthorityState::NewInstallation);
        }
        let mut legacy = false;
        for entry in fs::read_dir(&self.authorized_nodes_root)
            .map_err(|error| format!("No se pudo auditar authority de atestacion: {error}"))?
        {
            let root = entry
                .map_err(|error| format!("Entrada de authority invalida: {error}"))?
                .path()
                .join("state/supervisor");
            if root
                .join("attestation-journal-v1.initialized.json")
                .is_file()
            {
                return Ok(AttestationAuthorityState::CanonicalJournal);
            }
            if root.join("material-attestation.json").is_file()
                || has_json_files(&root.join("material-attestations-v1"))?
            {
                legacy = true;
            }
        }
        if host_identities_have_canonical_journal(&self.host_identities_root()) {
            return Ok(AttestationAuthorityState::CanonicalJournal);
        }
        Ok(if legacy {
            AttestationAuthorityState::LegacyJournal
        } else {
            AttestationAuthorityState::NewInstallation
        })
    }

    fn host_identities_root(&self) -> PathBuf {
        host_identities_root(&self.authorized_nodes_root)
    }

    fn restore_durable_attestation(&self, node_root: &Path) -> Result<(), String> {
        let topology_path = node_root.join("state/runtime-topology.json");
        if !topology_path.is_file() {
            return Ok(());
        }
        let topology = load_topology(&topology_path)?;
        let Some(host_id) = topology.host_id.as_deref() else {
            return Ok(());
        };
        let durable = host_deployment_attestation_dir(
            &self.host_identities_root(),
            host_id,
            &topology.deployment_id,
        );
        restore_attestation_journal(&durable, &node_root.join("state/supervisor"))?;
        restore_attestation_identity(
            &host_identity_snapshot_dir(&self.host_identities_root(), host_id),
            self.attestation_identity_path
                .parent()
                .unwrap_or_else(|| Path::new(".")),
        )?;
        Ok(())
    }

    fn snapshot_durable_attestation(&self, node_root: &Path, host_id: &str, deployment_id: &str) -> Result<(), String> {
        snapshot_attestation_journal(
            &node_root.join("state/supervisor"),
            &host_deployment_attestation_dir(
                &self.host_identities_root(),
                host_id,
                deployment_id,
            ),
        )?;
        if let Some(parent) = self.attestation_identity_path.parent() {
            snapshot_attestation_identity(
                parent,
                &host_identity_snapshot_dir(&self.host_identities_root(), host_id),
            )?;
        }
        Ok(())
    }

    fn remote_attestation_continuity_error(&self, node_root: &Path) -> Result<Option<String>, String> {
        let status = read_continuity_status(node_root)?;
        Ok(continuity_gate_error(
            evaluate_continuity_status(status.as_ref()),
            status.as_ref(),
        ))
    }

    fn require_desired_payload(&self, node_root: &Path) -> Result<(), String> {
        let desired = read_desired_payload_pin(node_root)?;
        let local = match verify_payload(&self.payload_root)? {
            VerifiedPayload::Schema3(manifest) => (manifest.release_version, manifest.tree_sha256),
            VerifiedPayload::LegacyUnverified {
                version,
                declared_digest,
                ..
            } => (version, declared_digest),
        };
        evaluate_desired_payload_gate(&local.0, &local.1, desired.as_ref())
    }

    fn runtime_unit_health(&self, unit: &crate::RuntimeUnit) -> Result<RuntimeUnitHealth, String> {
        let ids = docker_project_ids(&unit.compose_project)?;
        if ids.is_empty() {
            return Ok(RuntimeUnitHealth {
                runtime_unit_id: unit.runtime_unit_id.clone(),
                capability: unit.capability.clone(),
                compose_project: unit.compose_project.clone(),
                state: "commissioned".to_string(),
                commissioned: true,
                total_services: 0,
                alive_services: 0,
                ready_services: 0,
                failures: Vec::new(),
            });
        }
        let inspect = Command::new("docker")
            .arg("inspect")
            .args(&ids)
            .output()
            .map_err(|error| format!("No se pudo inspeccionar Docker: {error}"))?;
        let report = evaluate_docker_inspect(&output_text(inspect)?)?;
        Ok(RuntimeUnitHealth {
            runtime_unit_id: unit.runtime_unit_id.clone(),
            capability: unit.capability.clone(),
            compose_project: unit.compose_project.clone(),
            state: report.lifecycle_state().to_string(),
            commissioned: true,
            total_services: report.total,
            alive_services: report.alive,
            ready_services: report.ready,
            failures: report.failures,
        })
    }

    fn require_runtime_unit_health(
        &self,
        unit: &crate::RuntimeUnit,
    ) -> Result<RuntimeUnitHealth, String> {
        let health = self.runtime_unit_health(unit)?;
        if health.state != "ready" {
            return Err(format!(
                "Health gate de {} fallido ({}/{}): {}",
                unit.capability,
                health.ready_services,
                health.total_services,
                health.failures.join("; ")
            ));
        }
        Ok(health)
    }

    fn run_runtime_unit_action(
        &self,
        node_root: &Path,
        unit: &crate::RuntimeUnit,
        action: &str,
    ) -> Result<String, String> {
        let runtime = ReleaseManager::new(node_root).active_runtime_dir()?;
        self.run_runtime_unit_action_at(node_root, &runtime, unit, action)
    }

    fn run_runtime_unit_action_at(
        &self,
        node_root: &Path,
        runtime: &Path,
        unit: &crate::RuntimeUnit,
        action: &str,
    ) -> Result<String, String> {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("powershell.exe");
            command
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(runtime.join("manage-node.ps1"));
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = Command::new("/bin/sh");
            command.arg(runtime.join("manage-node.sh"));
            command
        };
        command
            .arg(action)
            .arg(&unit.runtime_unit_id)
            .env(
                "ACTIUM_DATA_PLANE_ENV_FILE",
                node_root.join("secrets/data-plane.env"),
            )
            .env("ACTIUM_LOGS_FOLLOW", "false")
            .current_dir(runtime);
        let result = output_text(
            command
                .output()
                .map_err(|error| format!("No se pudo ejecutar runtime unit: {error}"))?,
        );
        match result {
            Ok(output) => Ok(output),
            Err(error) if matches!(action, "start" | "bootstrap-start" | "restart") => {
                let diagnostics = self
                    .runtime_unit_logs_at(node_root, runtime, unit)
                    .unwrap_or_else(|logs_error| format!("logs no disponibles: {logs_error}"));
                Err(format!(
                    "{error}\n\n[ULTIMOS LOGS REDACTADOS {}]\n{}",
                    unit.capability,
                    redact_sensitive(&diagnostics)
                ))
            }
            Err(error) => Err(error),
        }
    }

    fn runtime_unit_logs_at(
        &self,
        node_root: &Path,
        runtime: &Path,
        unit: &crate::RuntimeUnit,
    ) -> Result<String, String> {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("powershell.exe");
            command
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(runtime.join("manage-node.ps1"));
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = Command::new("/bin/sh");
            command.arg(runtime.join("manage-node.sh"));
            command
        };
        let output = command
            .arg("logs")
            .arg(&unit.runtime_unit_id)
            .args(if cfg!(windows) { &["-NoFollow"][..] } else { &[] })
            .env("ACTIUM_DATA_PLANE_ENV_FILE", node_root.join("secrets/data-plane.env"))
            .env("ACTIUM_LOGS_FOLLOW", "false")
            .current_dir(runtime)
            .output()
            .map_err(|error| format!("No se pudieron leer logs de runtime unit: {error}"))?;
        output_text(output)
    }

    fn adopt_authoritative_host_identity(
        &self,
        node_root: &Path,
    ) -> Result<Option<String>, String> {
        let topology_path = node_root.join("state/runtime-topology.json");
        let mut topology = load_topology(&topology_path)?;
        let agent = topology
            .units
            .iter()
            .find(|unit| unit.capability == "agent")
            .ok_or_else(|| "La topologia no contiene Agent deployment-linked.".to_string())?;
        if self.runtime_unit_health(agent)?.state != "ready" {
            return Ok(None);
        }
        let ids = docker_project_ids(&agent.compose_project)?;
        let Some(container) = ids.first() else {
            return Ok(None);
        };
        let raw = output_text(
            Command::new("docker")
                .args([
                    "exec",
                    container,
                    "cat",
                    "/var/lib/actium-node-config/runtime.json",
                ])
                .output()
                .map_err(|error| format!("No se pudo leer runtime.json del Agent: {error}"))?,
        )?;
        let value = serde_json::from_str::<serde_json::Value>(&raw)
            .map_err(|error| format!("runtime.json del Agent es invalido: {error}"))?;
        let deployment_id = value
            .get("deploymentId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "runtime.json no declara deploymentId.".to_string())?;
        if deployment_id != topology.deployment_id {
            return Err(format!(
                "Agent reporta deployment {deployment_id}, pero la topologia pertenece a {}.",
                topology.deployment_id
            ));
        }
        let Some(host_id) = value
            .get("hostId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        let changed = topology.bind_host_id(host_id)?;
        let fabric_root = self.ensure_fabric_root(&topology.fabric)?;
        let _fabric_mutation = ReleaseManager::new(&fabric_root).lock_mutation()?;
        let identity = self.load_or_create_host_fabric_identity(&topology)?;
        if identity.fabric_id != topology.fabric.fabric_id
            || identity
                .host_id
                .as_deref()
                .is_some_and(|current| Some(current) != topology.host_id.as_deref())
        {
            return Err("El host autoritativo ya esta ligado a otro Fabric.".to_string());
        }
        if changed || identity.host_id.is_none() {
            write_runtime_topology_atomic(
                &topology_path,
                &serde_json::to_value(&topology)
                    .map_err(|error| format!("No se pudo serializar host_id: {error}"))?,
            )?;
            write_json_atomic(
                &self.fabric_identity_path,
                &serde_json::to_value(&topology.fabric)
                    .map_err(|error| format!("No se pudo serializar Fabric: {error}"))?,
            )?;
            write_json_atomic(
                &fabric_root.join("state/fabric-identity.json"),
                &serde_json::to_value(&topology.fabric)
                    .map_err(|error| format!("No se pudo serializar Fabric: {error}"))?,
            )?;
        }
        Ok(changed.then(|| host_id.to_string()))
    }

    fn load_or_create_host_fabric_identity(
        &self,
        topology: &RuntimeTopology,
    ) -> Result<FabricIdentity, String> {
        if self.fabric_identity_path.is_file() {
            let contents = fs::read_to_string(&self.fabric_identity_path).map_err(|error| {
                format!(
                    "No se pudo leer {}: {error}",
                    self.fabric_identity_path.display()
                )
            })?;
            return serde_json::from_str(&contents)
                .map_err(|error| format!("Identidad Fabric invalida: {error}"));
        }
        if let Some(parent) = self.fabric_identity_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("No se pudo crear estado de host: {error}"))?;
        }
        write_json_atomic(
            &self.fabric_identity_path,
            &serde_json::to_value(&topology.fabric)
                .map_err(|error| format!("No se pudo serializar identidad Fabric: {error}"))?,
        )?;
        Ok(topology.fabric.clone())
    }

    fn run_installer_at(
        &self,
        node_root: &Path,
        runtime_dir: &Path,
        enrollment_token: &str,
        prepare_only: bool,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<String, String> {
        let runtime = canonical_existing(runtime_dir)?;
        if runtime != node_root && !runtime.starts_with(node_root) {
            return Err("El runtime de instalacion esta fuera del nodo autorizado.".to_string());
        }
        if !prepare_only {
            let network = reconcile_node_network(node_root, true)?;
            if network.changed {
                eprintln!("{}", network.message);
            }
        }
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("powershell.exe");
            command
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(runtime.join("install-node.ps1"))
                .arg("-ConfigFile")
                .arg(node_root.join("node.env"));
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = Command::new("/bin/sh");
            command
                .arg(runtime.join("install-node.sh"))
                .arg("--config")
                .arg(node_root.join("node.env"));
            command
        };
        command
            .env("ACTIUM_SECRETS_DIR", node_root.join("secrets"))
            .current_dir(&runtime);
        if prepare_only {
            #[cfg(windows)]
            command.arg("-PrepareOnly");
            #[cfg(not(windows))]
            command.arg("--prepare-only");
        }
        if !enrollment_token.trim().is_empty() {
            command.env("ACTIUM_ENROLLMENT_TOKEN_OVERRIDE", enrollment_token.trim());
        }
        let headline = if prepare_only {
            format!(
                "$ {} --config {} --prepare-only",
                runtime.join(if cfg!(windows) { "install-node.ps1" } else { "install-node.sh" }).display(),
                node_root.join("node.env").display()
            )
        } else {
            format!(
                "$ {} --config {}",
                runtime.join(if cfg!(windows) { "install-node.ps1" } else { "install-node.sh" }).display(),
                node_root.join("node.env").display()
            )
        };
        run_logged_command(command, &headline, progress, "install_node")
    }

    pub fn require_health(&self, install_dir: &Path) -> Result<RuntimeActionResult, String> {
        let node_root = self.validate_node_root(install_dir)?;
        let output = self.health_gate(&node_root)?;
        Ok(RuntimeActionResult {
            message: "Health gate completado por Supervisor.".to_string(),
            output,
            release_version: None,
        })
    }

    fn project_inspect(&self, install_dir: &Path) -> Result<String, String> {
        let node_root = self.validate_node_root(install_dir)?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let mut ids = docker_project_ids(&topology.fabric.compose_project)?;
        for unit in topology.units {
            ids.extend(docker_project_ids(&unit.compose_project)?);
        }
        if ids.is_empty() {
            return Err("El deployment no tiene contenedores de runtime units.".to_string());
        }
        let raw = output_text(
            Command::new("docker")
                .arg("inspect")
                .args(&ids)
                .output()
                .map_err(|error| format!("No se pudo inspeccionar Docker: {error}"))?,
        )?;
        serde_json::from_str::<serde_json::Value>(&raw)
            .map_err(|error| format!("Docker devolvio JSON invalido: {error}"))?;
        Ok(raw)
    }

    pub fn project_audit(&self, install_dir: &Path) -> Result<ProjectAuditSummary, String> {
        let inspect = self.project_inspect(install_dir)?;
        let containers = serde_json::from_str::<Vec<serde_json::Value>>(&inspect)
            .map_err(|error| format!("Docker devolvio JSON invalido: {error}"))?;
        let mut services = containers
            .iter()
            .map(|container| {
                let state = container
                    .pointer("/State/Status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let health = container
                    .pointer("/State/Health/Status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(if state == "running" {
                        "running"
                    } else {
                        "none"
                    })
                    .to_string();
                ProjectServiceSummary {
                    workload: container
                        .pointer("/Config/Labels/com.actium.workload")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("desconocido")
                        .to_string(),
                    container_name: container
                        .get("Name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .trim_start_matches('/')
                        .to_string(),
                    state,
                    health,
                }
            })
            .collect::<Vec<_>>();
        services.sort_by(|left, right| left.workload.cmp(&right.workload));
        let has_postgres = services
            .iter()
            .any(|service| service.workload == "fabric_postgres");
        Ok(ProjectAuditSummary {
            services,
            has_postgres,
        })
    }

    pub fn telemetry_audit(&self, install_dir: &Path) -> Result<String, String> {
        let node_root = self.validate_node_root(install_dir)?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let telemetry = topology
            .units
            .iter()
            .find(|unit| unit.capability == "telemetry")
            .ok_or_else(|| "El deployment no contiene Telemetry.".to_string())?;
        let schema = telemetry
            .binding
            .database_schema
            .as_deref()
            .ok_or_else(|| "Telemetry no declara schema PostgreSQL.".to_string())?;
        if !safe_sql_identifier(schema) {
            return Err("Schema PostgreSQL de Telemetry invalido.".to_string());
        }
        let shell = r#"export PGOPTIONS="--search_path=$1,public"; exec psql -U actium_fabric_admin -d actium_fabric -At -v ON_ERROR_STOP=1 -c "$2""#;
        let raw = output_text(
            Command::new("docker")
                .args([
                    "exec",
                    &format!("{}-postgres", topology.fabric.compose_project),
                    "sh",
                    "-ec",
                    shell,
                    "actium-audit",
                    schema,
                ])
                .arg(include_str!("../assets/telemetry-audit.sql"))
                .output()
                .map_err(|error| format!("No se pudo consultar telemetria local: {error}"))?,
        )?;
        redact_json_document(&raw, "auditoria de telemetria")
    }

    pub fn node_agent_runtime(&self, install_dir: &Path) -> Result<String, String> {
        let node_root = self.validate_node_root(install_dir)?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let agent = topology
            .units
            .iter()
            .find(|unit| unit.capability == "agent")
            .ok_or_else(|| "El deployment no contiene Agent.".to_string())?;
        let agent = docker_project_ids(&agent.compose_project)?
            .into_iter()
            .next()
            .ok_or_else(|| "El agente del deployment no esta en ejecucion.".to_string())?;
        let raw = output_text(
            Command::new("docker")
                .args([
                    "exec",
                    &agent,
                    "cat",
                    "/var/lib/actium-node-config/runtime.json",
                ])
                .output()
                .map_err(|error| format!("No se pudo leer runtime.json: {error}"))?,
        )?;
        redact_json_document(&raw, "runtime.json")
    }

    fn prepare_new_node_root(&self, install_dir: &Path) -> Result<PathBuf, String> {
        let root = canonical_existing(&self.authorized_nodes_root)?;
        if !install_dir.is_absolute() {
            return Err("La ruta de commissioning debe ser absoluta.".to_string());
        }
        if install_dir
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("La ruta de commissioning contiene traversal.".to_string());
        }
        let parent = install_dir
            .parent()
            .ok_or_else(|| "La ruta de commissioning no tiene padre.".to_string())?;
        let parent = canonical_existing(parent)?;
        if parent != root {
            return Err(
                "Supervisor solo crea nodos como hijos directos de authorized_nodes_root."
                    .to_string(),
            );
        }
        if install_dir.exists() {
            let entries = fs::read_dir(install_dir)
                .map_err(|error| format!("No se pudo inspeccionar commissioning: {error}"))?;
            let has_material_files = entries.filter_map(Result::ok).any(|entry| {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                name_str == "compose.yml" || name_str == "node.env" || name_str == ".actium-node-installation.json" || name_str == "installation.json"
            });
            if has_material_files {
                return Err("El destino de commissioning no esta vacio.".to_string());
            }
        } else {
            fs::create_dir_all(install_dir)
                .map_err(|error| format!("No se pudo crear el nodo: {error}"))?;
        }
        set_unix_mode(install_dir, 0o755)?;
        let node = canonical_existing(install_dir)?;
        if node.parent() != Some(root.as_path()) {
            return Err("El destino resuelto salio de authorized_nodes_root.".to_string());
        }
        Ok(node)
    }

    fn prepare_incomplete_commission_root(
        &self,
        install_dir: &Path,
        request: &CommissionNodeRequest,
    ) -> Result<PathBuf, String> {
        let node = self.validate_node_root(install_dir)?;
        let disk_marker = read_json_object(&node.join(MARKER_FILE))?;
        let disk_env_path = node.join("node.env");
        let disk_env = if disk_env_path.is_file() {
            parse_env_document(
                &fs::read_to_string(&disk_env_path)
                    .map_err(|error| format!("No se pudo leer node.env existente: {error}"))?,
            )
        } else {
            BTreeMap::new()
        };
        let request_marker = serde_json::from_str::<serde_json::Value>(&request.marker)
            .map_err(|error| format!("Marcador de commissioning invalido: {error}"))?;
        let request_env = parse_env_document(&request.node_env);
        let status = json_string(&disk_marker, "status");
        if !matches!(
            status.as_deref(),
            Some("failed" | "installing" | "prepared" | "cancelled")
        ) {
            return Err("El destino no es una preparacion incompleta recuperable.".to_string());
        }
        let installation_id = crate::require_node_installation_id(
            json_string(&disk_marker, "installationId").as_deref(),
            env_string(&disk_env, crate::NODE_INSTALLATION_ENV_KEY).as_deref(),
        )?;
        let deployment_id = aligned_identity(
            json_string(&disk_marker, "deploymentId"),
            env_string(&disk_env, "ACTIUM_DEPLOYMENT_ID"),
            "deploymentId",
        )?;
        let request_installation_id = crate::require_node_installation_id(
            json_string(&request_marker, "installationId").as_deref(),
            env_string(&request_env, crate::NODE_INSTALLATION_ENV_KEY).as_deref(),
        )?;
        let request_deployment_id = aligned_identity(
            json_string(&request_marker, "deploymentId"),
            env_string(&request_env, "ACTIUM_DEPLOYMENT_ID"),
            "deploymentId del payload",
        )?;
        if request_installation_id != installation_id {
            return Err(
                "El retry debe conservar el installationId existente; no se crea una identidad nueva."
                    .to_string(),
            );
        }
        if request_deployment_id != deployment_id {
            return Err(
                "El retry exige el mismo deploymentId que la preparacion incompleta.".to_string(),
            );
        }
        let releases = ReleaseManager::new(&node);
        let state = releases.load_state().map_err(|error| {
            format!("El estado de release es ambiguo; no se reanuda commissioning inicial. {error}")
        })?;
        if state.active_release.is_some() {
            return Err(
                "El destino conserva una release activa; no se reanuda commissioning inicial."
                    .to_string(),
            );
        }
        if matches!(
            state.promotion_status.as_str(),
            "promoting" | "recovery_pending" | "manual_intervention_required"
        ) {
            return Err(format!(
                "El estado de promocion {} es ambiguo; no se reanuda commissioning inicial.",
                state.promotion_status
            ));
        }
        if node.join("compose.yml").is_file() {
            return Err(
                "El destino ya tiene Compose operativo; use las operaciones del nodo.".to_string(),
            );
        }
        if let Ok(runtime) = releases.active_runtime_dir() {
            if runtime != node && runtime.join("compose.yml").is_file() {
                return Err(
                    "Existe un runtime con Compose; no se reanuda commissioning inicial."
                        .to_string(),
                );
            }
        }
        if let Some(project) = env_string(&disk_env, "ACTIUM_DATA_PLANE_PROJECT")
            .or_else(|| env_string(&disk_env, "ACTIUM_PROJECT_NAME"))
        {
            if !project_container_ids(&project)?.is_empty() {
                return Err(
                    "Existen contenedores del proyecto; no se reanuda commissioning inicial."
                        .to_string(),
                );
            }
        }
        crate::assert_resume_identity(&disk_env, &request_env)?;
        let leftover_profiles = disk_env
            .get("ACTIUM_PROFILES")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let requested_profiles = request_env
            .get("ACTIUM_PROFILES")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        crate::assert_resume_profiles(
            &leftover_profiles,
            &requested_profiles,
            &requested_profiles,
        )?;
        let leftover_channel = json_string(&disk_marker, "managerChannel");
        let request_channel = json_string(&request_marker, "managerChannel");
        if leftover_channel.as_deref() != request_channel.as_deref() {
            return Err(format!(
                "RESUME_IDENTITY_MISMATCH: managerChannel leftover={leftover_channel:?} request={request_channel:?}."
            ));
        }
        Ok(node)
    }

    fn ensure_node_storage_path(&self, node_root: &Path, requested: &str) -> Result<(), String> {
        ensure_node_storage_path(node_root, requested).map(|_| ())
    }

    fn validate_node_root(&self, install_dir: &Path) -> Result<PathBuf, String> {
        let root = canonical_existing(&self.authorized_nodes_root)?;
        let node = canonical_existing(install_dir)?;
        if node == root || !node.starts_with(&root) {
            return Err(format!(
                "Ruta fuera de la raiz autorizada de Supervisor: {}.",
                node.display()
            ));
        }
        let marker_path = node.join(MARKER_FILE);
        let marker = fs::read_to_string(&marker_path)
            .map_err(|error| format!("No se pudo leer {}: {error}", marker_path.display()))?;
        let marker = serde_json::from_str::<serde_json::Value>(&marker)
            .map_err(|error| format!("Marcador de nodo invalido: {error}"))?;
        if marker
            .get("managerChannel")
            .and_then(serde_json::Value::as_str)
            != Some(self.manager_channel.as_str())
        {
            return Err(format!(
                "Supervisor {} solo administra nodos con managerChannel={}.",
                self.manager_channel, self.manager_channel
            ));
        }
        Ok(node)
    }

    fn run_action(&self, node_root: &Path, action: &str) -> Result<String, String> {
        let runtime = ReleaseManager::new(node_root).active_runtime_dir()?;
        self.run_action_at(node_root, &runtime, action, None)
    }

    fn run_action_with_progress(
        &self,
        node_root: &Path,
        action: &str,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<String, String> {
        let runtime = ReleaseManager::new(node_root).active_runtime_dir()?;
        self.run_action_at(node_root, &runtime, action, progress)
    }

    fn run_action_at(
        &self,
        node_root: &Path,
        runtime_root: &Path,
        action: &str,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<String, String> {
        if action == "diagnostics" {
            let mut sections = Vec::new();
            for nested in ["status", "verify", "logs"] {
                let output = self
                    .run_action_at(node_root, runtime_root, nested, progress)
                    .unwrap_or_else(|error| format!("[COMPROBACION FALLIDA]\n{error}"));
                sections.push(format!(
                    "================ {} ================\n{output}",
                    nested.to_uppercase()
                ));
            }
            return Ok(sections.join("\n\n"));
        }
        #[cfg(test)]
        if action == "stop"
            && RECONCILE_TEST_INTERCEPT.with(|cell| {
                if let Some(intercept) = cell.borrow().as_ref() {
                    intercept.stop_count.fetch_add(1, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })
        {
            return Ok("stopped:intercepted".to_string());
        }
        let (mut command, headline) = if action == "verify" {
            #[cfg(windows)]
            let mut command = {
                let mut command = Command::new("powershell.exe");
                command
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
                    .arg(runtime_root.join("verify-node.ps1"))
                    .arg("-EnvironmentFile")
                    .arg(node_root.join("secrets/data-plane.env"));
                command
            };
            #[cfg(not(windows))]
            let mut command = {
                let mut command = Command::new("/bin/sh");
                command.arg(runtime_root.join("verify-node.sh"));
                command
            };
            command
                .env("ACTIUM_DATA_PLANE_ENV_FILE", node_root.join("secrets/data-plane.env"))
                .current_dir(runtime_root);
            let headline = format!(
                "$ {}",
                runtime_root.join(if cfg!(windows) { "verify-node.ps1" } else { "verify-node.sh" }).display()
            );
            (command, headline)
        } else {
            #[cfg(windows)]
            let mut command = {
                let mut command = Command::new("powershell.exe");
                command
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
                    .arg(runtime_root.join("manage-node.ps1"));
                command
            };
            #[cfg(not(windows))]
            let mut command = {
                let mut command = Command::new("/bin/sh");
                command.arg(runtime_root.join("manage-node.sh"));
                command
            };
            command.arg(action)
                .env(
                    "ACTIUM_DATA_PLANE_ENV_FILE",
                    node_root.join("secrets/data-plane.env"),
                )
                .current_dir(runtime_root);
            if action == "logs" {
                command.env("ACTIUM_LOGS_FOLLOW", "false");
                #[cfg(windows)]
                command.arg("-NoFollow");
            }
            let headline = format!(
                "$ {} {action}",
                runtime_root.join(if cfg!(windows) { "manage-node.ps1" } else { "manage-node.sh" }).display()
            );
            (command, headline)
        };
        let _ = &mut command;
        run_logged_command(command, &headline, progress, action)
    }

    fn health_gate(&self, node_root: &Path) -> Result<String, String> {
        #[cfg(test)]
        if let Some(healthy) = RECONCILE_TEST_INTERCEPT.with(|cell| {
            cell.borrow()
                .as_ref()
                .map(ReconcileTestIntercept::locally_healthy)
        }) {
            return if healthy {
                Ok("Health gate OK: intercepted.".to_string())
            } else {
                Err("Health gate fallido: intercepted".to_string())
            };
        }
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let mut total = 0_usize;
        let mut ready = 0_usize;
        let mut failures = Vec::new();
        let fabric_ids = docker_project_ids(&topology.fabric.compose_project)?;
        if fabric_ids.is_empty() {
            failures.push("fabric: sin contenedores".to_string());
        } else {
            let inspect = Command::new("docker")
                .arg("inspect")
                .args(&fabric_ids)
                .output()
                .map_err(|error| format!("No se pudo inspeccionar Fabric: {error}"))?;
            let report = evaluate_docker_inspect(&output_text(inspect)?)?;
            total += report.total;
            ready += report.ready;
            if !report.healthy {
                failures.push(format!("fabric: {}", report.failures.join("; ")));
            }
        }
        for unit in &topology.units {
            let health = self.runtime_unit_health(unit)?;
            total += health.total_services;
            ready += health.ready_services;
            if health.state != "ready" {
                let detail = if health.failures.is_empty() {
                    "sin contenedores".to_string()
                } else {
                    health.failures.join("; ")
                };
                failures.push(format!("{}: {}", unit.capability, detail));
            }
        }
        if !failures.is_empty() {
            return Err(format!(
                "Health gate fallido ({ready}/{total} workloads listos): {}",
                failures.join(" | ")
            ));
        }
        self.adopt_authoritative_host_identity(node_root)?;
        self.restore_durable_attestation(node_root)?;
        if let Some(error) = self.remote_attestation_continuity_error(node_root)? {
            return Err(error);
        }
        Ok(format!("Health gate OK: {ready}/{total} workloads listos."))
    }

    fn wait_health_gate(&self, node_root: &Path) -> Result<String, String> {
        let timeout = std::env::var("ACTIUM_GLOBAL_HEALTH_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| (5..=1_800).contains(value))
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(180));
        let started = Instant::now();
        let mut last_error = "Health gate aun no evaluado.".to_string();
        while started.elapsed() < timeout {
            match self.health_gate(node_root) {
                Ok(health) => return Ok(health),
                Err(error) if error.starts_with("ATTESTATION_CONTINUITY_BLOCKED") => {
                    return Err(error);
                }
                Err(error) => last_error = error,
            }
            thread::sleep(Duration::from_secs(2));
        }
        Err(format!("GLOBAL_HEALTH_TIMEOUT: {last_error}"))
    }

    fn transactional_update(
        &self,
        node_root: &Path,
        node_mutation: crate::releases::ReleaseMutationGuard,
        progress: Option<&RuntimeProgress<'_>>,
        intent: Option<RuntimeIntent>,
    ) -> Result<RuntimeActionResult, String> {
        if intent.as_ref().map(|value| value.desired_state)
            == Some(RuntimeDesiredState::Stopped)
        {
            return Err(
                "UPDATE_REQUIRES_RUNNING_INTENT: el nodo esta detenido; no se promueve una release sin health gate."
                    .to_string(),
            );
        }
        if let Some(report) = progress {
            report("validating", "Verificando payload schema 3 y bytes.", None);
        }
        let manifest = match verify_payload(&self.payload_root)? {
            VerifiedPayload::Schema3(manifest) => manifest,
            VerifiedPayload::LegacyUnverified { .. } => {
                return Err("Supervisor exige payload schema 3 para actualizar.".to_string())
            }
        };
        self.require_desired_payload(node_root)?;
        self.require_runtime_capabilities(node_root, &manifest)?;
        let releases = ReleaseManager::new(node_root);
        if let Some(report) = progress {
            report("staging", "Preparando release aislada.", None);
        }
        let prepared = releases.prepare(&self.payload_root)?;
        let current_runtime = releases.active_runtime_dir()?;
        if releases.load_state()?.active_release.is_none() {
            let config = marker(node_root)?;
            let legacy_version = config
                .get("version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("legacy");
            releases.snapshot_legacy_locked(
                legacy_version,
                "supervisor-adopted",
                &node_mutation,
            )?;
        }
        self.run_action_at(node_root, &prepared.staging_path, "prepare-update", progress)?;
        if let Some(report) = progress {
            report("promoting", "Deteniendo LKG y promoviendo candidato.", None);
        }
        self.run_action_at(node_root, &current_runtime, "stop", progress)?;
        let transaction = match releases.begin_promotion_locked(prepared, node_mutation) {
            Ok(transaction) => transaction,
            Err(error) => {
                let _ = self.start_runtime_topology_at(
                    node_root,
                    &current_runtime,
                    RuntimeStartupMode::LocalOperational,
                    None,
                );
                return Err(format!("No se pudo promover; LKG reiniciado: {error}"));
            }
        };
        let candidate = transaction
            .promoted_state()
            .active_release
            .as_ref()
            .map(|release| node_root.join(&release.relative_path))
            .ok_or_else(|| "Promocion no materializo release candidato.".to_string())?;
        let candidate_result = (|| {
            promotion_checkpoint("update.before_topology")?;
            sync_release_marker(node_root, transaction.promoted_state(), "installing", None)?;
            promotion_checkpoint("update.topology")?;
            let topology = self.materialize_runtime_topology(node_root)?;
            promotion_checkpoint("update.fabric")?;
            self.ensure_fabric(node_root, &topology, FabricEnsureMode::ActiveReleaseOnly)?;
            promotion_checkpoint("update.before_runtime_start")?;
            self.start_runtime_topology_at(
                node_root,
                &candidate,
                RuntimeStartupMode::LocalOperational,
                None,
            )
            .and_then(|output| {
                promotion_checkpoint("update.final_health")?;
                self.wait_health_gate(node_root)
                    .map(|health| format!("{output}\n\n{health}"))
            })
        })();
        match candidate_result {
            Ok(output) => {
                let active = transaction.commit()?;
                sync_release_marker(node_root, &active, "running", None)?;
                Ok(RuntimeActionResult {
                    message: format!(
                        "Release {} promovida y validada por Supervisor.",
                        manifest.release_version
                    ),
                    output,
                    release_version: Some(manifest.release_version),
                })
            }
            Err(candidate_error) => {
                let _ = self.run_action_at(node_root, &candidate, "stop", None);
                Err(self.abort_node_promotion(node_root, transaction, &candidate_error))
            }
        }
    }

    fn abort_node_promotion(
        &self,
        node_root: &Path,
        transaction: ReleasePromotion,
        candidate_error: &str,
    ) -> String {
        let aborted = match transaction.abort() {
            Ok(value) => value,
            Err(abort_error) => {
                return format!(
                    "[MANUAL_INTERVENTION_REQUIRED] Candidato fallo ({candidate_error}) y no se pudo persistir el aborto ({abort_error})."
                )
            }
        };
        if !aborted.recovery_required {
            if node_root.join(MARKER_FILE).is_file() {
                let _ =
                    sync_release_marker(node_root, &aborted.state, "failed", Some(candidate_error));
            }
            return format!("[FIRST_INSTALL_ABORTED] {candidate_error}");
        }

        if node_root.join(MARKER_FILE).is_file() {
            let _ = sync_release_marker(
                node_root,
                &aborted.state,
                "recovering",
                Some(candidate_error),
            );
        }
        let previous = aborted
            .state
            .active_release
            .as_ref()
            .map(|release| node_root.join(&release.relative_path))
            .ok_or_else(|| "Recovery no conserva LKG activo.".to_string());
        let recovery = previous
            .and_then(|previous| {
                let manifest = match verify_payload(&previous)? {
                    VerifiedPayload::Schema3(manifest) => manifest,
                    VerifiedPayload::LegacyUnverified { .. } => {
                        return Err("Supervisor exige LKG schema 3 para recovery.".to_string())
                    }
                };
                self.require_runtime_capabilities(node_root, &manifest)?;
                self.start_runtime_topology_at(
                    node_root,
                    &previous,
                    RuntimeStartupMode::LocalOperational,
                    None,
                )
            })
            .and_then(|output| {
                self.wait_health_gate(node_root)
                    .map(|health| format!("{output}\n{health}"))
            });
        match recovery {
            Ok(output) => match aborted.complete_recovery() {
                Ok(recovered) => {
                    if node_root.join(MARKER_FILE).is_file() {
                        let _ = sync_release_marker(
                            node_root,
                            &recovered,
                            "running",
                            Some(candidate_error),
                        );
                    }
                    format!("[ROLLED_BACK] {candidate_error}\n\n{output}")
                }
                Err(state_error) => format!(
                    "[MANUAL_INTERVENTION_REQUIRED] LKG recupero ({output}), pero no se pudo cerrar su estado ({state_error}); candidato: {candidate_error}."
                ),
            },
            Err(recovery_error) => {
                match aborted.fail_recovery() {
                    Ok(state) => {
                        if node_root.join(MARKER_FILE).is_file() {
                            let _ = sync_release_marker(
                                node_root,
                                &state,
                                "failed",
                                Some(&recovery_error),
                            );
                        }
                        format!(
                            "[MANUAL_INTERVENTION_REQUIRED] Candidato fallo ({candidate_error}) y LKG no recupero ({recovery_error})."
                        )
                    }
                    Err(state_error) => format!(
                        "[MANUAL_INTERVENTION_REQUIRED] Candidato fallo ({candidate_error}), LKG no recupero ({recovery_error}) y el estado manual no persistio ({state_error})."
                    ),
                }
            }
        }
    }

    fn require_runtime_capabilities(
        &self,
        node_root: &Path,
        manifest: &crate::PayloadManifestV3,
    ) -> Result<(), String> {
        let config = node_config(node_root)?;
        let profiles = config
            .get("ACTIUM_PROFILES")
            .map(|value| crate::parse_profile_list(value))
            .unwrap_or_default();
        manifest.require_supported_profiles(&profiles)?;
        manifest.require_supported_features(&required_runtime_features(&config))
    }

    fn require_runtime_start_capabilities(
        &self,
        node_root: &Path,
        runtime_root: &Path,
        topology: &RuntimeTopology,
    ) -> Result<(), String> {
        let config = node_config(node_root)?;
        let mut profiles = config
            .get("ACTIUM_PROFILES")
            .map(|value| crate::parse_profile_list(value))
            .unwrap_or_default();
        for profile in ["people", "control"] {
            if topology
                .units
                .iter()
                .any(|unit| unit.capability == profile)
                && !profiles.iter().any(|configured| configured == profile)
            {
                profiles.push(profile.to_string());
            }
        }

        let required_features = required_runtime_features_for_profiles(&config, &profiles);
        let requires_capability_contract = profiles
            .iter()
            .any(|profile| matches!(profile.as_str(), "people" | "control"))
            || !required_features.is_empty();
        if !requires_capability_contract {
            return Ok(());
        }

        match verify_payload(runtime_root)? {
            VerifiedPayload::Schema3(manifest) => {
                manifest.require_supported_profiles(&profiles)?;
                manifest.require_supported_features(&required_features)
            }
            VerifiedPayload::LegacyUnverified { version, .. } => Err(format!(
                "RUNTIME_RELEASE_CAPABILITY_CONTRACT_REQUIRED: {version} no puede iniciar perfiles o features negociadas sin PAYLOAD schema 3 verificado."
            )),
        }
    }
}

fn required_runtime_features(config: &BTreeMap<String, String>) -> Vec<String> {
    let profiles = config
        .get("ACTIUM_PROFILES")
        .map(|value| crate::parse_profile_list(value))
        .unwrap_or_default();
    required_runtime_features_for_profiles(config, &profiles)
}

fn required_runtime_features_for_profiles(
    config: &BTreeMap<String, String>,
    profiles: &[String],
) -> Vec<String> {
    let mut features = config
        .get("ACTIUM_REQUIRED_RUNTIME_FEATURES")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|feature| !feature.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for (profile, feature) in [
        ("people", "people_runtime_v1"),
        ("control", "control_runtime_v1"),
    ] {
        if profiles.iter().any(|value| value == profile)
            && !features.iter().any(|value| value == feature)
        {
            features.push(feature.to_string());
        }
    }
    features.sort();
    features.dedup();
    features
}

fn promotion_checkpoint(stage: &str) -> Result<(), String> {
    #[cfg(feature = "fault-injection")]
    if std::env::var("ACTIUM_FAULT_INJECTION_STAGE")
        .ok()
        .as_deref()
        == Some(stage)
    {
        return Err(format!("FAULT_INJECTED:{stage}"));
    }
    let _ = stage;
    Ok(())
}

fn load_topology(path: &Path) -> Result<RuntimeTopology, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    let topology = serde_json::from_str::<RuntimeTopology>(&contents)
        .map_err(|error| format!("Topologia invalida en {}: {error}", path.display()))?;
    if topology.schema != crate::topology::RUNTIME_TOPOLOGY_SCHEMA {
        return Err(format!(
            "Schema de topologia incompatible en {}.",
            path.display()
        ));
    }
    Ok(topology)
}

fn random_secret() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn short_digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn unix_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_secret_if_missing(path: &Path, value: &str) -> Result<(), String> {
    if path.is_file() {
        return protect_windows_secret_acl(path, false);
    }
    write_managed_file(path, &format!("{value}\n"), 0o600)
}

#[cfg(unix)]
fn make_node_service_readable_secret(path: &Path) -> Result<(), String> {
    use nix::unistd::{chown, Gid};
    chown(path, None, Some(Gid::from_raw(1000)))
        .map_err(|error| format!("No se pudo asignar grupo de servicio a {}: {error}", path.display()))?;
    set_unix_mode(path, 0o640)
}

#[cfg(not(unix))]
fn make_node_service_readable_secret(_path: &Path) -> Result<(), String> {
    protect_windows_secret_acl(_path, false)
}

fn safe_sql_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
}

fn ensure_docker_network(network: &str, fabric_id: &str) -> Result<(), String> {
    let inspect = Command::new("docker")
        .args(["network", "inspect", network])
        .output()
        .map_err(|error| format!("No se pudo consultar la red Fabric: {error}"))?;
    if inspect.status.success() {
        return validate_fabric_network_inspect(
            &String::from_utf8_lossy(&inspect.stdout),
            fabric_id,
        );
    }
    output_text(
        Command::new("docker")
            .args([
                "network",
                "create",
                "--internal",
                "--label",
                &format!("com.actium.fabric-id={fabric_id}"),
                network,
            ])
            .output()
            .map_err(|error| format!("No se pudo crear la red Fabric: {error}"))?,
    )?;
    Ok(())
}

fn validate_fabric_network_inspect(raw: &str, fabric_id: &str) -> Result<(), String> {
    let networks = serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .map_err(|error| format!("Docker devolvio una red Fabric invalida: {error}"))?;
    let network = networks
        .first()
        .ok_or_else(|| "Docker no devolvio la red Fabric solicitada.".to_string())?;
    let internal = network
        .get("Internal")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let observed_fabric = network
        .pointer("/Labels/com.actium.fabric-id")
        .and_then(serde_json::Value::as_str);
    if !internal || observed_fabric != Some(fabric_id) {
        return Err(
            "La red Docker reservada para Fabric ya existe con ownership o aislamiento incompatibles."
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStateRead {
    Present(String),
    Missing,
    ContainerUnavailable(String),
}

#[cfg(unix)]
const CONTAINER_BOUNDED_READER_SCRIPT: &str = r#"const fs=require('fs');const path=require('path');const file=process.argv[1];const maxBytes=parseInt(process.argv[2],10);const allowlist=['runtime.json','agent-lifecycle.json'];if(!allowlist.includes(file)||isNaN(maxBytes)||maxBytes<=0){process.exit(44);}const target=path.join('/var/lib/actium-node-config',file);const flags=fs.constants.O_RDONLY|(fs.constants.O_NOFOLLOW||0)|(fs.constants.O_CLOEXEC||0);let fd;try{fd=fs.openSync(target,flags);}catch(e){if(e.code==='ENOENT')process.exit(40);if(e.code==='ELOOP')process.exit(42);if(e.code==='EACCES'||e.code==='EPERM')process.exit(43);process.exit(45);}try{const stat=fs.fstatSync(fd);if(!stat.isFile()||stat.isSymbolicLink()||(typeof stat.nlink==='number'&&stat.nlink>1)){process.exit(42);}if(stat.size>maxBytes){process.exit(41);}const buf=Buffer.alloc(maxBytes+1);let total=0;while(total<buf.length){const n=fs.readSync(fd,buf,total,buf.length-total,total);if(n===0)break;total+=n;}if(total>maxBytes){process.exit(41);}let written=0;while(written<total){const n=fs.writeSync(1,buf,written,total-written);if(n<=0)throw new Error('stdout short write');written+=n;}}catch(e){if(e.code==='EACCES'||e.code==='EPERM')process.exit(43);process.exit(45);}finally{try{fs.closeSync(fd);}catch(_){}}"#;

fn read_agent_lifecycle(node_root: &Path) -> Result<Option<AgentLifecycleDocument>, String> {
    match read_agent_state_file(node_root, "agent-lifecycle.json", 128 * 1024)? {
        AgentStateRead::Present(contents) => {
            let document = serde_json::from_str(&contents)
                .map_err(|error| format!("AGENT_LIFECYCLE_INVALID: {error}"))?;
            validate_agent_lifecycle(&document)?;
            Ok(Some(document))
        }
        AgentStateRead::Missing | AgentStateRead::ContainerUnavailable(_) => Ok(None),
    }
}

/// Lee un archivo del Agent state usando la frontera apropiada según la
/// plataforma.
///
/// En Linux el Supervisor productivo se ejecuta como root con únicamente
/// CAP_CHOWN (sin DAC_OVERRIDE, DAC_READ_SEARCH ni FOWNER). El directorio
/// `state/agent` queda `0750 1000:1000` después de la preparación, por lo
/// que un traversal host-direct falla con EACCES. El Supervisor lee el
/// estado a través del contenedor Agent (`docker exec --user 1000:1000 ... node -e ...`),
/// que ejecuta como uid 1000 dentro del bind mount y por lo tanto tiene acceso
/// legítimo de lectura no-follow con límite estricto de bytes y allowlist.
///
/// En Windows no existe este hardening y el acceso host-direct es válido.
///
/// Distingue explícitamente:
/// - Present(contents) → Archivo presente y leído legítimamente
/// - Missing → ENOENT real dentro del volumen
/// - ContainerUnavailable(reason) → Contenedor ausente, no iniciado o timeout
/// - Err(...) → Permiso denegado, archivo sobredimensionado, symlink/tipo inseguro o error grave
fn read_agent_state_file(
    node_root: &Path,
    filename: &str,
    max_bytes: usize,
) -> Result<AgentStateRead, String> {
    if filename != "runtime.json" && filename != "agent-lifecycle.json" {
        return Err(format!("AGENT_STATE_INVALID_INPUT: {filename} no esta en la allowlist"));
    }
    #[cfg(unix)]
    {
        read_agent_state_file_via_container(node_root, filename, max_bytes)
    }
    #[cfg(not(unix))]
    {
        let path = node_root.join("state/agent").join(filename);
        match fs::metadata(&path) {
            Ok(metadata) => {
                if metadata.len() as usize > max_bytes {
                    return Err(format!("AGENT_STATE_TOO_LARGE: {filename}"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(AgentStateRead::Missing),
            Err(error) => {
                return Err(format!(
                    "AGENT_STATE_ACCESS_ERROR: {filename}: {error}"
                ))
            }
        }
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("AGENT_STATE_READ_ERROR: {filename}: {error}"))?;
        Ok(AgentStateRead::Present(contents))
    }
}

#[cfg(unix)]
fn resolve_agent_container(
    compose_project: &str,
    unit: &RuntimeUnit,
) -> Result<Option<String>, String> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={compose_project}"),
            "--format",
            "{{.ID}}\t{{.State}}\t{{.Labels}}",
        ])
        .output()
        .map_err(|error| format!("No se pudo consultar Docker: {error}"))?;

    let text = output_text(output)?;
    let mut matching_running = Vec::new();

    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.is_empty() {
            continue;
        }
        let id = parts[0];
        let state = parts.get(1).copied().unwrap_or("");
        let labels = parts.get(2).copied().unwrap_or("");

        let is_agent = labels.contains("com.actium.capability=agent")
            || labels.contains(&format!("com.actium.runtime-unit-id={}", unit.runtime_unit_id))
            || labels.contains("com.actium.workload=node_agent")
            || labels.contains("com.docker.compose.service=node_agent")
            || labels.contains("com.docker.compose.service=agent");

        if is_agent && state.eq_ignore_ascii_case("running") {
            matching_running.push(id.to_string());
        }
    }

    if matching_running.len() > 1 {
        return Err(format!(
            "AGENT_STATE_CONTAINER_AMBIGUOUS: multiples contenedores coincidentes para el agente ({})",
            matching_running.join(", ")
        ));
    }

    Ok(matching_running.into_iter().next())
}

/// Lee un archivo del Agent state a través del contenedor Agent usando
/// `docker exec` de forma acotada. Requiere que el contenedor Agent esté en
/// ejecución y que `state/agent` esté bind-mounted en `/var/lib/actium-node-config`.
#[cfg(unix)]
fn read_agent_state_file_via_container(
    node_root: &Path,
    filename: &str,
    max_bytes: usize,
) -> Result<AgentStateRead, String> {
    let topology_path = node_root.join("state/runtime-topology.json");
    if !topology_path.exists() {
        return Ok(AgentStateRead::Missing);
    }
    let topology = match fs::read_to_string(&topology_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(AgentStateRead::Missing),
        Err(error) => {
            return Err(format!(
                "AGENT_STATE_TOPOLOGY_ERROR: {}: {error}",
                topology_path.display()
            ))
        }
    };
    let topology = serde_json::from_str::<RuntimeTopology>(&topology)
        .map_err(|error| format!("AGENT_STATE_TOPOLOGY_INVALID: {error}"))?;
    let agent = topology
        .units
        .iter()
        .find(|unit| unit.capability == "agent");
    let Some(agent) = agent else {
        return Ok(AgentStateRead::Missing);
    };

    let container = match resolve_agent_container(&agent.compose_project, agent) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Ok(AgentStateRead::ContainerUnavailable(
                "No hay contenedor en ejecucion para el agente".to_string(),
            ));
        }
        Err(err) => {
            if err.contains("AGENT_STATE_CONTAINER_AMBIGUOUS") {
                return Err(err);
            }
            if std::env::var("ACTIUM_ASSERT_CHOWN_ONLY").as_deref() == Ok("1") {
                return Ok(AgentStateRead::ContainerUnavailable(format!("Docker no disponible: {err}")));
            }
            let path = node_root.join("state/agent").join(filename);
            match fs::metadata(&path) {
                Ok(metadata) => {
                    if metadata.len() as usize > max_bytes {
                        return Err(format!("AGENT_STATE_TOO_LARGE: {filename}"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(AgentStateRead::Missing),
                Err(error) => {
                    return Err(format!("AGENT_STATE_ACCESS_ERROR: {filename}: {error}"));
                }
            }
            let contents = fs::read_to_string(&path)
                .map_err(|error| format!("AGENT_STATE_READ_ERROR: {filename}: {error}"))?;
            return Ok(AgentStateRead::Present(contents));
        }
    };

    let mut child = Command::new("docker")
        .args([
            "exec",
            "--user",
            "1000:1000",
            &container,
            "node",
            "-e",
            CONTAINER_BOUNDED_READER_SCRIPT,
            filename,
            &max_bytes.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            format!("AGENT_STATE_CONTAINER_ERROR: no se pudo iniciar docker exec: {error}")
        })?;

    let stdout_stream = child.stdout.take();
    let stderr_stream = child.stderr.take();

    let max_out_read = (max_bytes + 4096) as u64;
    let stdout_handle = std::thread::spawn(move || {
        use std::io::Read;
        let mut out_bytes = Vec::new();
        if let Some(mut stream) = stdout_stream {
            let _ = (&mut stream).take(max_out_read + 1).read_to_end(&mut out_bytes);
        }
        out_bytes
    });

    let stderr_handle = std::thread::spawn(move || {
        use std::io::Read;
        let mut err_bytes = Vec::new();
        if let Some(mut stream) = stderr_stream {
            let max_err = 64 * 1024;
            let _ = (&mut stream).take(max_err + 1).read_to_end(&mut err_bytes);
        }
        err_bytes
    });

    let timeout = Duration::from_secs(5);
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_handle.join();
                let _ = stderr_handle.join();
                return Err(format!(
                    "AGENT_STATE_CONTAINER_ERROR: error esperando docker exec: {error}"
                ));
            }
        }
    };

    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();

    if timed_out {
        return Ok(AgentStateRead::ContainerUnavailable(
            "Timeout (5s) esperando lectura del contenedor Agent".to_string(),
        ));
    }
    let status = status.expect("status presente si no hubo timeout");
    let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();

    if stdout_bytes.len() > max_bytes {
        return Err(format!(
            "AGENT_STATE_TOO_LARGE: {filename} excede el tamano maximo permitido ({max_bytes} bytes)."
        ));
    }

    match status.code() {
        Some(0) => {
            let contents = String::from_utf8(stdout_bytes)
                .map_err(|error| format!("AGENT_STATE_INVALID_UTF8: {filename}: {error}"))?;
            Ok(AgentStateRead::Present(contents))
        }
        Some(40) => Ok(AgentStateRead::Missing),
        Some(41) => Err(format!("AGENT_STATE_TOO_LARGE: {filename} excede el tamano maximo permitido ({max_bytes} bytes).")),
        Some(42) => Err(format!("AGENT_STATE_UNSAFE_TYPE: {filename} no es un archivo regular o es un symlink o tiene enlaces duros adicionales.")),
        Some(43) => Err(format!("AGENT_STATE_PERMISSION_DENIED: {filename} no es legible por el usuario 1000:1000 dentro del contenedor.")),
        Some(44) => Err(format!("AGENT_STATE_INVALID_INPUT: {filename} no esta en la lista autorizada.")),
        Some(45) => Err(format!("AGENT_STATE_IO_ERROR: error leyendo {filename} en el contenedor.")),
        Some(125) | Some(126) | Some(127) | Some(1)
            if stderr.contains("is not running")
                || stderr.contains("No such container")
                || stderr.contains("not found")
                || stderr.contains("Cannot connect")
                || stderr.contains("daemon is not running") =>
        {
            Ok(AgentStateRead::ContainerUnavailable(stderr))
        }
        _ => Err(format!("AGENT_STATE_READ_FAILED: {filename}: status={status:?} stderr={stderr}")),
    }
}


fn bootstrap_timeout(error_code: &str) -> Duration {
    let stage_variable = match error_code {
        "SITE_CORE_LIVENESS_TIMEOUT" => "ACTIUM_SITE_CORE_LIVENESS_TIMEOUT_SECONDS",
        "AGENT_ENROLLMENT_TIMEOUT" => "ACTIUM_AGENT_ENROLLMENT_TIMEOUT_SECONDS",
        "AGENT_HOST_RECONCILIATION_TIMEOUT" => "ACTIUM_AGENT_HOST_RECONCILIATION_TIMEOUT_SECONDS",
        "SITE_RUNTIME_SYNC_TIMEOUT" => "ACTIUM_SITE_RUNTIME_SYNC_TIMEOUT_SECONDS",
        "SITE_CORE_READINESS_TIMEOUT" => "ACTIUM_SITE_CORE_READINESS_TIMEOUT_SECONDS",
        "AGENT_REPORTING_TIMEOUT" => "ACTIUM_AGENT_REPORTING_TIMEOUT_SECONDS",
        _ => "ACTIUM_BOOTSTRAP_TIMEOUT_SECONDS",
    };
    let seconds = std::env::var(stage_variable)
        .ok()
        .or_else(|| std::env::var("ACTIUM_BOOTSTRAP_TIMEOUT_SECONDS").ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(300)
        .clamp(5, 1_800);
    Duration::from_secs(seconds)
}

fn prepare_agent_state_storage(node_root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        return prepare_agent_state_storage_unix(node_root);
    }
    #[cfg(not(unix))]
    {
        let persistent_agent = node_root.join("persistent/agent");
        let agent_state = node_root.join("state/agent");
        for path in [&persistent_agent, &agent_state] {
            fs::create_dir_all(path)
                .map_err(|error| format!("No se pudo crear storage durable del Agent: {error}"))?;
        }
        for relative in ["control-artifacts", "control-web"] {
            fs::create_dir_all(agent_state.join(relative)).map_err(|error| {
                format!("No se pudo crear cache content-addressed de Control: {error}")
            })?;
        }
        let supervisor_state = node_root.join("state/supervisor");
        fs::create_dir_all(&supervisor_state)
            .map_err(|error| format!("No se pudo crear estado durable del Supervisor: {error}"))?;
        Ok(())
    }
}

#[cfg(unix)]
fn prepare_agent_state_storage_unix(node_root: &Path) -> Result<(), String> {
    use crate::privileged_fs::PrivilegedDir;
    if !node_root.exists() {
        fs::create_dir_all(node_root)
            .map_err(|error| format!("No se pudo crear node_root {}: {error}", node_root.display()))?;
    }
    // Orden Lab.23: recuperar root:root, aplicar modo, migrar/hijos y ceder
    // 1000:1000 al final. Las mutaciones son descriptor-relative y no-follow.
    // persistent/state quedan root-owned para que el workload no reemplace
    // agent entre fstatat y fchownat.
    let persistent = PrivilegedDir::open_path(node_root)?.ensure_dir("persistent")?;
    persistent.reclaim(0, 0, 0o755)?;
    let state = PrivilegedDir::open_path(node_root)?.ensure_dir("state")?;
    state.reclaim(0, 0, 0o755)?;
    let persistent_agent = persistent.ensure_dir("agent")?;
    let agent_state = state.ensure_dir("agent")?;
    prepare_agent_storage_root(&persistent_agent)?;
    prepare_agent_storage_root(&agent_state)?;
    let supervisor_state = state.ensure_dir("supervisor")?;
    supervisor_state.reclaim(0, 0, 0o755)?;
    for name in ["control-artifacts", "control-web"] {
        let directory = agent_state.ensure_dir(name)?;
        directory.reclaim(0, 0, 0o750)?;
        directory.reclaim(1000, 1000, 0o750)?;
    }
    for name in ["runtime.json", "agent-lifecycle.json"] {
        agent_state.copy_file_if_missing(name, &node_root.join("state/node-runtime").join(name))?;
        if let Err(error) = agent_state.reclaim_entry(name, 1000, 1000, 0o600) {
            if !error.contains("No such file") && !error.contains("ENOENT") {
                return Err(error);
            }
        }
    }
    finalize_agent_storage_children(&persistent_agent)?;
    finalize_agent_storage_children(&agent_state)?;
    finalize_agent_storage_root(&persistent_agent)?;
    finalize_agent_storage_root(&agent_state)
}

pub fn is_dangerous_system_path(path: &Path) -> bool {
    let p_str = path.to_string_lossy();
    if p_str.trim().is_empty() {
        return true;
    }
    #[cfg(unix)]
    {
        let dangerous = [
            "/", "/bin", "/sbin", "/boot", "/dev", "/etc", "/lib", "/lib64",
            "/proc", "/sys", "/root", "/usr", "/var/run", "/run",
        ];
        if dangerous.contains(&p_str.as_ref()) {
            return true;
        }
        for d in dangerous {
            if d != "/" && (p_str.starts_with(&format!("{d}/")) || p_str == d) {
                return true;
            }
        }
    }
    #[cfg(windows)]
    {
        let lower = p_str.to_lowercase();
        if lower == "c:\\" || lower == "c:" || lower.starts_with("c:\\windows") || lower.starts_with("c:\\program files") {
            return true;
        }
    }
    false
}

pub fn ensure_node_storage_path(node_root: &Path, requested: &str) -> Result<PathBuf, String> {
    let persistent_root = node_root.join("persistent");
    let requested_path = Path::new(requested);
    
    if requested_path.is_absolute() {
        if is_dangerous_system_path(requested_path) {
            return Err(format!(
                "{}: ruta de storage peligrosa o reservada del sistema",
                WORKLOAD_SPECIAL_FILE_REJECTED
            ));
        }
        if requested_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(format!(
                "{}: traversal no permitido en storage path",
                WORKLOAD_SPECIAL_FILE_REJECTED
            ));
        }
        if requested_path.starts_with(&persistent_root) {
            let relative = requested_path
                .strip_prefix(&persistent_root)
                .map_err(|_| "El storage solicitado debe estar dentro de persistent/ del nodo.".to_string())?;
            #[cfg(unix)]
            {
                use crate::privileged_fs::PrivilegedDir;
                if !persistent_root.exists() {
                    fs::create_dir_all(&persistent_root)
                        .map_err(|error| format!("No se pudo crear persistent root: {error}"))?;
                }
                let mut current = PrivilegedDir::open_path(&persistent_root)?;
                for component in relative.components() {
                    match component {
                        std::path::Component::Normal(name) => {
                            let name_str = name
                                .to_str()
                                .ok_or_else(|| "Componente de ruta no UTF-8.".to_string())?;
                            current = current.ensure_dir(name_str)?;
                        }
                        std::path::Component::CurDir => continue,
                        _ => {
                            return Err(format!(
                                "{}: componente de ruta no valido dentro de persistent/",
                                WORKLOAD_SPECIAL_FILE_REJECTED
                            ));
                        }
                    }
                }
                return Ok(persistent_root.join(relative));
            }
            #[cfg(not(unix))]
            {
                let target = persistent_root.join(relative);
                fs::create_dir_all(&target)
                    .map_err(|error| format!("No se pudo crear storage autorizado: {error}"))?;
                let resolved = canonical_existing(&target)?;
                if !resolved.starts_with(&persistent_root) {
                    return Err("El storage resuelto salio del nodo autorizado.".to_string());
                }
                let _ = set_unix_mode(&resolved, 0o750);
                return Ok(target);
            }
        } else {
            // Absolute path outside persistent_root (dedicated secondary disk / mount point).
            #[cfg(unix)]
            {
                let created = crate::privileged_fs::ensure_absolute_dir_nofollow(requested_path)
                    .map_err(|error| {
                        format!(
                            "No se pudo crear storage personalizado en {}: {error}",
                            requested_path.display()
                        )
                    })?;
                let _ = created.reclaim(1000, 1000, 0o750);
                return Ok(requested_path.to_path_buf());
            }
            #[cfg(not(unix))]
            {
                if !requested_path.exists() {
                    fs::create_dir_all(requested_path).map_err(|error| {
                        format!(
                            "No se pudo crear storage personalizado en {}: {error}",
                            requested_path.display()
                        )
                    })?;
                }
                let _ = set_unix_mode(requested_path, 0o750);
                return Ok(requested_path.to_path_buf());
            }
        }
    }

    let relative = requested_path;
    if relative.components().any(|component| matches!(component, std::path::Component::ParentDir)) {
        return Err(format!(
            "{}: traversal no permitido en storage path",
            WORKLOAD_SPECIAL_FILE_REJECTED
        ));
    }

    #[cfg(unix)]
    {
        use crate::privileged_fs::PrivilegedDir;
        if !persistent_root.exists() {
            fs::create_dir_all(&persistent_root)
                .map_err(|error| format!("No se pudo crear persistent root: {error}"))?;
        }
        let mut current = PrivilegedDir::open_path(&persistent_root)?;
        for component in relative.components() {
            match component {
                std::path::Component::Normal(name) => {
                    let name_str = name
                        .to_str()
                        .ok_or_else(|| "Componente de ruta no UTF-8.".to_string())?;
                    current = current.ensure_dir(name_str)?;
                }
                std::path::Component::CurDir => continue,
                _ => {
                    return Err(format!(
                        "{}: componente de ruta no valido dentro de persistent/",
                        WORKLOAD_SPECIAL_FILE_REJECTED
                    ));
                }
            }
        }
        Ok(persistent_root.join(relative))
    }
    #[cfg(not(unix))]
    {
        let target = persistent_root.join(relative);
        fs::create_dir_all(&target)
            .map_err(|error| format!("No se pudo crear storage autorizado: {error}"))?;
        let resolved = canonical_existing(&target)?;
        if !resolved.starts_with(&persistent_root) {
            return Err("El storage resuelto salio del nodo autorizado.".to_string());
        }
        let _ = set_unix_mode(&resolved, 0o750);
        Ok(target)
    }
}

fn prepare_runtime_unit_storage(node_root: &Path, unit: &crate::RuntimeUnit) -> Result<(), String> {
    #[cfg(unix)]
    {
        return prepare_runtime_unit_storage_unix(node_root, unit);
    }
    #[cfg(not(unix))]
    {
        let root = node_root
            .join("persistent/runtime-units")
            .join(&unit.runtime_unit_id);
        fs::create_dir_all(&root)
            .map_err(|error| format!("No se pudo crear storage de runtime unit: {error}"))?;
        for child in runtime_unit_storage_children(&unit.capability) {
            fs::create_dir_all(root.join(child.relative)).map_err(|error| {
                format!("No se pudo crear storage de {}: {error}", unit.capability)
            })?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn prepare_runtime_unit_storage_unix(
    node_root: &Path,
    unit: &crate::RuntimeUnit,
) -> Result<(), String> {
    use crate::privileged_fs::PrivilegedDir;
    if !node_root.exists() {
        fs::create_dir_all(node_root)
            .map_err(|error| format!("No se pudo crear node_root {}: {error}", node_root.display()))?;
    }
    // El Supervisor Linux se ejecuta sin CAP_DAC_OVERRIDE ni
    // CAP_DAC_READ_SEARCH. Un retry puede encontrar este root cedido al
    // workload (0750, 1000:1000), por lo que debe recuperarlo primero con la
    // unica capacidad autorizada (CAP_CHOWN), procesar los hijos y cederlo
    // nuevamente al final. Las entradas se abren no-follow.
    let persistent = PrivilegedDir::open_path(node_root)?.ensure_dir("persistent")?;
    persistent.reclaim(0, 0, 0o755)?;
    let units = persistent.ensure_dir("runtime-units")?;
    units.reclaim(0, 0, 0o755)?;
    let root = units.ensure_dir(&unit.runtime_unit_id)?;
    prepare_runtime_unit_storage_root(&root)?;
    let children = runtime_unit_storage_children(&unit.capability);
    let mut declared = Vec::new();
    for child in children {
        let child_dir = root.ensure_dir(child.relative)?;
        set_runtime_unit_storage_child_owner(&child_dir, child)?;
        declared.push(child.relative);
    }
    root.reject_unsafe_entries(&declared)?;
    finalize_runtime_unit_storage_root(&root)
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Copy)]
struct RuntimeUnitStorageChild {
    relative: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
}

fn runtime_unit_storage_children(capability: &str) -> &'static [RuntimeUnitStorageChild] {
    const SITE_CORE: [RuntimeUnitStorageChild; 1] = [RuntimeUnitStorageChild {
        relative: "site-core",
        mode: 0o700,
        uid: 0,
        gid: 0,
    }];
    const RADIO_CONTROL: [RuntimeUnitStorageChild; 1] = [RuntimeUnitStorageChild {
        relative: "radio-archive",
        mode: 0o750,
        uid: 1000,
        gid: 1000,
    }];
    const RADIO_SAF: [RuntimeUnitStorageChild; 2] = [
        RuntimeUnitStorageChild {
            relative: "objects",
            mode: 0o750,
            uid: 1000,
            gid: 1000,
        },
        RuntimeUnitStorageChild {
            relative: "radio-archive",
            mode: 0o750,
            uid: 1000,
            gid: 1000,
        },
    ];
    const CONTROL: [RuntimeUnitStorageChild; 3] = [
        RuntimeUnitStorageChild {
            relative: "control-objects",
            mode: 0o750,
            uid: 1000,
            gid: 1000,
        },
        RuntimeUnitStorageChild {
            relative: "control-exports",
            mode: 0o750,
            uid: 1000,
            gid: 1000,
        },
        RuntimeUnitStorageChild {
            relative: "control-staging",
            mode: 0o750,
            uid: 1000,
            gid: 1000,
        },
    ];
    match capability {
        "site-core" => &SITE_CORE,
        "control" => &CONTROL,
        "radio-control" => &RADIO_CONTROL,
        "radio-saf" => &RADIO_SAF,
        _ => &[],
    }
}

#[cfg(unix)]
fn prepare_agent_storage_root(path: &crate::privileged_fs::PrivilegedDir) -> Result<(), String> {
    path.reclaim(0, 0, 0o750)
}

#[cfg(unix)]
fn finalize_agent_storage_children(
    root: &crate::privileged_fs::PrivilegedDir,
) -> Result<(), String> {
    root.reclaim_workload_children()
}

#[cfg(unix)]
fn finalize_agent_storage_root(path: &crate::privileged_fs::PrivilegedDir) -> Result<(), String> {
    path.reclaim(1000, 1000, 0o750)
}

#[cfg(unix)]
fn prepare_runtime_unit_storage_root(
    path: &crate::privileged_fs::PrivilegedDir,
) -> Result<(), String> {
    path.reclaim(0, 0, 0o750)
}

#[cfg(unix)]
fn set_runtime_unit_storage_child_owner(
    path: &crate::privileged_fs::PrivilegedDir,
    child: &RuntimeUnitStorageChild,
) -> Result<(), String> {
    // Primero root:root para que el Supervisor pueda corregir el modo aun si
    // el intento anterior lo dejo bajo la identidad del workload.
    path.reclaim(0, 0, child.mode)?;
    path.reclaim(child.uid, child.gid, child.mode)
}

#[cfg(unix)]
fn finalize_runtime_unit_storage_root(
    path: &crate::privileged_fs::PrivilegedDir,
) -> Result<(), String> {
    path.reclaim(1000, 1000, 0o750)
}

fn prepare_fabric_nats_storage(fabric_root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use crate::privileged_fs::PrivilegedDir;
        if !fabric_root.exists() {
            fs::create_dir_all(fabric_root)
                .map_err(|error| format!("No se pudo crear fabric_root {}: {error}", fabric_root.display()))?;
        }
        let persistent = PrivilegedDir::open_path(fabric_root)?.ensure_dir("persistent")?;
        persistent.reclaim(0, 0, 0o755)?;
        let nats = persistent.ensure_dir("nats")?;
        nats.reclaim(0, 0, 0o750)?;
        nats.reclaim(10_001, 10_001, 0o750)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(fabric_root.join("persistent/nats"))
            .map_err(|error| format!("No se pudo preparar Fabric persistent/nats: {error}"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentLifecycleDocument {
    schema_version: u8,
    deployment_id: String,
    runtime_unit_id: String,
    host_id: Option<String>,
    state: String,
    started_at: String,
    updated_at: String,
    enrolled_at: Option<String>,
    host_reconciled_at: Option<String>,
    runtime_synced_at: Option<String>,
    site_core_ready_at: Option<String>,
    reporting_at: Option<String>,
    failed_stage: Option<String>,
    error_code: Option<String>,
    events: Vec<AgentLifecycleEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentLifecycleEvent {
    state: String,
    at: String,
    error_code: Option<String>,
}

fn validate_agent_lifecycle(document: &AgentLifecycleDocument) -> Result<(), String> {
    const STATES: [&str; 8] = [
        "starting",
        "enrolled",
        "host_reconciled",
        "runtime_sync_pending",
        "runtime_synced",
        "site_core_ready",
        "reporting",
        "degraded",
    ];
    if document.schema_version != 1
        || Uuid::parse_str(&document.deployment_id).is_err()
        || Uuid::parse_str(&document.runtime_unit_id).is_err()
        || document
            .host_id
            .as_deref()
            .is_some_and(|value| Uuid::parse_str(value).is_err())
        || !STATES.contains(&document.state.as_str())
        || !valid_lifecycle_timestamp(&document.started_at)
        || !valid_lifecycle_timestamp(&document.updated_at)
        || document.updated_at < document.started_at
        || document.events.is_empty()
        || document.events.len() > 64
    {
        return Err("AGENT_LIFECYCLE_CONTRACT_INVALID".to_string());
    }
    let mut previous = "";
    for event in &document.events {
        if !STATES.contains(&event.state.as_str())
            || !valid_lifecycle_timestamp(&event.at)
            || event.at.as_str() < previous
            || event
                .error_code
                .as_deref()
                .is_some_and(|value| value.len() > 240)
        {
            return Err("AGENT_LIFECYCLE_EVENT_ORDER_INVALID".to_string());
        }
        previous = &event.at;
    }
    let milestones = [
        document.enrolled_at.as_deref(),
        document.host_reconciled_at.as_deref(),
        document.runtime_synced_at.as_deref(),
        document.site_core_ready_at.as_deref(),
        document.reporting_at.as_deref(),
    ];
    if milestones
        .iter()
        .flatten()
        .any(|value| !valid_lifecycle_timestamp(value))
    {
        return Err("AGENT_LIFECYCLE_TIMESTAMP_INVALID".to_string());
    }
    let mut previous_milestone = document.started_at.as_str();
    for milestone in milestones.into_iter().flatten() {
        if milestone < previous_milestone || milestone > document.updated_at.as_str() {
            return Err("AGENT_LIFECYCLE_MILESTONE_ORDER_INVALID".to_string());
        }
        previous_milestone = milestone;
    }
    if document
        .events
        .last()
        .is_none_or(|event| event.state != document.state)
    {
        return Err("AGENT_LIFECYCLE_CURRENT_STATE_INVALID".to_string());
    }
    Ok(())
}

fn valid_lifecycle_timestamp(value: &str) -> bool {
    value.len() >= 20
        && value.len() <= 30
        && value.ends_with('Z')
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.as_bytes().get(13) == Some(&b':')
        && value.as_bytes().get(16) == Some(&b':')
}

fn ensure_deployment_docker_network(network: &str, deployment_id: &str) -> Result<(), String> {
    let inspect = Command::new("docker")
        .args(["network", "inspect", network])
        .output()
        .map_err(|error| format!("No se pudo consultar la red local del deployment: {error}"))?;
    if inspect.status.success() {
        return validate_deployment_network_inspect(
            &String::from_utf8_lossy(&inspect.stdout),
            deployment_id,
        );
    }
    output_text(
        Command::new("docker")
            .args([
                "network",
                "create",
                "--internal",
                "--label",
                &format!("com.actium.deployment-id={deployment_id}"),
                network,
            ])
            .output()
            .map_err(|error| format!("No se pudo crear la red local del deployment: {error}"))?,
    )?;
    Ok(())
}

impl RuntimeOperator {
    fn start_runtime_topology(&self, node_root: &Path) -> Result<String, String> {
        let runtime = ReleaseManager::new(node_root).active_runtime_dir()?;
        self.start_runtime_topology_at(node_root, &runtime, RuntimeStartupMode::LocalOperational, None)
    }

    fn restart_runtime_topology(&self, node_root: &Path) -> Result<String, String> {
        let runtime = ReleaseManager::new(node_root).active_runtime_dir()?;
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        self.require_runtime_start_capabilities(node_root, &runtime, &topology)?;
        let stopped = self.run_action_at(node_root, &runtime, "stop", None)?;
        self.start_runtime_topology_at(node_root, &runtime, RuntimeStartupMode::LocalOperational, None)
            .map(|started| format!("{stopped}\n{started}"))
    }

    fn start_runtime_topology_at(
        &self,
        node_root: &Path,
        runtime_root: &Path,
        mode: RuntimeStartupMode,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<String, String> {
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        self.require_runtime_start_capabilities(node_root, runtime_root, &topology)?;
        let config = node_config(node_root)?;
        let site_core_candidate = config
            .get("SITE_CORE_RUNTIME_ROLE")
            .map(String::as_str)
            == Some("standby")
            && required_runtime_features(&config)
                .iter()
                .any(|feature| feature == "site_core_candidate_v1");
        #[cfg(test)]
        if RECONCILE_TEST_INTERCEPT.with(|cell| {
            if let Some(intercept) = cell.borrow().as_ref() {
                intercept.start_count.fetch_add(1, Ordering::SeqCst);
                true
            } else {
                false
            }
        }) {
            let _ = (node_root, runtime_root, mode);
            return Ok("runtime_started:intercepted".to_string());
        }
        let agent = topology
            .units
            .iter()
            .find(|unit| matches!(unit.startup_gate, RuntimeStartupGate::AgentReporting))
            .ok_or_else(|| "RUNTIME_TOPOLOGY_AGENT_BOOTSTRAP_REQUIRED".to_string())?;
        let site_core = topology
            .units
            .iter()
            .find(|unit| matches!(unit.startup_gate, RuntimeStartupGate::SiteCoreAlive));
        let mut events = Vec::new();
        let mut started = BTreeSet::new();

        if let Some(unit) = site_core {
            self.run_runtime_unit_action_at(node_root, runtime_root, unit, "bootstrap-start")?;
            promotion_checkpoint("runtime.site_core_started")?;
            self.wait_site_core_probe(unit, "/health/live", "SITE_CORE_LIVENESS_TIMEOUT")?;
            started.insert(unit.runtime_unit_id.clone());
            events.push(format!("{} site_core_alive", utc_timestamp()?));
        }

        self.run_runtime_unit_action_at(node_root, runtime_root, agent, "bootstrap-start")?;
        events.push(format!("{} agent_started", utc_timestamp()?));
        self.wait_agent_lifecycle(node_root, &topology, agent, "enrolled", progress)?;
        events.push(format!("{} agent_enrolled", utc_timestamp()?));
        self.wait_agent_lifecycle(node_root, &topology, agent, "host_reconciled", progress)?;
        events.push(format!("{} agent_host_reconciled", utc_timestamp()?));
        if let Some(unit) = site_core.filter(|_| !site_core_candidate) {
            self.wait_agent_lifecycle(node_root, &topology, agent, "runtime_synced", progress)?;
            events.push(format!("{} site_runtime_synced", utc_timestamp()?));
            self.wait_site_core_probe(unit, "/health/ready", "SITE_CORE_READINESS_TIMEOUT")?;
            self.wait_agent_lifecycle(node_root, &topology, agent, "site_core_ready", progress)?;
            events.push(format!("{} site_core_ready", utc_timestamp()?));
        } else if site_core_candidate {
            events.push(format!("{} site_core_candidate_fenced", utc_timestamp()?));
        }
        if matches!(mode, RuntimeStartupMode::Commissioning) {
            self.wait_agent_lifecycle(node_root, &topology, agent, "reporting", progress)?;
            events.push(format!("{} agent_reporting", utc_timestamp()?));
        } else {
            events.push(format!(
                "{} agent_local_operational",
                utc_timestamp()?
            ));
        }
        started.insert(agent.runtime_unit_id.clone());

        let mut pending = topology
            .units
            .iter()
            .filter(|unit| matches!(unit.startup_cohort, RuntimeStartupCohort::Runtime))
            .collect::<Vec<_>>();
        while !pending.is_empty() {
            let before = pending.len();
            let mut remaining = Vec::new();
            for unit in pending {
                if unit
                    .depends_on
                    .iter()
                    .all(|dependency| started.contains(dependency))
                {
                    self.run_runtime_unit_action_at(node_root, runtime_root, unit, "start")?;
                    self.require_runtime_unit_health(unit)?;
                    started.insert(unit.runtime_unit_id.clone());
                    events.push(format!(
                        "{} runtime_ready:{}",
                        utc_timestamp()?,
                        unit.capability
                    ));
                } else {
                    remaining.push(unit);
                }
            }
            if remaining.len() == before {
                return Err("RUNTIME_TOPOLOGY_DEPENDENCY_CYCLE".to_string());
            }
            pending = remaining;
        }
        Ok(events.join("\n"))
    }

    fn wait_site_core_probe(
        &self,
        unit: &crate::RuntimeUnit,
        path: &str,
        error_code: &str,
    ) -> Result<(), String> {
        let timeout = bootstrap_timeout(error_code);
        let started = Instant::now();
        let container = format!("{}-site-core", unit.compose_project);
        while started.elapsed() < timeout {
            let status = Command::new("docker")
                .args([
                    "exec",
                    &container,
                    "node",
                    "-e",
                    &format!(
                        "fetch('http://127.0.0.1:8088{path}').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
                    ),
                ])
                .status();
            if status.is_ok_and(|value| value.success()) {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(format!(
            "{error_code}: {} no alcanzo {path}.",
            unit.runtime_unit_id
        ))
    }

    fn wait_agent_lifecycle(
        &self,
        node_root: &Path,
        topology: &RuntimeTopology,
        agent: &crate::RuntimeUnit,
        stage: &str,
        progress: Option<&RuntimeProgress<'_>>,
    ) -> Result<AgentLifecycleDocument, String> {
        let error_code = match stage {
            "enrolled" => "AGENT_ENROLLMENT_TIMEOUT",
            "host_reconciled" => "AGENT_HOST_RECONCILIATION_TIMEOUT",
            "runtime_synced" => "SITE_RUNTIME_SYNC_TIMEOUT",
            "site_core_ready" => "SITE_CORE_READINESS_TIMEOUT",
            "reporting" => "AGENT_REPORTING_TIMEOUT",
            _ => "AGENT_BOOTSTRAP_TIMEOUT",
        };
        let timeout = bootstrap_timeout(error_code);
        let started = Instant::now();
        let mut last_cause = None;
        while started.elapsed() < timeout {
            if let Some(report) = progress {
                let elapsed = started.elapsed().as_secs();
                let detail = last_cause
                    .as_deref()
                    .map(|cause| format!("esperando {stage} ({elapsed}s): {cause}"))
                    .unwrap_or_else(|| format!("esperando {stage} ({elapsed}s)"));
                report("running", &detail, None);
            }
            if let Some(document) = read_agent_lifecycle(node_root)? {
                if document.schema_version != 1
                    || document.deployment_id != topology.deployment_id
                    || document.runtime_unit_id != agent.runtime_unit_id
                    || topology.host_id.as_deref().is_some_and(|expected| {
                        document
                            .host_id
                            .as_deref()
                            .is_some_and(|actual| actual != expected)
                    })
                {
                    return Err("AGENT_LIFECYCLE_IDENTITY_MISMATCH".to_string());
                }
                if document.state == "degraded" {
                    return Err(format!(
                        "AGENT_BOOTSTRAP_DEGRADED:{}:{}",
                        document.failed_stage.as_deref().unwrap_or("unknown"),
                        document.error_code.as_deref().unwrap_or("UNKNOWN_ERROR")
                    ));
                }
                if let Some(error) = document.error_code.as_deref() {
                    last_cause = Some(redact_sensitive(error));
                }
                let reached = match stage {
                    "enrolled" => document.enrolled_at.is_some(),
                    "host_reconciled" => document.host_reconciled_at.is_some(),
                    "runtime_synced" => document.runtime_synced_at.is_some(),
                    "site_core_ready" => document.site_core_ready_at.is_some(),
                    "reporting" => document.reporting_at.is_some(),
                    _ => false,
                };
                if reached {
                    if stage != "enrolled" && document.host_id.as_deref().is_none_or(str::is_empty)
                    {
                        return Err("AGENT_LIFECYCLE_HOST_ID_REQUIRED".to_string());
                    }
                    return Ok(document);
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err(match last_cause {
            Some(cause) => {
                format!("{error_code}: Agent no alcanzo {stage}; ultima causa declarada: {cause}.")
            }
            None => format!("{error_code}: Agent no alcanzo {stage}."),
        })
    }
}

fn run_logged_command(
    mut command: Command,
    headline: &str,
    progress: Option<&RuntimeProgress<'_>>,
    step: &str,
) -> Result<String, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut log = format!("{headline}\n");
    if let Some(report) = progress {
        report("running", step, Some(&log));
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("No se pudo iniciar {step}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{step}: stdout no disponible"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{step}: stderr no disponible"))?;
    let (tx, rx) = mpsc::channel::<(char, String)>();
    let stdout_tx = tx.clone();
    let stdout_handle = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                if stdout_tx.send(('o', line)).is_err() {
                    break;
                }
            }
        }
    });
    let stderr_handle = thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            if let Ok(line) = line {
                if tx.send(('e', line)).is_err() {
                    break;
                }
            }
        }
    });
    let mut last_report = Instant::now();
    while let Ok((kind, line)) = rx.recv() {
        if kind == 'e' {
            log.push_str("! ");
        }
        log.push_str(&line);
        log.push('\n');
        if let Some(report) = progress {
            if last_report.elapsed() >= Duration::from_millis(200) {
                report("running", step, Some(&log));
                last_report = Instant::now();
            }
        }
    }
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();
    let status = child
        .wait()
        .map_err(|error| format!("No se pudo esperar {step}: {error}"))?;
    if let Some(report) = progress {
        report("running", step, Some(&log));
    }
    if status.success() {
        Ok(redact_sensitive(&log))
    } else {
        Err(format!(
            "{step} fallo (status={status}).\n{}",
            redact_sensitive(&log)
        ))
    }
}

fn validate_deployment_network_inspect(raw: &str, deployment_id: &str) -> Result<(), String> {
    let networks = serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .map_err(|error| format!("Docker devolvio una red de deployment invalida: {error}"))?;
    let network = networks
        .first()
        .ok_or_else(|| "Docker no devolvio la red local solicitada.".to_string())?;
    let internal = network
        .get("Internal")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let observed_deployment = network
        .pointer("/Labels/com.actium.deployment-id")
        .and_then(serde_json::Value::as_str);
    if !internal || observed_deployment != Some(deployment_id) {
        return Err(
            "La red Docker reservada para el deployment ya existe con ownership o aislamiento incompatibles."
                .to_string(),
        );
    }
    Ok(())
}

fn run_fabric_compose(
    fabric_root: &Path,
    runtime_root: &Path,
    fabric: &FabricIdentity,
    install_mode: &str,
) -> Result<String, String> {
    let mut command = Command::new("docker");
    command.args([
        "compose",
        "-p",
        &fabric.compose_project,
        "--env-file",
        &fabric_root.join("fabric.env").to_string_lossy(),
        "-f",
        &runtime_root.join("compose.fabric.yml").to_string_lossy(),
        "up",
        "-d",
        "--wait",
        "--wait-timeout",
        "180",
    ]);
    if install_mode == "published_images" {
        command.args(["--pull", "always"]);
    } else {
        command.arg("--build");
    }
    output_text(
        command
            .current_dir(runtime_root)
            .output()
            .map_err(|error| format!("No se pudo iniciar Fabric: {error}"))?,
    )
}

fn restart_healthy_container(container: &str) -> Result<(), String> {
    let inspect = Command::new("docker")
        .args(["inspect", container])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("No se pudo inspeccionar {container}: {error}"))?;
    if !inspect.success() {
        return Ok(());
    }
    output_text(
        Command::new("docker")
            .args(["restart", container])
            .output()
            .map_err(|error| format!("No se pudo reiniciar {container}: {error}"))?,
    )?;
    for _ in 0..60 {
        let output = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                container,
            ])
            .output()
            .map_err(|error| format!("No se pudo esperar {container}: {error}"))?;
        let state = output_text(output)?;
        if matches!(state.as_str(), "healthy" | "running") {
            return Ok(());
        }
        if matches!(state.as_str(), "unhealthy" | "dead" | "exited") {
            return Err(format!(
                "{container} quedo {state} despues de actualizar credenciales."
            ));
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    Err(format!("{container} no alcanzo health en 120 segundos."))
}

fn read_json_object(path: &Path) -> Result<serde_json::Value, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    serde_json::from_str::<serde_json::Value>(&contents)
        .map_err(|error| format!("JSON invalido en {}: {error}", path.display()))
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn env_string(values: &BTreeMap<String, String>, key: &str) -> Option<String> {
    values
        .get(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn aligned_identity(
    left: Option<String>,
    right: Option<String>,
    label: &str,
) -> Result<String, String> {
    match (left, right) {
        (Some(left), Some(right)) if left == right => Ok(left),
        (Some(_), Some(_)) => Err(format!(
            "El {label} del marcador y de node.env no coinciden."
        )),
        (Some(value), None) | (None, Some(value)) => Ok(value),
        (None, None) => Err(format!("La preparacion incompleta no conserva {label}.")),
    }
}

fn parse_env_document(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn render_env_document(values: &BTreeMap<String, String>) -> String {
    let mut lines =
        vec!["# Generado por Actium Node Manager. No almacenar secretos aqui.".to_string()];
    for (key, value) in values {
        lines.push(format!("{key}={value}"));
    }
    format!("{}\n", lines.join("\n"))
}

fn updated_env_document(current: &str, updates: &BTreeMap<String, String>) -> String {
    let mut seen = std::collections::BTreeSet::new();
    let mut lines = Vec::new();
    for line in current.lines() {
        let key = line
            .split_once('=')
            .map(|(key, _)| key.trim())
            .unwrap_or_default();
        if let Some(value) = updates.get(key) {
            lines.push(format!("{key}={value}"));
            seen.insert(key.to_string());
        } else {
            lines.push(line.to_string());
        }
    }
    for (key, value) in updates {
        if !seen.contains(key) {
            lines.push(format!("{key}={value}"));
        }
    }
    format!("{}\n", lines.join("\n"))
}

fn write_managed_file(path: &Path, contents: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear {}: {error}", parent.display()))?;
        if path_has_secret_component(path) {
            protect_windows_secret_acl(parent, true)?;
        }
    }
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = fs::File::create(&temporary)
        .map_err(|error| format!("No se pudo crear {}: {error}", temporary.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo escribir {}: {error}", temporary.display()))?;
    set_unix_mode(&temporary, mode)?;
    replace_file(&temporary, path)
        .map_err(|error| format!("No se pudo promover {}: {error}", path.display()))?;
    if mode == 0o600 && path_has_secret_component(path) {
        protect_windows_secret_acl(path, false)?;
    }
    sync_parent_directory(path)
}

fn validate_initial_people_policy_cache(
    contents: &str,
    config: &BTreeMap<String, String>,
) -> Result<(), String> {
    if contents.len() > 64 * 1024 {
        return Err("PEOPLE_POLICY_CACHE_TOO_LARGE".to_string());
    }
    if !config
        .get("ACTIUM_PROFILES")
        .map(|value| crate::parse_profile_list(value))
        .unwrap_or_default()
        .iter()
        .any(|profile| profile == "people")
    {
        return Err("PEOPLE_POLICY_WITHOUT_PROFILE".to_string());
    }
    let value: serde_json::Value = serde_json::from_str(contents)
        .map_err(|_| "PEOPLE_POLICY_CACHE_INVALID".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "PEOPLE_POLICY_CACHE_INVALID".to_string())?;
    let policy = object
        .get("policy")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "PEOPLE_POLICY_CACHE_INVALID".to_string())?;
    let required = |key: &str| {
        config
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("PEOPLE_POLICY_SCOPE_MISSING:{key}"))
    };
    let matches_string = |value: Option<&serde_json::Value>, expected: &str| {
        value.and_then(serde_json::Value::as_str) == Some(expected)
    };
    if object.get("schema").and_then(serde_json::Value::as_u64) != Some(1)
        || !matches_string(object.get("source"), "actium_center_signed_bootstrap")
        || !matches_string(
            object.get("deploymentId"),
            required("ACTIUM_DEPLOYMENT_ID")?,
        )
        || !matches_string(
            policy.get("organizationId"),
            required("ACTIUM_ORGANIZATION_ID")?,
        )
        || !matches_string(policy.get("siteId"), required("ACTIUM_SITE_ID")?)
        || object
            .get("desiredGeneration")
            .and_then(serde_json::Value::as_i64)
            .is_none_or(|generation| generation < 0)
    {
        return Err("PEOPLE_POLICY_CACHE_SCOPE_INVALID".to_string());
    }
    let authority = object
        .get("authority")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "PEOPLE_POLICY_CACHE_AUTHORITY_INVALID".to_string())?;
    let checksum = authority
        .get("desiredChecksum")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !matches_string(
        authority.get("transport"),
        "signed_adpe_verified_by_node_manager",
    ) || checksum.len() != 64
        || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("PEOPLE_POLICY_CACHE_AUTHORITY_INVALID".to_string());
    }
    let policy_value = object
        .get("policy")
        .ok_or_else(|| "PEOPLE_POLICY_CACHE_INVALID".to_string())?;
    let digest = sha256_hex(canonical_json(policy_value)?.as_bytes());
    if object
        .get("policySha256")
        .and_then(serde_json::Value::as_str)
        != Some(digest.as_str())
    {
        return Err("PEOPLE_POLICY_CACHE_DIGEST_MISMATCH".to_string());
    }
    Ok(())
}

fn write_optional_secret(path: &Path, value: Option<&str>) -> Result<(), String> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    write_managed_file(path, &format!("{value}\n"), 0o600)
}

fn configuration_backup_root(node_root: &Path) -> PathBuf {
    node_root.join("state/configuration-rollback")
}

fn backup_configuration(node_root: &Path, node_env: &str) -> Result<(), String> {
    let backup = configuration_backup_root(node_root);
    clear_configuration_backup(node_root)?;
    let committed = node_root.join("state/configuration-committed");
    if committed.is_dir() {
        fs::remove_dir_all(&committed)
            .map_err(|error| format!("No se pudo limpiar commit de configuracion: {error}"))?;
    }
    fs::create_dir_all(&backup)
        .map_err(|error| format!("No se pudo preparar backup de configuracion: {error}"))?;
    set_unix_mode(&backup, 0o700)?;
    write_managed_file(&backup.join("node.env"), node_env, 0o600)?;
    for name in [
        "connectivity_edge_enrollment_token",
        "connectivity_internal_relay_token",
    ] {
        let source = node_root.join("secrets").join(name);
        if source.is_file() {
            let contents = fs::read_to_string(&source)
                .map_err(|error| format!("No se pudo respaldar {name}: {error}"))?;
            write_managed_file(&backup.join(name), &contents, 0o600)?;
        } else {
            write_managed_file(&backup.join(format!("{name}.absent")), "absent\n", 0o600)?;
        }
    }
    Ok(())
}

fn restore_configuration_backup(node_root: &Path) -> Result<(), String> {
    let backup = configuration_backup_root(node_root);
    if !backup.join("node.env").is_file() {
        return Err("No existe backup de configuracion para rollback.".to_string());
    }
    let node_env = fs::read_to_string(backup.join("node.env"))
        .map_err(|error| format!("No se pudo leer backup de node.env: {error}"))?;
    write_managed_file(&node_root.join("node.env"), &node_env, 0o644)?;
    for name in [
        "connectivity_edge_enrollment_token",
        "connectivity_internal_relay_token",
    ] {
        let target = node_root.join("secrets").join(name);
        let stored = backup.join(name);
        if stored.is_file() {
            let contents = fs::read_to_string(&stored)
                .map_err(|error| format!("No se pudo leer backup de {name}: {error}"))?;
            write_managed_file(&target, &contents, 0o600)?;
        } else if backup.join(format!("{name}.absent")).is_file() && target.is_file() {
            fs::remove_file(&target)
                .map_err(|error| format!("No se pudo restaurar ausencia de {name}: {error}"))?;
        }
    }
    clear_configuration_backup(node_root)
}

fn clear_configuration_backup(node_root: &Path) -> Result<(), String> {
    let backup = configuration_backup_root(node_root);
    if backup.is_dir() {
        fs::remove_dir_all(&backup)
            .map_err(|error| format!("No se pudo limpiar backup de configuracion: {error}"))?;
    }
    Ok(())
}

fn commit_configuration_backup(node_root: &Path) -> Result<(), String> {
    let backup = configuration_backup_root(node_root);
    if !backup.is_dir() {
        return Ok(());
    }
    let committed = node_root.join("state/configuration-committed");
    if committed.is_dir() {
        fs::remove_dir_all(&committed)
            .map_err(|error| format!("No se pudo reemplazar commit de configuracion: {error}"))?;
    }
    fs::rename(&backup, &committed)
        .map_err(|error| format!("No se pudo cerrar transaccion de configuracion: {error}"))?;
    let _ = fs::remove_dir_all(committed);
    Ok(())
}

#[cfg(unix)]
fn set_unix_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("No se pudo aplicar modo a {}: {error}", path.display()))
}

#[cfg(windows)]
fn set_unix_mode(path: &Path, mode: u32) -> Result<(), String> {
    if mode == 0o700 && path_has_secret_component(path) {
        return protect_windows_secret_acl(path, true);
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn set_unix_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn path_has_secret_component(path: &Path) -> bool {
    path.components().any(|component| component.as_os_str().to_string_lossy().eq_ignore_ascii_case("secrets"))
}

#[cfg(windows)]
fn revalidate_node_secret_acls(node_root: &Path) -> Result<(), String> {
    let mut directories = vec![node_root.join("secrets")];
    let topology_path = node_root.join("state/runtime-topology.json");
    if topology_path.is_file() {
        let topology = load_topology(&topology_path)?;
        for unit in topology.units {
            let declared = PathBuf::from(unit.binding.secrets_directory);
            let candidate = if declared.is_absolute() {
                declared
            } else {
                if declared.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir
                            | std::path::Component::RootDir
                            | std::path::Component::Prefix(_)
                    )
                }) {
                    return Err("WINDOWS_SECRET_ACL_SCOPE_INVALID".to_string());
                }
                node_root.join(declared)
            };
            if !candidate.starts_with(node_root) {
                return Err("WINDOWS_SECRET_ACL_SCOPE_INVALID".to_string());
            }
            directories.push(candidate);
        }
    }
    for directory in directories {
        if !directory.is_dir() {
            continue;
        }
        protect_windows_secret_acl(&directory, true)?;
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("No se pudo auditar ACL de {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("Entrada secrets invalida: {error}"))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("No se pudo inspeccionar {}: {error}", entry.path().display()))?;
            if file_type.is_symlink() {
                return Err("WINDOWS_SECRET_ACL_SYMLINK_REJECTED".to_string());
            }
            protect_windows_secret_acl(&entry.path(), file_type.is_dir())?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn revalidate_node_secret_acls(_node_root: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn protect_windows_secret_acl(path: &Path, directory: bool) -> Result<(), String> {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .ok_or_else(|| "PROGRAMDATA_REQUIRED_FOR_SECRET_ACL".to_string())?;
    let protected_root = program_data.join("Actium");
    if !path.starts_with(&protected_root) {
        #[cfg(test)]
        return Ok(());
        #[cfg(not(test))]
        return Err("WINDOWS_SECRET_ACL_SCOPE_INVALID".to_string());
    }
    let run = |arguments: &[&str]| -> Result<(), String> {
        let output = Command::new("icacls.exe")
            .arg(path)
            .args(arguments)
            .output()
            .map_err(|error| format!("No se pudo ejecutar icacls para {}: {error}", path.display()))?;
        if !output.status.success() {
            return Err(format!("WINDOWS_SECRET_ACL_FAILED:{}", path.display()));
        }
        Ok(())
    };
    run(&["/reset"])?;
    run(&["/inheritance:r"])?;
    if directory {
        run(&["/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
    } else {
        run(&["/grant:r", "*S-1-5-18:F", "*S-1-5-32-544:F"])
    }
}

#[cfg(not(windows))]
fn protect_windows_secret_acl(_path: &Path, _directory: bool) -> Result<(), String> {
    Ok(())
}

fn project_container_ids(project: &str) -> Result<Vec<String>, String> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            "{{.ID}}",
        ])
        .output();
    let Ok(output) = output else {
        return Ok(Vec::new());
    };
    if !output.status.success() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect())
}

fn docker_project_ids(project: &str) -> Result<Vec<String>, String> {
    let output = Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
            "--format",
            "{{.ID}}",
        ])
        .output()
        .map_err(|error| format!("No se pudo consultar Docker: {error}"))?;
    Ok(output_text(output)?
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttestationSnapshotRevision {
    topology_digest: String,
    agent_runtime_digest: String,
    configuration_digest: String,
    release_revision: u64,
    active_release_id: Option<String>,
    generation: u64,
    fabric_release_revision: u64,
    fabric_active_release_id: Option<String>,
    fabric_configuration_digest: String,
    composite_digest: String,
}

fn capture_coherent_snapshot<I, M, Read, Observe, SameRevision, DescribeDrift>(
    attempts: usize,
    mut read: Read,
    mut observe: Observe,
    same_revision: SameRevision,
    describe_drift: DescribeDrift,
) -> Result<(I, M), String>
where
    Read: FnMut() -> Result<I, String>,
    Observe: FnMut(&I) -> Result<M, String>,
    M: PartialEq,
    SameRevision: Fn(&I, &I) -> bool,
    DescribeDrift: Fn(&M, &M) -> String,
{
    let mut revision_stable = false;
    let mut material_stable = false;
    let mut material_drift = "not-observed".to_string();
    for _ in 0..attempts {
        let before = read()?;
        let material = observe(&before)?;
        let confirmation = observe(&before)?;
        let after = read()?;
        revision_stable = same_revision(&before, &after);
        material_stable = material == confirmation;
        if !material_stable {
            material_drift = describe_drift(&material, &confirmation);
        }
        if revision_stable && material_stable {
            return Ok((before, material));
        }
    }
    Err(format!(
        "ATTESTATION_SNAPSHOT_DRIFT: revisionStable={revision_stable} materialStable={material_stable} materialDrift={material_drift}."
    ))
}

fn describe_attestation_material_drift(
    left: &[AttestedRuntimeUnit],
    right: &[AttestedRuntimeUnit],
) -> String {
    if left.len() != right.len() {
        return format!("unit-count:{}->{}", left.len(), right.len());
    }
    for (left_unit, right_unit) in left.iter().zip(right) {
        if left_unit == right_unit {
            continue;
        }
        if left_unit.runtime_unit_id != right_unit.runtime_unit_id {
            return "runtime-unit-order".to_string();
        }
        let mut fields = Vec::new();
        if left_unit.health != right_unit.health {
            fields.push("health");
        }
        if left_unit.lifecycle_state != right_unit.lifecycle_state {
            fields.push("lifecycle");
        }
        if left_unit.started_at != right_unit.started_at {
            fields.push("startedAt");
        }
        if left_unit.effective_config_digest != right_unit.effective_config_digest {
            fields.push("configDigest");
        }
        if left_unit.containers != right_unit.containers {
            let container_drift = if left_unit.containers.len() != right_unit.containers.len() {
                format!(
                    "containers(count:{}->{})",
                    left_unit.containers.len(),
                    right_unit.containers.len()
                )
            } else {
                left_unit
                    .containers
                    .iter()
                    .zip(&right_unit.containers)
                    .find_map(|(left, right)| {
                        if left == right {
                            return None;
                        }
                        let mut changed = Vec::new();
                        if left.container_id != right.container_id {
                            changed.push("containerId");
                        }
                        if left.image_id != right.image_id {
                            changed.push("imageId");
                        }
                        if left.repo_digest != right.repo_digest {
                            changed.push("repoDigest");
                        }
                        if left.effective_config_digest != right.effective_config_digest {
                            changed.push("configDigest");
                        }
                        if left.health != right.health {
                            changed.push("health");
                        }
                        if left.lifecycle_state != right.lifecycle_state {
                            changed.push("lifecycle");
                        }
                        if left.started_at != right.started_at {
                            changed.push("startedAt");
                        }
                        Some(format!("{}:{}", left.compose_service, changed.join("+")))
                    })
                    .unwrap_or_else(|| "unknown".to_string())
            };
            return format!("{}:{container_drift}", left_unit.capability);
        }
        return format!("{}:{}", left_unit.capability, fields.join(","));
    }
    "unknown".to_string()
}

fn has_json_files(path: &Path) -> Result<bool, String> {
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(path)
        .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?
    {
        let path = entry
            .map_err(|error| format!("Entrada de journal invalida: {error}"))?
            .path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug, Clone)]
struct AttestationSnapshotInput {
    topology: RuntimeTopology,
    release: NodeReleaseState,
    fabric_release: NodeReleaseState,
    revision: AttestationSnapshotRevision,
}

fn read_attestation_snapshot_revision(
    node_root: &Path,
    fabric_root: &Path,
) -> Result<AttestationSnapshotInput, String> {
    let topology_path = node_root.join("state/runtime-topology.json");
    let topology_bytes = fs::read(&topology_path)
        .map_err(|error| format!("No se pudo leer {}: {error}", topology_path.display()))?;
    let topology_value = serde_json::from_slice::<serde_json::Value>(&topology_bytes)
        .map_err(|error| format!("Topologia de atestacion invalida: {error}"))?;
    let topology = serde_json::from_value::<RuntimeTopology>(topology_value.clone())
        .map_err(|error| format!("Topologia de atestacion incompatible: {error}"))?;
    if topology.schema != crate::topology::RUNTIME_TOPOLOGY_SCHEMA {
        return Err("Schema de topologia incompatible para atestacion.".to_string());
    }
    let topology_digest = sha256_hex(canonical_json(&topology_value)?.as_bytes());
    let has_agent_unit = topology
        .units
        .iter()
        .any(|unit| unit.capability == "agent");
    let (generation, agent_runtime_digest) = if has_agent_unit {
        match read_agent_state_file(node_root, "runtime.json", 256 * 1024)? {
            AgentStateRead::Present(contents) => {
                let parsed = serde_json::from_str::<serde_json::Value>(&contents)
                    .map_err(|error| format!("AGENT_RUNTIME_INVALID: {error}"))?;
                let gen = parsed
                    .get("generation")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        "AGENT_RUNTIME_INVALID: falta el campo generation o no es un entero positivo"
                            .to_string()
                    })?;
                if gen == 0 {
                    return Err("AGENT_RUNTIME_INVALID: generation debe ser mayor a 0".to_string());
                }
                let digest = sha256_hex(contents.as_bytes());
                (gen, digest)
            }
            AgentStateRead::Missing => {
                return Err(
                    "ATTESTATION_AGENT_RUNTIME_MISSING: runtime.json del Agent no existe en state/agent."
                        .to_string(),
                );
            }
            AgentStateRead::ContainerUnavailable(reason) => {
                return Err(format!(
                    "ATTESTATION_AGENT_CONTAINER_UNAVAILABLE: no se pudo leer runtime.json: {reason}"
                ));
            }
        }
    } else {
        (0, sha256_hex(b""))
    };
    let configuration_bytes = fs::read(node_root.join("node.env"))
        .map_err(|error| format!("No se pudo leer configuracion para atestacion: {error}"))?;
    let configuration_digest = sha256_hex(&configuration_bytes);
    let release = ReleaseManager::new(node_root).load_state()?;
    let fabric_release = ReleaseManager::new(fabric_root).load_state()?;
    let fabric_configuration = fs::read(fabric_root.join("fabric.env"))
        .map_err(|error| format!("No se pudo leer configuracion Fabric: {error}"))?;
    let fabric_configuration_digest = sha256_hex(&fabric_configuration);
    let active_release_id = release
        .active_release
        .as_ref()
        .map(|value| value.release_id.clone());
    let composite = serde_json::json!({
        "topologyDigest": topology_digest.clone(),
        "agentRuntimeDigest": agent_runtime_digest.clone(),
        "configurationDigest": configuration_digest.clone(),
        "releaseRevision": release.revision,
        "activeReleaseId": active_release_id.clone(),
        "generation": generation,
        "fabricReleaseRevision": fabric_release.revision,
        "fabricActiveReleaseId": fabric_release.active_release.as_ref().map(|value| value.release_id.clone()),
        "fabricConfigurationDigest": fabric_configuration_digest.clone(),
    });
    let composite_digest = sha256_hex(canonical_json(&composite)?.as_bytes());
    Ok(AttestationSnapshotInput {
        topology,
        release,
        fabric_release: fabric_release.clone(),
        revision: AttestationSnapshotRevision {
            topology_digest,
            agent_runtime_digest,
            configuration_digest,
            release_revision: composite
                .get("releaseRevision")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            active_release_id,
            generation,
            fabric_release_revision: fabric_release.revision,
            fabric_active_release_id: fabric_release
                .active_release
                .as_ref()
                .map(|value| value.release_id.clone()),
            fabric_configuration_digest,
            composite_digest,
        },
    })
}

fn build_attested_fabric(
    input: &AttestationSnapshotInput,
    units: &[AttestedRuntimeUnit],
) -> Result<AttestedFabric, String> {
    let unit = units
        .iter()
        .find(|unit| unit.runtime_unit_id == input.topology.fabric.fabric_id)
        .ok_or_else(|| "ATTESTATION_FABRIC_MATERIAL_MISSING".to_string())?;
    attested_fabric_from_parts(
        &input.topology.fabric,
        &input.fabric_release,
        &input.revision.fabric_configuration_digest,
        unit,
    )
}

fn attested_fabric_from_parts(
    fabric: &FabricIdentity,
    release: &NodeReleaseState,
    configuration_digest: &str,
    unit: &AttestedRuntimeUnit,
) -> Result<AttestedFabric, String> {
    let material = serde_json::json!({
        "fabricId": fabric.fabric_id,
        "composeProject": fabric.compose_project,
        "releaseRevision": release.revision,
        "activeReleaseId": release.active_release.as_ref().map(|value| value.release_id.clone()),
        "runtimeRelease": release.active_release.as_ref().map(|value| value.release_version.clone()),
        "payloadDigest": release.active_release.as_ref().map(|value| value.release_digest.clone()),
        "configurationDigest": configuration_digest,
        "runtimeUnit": stable_runtime_unit_material(unit),
    });
    Ok(AttestedFabric {
        fabric_id: fabric.fabric_id.clone(),
        compose_project: fabric.compose_project.clone(),
        release_revision: release.revision,
        active_release_id: release
            .active_release
            .as_ref()
            .map(|value| value.release_id.clone()),
        runtime_release: release
            .active_release
            .as_ref()
            .map(|value| value.release_version.clone()),
        payload_digest: release
            .active_release
            .as_ref()
            .map(|value| value.release_digest.clone()),
        configuration_digest: configuration_digest.to_string(),
        material_digest: sha256_hex(canonical_json(&material)?.as_bytes()),
        health: unit.health.clone(),
    })
}

/// Proyeccion estable usada como identidad material remota. Los datos de
/// ejecucion (health, lifecycle, containerId y timestamps) permanecen dentro
/// del statement firmado, pero no pueden convertir un restart en un fork.
fn stable_runtime_material_projection(units: &[AttestedRuntimeUnit]) -> serde_json::Value {
    serde_json::Value::Array(units.iter().map(stable_runtime_unit_material).collect())
}

fn stable_runtime_unit_material(unit: &AttestedRuntimeUnit) -> serde_json::Value {
    serde_json::json!({
        "runtimeUnitId": unit.runtime_unit_id,
        "capability": unit.capability,
        "dependencyScope": unit.dependency_scope,
        "composeProject": unit.compose_project,
        "effectiveConfigDigest": unit.effective_config_digest,
        "containers": unit.containers.iter().map(|container| serde_json::json!({
            "workloadCode": container.workload_code,
            "migrationProfile": container.migration_profile,
            "composeService": container.compose_service,
            "imageReference": container.image_reference,
            "imageId": container.image_id,
            "repoDigest": container.repo_digest,
            "effectiveConfigDigest": container.effective_config_digest,
            // El resultado estable de un migrador importa; su identidad efimera
            // y hora de finalizacion no. En workloads permanentes se omite.
            "migrationSucceeded": container.migration_profile.as_ref().map(|_| {
                container.exit_code == Some(0)
                    && container.lifecycle_state == "ready"
                    && container.health == "healthy"
            }),
        })).collect::<Vec<_>>(),
    })
}

fn observe_runtime_units(topology: &RuntimeTopology) -> Result<Vec<AttestedRuntimeUnit>, String> {
    let mut units = Vec::new();
    units.push(observe_runtime_unit(
        &topology.fabric.fabric_id,
        "fabric",
        "host-shared",
        &topology.fabric.compose_project,
    )?);
    for unit in &topology.units {
        units.push(observe_runtime_unit(
            &unit.runtime_unit_id,
            &unit.capability,
            "deployment",
            &unit.compose_project,
        )?);
    }
    units.sort_by(|left, right| left.runtime_unit_id.cmp(&right.runtime_unit_id));
    Ok(units)
}

fn observe_runtime_unit(
    runtime_unit_id: &str,
    capability: &str,
    dependency_scope: &str,
    compose_project: &str,
) -> Result<AttestedRuntimeUnit, String> {
    let ids = docker_project_ids(compose_project)?;
    let inspect = if ids.is_empty() {
        "[]".to_string()
    } else {
        output_text(
            Command::new("docker")
                .arg("inspect")
                .args(&ids)
                .output()
                .map_err(|error| format!("No se pudo inspeccionar {compose_project}: {error}"))?,
        )?
    };
    let report = evaluate_docker_inspect(&inspect)?;
    let mut containers = parse_attested_containers(&inspect)?;
    containers.sort_by(|left, right| left.compose_service.cmp(&right.compose_service));
    let lifecycle_state = report.lifecycle_state().to_string();
    let health = if report.healthy {
        "healthy"
    } else {
        "degraded"
    }
    .to_string();
    let started_at = containers
        .iter()
        .filter_map(|container| container.started_at.clone())
        .min();
    let digest_value = serde_json::to_value(
        containers
            .iter()
            .map(|container| {
                (
                    &container.compose_service,
                    &container.effective_config_digest,
                )
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|error| format!("No se pudo serializar unidad observada: {error}"))?;
    Ok(AttestedRuntimeUnit {
        runtime_unit_id: runtime_unit_id.to_string(),
        capability: capability.to_string(),
        dependency_scope: dependency_scope.to_string(),
        compose_project: compose_project.to_string(),
        effective_config_digest: sha256_hex(canonical_json(&digest_value)?.as_bytes()),
        health,
        lifecycle_state,
        started_at,
        containers,
    })
}

fn parse_attested_containers(raw: &str) -> Result<Vec<AttestedContainer>, String> {
    let values = serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .map_err(|error| format!("Docker inspect no devolvio JSON material valido: {error}"))?;
    values.into_iter().map(attested_container).collect()
}

fn attested_container(value: serde_json::Value) -> Result<AttestedContainer, String> {
    let lifecycle_report = evaluate_docker_inspect(
        &serde_json::to_string(&vec![value.clone()])
            .map_err(|error| format!("No se pudo evaluar lifecycle material: {error}"))?,
    )?;
    let labels = value
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object);
    let compose_service = labels
        .and_then(|labels| labels.get("com.docker.compose.service"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let workload_code = labels
        .and_then(|labels| labels.get("com.actium.workload"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| infer_workload_code(&compose_service).map(str::to_string));
    let migration_profile = labels
        .and_then(|labels| labels.get("com.actium.migration-profile"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let is_schema_migrator = workload_code.as_deref() == Some("schema_migrator");
    let image_reference = value
        .pointer("/Config/Image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let image_id = value
        .get("Image")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let repo_digest = docker_repo_digest(&image_id).ok().flatten();
    let started_at = value
        .pointer("/State/StartedAt")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.starts_with("0001-"))
        .map(str::to_string);
    let finished_at = is_schema_migrator
        .then(|| {
            value
                .pointer("/State/FinishedAt")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.starts_with("0001-"))
                .map(str::to_string)
        })
        .flatten();
    let exit_code = is_schema_migrator
        .then(|| {
            value
                .pointer("/State/ExitCode")
                .and_then(serde_json::Value::as_i64)
        })
        .flatten();
    let effective = effective_container_config(&value);
    Ok(AttestedContainer {
        workload_code,
        migration_profile,
        compose_service,
        container_id: value
            .get("Id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        image_reference,
        image_id,
        repo_digest,
        effective_config_digest: sha256_hex(canonical_json(&effective)?.as_bytes()),
        health: if lifecycle_report.healthy {
            "healthy"
        } else {
            "degraded"
        }
        .to_string(),
        lifecycle_state: lifecycle_report.lifecycle_state().to_string(),
        started_at,
        finished_at,
        exit_code,
    })
}

fn effective_container_config(value: &serde_json::Value) -> serde_json::Value {
    let environment = value
        .pointer("/Config/Env")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|entry| {
                    let (key, raw) = entry.split_once('=').unwrap_or((entry, ""));
                    let redacted = if sensitive_config_key(key) {
                        "<redacted>"
                    } else {
                        raw
                    };
                    (
                        key.to_string(),
                        serde_json::Value::String(redacted.to_string()),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let labels = value
        .pointer("/Config/Labels")
        .and_then(serde_json::Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .filter(|(key, _)| {
                    key.starts_with("com.actium.") || key.starts_with("com.docker.compose.")
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let mut mount_destinations = value
        .get("Mounts")
        .and_then(serde_json::Value::as_array)
        .map(|mounts| {
            mounts
                .iter()
                .map(|mount| {
                    serde_json::json!({
                        "destination": mount.get("Destination").cloned().unwrap_or(serde_json::Value::Null),
                        "type": mount.get("Type").cloned().unwrap_or(serde_json::Value::Null),
                        "readOnly": mount.get("RW").and_then(serde_json::Value::as_bool).map(|value| !value),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    mount_destinations.sort_by(|left, right| {
        left.get("destination")
            .and_then(serde_json::Value::as_str)
            .cmp(&right.get("destination").and_then(serde_json::Value::as_str))
            .then_with(|| {
                left.get("type")
                    .and_then(serde_json::Value::as_str)
                    .cmp(&right.get("type").and_then(serde_json::Value::as_str))
            })
            .then_with(|| {
                left.get("readOnly")
                    .and_then(serde_json::Value::as_bool)
                    .cmp(&right.get("readOnly").and_then(serde_json::Value::as_bool))
            })
    });
    serde_json::json!({
        "image": value.pointer("/Config/Image").cloned().unwrap_or(serde_json::Value::Null),
        "entrypoint": value.pointer("/Config/Entrypoint").cloned().unwrap_or(serde_json::Value::Null),
        "cmd": value.pointer("/Config/Cmd").cloned().unwrap_or(serde_json::Value::Null),
        "environment": environment,
        "labels": labels,
        "mounts": mount_destinations,
        "portBindings": value.pointer("/HostConfig/PortBindings").cloned().unwrap_or(serde_json::json!({})),
        "memory": value.pointer("/HostConfig/Memory").cloned().unwrap_or(serde_json::Value::Null),
        "nanoCpus": value.pointer("/HostConfig/NanoCpus").cloned().unwrap_or(serde_json::Value::Null),
        "pidsLimit": value.pointer("/HostConfig/PidsLimit").cloned().unwrap_or(serde_json::Value::Null),
        "restartPolicy": value.pointer("/HostConfig/RestartPolicy/Name").cloned().unwrap_or(serde_json::Value::Null),
        "networkMode": value.pointer("/HostConfig/NetworkMode").cloned().unwrap_or(serde_json::Value::Null),
    })
}

fn sensitive_config_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "credential",
        "private_key",
        "database_url",
        "apikey",
        "service_role",
        "jwt",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn infer_workload_code(service: &str) -> Option<&'static str> {
    match service {
        "data-plane-migrations"
        | "telemetry-migrations"
        | "people-migrations"
        | "control-migrations"
        | "radio-migrations"
        | "radio-saf-migrations" => Some("schema_migrator"),
        "data-plane-agent" => Some("node_agent"),
        "fabric-postgres" => Some("datastore_postgres"),
        "fabric-nats" => Some("broker_nats"),
        "site-core" => Some("site_core"),
        "telemetry-gateway" => Some("telemetry_gateway"),
        "telemetry-projector" => Some("telemetry_projector"),
        "people-gateway" => Some("people_gateway"),
        "control-runtime" => Some("control_runtime"),
        "radio-control" => Some("radio_control"),
        "radio-saf" => Some("radio_saf"),
        "radio-saf-storage" | "radio-saf-minio" | "minio" => Some("object_storage"),
        "radio-turn" | "turn" => Some("radio_turn"),
        "radio-livekit" | "livekit" => Some("radio_livekit"),
        "prometheus" => Some("observability"),
        "connectivity-node-connector" | "connectivity-connector" => Some("connectivity_connector"),
        _ => None,
    }
}

fn docker_repo_digest(image_id: &str) -> Result<Option<String>, String> {
    let raw = output_text(
        Command::new("docker")
            .args(["image", "inspect", image_id])
            .output()
            .map_err(|error| format!("No se pudo inspeccionar la imagen {image_id}: {error}"))?,
    )?;
    let images = serde_json::from_str::<Vec<serde_json::Value>>(&raw)
        .map_err(|error| format!("Docker image inspect devolvio JSON invalido: {error}"))?;
    Ok(images
        .first()
        .and_then(|image| image.get("RepoDigests"))
        .and_then(serde_json::Value::as_array)
        .and_then(|digests| digests.first())
        .and_then(serde_json::Value::as_str)
        .map(str::to_string))
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn utc_timestamp() -> Result<String, String> {
    if let Ok(output) = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        if let Ok(text) = output_text(output) {
            let trimmed = text.trim();
            if trimmed.len() >= 20 && trimmed.ends_with('Z') {
                return Ok(trimmed.to_string());
            }
        }
    }
    Ok(unix_seconds_to_rfc3339(crate::ipc::unix_timestamp()))
}

fn unix_seconds_to_rfc3339(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let tod = seconds % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn civil_from_unix_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}

fn canonical_existing(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map_err(|error| format!("No se pudo resolver {}: {error}", path.display()))
}

fn redact_json_document(raw: &str, label: &str) -> Result<String, String> {
    let mut value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|error| format!("{label} no contiene JSON valido: {error}"))?;
    redact_json_sensitive(&mut value);
    serde_json::to_string(&value)
        .map_err(|error| format!("No se pudo serializar {label} redactado: {error}"))
}

fn node_config(node_root: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = node_root.join("node.env");
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    Ok(parse_env_document(&contents))
}

fn project_name(config: &BTreeMap<String, String>) -> Result<&str, String> {
    config
        .get("ACTIUM_DATA_PLANE_PROJECT")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "El nodo no declara ACTIUM_DATA_PLANE_PROJECT.".to_string())
}

fn output_text(output: Output) -> Result<String, String> {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        Ok(match (stdout.is_empty(), stderr.is_empty()) {
            (false, false) => format!("{stdout}\n{stderr}"),
            (false, true) => stdout,
            (true, false) => stderr,
            (true, true) => "Operacion completada sin salida.".to_string(),
        })
    } else {
        Err(if stderr.is_empty() { stdout } else { stderr })
    }
}

fn test_reconcile_intercept_active() -> bool {
    #[cfg(test)]
    {
        return RECONCILE_TEST_INTERCEPT.with(|cell| cell.borrow().is_some());
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn test_fabric_actuation_skipped() -> bool {
    test_reconcile_intercept_active()
}

fn record_fabric_ensure_mode(_mode: FabricEnsureMode) {
    #[cfg(test)]
    RECONCILE_TEST_INTERCEPT.with(|cell| {
        if let Some(intercept) = cell.borrow().as_ref() {
            if let Ok(mut modes) = intercept.fabric_modes.lock() {
                modes.push(_mode);
            }
        }
    });
}

fn record_fabric_promotion() {
    #[cfg(test)]
    RECONCILE_TEST_INTERCEPT.with(|cell| {
        if let Some(intercept) = cell.borrow().as_ref() {
            intercept.fabric_promotions.fetch_add(1, Ordering::SeqCst);
        }
    });
}

fn wait_for_reconcile_hold(label: &str) {
    #[cfg(test)]
    {
        let hold = RECONCILE_TEST_INTERCEPT.with(|cell| {
            cell.borrow().as_ref().and_then(|intercept| {
                intercept
                    .node_holds
                    .lock()
                    .ok()
                    .and_then(|holds| holds.get(label).cloned())
            })
        });
        if let Some(hold) = hold {
            hold.entered.store(true, Ordering::SeqCst);
            let mut released = hold.released.lock().unwrap_or_else(|error| error.into_inner());
            while !*released {
                released = hold.cvar.wait(released).unwrap_or_else(|error| error.into_inner());
            }
        }
    }
    #[cfg(not(test))]
    {
        let _ = label;
    }
}

fn mark_reconcile_finished(label: &str) {
    #[cfg(test)]
    RECONCILE_TEST_INTERCEPT.with(|cell| {
        if let Some(intercept) = cell.borrow().as_ref() {
            if let Ok(mut finished) = intercept.finished_nodes.lock() {
                finished.push(label.to_string());
                intercept.finished_signal.notify_all();
            }
        }
    });
    #[cfg(not(test))]
    {
        let _ = label;
    }
}

fn marker(node_root: &Path) -> Result<serde_json::Value, String> {
    let path = node_root.join(MARKER_FILE);
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    serde_json::from_str(&contents).map_err(|error| format!("Marcador invalido: {error}"))
}

fn update_marker(
    node_root: &Path,
    status: Option<&str>,
    release_version: Option<&str>,
    last_error: Option<&str>,
) -> Result<(), String> {
    let mut value = marker(node_root)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "El marcador no es un objeto JSON.".to_string())?;
    if let Some(status) = status {
        object.insert("status".to_string(), serde_json::json!(status));
    }
    if let Some(version) = release_version {
        object.insert("version".to_string(), serde_json::json!(version));
    }
    object.insert(
        "updatedAtUnixSeconds".to_string(),
        serde_json::json!(crate::ipc::unix_timestamp()),
    );
    object.insert("lastError".to_string(), serde_json::json!(last_error));
    write_json_atomic(&node_root.join(MARKER_FILE), &value)
}

fn sync_release_marker(
    node_root: &Path,
    state: &crate::NodeReleaseState,
    status: &str,
    last_error: Option<&str>,
) -> Result<(), String> {
    let mut value = marker(node_root)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "El marcador no es un objeto JSON.".to_string())?;
    object.insert("status".to_string(), serde_json::json!(status));
    object.insert(
        "updatedAtUnixSeconds".to_string(),
        serde_json::json!(crate::ipc::unix_timestamp()),
    );
    object.insert("lastError".to_string(), serde_json::json!(last_error));
    object.insert(
        "activeRelease".to_string(),
        serde_json::json!(state
            .active_release
            .as_ref()
            .map(|release| &release.release_id)),
    );
    object.insert(
        "previousRelease".to_string(),
        serde_json::json!(state
            .previous_release
            .as_ref()
            .map(|release| &release.release_id)),
    );
    object.insert(
        "releaseDigest".to_string(),
        serde_json::json!(state
            .active_release
            .as_ref()
            .map(|release| &release.release_digest)),
    );
    object.insert(
        "payloadSchema".to_string(),
        serde_json::json!(state
            .active_release
            .as_ref()
            .map(|release| release.payload_schema)),
    );
    object.insert(
        "promotionStatus".to_string(),
        serde_json::json!(&state.promotion_status),
    );
    if let Some(active) = &state.active_release {
        object.insert(
            "version".to_string(),
            serde_json::json!(&active.release_version),
        );
    }
    write_json_atomic(&node_root.join(MARKER_FILE), &value)
}

fn write_runtime_topology_atomic(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), String> {
    // runtime-topology.json contiene topologia operacional, no secretos.
    // El Supervisor conserva autoridad de escritura (root-owned), mientras
    // los workloads no privilegiados deben poder leerla a traves de mounts :ro.
    write_json_atomic_with_mode(path, value, Some(0o644))
}

fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    write_json_atomic_with_mode(path, value, None)
}

fn write_json_atomic_with_mode(
    path: &Path,
    value: &serde_json::Value,
    explicit_mode: Option<u32>,
) -> Result<(), String> {
    let metadata = fs::metadata(path).ok();
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("No se pudo serializar marcador: {error}"))?;

    let mut file = fs::File::create(&temporary)
        .map_err(|error| format!("No se pudo crear {}: {error}", temporary.display()))?;

    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo escribir {}: {error}", temporary.display()))?;

    // Conserva ownership existente cuando corresponde.
    preserve_unix_owner_and_mode(&temporary, metadata.as_ref())?;

    // Para recursos con contrato de lectura por workloads, aplica el modo
    // antes del rename atomico. Así no existe una ventana post-promocion
    // donde el nuevo inode quede 0600 por UMask=0077.
    #[cfg(unix)]
    if let Some(mode) = explicit_mode {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode)).map_err(|error| {
            format!(
                "No se pudo aplicar modo {:o} a {}: {error}",
                mode,
                temporary.display()
            )
        })?;
    }

    #[cfg(not(unix))]
    let _ = explicit_mode;

    replace_file(&temporary, path)
        .map_err(|error| format!("No se pudo promover {}: {error}", path.display()))?;

    sync_parent_directory(path)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(source, target)
}

#[cfg(windows)]
fn replace_file(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} no tiene directorio padre.", path.display()))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("No se pudo sincronizar {}: {error}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn preserve_unix_owner_and_mode(
    path: &Path,
    metadata: Option<&fs::Metadata>,
) -> Result<(), String> {
    use nix::unistd::{chown, Gid, Uid};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(metadata) = metadata else {
        return Ok(());
    };
    fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode())).map_err(|error| {
        format!(
            "No se pudo preservar el modo de {}: {error}",
            path.display()
        )
    })?;
    chown(
        path,
        Some(Uid::from_raw(metadata.uid())),
        Some(Gid::from_raw(metadata.gid())),
    )
    .map_err(|error| {
        format!(
            "No se pudo preservar el owner de {}: {error}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn preserve_unix_owner_and_mode(
    _path: &Path,
    _metadata: Option<&fs::Metadata>,
) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "fault-injection")]
    use super::promotion_checkpoint;
    use crate::{
        attestation::{AttestedContainer, AttestedRuntimeUnit},
        canonical_json,
        manifest::tree_sha256,
        CommissionNodeRequest, ConfigurationWriteRequest, FabricIdentity, NodeReleaseState,
        PayloadFile, PayloadManifestV3, ReleaseManager, ReleaseMetadata, RuntimeStartupCohort,
        RuntimeStartupGate, RuntimeTopology, RuntimeUnit, RuntimeUnitActionRequest,
        RuntimeUnitBinding, RuntimeUnitResourceBudget,
    };
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, HashMap};
    use std::fs;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Barrier, Condvar, Mutex,
    };
    use uuid::Uuid;

    #[cfg(unix)]
    use super::prepare_runtime_unit_storage;

    #[cfg(unix)]
    fn require_privileged_chown_only() -> bool {
        use nix::unistd::Uid;
        let assert_only = std::env::var("ACTIUM_ASSERT_CHOWN_ONLY").as_deref() == Ok("1");
        if !Uid::effective().is_root() {
            assert!(
                !assert_only,
                "ACTIUM_ASSERT_CHOWN_ONLY exige root; no se admite early-return"
            );
            return false;
        }
        if assert_only {
            let status_text = fs::read_to_string("/proc/self/status")
                .expect("No se pudo leer /proc/self/status");
            let cap_eff = status_text
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:\t"))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                .expect("CapEff debe estar disponible en el gate Linux");
            let cap_prm = status_text
                .lines()
                .find_map(|line| line.strip_prefix("CapPrm:\t"))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                .expect("CapPrm debe estar disponible en el gate Linux");
            let cap_bnd = status_text
                .lines()
                .find_map(|line| line.strip_prefix("CapBnd:\t"))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                .expect("CapBnd debe estar disponible en el gate Linux");
            let cap_amb = status_text
                .lines()
                .find_map(|line| line.strip_prefix("CapAmb:\t"))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
                .expect("CapAmb debe estar disponible en el gate Linux");
            let no_new_privs = status_text
                .lines()
                .find_map(|line| line.strip_prefix("NoNewPrivs:\t"))
                .map(|value| value.trim() == "1")
                .unwrap_or(false);

            eprintln!(
                "BOUNDED RESTRICTED PROCESS: CapEff={cap_eff:016x} CapPrm={cap_prm:016x} CapBnd={cap_bnd:016x} CapAmb={cap_amb:016x} NoNewPrivs={no_new_privs}"
            );

            assert_eq!(
                cap_eff, 1,
                "CapEff debe contener exclusivamente CAP_CHOWN"
            );
            assert_eq!(
                cap_prm, 1,
                "CapPrm debe contener exclusivamente CAP_CHOWN"
            );
            assert_eq!(
                cap_bnd, 1,
                "CapBnd debe contener exclusivamente CAP_CHOWN"
            );
            assert_eq!(
                cap_amb, 0,
                "CapAmb debe permanecer vacio"
            );
            assert!(
                no_new_privs,
                "NoNewPrivs debe ser 1 en el gate product-equivalent"
            );
        }
        true
    }

    #[cfg(feature = "fault-injection")]
    static FAULT_ENV: Mutex<()> = Mutex::new(());

    #[test]
    fn snapshot_reintenta_si_generation_cambia_durante_observacion() {
        let revision = Arc::new(AtomicU64::new(1));
        let first_observation = Arc::new(AtomicBool::new(true));
        let entered = Arc::new(Barrier::new(2));
        let changed = Arc::new(Barrier::new(2));
        let mutator_revision = revision.clone();
        let mutator_entered = entered.clone();
        let mutator_changed = changed.clone();
        let mutator = std::thread::spawn(move || {
            mutator_entered.wait();
            mutator_revision.store(2, Ordering::SeqCst);
            mutator_changed.wait();
        });
        let observed = capture_coherent_snapshot(
            3,
            || Ok(revision.load(Ordering::SeqCst)),
            |_| {
                if first_observation.swap(false, Ordering::SeqCst) {
                    entered.wait();
                    changed.wait();
                }
                Ok(revision.load(Ordering::SeqCst))
            },
            |left, right| left == right,
            |_, _| "test-generation".to_string(),
        )
        .unwrap();
        mutator.join().unwrap();
        assert_eq!(observed, (2, 2));
    }

    #[test]
    fn evidencia_fabric_es_compartida_determinista_y_detecta_cambios() {
        let fabric = FabricIdentity {
            fabric_id: Uuid::new_v4().to_string(),
            compose_project: "actium-lab-fabric-proof".to_string(),
            network_name: "actium-lab-fabric-proof-net".to_string(),
            host_id: Some(Uuid::new_v4().to_string()),
        };
        let release = NodeReleaseState {
            revision: 4,
            active_release: Some(ReleaseMetadata {
                release_id: "0.8.0-lab.15-proof".to_string(),
                release_version: "0.8.0-lab.15".to_string(),
                release_digest: "a".repeat(64),
                payload_schema: 3,
                source_commit: Some("b".repeat(40)),
                relative_path: "releases/0.8.0-lab.15-proof".to_string(),
            }),
            ..Default::default()
        };
        let unit = AttestedRuntimeUnit {
            runtime_unit_id: fabric.fabric_id.clone(),
            capability: "fabric".to_string(),
            dependency_scope: "host-shared".to_string(),
            compose_project: fabric.compose_project.clone(),
            effective_config_digest: "c".repeat(64),
            health: "healthy".to_string(),
            lifecycle_state: "running".to_string(),
            started_at: Some("2026-08-15T00:00:00Z".to_string()),
            containers: vec![AttestedContainer {
                workload_code: Some("postgres".to_string()),
                migration_profile: None,
                compose_service: "postgres".to_string(),
                container_id: "a".repeat(64),
                image_reference: "postgres:17.6-alpine".to_string(),
                image_id: format!("sha256:{}", "1".repeat(64)),
                repo_digest: Some(format!("postgres@sha256:{}", "2".repeat(64))),
                effective_config_digest: "3".repeat(64),
                health: "healthy".to_string(),
                lifecycle_state: "ready".to_string(),
                started_at: Some("2026-08-15T00:00:00Z".to_string()),
                finished_at: None,
                exit_code: None,
            }],
        };
        let first = attested_fabric_from_parts(&fabric, &release, &"d".repeat(64), &unit).unwrap();
        let second = attested_fabric_from_parts(&fabric, &release, &"d".repeat(64), &unit).unwrap();
        assert_eq!(
            first, second,
            "dos deployments leen la misma prueba host-scoped"
        );
        let changed_config =
            attested_fabric_from_parts(&fabric, &release, &"e".repeat(64), &unit).unwrap();
        assert_ne!(first.material_digest, changed_config.material_digest);
        let mut changed_release = release.clone();
        changed_release.revision += 1;
        let changed_release =
            attested_fabric_from_parts(&fabric, &changed_release, &"d".repeat(64), &unit).unwrap();
        assert_ne!(first.material_digest, changed_release.material_digest);

        let mut restarted = unit.clone();
        restarted.health = "degraded".to_string();
        restarted.lifecycle_state = "alive".to_string();
        restarted.started_at = Some("2026-08-16T00:00:00Z".to_string());
        restarted.containers[0].container_id = "b".repeat(64);
        restarted.containers[0].health = "degraded".to_string();
        restarted.containers[0].lifecycle_state = "alive".to_string();
        restarted.containers[0].started_at = Some("2026-08-16T00:00:00Z".to_string());
        let restarted_fabric =
            attested_fabric_from_parts(&fabric, &release, &"d".repeat(64), &restarted).unwrap();
        assert_eq!(
            first.material_digest, restarted_fabric.material_digest,
            "restart/health son observacion operacional, no identidad material"
        );
        assert_eq!(
            canonical_json(&stable_runtime_material_projection(std::slice::from_ref(
                &unit
            )))
            .unwrap(),
            canonical_json(&stable_runtime_material_projection(&[restarted])).unwrap(),
            "el digest material del deployment tambien excluye identidad operacional"
        );

        let mut replaced_image = unit.clone();
        replaced_image.containers[0].image_id = format!("sha256:{}", "4".repeat(64));
        let replaced_image =
            attested_fabric_from_parts(&fabric, &release, &"d".repeat(64), &replaced_image)
                .unwrap();
        assert_ne!(first.material_digest, replaced_image.material_digest);
    }

    #[test]
    fn orden_node_luego_fabric_no_crea_deadlock_entre_deployments() {
        let root = std::env::temp_dir().join(format!("actium-lock-order-{}", Uuid::new_v4()));
        let node_a = root.join("nodes/a");
        let node_b = root.join("nodes/b");
        let fabric = root.join("fabrics/shared");
        let _node_a = ReleaseManager::new(&node_a).lock_mutation().unwrap();
        let _fabric = ReleaseManager::new(&fabric).lock_mutation().unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = barrier.clone();
        let worker_fabric = fabric.clone();
        let worker = std::thread::spawn(move || {
            let _node_b = ReleaseManager::new(&node_b).lock_mutation().unwrap();
            worker_barrier.wait();
            ReleaseManager::new(&worker_fabric)
                .lock_mutation()
                .unwrap_err()
        });
        barrier.wait();
        assert!(worker.join().unwrap().contains("MUTATION_BUSY"));
        drop(_fabric);
        assert!(ReleaseManager::new(&fabric).lock_mutation().is_ok());
        drop(_node_a);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn config_material_canonicaliza_el_orden_no_semantico_de_mounts() {
        let mount_a = serde_json::json!({
            "Destination": "/var/lib/actium-node-config",
            "Type": "bind",
            "RW": false
        });
        let mount_b = serde_json::json!({
            "Destination": "/run/secrets/token",
            "Type": "bind",
            "RW": false
        });
        let left = serde_json::json!({
            "Config": { "Image": "actium/agent:test", "Env": [], "Labels": {} },
            "HostConfig": {},
            "Mounts": [mount_a.clone(), mount_b.clone()]
        });
        let right = serde_json::json!({
            "Config": { "Image": "actium/agent:test", "Env": [], "Labels": {} },
            "HostConfig": {},
            "Mounts": [mount_b, mount_a]
        });
        assert_eq!(
            effective_container_config(&left),
            effective_container_config(&right)
        );
    }

    #[test]
    fn reemplazo_atomico_funciona_sobre_archivo_existente() {
        let root = std::env::temp_dir().join(format!("actium-atomic-replace-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let text = root.join("node.env");
        write_managed_file(&text, "VALUE=first\n", 0o640).unwrap();
        write_managed_file(&text, "VALUE=second\n", 0o640).unwrap();
        assert_eq!(fs::read_to_string(&text).unwrap(), "VALUE=second\n");
        let json = root.join("runtime-topology.json");
        write_json_atomic(&json, &serde_json::json!({"revision": 1})).unwrap();
        write_json_atomic(&json, &serde_json::json!({"revision": 2})).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&json).unwrap()).unwrap(),
            serde_json::json!({"revision": 2})
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn runtime_topology_repara_modo_0600_a_0644() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("actium-runtime-topology-mode-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();

        let topology = root.join("runtime-topology.json");

        fs::write(&topology, br#"{"revision":1}"#).unwrap();
        fs::set_permissions(&topology, fs::Permissions::from_mode(0o600)).unwrap();

        write_runtime_topology_atomic(
            &topology,
            &serde_json::json!({"revision": 2}),
        )
        .unwrap();

        let metadata = fs::metadata(&topology).unwrap();

        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o644,
            "runtime-topology.json debe ser root-owned pero legible por workloads no privilegiados"
        );

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(&topology).unwrap()).unwrap(),
            serde_json::json!({"revision": 2})
        );

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_site_core_recupera_retry_parcial_sin_dac_adicional() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-storage-retry-{}", Uuid::new_v4()));
        let unit = RuntimeUnit {
            runtime_unit_id: "site-core-retry".to_string(),
            capability: "site-core".to_string(),
            compose_project: "actium-lab-site-core-retry".to_string(),
            compose_file: "compose.site-core.yml".to_string(),
            depends_on: Vec::new(),
            startup_cohort: RuntimeStartupCohort::Bootstrap,
            startup_gate: RuntimeStartupGate::SiteCoreAlive,
            binding: RuntimeUnitBinding {
                secrets_directory: "secrets/runtime-units/site-core-retry".to_string(),
                database_role: None,
                database_schema: None,
                nats_account: None,
                nats_user: None,
                nats_subject_prefix: None,
                storage_buckets: Vec::new(),
            },
            resources: RuntimeUnitResourceBudget {
                cpus: "0.1".to_string(),
                memory_limit: "128m".to_string(),
                memory_reservation: "64m".to_string(),
                pids_limit: 64,
                log_max_size: "1m".to_string(),
                log_max_files: 1,
            },
        };

        // First install desde un root vacio.
        let fresh_root = root.join("fresh");
        prepare_runtime_unit_storage(&fresh_root, &unit)
            .expect("el first install Site Core debe materializar storage");
        let fresh_unit_root = fresh_root.join("persistent/runtime-units/site-core-retry");
        let fresh_site_core = fresh_unit_root.join("site-core");
        let fresh_root_metadata = fs::metadata(&fresh_unit_root).unwrap();
        assert_eq!(
            (fresh_root_metadata.uid(), fresh_root_metadata.gid()),
            (1000, 1000)
        );
        assert_eq!(fresh_root_metadata.permissions().mode() & 0o777, 0o750);
        // El layout final intencionalmente deja este root no searchable para
        // root sin capacidades DAC. Se recupera CAP_CHOWN temporalmente solo
        // para inspeccionar el hijo y se repone el estado final enseguida.
        chown(
            &fresh_unit_root,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(0)),
        )
        .unwrap();
        let fresh_child_metadata = fs::metadata(&fresh_site_core).unwrap();
        assert_eq!(
            (fresh_child_metadata.uid(), fresh_child_metadata.gid()),
            (0, 0)
        );
        assert_eq!(fresh_child_metadata.permissions().mode() & 0o777, 0o700);
        chown(
            &fresh_unit_root,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();

        // Estado parcial real tras FIRST_INSTALL_ABORTED: root cedido al
        // workload y Site Core root-owned antes del retry.
        let unit_root = root.join("persistent/runtime-units/site-core-retry");
        let site_core = unit_root.join("site-core");
        fs::create_dir_all(&site_core).unwrap();
        fs::set_permissions(&site_core, fs::Permissions::from_mode(0o700)).unwrap();
        chown(&site_core, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        fs::set_permissions(&unit_root, fs::Permissions::from_mode(0o750)).unwrap();
        chown(
            &unit_root,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();

        prepare_runtime_unit_storage(&root, &unit)
            .expect("el retry parcial no debe fallar con EACCES");
        // Segundo intento: representa el retry posterior a FIRST_INSTALL_ABORTED.
        prepare_runtime_unit_storage(&root, &unit).expect("el layout final debe ser idempotente");

        let root_metadata = fs::metadata(&unit_root).unwrap();
        assert_eq!((root_metadata.uid(), root_metadata.gid()), (1000, 1000));
        assert_eq!(root_metadata.permissions().mode() & 0o777, 0o750);
        chown(&unit_root, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        let child_metadata = fs::metadata(&site_core).unwrap();
        assert_eq!((child_metadata.uid(), child_metadata.gid()), (0, 0));
        assert_eq!(child_metadata.permissions().mode() & 0o777, 0o700);
        chown(
            &unit_root,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_recupera_retry_parcial_sin_dac_ni_fowner() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !require_privileged_chown_only() {
            return;
        }

        let root = std::env::temp_dir().join(format!("actium-agent-storage-{}", Uuid::new_v4()));
        let persistent = root.join("persistent/agent");
        let state = root.join("state/agent");
        let supervisor = root.join("state/supervisor");
        fs::create_dir_all(&persistent).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&supervisor).unwrap();
        fs::write(state.join("runtime.json"), "{\"schema\":1}\n").unwrap();
        fs::set_permissions(&persistent, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(
            state.join("runtime.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::set_permissions(&supervisor, fs::Permissions::from_mode(0o755)).unwrap();
        chown(
            &state.join("runtime.json"),
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        chown(
            &persistent,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();

        if std::env::var("ACTIUM_ASSERT_CHOWN_ONLY").as_deref() == Ok("1") {
            let legacy = fs::set_permissions(&persistent, fs::Permissions::from_mode(0o750));
            assert!(
                legacy.is_err(),
                "el orden viejo chmod-luego-chown debe fallar sin CAP_FOWNER"
            );
            let err = legacy.unwrap_err();
            assert_eq!(
                err.raw_os_error(),
                Some(1),
                "el orden viejo debe ser EPERM (os error 1), no {err}"
            );
        }

        super::prepare_agent_state_storage(&root)
            .expect("el retry Agent no debe fallar con EPERM bajo CAP_CHOWN");
        super::prepare_agent_state_storage(&root).expect("el layout Agent debe ser idempotente");

        let persistent_meta = fs::metadata(&persistent).unwrap();
        let state_meta = fs::metadata(&state).unwrap();
        assert_eq!((persistent_meta.uid(), persistent_meta.gid()), (1000, 1000));
        assert_eq!((state_meta.uid(), state_meta.gid()), (1000, 1000));
        assert_eq!(persistent_meta.permissions().mode() & 0o777, 0o750);
        assert_eq!(state_meta.permissions().mode() & 0o777, 0o750);

        chown(&state, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        let child = fs::metadata(state.join("runtime.json")).unwrap();
        assert_eq!((child.uid(), child.gid()), (1000, 1000));
        assert_eq!(child.permissions().mode() & 0o777, 0o600);
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();

        let supervisor_meta = fs::metadata(&supervisor).unwrap();
        assert_eq!(
            (supervisor_meta.uid(), supervisor_meta.gid()),
            (0, 0),
            "state/supervisor permanece root-owned"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_rechaza_symlink_y_no_sigue_al_objetivo() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        if !require_privileged_chown_only() {
            return;
        }

        let root = std::env::temp_dir().join(format!("actium-nofollow-{}", Uuid::new_v4()));
        let sibling = root.join("sibling-node");
        let fabric_state = root.join("state/host-identity.json");
        let persistent = root.join("persistent/agent");
        let state = root.join("state/agent");
        fs::create_dir_all(&persistent).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&sibling).unwrap();
        fs::create_dir_all(root.join("state")).unwrap();
        fs::write(&fabric_state, b"host-identity-preserve\n").unwrap();
        fs::write(sibling.join("marker"), b"sibling-preserve\n").unwrap();
        fs::set_permissions(&sibling, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&fabric_state, fs::Permissions::from_mode(0o640)).unwrap();
        chown(&sibling, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        chown(
            &fabric_state,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(0)),
        )
        .unwrap();
        symlink(&sibling, persistent.join("evil")).unwrap();
        symlink(&fabric_state, state.join("evil")).unwrap();
        chown(
            &persistent,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();

        let error = super::prepare_agent_state_storage(&root).expect_err("symlink debe fallar");
        assert!(
            error.contains(crate::privileged_fs::WORKLOAD_SYMLINK_REJECTED),
            "{error}"
        );

        let sibling_meta = fs::metadata(&sibling).unwrap();
        let fabric_meta = fs::metadata(&fabric_state).unwrap();
        assert_eq!((sibling_meta.uid(), sibling_meta.gid()), (0, 0));
        assert_eq!(sibling_meta.permissions().mode() & 0o777, 0o750);
        assert_eq!(
            fs::read(sibling.join("marker")).unwrap(),
            b"sibling-preserve\n"
        );
        assert_eq!((fabric_meta.uid(), fabric_meta.gid()), (0, 0));
        assert_eq!(fabric_meta.permissions().mode() & 0o777, 0o640);
        assert_eq!(
            fs::read(&fabric_state).unwrap(),
            b"host-identity-preserve\n"
        );
        assert!(fs::symlink_metadata(persistent.join("evil"))
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_rechaza_fifo_y_no_lo_promueve() {
        use nix::sys::stat::{mknod, Mode, SFlag};
        use nix::unistd::{chown, Gid, Uid};

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-fifo-{}", Uuid::new_v4()));
        let persistent = root.join("persistent/agent");
        fs::create_dir_all(&persistent).unwrap();
        fs::create_dir_all(root.join("state/agent")).unwrap();
        mknod(
            &persistent.join("evil.fifo"),
            SFlag::S_IFIFO,
            Mode::from_bits_truncate(0o600),
            0,
        )
        .unwrap();
        chown(
            &persistent,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        let error = super::prepare_agent_state_storage(&root).expect_err("fifo debe fallar");
        assert!(
            error.contains(crate::privileged_fs::WORKLOAD_SPECIAL_FILE_REJECTED),
            "{error}"
        );
        assert!(fs::symlink_metadata(persistent.join("evil.fifo")).is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_runtime_unit_rechaza_symlink_en_hijo() {
        use std::os::unix::fs::symlink;

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-unit-symlink-{}", Uuid::new_v4()));
        let unit = RuntimeUnit {
            runtime_unit_id: "radio-saf-retry".to_string(),
            capability: "radio-saf".to_string(),
            compose_project: "actium-lab-radio-saf-retry".to_string(),
            compose_file: "compose.radio-saf.yml".to_string(),
            depends_on: Vec::new(),
            startup_cohort: RuntimeStartupCohort::Bootstrap,
            startup_gate: RuntimeStartupGate::SiteCoreAlive,
            binding: RuntimeUnitBinding {
                secrets_directory: "secrets/runtime-units/radio-saf-retry".to_string(),
                database_role: None,
                database_schema: None,
                nats_account: None,
                nats_user: None,
                nats_subject_prefix: None,
                storage_buckets: Vec::new(),
            },
            resources: RuntimeUnitResourceBudget {
                cpus: "0.1".to_string(),
                memory_limit: "128m".to_string(),
                memory_reservation: "64m".to_string(),
                pids_limit: 64,
                log_max_size: "1m".to_string(),
                log_max_files: 1,
            },
        };
        let unit_root = root.join("persistent/runtime-units/radio-saf-retry");
        fs::create_dir_all(&unit_root).unwrap();
        let sibling = root.join("sibling-secret");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("secret"), b"keep\n").unwrap();
        symlink(&sibling, unit_root.join("objects")).unwrap();
        let error = super::prepare_runtime_unit_storage(&root, &unit)
            .expect_err("symlink unit debe fallar");
        assert!(
            error.contains(crate::privileged_fs::WORKLOAD_SYMLINK_REJECTED),
            "{error}"
        );
        assert_eq!(fs::read(sibling.join("secret")).unwrap(), b"keep\n");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_toctou_cerrado_tras_recuperar_root() {
        if !require_privileged_chown_only() {
            return;
        }

        let root = std::env::temp_dir().join(format!("actium-toctou-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();

        let persistent = crate::privileged_fs::PrivilegedDir::open_path(&root)
            .unwrap()
            .ensure_dir("persistent")
            .unwrap()
            .ensure_dir("agent")
            .unwrap();

        persistent.reclaim(0, 0, 0o750).unwrap();

        let target = root.join("outside");
        fs::write(&target, b"keep\n").unwrap();

        // El supervisor de este test corre deliberadamente como EUID 0 con
        // CAP_CHOWN como unica capability. No puede usar seteuid(1000),
        // porque CAP_SETUID no forma parte del boundary product-equivalent.
        //
        // Simulamos por eso al atacante en un proceso independiente realmente
        // UID/GID 1000, sin capabilities y con no-new-privileges.
        let mount_arg = format!("{}:/fixture", root.display());

        let attacker_script = r#"
const fs = require('fs');

if (typeof process.getuid !== 'function' || process.getuid() !== 1000) {
  console.error('ATTACKER_WRONG_UID');
  process.exit(90);
}

try {
  fs.symlinkSync(
    '/fixture/outside',
    '/fixture/persistent/agent/race'
  );

  console.error('ATTACKER_SYMLINK_CREATED');
  process.exit(91);
} catch (error) {
  if (error && (error.code === 'EACCES' || error.code === 'EPERM')) {
    process.exit(0);
  }

  console.error(
    `ATTACKER_UNEXPECTED_ERROR:${error && (error.code || error.message)}`
  );
  process.exit(92);
}
"#;

        let attacker = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                "1000:1000",
                "-v",
                &mount_arg,
                "node:20-alpine",
                "node",
                "-e",
                attacker_script,
            ])
            .output()
            .expect("debe poder ejecutar el fixture atacante UID 1000");

        assert!(
            attacker.status.success(),
            "el atacante UID 1000 debe recibir EACCES/EPERM al intentar plantar \
             el symlink; status={:?}, stdout={}, stderr={}",
            attacker.status,
            String::from_utf8_lossy(&attacker.stdout),
            String::from_utf8_lossy(&attacker.stderr),
        );

        assert!(
            fs::symlink_metadata(root.join("persistent/agent/race")).is_err(),
            "el symlink atacante no debe existir tras recuperar root:root 0750"
        );

        assert_eq!(fs::read(&target).unwrap(), b"keep\n");

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_radio_saf_recupera_retry_parcial_sin_dac() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-radio-saf-{}", Uuid::new_v4()));
        let unit = RuntimeUnit {
            runtime_unit_id: "radio-saf-retry".to_string(),
            capability: "radio-saf".to_string(),
            compose_project: "actium-lab-radio-saf-retry".to_string(),
            compose_file: "compose.radio-saf.yml".to_string(),
            depends_on: Vec::new(),
            startup_cohort: RuntimeStartupCohort::Bootstrap,
            startup_gate: RuntimeStartupGate::SiteCoreAlive,
            binding: RuntimeUnitBinding {
                secrets_directory: "secrets/runtime-units/radio-saf-retry".to_string(),
                database_role: None,
                database_schema: None,
                nats_account: None,
                nats_user: None,
                nats_subject_prefix: None,
                storage_buckets: Vec::new(),
            },
            resources: RuntimeUnitResourceBudget {
                cpus: "0.1".to_string(),
                memory_limit: "128m".to_string(),
                memory_reservation: "64m".to_string(),
                pids_limit: 64,
                log_max_size: "1m".to_string(),
                log_max_files: 1,
            },
        };
        let unit_root = root.join("persistent/runtime-units/radio-saf-retry");
        let objects = unit_root.join("objects");
        let archive = unit_root.join("radio-archive");
        fs::create_dir_all(&objects).unwrap();
        fs::create_dir_all(&archive).unwrap();
        for path in [&objects, &archive, &unit_root] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o750)).unwrap();
            chown(path, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        }
        super::prepare_runtime_unit_storage(&root, &unit)
            .expect("radio-saf 0750 1000:1000 debe recuperarse con CAP_CHOWN");
        super::prepare_runtime_unit_storage(&root, &unit).expect("radio-saf idempotente");
        chown(&unit_root, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        for child in [&objects, &archive] {
            let meta = fs::metadata(child).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (1000, 1000));
            assert_eq!(meta.permissions().mode() & 0o777, 0o750);
        }
        chown(
            &unit_root,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_fabric_nats_recupera_sin_dac() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-fabric-nats-{}", Uuid::new_v4()));
        let nats = root.join("persistent/nats");
        fs::create_dir_all(&nats).unwrap();
        fs::set_permissions(&nats, fs::Permissions::from_mode(0o750)).unwrap();
        chown(
            &nats,
            Some(Uid::from_raw(10_001)),
            Some(Gid::from_raw(10_001)),
        )
        .unwrap();
        super::prepare_fabric_nats_storage(&root)
            .expect("Fabric nats 0750 10001:10001 debe recuperarse con CAP_CHOWN");
        super::prepare_fabric_nats_storage(&root).expect("Fabric nats idempotente");
        let persistent = root.join("persistent");
        chown(&persistent, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        let meta = fs::metadata(&nats).unwrap();
        assert_eq!((meta.uid(), meta.gid()), (10_001, 10_001));
        assert_eq!(meta.permissions().mode() & 0o777, 0o750);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_rechaza_socket_y_no_lo_promueve() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::net::UnixListener;

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-socket-{}", Uuid::new_v4()));
        let persistent = root.join("persistent/agent");
        fs::create_dir_all(&persistent).unwrap();
        fs::create_dir_all(root.join("state/agent")).unwrap();
        let _listener = UnixListener::bind(persistent.join("evil.sock")).unwrap();
        chown(
            &persistent,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        let error = super::prepare_agent_state_storage(&root).expect_err("socket debe fallar");
        assert!(
            error.contains(crate::privileged_fs::WORKLOAD_SPECIAL_FILE_REJECTED),
            "{error}"
        );
        assert!(fs::symlink_metadata(persistent.join("evil.sock")).is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_no_confunde_runtime_json_0600_con_ausente() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-agent-exist-{}", Uuid::new_v4()));
        let state = root.join("state/agent");
        let legacy = root.join("state/node-runtime");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&legacy).unwrap();
        fs::create_dir_all(root.join("persistent/agent")).unwrap();
        fs::write(state.join("runtime.json"), b"keep-existing\n").unwrap();
        fs::write(legacy.join("runtime.json"), b"should-not-copy\n").unwrap();
        fs::set_permissions(state.join("runtime.json"), fs::Permissions::from_mode(0o600)).unwrap();
        chown(
            &state.join("runtime.json"),
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        super::prepare_agent_state_storage(&root)
            .expect("runtime.json 0600 existente no es ausente");
        chown(&state, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();

        let runtime_path = state.join("runtime.json");

        // Comprobar primero el estado productivo sin alterar el archivo.
        let child = fs::metadata(&runtime_path).unwrap();
        assert_eq!((child.uid(), child.gid()), (1000, 1000));
        assert_eq!(child.permissions().mode() & 0o777, 0o600);

        // Un Supervisor CAP_CHOWN-only no puede leer directamente un archivo
        // 0600 1000:1000. Reclamamos temporalmente sólo para inspección del test.
        chown(
            &runtime_path,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(0)),
        )
        .unwrap();

        let contents = fs::read(&runtime_path).unwrap();

        chown(
            &runtime_path,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();

        assert_eq!(contents, b"keep-existing\n");

        let child = fs::metadata(&runtime_path).unwrap();
        assert_eq!((child.uid(), child.gid()), (1000, 1000));
        assert_eq!(child.permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_copy_legacy_migra_archivo_faltante() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !require_privileged_chown_only() {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-agent-copy-{}", Uuid::new_v4()));
        let state = root.join("state/agent");
        let legacy = root.join("state/node-runtime");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&legacy).unwrap();
        fs::create_dir_all(root.join("persistent/agent")).unwrap();
        fs::write(legacy.join("runtime.json"), b"{\"migrated\":true}\n").unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        chown(&legacy, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();

        super::prepare_agent_state_storage(&root)
            .expect("copy_file_if_missing debe migrar exitosamente con FD escribible");

        chown(&state, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();

        let runtime_path = state.join("runtime.json");

        // La migración debe terminar en el ownership/mode productivo.
        let child = fs::metadata(&runtime_path).unwrap();
        assert_eq!((child.uid(), child.gid()), (1000, 1000));
        assert_eq!(child.permissions().mode() & 0o777, 0o600);

        // Inspección controlada usando exclusivamente CAP_CHOWN.
        chown(
            &runtime_path,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(0)),
        )
        .unwrap();

        let contents = fs::read(&runtime_path).unwrap();

        chown(
            &runtime_path,
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .unwrap();

        assert_eq!(
            contents,
            b"{\"migrated\":true}\n",
            "el archivo migrado debe tener el contenido exacto de la fuente legacy"
        );

        let child = fs::metadata(&runtime_path).unwrap();
        assert_eq!((child.uid(), child.gid()), (1000, 1000));
        assert_eq!(child.permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_restricted_supervisor_falla_lectura_host_directo() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::PermissionsExt;

        if !require_privileged_chown_only() {
            return;
        }
        if std::env::var("ACTIUM_ASSERT_CHOWN_ONLY").as_deref() != Ok("1") {
            return;
        }
        let root = std::env::temp_dir().join(format!("actium-agent-eacces-{}", Uuid::new_v4()));
        let state = root.join("state/agent");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("agent-lifecycle.json"), b"{\"state\":\"running\"}\n").unwrap();
        fs::write(state.join("runtime.json"), b"{\"generation\":1}\n").unwrap();
        fs::set_permissions(state.join("agent-lifecycle.json"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(state.join("runtime.json"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
        chown(&state.join("agent-lifecycle.json"), Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        chown(&state.join("runtime.json"), Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();

        // Demuestra que un proceso root sin CAP_DAC_READ_SEARCH no puede leer directamente por host
        let host_read = fs::read_to_string(state.join("agent-lifecycle.json"));
        assert!(
            host_read.is_err(),
            "la lectura host tradicional DEBE fallar con EACCES bajo el hardening real"
        );
        let err = host_read.unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(13),
            "el error debe ser exactamente EACCES (os error 13), no {err}"
        );

        let host_runtime = fs::read_to_string(state.join("runtime.json"));
        assert!(
            host_runtime.is_err(),
            "la lectura de runtime.json DEBE fallar con EACCES bajo el hardening real"
        );
        assert_eq!(
            host_runtime.unwrap_err().raw_os_error(),
            Some(13)
        );

        // Limpieza con chown temporal para poder borrar
        chown(&state, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_ensure_node_storage_path_rechaza_symlink_y_no_escapa() {
        use std::os::unix::fs::symlink;

        if !require_privileged_chown_only() {
            return;
        }

        let root = std::env::temp_dir().join(format!("actium-node-path-{}", Uuid::new_v4()));
        let persistent = root.join("persistent");
        let attacker_dir = persistent.join("attacker");
        let external = root.join("sibling-node");
        let sentinel = external.join("sentinel.txt");

        fs::create_dir_all(&attacker_dir).unwrap();
        fs::create_dir_all(&external).unwrap();
        fs::write(&sentinel, b"sentinel-protected-content\n").unwrap();

        // attacker crea un symlink que apunta a sibling-node
        symlink(&external, attacker_dir.join("evil")).unwrap();

        // Intentar crear storage atravesando el symlink evil
        let result = ensure_node_storage_path(&root, "attacker/evil/unauthorized_subdir");
        assert!(
            result.is_err(),
            "ensure_node_storage_path DEBE fallar al atravesar un symlink dentro de persistent"
        );
        let error = result.unwrap_err();
        assert!(
            error.contains(crate::privileged_fs::WORKLOAD_SYMLINK_REJECTED),
            "error debe ser WORKLOAD_SYMLINK_REJECTED, fue: {error}"
        );

        // Verificar que NO se creo el subdirectorio dentro de external
        assert!(
            !external.join("unauthorized_subdir").exists(),
            "no debe haberse creado ningun subdirectorio en el target del symlink"
        );

        // Verificar que el sentinel sigue intacto
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"sentinel-protected-content\n",
            "el contenido del sentinel no debe haber sido modificado"
        );

        // Verificar que evil sigue siendo un symlink sin haber sido seguido
        let meta = fs::symlink_metadata(attacker_dir.join("evil")).unwrap();
        assert!(meta.file_type().is_symlink());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_ensure_node_storage_path_crea_ruta_absoluta_externa() {
        let root = std::env::temp_dir().join(format!("actium-node-ext-{}", Uuid::new_v4()));
        let node = root.join("node");
        let mass = root.join("hdd").join("dvr");
        fs::create_dir_all(&node).unwrap();
        let created = ensure_node_storage_path(&node, mass.to_str().unwrap()).unwrap();
        assert_eq!(created, mass);
        assert!(mass.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_restricted_supervisor_e2e_reader_container() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::PermissionsExt;

        if !require_privileged_chown_only() {
            return;
        }
        if std::env::var("ACTIUM_ASSERT_CHOWN_ONLY").as_deref() != Ok("1") {
            return;
        }

        struct ContainerGuard {
            container_name: String,
            state_dir: std::path::PathBuf,
            root_dir: std::path::PathBuf,
            fabric_dir: std::path::PathBuf,
        }

        impl Drop for ContainerGuard {
            fn drop(&mut self) {
                let _ = Command::new("docker").args(["rm", "-f", &self.container_name]).output();
                #[cfg(unix)]
                {
                    use nix::unistd::{chown, Gid, Uid};
                    let _ = chown(&self.state_dir, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)));
                }
                let _ = fs::remove_dir_all(&self.root_dir);
                let _ = fs::remove_dir_all(&self.fabric_dir);
            }
        }

        let docker_check = Command::new("docker")
            .args(["info"])
            .output()
            .expect("Docker CLI debe poder ejecutarse en el gate E2E");
        assert!(
            docker_check.status.success(),
            "Docker daemon debe estar activo para el test E2E restricted: {}",
            String::from_utf8_lossy(&docker_check.stderr)
        );

        let root = std::env::temp_dir().join(format!("actium-e2e-node-{}", Uuid::new_v4()));
        let fabric_root = std::env::temp_dir().join(format!("actium-e2e-fab-{}", Uuid::new_v4()));
        let state = root.join("state/agent");
        let supervisor_state = root.join("state/supervisor");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&supervisor_state).unwrap();
        fs::create_dir_all(root.join("persistent/agent")).unwrap();
        fs::create_dir_all(&fabric_root).unwrap();

        let deployment_id = Uuid::new_v4().to_string();
        let runtime_unit_id = Uuid::new_v4().to_string();
        let fabric_id = Uuid::new_v4().to_string();
        let host_id = Uuid::new_v4().to_string();

        let lifecycle_json = format!(
            r#"{{
  "schemaVersion": 1,
  "deploymentId": "{deployment_id}",
  "runtimeUnitId": "{runtime_unit_id}",
  "hostId": "{host_id}",
  "state": "reporting",
  "startedAt": "2026-08-18T00:00:00Z",
  "updatedAt": "2026-08-18T00:00:10Z",
  "enrolledAt": "2026-08-18T00:00:02Z",
  "hostReconciledAt": "2026-08-18T00:00:04Z",
  "runtimeSyncedAt": "2026-08-18T00:00:06Z",
  "siteCoreReadyAt": "2026-08-18T00:00:08Z",
  "reportingAt": "2026-08-18T00:00:10Z",
  "events": [
    {{"state": "starting", "at": "2026-08-18T00:00:00Z"}},
    {{"state": "enrolled", "at": "2026-08-18T00:00:02Z"}},
    {{"state": "host_reconciled", "at": "2026-08-18T00:00:04Z"}},
    {{"state": "runtime_sync_pending", "at": "2026-08-18T00:00:05Z"}},
    {{"state": "runtime_synced", "at": "2026-08-18T00:00:06Z"}},
    {{"state": "site_core_ready", "at": "2026-08-18T00:00:08Z"}},
    {{"state": "reporting", "at": "2026-08-18T00:00:10Z"}}
  ]
}}"#
        );
        let runtime_json = format!(
            r#"{{"generation":42,"schemaVersion":1,"deploymentId":"{deployment_id}","runtimeUnitId":"{runtime_unit_id}","data":"test-e2e-payload"}}"#
        );

        fs::write(state.join("agent-lifecycle.json"), lifecycle_json.as_bytes()).unwrap();
        fs::write(state.join("runtime.json"), runtime_json.as_bytes()).unwrap();
        fs::set_permissions(state.join("agent-lifecycle.json"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(state.join("runtime.json"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
        chown(&state.join("agent-lifecycle.json"), Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        chown(&state.join("runtime.json"), Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();

        // 1. Probar que host direct read falla con EACCES bajo CAP_CHOWN
        let host_read = fs::read_to_string(state.join("agent-lifecycle.json"));
        assert!(host_read.is_err(), "host read debe fallar con EACCES");
        assert_eq!(host_read.unwrap_err().raw_os_error(), Some(13));

        let host_runtime = fs::read_to_string(state.join("runtime.json"));
        assert!(host_runtime.is_err(), "host read de runtime.json debe fallar con EACCES");
        assert_eq!(host_runtime.unwrap_err().raw_os_error(), Some(13));

        // 2. Levantar contenedor Agent-like con labels canónicos
        let container_name = format!("actium-e2e-agent-{}", Uuid::new_v4());
        let compose_project = format!("proj-e2e-{}", Uuid::new_v4());
        let mount_arg = format!("{}:/var/lib/actium-node-config", state.display());
        let label_proj = format!("com.docker.compose.project={}", compose_project);
        let label_unit = format!("com.actium.runtime-unit-id={}", runtime_unit_id);

        let run_res = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &container_name,
                "--label",
                &label_proj,
                "--label",
                "com.actium.capability=agent",
                "--label",
                &label_unit,
                "-v",
                &mount_arg,
                "--user",
                "1000:1000",
                "node:20-alpine",
                "sleep",
                "120",
            ])
            .output()
            .expect("docker run debe ejecutarse para el test E2E");

        assert!(
            run_res.status.success(),
            "Container fixture debe arrancar exitosamente: {}",
            String::from_utf8_lossy(&run_res.stderr)
        );

        let _guard = ContainerGuard {
            container_name: container_name.clone(),
            state_dir: state.clone(),
            root_dir: root.clone(),
            fabric_dir: fabric_root.clone(),
        };

        // 3. Escribir runtime-topology.json
        let topology = RuntimeTopology {
            schema: crate::topology::RUNTIME_TOPOLOGY_SCHEMA,
            host_installation_id: "host-inst-e2e".to_string(),
            host_id: Some(host_id),
            deployment_id: deployment_id.clone(),
            deployment_code: "dep-test-e2e".to_string(),
            deployment_network_name: "actium-dep-e2e-net".to_string(),
            fabric: FabricIdentity {
                fabric_id: fabric_id.clone(),
                compose_project: "actium-fab-e2e".to_string(),
                network_name: "actium-fab-e2e-net".to_string(),
                host_id: None,
            },
            units: vec![RuntimeUnit {
                runtime_unit_id: runtime_unit_id.clone(),
                capability: "agent".to_string(),
                compose_project,
                compose_file: "compose.agent.yml".to_string(),
                depends_on: Vec::new(),
                startup_cohort: RuntimeStartupCohort::Bootstrap,
                startup_gate: RuntimeStartupGate::AgentReporting,
                binding: RuntimeUnitBinding {
                    secrets_directory: format!("secrets/runtime-units/{runtime_unit_id}"),
                    database_role: None,
                    database_schema: None,
                    nats_account: None,
                    nats_user: None,
                    nats_subject_prefix: None,
                    storage_buckets: Vec::new(),
                },
                resources: RuntimeUnitResourceBudget {
                    cpus: "0.1".to_string(),
                    memory_limit: "128m".to_string(),
                    memory_reservation: "64m".to_string(),
                    pids_limit: 64,
                    log_max_size: "1m".to_string(),
                    log_max_files: 1,
                },
            }],
        };
        let topology_json = serde_json::to_string(&topology).unwrap();
        fs::write(root.join("state/runtime-topology.json"), topology_json).unwrap();
        fs::write(
            root.join("node.env"),
            format!("ACTIUM_DEPLOYMENT_ID={deployment_id}\nACTIUM_INSTALLER_VERSION=0.8.0-lab.28\n"),
        )
        .unwrap();
        fs::write(
            fabric_root.join("fabric.env"),
            format!("ACTIUM_FABRIC_ID={fabric_id}\n"),
        )
        .unwrap();

        // 4. Probar reader productivo con contenedor activo
        let state_read = read_agent_state_file(&root, "agent-lifecycle.json", 128 * 1024)
            .expect("read_agent_state_file debe tener exito");
        match state_read {
            AgentStateRead::Present(contents) => {
                assert!(contents.contains("reporting"), "contenido leido debe ser reporting");
            }
            other => panic!("se esperaba AgentStateRead::Present, se obtuvo: {other:?}"),
        }

        let runtime_read = read_agent_state_file(&root, "runtime.json", 256 * 1024)
            .expect("read_agent_state_file runtime.json debe tener exito");
        match runtime_read {
            AgentStateRead::Present(contents) => {
                assert!(contents.contains("\"generation\":42"), "contenido leido debe tener generation 42");
            }
            other => panic!("se esperaba AgentStateRead::Present, se obtuvo: {other:?}"),
        }

        // Probar read_agent_lifecycle
        let doc = read_agent_lifecycle(&root)
            .expect("read_agent_lifecycle exitoso")
            .expect("debe contener documento");
        assert_eq!(doc.state, "reporting");
        assert_eq!(doc.runtime_unit_id, runtime_unit_id);
        assert_eq!(doc.deployment_id, deployment_id);

        // Probar attestation reader con generation 42 y digest real
        let snapshot = read_attestation_snapshot_revision(&root, &fabric_root)
            .expect("read_attestation_snapshot_revision exitoso");
        assert_eq!(snapshot.revision.generation, 42);
        assert_eq!(
            snapshot.revision.agent_runtime_digest,
            sha256_hex(runtime_json.as_bytes())
        );
    }

    #[cfg(unix)]
    #[test]
    fn storage_agent_reader_large_payload_no_pipe_deadlock() {
        use nix::unistd::{chown, Gid, Uid};
        use std::os::unix::fs::PermissionsExt;

        if !require_privileged_chown_only() {
            return;
        }
        if std::env::var("ACTIUM_ASSERT_CHOWN_ONLY").as_deref() != Ok("1") {
            return;
        }

        struct ContainerGuard {
            container_name: String,
            state_dir: std::path::PathBuf,
            root_dir: std::path::PathBuf,
        }

        impl Drop for ContainerGuard {
            fn drop(&mut self) {
                let _ = Command::new("docker").args(["rm", "-f", &self.container_name]).output();
                #[cfg(unix)]
                {
                    use nix::unistd::{chown, Gid, Uid};
                    let _ = chown(&self.state_dir, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)));
                }
                let _ = fs::remove_dir_all(&self.root_dir);
            }
        }

        let root = std::env::temp_dir().join(format!("actium-pipe-node-{}", Uuid::new_v4()));
        let state = root.join("state/agent");
        fs::create_dir_all(&state).unwrap();

        let deployment_id = Uuid::new_v4().to_string();
        let runtime_unit_id = Uuid::new_v4().to_string();

        let padding = "x".repeat(100 * 1024);
        let large_runtime_json = format!(
            r#"{{"generation":101,"schemaVersion":1,"deploymentId":"{deployment_id}","runtimeUnitId":"{runtime_unit_id}","padding":"{padding}"}}"#
        );

        fs::write(state.join("runtime.json"), large_runtime_json.as_bytes()).unwrap();
        fs::set_permissions(state.join("runtime.json"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750)).unwrap();
        chown(&state.join("runtime.json"), Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();
        chown(&state, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).unwrap();

        let container_name = format!("actium-pipe-agent-{}", Uuid::new_v4());
        let compose_project = format!("proj-pipe-{}", Uuid::new_v4());
        let mount_arg = format!("{}:/var/lib/actium-node-config", state.display());
        let label_proj = format!("com.docker.compose.project={}", compose_project);
        let label_unit = format!("com.actium.runtime-unit-id={}", runtime_unit_id);

        let run_res = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &container_name,
                "--label",
                &label_proj,
                "--label",
                "com.actium.capability=agent",
                "--label",
                &label_unit,
                "-v",
                &mount_arg,
                "--user",
                "1000:1000",
                "node:20-alpine",
                "sleep",
                "120",
            ])
            .output()
            .expect("docker run debe ejecutarse");

        assert!(run_res.status.success(), "Container fixture debe arrancar");

        let _guard = ContainerGuard {
            container_name: container_name.clone(),
            state_dir: state.clone(),
            root_dir: root.clone(),
        };

        let topology = RuntimeTopology {
            schema: crate::topology::RUNTIME_TOPOLOGY_SCHEMA,
            host_installation_id: "host-inst-pipe".to_string(),
            host_id: None,
            deployment_id: deployment_id.clone(),
            deployment_code: "dep-test-pipe".to_string(),
            deployment_network_name: "actium-dep-pipe-net".to_string(),
            fabric: FabricIdentity {
                fabric_id: "fab-pipe".to_string(),
                compose_project: "actium-fab-pipe".to_string(),
                network_name: "actium-fab-pipe-net".to_string(),
                host_id: None,
            },
            units: vec![RuntimeUnit {
                runtime_unit_id: runtime_unit_id.clone(),
                capability: "agent".to_string(),
                compose_project,
                compose_file: "compose.agent.yml".to_string(),
                depends_on: Vec::new(),
                startup_cohort: RuntimeStartupCohort::Bootstrap,
                startup_gate: RuntimeStartupGate::AgentReporting,
                binding: RuntimeUnitBinding {
                    secrets_directory: format!("secrets/runtime-units/{runtime_unit_id}"),
                    database_role: None,
                    database_schema: None,
                    nats_account: None,
                    nats_user: None,
                    nats_subject_prefix: None,
                    storage_buckets: Vec::new(),
                },
                resources: RuntimeUnitResourceBudget {
                    cpus: "0.1".to_string(),
                    memory_limit: "128m".to_string(),
                    memory_reservation: "64m".to_string(),
                    pids_limit: 64,
                    log_max_size: "1m".to_string(),
                    log_max_files: 1,
                },
            }],
        };
        fs::write(root.join("state/runtime-topology.json"), serde_json::to_string(&topology).unwrap()).unwrap();

        let runtime_read = read_agent_state_file(&root, "runtime.json", 256 * 1024)
            .expect("read_agent_state_file debe tener exito");
        match runtime_read {
            AgentStateRead::Present(contents) => {
                assert!(contents.contains("\"generation\":101"), "contenido leido debe tener generation 101");
                assert_eq!(contents.len(), large_runtime_json.len());
            }
            other => panic!("se esperaba AgentStateRead::Present, se obtuvo: {other:?}"),
        }

        let too_large_res = read_agent_state_file(&root, "runtime.json", 50 * 1024);
        assert!(too_large_res.is_err(), "debe fallar con error de tamano");
        assert!(too_large_res.unwrap_err().contains("AGENT_STATE_TOO_LARGE"));
    }

    fn test_payload(root: &std::path::Path, version: &str) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("VERSION"), format!("{version}\n")).unwrap();
        let bytes = fs::read(root.join("VERSION")).unwrap();
        let files = vec![PayloadFile {
            path: "VERSION".to_string(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }];
        let manifest = PayloadManifestV3 {
            schema: 3,
            release_version: version.to_string(),
            generated_at: "2026-08-14T00:00:00Z".to_string(),
            site_runtime_schema: "1.1".to_string(),
            supported_profiles: crate::KNOWN_PROFILES
                .iter()
                .filter(|profile| !matches!(**profile, "people" | "control"))
                .map(|profile| (*profile).to_string())
                .collect(),
            supported_features: Vec::new(),
            tree_sha256: tree_sha256(&files),
            files,
            source_commit: Some("fault-test".to_string()),
            source_dirty: false,
        };
        fs::write(
            root.join("PAYLOAD.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn test_people_payload(root: &std::path::Path, version: &str) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("VERSION"), format!("{version}\n")).unwrap();
        let supported_profiles = crate::KNOWN_PROFILES
            .iter()
            .map(|profile| (*profile).to_string())
            .collect::<Vec<_>>();
        let supported_features = vec!["people_runtime_v1".to_string()];
        let releases = BTreeMap::from([(
            version.to_string(),
            serde_json::json!({
                "supportedProfiles": supported_profiles.clone(),
                "supportedFeatures": supported_features.clone(),
            }),
        )]);
        fs::write(
            root.join("release-capabilities.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema": 1,
                "releases": releases,
            }))
            .unwrap(),
        )
        .unwrap();
        let files = ["VERSION", "release-capabilities.json"]
            .into_iter()
            .map(|name| {
                let bytes = fs::read(root.join(name)).unwrap();
                PayloadFile {
                    path: name.to_string(),
                    size: bytes.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(bytes)),
                }
            })
            .collect::<Vec<_>>();
        let manifest = PayloadManifestV3 {
            schema: 3,
            release_version: version.to_string(),
            generated_at: "2026-08-20T00:00:00Z".to_string(),
            site_runtime_schema: "1.1".to_string(),
            supported_profiles,
            supported_features,
            tree_sha256: tree_sha256(&files),
            files,
            source_commit: Some("a".repeat(40)),
            source_dirty: false,
        };
        fs::write(
            root.join("PAYLOAD.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn commissioning_y_resume_rechazan_people_si_el_payload_no_lo_declara() {
        for resume_incomplete in [false, true] {
            let root = std::env::temp_dir().join(format!(
                "actium-people-release-gate-{}",
                Uuid::new_v4()
            ));
            let nodes = root.join("nodes");
            let payload = root.join("payload");
            fs::create_dir_all(&nodes).unwrap();
            test_payload(&payload, "0.8.0-lab.32");
            let (installation_id, deployment_id, project) = incomplete_ids();
            let node = nodes.join(&project);
            if resume_incomplete {
                write_incomplete_leftover(
                    &node,
                    &installation_id,
                    &deployment_id,
                    &project,
                    "failed",
                );
                let leftover = fs::read_to_string(node.join("node.env")).unwrap();
                fs::write(
                    node.join("node.env"),
                    leftover.replace("ACTIUM_PROFILES=site-core", "ACTIUM_PROFILES=people"),
                )
                .unwrap();
            }
            let mut request = resume_request(
                &node,
                "0.8.0-lab.32",
                &installation_id,
                &deployment_id,
                &project,
                resume_incomplete,
            );
            request.node_env = request
                .node_env
                .replace("ACTIUM_PROFILES=site-core", "ACTIUM_PROFILES=people");
            let operator = RuntimeOperator::new(&nodes, &payload);
            let error = operator
                .commission_node(&request)
                .expect_err("Lab.32 no debe aceptar People");
            assert!(
                error.contains("RUNTIME_RELEASE_PROFILE_UNSUPPORTED"),
                "{error}"
            );
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn update_y_recovery_validan_profiles_y_features_del_intent_activo() {
        let root = std::env::temp_dir().join(format!(
            "actium-runtime-capability-update-{}",
            Uuid::new_v4()
        ));
        let nodes = root.join("nodes");
        let node = nodes.join("actium-lab-capability-gate");
        let payload = root.join("payload");
        fs::create_dir_all(&node).unwrap();
        test_payload(&payload, "0.8.0-lab.32");
        let manifest = match verify_payload(&payload).unwrap() {
            VerifiedPayload::Schema3(manifest) => manifest,
            _ => unreachable!(),
        };
        let operator = RuntimeOperator::new(&nodes, &payload);

        fs::write(
            node.join("node.env"),
            "ACTIUM_PROFILES=people\nACTIUM_REQUIRED_RUNTIME_FEATURES=\n",
        )
        .unwrap();
        let profile_error = operator
            .require_runtime_capabilities(&node, &manifest)
            .expect_err("un downgrade no puede quitar People");
        assert!(profile_error.contains("RUNTIME_RELEASE_PROFILE_UNSUPPORTED"));

        fs::write(
            node.join("node.env"),
            "ACTIUM_PROFILES=site-core\nACTIUM_REQUIRED_RUNTIME_FEATURES=site_core_candidate_v1\n",
        )
        .unwrap();
        let feature_error = operator
            .require_runtime_capabilities(&node, &manifest)
            .expect_err("un downgrade no puede quitar features activas");
        assert!(feature_error.contains("RUNTIME_RELEASE_FEATURE_UNSUPPORTED"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn start_y_apply_rechazan_people_sobre_lab32_antes_de_tocar_runtime() {
        let root = std::env::temp_dir().join(format!(
            "actium-runtime-start-capability-gate-{}",
            Uuid::new_v4()
        ));
        let nodes = root.join("nodes");
        let node = nodes.join("actium-lab-start-gate");
        let payload = root.join("lab32");
        let rejected_candidate = root.join("lab33");
        write_lab_marker(&node, "running");
        write_min_topology(&node, "start-gate");
        add_people_to_min_topology(&node);
        fs::OpenOptions::new()
            .append(true)
            .open(node.join("node.env"))
            .unwrap()
            .write_all(
                b"ACTIUM_PROFILES=people\nACTIUM_REQUIRED_RUNTIME_FEATURES=people_runtime_v1\n",
            )
            .unwrap();
        test_payload(&payload, "0.8.0-lab.32");
        test_payload(&rejected_candidate, "0.8.0-lab.33");
        let releases = ReleaseManager::new(&node);
        releases
            .begin_promotion(releases.prepare(&payload).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let operator = RuntimeOperator::new(&nodes, &payload);

        with_reconcile_intercept(true, false, |intercept| {
            for action in ["start", "apply_configuration"] {
                let error = operator
                    .execute(&node, action, None)
                    .expect_err("Lab.32 no puede arrancar ni aplicar People");
                assert!(
                    error.contains("RUNTIME_RELEASE_PROFILE_UNSUPPORTED"),
                    "{action}: {error}"
                );
            }
            let unit_error = operator
                .execute_runtime_unit(&RuntimeUnitActionRequest {
                    install_dir: node.to_string_lossy().into_owned(),
                    runtime_unit_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_string(),
                    action: "start".to_string(),
                })
                .expect_err("el start directo de People tampoco puede eludir la release");
            assert!(
                unit_error.contains("RUNTIME_RELEASE_PROFILE_UNSUPPORTED"),
                "{unit_error}"
            );
            let steady_error = operator
                .reconcile_node_runtime(&node)
                .expect_err("steady healthy debe revalidar la release activa");
            assert!(steady_error.contains("RUNTIME_RELEASE_PROFILE_UNSUPPORTED"));

            releases
                .begin_promotion(releases.prepare(&rejected_candidate).unwrap())
                .unwrap()
                .abort()
                .unwrap()
                .fail_recovery()
                .unwrap();
            let recovery_error = operator
                .reconcile_node_runtime(&node)
                .expect_err("recovery healthy debe revalidar LKG antes de aceptarlo");
            assert!(recovery_error.contains("RUNTIME_RELEASE_PROFILE_UNSUPPORTED"));
            assert_eq!(
                releases.load_state().unwrap().promotion_status,
                "manual_intervention_required"
            );
            assert_eq!(intercept.start_count.load(Ordering::SeqCst), 0);
            assert_eq!(intercept.stop_count.load(Ordering::SeqCst), 0);
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn start_gate_acepta_release_people_futura_y_preserva_perfiles_legacy() {
        let root = std::env::temp_dir().join(format!(
            "actium-runtime-start-capability-future-{}",
            Uuid::new_v4()
        ));
        let nodes = root.join("nodes");
        let people_node = nodes.join("actium-lab-people-future");
        let people_payload = root.join("people-future");
        write_min_topology(&people_node, "people-future");
        add_people_to_min_topology(&people_node);
        fs::OpenOptions::new()
            .append(true)
            .open(people_node.join("node.env"))
            .unwrap()
            .write_all(
                b"ACTIUM_PROFILES=people\nACTIUM_REQUIRED_RUNTIME_FEATURES=people_runtime_v1\n",
            )
            .unwrap();
        test_people_payload(&people_payload, "0.8.0-next.1");
        let operator = RuntimeOperator::new(&nodes, &people_payload);
        let people_topology = load_topology(&people_node.join("state/runtime-topology.json")).unwrap();
        operator
            .require_runtime_start_capabilities(&people_node, &people_payload, &people_topology)
            .expect("release futura ligada puede iniciar People");

        let legacy_node = nodes.join("actium-lab-legacy-profile");
        write_min_topology(&legacy_node, "legacy-profile");
        let legacy_topology = load_topology(&legacy_node.join("state/runtime-topology.json")).unwrap();
        operator
            .require_runtime_start_capabilities(
                &legacy_node,
                &root.join("payload-legacy-sin-manifest"),
                &legacy_topology,
            )
            .expect("perfiles existentes no adquieren requisito schema3 retroactivo");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cache_people_inicial_queda_ligado_a_scope_y_digest_del_adpe() {
        let deployment_id = Uuid::new_v4().to_string();
        let organization_id = Uuid::new_v4().to_string();
        let site_id = Uuid::new_v4().to_string();
        let policy = serde_json::json!({
            "schema": 1,
            "status": "active",
            "organizationId": organization_id,
            "siteId": site_id,
            "policyRevision": 1,
            "validUntil": "2030-01-01T00:00:00.000Z",
            "runtimePlacement": "edge_local",
            "piiStorageMode": "local_only",
            "identityResolutionMode": "actium_index_plus_local_vault",
            "syncPolicy": "no_raw_pii_sync",
            "residencyPolicy": { "approvedRegions": [], "providerAllowlist": [] },
            "serviceCapabilities": ["people.resolve"]
        });
        let policy_sha = sha256_hex(canonical_json(&policy).unwrap().as_bytes());
        let cache = serde_json::json!({
            "schema": 1,
            "source": "actium_center_signed_bootstrap",
            "authority": {
                "transport": "signed_adpe_verified_by_node_manager",
                "desiredChecksum": "a".repeat(64),
            },
            "deploymentId": deployment_id,
            "desiredGeneration": 7,
            "policySha256": policy_sha,
            "policy": policy,
        });
        let mut config = BTreeMap::new();
        config.insert("ACTIUM_PROFILES".to_string(), "people".to_string());
        config.insert("ACTIUM_DEPLOYMENT_ID".to_string(), deployment_id);
        config.insert("ACTIUM_ORGANIZATION_ID".to_string(), organization_id);
        config.insert("ACTIUM_SITE_ID".to_string(), site_id);
        assert!(validate_initial_people_policy_cache(&cache.to_string(), &config).is_ok());

        let mut altered = cache;
        altered["policySha256"] = serde_json::Value::String("b".repeat(64));
        assert_eq!(
            validate_initial_people_policy_cache(&altered.to_string(), &config),
            Err("PEOPLE_POLICY_CACHE_DIGEST_MISMATCH".to_string())
        );
    }

    #[test]
    fn rechaza_nodo_fuera_de_raiz_y_canal_no_lab() {
        let root = std::env::temp_dir().join(format!("actium-runtime-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let outside = root.join("outside");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(
            outside.join(".actium-node-installation.json"),
            r#"{"managerChannel":"lab"}"#,
        )
        .unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        assert!(operator.execute(&outside, "status", None).is_err());

        let node = allowed.join("node");
        fs::create_dir_all(&node).unwrap();
        fs::write(
            node.join(".actium-node-installation.json"),
            r#"{"managerChannel":"stable"}"#,
        )
        .unwrap();
        assert!(operator.execute(&node, "status", None).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn supervisor_crea_solo_hijos_directos_y_persiste_allowlist() {
        let root = std::env::temp_dir().join(format!("actium-runtime-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        fs::create_dir_all(&allowed).unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        let node = operator
            .prepare_new_node_root(&allowed.join("actium-lab-node-01"))
            .expect("crea hijo directo");
        assert!(operator
            .prepare_new_node_root(&allowed.join("nested/node"))
            .is_err());
        fs::write(
            node.join(".actium-node-installation.json"),
            r#"{"managerChannel":"lab"}"#,
        )
        .unwrap();
        fs::write(
            node.join("node.env"),
            "ACTIUM_DATA_PLANE_PROJECT=actium-lab-node-01\nACTIUM_PROFILES=telemetry\nTELEMETRY_PORT=8090\n",
        )
        .unwrap();
        let request = ConfigurationWriteRequest {
            install_dir: node.to_string_lossy().into_owned(),
            env_updates: BTreeMap::from([("TELEMETRY_PORT".to_string(), "8190".to_string())]),
            connectivity_edge_enrollment_token: None,
            connectivity_internal_relay_token: None,
            radio_archive_host_path: None,
            prepare_rollback: true,
        };
        operator
            .persist_configuration(&request)
            .expect("persiste clave permitida");
        assert!(fs::read_to_string(node.join("node.env"))
            .unwrap()
            .contains("TELEMETRY_PORT=8190"));
        assert!(node.join("state/configuration-rollback/node.env").is_file());

        let mut rejected = request;
        rejected
            .env_updates
            .insert("ACTIUM_PROJECT_NAME".to_string(), "otro".to_string());
        assert!(operator.persist_configuration(&rejected).is_err());

        let mut inactive = rejected;
        inactive.env_updates = BTreeMap::from([("TURN_PORT".to_string(), "19999".to_string())]);
        let error = operator.persist_configuration(&inactive).unwrap_err();
        assert!(
            error.contains("inactiva") || error.contains("TURN_PORT"),
            "{error}"
        );
        assert!(!fs::read_to_string(node.join("node.env"))
            .unwrap()
            .contains("TURN_PORT=19999"));
        fs::write(
            node.join("node.env"),
            "ACTIUM_DATA_PLANE_PROJECT=actium-lab-node-01\nACTIUM_PROFILES=telemetry\nTELEMETRY_PORT=8190\nTURN_URLS=not-a-turn-url\nLIVEKIT_PUBLIC_URL=http://invalid\n",
        )
        .unwrap();
        let mut malformed = inactive;
        malformed.env_updates =
            BTreeMap::from([("TELEMETRY_PORT".to_string(), "8290".to_string())]);
        operator
            .persist_configuration(&malformed)
            .expect("TURN/LiveKit legado invalido no bloquea Telemetry activo");
        assert!(fs::read_to_string(node.join("node.env"))
            .unwrap()
            .contains("TELEMETRY_PORT=8290"));
        let _ = fs::remove_dir_all(root);
    }

    fn incomplete_ids() -> (String, String, String) {
        (
            "e0864698-6978-4481-bfb2-76df5d9032bf".to_string(),
            "7e207490-88fd-4e31-9684-d247475215ab".to_string(),
            format!(
                "actium-lab-resume-{}",
                &Uuid::new_v4().simple().to_string()[..8]
            ),
        )
    }

    fn write_incomplete_leftover(
        node: &std::path::Path,
        installation_id: &str,
        deployment_id: &str,
        project: &str,
        status: &str,
    ) {
        fs::create_dir_all(node.join("keys")).unwrap();
        fs::write(
            node.join(".actium-node-installation.json"),
            serde_json::json!({
                "managerChannel": "lab",
                "status": status,
                "installationId": installation_id,
                "deploymentId": deployment_id,
                "promotionStatus": "failed",
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            node.join("node.env"),
            format!(
                "ACTIUM_NODE_INSTALLATION_ID={installation_id}\n\
ACTIUM_HOST_INSTALLATION_ID=cccccccc-cccc-4ccc-8ccc-cccccccccccc\n\
ACTIUM_HOST_CODE=actium-host-cccccccc\n\
ACTIUM_HOST_DISPLAY_NAME=Actium Host\n\
ACTIUM_DEPLOYMENT_ID={deployment_id}\n\
ACTIUM_DEPLOYMENT_CODE={project}\n\
ACTIUM_PROFILES=site-core\n\
ACTIUM_PROJECT_NAME={project}\n\
ACTIUM_DATA_PLANE_PROJECT={project}\n"
            ),
        )
        .unwrap();
        fs::write(node.join("keys/actium-terminal-public.pem"), "terminal\n").unwrap();
        fs::write(node.join("keys/actium-operator-public.pem"), "operator\n").unwrap();
    }

    fn resume_request(
        node: &std::path::Path,
        version: &str,
        installation_id: &str,
        deployment_id: &str,
        project: &str,
        resume_incomplete: bool,
    ) -> CommissionNodeRequest {
        CommissionNodeRequest {
            install_dir: node.to_string_lossy().into_owned(),
            expected_release: version.to_string(),
            node_env: format!(
                "ACTIUM_NODE_INSTALLATION_ID={installation_id}\n\
ACTIUM_DEPLOYMENT_ID={deployment_id}\n\
ACTIUM_DEPLOYMENT_CODE={project}\n\
ACTIUM_PROFILES=site-core\n\
ACTIUM_PROJECT_NAME={project}\n\
ACTIUM_DATA_PLANE_PROJECT={project}\n"
            ),
            marker: serde_json::json!({
                "managerChannel": "lab",
                "status": "installing",
                "installationId": installation_id,
                "deploymentId": deployment_id,
            })
            .to_string(),
            terminal_public_key: "terminal\n".to_string(),
            operator_public_key: "operator\n".to_string(),
            site_runtime_public_key: None,
            initial_people_policy_cache: None,
            control_plane_ca_pem: None,
            connectivity_edge_enrollment_token: None,
            connectivity_internal_relay_token: None,
            connectivity_edge_control_url: None,
            enrollment_token: "adpe_test".to_string(),
            radio_archive_host_path: None,
            prepare_only: true,
            resume_incomplete,
        }
    }

    #[test]
    fn commissioning_fresco_sigue_rechazando_destino_existente() {
        let root = std::env::temp_dir().join(format!("actium-resume-fresh-{}", Uuid::new_v4()));
        let nodes = root.join("nodes");
        let payload = root.join("payload");
        let node = nodes.join("actium-lab-resume-01");
        let (installation_id, deployment_id, project) = incomplete_ids();
        fs::create_dir_all(&node).unwrap();
        test_payload(&payload, "0.8.0-lab.resume");
        write_incomplete_leftover(&node, &installation_id, &deployment_id, &project, "failed");
        let operator = RuntimeOperator::new(&nodes, &payload);
        let error = operator
            .commission_node(&resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                false,
            ))
            .expect_err("el commissioning inicial no puede adoptar un destino no vacio");
        assert!(
            error.contains("no esta vacio"),
            "rechazo inesperado: {error}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_incompleto_acepta_preparacion_cancelada_con_la_misma_identidad() {
        let root = std::env::temp_dir().join(format!("actium-resume-cancelled-{}", Uuid::new_v4()));
        let nodes = root.join("nodes");
        let payload = root.join("payload");
        let node = nodes.join("actium-lab-resume-cancelled");
        let (installation_id, deployment_id, project) = incomplete_ids();
        fs::create_dir_all(&node).unwrap();
        test_payload(&payload, "0.8.0-lab.resume");
        write_incomplete_leftover(&node, &installation_id, &deployment_id, &project, "cancelled");
        let operator = RuntimeOperator::new(&nodes, &payload);
        let accepted = operator.prepare_incomplete_commission_root(
            &node,
            &resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                true,
            ),
        );
        assert!(accepted.is_ok(), "una preparación cancelada debe poder reutilizarse: {accepted:?}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_incompleto_exige_mismo_deployment_e_installation_id() {
        let root = std::env::temp_dir().join(format!("actium-resume-id-{}", Uuid::new_v4()));
        let nodes = root.join("nodes");
        let payload = root.join("payload");
        let node = nodes.join("actium-lab-resume-01");
        let (installation_id, deployment_id, project) = incomplete_ids();
        fs::create_dir_all(&node).unwrap();
        test_payload(&payload, "0.8.0-lab.resume");
        write_incomplete_leftover(&node, &installation_id, &deployment_id, &project, "failed");
        let operator = RuntimeOperator::new(&nodes, &payload);
        let other_install = operator
            .commission_node(&resume_request(
                &node,
                "0.8.0-lab.resume",
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                &deployment_id,
                &project,
                true,
            ))
            .expect_err("otro installationId debe fallar cerrado");
        assert!(other_install.contains("installationId"), "{other_install}");
        let other_deploy = operator
            .commission_node(&resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                &project,
                true,
            ))
            .expect_err("otro deploymentId debe fallar cerrado");
        assert!(other_deploy.contains("deploymentId"), "{other_deploy}");
        let accepted = operator.prepare_incomplete_commission_root(
            &node,
            &resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                true,
            ),
        );
        assert!(
            accepted.is_ok(),
            "HOST distinto del node installationId no debe bloquear resume: {accepted:?}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_incompleto_acepta_marker_sin_node_env_en_disco() {
        let root = std::env::temp_dir().join(format!("actium-resume-no-env-{}", Uuid::new_v4()));
        let nodes = root.join("nodes");
        let payload = root.join("payload");
        let node = nodes.join("actium-lab-resume-no-env");
        let (installation_id, deployment_id, project) = incomplete_ids();
        fs::create_dir_all(&node).unwrap();
        test_payload(&payload, "0.8.0-lab.resume");
        fs::write(
            node.join(MARKER_FILE),
            serde_json::json!({
                "managerChannel": "lab",
                "status": "failed",
                "installationId": installation_id,
                "deploymentId": deployment_id,
                "projectName": project,
            })
            .to_string(),
        )
        .unwrap();
        fs::create_dir_all(node.join("keys")).unwrap();
        fs::write(node.join("keys/actium-terminal-public.pem"), "terminal\n").unwrap();
        fs::write(node.join("keys/actium-operator-public.pem"), "operator\n").unwrap();

        let operator = RuntimeOperator::new(&nodes, &payload);
        let accepted = operator.prepare_incomplete_commission_root(
            &node,
            &resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                true,
            ),
        );
        assert!(
            accepted.is_ok(),
            "La ausencia de node.env en disco no debe bloquear la recuperacion: {accepted:?}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn dos_nodos_reutilizan_la_misma_host_identity() {
        let root = std::env::temp_dir().join(format!("actium-two-hosts-{}", Uuid::new_v4()));
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let first = crate::reconcile_host_identity(
            &state,
            &BTreeMap::new(),
            crate::HostIdentityScope::Fresh,
        )
        .unwrap();
        let second = crate::reconcile_host_identity(
            &state,
            &BTreeMap::new(),
            crate::HostIdentityScope::Fresh,
        )
        .unwrap();
        assert_eq!(first.host_installation_id, second.host_installation_id);
        assert_eq!(first.host_code, second.host_code);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_incompleto_falla_cerrado_si_hay_compose_o_release_activa() {
        let root = std::env::temp_dir().join(format!("actium-resume-ops-{}", Uuid::new_v4()));
        let nodes = root.join("nodes");
        let payload = root.join("payload");
        let node = nodes.join("actium-lab-resume-01");
        let (installation_id, deployment_id, project) = incomplete_ids();
        fs::create_dir_all(&node).unwrap();
        test_payload(&payload, "0.8.0-lab.resume");
        write_incomplete_leftover(&node, &installation_id, &deployment_id, &project, "failed");
        fs::write(node.join("compose.yml"), "services: {}\n").unwrap();
        let operator = RuntimeOperator::new(&nodes, &payload);
        let compose_error = operator
            .commission_node(&resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                true,
            ))
            .expect_err("Compose operativo bloquea el resume");
        assert!(compose_error.contains("Compose"), "{compose_error}");
        fs::remove_file(node.join("compose.yml")).unwrap();
        fs::create_dir_all(node.join("state")).unwrap();
        fs::write(
            node.join("state/release-state.json"),
            serde_json::json!({
                "schema": 2,
                "revision": 1,
                "activeRelease": {
                    "releaseId": "active",
                    "releaseVersion": "0.8.0-lab.resume",
                    "releaseDigest": "abc",
                    "payloadSchema": 3,
                    "relativePath": "releases/active"
                },
                "previousRelease": null,
                "promotionStatus": "active",
                "lastSuccessfulRelease": null,
                "lastFailedRelease": null
            })
            .to_string(),
        )
        .unwrap();
        let active_error = operator
            .commission_node(&resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                true,
            ))
            .expect_err("release activa bloquea el resume");
        assert!(active_error.contains("release activa"), "{active_error}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_acepta_leftover_pre_topology_con_storage_parcial() {
        let root = std::env::temp_dir().join(format!("actium-resume-partial-{}", Uuid::new_v4()));
        let nodes = root.join("nodes");
        let payload = root.join("payload");
        let node = nodes.join("actium-lab-resume-01");
        let (installation_id, deployment_id, project) = incomplete_ids();
        fs::create_dir_all(node.join("persistent/runtime-units/site-core-retry/site-core"))
            .unwrap();
        test_payload(&payload, "0.8.0-lab.resume");
        write_incomplete_leftover(&node, &installation_id, &deployment_id, &project, "failed");
        let operator = RuntimeOperator::new(&nodes, &payload);
        let accepted = operator.prepare_incomplete_commission_root(
            &node,
            &resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                true,
            ),
        );
        let accepted = accepted.expect("leftover pre-topology es reanudable");
        assert_eq!(
            accepted.file_name(),
            node.file_name(),
            "el resume debe reutilizar el mismo directorio: {accepted:?}"
        );
        assert!(!node.join("compose.yml").is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn first_install_pre_topology_deja_leftover_reanudable_con_mismo_installation_id() {
        let _lock = FAULT_ENV.lock().unwrap();
        let root = std::env::temp_dir().join(format!("actium-resume-fault-{}", Uuid::new_v4()));
        let nodes = root.join("nodes");
        let payload = root.join("payload");
        let node = nodes.join("actium-lab-resume-01");
        let (installation_id, deployment_id, project) = incomplete_ids();
        fs::create_dir_all(&nodes).unwrap();
        test_payload(&payload, "0.8.0-lab.resume");
        let operator = RuntimeOperator::new(&nodes, &payload);
        std::env::set_var("ACTIUM_FAULT_INJECTION_STAGE", "commission.topology");
        let failure = operator
            .commission_node(&resume_request(
                &node,
                "0.8.0-lab.resume",
                &installation_id,
                &deployment_id,
                &project,
                false,
            ))
            .expect_err("el first install debe abortar antes de topologia");
        std::env::remove_var("ACTIUM_FAULT_INJECTION_STAGE");
        assert!(
            failure.contains("FIRST_INSTALL_ABORTED") || failure.contains("FAULT_INJECTED"),
            "{failure}"
        );
        assert!(node.join("node.env").is_file());
        assert!(!node.join("compose.yml").is_file());
        let marker: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(node.join(".actium-node-installation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            marker.get("status").and_then(|value| value.as_str()),
            Some("failed")
        );
        assert_eq!(
            marker
                .get("installationId")
                .and_then(|value| value.as_str()),
            Some(installation_id.as_str())
        );
        let leftover_env =
            super::parse_env_document(&fs::read_to_string(node.join("node.env")).unwrap());
        let leftover_host = leftover_env
            .get("ACTIUM_HOST_INSTALLATION_ID")
            .cloned()
            .unwrap_or_default();
        let leftover_node = leftover_env
            .get("ACTIUM_NODE_INSTALLATION_ID")
            .cloned()
            .unwrap_or_default();
        assert_eq!(leftover_node, installation_id);
        assert!(!leftover_host.is_empty());
        assert_ne!(leftover_host, leftover_node);
        assert!(leftover_env
            .get("ACTIUM_HOST_CODE")
            .is_some_and(|value| value.starts_with("actium-host-")));
        let restarted = RuntimeOperator::new(&nodes, &payload);
        restarted
            .prepare_incomplete_commission_root(
                &node,
                &resume_request(
                    &node,
                    "0.8.0-lab.resume",
                    &installation_id,
                    &deployment_id,
                    &project,
                    true,
                ),
            )
            .expect("Manager restart debe reconocer el leftover como reanudable");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn red_fabric_existente_debe_ser_interna_y_tener_owner() {
        let fabric_id = "11111111-1111-4111-8111-111111111111";
        let valid =
            format!(r#"[{{"Internal":true,"Labels":{{"com.actium.fabric-id":"{fabric_id}"}}}}]"#);
        assert!(validate_fabric_network_inspect(&valid, fabric_id).is_ok());
        assert!(validate_fabric_network_inspect(
            r#"[{"Internal":false,"Labels":{"com.actium.fabric-id":"11111111-1111-4111-8111-111111111111"}}]"#,
            fabric_id,
        )
        .is_err());
        assert!(validate_fabric_network_inspect(
            r#"[{"Internal":true,"Labels":{"com.actium.fabric-id":"22222222-2222-4222-8222-222222222222"}}]"#,
            fabric_id,
        )
        .is_err());
    }

    #[test]
    fn red_deployment_existente_debe_ser_interna_y_tener_owner() {
        let deployment_id = "33333333-3333-4333-8333-333333333333";
        let valid = format!(
            r#"[{{"Internal":true,"Labels":{{"com.actium.deployment-id":"{deployment_id}"}}}}]"#
        );
        assert!(validate_deployment_network_inspect(&valid, deployment_id).is_ok());
        assert!(validate_deployment_network_inspect(
            r#"[{"Internal":false,"Labels":{"com.actium.deployment-id":"33333333-3333-4333-8333-333333333333"}}]"#,
            deployment_id,
        )
        .is_err());
        assert!(validate_deployment_network_inspect(
            r#"[{"Internal":true,"Labels":{"com.actium.deployment-id":"44444444-4444-4444-8444-444444444444"}}]"#,
            deployment_id,
        )
        .is_err());
    }

    #[test]
    fn atestacion_no_promueve_running_sin_health_a_healthy() {
        let running = attested_container(serde_json::json!({
            "Id": "a".repeat(64),
            "Image": format!("sha256:{}", "b".repeat(64)),
            "Name": "/runtime-api",
            "Config": {
                "Image": "actium/runtime:test",
                "Labels": { "com.docker.compose.service": "runtime-api" }
            },
            "State": { "Status": "running", "ExitCode": 0 }
        }))
        .unwrap();
        assert_eq!(running.health, "degraded");
        assert_eq!(running.lifecycle_state, "alive");

        let ready = attested_container(serde_json::json!({
            "Id": "c".repeat(64),
            "Image": format!("sha256:{}", "d".repeat(64)),
            "Name": "/runtime-api",
            "Config": {
                "Image": "actium/runtime:test",
                "Labels": { "com.docker.compose.service": "runtime-api" }
            },
            "State": { "Status": "running", "ExitCode": 0, "Health": { "Status": "healthy" } }
        }))
        .unwrap();
        assert_eq!(ready.health, "healthy");
        assert_eq!(ready.lifecycle_state, "ready");
    }

    #[test]
    fn atestacion_materializa_migrador_one_shot_sin_daemon_sintetico() {
        let finished_at = "2026-08-16T00:00:07Z";
        let migration = attested_container(serde_json::json!({
            "Id": "e".repeat(64),
            "Image": format!("sha256:{}", "f".repeat(64)),
            "Name": "/actium-telemetry-telemetry-migrations-1",
            "Config": {
                "Image": "actium/data-plane-telemetry-migrations:0.8.0",
                "Labels": {
                    "com.docker.compose.service": "telemetry-migrations",
                    "com.actium.workload": "schema_migrator",
                    "com.actium.migration-profile": "telemetry"
                }
            },
            "State": {
                "Status": "exited",
                "ExitCode": 0,
                "StartedAt": "2026-08-16T00:00:01Z",
                "FinishedAt": finished_at
            }
        }))
        .unwrap();

        assert_eq!(migration.workload_code.as_deref(), Some("schema_migrator"));
        assert_eq!(migration.migration_profile.as_deref(), Some("telemetry"));
        assert_eq!(migration.exit_code, Some(0));
        assert_eq!(migration.finished_at.as_deref(), Some(finished_at));
        assert_eq!(migration.health, "healthy");
        assert_eq!(migration.lifecycle_state, "ready");
    }

    #[test]
    fn reboot_aborta_primera_promocion_interrumpida_sin_lkg() {
        let root = std::env::temp_dir().join(format!("actium-reboot-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-reboot");
        let payload = root.join("payload");
        fs::create_dir_all(&node).unwrap();
        fs::write(
            node.join(".actium-node-installation.json"),
            r#"{"managerChannel":"lab","status":"installing"}"#,
        )
        .unwrap();
        test_payload(&payload, "0.8.0-lab.reboot");
        let releases = ReleaseManager::new(&node);
        releases
            .begin_promotion(releases.prepare(&payload).unwrap())
            .expect("simula crash posterior a promote")
            .simulate_process_crash();
        assert_eq!(releases.load_state().unwrap().promotion_status, "promoting");

        let operator = RuntimeOperator::new(&allowed, &payload);
        let message = operator
            .recover_after_reboot(&node)
            .expect("recovery")
            .expect("mensaje");
        let recovered = releases.load_state().unwrap();
        assert!(message.contains("sin candidato activo"));
        assert!(recovered.active_release.is_none());
        assert!(recovered.last_failed_release.is_some());
        assert_eq!(recovered.promotion_status, "failed");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn fault_injection_cierra_first_install_upgrade_y_fabric() {
        let _lock = FAULT_ENV.lock().unwrap();
        let stages = [
            "commission.before_topology",
            "commission.topology",
            "commission.fabric",
            "commission.before_runtime_start",
            "runtime.site_core_started",
            "commission.final_health",
            "update.before_topology",
            "update.topology",
            "update.fabric",
            "update.before_runtime_start",
            "update.final_health",
            "fabric.before_start",
            "fabric.provision",
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            for has_lkg in [false, true] {
                let root = std::env::temp_dir().join(format!(
                    "actium-promotion-fault-{index}-{has_lkg}-{}",
                    Uuid::new_v4()
                ));
                let first = root.join("first");
                let candidate = root.join("candidate");
                test_payload(&first, "0.8.0-lab.lkg");
                test_payload(&candidate, "0.8.0-lab.candidate");
                let manager = ReleaseManager::new(root.join("release-root"));
                if has_lkg {
                    manager
                        .begin_promotion(manager.prepare(&first).unwrap())
                        .unwrap()
                        .commit()
                        .unwrap();
                }
                std::env::set_var("ACTIUM_FAULT_INJECTION_STAGE", stage);
                let transaction = manager
                    .begin_promotion(manager.prepare(&candidate).unwrap())
                    .unwrap();
                let error = promotion_checkpoint(stage).expect_err("fault injected");
                assert_eq!(error, format!("FAULT_INJECTED:{stage}"));
                let aborted = transaction.abort().unwrap();
                std::env::remove_var("ACTIUM_FAULT_INJECTION_STAGE");
                if has_lkg {
                    assert!(aborted.recovery_required, "stage={stage}");
                    assert_eq!(aborted.state.promotion_status, "recovery_pending");
                    assert_eq!(
                        aborted
                            .state
                            .active_release
                            .as_ref()
                            .unwrap()
                            .release_version,
                        "0.8.0-lab.lkg"
                    );
                    assert_eq!(
                        aborted.complete_recovery().unwrap().promotion_status,
                        "rolled_back"
                    );
                } else {
                    assert!(!aborted.recovery_required, "stage={stage}");
                    assert!(aborted.state.active_release.is_none());
                    assert_eq!(aborted.state.promotion_status, "failed");
                }
                let _ = fs::remove_dir_all(root);
            }
        }
    }

    struct ReconcileInterceptGuard;

    impl Drop for ReconcileInterceptGuard {
        fn drop(&mut self) {
            RECONCILE_TEST_INTERCEPT.with(|cell| *cell.borrow_mut() = None);
        }
    }

    fn with_reconcile_intercept<T>(
        healthy: bool,
        become_healthy_after_start: bool,
        callback: impl FnOnce(&ReconcileTestIntercept) -> T,
    ) -> T {
        let intercept = ReconcileTestIntercept {
            healthy,
            become_healthy_after_start,
            start_count: Arc::new(AtomicU64::new(0)),
            stop_count: Arc::new(AtomicU64::new(0)),
            exercise_fabric: false,
            fabric_modes: Arc::new(Mutex::new(Vec::new())),
            fabric_promotions: Arc::new(AtomicU64::new(0)),
            node_holds: Arc::new(Mutex::new(HashMap::new())),
            finished_nodes: Arc::new(Mutex::new(Vec::new())),
            finished_signal: Arc::new(Condvar::new()),
        };
        RECONCILE_TEST_INTERCEPT.with(|cell| *cell.borrow_mut() = Some(intercept.clone()));
        let _guard = ReconcileInterceptGuard;
        callback(&intercept)
    }

    fn write_lab_marker(node: &Path, status: &str) {
        fs::create_dir_all(node).unwrap();
        fs::write(
            node.join(".actium-node-installation.json"),
            serde_json::json!({
                "managerChannel": "lab",
                "status": status,
                "updatedAtUnixSeconds": 1
            })
            .to_string(),
        )
        .unwrap();
    }

    fn promote_two_releases(node: &Path, first: &Path, second: &Path) -> ReleaseManager {
        let releases = ReleaseManager::new(node);
        releases
            .begin_promotion(releases.prepare(first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let aborted = releases
            .begin_promotion(releases.prepare(second).unwrap())
            .unwrap()
            .abort()
            .unwrap();
        aborted.fail_recovery().unwrap();
        releases
    }

    #[test]
    fn runtime_intent_running_y_healthy_no_recrea() {
        let root = std::env::temp_dir().join(format!("actium-reconcile-healthy-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-healthy");
        let first = root.join("lab28");
        let second = root.join("lab29");
        write_lab_marker(&node, "failed");
        write_min_topology(&node, "healthy");
        test_payload(&first, "0.8.0-lab.28");
        test_payload(&second, "0.8.0-lab.29");
        let releases = ReleaseManager::new(&node);
        releases
            .begin_promotion(releases.prepare(&first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(true, false, |intercept| {
            let report = operator.reconcile_node_runtime(&node).expect("reconcile");
            assert!(!report.skipped_busy);
            assert_eq!(intercept.start_count.load(Ordering::SeqCst), 0);
            assert!(report.message.contains("sin recrear"));
            let intent = serde_json::from_str::<RuntimeIntent>(
                &fs::read_to_string(node.join("state/runtime-intent.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(intent.desired_state, RuntimeDesiredState::Running);
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_intent_running_sin_contenedores_inicia() {
        let root = std::env::temp_dir().join(format!("actium-reconcile-start-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-start");
        let first = root.join("lab28");
        write_lab_marker(&node, "failed");
        write_min_topology(&node, "start");
        test_payload(&first, "0.8.0-lab.28");
        let releases = ReleaseManager::new(&node);
        releases
            .begin_promotion(releases.prepare(&first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(false, true, |intercept| {
            let report = operator.reconcile_node_runtime(&node).expect("reconcile");
            assert!(intercept.start_count.load(Ordering::SeqCst) >= 1);
            assert!(report.message.contains("iniciado"));
            let marker = serde_json::from_str::<serde_json::Value>(
                &fs::read_to_string(node.join(".actium-node-installation.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(marker.get("status").and_then(serde_json::Value::as_str), Some("running"));
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_intent_stopped_no_inicia() {
        let root = std::env::temp_dir().join(format!("actium-reconcile-stop-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-stopped");
        let first = root.join("lab28");
        write_lab_marker(&node, "stopped");
        test_payload(&first, "0.8.0-lab.28");
        let releases = ReleaseManager::new(&node);
        releases
            .begin_promotion(releases.prepare(&first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(false, true, |intercept| {
            let report = operator.reconcile_node_runtime(&node).expect("reconcile");
            assert_eq!(intercept.start_count.load(Ordering::SeqCst), 0);
            assert!(intercept.stop_count.load(Ordering::SeqCst) >= 1);
            assert!(report.message.contains("stopped"));
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn manual_intervention_con_lkg_healthy_completa_recovery() {
        let root = std::env::temp_dir().join(format!("actium-reconcile-lkg-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-lkg");
        let first = root.join("lab28");
        let second = root.join("lab29");
        write_lab_marker(&node, "failed");
        write_min_topology(&node, "lkg");
        test_payload(&first, "0.8.0-lab.28");
        test_payload(&second, "0.8.0-lab.29");
        let releases = promote_two_releases(&node, &first, &second);
        let before = releases.load_state().unwrap();
        assert_eq!(before.promotion_status, "manual_intervention_required");
        assert_eq!(
            before.active_release.as_ref().unwrap().release_version,
            "0.8.0-lab.28"
        );
        assert_eq!(
            before.last_failed_release.as_ref().unwrap().release_version,
            "0.8.0-lab.29"
        );
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(true, false, |intercept| {
            operator.reconcile_node_runtime(&node).expect("reconcile");
            assert_eq!(intercept.start_count.load(Ordering::SeqCst), 0);
        });
        let after = releases.load_state().unwrap();
        assert_eq!(after.promotion_status, "rolled_back");
        assert_eq!(
            after.active_release.as_ref().unwrap().release_version,
            "0.8.0-lab.28"
        );
        assert_eq!(
            after.last_failed_release.as_ref().unwrap().release_version,
            "0.8.0-lab.29"
        );
        let marker = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(node.join(".actium-node-installation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(marker.get("status").and_then(serde_json::Value::as_str), Some("running"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn promocion_interrumpida_recupera_lkg() {
        let root = std::env::temp_dir().join(format!("actium-reconcile-promo-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-promo");
        let first = root.join("lab28");
        let second = root.join("lab29");
        write_lab_marker(&node, "installing");
        write_min_topology(&node, "promo");
        test_payload(&first, "0.8.0-lab.28");
        test_payload(&second, "0.8.0-lab.29");
        let releases = ReleaseManager::new(&node);
        releases
            .begin_promotion(releases.prepare(&first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        releases
            .begin_promotion(releases.prepare(&second).unwrap())
            .expect("promoting")
            .simulate_process_crash();
        assert_eq!(releases.load_state().unwrap().promotion_status, "promoting");
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(true, false, |_| {
            operator.reconcile_node_runtime(&node).expect("reconcile");
        });
        let after = releases.load_state().unwrap();
        assert_eq!(after.promotion_status, "rolled_back");
        assert_eq!(
            after.active_release.as_ref().unwrap().release_version,
            "0.8.0-lab.28"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mutation_busy_omite_nodo() {
        let root = std::env::temp_dir().join(format!("actium-reconcile-busy-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-busy");
        let first = root.join("lab28");
        write_lab_marker(&node, "running");
        test_payload(&first, "0.8.0-lab.28");
        let releases = ReleaseManager::new(&node);
        releases
            .begin_promotion(releases.prepare(&first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let _guard = releases.lock_mutation().unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        let report = operator.reconcile_node_runtime(&node).expect("skip busy");
        assert!(report.skipped_busy);
        assert!(report.message.contains("omitida"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fallo_de_un_nodo_no_bloquea_a_otros() {
        let root = std::env::temp_dir().join(format!("actium-reconcile-multi-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let broken = allowed.join("actium-lab-broken");
        let healthy = allowed.join("actium-lab-ok");
        let first = root.join("lab28");
        write_lab_marker(&broken, "failed");
        write_lab_marker(&healthy, "failed");
        write_min_topology(&healthy, "ok");
        test_payload(&first, "0.8.0-lab.28");
        fs::create_dir_all(broken.join("state")).unwrap();
        fs::write(broken.join("state/release-state.json"), "{not-json").unwrap();
        let releases = ReleaseManager::new(&healthy);
        releases
            .begin_promotion(releases.prepare(&first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(true, false, |_| {
            let messages = operator
                .reconcile_authorized_runtimes()
                .expect("multi-node");
            assert!(
                messages.iter().any(|message| message.contains("broken") || message.contains("invalido") || message.contains("no disponible")),
                "{messages:?}"
            );
            let marker = serde_json::from_str::<serde_json::Value>(
                &fs::read_to_string(healthy.join(".actium-node-installation.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                marker.get("status").and_then(serde_json::Value::as_str),
                Some("running")
            );
        });
        let _ = fs::remove_dir_all(root);
    }

    fn default_fabric() -> FabricIdentity {
        FabricIdentity {
            fabric_id: "11111111-1111-4111-8111-111111111111".to_string(),
            compose_project: "actium-lab-fabric-01".to_string(),
            network_name: "actium-lab-fabric-01".to_string(),
            host_id: None,
        }
    }

    fn write_min_topology(node: &Path, deployment_code: &str) {
        fs::create_dir_all(node.join("state")).unwrap();
        let topology = RuntimeTopology {
            schema: 3,
            host_installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_string(),
            host_id: None,
            deployment_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_string(),
            deployment_code: deployment_code.to_string(),
            deployment_network_name: format!("actium-lab-{deployment_code}-net"),
            fabric: default_fabric(),
            units: vec![RuntimeUnit {
                runtime_unit_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_string(),
                capability: "agent".to_string(),
                compose_project: format!("actium-lab-{deployment_code}"),
                compose_file: "compose.agent.yml".to_string(),
                depends_on: Vec::new(),
                startup_cohort: RuntimeStartupCohort::Bootstrap,
                startup_gate: RuntimeStartupGate::AgentReporting,
                binding: RuntimeUnitBinding {
                    secrets_directory: "secrets".to_string(),
                    database_role: None,
                    database_schema: None,
                    nats_account: None,
                    nats_user: None,
                    nats_subject_prefix: None,
                    storage_buckets: Vec::new(),
                },
                resources: RuntimeUnitResourceBudget {
                    cpus: "0.25".to_string(),
                    memory_limit: "128m".to_string(),
                    memory_reservation: "64m".to_string(),
                    pids_limit: 64,
                    log_max_size: "1m".to_string(),
                    log_max_files: 1,
                },
            }],
        };
        fs::write(
            node.join("state/runtime-topology.json"),
            serde_json::to_vec_pretty(&topology).unwrap(),
        )
        .unwrap();
        fs::write(
            node.join("node.env"),
            format!(
                "ACTIUM_DATA_PLANE_PROJECT=actium-lab-{deployment_code}\nACTIUM_USE_PUBLISHED_IMAGES=true\n"
            ),
        )
        .unwrap();
    }

    fn add_people_to_min_topology(node: &Path) {
        let path = node.join("state/runtime-topology.json");
        let mut topology = load_topology(&path).unwrap();
        let mut people = topology.units[0].clone();
        people.runtime_unit_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".to_string();
        people.capability = "people".to_string();
        people.compose_project = format!("{}-people", people.compose_project);
        people.compose_file = "compose.people.yml".to_string();
        people.startup_cohort = RuntimeStartupCohort::Runtime;
        people.startup_gate = RuntimeStartupGate::SteadyReady;
        topology.units.push(people);
        fs::write(path, serde_json::to_vec_pretty(&topology).unwrap()).unwrap();
    }

    fn seed_fabric_release(root: &Path, payload: &Path) -> PathBuf {
        let fabric_root = root
            .join("fabrics")
            .join("11111111-1111-4111-8111-111111111111");
        fs::create_dir_all(&fabric_root).unwrap();
        let releases = ReleaseManager::new(&fabric_root);
        releases
            .begin_promotion(releases.prepare(payload).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        fabric_root
    }

    fn with_fabric_intercept<T>(callback: impl FnOnce(&ReconcileTestIntercept) -> T) -> T {
        with_reconcile_intercept(false, true, |intercept| {
            let mut live = intercept.clone();
            live.exercise_fabric = true;
            RECONCILE_TEST_INTERCEPT.with(|cell| *cell.borrow_mut() = Some(live.clone()));
            callback(&live)
        })
    }

    #[test]
    fn reconciler_no_promueve_fabric_cuando_el_payload_difiere() {
        let root = std::env::temp_dir().join(format!("actium-fabric-no-update-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-site");
        let fabric_a = root.join("lab29");
        let payload_b = root.join("lab30");
        write_lab_marker(&node, "failed");
        write_min_topology(&node, "site");
        test_payload(&fabric_a, "0.8.0-lab.29");
        test_payload(&payload_b, "0.8.0-lab.30");
        let node_releases = ReleaseManager::new(&node);
        node_releases
            .begin_promotion(node_releases.prepare(&fabric_a).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let fabric_root = seed_fabric_release(&root, &fabric_a);
        let operator = RuntimeOperator::new(&allowed, &payload_b);
        with_fabric_intercept(|intercept| {
            operator
                .ensure_fabric(
                    &node,
                    &load_topology(&node.join("state/runtime-topology.json")).unwrap(),
                    FabricEnsureMode::ActiveReleaseOnly,
                )
                .unwrap();
            operator.reconcile_node_runtime(&node).unwrap();
            assert_eq!(intercept.fabric_promotions.load(Ordering::SeqCst), 0);
            assert!(intercept
                .fabric_modes
                .lock()
                .unwrap()
                .iter()
                .all(|mode| *mode == FabricEnsureMode::ActiveReleaseOnly));
        });
        let fabric_state = ReleaseManager::new(&fabric_root).load_state().unwrap();
        assert_eq!(
            fabric_state
                .active_release
                .as_ref()
                .unwrap()
                .release_version,
            "0.8.0-lab.29"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn restart_de_nodo_no_promueve_fabric() {
        let root = std::env::temp_dir().join(format!("actium-fabric-restart-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-restart");
        let fabric_a = root.join("lab29");
        let payload_b = root.join("lab30");
        write_lab_marker(&node, "running");
        write_min_topology(&node, "restart");
        test_payload(&fabric_a, "0.8.0-lab.29");
        test_payload(&payload_b, "0.8.0-lab.30");
        let node_releases = ReleaseManager::new(&node);
        node_releases
            .begin_promotion(node_releases.prepare(&fabric_a).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let fabric_root = seed_fabric_release(&root, &fabric_a);
        let operator = RuntimeOperator::new(&allowed, &payload_b);
        with_fabric_intercept(|intercept| {
            let _ = operator.execute(&node, "restart", None);
            assert_eq!(intercept.fabric_promotions.load(Ordering::SeqCst), 0);
            assert!(intercept
                .fabric_modes
                .lock()
                .unwrap()
                .contains(&FabricEnsureMode::ActiveReleaseOnly));
        });
        assert_eq!(
            ReleaseManager::new(&fabric_root)
                .load_state()
                .unwrap()
                .active_release
                .unwrap()
                .release_version,
            "0.8.0-lab.29"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_unit_restart_no_promueve_fabric() {
        let root = std::env::temp_dir().join(format!("actium-fabric-unit-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-unit");
        let fabric_a = root.join("lab29");
        let payload_b = root.join("lab30");
        write_lab_marker(&node, "running");
        write_min_topology(&node, "unit");
        test_payload(&fabric_a, "0.8.0-lab.29");
        test_payload(&payload_b, "0.8.0-lab.30");
        ReleaseManager::new(&node)
            .begin_promotion(ReleaseManager::new(&node).prepare(&fabric_a).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let fabric_root = seed_fabric_release(&root, &fabric_a);
        let operator = RuntimeOperator::new(&allowed, &payload_b);
        with_fabric_intercept(|intercept| {
            let _ = operator.execute_runtime_unit(&RuntimeUnitActionRequest {
                install_dir: node.to_string_lossy().into_owned(),
                runtime_unit_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_string(),
                action: "restart".to_string(),
            });
            assert_eq!(intercept.fabric_promotions.load(Ordering::SeqCst), 0);
            assert!(intercept
                .fabric_modes
                .lock()
                .unwrap()
                .contains(&FabricEnsureMode::ActiveReleaseOnly));
        });
        assert_eq!(
            ReleaseManager::new(&fabric_root)
                .load_state()
                .unwrap()
                .active_release
                .unwrap()
                .release_version,
            "0.8.0-lab.29"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn promocion_explicita_de_fabric_sigue_disponible() {
        let root = std::env::temp_dir().join(format!("actium-fabric-update-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-update");
        let fabric_a = root.join("lab29");
        let payload_b = root.join("lab30");
        write_lab_marker(&node, "running");
        write_min_topology(&node, "update");
        test_payload(&fabric_a, "0.8.0-lab.29");
        test_payload(&payload_b, "0.8.0-lab.30");
        ReleaseManager::new(&node)
            .begin_promotion(ReleaseManager::new(&node).prepare(&fabric_a).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let fabric_root = seed_fabric_release(&root, &fabric_a);
        let operator = RuntimeOperator::new(&allowed, &payload_b);
        with_fabric_intercept(|intercept| {
            operator
                .ensure_fabric(
                    &node,
                    &load_topology(&node.join("state/runtime-topology.json")).unwrap(),
                    FabricEnsureMode::AllowPayloadPromotion,
                )
                .unwrap();
            assert!(intercept.fabric_promotions.load(Ordering::SeqCst) >= 1);
            assert!(intercept
                .fabric_modes
                .lock()
                .unwrap()
                .contains(&FabricEnsureMode::AllowPayloadPromotion));
        });
        assert_eq!(
            ReleaseManager::new(&fabric_root)
                .load_state()
                .unwrap()
                .active_release
                .unwrap()
                .release_version,
            "0.8.0-lab.30"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fabric_sin_active_no_adopta_payload_en_recovery() {
        let root = std::env::temp_dir().join(format!("actium-fabric-missing-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node = allowed.join("actium-lab-missing");
        let payload_b = root.join("lab30");
        write_lab_marker(&node, "failed");
        write_min_topology(&node, "missing");
        test_payload(&payload_b, "0.8.0-lab.30");
        fs::create_dir_all(
            root.join("fabrics")
                .join("11111111-1111-4111-8111-111111111111"),
        )
        .unwrap();
        let operator = RuntimeOperator::new(&allowed, &payload_b);
        with_fabric_intercept(|_| {
            let error = operator
                .ensure_fabric(
                    &node,
                    &load_topology(&node.join("state/runtime-topology.json")).unwrap(),
                    FabricEnsureMode::ActiveReleaseOnly,
                )
                .unwrap_err();
            assert_eq!(error, "FABRIC_ACTIVE_RELEASE_REQUIRED");
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reconciler_aisla_temporalmente_un_nodo_lento() {
        let root = std::env::temp_dir().join(format!("actium-parallel-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let blocked = allowed.join("actium-lab-blocked");
        let healthy = allowed.join("actium-lab-ok");
        let first = root.join("lab28");
        write_lab_marker(&blocked, "failed");
        write_lab_marker(&healthy, "failed");
        test_payload(&first, "0.8.0-lab.28");
        for node in [&blocked, &healthy] {
            ReleaseManager::new(node)
                .begin_promotion(ReleaseManager::new(node).prepare(&first).unwrap())
                .unwrap()
                .commit()
                .unwrap();
        }
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(true, false, |intercept| {
            let hold = Arc::new(NodeReconcileHold {
                released: Mutex::new(false),
                cvar: Condvar::new(),
                entered: AtomicBool::new(false),
            });
            intercept
                .node_holds
                .lock()
                .unwrap()
                .insert("actium-lab-blocked".to_string(), hold.clone());
            let worker_intercept = intercept.clone();
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    RECONCILE_TEST_INTERCEPT.with(|cell| {
                        *cell.borrow_mut() = Some(worker_intercept);
                    });
                    operator
                        .reconcile_authorized_runtimes_bounded(2)
                        .expect("parallel")
                });
                let started = std::time::Instant::now();
                loop {
                    let finished = intercept.finished_nodes.lock().unwrap();
                    if finished.iter().any(|name| name == "actium-lab-ok") {
                        assert!(
                            !finished.iter().any(|name| name == "actium-lab-blocked"),
                            "Node B debe terminar antes de liberar A: {finished:?}"
                        );
                        break;
                    }
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(3),
                        "Node B no reconcilio mientras A estaba bloqueado: {finished:?}"
                    );
                    let _ = intercept
                        .finished_signal
                        .wait_timeout(finished, std::time::Duration::from_millis(50))
                        .expect("wait");
                }
                assert!(hold.entered.load(Ordering::SeqCst));
                *hold.released.lock().unwrap() = true;
                hold.cvar.notify_all();
                worker.join().unwrap();
            });
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mutation_busy_en_un_nodo_no_impide_al_otro() {
        let root = std::env::temp_dir().join(format!("actium-busy-parallel-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let busy = allowed.join("actium-lab-busy");
        let ok = allowed.join("actium-lab-free");
        let first = root.join("lab28");
        write_lab_marker(&busy, "failed");
        write_lab_marker(&ok, "failed");
        write_min_topology(&ok, "free");
        test_payload(&first, "0.8.0-lab.28");
        for node in [&busy, &ok] {
            ReleaseManager::new(node)
                .begin_promotion(ReleaseManager::new(node).prepare(&first).unwrap())
                .unwrap()
                .commit()
                .unwrap();
        }
        let _guard = ReleaseManager::new(&busy).lock_mutation().unwrap();
        let operator = RuntimeOperator::new(&allowed, root.join("payload"));
        with_reconcile_intercept(true, false, |_| {
            let messages = operator
                .reconcile_authorized_runtimes_bounded(2)
                .unwrap();
            assert!(messages.iter().any(|message| message.contains("busy") && message.contains("omitida")));
            let marker = serde_json::from_str::<serde_json::Value>(
                &fs::read_to_string(ok.join(".actium-node-installation.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                marker.get("status").and_then(serde_json::Value::as_str),
                Some("running")
            );
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn dos_nodos_comparten_fabric_sin_deadlock() {
        let root = std::env::temp_dir().join(format!("actium-shared-fabric-{}", Uuid::new_v4()));
        let allowed = root.join("nodes");
        let node_a = allowed.join("actium-lab-a");
        let node_b = allowed.join("actium-lab-b");
        let fabric_a = root.join("lab29");
        write_lab_marker(&node_a, "failed");
        write_lab_marker(&node_b, "failed");
        write_min_topology(&node_a, "a");
        write_min_topology(&node_b, "b");
        test_payload(&fabric_a, "0.8.0-lab.29");
        for node in [&node_a, &node_b] {
            ReleaseManager::new(node)
                .begin_promotion(ReleaseManager::new(node).prepare(&fabric_a).unwrap())
                .unwrap()
                .commit()
                .unwrap();
        }
        seed_fabric_release(&root, &fabric_a);
        let operator = RuntimeOperator::new(&allowed, &fabric_a);
        with_fabric_intercept(|_| {
            operator
                .reconcile_authorized_runtimes_bounded(2)
                .expect("shared fabric");
        });
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn run_logged_command_captures_native_stdout() {
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("cmd");
            command.args(["/C", "echo hello-console"]);
            command
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "echo hello-console"]);
            command
        };
        let output = super::run_logged_command(command, "$ echo hello-console", None, "echo")
            .expect("native console");
        assert!(
            output.contains("hello-console"),
            "unexpected console output: {output}"
        );
        assert!(output.contains("$ echo hello-console"));
    }
}
