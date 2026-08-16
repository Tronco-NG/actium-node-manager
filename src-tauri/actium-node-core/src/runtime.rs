use crate::topology::channel_project_prefix;
use crate::{
    attestation::{AttestedContainer, AttestedFabric, AttestedRuntimeUnit},
    canonical_json, evaluate_docker_inspect, reconcile_node_network, redact_json_sensitive,
    redact_sensitive, verify_payload, AttestationAuthorityState, AttestationJournal,
    AttestationSigner, CommissionNodeRequest, ConfigurationWriteRequest, FabricIdentity,
    MaterialAttestationStatement, NodeReleaseState, NodeRuntimeSummary, ProjectAuditSummary,
    ProjectServiceSummary, ReleaseManager, ReleasePromotion, RuntimeStartupCohort,
    RuntimeStartupGate, RuntimeTopology, RuntimeUnitActionRequest, RuntimeUnitHealth,
    RuntimeUnitInventory, VerifiedPayload,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const MARKER_FILE: &str = ".actium-node-installation.json";
const ALLOWED_ACTIONS: [&str; 15] = [
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
];
const CONFIGURATION_KEYS: [&str; 46] = [
    "ACTIUM_INSTALLER_VERSION",
    "RADIO_SAF_ENABLED",
    "RADIO_LIVEKIT_ENABLED",
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
    "TURN_URLS",
    "TELEMETRY_PORT",
    "GPS_STREAM_MAX_BYTES",
    "HEARTBEAT_STREAM_MAX_BYTES",
    "RADIO_CONTROL_PORT",
    "SITE_CORE_PORT",
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
    "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED",
    "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED",
    "CONNECTIVITY_FALLBACK_ORDER",
];

type RuntimeProgress<'a> = dyn Fn(&str, &str) + 'a;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeActionResult {
    pub message: String,
    pub output: String,
    pub release_version: Option<String>,
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
        let node_root = self.validate_node_root(install_dir)?;
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
        if matches!(
            action,
            "start" | "restart" | "update" | "apply_configuration"
        ) {
            let network = reconcile_node_network(&node_root, true)?;
            if network.changed {
                eprintln!("{}", network.message);
            }
            let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
            self.ensure_fabric(&node_root, &topology)?;
        }
        if action == "update" {
            return self.transactional_update(
                &node_root,
                node_mutation
                    .take()
                    .ok_or_else(|| "Update no adquirio lock de nodo.".to_string())?,
                progress,
            );
        }
        if action == "save_configuration" {
            return Ok(RuntimeActionResult {
                message: "Configuracion persistida; el runtime conserva su estado actual."
                    .to_string(),
                output: "Supervisor registro la configuracion pendiente sin ejecutar Docker."
                    .to_string(),
                release_version: None,
            });
        }
        if action == "apply_configuration" {
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
            _ => self.run_action(&node_root, effective_action)?,
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

    pub fn validate_operation_target(&self, install_dir: &Path) -> Result<PathBuf, String> {
        self.validate_node_root(install_dir)
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
        let candidate_release = self.payload_release_version()?;
        if candidate_release != request.expected_release {
            return Err(format!(
                "Manager solicito {}, pero Supervisor posee {}.",
                request.expected_release, candidate_release
            ));
        }
        let node_root = self.prepare_new_node_root(Path::new(&request.install_dir))?;
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
        let config = parse_env_document(&request.node_env);
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
            write_managed_file(&node_root.join("node.env"), &request.node_env, 0o644)?;
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
            let topology = self.materialize_runtime_topology(&node_root)?;
            sync_release_marker(&node_root, transaction.promoted_state(), "installing", None)?;
            if !request.prepare_only {
                promotion_checkpoint("commission.fabric")?;
                self.ensure_fabric(&node_root, &topology)?;
            }
            self.run_installer_at(&node_root, &candidate, &request.enrollment_token, true)
                .and_then(|output| {
                    if request.prepare_only {
                        Ok(output)
                    } else {
                        promotion_checkpoint("commission.before_runtime_start")?;
                        self.start_runtime_topology_at(&node_root, &candidate)
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
                Ok(RuntimeActionResult {
                    message: format!("Nodo {project} creado por Supervisor."),
                    output,
                    release_version: active.active_release.map(|release| release.release_version),
                })
            }
            Err(error) => {
                let _ = self.run_action_at(&node_root, &candidate, "stop");
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
        let host_installation_id = self.local_host_installation_id()?;
        let topology = RuntimeTopology::materialize_for_channel(
            &self.manager_channel,
            &host_installation_id,
            required("ACTIUM_DEPLOYMENT_ID")?,
            required("ACTIUM_DEPLOYMENT_CODE")?,
            &profiles,
            self.fabric.clone(),
            node_root,
        )?;
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
            if let Some(value) = &unit.binding.database_role {
                values.insert("ACTIUM_RUNTIME_DB_USER", value.clone());
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
        write_json_atomic(
            &node_root.join("state/runtime-topology.json"),
            &serde_json::to_value(&topology)
                .map_err(|error| format!("No se pudo serializar topologia: {error}"))?,
        )?;
        let env_path = node_root.join("node.env");
        let current = fs::read_to_string(&env_path)
            .map_err(|error| format!("No se pudo leer node.env: {error}"))?;
        let updated = updated_env_document(
            &current,
            &BTreeMap::from([
                (
                    "ACTIUM_FABRIC_ID".to_string(),
                    topology.fabric.fabric_id.clone(),
                ),
                (
                    "ACTIUM_HOST_INSTALLATION_ID".to_string(),
                    host_installation_id,
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
            ]),
        );
        write_managed_file(&env_path, &updated, 0o640)?;
        Ok(topology)
    }

    fn local_host_installation_id(&self) -> Result<String, String> {
        let parent = self
            .fabric_identity_path
            .parent()
            .ok_or_else(|| "fabric_identity_path no tiene directorio padre.".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear estado de host: {error}"))?;
        let path = parent.join("host-installation-id");
        if path.is_file() {
            let value = fs::read_to_string(&path)
                .map_err(|error| format!("No se pudo leer host-installation-id: {error}"))?;
            return Uuid::parse_str(value.trim())
                .map(|value| value.to_string())
                .map_err(|_| "host-installation-id persistido no es UUID.".to_string());
        }
        let value = Uuid::new_v4().to_string();
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(format!("{value}\n").as_bytes())
                    .map_err(|error| {
                        format!("No se pudo persistir host-installation-id: {error}")
                    })?;
                set_unix_mode(&path, 0o640)?;
                Ok(value)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stored = fs::read_to_string(&path).map_err(|read_error| {
                    format!("No se pudo leer host-installation-id concurrente: {read_error}")
                })?;
                Uuid::parse_str(stored.trim())
                    .map(|value| value.to_string())
                    .map_err(|_| "host-installation-id concurrente no es UUID.".to_string())
            }
            Err(error) => Err(format!("No se pudo crear host-installation-id: {error}")),
        }
    }

    fn ensure_fabric(&self, node_root: &Path, topology: &RuntimeTopology) -> Result<(), String> {
        let root = self.ensure_fabric_root(&topology.fabric)?;
        let releases = ReleaseManager::new(&root);
        let mut fabric_mutation = Some(releases.lock_mutation()?);
        for directory in ["persistent/postgres", "persistent/nats", "secrets", "state"] {
            fs::create_dir_all(root.join(directory))
                .map_err(|error| format!("No se pudo preparar Fabric {directory}: {error}"))?;
        }
        set_unix_mode(&root.join("persistent/nats"), 0o750)?;
        set_nats_storage_owner(&root.join("persistent/nats"))?;
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
        let nats_changed = self.write_nats_runtime_config(&root)?;
        ensure_docker_network(&topology.fabric.network_name, &topology.fabric.fabric_id)?;
        ensure_deployment_docker_network(
            &topology.deployment_network_name,
            &topology.deployment_id,
        )?;

        let (desired_release, desired_digest) = match verify_payload(&self.payload_root)? {
            VerifiedPayload::Schema3(manifest) => (manifest.release_version, manifest.tree_sha256),
            VerifiedPayload::LegacyUnverified { .. } => {
                return Err("Supervisor exige payload schema 3 para Fabric.".to_string())
            }
        };
        let state = releases.load_state()?;
        let requires_promotion = state.active_release.as_ref().is_none_or(|release| {
            release.release_version != desired_release || release.release_digest != desired_digest
        });
        let transaction = if requires_promotion {
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
            if password.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
                return Err("Password PostgreSQL administrado no es hexadecimal.".to_string());
            }
            let sql = format!(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN CREATE ROLE {role} LOGIN PASSWORD '{password}'; ELSE ALTER ROLE {role} WITH LOGIN PASSWORD '{password}'; END IF; END $$;\nCREATE SCHEMA IF NOT EXISTS {schema} AUTHORIZATION {role};\nALTER SCHEMA {schema} OWNER TO {role};\nALTER ROLE {role} IN DATABASE actium_fabric SET search_path TO {schema}, public;\nGRANT CONNECT ON DATABASE actium_fabric TO {role};\n"
            );
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
        for key in request.env_updates.keys() {
            if !CONFIGURATION_KEYS.contains(&key.as_str()) {
                return Err(format!(
                    "Supervisor rechazo la clave de configuracion {key}."
                ));
            }
        }
        if let Some(path) = request.radio_archive_host_path.as_deref() {
            self.ensure_node_storage_path(&node_root, path)?;
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
        let node_root = self.validate_node_root(install_dir)?;
        let releases = ReleaseManager::new(&node_root);
        let Some(recovery_guard) = releases.recover_interrupted()? else {
            return Ok(None);
        };
        let state = recovery_guard.state.clone();
        let interrupted_candidate = state
            .last_failed_release
            .as_ref()
            .map(|release| node_root.join(&release.relative_path));
        if let Some(candidate) = interrupted_candidate.as_ref() {
            let _ = self.run_action_at(&node_root, candidate, "stop");
        }
        if !recovery_guard.recovery_required {
            if node_root.join(MARKER_FILE).is_file() {
                let _ = sync_release_marker(
                    &node_root,
                    &state,
                    "failed",
                    Some("Supervisor aborto una primera promocion interrumpida por reboot."),
                );
            }
            return Ok(Some(
                "Primera promocion interrumpida abortada sin candidato activo; no existia LKG."
                    .to_string(),
            ));
        }
        sync_release_marker(
            &node_root,
            &state,
            "recovering",
            Some("Supervisor detecto una promocion interrumpida por reboot."),
        )?;
        let runtime = releases.active_runtime_dir()?;
        let recovery = self
            .start_runtime_topology_at(&node_root, &runtime)
            .and_then(|output| {
                self.wait_health_gate(&node_root)
                    .map(|health| format!("{output}\n{health}"))
            });
        match recovery {
            Ok(output) => {
                let recovered = recovery_guard.complete_recovery()?;
                sync_release_marker(&node_root, &recovered, "running", None)?;
                Ok(Some(format!(
                    "Promocion interrumpida revertida al LKG despues del reboot. {output}"
                )))
            }
            Err(error) => {
                let manual = recovery_guard.fail_recovery()?;
                let _ = sync_release_marker(&node_root, &manual, "failed", Some(&error));
                Err(format!(
                    "[MANUAL_INTERVENTION_REQUIRED] Recovery de LKG despues de reboot fallo: {error}"
                ))
            }
        }
    }

    pub fn recover_configuration_after_reboot(
        &self,
        install_dir: &Path,
    ) -> Result<Option<String>, String> {
        let node_root = self.validate_node_root(install_dir)?;
        let _mutation = ReleaseManager::new(&node_root).lock_mutation()?;
        if !configuration_backup_root(&node_root)
            .join("node.env")
            .is_file()
        {
            return Ok(None);
        }
        restore_configuration_backup(&node_root)?;
        let output = self.restart_runtime_topology(&node_root)?;
        let health = self.wait_health_gate(&node_root)?;
        update_marker(&node_root, Some("running"), None, None)?;
        Ok(Some(format!(
            "Configuracion interrumpida revertida despues del reboot. {output}\n{health}"
        )))
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
        let material_value = serde_json::to_value(&units)
            .map_err(|error| format!("No se pudo serializar material Docker: {error}"))?;
        let material_digest = sha256_hex(canonical_json(&material_value)?.as_bytes());
        let fabric = build_attested_fabric(&before, &units)?;
        let observation_completed_at = utc_timestamp()?;
        let supervisor_state = node_root.join("state/supervisor");
        fs::create_dir_all(&supervisor_state)
            .map_err(|error| format!("No se pudo crear estado autoritativo: {error}"))?;
        set_unix_mode(&supervisor_state, 0o755)?;
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
            self.ensure_fabric(&node_root, &topology)?;
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
        Ok(if legacy {
            AttestationAuthorityState::LegacyJournal
        } else {
            AttestationAuthorityState::NewInstallation
        })
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
        let mut command = Command::new("/bin/sh");
        command
            .arg(runtime.join("manage-node.sh"))
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
        let output = Command::new("/bin/sh")
            .arg(runtime.join("manage-node.sh"))
            .arg("logs")
            .arg(&unit.runtime_unit_id)
            .env(
                "ACTIUM_DATA_PLANE_ENV_FILE",
                node_root.join("secrets/data-plane.env"),
            )
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
            write_json_atomic(
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
        let mut command = Command::new("/bin/sh");
        command
            .arg(runtime.join("install-node.sh"))
            .arg("--config")
            .arg(node_root.join("node.env"))
            .env("ACTIUM_SECRETS_DIR", node_root.join("secrets"))
            .current_dir(&runtime);
        if prepare_only {
            command.arg("--prepare-only");
        }
        if !enrollment_token.trim().is_empty() {
            command.env("ACTIUM_ENROLLMENT_TOKEN_OVERRIDE", enrollment_token.trim());
        }
        output_text(
            command
                .output()
                .map_err(|error| format!("No se pudo ejecutar install-node.sh: {error}"))?,
        )
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
            let mut entries = fs::read_dir(install_dir)
                .map_err(|error| format!("No se pudo inspeccionar commissioning: {error}"))?;
            if entries.next().is_some() {
                return Err("El destino de commissioning no esta vacio.".to_string());
            }
        } else {
            fs::create_dir(install_dir)
                .map_err(|error| format!("No se pudo crear el nodo: {error}"))?;
        }
        set_unix_mode(install_dir, 0o755)?;
        let node = canonical_existing(install_dir)?;
        if node.parent() != Some(root.as_path()) {
            return Err("El destino resuelto salio de authorized_nodes_root.".to_string());
        }
        Ok(node)
    }

    fn ensure_node_storage_path(&self, node_root: &Path, requested: &str) -> Result<(), String> {
        let requested = Path::new(requested);
        if !requested.is_absolute()
            || requested
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || !requested.starts_with(node_root.join("persistent"))
        {
            return Err(
                "El storage solicitado debe estar dentro de persistent/ del nodo.".to_string(),
            );
        }
        fs::create_dir_all(requested)
            .map_err(|error| format!("No se pudo crear storage autorizado: {error}"))?;
        let resolved = canonical_existing(requested)?;
        if !resolved.starts_with(node_root.join("persistent")) {
            return Err("El storage resuelto salio del nodo autorizado.".to_string());
        }
        set_unix_mode(&resolved, 0o750)
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
        self.run_action_at(node_root, &runtime, action)
    }

    fn run_action_at(
        &self,
        node_root: &Path,
        runtime_root: &Path,
        action: &str,
    ) -> Result<String, String> {
        if action == "diagnostics" {
            let mut sections = Vec::new();
            for nested in ["status", "verify", "logs"] {
                let output = self
                    .run_action_at(node_root, runtime_root, nested)
                    .unwrap_or_else(|error| format!("[COMPROBACION FALLIDA]\n{error}"));
                sections.push(format!(
                    "================ {} ================\n{output}",
                    nested.to_uppercase()
                ));
            }
            return Ok(sections.join("\n\n"));
        }
        let output = if action == "verify" {
            Command::new("/bin/sh")
                .arg(runtime_root.join("verify-node.sh"))
                .env(
                    "ACTIUM_DATA_PLANE_ENV_FILE",
                    node_root.join("secrets/data-plane.env"),
                )
                .current_dir(runtime_root)
                .output()
        } else {
            let mut command = Command::new("/bin/sh");
            command
                .arg(runtime_root.join("manage-node.sh"))
                .arg(action)
                .env(
                    "ACTIUM_DATA_PLANE_ENV_FILE",
                    node_root.join("secrets/data-plane.env"),
                )
                .current_dir(runtime_root);
            if action == "logs" {
                command.env("ACTIUM_LOGS_FOLLOW", "false");
            }
            command.output()
        }
        .map_err(|error| format!("No se pudo ejecutar {action}: {error}"))?;
        output_text(output)
    }

    fn health_gate(&self, node_root: &Path) -> Result<String, String> {
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
    ) -> Result<RuntimeActionResult, String> {
        if let Some(report) = progress {
            report("validating", "Verificando payload schema 3 y bytes.");
        }
        let manifest = match verify_payload(&self.payload_root)? {
            VerifiedPayload::Schema3(manifest) => manifest,
            VerifiedPayload::LegacyUnverified { .. } => {
                return Err("Supervisor exige payload schema 3 para actualizar.".to_string())
            }
        };
        let releases = ReleaseManager::new(node_root);
        if let Some(report) = progress {
            report("staging", "Preparando release aislada.");
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
        self.run_action_at(node_root, &prepared.staging_path, "prepare-update")?;
        if let Some(report) = progress {
            report("promoting", "Deteniendo LKG y promoviendo candidato.");
        }
        self.run_action_at(node_root, &current_runtime, "stop")?;
        let transaction = match releases.begin_promotion_locked(prepared, node_mutation) {
            Ok(transaction) => transaction,
            Err(error) => {
                let _ = self.start_runtime_topology_at(node_root, &current_runtime);
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
            self.ensure_fabric(node_root, &topology)?;
            promotion_checkpoint("update.before_runtime_start")?;
            self.start_runtime_topology_at(node_root, &candidate)
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
                let _ = self.run_action_at(node_root, &candidate, "stop");
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
            .and_then(|previous| self.start_runtime_topology_at(node_root, &previous))
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
        return Ok(());
    }
    write_managed_file(path, &format!("{value}\n"), 0o600)
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

fn read_agent_lifecycle(node_root: &Path) -> Result<Option<AgentLifecycleDocument>, String> {
    let path = node_root.join("state/agent/agent-lifecycle.json");
    if !path.is_file() {
        return Ok(None);
    }
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("No se pudo inspeccionar Agent lifecycle: {error}"))?;
    if metadata.len() > 128 * 1024 {
        return Err("AGENT_LIFECYCLE_TOO_LARGE".to_string());
    }
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("No se pudo leer Agent lifecycle: {error}"))?;
    let document = serde_json::from_str(&contents)
        .map_err(|error| format!("AGENT_LIFECYCLE_INVALID: {error}"))?;
    validate_agent_lifecycle(&document)?;
    Ok(Some(document))
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
    let agent_state = node_root.join("state/agent");
    for path in [node_root.join("persistent/agent"), agent_state.clone()] {
        fs::create_dir_all(&path)
            .map_err(|error| format!("No se pudo crear storage durable del Agent: {error}"))?;
        set_unix_mode(&path, 0o750)?;
        set_agent_storage_owner(&path)?;
    }
    let supervisor_state = node_root.join("state/supervisor");
    fs::create_dir_all(&supervisor_state)
        .map_err(|error| format!("No se pudo crear estado durable del Supervisor: {error}"))?;
    set_unix_mode(&supervisor_state, 0o755)?;

    let legacy = node_root.join("state/node-runtime");
    for name in ["runtime.json", "agent-lifecycle.json"] {
        let source = legacy.join(name);
        let target = agent_state.join(name);
        if source.is_file() && !target.exists() {
            fs::copy(&source, &target).map_err(|error| {
                format!("No se pudo migrar estado legacy del Agent {name}: {error}")
            })?;
            set_unix_mode(&target, 0o600)?;
            set_agent_storage_owner(&target)?;
        }
    }
    Ok(())
}

fn prepare_runtime_unit_storage(node_root: &Path, unit: &crate::RuntimeUnit) -> Result<(), String> {
    let root = node_root
        .join("persistent/runtime-units")
        .join(&unit.runtime_unit_id);
    fs::create_dir_all(&root)
        .map_err(|error| format!("No se pudo crear storage de runtime unit: {error}"))?;
    for relative in match unit.capability.as_str() {
        "site-core" => vec!["site-core"],
        "radio-control" => vec!["radio-archive"],
        "radio-saf" => vec!["objects", "radio-archive"],
        _ => Vec::new(),
    } {
        fs::create_dir_all(root.join(relative))
            .map_err(|error| format!("No se pudo crear storage de {}: {error}", unit.capability))?;
    }
    set_unix_mode(&root, 0o750)?;
    set_runtime_unit_storage_owner(&root)
}

#[cfg(unix)]
fn set_agent_storage_owner(path: &Path) -> Result<(), String> {
    use nix::unistd::{chown, Gid, Uid};
    chown(path, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000)))
        .map_err(|error| format!("No se pudo asignar storage del Agent a uid/gid 1000: {error}"))
}

#[cfg(not(unix))]
fn set_agent_storage_owner(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_runtime_unit_storage_owner(path: &Path) -> Result<(), String> {
    use nix::unistd::{chown, Gid, Uid};
    chown(path, Some(Uid::from_raw(1000)), Some(Gid::from_raw(1000))).map_err(|error| {
        format!("No se pudo asignar storage de runtime unit a uid/gid 1000: {error}")
    })?;
    for entry in fs::read_dir(path)
        .map_err(|error| format!("No se pudo inspeccionar storage de runtime unit: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Storage de runtime unit invalido: {error}"))?;
        chown(
            &entry.path(),
            Some(Uid::from_raw(1000)),
            Some(Gid::from_raw(1000)),
        )
        .map_err(|error| format!("No se pudo asignar subdirectorio de runtime unit: {error}"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_runtime_unit_storage_owner(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_nats_storage_owner(path: &Path) -> Result<(), String> {
    use nix::unistd::{chown, Gid, Uid};
    chown(
        path,
        Some(Uid::from_raw(10_001)),
        Some(Gid::from_raw(10_001)),
    )
    .map_err(|error| format!("No se pudo asignar storage NATS a uid/gid 10001: {error}"))
}

#[cfg(not(unix))]
fn set_nats_storage_owner(_path: &Path) -> Result<(), String> {
    Ok(())
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
        self.start_runtime_topology_at(node_root, &runtime)
    }

    fn restart_runtime_topology(&self, node_root: &Path) -> Result<String, String> {
        let runtime = ReleaseManager::new(node_root).active_runtime_dir()?;
        let stopped = self.run_action_at(node_root, &runtime, "stop")?;
        self.start_runtime_topology_at(node_root, &runtime)
            .map(|started| format!("{stopped}\n{started}"))
    }

    fn start_runtime_topology_at(
        &self,
        node_root: &Path,
        runtime_root: &Path,
    ) -> Result<String, String> {
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
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
        self.wait_agent_lifecycle(node_root, &topology, agent, "enrolled")?;
        events.push(format!("{} agent_enrolled", utc_timestamp()?));
        self.wait_agent_lifecycle(node_root, &topology, agent, "host_reconciled")?;
        events.push(format!("{} agent_host_reconciled", utc_timestamp()?));
        if let Some(unit) = site_core {
            self.wait_agent_lifecycle(node_root, &topology, agent, "runtime_synced")?;
            events.push(format!("{} site_runtime_synced", utc_timestamp()?));
            self.wait_site_core_probe(unit, "/health/ready", "SITE_CORE_READINESS_TIMEOUT")?;
            self.wait_agent_lifecycle(node_root, &topology, agent, "site_core_ready")?;
            events.push(format!("{} site_core_ready", utc_timestamp()?));
        }
        self.wait_agent_lifecycle(node_root, &topology, agent, "reporting")?;
        started.insert(agent.runtime_unit_id.clone());
        events.push(format!("{} agent_reporting", utc_timestamp()?));

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
    sync_parent_directory(path)
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

#[cfg(not(unix))]
fn set_unix_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
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
    let agent_path = node_root.join("state/agent/runtime.json");
    let agent_bytes = if agent_path.is_file() {
        fs::read(&agent_path)
            .map_err(|error| format!("No se pudo leer runtime del Agent: {error}"))?
    } else {
        Vec::new()
    };
    if agent_bytes.len() > 256 * 1024 {
        return Err("AGENT_RUNTIME_TOO_LARGE".to_string());
    }
    let generation = if agent_bytes.is_empty() {
        0
    } else {
        serde_json::from_slice::<serde_json::Value>(&agent_bytes)
            .map_err(|error| format!("AGENT_RUNTIME_INVALID: {error}"))?
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    let agent_runtime_digest = sha256_hex(&agent_bytes);
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
        "runtimeUnit": unit,
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
        | "radio-migrations"
        | "radio-saf-migrations" => Some("schema_migrator"),
        "data-plane-agent" => Some("node_agent"),
        "fabric-postgres" => Some("datastore_postgres"),
        "fabric-nats" => Some("broker_nats"),
        "site-core" => Some("site_core"),
        "telemetry-gateway" => Some("telemetry_gateway"),
        "telemetry-projector" => Some("telemetry_projector"),
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
    output_text(
        Command::new("date")
            .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
            .output()
            .map_err(|error| format!("No se pudo obtener tiempo UTC: {error}"))?,
    )
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

fn write_json_atomic(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let metadata = fs::metadata(path).ok();
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("No se pudo serializar marcador: {error}"))?;
    let mut file = fs::File::create(&temporary)
        .map_err(|error| format!("No se pudo crear {}: {error}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo escribir {}: {error}", temporary.display()))?;
    preserve_unix_owner_and_mode(&temporary, metadata.as_ref())?;
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
    #[cfg(feature = "fault-injection")]
    use super::promotion_checkpoint;
    use super::{
        attested_container, attested_fabric_from_parts, capture_coherent_snapshot,
        effective_container_config, validate_deployment_network_inspect,
        validate_fabric_network_inspect, write_json_atomic, write_managed_file, RuntimeOperator,
    };
    use crate::{
        attestation::AttestedRuntimeUnit, manifest::tree_sha256, ConfigurationWriteRequest,
        FabricIdentity, NodeReleaseState, PayloadFile, PayloadManifestV3, ReleaseManager,
        ReleaseMetadata,
    };
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs;
    #[cfg(feature = "fault-injection")]
    use std::sync::Mutex;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Barrier,
    };
    use uuid::Uuid;

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
            containers: Vec::new(),
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
        let mut changed_release = release;
        changed_release.revision += 1;
        let changed_release =
            attested_fabric_from_parts(&fabric, &changed_release, &"d".repeat(64), &unit).unwrap();
        assert_ne!(first.material_digest, changed_release.material_digest);
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
            "ACTIUM_DATA_PLANE_PROJECT=actium-lab-node-01\nTELEMETRY_PORT=8090\n",
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
}
