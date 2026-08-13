use crate::{
    evaluate_docker_inspect, reconcile_node_network, redact_json_sensitive, verify_payload,
    CommissionNodeRequest, ConfigurationWriteRequest, FabricIdentity, NodeRuntimeSummary,
    ProjectAuditSummary, ProjectServiceSummary, ReleaseManager, RuntimeTopology,
    RuntimeUnitActionRequest, RuntimeUnitHealth, RuntimeUnitInventory, VerifiedPayload,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
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
const CONFIGURATION_KEYS: [&str; 44] = [
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
        }
    }

    pub fn new_with_fabric(
        authorized_nodes_root: impl Into<PathBuf>,
        authorized_fabrics_root: impl Into<PathBuf>,
        payload_root: impl Into<PathBuf>,
        fabric: FabricIdentity,
        fabric_identity_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            authorized_nodes_root: authorized_nodes_root.into(),
            authorized_fabrics_root: authorized_fabrics_root.into(),
            payload_root: payload_root.into(),
            fabric,
            fabric_identity_path: fabric_identity_path.into(),
        }
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
        if !project.starts_with("actium-lab-") {
            return Err(format!(
                "Supervisor Lab rechazo el proyecto fuera del namespace actium-lab-: {project}."
            ));
        }
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
            return self.transactional_update(&node_root, progress);
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
            let candidate = self.run_action(&node_root, "restart").and_then(|output| {
                self.health_gate(&node_root)
                    .map(|health| format!("{output}\n\n{health}"))
            });
            return match candidate {
                Ok(output) => {
                    clear_configuration_backup(&node_root)?;
                    update_marker(&node_root, Some("running"), None, None)?;
                    Ok(RuntimeActionResult {
                        message: "Configuracion aplicada y validada por Supervisor.".to_string(),
                        output,
                        release_version: None,
                    })
                }
                Err(candidate_error) => {
                    restore_configuration_backup(&node_root)?;
                    let recovery = self.run_action(&node_root, "restart").and_then(|output| {
                        self.health_gate(&node_root)
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
        let mut output = self.run_action(&node_root, effective_action)?;
        if matches!(action, "start" | "restart") {
            output = format!("{output}\n\n{}", self.health_gate(&node_root)?);
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
            != Some("lab")
        {
            return Err("Commissioning rechazo un marcador que no pertenece a Lab.".to_string());
        }
        let config = parse_env_document(&request.node_env);
        let project = project_name(&config)?;
        if !project.starts_with("actium-lab-") {
            return Err(format!(
                "Commissioning rechazo el proyecto fuera del namespace actium-lab-: {project}."
            ));
        }
        if let Some(path) = request.radio_archive_host_path.as_deref() {
            self.ensure_node_storage_path(&node_root, path)?;
        }

        let releases = ReleaseManager::new(&node_root);
        let prepared = releases.prepare(&self.payload_root)?;
        let promoted = releases.promote(prepared)?;
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
        write_optional_secret(
            &node_root.join("secrets/connectivity_edge_enrollment_token"),
            request.connectivity_edge_enrollment_token.as_deref(),
        )?;
        write_optional_secret(
            &node_root.join("secrets/connectivity_internal_relay_token"),
            request.connectivity_internal_relay_token.as_deref(),
        )?;
        let topology = self.materialize_runtime_topology(&node_root)?;
        sync_release_marker(&node_root, &promoted, "installing", None)?;
        let runtime = releases.active_runtime_dir()?;
        if !request.prepare_only {
            self.ensure_fabric(&node_root, &topology)?;
        }
        let result = self
            .run_installer_at(
                &node_root,
                &runtime,
                &request.enrollment_token,
                request.prepare_only,
            )
            .and_then(|output| {
                if request.prepare_only {
                    Ok(output)
                } else {
                    self.health_gate(&node_root)
                        .map(|health| format!("{output}\n\n{health}"))
                }
            });
        match result {
            Ok(output) => {
                let active = releases.mark_success()?;
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
                let _ = self.run_action_at(&node_root, &runtime, "stop");
                let failed = releases.mark_failed_without_rollback()?;
                sync_release_marker(&node_root, &failed, "failed", Some(&error))?;
                Err(error)
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
        let topology = RuntimeTopology::materialize(
            &host_installation_id,
            required("ACTIUM_DEPLOYMENT_ID")?,
            required("ACTIUM_DEPLOYMENT_CODE")?,
            &profiles,
            self.fabric.clone(),
            node_root,
        )?;
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
            fs::create_dir_all(
                node_root
                    .join("persistent/runtime-units")
                    .join(&unit.runtime_unit_id),
            )
            .map_err(|error| format!("No se pudo crear storage de runtime unit: {error}"))?;

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
            }
            if unit.capability == "radio-control" {
                if let Some(project) = &livekit_project {
                    values.insert(
                        "LIVEKIT_INTERNAL_URL",
                        format!("http://{project}-livekit:17880"),
                    );
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
                    "ACTIUM_RUNTIME_TOPOLOGY_SCHEMA".to_string(),
                    "1".to_string(),
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
        for directory in ["persistent/postgres", "persistent/nats", "secrets", "state"] {
            fs::create_dir_all(root.join(directory))
                .map_err(|error| format!("No se pudo preparar Fabric {directory}: {error}"))?;
        }
        set_unix_mode(&root.join("secrets"), 0o700)?;
        write_secret_if_missing(
            &root.join("secrets/postgres_admin_password"),
            &random_secret(),
        )?;
        let config = node_config(node_root)?;
        let install_mode = config
            .get("ACTIUM_USE_PUBLISHED_IMAGES")
            .is_some_and(|value| value == "true")
            .then_some("published_images")
            .unwrap_or("local_build");
        let fabric_env = format!(
            "ACTIUM_FABRIC_ID={}\nACTIUM_FABRIC_PROJECT={}\nACTIUM_FABRIC_NETWORK={}\nACTIUM_FABRIC_ROOT={}\nACTIUM_INSTALL_MODE={}\n",
            topology.fabric.fabric_id,
            topology.fabric.compose_project,
            topology.fabric.network_name,
            unix_path(&root),
            install_mode,
        );
        write_managed_file(&root.join("fabric.env"), &fabric_env, 0o640)?;
        let nats_changed = self.write_nats_runtime_config(&root)?;
        ensure_docker_network(&topology.fabric.network_name, &topology.fabric.fabric_id)?;

        let releases = ReleaseManager::new(&root);
        let desired_release = self.payload_release_version()?;
        let state = releases.load_state()?;
        let requires_promotion = state
            .active_release
            .as_ref()
            .is_none_or(|release| release.release_version != desired_release);
        if requires_promotion {
            let prepared = releases.prepare(&self.payload_root)?;
            releases.promote(prepared)?;
        }
        let runtime = releases.active_runtime_dir()?;
        let start_result = run_fabric_compose(&root, &runtime, &topology.fabric, install_mode)
            .and_then(|output| {
                if nats_changed {
                    restart_healthy_container(&format!(
                        "{}-nats",
                        topology.fabric.compose_project
                    ))?;
                }
                self.provision_database_units(topology)?;
                Ok(output)
            });
        match start_result {
            Ok(_) => {
                if requires_promotion {
                    releases.mark_success()?;
                }
                Ok(())
            }
            Err(error) if requires_promotion && state.active_release.is_some() => {
                releases.rollback()?;
                let previous = releases.active_runtime_dir()?;
                let recovery = run_fabric_compose(&root, &previous, &topology.fabric, install_mode);
                Err(match recovery {
                    Ok(_) => format!("[ROLLED_BACK] Fabric candidato rechazado: {error}"),
                    Err(recovery_error) => format!(
                        "[MANUAL_INTERVENTION_REQUIRED] Fabric fallo ({error}) y LKG no recupero ({recovery_error})."
                    ),
                })
            }
            Err(error) => Err(error),
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
        write_json_atomic(
            &candidate.join("state/fabric-identity.json"),
            &serde_json::to_value(fabric)
                .map_err(|error| format!("No se pudo serializar Fabric: {error}"))?,
        )?;
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
        let state = releases.load_state()?;
        if state.promotion_status != "promoting" {
            return Ok(None);
        }
        let current = releases.active_runtime_dir()?;
        let _ = self.run_action_at(&node_root, &current, "stop");
        let rolled_back = releases.rollback()?;
        sync_release_marker(
            &node_root,
            &rolled_back,
            "recovering",
            Some("Supervisor detecto una promocion interrumpida por reboot."),
        )?;
        let runtime = releases.active_runtime_dir()?;
        self.run_action_at(&node_root, &runtime, "start")?;
        let health = self.health_gate(&node_root)?;
        sync_release_marker(&node_root, &rolled_back, "running", None)?;
        Ok(Some(format!(
            "Promocion interrumpida revertida al LKG despues del reboot. {health}"
        )))
    }

    pub fn recover_configuration_after_reboot(
        &self,
        install_dir: &Path,
    ) -> Result<Option<String>, String> {
        let node_root = self.validate_node_root(install_dir)?;
        if !configuration_backup_root(&node_root)
            .join("node.env")
            .is_file()
        {
            return Ok(None);
        }
        restore_configuration_backup(&node_root)?;
        let output = self.run_action(&node_root, "restart")?;
        let health = self.health_gate(&node_root)?;
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
            match reconcile_node_network(&entry.path(), false) {
                Ok(result) if result.changed => {
                    self.run_action(&entry.path(), "restart")?;
                    self.health_gate(&entry.path())?;
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
        let topology = load_topology(&node_root.join("state/runtime-topology.json"))?;
        let unit = topology.unit(&request.runtime_unit_id)?.clone();
        if matches!(request.action.as_str(), "start" | "restart" | "update") {
            self.ensure_fabric(&node_root, &topology)?;
            for dependency in &unit.depends_on {
                let dependency = topology.unit(dependency)?;
                let health = self.runtime_unit_health(dependency)?;
                if health.state != "healthy" {
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

    fn runtime_unit_health(&self, unit: &crate::RuntimeUnit) -> Result<RuntimeUnitHealth, String> {
        let ids = docker_project_ids(&unit.compose_project)?;
        if ids.is_empty() {
            return Ok(RuntimeUnitHealth {
                runtime_unit_id: unit.runtime_unit_id.clone(),
                capability: unit.capability.clone(),
                compose_project: unit.compose_project.clone(),
                state: "stopped".to_string(),
                total_services: 0,
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
            state: if report.healthy {
                "healthy"
            } else {
                "degraded"
            }
            .to_string(),
            total_services: report.total,
            ready_services: report.ready,
            failures: report.failures,
        })
    }

    fn require_runtime_unit_health(
        &self,
        unit: &crate::RuntimeUnit,
    ) -> Result<RuntimeUnitHealth, String> {
        let health = self.runtime_unit_health(unit)?;
        if health.state != "healthy" {
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
            .current_dir(&runtime);
        output_text(
            command
                .output()
                .map_err(|error| format!("No se pudo ejecutar runtime unit: {error}"))?,
        )
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
        if self.runtime_unit_health(agent)?.state != "healthy" {
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
            let fabric_root = self.ensure_fabric_root(&topology.fabric)?;
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
            != Some("lab")
        {
            return Err("Supervisor Lab solo administra nodos con managerChannel=lab.".to_string());
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
        for unit in &topology.units {
            let health = self.runtime_unit_health(unit)?;
            total += health.total_services;
            ready += health.ready_services;
            if health.state != "healthy" {
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

    fn transactional_update(
        &self,
        node_root: &Path,
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
            releases.snapshot_legacy(legacy_version, "supervisor-adopted")?;
        }
        self.run_action_at(node_root, &prepared.staging_path, "prepare-update")?;
        if let Some(report) = progress {
            report("promoting", "Deteniendo LKG y promoviendo candidato.");
        }
        self.run_action_at(node_root, &current_runtime, "stop")?;
        let promoted = match releases.promote(prepared) {
            Ok(state) => state,
            Err(error) => {
                let _ = self.run_action_at(node_root, &current_runtime, "start");
                return Err(format!("No se pudo promover; LKG reiniciado: {error}"));
            }
        };
        sync_release_marker(node_root, &promoted, "installing", None)?;
        let candidate = releases.active_runtime_dir()?;
        let topology = self.materialize_runtime_topology(node_root)?;
        self.ensure_fabric(node_root, &topology)?;
        let candidate_result =
            self.run_action_at(node_root, &candidate, "start")
                .and_then(|output| {
                    self.health_gate(node_root)
                        .map(|health| format!("{output}\n\n{health}"))
                });
        match candidate_result {
            Ok(output) => {
                let active = releases.mark_success()?;
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
                let rolled_back = releases.rollback().map_err(|rollback_error| {
                    format!(
                        "[MANUAL_INTERVENTION_REQUIRED] Candidato fallo ({candidate_error}) y no se pudo seleccionar LKG ({rollback_error})."
                    )
                })?;
                let previous = releases.active_runtime_dir()?;
                let recovery =
                    self.run_action_at(node_root, &previous, "start")
                        .and_then(|output| {
                            self.health_gate(node_root)
                                .map(|health| format!("{output}\n{health}"))
                        });
                match recovery {
                    Ok(output) => {
                        let message = format!("Candidato rechazado: {candidate_error}");
                        sync_release_marker(node_root, &rolled_back, "running", Some(&message))?;
                        Err(format!("[ROLLED_BACK] {message}\n\n{output}"))
                    }
                    Err(recovery_error) => Err(format!(
                        "[MANUAL_INTERVENTION_REQUIRED] Candidato fallo ({candidate_error}) y LKG no recupero ({recovery_error})."
                    )),
                }
            }
        }
    }
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
    fs::write(&temporary, contents)
        .map_err(|error| format!("No se pudo escribir {}: {error}", temporary.display()))?;
    set_unix_mode(&temporary, mode)?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo promover {}: {error}", path.display()))
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
    fs::write(&temporary, bytes)
        .map_err(|error| format!("No se pudo escribir {}: {error}", temporary.display()))?;
    preserve_unix_owner_and_mode(&temporary, metadata.as_ref())?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo promover {}: {error}", path.display()))
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
    use super::{validate_fabric_network_inspect, RuntimeOperator};
    use crate::ConfigurationWriteRequest;
    use std::collections::BTreeMap;
    use std::fs;
    use uuid::Uuid;

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
}
