use crate::{
    evaluate_docker_inspect, reconcile_node_network, redact_json_sensitive, verify_payload,
    CommissionNodeRequest, ConfigurationWriteRequest, NodeRuntimeSummary, ProjectAuditSummary,
    ProjectServiceSummary, ReleaseManager, VerifiedPayload,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
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
    payload_root: PathBuf,
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
        Self {
            authorized_nodes_root: authorized_nodes_root.into(),
            payload_root: payload_root.into(),
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
        sync_release_marker(&node_root, &promoted, "installing", None)?;
        let runtime = releases.active_runtime_dir()?;
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
        let project = project_name(&config)?.to_string();
        let ids = docker_project_ids(&project)?;
        if ids.is_empty() {
            return Ok(NodeRuntimeSummary {
                project_name: project,
                total_services: 0,
                running_services: 0,
                starting_services: 0,
                unhealthy_services: 0,
            });
        }
        let inspect = Command::new("docker")
            .arg("inspect")
            .args(&ids)
            .output()
            .map_err(|error| format!("No se pudo inspeccionar Docker: {error}"))?;
        let raw = output_text(inspect)?;
        let containers = serde_json::from_str::<Vec<serde_json::Value>>(&raw)
            .map_err(|error| format!("Docker devolvio JSON invalido: {error}"))?;
        let mut summary = NodeRuntimeSummary {
            project_name: project,
            total_services: containers.len(),
            running_services: 0,
            starting_services: 0,
            unhealthy_services: 0,
        };
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
        Ok(summary)
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
        let project = project_name(&node_config(&node_root)?)?.to_string();
        let ids = docker_project_ids(&project)?;
        if ids.is_empty() {
            return Err(format!(
                "El proyecto Docker {project} no tiene contenedores."
            ));
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
            .any(|service| service.workload == "datastore_postgres");
        Ok(ProjectAuditSummary {
            services,
            has_postgres,
        })
    }

    pub fn telemetry_audit(&self, install_dir: &Path) -> Result<String, String> {
        let inspect = self.project_inspect(install_dir)?;
        let containers = serde_json::from_str::<Vec<serde_json::Value>>(&inspect)
            .map_err(|error| format!("Docker devolvio JSON invalido: {error}"))?;
        let postgres = containers
            .iter()
            .find(|container| {
                container
                    .pointer("/Config/Labels/com.actium.workload")
                    .and_then(serde_json::Value::as_str)
                    == Some("datastore_postgres")
            })
            .and_then(|container| container.get("Id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "No se encontro PostgreSQL en el nodo.".to_string())?;
        let shell = r#"export PGPASSWORD="$(cat /run/secrets/postgres_password)"; exec psql -U aegis_data_plane -d aegis_data_plane -At -v ON_ERROR_STOP=1 -c "$1""#;
        let raw = output_text(
            Command::new("docker")
                .args(["exec", postgres, "sh", "-ec", shell, "actium-audit"])
                .arg(include_str!("../assets/telemetry-audit.sql"))
                .output()
                .map_err(|error| format!("No se pudo consultar telemetria local: {error}"))?,
        )?;
        redact_json_document(&raw, "auditoria de telemetria")
    }

    pub fn node_agent_runtime(&self, install_dir: &Path) -> Result<String, String> {
        let inspect = self.project_inspect(install_dir)?;
        let containers = serde_json::from_str::<Vec<serde_json::Value>>(&inspect)
            .map_err(|error| format!("Docker devolvio JSON invalido: {error}"))?;
        let agent = containers
            .iter()
            .find(|container| {
                container
                    .pointer("/Config/Labels/com.actium.workload")
                    .and_then(serde_json::Value::as_str)
                    == Some("node_agent")
                    && container
                        .pointer("/State/Status")
                        .and_then(serde_json::Value::as_str)
                        == Some("running")
            })
            .and_then(|container| container.get("Id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "El agente del nodo no esta en ejecucion.".to_string())?;
        let raw = output_text(
            Command::new("docker")
                .args([
                    "exec",
                    agent,
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
        let config = node_config(node_root)?;
        let project = project_name(&config)?;
        let ids = docker_project_ids(project)?;
        if ids.is_empty() {
            return Err("Health gate fallido: no hay contenedores observables.".to_string());
        }
        let inspect = Command::new("docker")
            .arg("inspect")
            .args(&ids)
            .output()
            .map_err(|error| format!("No se pudo inspeccionar Docker: {error}"))?;
        let report = evaluate_docker_inspect(&output_text(inspect)?)?;
        if !report.healthy {
            return Err(format!(
                "Health gate fallido ({}/{} listos): {}",
                report.ready,
                report.total,
                report.failures.join("; ")
            ));
        }
        Ok(format!(
            "Health gate OK: {}/{} workloads listos.",
            report.ready, report.total
        ))
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
    use super::RuntimeOperator;
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
}
