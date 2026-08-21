use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path};
use uuid::Uuid;

pub const RUNTIME_TOPOLOGY_SCHEMA: u8 = 3;
const RUNTIME_UNIT_NAMESPACE: Uuid = Uuid::from_u128(0x9fd4d6d4_7419_5d55_9ca2_c6f72b240759);
// Reserve the longest runtime service suffix (`-control-runtime`, 16 chars)
// so every materialized Compose DNS label remains within RFC 1123's 63 chars.
const RUNTIME_PROJECT_BASE_MAX_LEN: usize = 38;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FabricIdentity {
    pub fabric_id: String,
    pub compose_project: String,
    pub network_name: String,
    pub host_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTopology {
    pub schema: u8,
    pub host_installation_id: String,
    pub host_id: Option<String>,
    pub deployment_id: String,
    pub deployment_code: String,
    pub deployment_network_name: String,
    pub fabric: FabricIdentity,
    pub units: Vec<RuntimeUnit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeUnit {
    pub runtime_unit_id: String,
    pub capability: String,
    pub compose_project: String,
    pub compose_file: String,
    pub depends_on: Vec<String>,
    pub startup_cohort: RuntimeStartupCohort,
    pub startup_gate: RuntimeStartupGate,
    pub binding: RuntimeUnitBinding,
    pub resources: RuntimeUnitResourceBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStartupCohort {
    Bootstrap,
    Runtime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStartupGate {
    SiteCoreAlive,
    AgentReporting,
    SteadyReady,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeUnitBinding {
    pub secrets_directory: String,
    pub database_role: Option<String>,
    pub database_schema: Option<String>,
    pub nats_account: Option<String>,
    pub nats_user: Option<String>,
    pub nats_subject_prefix: Option<String>,
    pub storage_buckets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeUnitResourceBudget {
    pub cpus: String,
    pub memory_limit: String,
    pub memory_reservation: String,
    pub pids_limit: u32,
    pub log_max_size: String,
    pub log_max_files: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeUnitActionRequest {
    pub install_dir: String,
    pub runtime_unit_id: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeUnitHealth {
    pub runtime_unit_id: String,
    pub capability: String,
    pub compose_project: String,
    pub state: String,
    pub commissioned: bool,
    pub total_services: usize,
    pub alive_services: usize,
    pub ready_services: usize,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeUnitInventory {
    pub fabric: FabricIdentity,
    pub deployment_id: String,
    pub units: Vec<RuntimeUnitHealth>,
}

impl RuntimeTopology {
    pub fn materialize(
        host_installation_id: &str,
        deployment_id: &str,
        deployment_code: &str,
        profiles: &[String],
        fabric: FabricIdentity,
        node_root: &Path,
    ) -> Result<Self, String> {
        Self::materialize_for_channel(
            "lab",
            host_installation_id,
            deployment_id,
            deployment_code,
            profiles,
            fabric,
            node_root,
        )
    }

    pub fn materialize_for_channel(
        manager_channel: &str,
        host_installation_id: &str,
        deployment_id: &str,
        deployment_code: &str,
        profiles: &[String],
        fabric: FabricIdentity,
        node_root: &Path,
    ) -> Result<Self, String> {
        let project_prefix = channel_project_prefix(manager_channel)?;
        require_uuid(host_installation_id, "host_installation_id")?;
        let deployment_uuid = require_uuid(deployment_id, "deployment_id")?;
        validate_identifier(&fabric.fabric_id, "fabric_id")?;
        validate_project(&fabric.compose_project, "proyecto Fabric", project_prefix)?;
        validate_project(&fabric.network_name, "red Fabric", project_prefix)?;
        let deployment_network_name = project_name(
            deployment_code,
            "local",
            &short_hash(&deployment_uuid.to_string()),
            project_prefix,
        );
        validate_project(
            &deployment_network_name,
            "red local del deployment",
            project_prefix,
        )?;

        let mut capabilities = vec!["agent".to_string()];
        for profile in profiles {
            let capability = normalize_capability(profile)?;
            if !capabilities.contains(&capability) {
                capabilities.push(capability);
            }
        }
        capabilities.sort_by_key(|capability| capability_rank(capability));

        let mut units = Vec::new();
        for capability in &capabilities {
            let runtime_unit_id = Uuid::new_v5(
                &RUNTIME_UNIT_NAMESPACE,
                format!("{deployment_uuid}:{capability}").as_bytes(),
            )
            .to_string();
            let token = short_hash(&runtime_unit_id);
            let compose_project = project_name(deployment_code, capability, &token, project_prefix);
            let binding = binding_for(node_root, &runtime_unit_id, capability, &token);
            units.push(RuntimeUnit {
                runtime_unit_id,
                capability: capability.clone(),
                compose_project,
                compose_file: compose_file(capability)?.to_string(),
                depends_on: Vec::new(),
                startup_cohort: startup_cohort(capability),
                startup_gate: startup_gate(capability),
                binding,
                resources: resource_budget(capability),
            });
        }

        let id_for = |capability: &str| {
            units
                .iter()
                .find(|unit| unit.capability == capability)
                .map(|unit| unit.runtime_unit_id.clone())
        };
        let telemetry_id = id_for("telemetry");
        let turn_id = id_for("turn");
        let livekit_id = id_for("livekit");
        for unit in &mut units {
            if unit.capability == "connectivity" {
                let dependency = telemetry_id.clone().ok_or_else(|| {
                    "Connectivity requiere una runtime unit Telemetry en el mismo deployment."
                        .to_string()
                })?;
                unit.depends_on.push(dependency);
            }
            if unit.capability == "radio-control" {
                if let Some(dependency) = &turn_id {
                    unit.depends_on.push(dependency.clone());
                }
                if let Some(dependency) = &livekit_id {
                    unit.depends_on.push(dependency.clone());
                }
            }
        }
        validate_topology_units(&units)?;

        Ok(Self {
            schema: RUNTIME_TOPOLOGY_SCHEMA,
            host_installation_id: host_installation_id.to_string(),
            host_id: fabric.host_id.clone(),
            deployment_id: deployment_id.to_string(),
            deployment_code: deployment_code.to_string(),
            deployment_network_name,
            fabric,
            units,
        })
    }

    pub fn unit(&self, runtime_unit_id: &str) -> Result<&RuntimeUnit, String> {
        self.units
            .iter()
            .find(|unit| unit.runtime_unit_id == runtime_unit_id)
            .ok_or_else(|| format!("Runtime unit no administrada: {runtime_unit_id}."))
    }

    pub fn bind_host_id(&mut self, host_id: &str) -> Result<bool, String> {
        require_uuid(host_id, "host_id")?;
        if let Some(current) = self.host_id.as_deref() {
            if current != host_id {
                return Err(format!(
                    "El deployment ya esta ligado al host autoritativo {current}; se rechazo {host_id}."
                ));
            }
            return Ok(false);
        }
        if let Some(current) = self.fabric.host_id.as_deref() {
            if current != host_id {
                return Err(format!(
                    "Fabric pertenece al host autoritativo {current}; se rechazo {host_id}."
                ));
            }
        }
        self.host_id = Some(host_id.to_string());
        self.fabric.host_id = Some(host_id.to_string());
        Ok(true)
    }
}

fn validate_topology_units(units: &[RuntimeUnit]) -> Result<(), String> {
    let ids = units
        .iter()
        .map(|unit| unit.runtime_unit_id.as_str())
        .collect::<BTreeSet<_>>();
    let projects = units
        .iter()
        .map(|unit| unit.compose_project.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != units.len() || projects.len() != units.len() {
        return Err("La topologia genero identidades o proyectos duplicados.".to_string());
    }
    for unit in units {
        if !matches!(
            (&unit.startup_cohort, &unit.startup_gate),
            (
                RuntimeStartupCohort::Bootstrap,
                RuntimeStartupGate::SiteCoreAlive
            ) | (
                RuntimeStartupCohort::Bootstrap,
                RuntimeStartupGate::AgentReporting
            ) | (
                RuntimeStartupCohort::Runtime,
                RuntimeStartupGate::SteadyReady
            )
        ) {
            return Err(format!(
                "La runtime unit {} declara una cohorte y gate contradictorios.",
                unit.runtime_unit_id
            ));
        }
        for dependency in &unit.depends_on {
            if !ids.contains(dependency.as_str()) {
                return Err(format!(
                    "La runtime unit {} depende de una identidad inexistente.",
                    unit.runtime_unit_id
                ));
            }
        }
    }
    Ok(())
}

fn startup_cohort(capability: &str) -> RuntimeStartupCohort {
    if matches!(capability, "site-core" | "agent") {
        RuntimeStartupCohort::Bootstrap
    } else {
        RuntimeStartupCohort::Runtime
    }
}

fn startup_gate(capability: &str) -> RuntimeStartupGate {
    match capability {
        "site-core" => RuntimeStartupGate::SiteCoreAlive,
        "agent" => RuntimeStartupGate::AgentReporting,
        _ => RuntimeStartupGate::SteadyReady,
    }
}

fn binding_for(
    node_root: &Path,
    runtime_unit_id: &str,
    capability: &str,
    token: &str,
) -> RuntimeUnitBinding {
    let data_bound = matches!(
        capability,
        "site-core" | "telemetry" | "people" | "control" | "radio-control" | "radio-saf"
    );
    let nats_bound = matches!(capability, "telemetry" | "radio-control" | "radio-saf");
    RuntimeUnitBinding {
        secrets_directory: node_root
            .join("secrets/runtime-units")
            .join(runtime_unit_id)
            .to_string_lossy()
            .replace('\\', "/"),
        database_role: data_bound.then(|| format!("u_{token}")),
        database_schema: data_bound.then(|| format!("unit_{token}")),
        nats_account: nats_bound.then(|| format!("A_{}", token.to_ascii_uppercase())),
        nats_user: nats_bound.then(|| format!("n_{token}")),
        nats_subject_prefix: nats_bound.then(|| format!("actium.unit.{token}")),
        storage_buckets: match capability {
            "radio-saf" => vec![format!("radio-saf-{token}")],
            "control" => vec!["aegis-control-evidence".to_string()],
            _ => Vec::new(),
        },
    }
}

fn resource_budget(capability: &str) -> RuntimeUnitResourceBudget {
    let (cpus, memory_limit, memory_reservation, pids_limit) = match capability {
        "agent" => ("0.25", "192m", "64m", 128),
        "site-core" => ("0.50", "512m", "128m", 256),
        "telemetry" => ("1.00", "1024m", "256m", 384),
        "people" => ("0.50", "512m", "128m", 192),
        "control" => ("1.00", "1024m", "256m", 384),
        "connectivity" => ("0.25", "256m", "64m", 128),
        "observability" => ("0.75", "1024m", "256m", 384),
        "radio-control" => ("0.50", "512m", "128m", 256),
        "radio-saf" => ("0.75", "1024m", "256m", 384),
        "turn" => ("0.50", "384m", "64m", 256),
        "livekit" => ("1.50", "1536m", "384m", 512),
        _ => ("0.25", "256m", "64m", 128),
    };
    RuntimeUnitResourceBudget {
        cpus: cpus.to_string(),
        memory_limit: memory_limit.to_string(),
        memory_reservation: memory_reservation.to_string(),
        pids_limit,
        log_max_size: "10m".to_string(),
        log_max_files: 3,
    }
}

fn normalize_capability(profile: &str) -> Result<String, String> {
    match profile.trim() {
        "site-core" | "telemetry" | "people" | "control" | "radio-control" | "radio-saf" | "connectivity"
        | "observability" => Ok(profile.trim().to_string()),
        "radio-turn" => Ok("turn".to_string()),
        "radio-livekit" => Ok("livekit".to_string()),
        value => Err(format!("Perfil sin runtime unit en schema 1: {value}.")),
    }
}

fn compose_file(capability: &str) -> Result<&'static str, String> {
    match capability {
        "agent" => Ok("compose.agent.yml"),
        "site-core" => Ok("compose.site-core.yml"),
        "telemetry" => Ok("compose.telemetry.yml"),
        "people" => Ok("compose.people.yml"),
        "control" => Ok("compose.control.yml"),
        "radio-control" => Ok("compose.radio-control.yml"),
        "radio-saf" => Ok("compose.radio-saf.yml"),
        "turn" => Ok("compose.turn.yml"),
        "livekit" => Ok("compose.livekit.yml"),
        "connectivity" => Ok("compose.connectivity.yml"),
        "observability" => Ok("compose.observability.yml"),
        value => Err(format!("Capability sin Compose: {value}.")),
    }
}

fn capability_rank(capability: &str) -> usize {
    match capability {
        "site-core" => 0,
        "agent" => 1,
        "telemetry" => 2,
        "people" => 3,
        "control" => 4,
        "turn" => 5,
        "livekit" => 6,
        "radio-control" => 7,
        "radio-saf" => 8,
        "connectivity" => 9,
        "observability" => 10,
        _ => usize::MAX,
    }
}

fn project_name(
    deployment_code: &str,
    capability: &str,
    token: &str,
    project_prefix: &str,
) -> String {
    let base = format!(
        "{}-{}",
        deployment_code
            .trim()
            .to_ascii_lowercase()
            .chars()
            .map(|character| if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            })
            .collect::<String>()
            .trim_matches('-'),
        capability
    );
    let mut project = base.trim_matches('-').to_string();
    if !project.starts_with(project_prefix) {
        project = format!("{project_prefix}{project}");
    }
    // Compose service names are also DNS labels on the deployment network.
    // Reserve 14 bytes for the longest runtime suffix (`-radio-control`) so
    // the effective hostname never exceeds the RFC 1123 label limit.
    if project.len() > RUNTIME_PROJECT_BASE_MAX_LEN {
        project.truncate(RUNTIME_PROJECT_BASE_MAX_LEN);
        project = project.trim_matches('-').to_string();
    }
    format!("{project}-{}", &token[..8])
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..10]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn require_uuid(value: &str, field: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value.trim()).map_err(|_| format!("{field} debe ser UUID."))
}

fn validate_identifier(value: &str, field: &str) -> Result<(), String> {
    require_uuid(value, field).map(|_| ())
}

fn validate_project(value: &str, field: &str, project_prefix: &str) -> Result<(), String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 63
        || !value.starts_with(project_prefix)
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
    {
        return Err(format!(
            "{field} no pertenece al namespace {project_prefix}."
        ));
    }
    Ok(())
}

pub fn channel_project_prefix(channel: &str) -> Result<&'static str, String> {
    match channel.trim() {
        "lab" => Ok("actium-lab-"),
        "stable" => Ok("actium-node-"),
        _ => Err("manager_channel debe ser lab o stable.".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{FabricIdentity, RuntimeTopology};
    use std::path::Path;

    fn fabric() -> FabricIdentity {
        FabricIdentity {
            fabric_id: "11111111-1111-4111-8111-111111111111".to_string(),
            compose_project: "actium-lab-fabric-01".to_string(),
            network_name: "actium-lab-fabric-01".to_string(),
            host_id: None,
        }
    }

    #[test]
    fn materializa_ids_estables_y_dependencia_connectivity() {
        let profiles = vec!["telemetry".to_string(), "connectivity".to_string()];
        let first = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-01",
            &profiles,
            fabric(),
            Path::new("/srv/actium-data/nodes/deployment-01"),
        )
        .unwrap();
        let second = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-01",
            &profiles,
            fabric(),
            Path::new("/srv/actium-data/nodes/deployment-01"),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.schema, 3);
        assert_eq!(first.units.len(), 3);
        assert!(first
            .deployment_network_name
            .starts_with("actium-lab-deployment-01-local-"));
        let telemetry = first
            .units
            .iter()
            .find(|unit| unit.capability == "telemetry")
            .unwrap();
        let connectivity = first
            .units
            .iter()
            .find(|unit| unit.capability == "connectivity")
            .unwrap();
        assert_eq!(
            connectivity.depends_on,
            vec![telemetry.runtime_unit_id.clone()]
        );
        assert!(first
            .units
            .iter()
            .all(|unit| unit.compose_project.starts_with("actium-lab-")));
    }

    #[test]
    fn reserva_espacio_dns_para_sufijos_de_servicio() {
        let profiles = vec![
            "site-core".to_string(),
            "telemetry".to_string(),
            "people".to_string(),
            "control".to_string(),
            "radio-control".to_string(),
            "radio-saf".to_string(),
            "radio-livekit".to_string(),
            "radio-turn".to_string(),
            "connectivity".to_string(),
            "observability".to_string(),
        ];
        let topology = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-con-un-nombre-deliberadamente-muy-largo-para-dns",
            &profiles,
            fabric(),
            Path::new("/srv/actium-data/nodes/deployment-largo"),
        )
        .unwrap();
        for unit in topology.units {
            let suffix = match unit.capability.as_str() {
                "site-core" => "-site-core",
                "telemetry" => "-projector",
                "people" => "-people",
                "control" => "-control-runtime",
                "radio-control" => "-radio-control",
                "radio-saf" => "-radio-saf",
                "livekit" => "-livekit",
                "turn" => "-turn",
                "connectivity" => "-connector",
                "observability" => "-prometheus",
                "agent" => "-agent",
                capability => panic!("capability sin contrato DNS: {capability}"),
            };
            assert!(
                unit.compose_project.len() + suffix.len() <= 63,
                "hostname demasiado largo: {}{}",
                unit.compose_project,
                suffix
            );
        }
    }

    #[test]
    fn materializa_dependencias_condicionales_y_aisla_dos_deployments() {
        let profiles = vec![
            "telemetry".to_string(),
            "connectivity".to_string(),
            "radio-control".to_string(),
            "radio-turn".to_string(),
            "radio-livekit".to_string(),
        ];
        let first = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-a",
            &profiles,
            fabric(),
            Path::new("/srv/actium-data/nodes/deployment-a"),
        )
        .unwrap();
        let second = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "44444444-4444-4444-8444-444444444444",
            "deployment-b",
            &profiles,
            fabric(),
            Path::new("/srv/actium-data/nodes/deployment-b"),
        )
        .unwrap();

        let id = |topology: &RuntimeTopology, capability: &str| {
            topology
                .units
                .iter()
                .find(|unit| unit.capability == capability)
                .unwrap()
                .runtime_unit_id
                .clone()
        };
        let radio = first
            .units
            .iter()
            .find(|unit| unit.capability == "radio-control")
            .unwrap();
        assert_eq!(
            radio.depends_on,
            vec![id(&first, "turn"), id(&first, "livekit")]
        );
        assert_eq!(
            first
                .units
                .iter()
                .find(|unit| unit.capability == "connectivity")
                .unwrap()
                .depends_on,
            vec![id(&first, "telemetry")]
        );
        assert!(first
            .units
            .iter()
            .map(|unit| unit.compose_project.as_str())
            .all(|project| !second
                .units
                .iter()
                .any(|unit| unit.compose_project == project)));
        assert_eq!(first.fabric, second.fabric);
        assert_ne!(
            first.deployment_network_name,
            second.deployment_network_name
        );

        let order = first
            .units
            .iter()
            .map(|unit| unit.capability.as_str())
            .collect::<Vec<_>>();
        assert!(
            order.iter().position(|value| *value == "turn").unwrap()
                < order
                    .iter()
                    .position(|value| *value == "radio-control")
                    .unwrap()
        );
        assert!(
            order.iter().position(|value| *value == "livekit").unwrap()
                < order
                    .iter()
                    .position(|value| *value == "radio-control")
                    .unwrap()
        );
        assert!(
            order.iter().position(|value| *value == "agent").unwrap()
                < order
                    .iter()
                    .position(|value| *value == "telemetry")
                    .unwrap()
        );
    }

    #[test]
    fn materializa_people_only_sin_dependencia_same_node() {
        let topology = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "people-01",
            &["people".to_string()],
            fabric(),
            Path::new("/srv/actium-data/nodes/people-01"),
        )
        .unwrap();
        let people = topology
            .units
            .iter()
            .find(|unit| unit.capability == "people")
            .unwrap();
        assert!(people.depends_on.is_empty());
        assert_eq!(people.compose_file, "compose.people.yml");
        assert!(people.binding.database_role.is_some());
        assert!(people.binding.database_schema.is_some());
        assert!(people.binding.nats_account.is_none());
        assert!(!topology.units.iter().any(|unit| unit.capability == "site-core"));
        assert!(!topology.units.iter().any(|unit| unit.capability == "connectivity"));
    }

    #[test]
    fn materializa_control_only_sin_site_core_ni_nats() {
        let topology = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "control-01",
            &["control".to_string()],
            fabric(),
            Path::new("/srv/actium-data/nodes/control-01"),
        )
        .unwrap();
        let control = topology
            .units
            .iter()
            .find(|unit| unit.capability == "control")
            .unwrap();
        assert!(control.depends_on.is_empty());
        assert_eq!(control.compose_file, "compose.control.yml");
        assert!(control.binding.database_role.is_some());
        assert!(control.binding.database_schema.is_some());
        assert!(control.binding.nats_account.is_none());
        assert_eq!(control.binding.storage_buckets, vec!["aegis-control-evidence"]);
        assert!(!topology.units.iter().any(|unit| unit.capability == "site-core"));
    }

    #[test]
    fn people_multi_capability_y_multi_node_no_colisiona() {
        let profiles = vec![
            "site-core".to_string(),
            "telemetry".to_string(),
            "people".to_string(),
            "observability".to_string(),
        ];
        let first = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "node-a",
            &profiles,
            fabric(),
            Path::new("/srv/actium-data/nodes/node-a"),
        )
        .unwrap();
        let second = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "44444444-4444-4444-8444-444444444444",
            "node-b",
            &["people".to_string()],
            fabric(),
            Path::new("/srv/actium-data/nodes/node-b"),
        )
        .unwrap();
        let first_people = first.units.iter().find(|unit| unit.capability == "people").unwrap();
        let second_people = second.units.iter().find(|unit| unit.capability == "people").unwrap();
        assert_ne!(first_people.runtime_unit_id, second_people.runtime_unit_id);
        assert_ne!(first_people.compose_project, second_people.compose_project);
        assert_ne!(first_people.binding.database_role, second_people.binding.database_role);
        assert_ne!(first_people.binding.database_schema, second_people.binding.database_schema);
    }

    #[test]
    fn stable_usa_namespace_nuevo_sin_adoptar_proyectos_legacy() {
        let stable_fabric = FabricIdentity {
            fabric_id: "11111111-1111-4111-8111-111111111111".to_string(),
            compose_project: "actium-node-fabric-01".to_string(),
            network_name: "actium-node-fabric-01".to_string(),
            host_id: None,
        };
        let topology = RuntimeTopology::materialize_for_channel(
            "stable",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-01",
            &["telemetry".to_string()],
            stable_fabric,
            Path::new(r"C:\ProgramData\Actium\NodeManager\Nodes\deployment-01"),
        )
        .unwrap();
        assert!(topology
            .units
            .iter()
            .all(|unit| unit.compose_project.starts_with("actium-node-")));
        assert!(RuntimeTopology::materialize_for_channel(
            "stable",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-01",
            &["telemetry".to_string()],
            fabric(),
            Path::new(r"C:\ProgramData\Actium\NodeManager\Nodes\deployment-01"),
        )
        .is_err());
    }

    #[test]
    fn rechaza_connectivity_sin_telemetry_y_host_contradictorio() {
        let error = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-01",
            &["connectivity".to_string()],
            fabric(),
            Path::new("/srv/actium-data/nodes/deployment-01"),
        )
        .unwrap_err();
        assert!(error.contains("Telemetry"));

        let mut topology = RuntimeTopology::materialize(
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "deployment-01",
            &["telemetry".to_string()],
            fabric(),
            Path::new("/srv/actium-data/nodes/deployment-01"),
        )
        .unwrap();
        assert!(topology
            .bind_host_id("44444444-4444-4444-8444-444444444444")
            .unwrap());
        assert!(topology
            .bind_host_id("55555555-5555-4555-8555-555555555555")
            .is_err());
    }
}
