use actium_node_core::{
    active_port_keys, assert_resume_profiles, canonical_json, effective_profiles, evaluate_docker_inspect,
    evaluate_supervisor_compatibility, key_is_authoritative, merge_resume_env, profile_env_keys,
    validate_access_transport_policy, verify_payload, CommissionNodeRequest,
    ConfigurationWriteRequest, JournalOperation,
    NetworkAddress, NodeReleaseState, PayloadManifestV3, ReleaseManager, RuntimeUnitActionRequest,
    RuntimeUnitInventory, SupervisorClient, SupervisorCommand, SupervisorCompatibility,
    SupervisorOperationRequest, SupervisorReply, VerifiedPayload, KNOWN_PROFILES,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
mod paths;
mod product;
mod promotion;
mod safety;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::{IpAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{path::BaseDirectory, AppHandle, Manager};
use uuid::Uuid;

const MARKER_FILE: &str = ".actium-node-installation.json";
const TRUSTED_BOOTSTRAP_ISSUER: &str =
    "https://lgngdqgjmvmjplovvxqd.supabase.co/functions/v1/actium-data-plane-bootstrap";
const TRUSTED_BOOTSTRAP_AUDIENCES: [&str; 2] =
    ["actium-node-manager", "actium-telemetry-node-installer"];
const TRUSTED_BOOTSTRAP_KEY_REF: &str = "actium-ed25519-telemetry-20260722-v1";
const INSTALLER_VERSION: &str = product::DATA_PLANE_RELEASE_VERSION;
type OperationProgress<'a> = dyn Fn(&str, &str) + 'a;
const TRUSTED_BOOTSTRAP_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAl50wZ6t9RtKPkcSpbbntRyZxLdUgPuwPSqdHPyzpzQw=\n-----END PUBLIC KEY-----\n";
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemInfo {
    product_display_name: String,
    product_channel: String,
    node_manager_version: String,
    data_plane_release_version: String,
    payload_schema_version: u8,
    site_runtime_schema_version: String,
    legacy_product_aliases: Vec<String>,
    platform: String,
    architecture: String,
    default_install_dir: String,
    docker_cli: bool,
    docker_daemon: bool,
    compose_v2: bool,
    dependency_install_supported: bool,
    dependency_message: String,
    payload_version: String,
    release_supported_profiles: Vec<String>,
    release_supported_features: Vec<String>,
    suggested_public_base_url: String,
    managed_nodes_dir: String,
    authorized_nodes_root: String,
    default_network_ports: NetworkPortPlan,
    execution_backend: String,
    supervisor_available: bool,
    supervisor_compatible: bool,
    supervisor_version: Option<String>,
    node_supervisor_version: String,
    supervisor_recovered_operations: usize,
    supervisor_observed_protocol: Option<u16>,
    supervisor_required_protocol: u16,
    supervisor_observed_features: Vec<String>,
    supervisor_required_features: Vec<String>,
    supervisor_compatibility_reason: String,
    network_addresses: Vec<NetworkAddress>,
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
    host_installation_id: Option<String>,
    recoverable_incomplete_preparation: bool,
    last_error: Option<String>,
    manager_channel: Option<String>,
    active_release: Option<String>,
    previous_release: Option<String>,
    release_digest: Option<String>,
    payload_schema: Option<u8>,
    promotion_status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InspectRequest {
    install_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeUnitInventoryRequest {
    install_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeUnitCommandRequest {
    install_dir: String,
    runtime_unit_id: String,
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallRequest {
    install_dir: String,
    bootstrap_jws: String,
    profiles: Vec<String>,
    project_name: String,
    network_mode: String,
    network_configuration_deferred: bool,
    network_reconciliation_policy: String,
    network_interface: String,
    network_address: String,
    network_plane: String,
    network_priority: u16,
    bind_address: String,
    public_base_url: String,
    cors_origins: String,
    telemetry_port: u16,
    people_port: u16,
    control_runtime_port: u16,
    radio_control_port: u16,
    radio_saf_port: u16,
    site_core_port: u16,
    radio_archive_host_path: String,
    #[serde(default)]
    node_root_path: Option<String>,
    #[serde(default)]
    site_core_data_path: Option<String>,
    #[serde(default)]
    telemetry_data_path: Option<String>,
    #[serde(default)]
    dvr_media_path: Option<String>,
    #[serde(default)]
    people_data_path: Option<String>,
    #[serde(default)]
    control_runtime_data_path: Option<String>,
    #[serde(default)]
    radio_control_data_path: Option<String>,
    #[serde(default)]
    radio_saf_storage_path: Option<String>,
    #[serde(default)]
    turn_data_path: Option<String>,
    #[serde(default)]
    livekit_data_path: Option<String>,
    #[serde(default)]
    prometheus_data_path: Option<String>,
    #[serde(default)]
    grafana_data_path: Option<String>,
    #[serde(default)]
    connectivity_spool_path: Option<String>,
    prometheus_port: u16,
    grafana_port: u16,
    turn_realm: String,
    turn_external_ip: String,
    turn_port: u16,
    turn_tls_port: u16,
    turn_min_port: u16,
    turn_max_port: u16,
    livekit_node_ip: String,
    livekit_public_url: String,
    livekit_http_port: u16,
    livekit_rtc_tcp_port: u16,
    livekit_udp_min_port: u16,
    livekit_udp_max_port: u16,
    connectivity_edge_control_url: String,
    connectivity_edge_enrollment_token: String,
    connectivity_internal_relay_token: String,
    connectivity_node_role: String,
    connectivity_node_priority: u16,
    connectivity_pull_limit: u16,
    #[serde(default)]
    connectivity_sync_enabled: bool,
    connectivity_direct_data_plane_fallback_enabled: bool,
    connectivity_supabase_fallback_enabled: bool,
    connectivity_fallback_order: Vec<String>,
    /// Abstract transport preference written to CONNECTIVITY_PREFERRED_TRANSPORT.
    #[serde(default)]
    connectivity_preferred_transport: Option<String>,
    /// Allowed abstract transports written to CONNECTIVITY_ALLOWED_TRANSPORTS.
    #[serde(default)]
    connectivity_allowed_transports: Option<Vec<String>>,
    /// Gateway strategy: node_direct | site_gateway | cloud_runtime.
    #[serde(default)]
    connectivity_gateway_strategy: Option<String>,
    /// Whether the node may roam across network interfaces.
    #[serde(default)]
    connectivity_roaming_allowed: Option<bool>,
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
    #[serde(default)]
    site_id: Option<String>,
    #[serde(default)]
    site_code: Option<String>,
    #[serde(default)]
    site_name: Option<String>,
    #[serde(default)]
    site_core_deployment_id: Option<String>,
    #[serde(default)]
    site_core_endpoint: Option<String>,
    #[serde(default, alias = "siteCoreIntent")]
    site_core_intent: Option<SiteCoreIntent>,
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
    #[serde(default)]
    site_runtime_expected_issuer: Option<String>,
    #[serde(default)]
    site_runtime_bundle_public_key_pem: Option<String>,
    profiles: Vec<String>,
    #[serde(default, alias = "runtimeContractRevision")]
    runtime_contract_revision: u8,
    #[serde(default, alias = "supportedProfiles")]
    supported_profiles: Vec<String>,
    #[serde(default, alias = "supportedFeatures")]
    supported_features: Vec<String>,
    #[serde(default, alias = "requiredFeatures")]
    required_features: Vec<String>,
    #[serde(default, alias = "peoplePolicy")]
    people_policy: Option<PeoplePolicy>,
    #[serde(default, alias = "runtimeCapabilities")]
    runtime_capabilities: Option<RuntimeCapabilitiesClaim>,
    #[serde(default)]
    connectivity_policy: Option<ConnectivityPolicy>,
    exp: usize,
    iss: String,
    aud: serde_json::Value,
    sub: String,
    jti: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeCapabilitiesClaim {
    schema: u8,
    verified: bool,
    runtime_release: String,
    payload_digest: String,
    installer_min_version: String,
    source_commit: String,
    tree_sha256: String,
    files: Vec<RuntimeCapabilityFileClaim>,
    supported_profiles: Vec<String>,
    supported_features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeCapabilityFileClaim {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SiteCoreIntent {
    schema: u8,
    deployment_id: String,
    site_id: String,
    role: String,
    fencing_state: String,
    authority_mode: String,
    authority_epoch: Option<u64>,
    effective_primary_deployment_id: String,
    required_feature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeoplePolicy {
    schema: u8,
    status: String,
    organization_id: String,
    site_id: String,
    policy_revision: u64,
    valid_until: String,
    runtime_placement: String,
    pii_storage_mode: String,
    identity_resolution_mode: String,
    sync_policy: String,
    residency_policy: PeopleResidencyPolicy,
    service_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PeopleResidencyPolicy {
    #[serde(default)]
    local_site: Option<bool>,
    #[serde(default)]
    country: Option<String>,
    approved_regions: Vec<String>,
    provider_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectivityPolicy {
    edge_control_url: String,
    node_role: String,
    node_priority: u16,
    pull_limit: u16,
    #[serde(default)]
    sync_enabled: bool,
    direct_data_plane_fallback_enabled: bool,
    supabase_fallback_enabled: bool,
    fallback_order: Vec<String>,
    /// Abstract transport preference — never "wireguard" or vendor names.
    #[serde(default)]
    preferred_transport: Option<String>,
    /// Comma-separated list of allowed abstract transports.
    #[serde(default)]
    allowed_transports: Option<Vec<String>>,
    /// How the node selects its site gateway: node_direct | site_gateway | cloud_runtime.
    #[serde(default)]
    gateway_strategy: Option<String>,
    /// Whether this node is permitted to roam across network interfaces.
    #[serde(default)]
    roaming_allowed: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapValidationResult {
    valid: bool,
    deployment_id: String,
    deployment_code: String,
    deployment_name: String,
    client_id: Option<String>,
    organization_id: Option<String>,
    site_id: Option<String>,
    site_code: Option<String>,
    site_name: Option<String>,
    site_core_deployment_id: Option<String>,
    site_core_endpoint: Option<String>,
    generation: i64,
    checksum: String,
    expires_at_unix_seconds: usize,
    profiles: Vec<String>,
    supported_profiles: Vec<String>,
    supported_features: Vec<String>,
    required_features: Vec<String>,
    control_endpoint: String,
    signing_key_ref: String,
    installer_min_version: String,
    connectivity_policy: Option<ConnectivityPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeActionRequest {
    install_dir: String,
    action: String,
    #[serde(default)]
    node_key: Option<String>,
    #[serde(default)]
    node_label: Option<String>,
    #[serde(default)]
    terminal_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeConfigurationRequest {
    install_dir: String,
    network_mode: String,
    network_reconciliation_policy: String,
    network_interface: String,
    network_address: String,
    network_plane: String,
    network_priority: u16,
    bind_address: String,
    public_base_url: String,
    cors_origins: String,
    telemetry_ingress_public_url: String,
    telemetry_read_public_url: String,
    metrics_public_url: String,
    radio_control_public_url: String,
    site_core_public_url: String,
    people_resolve_public_url: String,
    control_runtime_public_url: String,
    turn_urls: String,
    telemetry_port: u16,
    people_port: u16,
    control_runtime_port: u16,
    radio_control_port: u16,
    radio_saf_port: u16,
    site_core_port: u16,
    radio_archive_host_path: String,
    #[serde(default)]
    node_root_path: Option<String>,
    #[serde(default)]
    site_core_data_path: Option<String>,
    #[serde(default)]
    telemetry_data_path: Option<String>,
    #[serde(default)]
    dvr_media_path: Option<String>,
    #[serde(default)]
    people_data_path: Option<String>,
    #[serde(default)]
    control_runtime_data_path: Option<String>,
    #[serde(default)]
    radio_control_data_path: Option<String>,
    #[serde(default)]
    radio_saf_storage_path: Option<String>,
    #[serde(default)]
    turn_data_path: Option<String>,
    #[serde(default)]
    livekit_data_path: Option<String>,
    #[serde(default)]
    prometheus_data_path: Option<String>,
    #[serde(default)]
    grafana_data_path: Option<String>,
    #[serde(default)]
    connectivity_spool_path: Option<String>,
    prometheus_port: u16,
    grafana_port: u16,
    turn_realm: String,
    turn_external_ip: String,
    turn_port: u16,
    turn_tls_port: u16,
    turn_min_port: u16,
    turn_max_port: u16,
    livekit_node_ip: String,
    livekit_public_url: String,
    livekit_http_port: u16,
    livekit_rtc_tcp_port: u16,
    livekit_udp_min_port: u16,
    livekit_udp_max_port: u16,
    connectivity_edge_control_url: String,
    connectivity_edge_enrollment_token: String,
    connectivity_internal_relay_token: String,
    connectivity_node_role: String,
    connectivity_node_priority: u16,
    connectivity_pull_limit: u16,
    #[serde(default)]
    connectivity_sync_enabled: bool,
    connectivity_direct_data_plane_fallback_enabled: bool,
    connectivity_supabase_fallback_enabled: bool,
    connectivity_fallback_order: Vec<String>,
    /// Abstract transport preference — never "wireguard" or vendor names.
    #[serde(default)]
    connectivity_preferred_transport: Option<String>,
    /// Allowed abstract transports (comma-separated in env).
    #[serde(default)]
    connectivity_allowed_transports: Option<Vec<String>>,
    /// Gateway strategy: node_direct | site_gateway | cloud_runtime.
    #[serde(default)]
    connectivity_gateway_strategy: Option<String>,
    /// Whether the node may roam across network interfaces.
    #[serde(default)]
    connectivity_roaming_allowed: Option<bool>,
    use_published_images: bool,
    restart_services: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeConfigurationOperationRequest {
    configuration: NodeConfigurationRequest,
    #[serde(default)]
    node_key: Option<String>,
    #[serde(default)]
    node_label: Option<String>,
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
    starting_services: usize,
    unhealthy_services: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PortSuggestionRequest {
    profiles: Vec<String>,
    install_dir: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkPortPlan {
    telemetry_port: u16,
    people_port: u16,
    control_runtime_port: u16,
    radio_control_port: u16,
    radio_saf_port: u16,
    site_core_port: u16,
    prometheus_port: u16,
    grafana_port: u16,
    turn_port: u16,
    turn_tls_port: u16,
    turn_min_port: u16,
    turn_max_port: u16,
    livekit_http_port: u16,
    livekit_rtc_tcp_port: u16,
    livekit_udp_min_port: u16,
    livekit_udp_max_port: u16,
}

fn product_default_network_port_plan() -> NetworkPortPlan {
    NetworkPortPlan {
        telemetry_port: product::TELEMETRY_PORT,
        people_port: product::PEOPLE_PORT,
        control_runtime_port: product::CONTROL_RUNTIME_PORT,
        radio_control_port: product::RADIO_CONTROL_PORT,
        radio_saf_port: product::RADIO_SAF_PORT,
        site_core_port: product::SITE_CORE_PORT,
        prometheus_port: product::PROMETHEUS_PORT,
        grafana_port: product::GRAFANA_PORT,
        turn_port: product::TURN_PORT,
        turn_tls_port: product::TURN_TLS_PORT,
        turn_min_port: product::TURN_MIN_PORT,
        turn_max_port: product::TURN_MAX_PORT,
        livekit_http_port: product::LIVEKIT_HTTP_PORT,
        livekit_rtc_tcp_port: product::LIVEKIT_RTC_TCP_PORT,
        livekit_udp_min_port: product::LIVEKIT_UDP_MIN_PORT,
        livekit_udp_max_port: product::LIVEKIT_UDP_MAX_PORT,
    }
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
    active_release: Option<String>,
    release_digest: Option<String>,
    payload_schema: Option<u8>,
    promotion_status: Option<String>,
    profiles: Vec<String>,
    status: String,
    operational: bool,
    recoverable: bool,
    archived: bool,
    can_manage: bool,
    last_error: Option<String>,
    total_services: usize,
    running_services: usize,
    starting_services: usize,
    unhealthy_services: usize,
    connectivity_configured: bool,
    connectivity_node_role: Option<String>,
    connectivity_node_priority: Option<u16>,
    connectivity_pull_limit: Option<u16>,
    connectivity_sync_enabled: bool,
    connectivity_direct_data_plane_fallback_enabled: bool,
    connectivity_supabase_fallback_enabled: bool,
    connectivity_fallback_order: Vec<String>,
    connectivity_edge_enrollment_token_configured: bool,
    connectivity_internal_relay_token_configured: bool,
    /// Abstract preferred transport from node.env (direct | overlay | relay).
    #[serde(skip_serializing_if = "Option::is_none")]
    connectivity_preferred_transport: Option<String>,
    /// Allowed transports from node.env.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    connectivity_allowed_transports: Vec<String>,
    /// Gateway strategy from node.env.
    #[serde(skip_serializing_if = "Option::is_none")]
    connectivity_gateway_strategy: Option<String>,
    /// Roaming flag from node.env.
    #[serde(skip_serializing_if = "Option::is_none")]
    connectivity_roaming_allowed: Option<bool>,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeOperationJob {
    id: String,
    install_dir: String,
    node_key: String,
    node_label: String,
    terminal_id: Option<String>,
    action: String,
    state: String,
    queued_at_unix_seconds: u64,
    started_at_unix_seconds: Option<u64>,
    finished_at_unix_seconds: Option<u64>,
    message: String,
    output: String,
}

#[derive(Clone)]
struct OperationBackend {
    supervisor: Option<SupervisorClient>,
}

impl OperationBackend {
    fn open() -> Result<Self, String> {
        if cfg!(any(target_os = "linux", target_os = "windows")) {
            return Ok(Self {
                supervisor: Some(SupervisorClient::new(
                    paths::supervisor_socket_path(),
                    paths::supervisor_key_path(),
                )),
            });
        }
        Err("Actium Node Manager 0.7 requiere Actium Node Supervisor; esta plataforma no tiene transporte soportado.".to_string())
    }

    fn name(&self) -> &'static str {
        if self.supervisor.is_some() {
            "supervisor"
        } else {
            "unsupported"
        }
    }
}

fn supervisor_client() -> Option<SupervisorClient> {
    cfg!(any(target_os = "linux", target_os = "windows")).then(|| {
        SupervisorClient::new(
            paths::supervisor_socket_path(),
            paths::supervisor_key_path(),
        )
    })
}

fn supervisor_handshake(client: &SupervisorClient) -> SupervisorCompatibility {
    match client.request(SupervisorCommand::Ping) {
        Ok(reply) => evaluate_supervisor_compatibility(Ok(&reply)),
        Err(error) => evaluate_supervisor_compatibility(Err(error.as_str())),
    }
}

fn require_phase4_supervisor(supervisor_available: bool) -> Result<(), String> {
    if !supervisor_available {
        return Err(
            "Actium Node Manager 0.7 solo modifica nodos mediante un Actium Node Supervisor compatible (protocolo 3, resume_incomplete); embedded_legacy fue retirado."
                .to_string(),
        );
    }
    let Some(client) = supervisor_client() else {
        return Err("Supervisor no esta disponible en esta plataforma.".to_string());
    };
    let compatibility = supervisor_handshake(&client);
    if !compatibility.compatible {
        return Err(format!(
            "Supervisor incompatible. observado={} requerido={} features_obs=[{}] features_req=[{}]. {}",
            compatibility
                .observed_protocol
                .map(|value| value.to_string())
                .unwrap_or_else(|| "ausente".to_string()),
            compatibility.required_protocol,
            compatibility.observed_features.join(","),
            compatibility.required_features.join(","),
            compatibility.reason
        ));
    }
    Ok(())
}

fn job_from_journal(operation: JournalOperation) -> NodeOperationJob {
    NodeOperationJob {
        id: operation.id,
        install_dir: operation.install_dir,
        node_key: operation.target_node_id,
        node_label: operation.node_label,
        terminal_id: operation.terminal_id,
        action: operation.action,
        state: operation.state,
        queued_at_unix_seconds: operation.queued_at.parse().unwrap_or_default(),
        started_at_unix_seconds: operation.started_at.and_then(|value| value.parse().ok()),
        finished_at_unix_seconds: operation.finished_at.and_then(|value| value.parse().ok()),
        message: operation.current_step,
        output: operation.output_redacted,
    }
}

fn enqueue_supervisor_job(
    client: &SupervisorClient,
    install_dir: String,
    node_key: String,
    node_label: String,
    terminal_id: Option<String>,
    action: String,
) -> Result<NodeOperationJob, String> {
    let requested_release = (action == "update").then(|| INSTALLER_VERSION.to_string());
    match client.request(SupervisorCommand::EnqueueOperation(
        SupervisorOperationRequest {
            target_node_id: node_key,
            install_dir,
            node_label,
            terminal_id,
            action,
            requested_release,
        },
    ))? {
        SupervisorReply::Operation(operation) => Ok(job_from_journal(*operation)),
        _ => Err("Supervisor devolvio una respuesta inesperada al encolar.".to_string()),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeOperationJobRequest {
    job_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeAuditRequest {
    install_dir: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportDiagnosticRequest {
    node_label: String,
    report: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportDiagnosticResult {
    path: String,
    bytes: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeAuditService {
    workload: String,
    container_name: String,
    state: String,
    health: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeAuditSnapshot {
    generated_at: String,
    project_name: String,
    services: Vec<NodeAuditService>,
    database_ok: bool,
    database_error: Option<String>,
    telemetry: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeHtAuditFinding {
    code: String,
    tone: String,
    title: String,
    detail: String,
    action: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeHtAuditSnapshot {
    generated_at: String,
    project_name: String,
    services: Vec<NodeAuditService>,
    configuration: serde_json::Value,
    runtime: serde_json::Value,
    runtime_error: Option<String>,
    findings: Vec<NodeHtAuditFinding>,
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
    #[serde(default)]
    manager_channel: Option<String>,
    #[serde(default)]
    active_release: Option<String>,
    #[serde(default)]
    previous_release: Option<String>,
    #[serde(default)]
    release_digest: Option<String>,
    #[serde(default)]
    payload_schema: Option<u8>,
    #[serde(default)]
    promotion_status: Option<String>,
    #[serde(default)]
    last_successful_release: Option<String>,
    #[serde(default)]
    last_failed_release: Option<String>,
}

#[derive(Debug, Clone)]
struct PayloadIdentity {
    schema: u8,
    version: String,
    digest: String,
    source_dirty: bool,
}

fn payload_identity(root: &Path) -> Result<PayloadIdentity, String> {
    match verify_payload(root)? {
        VerifiedPayload::Schema3(manifest) => Ok(PayloadIdentity {
            schema: 3,
            version: manifest.release_version,
            digest: manifest.tree_sha256,
            source_dirty: manifest.source_dirty,
        }),
        VerifiedPayload::LegacyUnverified {
            version,
            declared_digest,
            ..
        } => Ok(PayloadIdentity {
            schema: 2,
            version,
            digest: declared_digest,
            source_dirty: false,
        }),
    }
}

fn validate_payload_manifest(root: &Path) -> Result<PayloadIdentity, String> {
    let manifest = payload_identity(root)?;
    if manifest.schema != product::PAYLOAD_SCHEMA_VERSION {
        return Err(format!(
            "El payload {} usa un manifiesto no soportado (schema {}).",
            manifest.version, manifest.schema
        ));
    }
    if manifest.version != INSTALLER_VERSION {
        return Err(format!(
            "La identidad del payload no coincide: manifiesto={}, Runtime incluido={}.",
            manifest.version, INSTALLER_VERSION
        ));
    }
    if product::is_lab() && manifest.source_dirty {
        return Err(
            "El payload Lab fue generado desde un working tree sucio y no puede promoverse. Genere el bundle desde un commit limpio."
                .to_string(),
        );
    }
    Ok(manifest)
}

fn validate_payload_update(source: &Path, target: &Path) -> Result<PayloadIdentity, String> {
    let source_manifest = validate_payload_manifest(source)?;
    let target_version_text = fs::read_to_string(target.join(MARKER_FILE))
        .ok()
        .and_then(|contents| serde_json::from_str::<InstallationMarker>(&contents).ok())
        .map(|marker| marker.version)
        .or_else(|| read_trimmed(&target.join("VERSION")));

    let Some(target_version_text) = target_version_text else {
        return Ok(source_manifest);
    };
    let target_digest = if target_version_text == source_manifest.version {
        let target_runtime = active_runtime_dir(target)?;
        Some(payload_identity(&target_runtime).map_err(|_| {
            format!(
                "Actualizacion rechazada: la version {} ya esta instalada pero no posee una identidad de payload verificable. Genere una version nueva.",
                source_manifest.version
            )
        })?.digest)
    } else {
        None
    };
    validate_payload_transition(
        &source_manifest,
        &target_version_text,
        target_digest.as_deref(),
    )?;
    Ok(source_manifest)
}

fn validate_payload_transition(
    source_manifest: &PayloadIdentity,
    target_version_text: &str,
    target_digest: Option<&str>,
) -> Result<(), String> {
    let source_version = Version::parse(&source_manifest.version)
        .map_err(|_| "La version del payload no es SemVer valida.".to_string())?;
    let target_version = Version::parse(target_version_text).map_err(|_| {
        format!("La instalacion existente declara una version invalida ({target_version_text}).")
    })?;
    if source_version < target_version {
        return Err(format!(
            "Actualizacion rechazada: el payload {} no puede degradar el nodo {}.",
            source_manifest.version, target_version_text
        ));
    }
    if source_version == target_version {
        let target_digest = target_digest.ok_or_else(|| format!(
            "Actualizacion rechazada: la version {} ya esta instalada pero no posee una identidad de payload verificable. Genere una version nueva.",
            source_manifest.version
        ))?;
        if target_digest != source_manifest.digest {
            return Err(format!(
                "Actualizacion rechazada: existen dos payloads distintos con la misma version {}. Incremente la version del instalador antes de actualizar.",
                source_manifest.version
            ));
        }
    }
    Ok(())
}

fn active_runtime_dir(node_root: &Path) -> Result<PathBuf, String> {
    ReleaseManager::new(node_root).active_runtime_dir()
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
    paths::default_install_dir()
}

fn managed_nodes_dir() -> PathBuf {
    paths::managed_nodes_dir()
}

fn recovery_root_dir() -> PathBuf {
    paths::recovery_root_dir()
}

fn registry_path() -> PathBuf {
    paths::registry_path()
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
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    read_env_file_from_contents(&contents)
}

fn read_env_file_from_contents(contents: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
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
    let active_release = marker
        .as_ref()
        .and_then(|value| value.active_release.clone());
    let recoverable_incomplete_preparation =
        is_recoverable_incomplete_preparation(status.as_deref(), active_release.as_deref());
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
        .and_then(|value| value.installation_id.clone());
    let host_installation_id = config.get("ACTIUM_HOST_INSTALLATION_ID").cloned();
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
        host_installation_id,
        recoverable_incomplete_preparation,
        manager_channel: marker
            .as_ref()
            .and_then(|value| value.manager_channel.clone()),
        active_release,
        previous_release: marker
            .as_ref()
            .and_then(|value| value.previous_release.clone()),
        release_digest: marker
            .as_ref()
            .and_then(|value| value.release_digest.clone()),
        payload_schema: marker.as_ref().and_then(|value| value.payload_schema),
        promotion_status: marker
            .as_ref()
            .and_then(|value| value.promotion_status.clone()),
        last_error: marker.and_then(|value| value.last_error),
    }
}

fn installation_owned_by_current_channel(state: &InstallationState) -> bool {
    state.manager_channel.as_deref() == Some(product::PRODUCT_CHANNEL)
}

fn project_owned_by_current_channel(project_name: Option<&str>) -> bool {
    project_name.is_none_or(product::project_name_allowed)
}

fn is_recoverable_preparation_status(status: Option<&str>) -> bool {
    matches!(status, Some("failed" | "installing" | "prepared"))
}

fn has_canonical_active_release(active_release: Option<&str>) -> bool {
    active_release
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn is_recoverable_incomplete_preparation(
    status: Option<&str>,
    active_release: Option<&str>,
) -> bool {
    is_recoverable_preparation_status(status) && !has_canonical_active_release(active_release)
}

fn supervisor_runtime_summary_eligible(
    operational: bool,
    archived: bool,
    active_release: Option<&str>,
) -> bool {
    !archived && (operational || has_canonical_active_release(active_release))
}

fn is_operational_installation(installed: bool, status: Option<&str>) -> bool {
    installed && matches!(status, None | Some("running" | "stopped"))
}

fn is_reconfigurable_installation(path: &Path, existing: &InstallationState) -> bool {
    let runtime = active_runtime_dir(path).unwrap_or_else(|_| path.to_path_buf());
    existing.installed
        && (existing.operational || existing.recoverable_incomplete_preparation)
        && path.join("node.env").is_file()
        && runtime.join("compose.yml").is_file()
}

fn incomplete_commission_resume_allowed(
    existing: &InstallationState,
    install_dir: &Path,
    bootstrap_deployment_id: &str,
) -> Result<bool, String> {
    if !existing.recoverable_incomplete_preparation {
        return Ok(false);
    }
    if existing.deployment_id.as_deref() != Some(bootstrap_deployment_id) {
        return Err(
            "Existe una preparacion incompleta de otro despliegue. Archivela de forma segura antes de continuar."
                .to_string(),
        );
    }
    if !installation_owned_by_current_channel(existing) {
        return Err(format!(
            "La instalacion pertenece a otro canal y {} no puede reanudarla.",
            product::display_name()
        ));
    }
    if existing.operational {
        return Err(
            "El destino mezcla preparacion incompleta con un nodo operativo; el retry queda bloqueado."
                .to_string(),
        );
    }
    if existing
        .installation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(
            "La preparacion incompleta no conserva installationId; el retry queda bloqueado."
                .to_string(),
        );
    }
    if existing
        .active_release
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        return Err(
            "El destino conserva una release activa; no se reanuda commissioning inicial."
                .to_string(),
        );
    }
    if matches!(
        existing.promotion_status.as_deref(),
        Some("promoting" | "recovery_pending" | "manual_intervention_required")
    ) {
        return Err(
            "El estado de promocion es ambiguo; no se reanuda commissioning inicial.".to_string(),
        );
    }
    if install_dir.join("compose.yml").is_file() {
        return Err("El destino ya tiene Compose; use las operaciones del nodo.".to_string());
    }
    if let Ok(runtime) = active_runtime_dir(install_dir) {
        if runtime != install_dir && runtime.join("compose.yml").is_file() {
            return Err(
                "Existe un runtime con Compose; no se reanuda commissioning inicial.".to_string(),
            );
        }
    }
    Ok(true)
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
            Some((key.trim().to_string(), value.to_string()))
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

fn split_profiles(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

use safety::{path_identity, path_is_within};

fn read_registry() -> NodeRegistry {
    fs::read_to_string(registry_path())
        .ok()
        .and_then(|contents| serde_json::from_str::<NodeRegistry>(&contents).ok())
        .unwrap_or(NodeRegistry {
            schema: 1,
            nodes: Vec::new(),
        })
}

fn path_allowed_for_current_channel(path: &Path) -> bool {
    safety::validated_descendant(path, &paths::authorized_nodes_root()).is_ok()
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
    if !path_allowed_for_current_channel(path) {
        return Err(format!(
            "El canal {} no puede registrar la ruta {} fuera de {}.",
            product::PRODUCT_CHANNEL,
            path.display(),
            paths::authorized_nodes_root().display()
        ));
    }
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

fn forget_node_path(path: &Path) -> Result<(), String> {
    let mut registry = read_registry();
    let identity = path_identity(path);
    registry
        .nodes
        .retain(|entry| path_identity(Path::new(&entry.install_dir)) != identity);
    write_registry(&registry)
}

fn replace_registered_node_path(source: &Path, target: &Path) -> Result<(), String> {
    if !path_allowed_for_current_channel(source) || !path_allowed_for_current_channel(target) {
        return Err("El reemplazo solicitado cruza la raiz autorizada del canal.".to_string());
    }
    let mut registry = read_registry();
    registry.schema = 1;
    let source_identity = path_identity(source);
    let target_identity = path_identity(target);
    registry.nodes.retain(|entry| {
        let identity = path_identity(Path::new(&entry.install_dir));
        identity != source_identity && identity != target_identity
    });
    registry.nodes.push(NodeRegistryEntry {
        install_dir: target.to_string_lossy().into_owned(),
        last_discovered_at_unix_seconds: now_marker_timestamp(),
    });
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
    if supervisor_client().is_some() {
        return runtimes;
    }
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
        let project_name = labels
            .get("com.docker.compose.project")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let path = PathBuf::from(working_dir);
        if !path_allowed_for_current_channel(&path)
            || !project_owned_by_current_channel(project_name)
        {
            continue;
        }
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
        } else if health == "starting" {
            runtime.1.starting_services += 1;
        }
        if runtime.1.project_name.is_none() {
            runtime.1.project_name = project_name.map(str::to_string);
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
        if path_allowed_for_current_channel(&path) {
            candidates.insert(path_identity(&path), path);
        }
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
        if path_allowed_for_current_channel(path) {
            candidates.insert(identity.clone(), path.clone());
        }
    }

    let recovery_root = recovery_root_dir();
    let mut nodes = Vec::new();
    let mut remembered = Vec::new();
    for (identity, path) in candidates {
        if !path_allowed_for_current_channel(&path) {
            continue;
        }
        let state = inspect_path(&path);
        let runtime = runtimes.get(&identity).map(|value| &value.1);
        let registered = registry_identities.contains(&identity);
        if !state.installed && runtime.is_none() && !registered {
            continue;
        }
        if (state.installed || runtime.is_some()) && !installation_owned_by_current_channel(&state)
        {
            continue;
        }
        let archived = path_is_within(&path, &recovery_root);
        let project_name = state
            .config
            .get("ACTIUM_DATA_PLANE_PROJECT")
            .or_else(|| state.config.get("ACTIUM_PROJECT_NAME"))
            .cloned()
            .or_else(|| runtime.and_then(|value| value.project_name.clone()));
        if !project_owned_by_current_channel(project_name.as_deref()) {
            continue;
        }
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
        // La UI no inspecciona la release activa ni scripts dentro del
        // boundary privilegiado. Supervisor es la autoridad que valida
        // target, acción y payload al encolar/ejecutar la operación.
        let can_manage = state.operational
            && !archived
            && supervisor_client()
                .is_some_and(|client| supervisor_handshake(&client).compatible);
        nodes.push(ManagedNode {
            key,
            install_dir: path.to_string_lossy().into_owned(),
            display_name,
            project_name,
            deployment_id: state.deployment_id.clone(),
            deployment_code: state.deployment_code.clone(),
            installation_id: state.installation_id.clone(),
            version: state.version.clone(),
            active_release: state.active_release.clone(),
            release_digest: state.release_digest.clone(),
            payload_schema: state.payload_schema,
            promotion_status: state.promotion_status.clone(),
            profiles: state.profiles.clone(),
            status,
            operational: state.operational,
            recoverable: state.recoverable_incomplete_preparation,
            archived,
            can_manage,
            last_error: state.last_error.clone(),
            total_services: runtime.map_or(0, |value| value.total_services),
            running_services: runtime.map_or(0, |value| value.running_services),
            starting_services: runtime.map_or(0, |value| value.starting_services),
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
            connectivity_sync_enabled: state
                .config
                .get("CONNECTIVITY_SYNC_ENABLED")
                .is_some_and(|value| value.eq_ignore_ascii_case("true")),
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
            connectivity_edge_enrollment_token_configured: path
                .join("secrets/connectivity_edge_enrollment_token")
                .is_file(),
            connectivity_internal_relay_token_configured: path
                .join("secrets/connectivity_internal_relay_token")
                .is_file(),
            connectivity_preferred_transport: state
                .config
                .get("CONNECTIVITY_PREFERRED_TRANSPORT")
                .cloned(),
            connectivity_allowed_transports: state
                .config
                .get("CONNECTIVITY_ALLOWED_TRANSPORTS")
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            connectivity_gateway_strategy: state
                .config
                .get("CONNECTIVITY_GATEWAY_STRATEGY")
                .cloned(),
            connectivity_roaming_allowed: state
                .config
                .get("CONNECTIVITY_ROAMING_ALLOWED")
                .map(|value| value.eq_ignore_ascii_case("true")),
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
fn get_system_info(
    app: AppHandle,
    backend: tauri::State<'_, OperationBackend>,
) -> Result<SystemInfo, String> {
    let payload = payload_dir(&app)?;
    let (dependency_install_supported, dependency_message) = dependency_support();
    let data_plane_release_version = read_trimmed(&payload.join("VERSION"))
        .unwrap_or_else(|| product::DATA_PLANE_RELEASE_VERSION.to_string());
    let (release_supported_profiles, release_supported_features) = match verify_payload(&payload)? {
        VerifiedPayload::Schema3(manifest) => {
            (manifest.supported_profiles, manifest.supported_features)
        }
        VerifiedPayload::LegacyUnverified { .. } => (Vec::new(), Vec::new()),
    };
    let supervisor_compatibility = backend
        .supervisor
        .as_ref()
        .map(supervisor_handshake)
        .unwrap_or_else(|| evaluate_supervisor_compatibility(Err("Supervisor no construido.")));
    let network_addresses = backend
        .supervisor
        .as_ref()
        .and_then(|client| client.request(SupervisorCommand::NetworkInventory).ok())
        .and_then(|reply| match reply {
            SupervisorReply::NetworkInventory(addresses) => Some(addresses),
            _ => None,
        })
        .unwrap_or_default();
    let runtime_accessible =
        supervisor_compatibility.compatible || command_succeeds("docker", &["info"]);
    Ok(SystemInfo {
        product_display_name: product::display_name().to_string(),
        product_channel: product::PRODUCT_CHANNEL.to_string(),
        node_manager_version: product::manager_version().to_string(),
        data_plane_release_version: data_plane_release_version.clone(),
        payload_schema_version: product::PAYLOAD_SCHEMA_VERSION,
        site_runtime_schema_version: product::SITE_RUNTIME_SCHEMA_VERSION.to_string(),
        legacy_product_aliases: product::LEGACY_PRODUCT_ALIASES
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        platform: env::consts::OS.to_string(),
        architecture: env::consts::ARCH.to_string(),
        default_install_dir: default_install_dir().to_string_lossy().into_owned(),
        docker_cli: command_exists("docker"),
        docker_daemon: runtime_accessible,
        compose_v2: supervisor_compatibility.compatible
            || command_succeeds("docker", &["compose", "version"]),
        dependency_install_supported,
        dependency_message,
        payload_version: data_plane_release_version,
        release_supported_profiles,
        release_supported_features,
        suggested_public_base_url: suggested_public_base_url(),
        managed_nodes_dir: managed_nodes_dir().to_string_lossy().into_owned(),
        authorized_nodes_root: paths::authorized_nodes_root()
            .to_string_lossy()
            .into_owned(),
        default_network_ports: product_default_network_port_plan(),
        execution_backend: backend.name().to_string(),
        supervisor_available: supervisor_compatibility.observed_version.is_some(),
        supervisor_compatible: supervisor_compatibility.compatible,
        supervisor_version: supervisor_compatibility.observed_version.clone(),
        node_supervisor_version: product::NODE_SUPERVISOR_VERSION.to_string(),
        supervisor_recovered_operations: supervisor_compatibility.recovered_operations,
        supervisor_observed_protocol: supervisor_compatibility.observed_protocol,
        supervisor_required_protocol: supervisor_compatibility.required_protocol,
        supervisor_observed_features: supervisor_compatibility.observed_features.clone(),
        supervisor_required_features: supervisor_compatibility.required_features.clone(),
        supervisor_compatibility_reason: supervisor_compatibility.reason.clone(),
        network_addresses,
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
async fn list_managed_nodes(
    backend: tauri::State<'_, OperationBackend>,
) -> Result<Vec<ManagedNode>, String> {
    let supervisor = backend.supervisor.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut nodes = discover_managed_nodes()?;
        if let Some(client) = supervisor {
            for node in &mut nodes {
                if !supervisor_runtime_summary_eligible(
                    node.operational,
                    node.archived,
                    node.active_release.as_deref(),
                ) {
                    continue;
                }
                match client.request(SupervisorCommand::NodeRuntimeSummary {
                    install_dir: node.install_dir.clone(),
                }) {
                    Ok(SupervisorReply::NodeRuntimeSummary(runtime)) => {
                        node.project_name = Some(runtime.project_name);
                        node.total_services = runtime.total_services;
                        node.running_services = runtime.running_services;
                        node.starting_services = runtime.starting_services;
                        node.unhealthy_services = runtime.unhealthy_services;
                    }
                    Ok(_) | Err(_) => {}
                }
            }
        }
        Ok(nodes)
    })
    .await
    .map_err(|error| format!("La deteccion local de nodos fallo: {error}"))?
}

#[tauri::command]
async fn runtime_unit_inventory(
    request: RuntimeUnitInventoryRequest,
    backend: tauri::State<'_, OperationBackend>,
) -> Result<RuntimeUnitInventory, String> {
    let client = backend
        .supervisor
        .clone()
        .ok_or_else(|| "Runtime units requieren Actium Node Supervisor compatible.".to_string())?;
    let install_dir = validated_install_path(&request.install_dir)?;
    tauri::async_runtime::spawn_blocking(move || {
        match client.request(SupervisorCommand::RuntimeUnitInventory {
            install_dir: install_dir.to_string_lossy().into_owned(),
        })? {
            SupervisorReply::RuntimeUnitInventory(inventory) => Ok(inventory),
            _ => Err("Supervisor devolvio un inventario de runtime units inesperado.".to_string()),
        }
    })
    .await
    .map_err(|error| format!("No se pudo consultar runtime units: {error}"))?
}

#[tauri::command]
async fn execute_runtime_unit(
    request: RuntimeUnitCommandRequest,
    backend: tauri::State<'_, OperationBackend>,
) -> Result<actium_node_core::RuntimeActionResult, String> {
    let client = backend
        .supervisor
        .clone()
        .ok_or_else(|| "Runtime units requieren Actium Node Supervisor compatible.".to_string())?;
    let install_dir = validated_install_path(&request.install_dir)?;
    let runtime_unit_id = Uuid::parse_str(request.runtime_unit_id.trim())
        .map_err(|_| "runtimeUnitId invalido.".to_string())?
        .to_string();
    if !matches!(
        request.action.as_str(),
        "status" | "start" | "stop" | "restart" | "logs" | "update" | "verify"
    ) {
        return Err("Accion de runtime unit no permitida.".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        match client.request(SupervisorCommand::ExecuteRuntimeUnit(
            RuntimeUnitActionRequest {
                install_dir: install_dir.to_string_lossy().into_owned(),
                runtime_unit_id,
                action: request.action,
            },
        ))? {
            SupervisorReply::RuntimeAction(result) => Ok(result),
            _ => Err("Supervisor devolvio una accion de runtime unit inesperada.".to_string()),
        }
    })
    .await
    .map_err(|error| format!("No se pudo operar runtime unit: {error}"))?
}

#[tauri::command]
async fn suggest_installation_target(
    request: BootstrapRequest,
) -> Result<InstallationTarget, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let bootstrap = validate_bootstrap_jws(&request.bootstrap_jws)?;
        let nodes = discover_managed_nodes()?;
        let matches = nodes
            .iter()
            .filter(|node| node.deployment_id.as_deref() == Some(bootstrap.deployment_id.as_str()))
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(format!(
                "ADPE_TARGET_AMBIGUOUS: hay {} destinos locales para deploymentId {}.",
                matches.len(),
                bootstrap.deployment_id
            ));
        }
        if let Some(node) = matches.into_iter().next() {
            let path = validated_install_path(&node.install_dir)?;
            return Ok(InstallationTarget {
                install_dir: node.install_dir.clone(),
                matched_existing: true,
                installation: inspect_path(&path),
            });
        }

        let target = managed_nodes_dir().join(safe_archive_fragment(&bootstrap.deployment_code));
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
    if product::is_lab() {
        safety::validated_descendant(&path, &paths::authorized_nodes_root()).map_err(|error| {
            format!(
                "El canal Lab solo administra descendientes de {}. {error}",
                paths::authorized_nodes_root().display()
            )
        })
    } else {
        Ok(path)
    }
}

fn validate_request(
    request: &InstallRequest,
    existing: &InstallationState,
    payload_manifest: Option<&PayloadManifestV3>,
) -> Result<(Vec<String>, BootstrapClaims), String> {
    let bootstrap = validate_bootstrap_jws(&request.bootstrap_jws)?;
    validate_runtime_capabilities_against_payload(&bootstrap, payload_manifest)?;
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
    for (profile, feature) in [
        ("people", "people_runtime_v1"),
        ("control", "control_runtime_v1"),
    ] {
        if request.profiles.iter().any(|value| value == profile)
            && (!product::RELEASE_SUPPORTED_PROFILES.contains(&profile)
                || !product::RELEASE_SUPPORTED_FEATURES.contains(&feature))
        {
            return Err(format!(
                "RUNTIME_RELEASE_PROFILE_UNSUPPORTED: {} no soporta {profile}/{feature}.",
                product::DATA_PLANE_RELEASE_VERSION
            ));
        }
    }
    let mut profiles = BTreeSet::new();
    let existing_profiles = if existing.operational || existing.recoverable_incomplete_preparation {
        existing.profiles.as_slice()
    } else {
        &[]
    };
    if existing.recoverable_incomplete_preparation {
        assert_resume_profiles(&existing.profiles, &request.profiles, &bootstrap.profiles)?;
    }
    for profile in existing_profiles.iter().chain(request.profiles.iter()) {
        if !KNOWN_PROFILES.contains(&profile.as_str()) {
            return Err(format!("Perfil desconocido: {profile}."));
        }
        if !existing_profiles.contains(profile) && !is_profile_authorized_rust(profile, &bootstrap.profiles) {
            return Err(format!(
                "El perfil {profile} no fue autorizado por el paquete .adpe."
            ));
        }
        profiles.insert(profile.clone());
    }
    if let Some(path) = request.node_root_path.as_deref().filter(|p| !p.trim().is_empty()) {
        validate_custom_storage_path("directorio raíz del nodo", path)?;
    }
    if profiles.contains("site-core") {
        if let Some(path) = request.site_core_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de datos Site Core", path)?;
        }
    }
    if profiles.contains("telemetry") {
        if let Some(path) = request.telemetry_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de telemetría", path)?;
        }
        if let Some(path) = request.dvr_media_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de medios DVR", path)?;
        }
    }
    if profiles.contains("people") {
        if let Some(path) = request.people_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de datos People", path)?;
        }
    }
    if profiles.contains("control") {
        if let Some(path) = request.control_runtime_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de datos Control Runtime", path)?;
        }
    }
    if profiles.contains("radio-control") {
        if let Some(path) = request.radio_control_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de datos HT Radio", path)?;
        }
    }
    if profiles.contains("radio-saf") {
        validate_radio_archive_path(&request.radio_archive_host_path)?;
        if let Some(path) = request.radio_saf_storage_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de almacenamiento Store & Forward", path)?;
        }
    }
    if profiles.contains("radio-turn") {
        if let Some(path) = request.turn_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de datos TURN", path)?;
        }
        if request.turn_realm.trim().is_empty() {
            return Err("TURN requiere un realm o dominio publico.".to_string());
        }
    }
    if profiles.contains("radio-livekit") {
        if let Some(path) = request.livekit_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de datos LiveKit", path)?;
        }
        if request.livekit_node_ip.trim().is_empty() {
            return Err("LiveKit requiere la IP anunciada del nodo.".to_string());
        }
        if !request.livekit_public_url.trim().starts_with("wss://") {
            return Err("La URL publica de LiveKit debe usar wss://.".to_string());
        }
    }
    if profiles.contains("observability") {
        if let Some(path) = request.prometheus_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de TSDB Prometheus", path)?;
        }
        if let Some(path) = request.grafana_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de Grafana Dashboards", path)?;
        }
    }
    if profiles.contains("connectivity") {
        if let Some(path) = request.connectivity_spool_path.as_deref().filter(|p| !p.trim().is_empty()) {
            validate_custom_storage_path("ruta de spool Connectivity", path)?;
        }
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
    network_port_claims(
        &profiles.iter().cloned().collect::<Vec<_>>(),
        &install_port_plan(request),
    )?;
    if !request.public_base_url.starts_with("http://")
        && !request.public_base_url.starts_with("https://")
    {
        return Err("La URL accesible del nodo debe usar http:// o https://.".to_string());
    }
    validate_network_policy(
        &request.network_mode,
        &request.bind_address,
        &request.public_base_url,
    )?;
    validate_network_reconciliation(
        &request.network_reconciliation_policy,
        &request.network_interface,
        &request.network_address,
        &request.network_plane,
        request.network_priority,
    )?;
    if !is_host_code(&request.project_name) {
        return Err(
            "El nombre tecnico debe tener 3 a 80 caracteres: a-z, 0-9, punto, guion o guion bajo."
                .to_string(),
        );
    }
    let mut env_checks = vec![
        ("nombre de proyecto", request.project_name.as_str()),
        ("direccion de escucha", request.bind_address.as_str()),
        ("URL accesible del nodo", request.public_base_url.as_str()),
        ("origenes CORS", request.cors_origins.as_str()),
    ];
    if profiles.contains("radio-turn") {
        env_checks.extend([
            ("realm TURN", request.turn_realm.as_str()),
            ("IP TURN", request.turn_external_ip.as_str()),
        ]);
    }
    if profiles.contains("radio-livekit") {
        env_checks.extend([
            ("IP LiveKit", request.livekit_node_ip.as_str()),
            ("URL LiveKit", request.livekit_public_url.as_str()),
        ]);
    }
    if profiles.contains("radio-saf") {
        env_checks.push((
            "ruta del archivo Radio HT",
            request.radio_archive_host_path.as_str(),
        ));
    }
    if profiles.contains("connectivity") {
        env_checks.extend([
            (
                "URL Connectivity Edge",
                request.connectivity_edge_control_url.as_str(),
            ),
            ("rol Connectivity", request.connectivity_node_role.as_str()),
        ]);
    }
    for (label, value) in env_checks {
        validate_env_value(label, value)?;
    }
    Ok((profiles.into_iter().collect(), bootstrap))
}

fn install_port_plan(request: &InstallRequest) -> NetworkPortPlan {
    NetworkPortPlan {
        telemetry_port: request.telemetry_port,
        people_port: request.people_port,
        control_runtime_port: request.control_runtime_port,
        radio_control_port: request.radio_control_port,
        radio_saf_port: request.radio_saf_port,
        site_core_port: request.site_core_port,
        prometheus_port: request.prometheus_port,
        grafana_port: request.grafana_port,
        turn_port: request.turn_port,
        turn_tls_port: request.turn_tls_port,
        turn_min_port: request.turn_min_port,
        turn_max_port: request.turn_max_port,
        livekit_http_port: request.livekit_http_port,
        livekit_rtc_tcp_port: request.livekit_rtc_tcp_port,
        livekit_udp_min_port: request.livekit_udp_min_port,
        livekit_udp_max_port: request.livekit_udp_max_port,
    }
}

fn configuration_port_plan(request: &NodeConfigurationRequest) -> NetworkPortPlan {
    NetworkPortPlan {
        telemetry_port: request.telemetry_port,
        people_port: request.people_port,
        control_runtime_port: request.control_runtime_port,
        radio_control_port: request.radio_control_port,
        radio_saf_port: request.radio_saf_port,
        site_core_port: request.site_core_port,
        prometheus_port: request.prometheus_port,
        grafana_port: request.grafana_port,
        turn_port: request.turn_port,
        turn_tls_port: request.turn_tls_port,
        turn_min_port: request.turn_min_port,
        turn_max_port: request.turn_max_port,
        livekit_http_port: request.livekit_http_port,
        livekit_rtc_tcp_port: request.livekit_rtc_tcp_port,
        livekit_udp_min_port: request.livekit_udp_min_port,
        livekit_udp_max_port: request.livekit_udp_max_port,
    }
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

fn normalize_profile_name(name: &str) -> String {
    let code = name.trim().to_lowercase().replace('_', "-");
    match code.as_str() {
        "site-core" | "sitecore" | "site" => "site-core".to_string(),
        "telemetry" | "gps" | "dvr" => "telemetry".to_string(),
        "people" => "people".to_string(),
        "control" => "control".to_string(),
        "radio" | "radio-control" | "ht" => "radio-control".to_string(),
        "radio-saf" | "saf" => "radio-saf".to_string(),
        "radio-turn" | "turn" => "radio-turn".to_string(),
        "radio-livekit" | "livekit" => "radio-livekit".to_string(),
        "observability" | "metrics" | "sre" => "observability".to_string(),
        "connectivity" | "sync" => "connectivity".to_string(),
        _ => code,
    }
}

fn is_profile_authorized_rust(profile: &str, authorized: &[String]) -> bool {
    let normalized = normalize_profile_name(profile);
    authorized.iter().any(|p| normalize_profile_name(p) == normalized)
}

fn validate_env_value(label: &str, value: &str) -> Result<(), String> {
    if value.contains('\n') || value.contains('\r') {
        return Err(format!("{label} contiene saltos de linea no permitidos."));
    }
    Ok(())
}

fn validate_custom_storage_path(label: &str, value: &str) -> Result<PathBuf, String> {
    validate_env_value(label, value)?;
    if value.contains('=') || value.contains('#') {
        return Err(format!("{label} no admite = ni #."));
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} no puede estar vacia."));
    }
    let path = PathBuf::from(trimmed);
    if !path.is_absolute() || path.parent().is_none() {
        return Err(format!("{label} debe ser una ruta absoluta y no puede ser la raiz del sistema."));
    }
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("{label} no admite traversal (..)."));
    }
    if actium_node_core::is_dangerous_system_path(&path) {
        return Err(format!("La ruta {trimmed} para {label} es una ruta reservada o peligrosa del sistema."));
    }
    Ok(path)
}

fn ensure_custom_storage_directory(label: &str, value: &str) -> Result<(), String> {
    let path = validate_custom_storage_path(label, value)?;
    if !path.exists() {
        if let Err(error) = fs::create_dir_all(&path) {
            if supervisor_client().is_some() {
                return Ok(());
            }
            return Err(format!("No se pudo crear el directorio de {label} en {}: {error}", path.display()));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o775));
    }
    let probe = path.join(format!(".actium-write-test-{}", uuid::Uuid::new_v4()));
    if let Err(error) = fs::write(&probe, b"actium-storage-test") {
        if supervisor_client().is_none() {
            return Err(format!("El directorio de {label} en {} no permite escritura: {error}", path.display()));
        }
    } else {
        let _ = fs::remove_file(&probe);
    }
    Ok(())
}

fn ensure_custom_storage_directory_if_external(
    label: &str,
    value: &str,
    install_dir: &Path,
) -> Result<(), String> {
    let path = Path::new(value.trim());
    if path_is_within(path, install_dir) {
        return Ok(());
    }
    ensure_custom_storage_directory(label, value)
}

fn validate_radio_archive_path(value: &str) -> Result<PathBuf, String> {
    validate_env_value("ruta del archivo Radio HT", value)?;
    if value.contains('=') || value.contains('#') {
        return Err("La ruta del archivo Radio HT no admite = ni #.".to_string());
    }
    let path = PathBuf::from(value.trim());
    if value.trim().is_empty() || !path.is_absolute() || path.parent().is_none() {
        return Err(
            "La ruta del archivo Radio HT debe ser absoluta y no puede ser la raiz del sistema."
                .to_string(),
        );
    }
    if actium_node_core::is_dangerous_system_path(&path) {
        return Err(format!("La ruta {} para archivo Radio HT es una ruta reservada o peligrosa del sistema.", value.trim()));
    }
    Ok(path)
}

fn ensure_radio_archive_directory(value: &str) -> Result<(), String> {
    let path = validate_radio_archive_path(value)?;
    fs::create_dir_all(&path).map_err(|error| {
        format!(
            "No se pudo crear el archivo Radio HT en {}: {error}",
            path.display()
        )
    })?;
    let probe = path.join(format!(".actium-write-test-{}", uuid::Uuid::new_v4()));
    fs::write(&probe, b"actium-radio-archive")
        .map_err(|error| format!("La ruta del archivo Radio HT no permite escritura: {error}"))?;
    fs::remove_file(&probe).map_err(|error| {
        format!("No se pudo completar la prueba de la ruta del archivo Radio HT: {error}")
    })?;
    Ok(())
}

fn validate_network_policy(
    mode: &str,
    bind_address: &str,
    public_base_url: &str,
) -> Result<(), String> {
    if !matches!(mode, "local_only" | "trusted_lan" | "stable_vpn") {
        return Err("El modo de red debe ser local_only, trusted_lan o stable_vpn.".to_string());
    }
    let loopback_url = is_loopback_http_url(public_base_url);
    if mode == "local_only" && (bind_address.trim() != "127.0.0.1" || !loopback_url) {
        return Err(
            "El modo Solo este equipo debe escuchar y publicarse exclusivamente por loopback."
                .to_string(),
        );
    }
    if mode == "stable_vpn" && loopback_url {
        return Err("El modo VPN estable requiere una URL o IP de VPN no local.".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PortTransport {
    Tcp,
    Udp,
}

fn add_port_claim(
    claims: &mut BTreeMap<(PortTransport, u16), &'static str>,
    transport: PortTransport,
    port: u16,
    label: &'static str,
) -> Result<(), String> {
    if port == 0 {
        return Err(format!("{label} debe estar entre 1 y 65535."));
    }
    if let Some(previous) = claims.insert((transport, port), label) {
        return Err(format!(
            "El puerto {port}/{} esta asignado a {previous} y {label}.",
            match transport {
                PortTransport::Tcp => "TCP",
                PortTransport::Udp => "UDP",
            }
        ));
    }
    Ok(())
}

fn network_port_claims(
    profiles: &[String],
    plan: &NetworkPortPlan,
) -> Result<BTreeMap<(PortTransport, u16), &'static str>, String> {
    let selected = |profile: &str| profiles.iter().any(|value| value == profile);
    let mut claims = BTreeMap::new();
    if selected("telemetry") || selected("connectivity") {
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.telemetry_port,
            "GPS/DVR",
        )?;
    }
    if selected("people") {
        add_port_claim(&mut claims, PortTransport::Tcp, plan.people_port, "People")?;
    }
    if selected("control") {
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.control_runtime_port,
            "Control Runtime",
        )?;
    }
    if selected("site-core") {
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.site_core_port,
            "Site Core",
        )?;
    }
    if selected("radio-control") {
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.radio_control_port,
            "HT control",
        )?;
    }
    if selected("radio-saf") {
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.radio_saf_port,
            "Radio S&F",
        )?;
    }
    if selected("observability") {
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.prometheus_port,
            "Prometheus",
        )?;
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.grafana_port,
            "Grafana",
        )?;
    }
    if selected("radio-turn") {
        add_port_claim(&mut claims, PortTransport::Tcp, plan.turn_port, "TURN")?;
        add_port_claim(&mut claims, PortTransport::Udp, plan.turn_port, "TURN")?;
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.turn_tls_port,
            "TURN TLS",
        )?;
        if plan.turn_min_port > plan.turn_max_port {
            return Err("El rango TURN debe usar puertos validos y ordenados.".to_string());
        }
        for port in plan.turn_min_port..=plan.turn_max_port {
            add_port_claim(&mut claims, PortTransport::Udp, port, "TURN relay")?;
        }
    }
    if selected("radio-livekit") {
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.livekit_http_port,
            "LiveKit HTTP",
        )?;
        add_port_claim(
            &mut claims,
            PortTransport::Tcp,
            plan.livekit_rtc_tcp_port,
            "LiveKit RTC",
        )?;
        if plan.livekit_udp_min_port > plan.livekit_udp_max_port {
            return Err("El rango UDP LiveKit debe usar puertos validos y ordenados.".to_string());
        }
        for port in plan.livekit_udp_min_port..=plan.livekit_udp_max_port {
            add_port_claim(&mut claims, PortTransport::Udp, port, "LiveKit RTC")?;
        }
    }
    Ok(claims)
}

fn tcp_port_available(port: u16) -> bool {
    TcpListener::bind(("0.0.0.0", port)).is_ok()
}

fn udp_port_available(port: u16) -> bool {
    UdpSocket::bind(("0.0.0.0", port)).is_ok()
}

fn parse_excluded_udp_port_ranges(contents: &str) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for line in contents.lines() {
        let range = line
            .split_whitespace()
            .filter_map(|value| value.parse::<u16>().ok())
            .take(2)
            .collect::<Vec<_>>();
        let [start, end] = range.as_slice() else {
            continue;
        };
        if start <= end {
            ports.extend(*start..=*end);
        }
    }
    ports
}

#[cfg(target_os = "windows")]
fn system_reserved_udp_ports() -> Result<BTreeSet<u16>, String> {
    let mut reserved = BTreeSet::new();
    for family in ["ipv4", "ipv6"] {
        let output = Command::new("netsh")
            .args([
                "interface",
                family,
                "show",
                "excludedportrange",
                "protocol=udp",
            ])
            .output()
            .map_err(|error| {
                format!(
                    "No se pudieron consultar los puertos UDP reservados por Windows ({family}): {error}"
                )
            })?;
        if !output.status.success() {
            return Err(format!(
                "Windows no devolvio los puertos UDP reservados ({family}): {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        reserved.extend(parse_excluded_udp_port_ranges(&String::from_utf8_lossy(
            &output.stdout,
        )));
    }
    Ok(reserved)
}

#[cfg(not(target_os = "windows"))]
fn system_reserved_udp_ports() -> Result<BTreeSet<u16>, String> {
    Ok(BTreeSet::new())
}

fn find_tcp_port(start: u16, reserved: &BTreeSet<u16>) -> Result<u16, String> {
    (u32::from(start)..=u32::from(u16::MAX))
        .map(|value| value as u16)
        .find(|port| !reserved.contains(port) && tcp_port_available(*port))
        .ok_or_else(|| format!("No se encontro un puerto TCP libre desde {start}."))
}

fn find_dual_port(
    start: u16,
    reserved_tcp: &BTreeSet<u16>,
    reserved_udp: &BTreeSet<u16>,
) -> Result<u16, String> {
    (u32::from(start)..=u32::from(u16::MAX))
        .map(|value| value as u16)
        .find(|port| {
            !reserved_tcp.contains(port)
                && !reserved_udp.contains(port)
                && tcp_port_available(*port)
                && udp_port_available(*port)
        })
        .ok_or_else(|| format!("No se encontro un puerto TCP/UDP libre desde {start}."))
}

fn find_udp_range(start: u16, length: u16, reserved: &BTreeSet<u16>) -> Result<(u16, u16), String> {
    let mut candidate = u32::from(start);
    let length = u32::from(length);
    while candidate + length - 1 <= u32::from(u16::MAX) {
        let end = candidate + length - 1;
        let available = (candidate..=end).all(|value| {
            let port = value as u16;
            !reserved.contains(&port) && udp_port_available(port)
        });
        if available {
            return Ok((candidate as u16, end as u16));
        }
        candidate = end + 1;
    }
    Err(format!(
        "No se encontro un rango UDP libre de {length} puertos desde {start}."
    ))
}

fn configured_port_reservations(
    excluded_path: Option<&Path>,
) -> Result<BTreeMap<(PortTransport, u16), String>, String> {
    let excluded_identity = excluded_path.map(path_identity);
    let mut reservations = BTreeMap::new();
    for node in discover_managed_nodes()? {
        let path = PathBuf::from(&node.install_dir);
        if excluded_identity
            .as_ref()
            .is_some_and(|identity| *identity == path_identity(&path))
        {
            continue;
        }
        let state = inspect_path(&path);
        if !state.installed {
            continue;
        }
        for (claim, label) in network_port_claims(
            &state.profiles,
            &configured_network_port_plan(&state.config),
        )? {
            reservations
                .entry(claim)
                .or_insert_with(|| format!("{} ({label})", node.display_name));
        }
    }
    Ok(reservations)
}

fn reserved_port_sets(
    reservations: &BTreeMap<(PortTransport, u16), String>,
) -> (BTreeSet<u16>, BTreeSet<u16>) {
    let mut reserved_tcp = BTreeSet::new();
    let mut reserved_udp = BTreeSet::new();
    for (transport, port) in reservations.keys() {
        match transport {
            PortTransport::Tcp => {
                reserved_tcp.insert(*port);
            }
            PortTransport::Udp => {
                reserved_udp.insert(*port);
            }
        }
    }
    (reserved_tcp, reserved_udp)
}

fn suggest_available_network_ports(
    profiles: &[String],
    excluded_path: Option<&Path>,
) -> Result<NetworkPortPlan, String> {
    let reservations = configured_port_reservations(excluded_path)?;
    let (mut reserved_tcp, mut reserved_udp) = reserved_port_sets(&reservations);
    reserved_udp.extend(system_reserved_udp_ports()?);

    let active = active_port_keys(profiles);
    let mut allocate_tcp = |preferred: u16, key: &str| -> Result<u16, String> {
        if !active.contains(key) {
            return Ok(preferred);
        }
        let port = find_tcp_port(preferred, &reserved_tcp)?;
        reserved_tcp.insert(port);
        Ok(port)
    };
    let telemetry_port = allocate_tcp(product::TELEMETRY_PORT, "TELEMETRY_PORT")?;
    let people_port = allocate_tcp(product::PEOPLE_PORT, "PEOPLE_PORT")?;
    let control_runtime_port =
        allocate_tcp(product::CONTROL_RUNTIME_PORT, "CONTROL_RUNTIME_PORT")?;
    let radio_control_port = allocate_tcp(product::RADIO_CONTROL_PORT, "RADIO_CONTROL_PORT")?;
    let radio_saf_port = allocate_tcp(product::RADIO_SAF_PORT, "RADIO_SAF_PORT")?;
    let site_core_port = allocate_tcp(product::SITE_CORE_PORT, "SITE_CORE_PORT")?;
    let prometheus_port = allocate_tcp(product::PROMETHEUS_PORT, "PROMETHEUS_PORT")?;
    let grafana_port = allocate_tcp(product::GRAFANA_PORT, "GRAFANA_PORT")?;

    let selected = |profile: &str| effective_profiles(profiles).contains(profile);
    let mut turn_port = product::TURN_PORT;
    let mut turn_tls_port = product::TURN_TLS_PORT;
    let mut turn_min_port = product::TURN_MIN_PORT;
    let mut turn_max_port = product::TURN_MAX_PORT;
    if selected("radio-turn") {
        turn_port = find_dual_port(product::TURN_PORT, &reserved_tcp, &reserved_udp)?;
        reserved_tcp.insert(turn_port);
        reserved_udp.insert(turn_port);
        turn_tls_port = find_tcp_port(product::TURN_TLS_PORT, &reserved_tcp)?;
        reserved_tcp.insert(turn_tls_port);
        (turn_min_port, turn_max_port) = find_udp_range(product::TURN_MIN_PORT, 41, &reserved_udp)?;
        reserved_udp.extend(turn_min_port..=turn_max_port);
    }

    let mut livekit_http_port = product::LIVEKIT_HTTP_PORT;
    let mut livekit_rtc_tcp_port = product::LIVEKIT_RTC_TCP_PORT;
    let mut livekit_udp_min_port = product::LIVEKIT_UDP_MIN_PORT;
    let mut livekit_udp_max_port = product::LIVEKIT_UDP_MAX_PORT;
    if selected("radio-livekit") {
        livekit_http_port = find_tcp_port(product::LIVEKIT_HTTP_PORT, &reserved_tcp)?;
        reserved_tcp.insert(livekit_http_port);
        livekit_rtc_tcp_port = find_tcp_port(product::LIVEKIT_RTC_TCP_PORT, &reserved_tcp)?;
        reserved_tcp.insert(livekit_rtc_tcp_port);
        (livekit_udp_min_port, livekit_udp_max_port) =
            find_udp_range(product::LIVEKIT_UDP_MIN_PORT, 101, &reserved_udp)?;
    }

    Ok(NetworkPortPlan {
        telemetry_port,
        people_port,
        control_runtime_port,
        radio_control_port,
        radio_saf_port,
        site_core_port,
        prometheus_port,
        grafana_port,
        turn_port,
        turn_tls_port,
        turn_min_port,
        turn_max_port,
        livekit_http_port,
        livekit_rtc_tcp_port,
        livekit_udp_min_port,
        livekit_udp_max_port,
    })
}

fn ensure_network_ports_available(
    profiles: &[String],
    plan: &NetworkPortPlan,
) -> Result<(), String> {
    let claims = network_port_claims(profiles, plan)?;
    let system_reserved_udp = system_reserved_udp_ports()?;
    let conflicts = claims
        .into_iter()
        .filter_map(|((transport, port), label)| {
            if transport == PortTransport::Udp && system_reserved_udp.contains(&port) {
                return Some(format!(
                    "{label} {port}/UDP reservado por Windows; Docker Desktop no puede publicarlo"
                ));
            }
            let available = match transport {
                PortTransport::Tcp => tcp_port_available(port),
                PortTransport::Udp => udp_port_available(port),
            };
            (!available).then(|| {
                format!(
                    "{label} {port}/{}",
                    match transport {
                        PortTransport::Tcp => "TCP",
                        PortTransport::Udp => "UDP",
                    }
                )
            })
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        return Ok(());
    }
    let visible = conflicts.iter().take(12).cloned().collect::<Vec<_>>();
    let suffix = if conflicts.len() > visible.len() {
        format!(" y {} conflicto(s) mas", conflicts.len() - visible.len())
    } else {
        String::new()
    };
    Err(format!(
        "Hay puertos ocupados antes de iniciar Docker: {}{suffix}. Use Asignar puertos libres y vuelva a validar.",
        visible.join(", ")
    ))
}

fn ensure_network_ports_available_for_existing_runtime(
    path: &Path,
    profiles: &[String],
    requested: &NetworkPortPlan,
    owned_plan: &NetworkPortPlan,
) -> Result<(), String> {
    let identity = path_identity(path);
    let owns_runtime = docker_node_runtimes()
        .get(&identity)
        .is_some_and(|(_, runtime)| {
            runtime.total_services > 0 && runtime.running_services == runtime.total_services
        });
    if !owns_runtime {
        return ensure_network_ports_available(profiles, requested);
    }

    let owned = network_port_claims(profiles, owned_plan)?;
    let requested_claims = network_port_claims(profiles, requested)?;
    let system_reserved_udp = system_reserved_udp_ports()?;
    let conflicts = requested_claims
        .into_iter()
        .filter(|(claim, _)| !owned.contains_key(claim))
        .filter_map(|((transport, port), label)| {
            if transport == PortTransport::Udp && system_reserved_udp.contains(&port) {
                return Some(format!(
                    "{label} {port}/UDP reservado por Windows; Docker Desktop no puede publicarlo"
                ));
            }
            let available = match transport {
                PortTransport::Tcp => tcp_port_available(port),
                PortTransport::Udp => udp_port_available(port),
            };
            (!available).then(|| {
                format!(
                    "{label} {port}/{}",
                    match transport {
                        PortTransport::Tcp => "TCP",
                        PortTransport::Udp => "UDP",
                    }
                )
            })
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "Los nuevos puertos entran en conflicto con procesos externos: {}.",
            conflicts
                .into_iter()
                .take(12)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

fn ensure_network_ports_unreserved(
    install_dir: &Path,
    profiles: &[String],
    plan: &NetworkPortPlan,
) -> Result<(), String> {
    let reservations = configured_port_reservations(Some(install_dir))?;
    let conflicts = network_port_claims(profiles, plan)?
        .into_iter()
        .filter_map(|((transport, port), label)| {
            reservations.get(&(transport, port)).map(|owner| {
                format!(
                    "{label} {port}/{} reservado por {owner}",
                    match transport {
                        PortTransport::Tcp => "TCP",
                        PortTransport::Udp => "UDP",
                    }
                )
            })
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        Ok(())
    } else {
        let visible = conflicts.iter().take(12).cloned().collect::<Vec<_>>();
        let suffix = if conflicts.len() > visible.len() {
            format!(" y {} conflicto(s) mas", conflicts.len() - visible.len())
        } else {
            String::new()
        };
        Err(format!(
            "La configuracion reutiliza puertos reservados por otros nodos, incluso si estan detenidos: {}{suffix}. Use Asignar puertos libres.",
            visible.join(", ")
        ))
    }
}

fn configured_port(config: &BTreeMap<String, String>, key: &str, fallback: u16) -> u16 {
    config
        .get(key)
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(fallback)
}

fn configured_network_port_plan(config: &BTreeMap<String, String>) -> NetworkPortPlan {
    NetworkPortPlan {
        telemetry_port: configured_port(config, "TELEMETRY_PORT", product::TELEMETRY_PORT),
        people_port: configured_port(config, "PEOPLE_PORT", product::PEOPLE_PORT),
        control_runtime_port: configured_port(
            config,
            "CONTROL_RUNTIME_PORT",
            product::CONTROL_RUNTIME_PORT,
        ),
        radio_control_port: configured_port(
            config,
            "RADIO_CONTROL_PORT",
            product::RADIO_CONTROL_PORT,
        ),
        radio_saf_port: configured_port(config, "RADIO_SAF_PORT", product::RADIO_SAF_PORT),
        site_core_port: configured_port(config, "SITE_CORE_PORT", product::SITE_CORE_PORT),
        prometheus_port: configured_port(config, "PROMETHEUS_PORT", product::PROMETHEUS_PORT),
        grafana_port: configured_port(config, "GRAFANA_PORT", product::GRAFANA_PORT),
        turn_port: configured_port(config, "TURN_PORT", product::TURN_PORT),
        turn_tls_port: configured_port(config, "TURN_TLS_PORT", product::TURN_TLS_PORT),
        turn_min_port: configured_port(config, "TURN_MIN_PORT", product::TURN_MIN_PORT),
        turn_max_port: configured_port(config, "TURN_MAX_PORT", product::TURN_MAX_PORT),
        livekit_http_port: configured_port(config, "LIVEKIT_HTTP_PORT", product::LIVEKIT_HTTP_PORT),
        livekit_rtc_tcp_port: configured_port(
            config,
            "LIVEKIT_RTC_TCP_PORT",
            product::LIVEKIT_RTC_TCP_PORT,
        ),
        livekit_udp_min_port: configured_port(
            config,
            "LIVEKIT_UDP_MIN_PORT",
            product::LIVEKIT_UDP_MIN_PORT,
        ),
        livekit_udp_max_port: configured_port(
            config,
            "LIVEKIT_UDP_MAX_PORT",
            product::LIVEKIT_UDP_MAX_PORT,
        ),
    }
}

fn ensure_changed_network_ports_available(
    existing: &InstallationState,
    requested: &NetworkPortPlan,
) -> Result<(), String> {
    let current = network_port_claims(
        &existing.profiles,
        &configured_network_port_plan(&existing.config),
    )?;
    let requested = network_port_claims(&existing.profiles, requested)?;
    let system_reserved_udp = system_reserved_udp_ports()?;
    let conflicts = requested
        .into_iter()
        .filter(|(claim, _)| !current.contains_key(claim))
        .filter_map(|((transport, port), label)| {
            if transport == PortTransport::Udp && system_reserved_udp.contains(&port) {
                return Some(format!(
                    "{label} {port}/UDP reservado por Windows; Docker Desktop no puede publicarlo"
                ));
            }
            let available = match transport {
                PortTransport::Tcp => tcp_port_available(port),
                PortTransport::Udp => udp_port_available(port),
            };
            (!available).then(|| {
                format!(
                    "{label} {port}/{}",
                    match transport {
                        PortTransport::Tcp => "TCP",
                        PortTransport::Udp => "UDP",
                    }
                )
            })
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "La nueva configuracion usa puertos ocupados: {}.",
            conflicts
                .into_iter()
                .take(12)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

#[tauri::command]
fn suggest_network_ports(request: PortSuggestionRequest) -> Result<NetworkPortPlan, String> {
    for profile in &request.profiles {
        if !KNOWN_PROFILES.contains(&profile.as_str()) {
            return Err(format!("Perfil desconocido: {profile}."));
        }
    }
    let excluded_path = request
        .install_dir
        .as_deref()
        .map(validated_install_path)
        .transpose()?;
    suggest_available_network_ports(&request.profiles, excluded_path.as_deref())
}

fn is_loopback_http_url(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    let authority_and_path = normalized
        .strip_prefix("http://")
        .or_else(|| normalized.strip_prefix("https://"));
    let Some(authority_and_path) = authority_and_path else {
        return false;
    };
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') {
        return false;
    }
    let host = authority.split(':').next().unwrap_or_default();
    matches!(host, "127.0.0.1" | "localhost")
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

fn validate_network_reconciliation(
    policy: &str,
    interface: &str,
    address: &str,
    plane: &str,
    priority: u16,
) -> Result<(), String> {
    if !matches!(
        policy.trim(),
        "manual" | "reconcile_on_operation" | "auto_on_interface_change"
    ) {
        return Err("Politica de reconciliacion de red desconocida.".to_string());
    }
    if !matches!(plane.trim(), "lan" | "vpn" | "wan" | "management") {
        return Err("El plano de red debe ser lan, vpn, wan o management.".to_string());
    }
    if priority > 1_000 {
        return Err("La prioridad de red debe estar entre 0 y 1000.".to_string());
    }
    if policy.trim() != "manual" {
        if interface.trim().is_empty() {
            return Err("La reconciliacion automatizada exige una interfaz explicita.".to_string());
        }
        address.trim().parse::<IpAddr>().map_err(|_| {
            "La reconciliacion automatizada exige una direccion IP explicita.".to_string()
        })?;
    }
    Ok(())
}

fn validate_node_configuration(
    request: &NodeConfigurationRequest,
    existing: &InstallationState,
    path: &Path,
) -> Result<(), String> {
    if !is_reconfigurable_installation(path, existing) {
        return Err(
            "Solo se puede configurar un nodo administrado que conserve node.env y Compose."
                .to_string(),
        );
    }
    if request.bind_address.trim().is_empty() {
        return Err("La direccion de escucha no puede quedar vacia.".to_string());
    }
    if !is_http_endpoint(&request.public_base_url, false) {
        return Err("La URL accesible del nodo debe usar http:// o https://.".to_string());
    }
    validate_network_policy(
        &request.network_mode,
        &request.bind_address,
        &request.public_base_url,
    )?;
    validate_network_reconciliation(
        &request.network_reconciliation_policy,
        &request.network_interface,
        &request.network_address,
        &request.network_plane,
        request.network_priority,
    )?;
    if request.cors_origins.trim().is_empty() {
        return Err("Defina al menos un origen CORS explicito.".to_string());
    }
    let has_profile = |name: &str| existing.profiles.iter().any(|profile| profile == name);
    let mut public_endpoints = Vec::new();
    if has_profile("telemetry") {
        public_endpoints.extend([
            (
                "Telemetry Ingress",
                request.telemetry_ingress_public_url.as_str(),
            ),
            ("Telemetry Read", request.telemetry_read_public_url.as_str()),
        ]);
    }
    if has_profile("observability") {
        public_endpoints.push(("metricas", request.metrics_public_url.as_str()));
    }
    if has_profile("radio-control") {
        public_endpoints.push(("Radio Control", request.radio_control_public_url.as_str()));
    }
    if has_profile("site-core") {
        public_endpoints.push(("Site Core", request.site_core_public_url.as_str()));
    }
    if has_profile("people") {
        public_endpoints.push(("People Resolve", request.people_resolve_public_url.as_str()));
    }
    if has_profile("control") {
        public_endpoints.push((
            "Control Runtime",
            request.control_runtime_public_url.as_str(),
        ));
    }
    for (label, value) in public_endpoints {
        if !value.trim().is_empty() && !is_http_endpoint(value, false) {
            return Err(format!("{label} debe usar una URL http:// o https://."));
        }
    }
    if has_profile("radio-turn")
        && request
            .turn_urls
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .any(|value| {
                !(value.starts_with("turn:") || value.starts_with("turns:"))
                    || value.chars().any(char::is_whitespace)
            })
    {
        return Err("Cada URL TURN debe usar turn: o turns:.".to_string());
    }
    if has_profile("radio-saf") {
        validate_radio_archive_path(&request.radio_archive_host_path)?;
    }
    network_port_claims(&existing.profiles, &configuration_port_plan(request))?;
    if has_profile("radio-turn") && request.turn_realm.trim().is_empty() {
        return Err("TURN requiere un realm o dominio publico.".to_string());
    }
    if has_profile("radio-livekit")
        && (request.livekit_node_ip.trim().is_empty()
            || !request.livekit_public_url.trim().starts_with("wss://")
            || request.livekit_public_url.chars().any(char::is_whitespace)
            || request.livekit_public_url.contains('@'))
    {
        return Err("LiveKit requiere una IP anunciada y una URL publica wss://.".to_string());
    }
    if has_profile("connectivity") {
        if !is_http_endpoint(&request.connectivity_edge_control_url, true) {
            return Err("Connectivity Edge requiere una URL de control https://.".to_string());
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
        for (value, prefix, label) in [
            (
                request.connectivity_edge_enrollment_token.as_str(),
                "acen_",
                "token de enrolamiento Edge",
            ),
            (
                request.connectivity_internal_relay_token.as_str(),
                "acer_",
                "token de relay interno",
            ),
        ] {
            if !value.trim().is_empty() && !is_connectivity_secret(value, prefix) {
                return Err(format!("El {label} no tiene el formato soberano esperado."));
            }
        }
    }
    let mut env_checks = vec![
        ("direccion de escucha", request.bind_address.as_str()),
        ("URL accesible del nodo", request.public_base_url.as_str()),
        ("origenes CORS", request.cors_origins.as_str()),
        (
            "Telemetry Ingress publico",
            request.telemetry_ingress_public_url.as_str(),
        ),
        (
            "Telemetry Read publico",
            request.telemetry_read_public_url.as_str(),
        ),
        ("metricas publicas", request.metrics_public_url.as_str()),
        (
            "Radio Control publico",
            request.radio_control_public_url.as_str(),
        ),
        ("Site Core publico", request.site_core_public_url.as_str()),
        ("People Resolve publico", request.people_resolve_public_url.as_str()),
        (
            "Control Runtime publico",
            request.control_runtime_public_url.as_str(),
        ),
    ];
    if has_profile("radio-turn") {
        env_checks.extend([
            ("URLs TURN", request.turn_urls.as_str()),
            ("realm TURN", request.turn_realm.as_str()),
            ("IP TURN", request.turn_external_ip.as_str()),
        ]);
    }
    if has_profile("radio-livekit") {
        env_checks.extend([
            ("IP LiveKit", request.livekit_node_ip.as_str()),
            ("URL LiveKit", request.livekit_public_url.as_str()),
        ]);
    }
    if has_profile("connectivity") {
        env_checks.extend([
            (
                "URL Connectivity Edge",
                request.connectivity_edge_control_url.as_str(),
            ),
            ("rol Connectivity", request.connectivity_node_role.as_str()),
        ]);
    }
    for (label, value) in env_checks {
        validate_env_value(label, value)?;
    }
    Ok(())
}

fn is_http_endpoint(value: &str, https_only: bool) -> bool {
    let value = value.trim();
    let authority_and_path = if https_only {
        value.strip_prefix("https://")
    } else {
        value
            .strip_prefix("http://")
            .or_else(|| value.strip_prefix("https://"))
    };
    authority_and_path.is_some_and(|remainder| {
        !remainder.is_empty()
            && !remainder.starts_with('/')
            && !value.contains('@')
            && !value.chars().any(char::is_whitespace)
    })
}

fn is_connectivity_secret(value: &str, prefix: &str) -> bool {
    let value = value.trim();
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() >= 40
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
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
    )?;
    // Validate abstract transport policy when present. Rejects vendor names as domain.
    if policy.preferred_transport.is_some()
        || policy.allowed_transports.is_some()
        || policy.gateway_strategy.is_some()
    {
        let preferred = policy
            .preferred_transport
            .as_deref()
            .unwrap_or("direct");
        let empty: Vec<String> = Vec::new();
        let allowed = policy
            .allowed_transports
            .as_deref()
            .unwrap_or(&empty);
        let strategy = policy
            .gateway_strategy
            .as_deref()
            .unwrap_or("node_direct");
        validate_access_transport_policy(preferred, allowed, strategy)
            .map_err(|error| format!("Transport policy invalida: {error}"))?;
    }
    Ok(())
}

#[tauri::command]
fn validate_installation_request(
    app: AppHandle,
    request: InstallRequest,
) -> Result<ActionResult, String> {
    let install_dir = validated_install_path(&request.install_dir)?;
    let existing = inspect_path(&install_dir);
    target_is_safe(&install_dir, &existing)?;
    let payload = payload_dir(&app)?;
    let verified_payload = verify_payload(&payload)?;
    let manifest = match &verified_payload {
        VerifiedPayload::Schema3(manifest) => Some(manifest),
        VerifiedPayload::LegacyUnverified { .. } => None,
    };
    let (profiles, bootstrap) = validate_request(&request, &existing, manifest)?;
    ensure_project_name_available(&install_dir, &request.project_name)?;
    ensure_network_ports_unreserved(&install_dir, &profiles, &install_port_plan(&request))?;
    if !request.prepare_only && !existing.operational {
        ensure_network_ports_available(&profiles, &install_port_plan(&request))?;
    }
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

fn audience_contains_any(value: &serde_json::Value, expected: &[&str]) -> bool {
    match value {
        serde_json::Value::String(candidate) => expected.contains(&candidate.as_str()),
        serde_json::Value::Array(candidates) => candidates
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|candidate| expected.contains(&candidate)),
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

fn required_runtime_features(
    profiles: &[String],
    site_core_intent: Option<&SiteCoreIntent>,
) -> Vec<String> {
    let mut required = Vec::new();
    if profiles.iter().any(|profile| profile == "people") {
        required.push("people_runtime_v1".to_string());
    }
    if profiles.iter().any(|profile| profile == "control") {
        required.push("control_runtime_v1".to_string());
    }
    if site_core_intent.is_some() {
        required.push("site_core_candidate_v1".to_string());
    }
    required
}

fn runtime_capability_contract_required(claims: &BootstrapClaims) -> bool {
    claims
        .supported_profiles
        .iter()
        .any(|profile| matches!(profile.as_str(), "people" | "control"))
        || !claims.supported_features.is_empty()
        || !claims.required_features.is_empty()
}

fn validate_runtime_capabilities_claim(claims: &BootstrapClaims) -> Result<(), String> {
    let required = runtime_capability_contract_required(claims);
    let Some(capabilities) = claims.runtime_capabilities.as_ref() else {
        if required || claims.runtime_contract_revision != 0 {
            return Err("RUNTIME_CAPABILITIES_REQUIRED".to_string());
        }
        return Ok(());
    };
    let lower_hex = |value: &str, length: usize| {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    };
    let safe_path = |value: &str| {
        !value.is_empty()
            && value.len() <= 240
            && !value.contains('\\')
            && !Path::new(value).is_absolute()
            && Path::new(value)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_)))
    };
    let ordered_unique_files = capabilities
        .files
        .windows(2)
        .all(|pair| pair[0].path < pair[1].path);
    if claims.runtime_contract_revision != 1
        || capabilities.schema != 1
        || !capabilities.verified
        || capabilities.runtime_release.trim().is_empty()
        || capabilities.installer_min_version != claims.installer_min_version
        || !lower_hex(&capabilities.payload_digest, 64)
        || !lower_hex(&capabilities.tree_sha256, 64)
        || capabilities.payload_digest != capabilities.tree_sha256
        || !lower_hex(&capabilities.source_commit, 40)
        || capabilities.files.is_empty()
        || !ordered_unique_files
        || capabilities
            .files
            .iter()
            .any(|file| !safe_path(&file.path) || !lower_hex(&file.sha256, 64))
        || !capabilities
            .files
            .iter()
            .any(|file| file.path == "release-capabilities.json")
        || capabilities.supported_profiles != claims.supported_profiles
        || capabilities.supported_features != claims.supported_features
    {
        return Err("RUNTIME_CAPABILITIES_CONTRACT_INVALID".to_string());
    }
    Ok(())
}

fn validate_runtime_capabilities_against_payload(
    claims: &BootstrapClaims,
    payload: Option<&PayloadManifestV3>,
) -> Result<(), String> {
    validate_runtime_capabilities_claim(claims)?;
    let Some(capabilities) = claims.runtime_capabilities.as_ref() else {
        return Ok(());
    };
    let payload = payload.ok_or_else(|| "RUNTIME_CAPABILITIES_PAYLOAD_SCHEMA3_REQUIRED".to_string())?;
    let files_match = capabilities.files.len() == payload.files.len()
        && capabilities
            .files
            .iter()
            .zip(payload.files.iter())
            .all(|(claim, file)| {
                claim.path == file.path
                    && claim.size == file.size
                    && claim.sha256 == file.sha256
            });
    if capabilities.runtime_release != payload.release_version
        || capabilities.runtime_release != product::DATA_PLANE_RELEASE_VERSION
        || capabilities.payload_digest != payload.tree_sha256
        || capabilities.tree_sha256 != payload.tree_sha256
        || Some(capabilities.source_commit.as_str()) != payload.source_commit.as_deref()
        || capabilities.supported_profiles != payload.supported_profiles
        || capabilities.supported_features != payload.supported_features
        || payload.supported_profiles
            != product::RELEASE_SUPPORTED_PROFILES
                .iter()
                .map(|profile| (*profile).to_string())
                .collect::<Vec<_>>()
        || payload.supported_features
            != product::RELEASE_SUPPORTED_FEATURES
                .iter()
                .map(|feature| (*feature).to_string())
                .collect::<Vec<_>>()
        || !files_match
    {
        return Err("RUNTIME_CAPABILITIES_PAYLOAD_MISMATCH".to_string());
    }
    Ok(())
}

fn validate_people_policy(policy: &PeoplePolicy, claims: &BootstrapClaims) -> Result<(), String> {
    let uuid = |value: &str| Uuid::parse_str(value).is_ok();
    let unique_bounded = |values: &[String], max_items: usize, max_length: usize| {
        values.len() <= max_items
            && values.iter().all(|value| {
                value == value.trim() && !value.is_empty() && value.len() <= max_length
            })
            && values.len() == values.iter().collect::<BTreeSet<_>>().len()
    };
    let valid_until = chrono::DateTime::parse_from_rfc3339(&policy.valid_until)
        .map_err(|_| "PEOPLE_POLICY_VALID_UNTIL_INVALID".to_string())?;
    if policy.schema != 1
        || policy.status != "active"
        || !uuid(&policy.organization_id)
        || !uuid(&policy.site_id)
        || claims.organization_id.as_deref() != Some(policy.organization_id.as_str())
        || claims.site_id.as_deref() != Some(policy.site_id.as_str())
        || policy.policy_revision == 0
        || valid_until <= chrono::Utc::now()
        || policy.runtime_placement != "edge_local"
        || !matches!(policy.pii_storage_mode.as_str(), "minimized_cloud" | "local_only")
        || !matches!(
            policy.identity_resolution_mode.as_str(),
            "actium_identity_master" | "local_identity_cache" | "actium_index_plus_local_vault"
        )
        || !matches!(
            policy.sync_policy.as_str(),
            "metadata_only" | "pseudonymized_index" | "bidirectional_selected" | "no_raw_pii_sync"
        )
        || policy.pii_storage_mode == "local_only" && policy.sync_policy != "no_raw_pii_sync"
        || policy
            .residency_policy
            .country
            .as_deref()
            .is_some_and(|country| {
                country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase())
            })
        || !unique_bounded(&policy.residency_policy.approved_regions, 32, 80)
        || !unique_bounded(&policy.residency_policy.provider_allowlist, 32, 120)
        || policy.service_capabilities != ["people.resolve"]
    {
        return Err("PEOPLE_POLICY_CONTRACT_INVALID".to_string());
    }
    Ok(())
}

fn validate_site_core_intent(
    intent: &SiteCoreIntent,
    claims: &BootstrapClaims,
) -> Result<(), String> {
    if intent.schema != 1
        || intent.deployment_id != claims.deployment_id
        || claims.site_id.as_deref() != Some(intent.site_id.as_str())
        || intent.role != "standby"
        || intent.fencing_state != "fenced"
        || intent.authority_mode != "disabled"
        || intent.authority_epoch.is_some()
        || claims.site_core_deployment_id.as_deref()
            != Some(intent.effective_primary_deployment_id.as_str())
        || intent.effective_primary_deployment_id == intent.deployment_id
        || intent.required_feature != "site_core_candidate_v1"
        || Uuid::parse_str(&intent.deployment_id).is_err()
        || Uuid::parse_str(&intent.site_id).is_err()
        || Uuid::parse_str(&intent.effective_primary_deployment_id).is_err()
    {
        return Err("SITE_CORE_CANDIDATE_INTENT_INVALID".to_string());
    }
    Ok(())
}

fn initial_people_policy_cache(bootstrap: &BootstrapClaims) -> Result<Option<String>, String> {
    let Some(policy) = bootstrap.people_policy.as_ref() else {
        return Ok(None);
    };
    validate_people_policy(policy, bootstrap)?;
    let policy_value = serde_json::to_value(policy)
        .map_err(|error| format!("No se pudo serializar People policy: {error}"))?;
    let policy_sha256 = format!("{:x}", Sha256::digest(canonical_json(&policy_value)?.as_bytes()));
    let cache = serde_json::json!({
        "schema": 1,
        "source": "actium_center_signed_bootstrap",
        "authority": {
            "transport": "signed_adpe_verified_by_node_manager",
            "desiredChecksum": bootstrap.checksum,
        },
        "deploymentId": bootstrap.deployment_id,
        "desiredGeneration": bootstrap.generation,
        "policySha256": policy_sha256,
        "policy": policy,
    });
    let serialized = serde_json::to_string_pretty(&cache)
        .map_err(|error| format!("No se pudo materializar People policy: {error}"))?;
    Ok(Some(format!("{serialized}\n")))
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
    validation.set_audience(&TRUSTED_BOOTSTRAP_AUDIENCES);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "jti"]);
    validation.leeway = 15;
    let claims = decode::<BootstrapClaims>(compact, &key, &validation)
        .map_err(|error| format!("Firma o vigencia del paquete .adpe invalida: {error}"))?
        .claims;
    if claims.schema_version != 1
        || claims.package_type != "actium-data-plane-enrollment"
        || claims.signing_key_ref != TRUSTED_BOOTSTRAP_KEY_REF
        || claims.iss != TRUSTED_BOOTSTRAP_ISSUER
        || !audience_contains_any(&claims.aud, &TRUSTED_BOOTSTRAP_AUDIENCES)
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
    if claims.client_id.as_deref().is_none_or(str::is_empty)
        || claims.organization_id.as_deref().is_none_or(str::is_empty)
        || claims.site_id.as_deref().is_none_or(str::is_empty)
        || claims.site_code.as_deref().is_none_or(str::is_empty)
        || claims.site_name.as_deref().is_none_or(str::is_empty)
    {
        return Err(
            "El paquete .adpe no identifica cliente, organizacion y sitio operativo.".to_string(),
        );
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
    let issuer = claims
        .site_runtime_expected_issuer
        .as_deref()
        .unwrap_or_default();
    let public_key = claims
        .site_runtime_bundle_public_key_pem
        .as_deref()
        .unwrap_or_default();
    if !issuer.starts_with("https://") {
        return Err(
            "El paquete .adpe no contiene un issuer Site Runtime HTTPS confiable.".to_string(),
        );
    }
    validate_public_key(public_key, "Site Runtime Bundle")?;
    let has_site_core = claims.profiles.iter().any(|profile| profile == "site-core");
    if has_site_core {
        if claims.site_core_deployment_id.as_deref() == Some(claims.deployment_id.as_str()) {
            if claims.site_core_intent.is_some() {
                return Err("SITE_CORE_PRIMARY_WITH_CANDIDATE_INTENT".to_string());
            }
        } else {
            let intent = claims
                .site_core_intent
                .as_ref()
                .ok_or_else(|| "SITE_CORE_CANDIDATE_INTENT_REQUIRED".to_string())?;
            validate_site_core_intent(intent, &claims)?;
        }
    } else {
        if claims.site_core_intent.is_some() {
            return Err("SITE_CORE_CANDIDATE_INTENT_WITHOUT_PROFILE".to_string());
        }
        if claims
            .site_core_deployment_id
            .as_deref()
            .is_none_or(str::is_empty)
            || claims
                .site_core_endpoint
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(
                "El sitio todavia no tiene un Site Core operativo para este deployment."
                    .to_string(),
            );
        }
    }
    if claims.profiles.is_empty()
        || claims
            .profiles
            .iter()
            .any(|profile| !KNOWN_PROFILES.contains(&profile.as_str()))
    {
        return Err("El paquete .adpe no autoriza perfiles operativos validos.".to_string());
    }
    if claims.supported_profiles.len()
        != claims.supported_profiles.iter().collect::<BTreeSet<_>>().len()
        || claims
            .supported_profiles
            .iter()
            .any(|profile| !KNOWN_PROFILES.contains(&profile.as_str()))
        || claims.supported_features.len()
            != claims.supported_features.iter().collect::<BTreeSet<_>>().len()
        || claims.required_features.len()
            != claims.required_features.iter().collect::<BTreeSet<_>>().len()
        || claims
            .supported_features
            .iter()
            .chain(claims.required_features.iter())
            .any(|feature| {
            feature.is_empty()
                || feature.len() > 80
                || !feature.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                })
            })
        || claims
            .required_features
            .iter()
            .any(|feature| !claims.supported_features.contains(feature))
    {
        return Err("El paquete .adpe declara capacidades de runtime invalidas.".to_string());
    }
    validate_runtime_capabilities_claim(&claims)?;
    let required_features = required_runtime_features(
        &claims.profiles,
        claims.site_core_intent.as_ref(),
    );
    if claims.required_features != required_features {
        return Err("RUNTIME_REQUIRED_FEATURES_MISMATCH: requiredFeatures no coincide con la intencion activa del Node.".to_string());
    }
    if required_features.iter().any(|feature| {
        let profile = match feature.as_str() {
            "people_runtime_v1" => Some("people"),
            "control_runtime_v1" => Some("control"),
            _ => None,
        };
        !claims.supported_features.contains(feature)
            || profile.is_some_and(|profile| {
                !claims.supported_profiles.iter().any(|value| value == profile)
            })
    }) {
        return Err("RUNTIME_RELEASE_PROFILE_UNSUPPORTED: cada perfil runtime requiere profile y feature verificables.".to_string());
    }
    let has_people = claims.profiles.iter().any(|profile| profile == "people");
    if has_people {
        if claims.generation < 0
            || claims.checksum.len() != 64
            || !claims
                .checksum
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("PEOPLE_POLICY_AUTHORITY_SCOPE_INVALID".to_string());
        }
        let policy = claims
            .people_policy
            .as_ref()
            .ok_or_else(|| "PEOPLE_POLICY_REQUIRED".to_string())?;
        validate_people_policy(policy, &claims)?;
    } else if claims.people_policy.is_some() {
        return Err("PEOPLE_POLICY_WITHOUT_PROFILE".to_string());
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
fn validate_bootstrap(
    app: AppHandle,
    request: BootstrapRequest,
) -> Result<BootstrapValidationResult, String> {
    let claims = validate_bootstrap_jws(&request.bootstrap_jws)?;
    let payload = payload_dir(&app)?;
    let verified_payload = verify_payload(&payload)?;
    let manifest = match &verified_payload {
        VerifiedPayload::Schema3(manifest) => Some(manifest),
        VerifiedPayload::LegacyUnverified { .. } => None,
    };
    validate_runtime_capabilities_against_payload(&claims, manifest)?;
    Ok(BootstrapValidationResult {
        valid: true,
        deployment_id: claims.deployment_id,
        deployment_code: claims.deployment_code,
        deployment_name: claims.deployment_name,
        client_id: claims.client_id,
        organization_id: claims.organization_id,
        site_id: claims.site_id,
        site_code: claims.site_code,
        site_name: claims.site_name,
        site_core_deployment_id: claims.site_core_deployment_id,
        site_core_endpoint: claims.site_core_endpoint,
        generation: claims.generation,
        checksum: claims.checksum,
        expires_at_unix_seconds: claims.exp,
        profiles: claims.profiles,
        supported_profiles: claims.supported_profiles,
        supported_features: claims.supported_features,
        required_features: claims.required_features,
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

fn nonempty_secret(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn write_node_env(
    path: &Path,
    request: &InstallRequest,
    bootstrap: &BootstrapClaims,
    profiles: &[String],
    installation_id: &str,
) -> Result<(), String> {
    let node_root = path
        .parent()
        .ok_or_else(|| "node.env no tiene directorio padre.".to_string())?;
    let contents = node_env_document(node_root, request, bootstrap, profiles, installation_id);
    fs::write(path, contents).map_err(|error| format!("No se pudo escribir node.env: {error}"))
}

fn default_storage_path(install_dir: &Path, sub: &str) -> String {
    install_dir.join("persistent").join(sub).to_string_lossy().replace('\\', "/")
}

fn node_env_document(
    node_root: &Path,
    request: &InstallRequest,
    bootstrap: &BootstrapClaims,
    profiles: &[String],
    installation_id: &str,
) -> String {
    // Active intent, not the whole release capability surface. Persisting every
    // supported feature here would make unrelated future payload features a
    // downgrade requirement for this Node.
    let required_features = required_runtime_features(profiles, bootstrap.site_core_intent.as_ref());
    let site_runtime_schema_version = site_runtime_schema_version_for_profiles(profiles);
    let site_core_role = bootstrap
        .site_core_intent
        .as_ref()
        .map(|intent| intent.role.as_str())
        .unwrap_or("primary");
    let site_core_fencing = bootstrap
        .site_core_intent
        .as_ref()
        .map(|intent| intent.fencing_state.as_str())
        .unwrap_or("active");
    let site_core_authority_mode = bootstrap
        .site_core_intent
        .as_ref()
        .map(|intent| intent.authority_mode.as_str())
        .unwrap_or("enabled");
    let effective_primary = bootstrap
        .site_core_intent
        .as_ref()
        .map(|intent| intent.effective_primary_deployment_id.as_str())
        .or(bootstrap.site_core_deployment_id.as_deref())
        .unwrap_or(bootstrap.deployment_id.as_str());
    let site_core_intent_sha256 = bootstrap
        .site_core_intent
        .as_ref()
        .and_then(|intent| serde_json::to_value(intent).ok())
        .and_then(|intent| canonical_json(&intent).ok())
        .map(|intent| format!("{:x}", Sha256::digest(intent.as_bytes())))
        .unwrap_or_default();
    let key_path = |name: &str| {
        node_root
            .join("keys")
            .join(name)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let node_root_str = request
        .node_root_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| node_root.to_str().unwrap_or_default());
    let site_core_data_path = request
        .site_core_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "site-core"));
    let telemetry_data_path = request
        .telemetry_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "telemetry"));
    let dvr_media_path = request
        .dvr_media_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "telemetry"));
    let people_data_path = request
        .people_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "people"));
    let control_runtime_data_path = request
        .control_runtime_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "control"));
    let radio_control_data_path = request
        .radio_control_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "radio-control"));
    let radio_saf_storage_path = request
        .radio_saf_storage_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "radio-archive"));
    let turn_data_path = request
        .turn_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "turn"));
    let livekit_data_path = request
        .livekit_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "livekit"));
    let prometheus_data_path = request
        .prometheus_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "metrics"));
    let grafana_data_path = request
        .grafana_data_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "metrics"));
    let connectivity_spool_path = request
        .connectivity_spool_path
        .as_deref()
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_string())
        .unwrap_or_else(|| default_storage_path(node_root, "connectivity"));

    let raw = format!(
        "# Generado por Actium Node Manager. No almacenar secretos aqui.\n\
ACTIUM_CONTROL_ENDPOINT={}\n\
ACTIUM_ENROLLMENT_TOKEN=\n\
ACTIUM_NODE_INSTALLATION_ID={}\n\
ACTIUM_INSTALLER_VERSION={}\n\
ACTIUM_DEPLOYMENT_ID={}\n\
ACTIUM_DEPLOYMENT_CODE={}\n\
ACTIUM_CLIENT_ID={}\n\
ACTIUM_ORGANIZATION_ID={}\n\
ACTIUM_SITE_ID={}\n\
ACTIUM_SITE_CODE={}\n\
ACTIUM_SITE_CORE_DEPLOYMENT_ID={}\n\
ACTIUM_SITE_CORE_ENDPOINT={}\n\
SITE_CORE_RUNTIME_ROLE={}\n\
SITE_CORE_FENCING_STATE={}\n\
SITE_CORE_AUTHORITY_MODE={}\n\
SITE_CORE_EFFECTIVE_PRIMARY_DEPLOYMENT_ID={}\n\
SITE_CORE_INTENT_SHA256={}\n\
ACTIUM_TERMINAL_PUBLIC_KEY_PATH={}\n\
ACTIUM_OPERATOR_PUBLIC_KEY_PATH={}\n\
SITE_RUNTIME_BUNDLE_PUBLIC_KEY_PATH={}\n\
ACTIUM_TERMINAL_ISSUER={}\n\
ACTIUM_OPERATOR_ISSUER={}\n\
SITE_RUNTIME_EXPECTED_ISSUER={}\n\
SITE_RUNTIME_SCHEMA_VERSION={}\n\
ACTIUM_PROFILES={}\n\
ACTIUM_REQUIRED_RUNTIME_FEATURES={}\n\
ACTIUM_PROJECT_NAME={}\n\
ACTIUM_DATA_PLANE_PROJECT={}\n\
ACTIUM_USE_PUBLISHED_IMAGES={}\n\
NODE_ROOT_PATH={}\n\
SITE_CORE_DATA_PATH={}\n\
TELEMETRY_DATA_PATH={}\n\
DVR_MEDIA_PATH={}\n\
PEOPLE_DATA_PATH={}\n\
CONTROL_RUNTIME_DATA_PATH={}\n\
RADIO_CONTROL_DATA_PATH={}\n\
RADIO_ARCHIVE_HOST_PATH={}\n\
RADIO_SAF_STORAGE_PATH={}\n\
TURN_DATA_PATH={}\n\
LIVEKIT_DATA_PATH={}\n\
PROMETHEUS_DATA_PATH={}\n\
GRAFANA_DATA_PATH={}\n\
CONNECTIVITY_SPOOL_PATH={}\n\
DATA_PLANE_NETWORK_MODE={}\n\
DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED={}\n\
ACTIUM_NETWORK_RECONCILIATION_POLICY={}\n\
ACTIUM_NETWORK_INTERFACE={}\n\
ACTIUM_NETWORK_ADDRESS={}\n\
ACTIUM_NETWORK_PLANE={}\n\
ACTIUM_NETWORK_PRIORITY={}\n\
DATA_PLANE_BIND_ADDRESS={}\n\
DATA_PLANE_PUBLIC_BASE_URL={}\n\
DATA_PLANE_CORS_ORIGINS={}\n\
SITE_CORE_PUBLIC_URL=\n\
PEOPLE_RESOLVE_PUBLIC_URL=\n\
CONTROL_RUNTIME_PUBLIC_URL=\n\
TELEMETRY_PORT={}\n\
PEOPLE_PORT={}\n\
CONTROL_RUNTIME_PORT={}\n\
RADIO_CONTROL_PORT={}\n\
RADIO_SAF_PORT={}\n\
SITE_CORE_PORT={}\n\
RADIO_SAF_ENABLED={}\n\
RADIO_LIVEKIT_ENABLED={}\n\
PROMETHEUS_PORT={}\n\
GRAFANA_PORT={}\n\
TURN_REALM={}\n\
TURN_EXTERNAL_IP={}\n\
TURN_PORT={}\n\
TURN_TLS_PORT={}\n\
TURN_MIN_PORT={}\n\
TURN_MAX_PORT={}\n\
LIVEKIT_NODE_IP={}\n\
LIVEKIT_PUBLIC_URL={}\n\
LIVEKIT_HTTP_PORT={}\n\
LIVEKIT_RTC_TCP_PORT={}\n\
LIVEKIT_UDP_MIN_PORT={}\n\
LIVEKIT_UDP_MAX_PORT={}\n\
CONNECTIVITY_EDGE_CONTROL_URL={}\n\
CONNECTIVITY_NODE_ROLE={}\n\
CONNECTIVITY_NODE_PRIORITY={}\n\
CONNECTIVITY_PULL_LIMIT={}\n\
CONNECTIVITY_SYNC_ENABLED={}\n\
CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED={}\n\
CONNECTIVITY_SUPABASE_FALLBACK_ENABLED={}\n\
CONNECTIVITY_FALLBACK_ORDER={}\n",
        bootstrap.control_endpoint.trim_end_matches('/'),
        installation_id,
        INSTALLER_VERSION,
        bootstrap.deployment_id,
        bootstrap.deployment_code,
        bootstrap.client_id.as_deref().unwrap_or_default(),
        bootstrap.organization_id.as_deref().unwrap_or_default(),
        bootstrap.site_id.as_deref().unwrap_or_default(),
        bootstrap.site_code.as_deref().unwrap_or_default(),
        bootstrap
            .site_core_deployment_id
            .as_deref()
            .unwrap_or(bootstrap.deployment_id.as_str()),
        bootstrap.site_core_endpoint.as_deref().unwrap_or_default(),
        site_core_role,
        site_core_fencing,
        site_core_authority_mode,
        effective_primary,
        site_core_intent_sha256,
        key_path("actium-terminal-public.pem"),
        key_path("actium-operator-public.pem"),
        key_path("actium-site-runtime-bundle-public.pem"),
        bootstrap.terminal_issuer.trim(),
        bootstrap.operator_issuer.trim(),
        bootstrap
            .site_runtime_expected_issuer
            .as_deref()
            .unwrap_or_default(),
        site_runtime_schema_version,
        profiles.join(","),
        required_features.join(","),
        request.project_name.trim(),
        request.project_name.trim(),
        request.use_published_images,
        node_root_str,
        site_core_data_path,
        telemetry_data_path,
        dvr_media_path,
        people_data_path,
        control_runtime_data_path,
        radio_control_data_path,
        request.radio_archive_host_path.trim(),
        radio_saf_storage_path,
        turn_data_path,
        livekit_data_path,
        prometheus_data_path,
        grafana_data_path,
        connectivity_spool_path,
        request.network_mode.trim(),
        request.network_configuration_deferred,
        request.network_reconciliation_policy.trim(),
        request.network_interface.trim(),
        request.network_address.trim(),
        request.network_plane.trim(),
        request.network_priority,
        request.bind_address.trim(),
        request.public_base_url.trim_end_matches('/'),
        request.cors_origins.trim(),
        request.telemetry_port,
        request.people_port,
        request.control_runtime_port,
        request.radio_control_port,
        request.radio_saf_port,
        request.site_core_port,
        profiles.iter().any(|profile| profile == "radio-saf"),
        profiles.iter().any(|profile| profile == "radio-livekit"),
        request.prometheus_port,
        request.grafana_port,
        request.turn_realm.trim(),
        request.turn_external_ip.trim(),
        request.turn_port,
        request.turn_tls_port,
        request.turn_min_port,
        request.turn_max_port,
        request.livekit_node_ip.trim(),
        request.livekit_public_url.trim(),
        request.livekit_http_port,
        request.livekit_rtc_tcp_port,
        request.livekit_udp_min_port,
        request.livekit_udp_max_port,
        request.connectivity_edge_control_url.trim_end_matches('/'),
        request.connectivity_node_role.trim(),
        request.connectivity_node_priority,
        request.connectivity_pull_limit,
        request.connectivity_sync_enabled,
        request.connectivity_direct_data_plane_fallback_enabled,
        request.connectivity_supabase_fallback_enabled,
        request.connectivity_fallback_order.join(","),
    );
    apply_inactive_profile_defaults(&raw, profiles)
}

fn site_runtime_schema_version_for_profiles(profiles: &[String]) -> &'static str {
    if profiles.iter().any(|profile| profile == "control") {
        "1.2"
    } else {
        product::SITE_RUNTIME_SCHEMA_VERSION
    }
}

fn inactive_profile_default(key: &str) -> Option<String> {
    Some(match key {
        "NODE_ROOT_PATH" => String::new(),
        "SITE_CORE_DATA_PATH" => String::new(),
        "TELEMETRY_DATA_PATH" | "DVR_MEDIA_PATH" => String::new(),
        "PEOPLE_DATA_PATH" => String::new(),
        "CONTROL_RUNTIME_DATA_PATH" => String::new(),
        "RADIO_CONTROL_DATA_PATH" => String::new(),
        "RADIO_SAF_STORAGE_PATH" => String::new(),
        "TURN_DATA_PATH" => String::new(),
        "LIVEKIT_DATA_PATH" => String::new(),
        "PROMETHEUS_DATA_PATH" | "GRAFANA_DATA_PATH" => String::new(),
        "CONNECTIVITY_SPOOL_PATH" => String::new(),
        "SITE_CORE_PORT" => product::SITE_CORE_PORT.to_string(),
        "SITE_CORE_PUBLIC_URL" => String::new(),
        "TELEMETRY_PORT" => product::TELEMETRY_PORT.to_string(),
        "TELEMETRY_INGRESS_PUBLIC_URL" | "TELEMETRY_READ_PUBLIC_URL" => String::new(),
        "PEOPLE_PORT" => product::PEOPLE_PORT.to_string(),
        "PEOPLE_RESOLVE_PUBLIC_URL" => String::new(),
        "CONTROL_RUNTIME_PORT" => product::CONTROL_RUNTIME_PORT.to_string(),
        "CONTROL_RUNTIME_PUBLIC_URL" => String::new(),
        "RADIO_CONTROL_PORT" => product::RADIO_CONTROL_PORT.to_string(),
        "RADIO_CONTROL_PUBLIC_URL" => String::new(),
        "RADIO_SAF_PORT" => product::RADIO_SAF_PORT.to_string(),
        "RADIO_ARCHIVE_HOST_PATH" => String::new(),
        "RADIO_SAF_ENABLED" | "RADIO_LIVEKIT_ENABLED" => "false".to_string(),
        "PROMETHEUS_PORT" => product::PROMETHEUS_PORT.to_string(),
        "GRAFANA_PORT" => product::GRAFANA_PORT.to_string(),
        "METRICS_PUBLIC_URL" => String::new(),
        "TURN_REALM" | "TURN_EXTERNAL_IP" | "TURN_URLS" => String::new(),
        "TURN_PORT" => product::TURN_PORT.to_string(),
        "TURN_TLS_PORT" => product::TURN_TLS_PORT.to_string(),
        "TURN_MIN_PORT" => product::TURN_MIN_PORT.to_string(),
        "TURN_MAX_PORT" => product::TURN_MAX_PORT.to_string(),
        "LIVEKIT_NODE_IP" | "LIVEKIT_PUBLIC_URL" => String::new(),
        "LIVEKIT_HTTP_PORT" => product::LIVEKIT_HTTP_PORT.to_string(),
        "LIVEKIT_RTC_TCP_PORT" => product::LIVEKIT_RTC_TCP_PORT.to_string(),
        "LIVEKIT_UDP_MIN_PORT" => product::LIVEKIT_UDP_MIN_PORT.to_string(),
        "LIVEKIT_UDP_MAX_PORT" => product::LIVEKIT_UDP_MAX_PORT.to_string(),
        "CONNECTIVITY_EDGE_CONTROL_URL" => String::new(),
        "CONNECTIVITY_NODE_ROLE" => "replica".to_string(),
        "CONNECTIVITY_NODE_PRIORITY" => "100".to_string(),
        "CONNECTIVITY_PULL_LIMIT" => "25".to_string(),
        "CONNECTIVITY_SYNC_ENABLED" => "false".to_string(),
        "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED" => "true".to_string(),
        "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED" => "false".to_string(),
        "CONNECTIVITY_FALLBACK_ORDER" => "direct_data_plane".to_string(),
        "CONNECTIVITY_PREFERRED_TRANSPORT" => "direct".to_string(),
        "CONNECTIVITY_ALLOWED_TRANSPORTS" => "direct".to_string(),
        "CONNECTIVITY_GATEWAY_STRATEGY" => "node_direct".to_string(),
        "CONNECTIVITY_ROAMING_ALLOWED" => "true".to_string(),
        _ => return None,
    })
}

fn apply_inactive_profile_defaults(document: &str, profiles: &[String]) -> String {
    let mut updates = BTreeMap::new();
    for profile in KNOWN_PROFILES {
        for key in profile_env_keys(profile) {
            if key_is_authoritative(profiles, key) {
                continue;
            }
            if let Some(default) = inactive_profile_default(key) {
                updates.insert(*key, default);
            }
        }
    }
    updated_env_document(document, &updates)
}

fn updated_env_document(current: &str, updates: &BTreeMap<&str, String>) -> String {
    let mut seen = BTreeSet::new();
    let mut lines = Vec::new();
    for line in current.lines() {
        let key = line
            .split_once('=')
            .map(|(key, _)| key.trim())
            .unwrap_or("");
        if let Some(value) = updates.get(key) {
            lines.push(format!("{key}={value}"));
            seen.insert(key);
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

fn write_network_port_plan(path: &Path, plan: &NetworkPortPlan) -> Result<(), String> {
    let node_env_path = path.join("node.env");
    let current = fs::read_to_string(&node_env_path)
        .map_err(|error| format!("No se pudo leer node.env para reasignar puertos: {error}"))?;
    let profiles = current
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_PROFILES=").map(split_profiles))
        .unwrap_or_default();
    let active = active_port_keys(&profiles);
    let mut updates = BTreeMap::from([("ACTIUM_INSTALLER_VERSION", INSTALLER_VERSION.to_string())]);
    let mut put = |key: &'static str, value: String| {
        if active.contains(key) {
            updates.insert(key, value);
        }
    };
    put("TELEMETRY_PORT", plan.telemetry_port.to_string());
    put("PEOPLE_PORT", plan.people_port.to_string());
    put(
        "CONTROL_RUNTIME_PORT",
        plan.control_runtime_port.to_string(),
    );
    put("RADIO_CONTROL_PORT", plan.radio_control_port.to_string());
    put("RADIO_SAF_PORT", plan.radio_saf_port.to_string());
    put("SITE_CORE_PORT", plan.site_core_port.to_string());
    put("PROMETHEUS_PORT", plan.prometheus_port.to_string());
    put("GRAFANA_PORT", plan.grafana_port.to_string());
    put("TURN_PORT", plan.turn_port.to_string());
    put("TURN_TLS_PORT", plan.turn_tls_port.to_string());
    put("TURN_MIN_PORT", plan.turn_min_port.to_string());
    put("TURN_MAX_PORT", plan.turn_max_port.to_string());
    put("LIVEKIT_HTTP_PORT", plan.livekit_http_port.to_string());
    put(
        "LIVEKIT_RTC_TCP_PORT",
        plan.livekit_rtc_tcp_port.to_string(),
    );
    put(
        "LIVEKIT_UDP_MIN_PORT",
        plan.livekit_udp_min_port.to_string(),
    );
    put(
        "LIVEKIT_UDP_MAX_PORT",
        plan.livekit_udp_max_port.to_string(),
    );
    write_secure(&node_env_path, &updated_env_document(&current, &updates))
}

#[cfg(test)]
fn write_payload_version(path: &Path, version: &str) -> Result<(), String> {
    let updates = BTreeMap::from([("ACTIUM_INSTALLER_VERSION", version.to_string())]);
    for relative in ["node.env", "secrets/data-plane.env"] {
        let env_path = path.join(relative);
        if !env_path.is_file() {
            continue;
        }
        let current = fs::read_to_string(&env_path).map_err(|error| {
            format!("No se pudo leer {relative} para actualizar el payload: {error}")
        })?;
        write_secure(&env_path, &updated_env_document(&current, &updates))?;
    }
    Ok(())
}

fn restore_optional_secure_file(path: &Path, original: Option<&str>) -> Result<(), String> {
    if let Some(contents) = original {
        write_secure(path, contents)
    } else if path.is_file() {
        fs::remove_file(path).map_err(|error| {
            format!(
                "No se pudo retirar {} durante el rollback: {error}",
                path.display()
            )
        })
    } else {
        Ok(())
    }
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
    let contents = marker_document(
        version,
        profiles,
        status,
        bootstrap,
        installation_id,
        last_error,
    )?;
    fs::write(path.join(MARKER_FILE), contents)
        .map_err(|error| format!("No se pudo guardar el estado administrado: {error}"))
}

fn marker_document(
    version: &str,
    profiles: &[String],
    status: &str,
    bootstrap: &BootstrapClaims,
    installation_id: &str,
    last_error: Option<&str>,
) -> Result<String, String> {
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
        manager_channel: Some(product::PRODUCT_CHANNEL.to_string()),
        active_release: None,
        previous_release: None,
        release_digest: None,
        payload_schema: None,
        promotion_status: None,
        last_successful_release: None,
        last_failed_release: None,
    };
    let contents = serde_json::to_string_pretty(&marker)
        .map_err(|error| format!("No se pudo serializar el estado: {error}"))?;
    Ok(format!("{contents}\n"))
}

fn sync_release_marker(
    path: &Path,
    releases: &NodeReleaseState,
    status: &str,
    last_error: Option<&str>,
) -> Result<(), String> {
    let marker_path = path.join(MARKER_FILE);
    let contents = fs::read_to_string(&marker_path)
        .map_err(|error| format!("No se pudo leer el estado administrado: {error}"))?;
    let mut marker = serde_json::from_str::<InstallationMarker>(&contents)
        .map_err(|error| format!("El estado administrado local no es valido: {error}"))?;
    marker.status = status.to_string();
    marker.updated_at_unix_seconds = now_marker_timestamp();
    marker.last_error = last_error.map(str::to_string);
    marker.active_release = releases
        .active_release
        .as_ref()
        .map(|value| value.release_id.clone());
    marker.previous_release = releases
        .previous_release
        .as_ref()
        .map(|value| value.release_id.clone());
    marker.release_digest = releases
        .active_release
        .as_ref()
        .map(|value| value.release_digest.clone());
    marker.payload_schema = releases
        .active_release
        .as_ref()
        .map(|value| value.payload_schema);
    marker.promotion_status = Some(releases.promotion_status.clone());
    marker.last_successful_release = releases
        .last_successful_release
        .as_ref()
        .map(|value| value.release_id.clone());
    marker.last_failed_release = releases
        .last_failed_release
        .as_ref()
        .map(|value| value.release_id.clone());
    if let Some(active) = &releases.active_release {
        marker.version = active.release_version.clone();
    }
    let serialized = serde_json::to_string_pretty(&marker)
        .map_err(|error| format!("No se pudo serializar el estado de release: {error}"))?;
    fs::write(marker_path, format!("{serialized}\n"))
        .map_err(|error| format!("No se pudo sincronizar el estado de release: {error}"))
}

fn update_existing_marker(
    path: &Path,
    status: Option<&str>,
    version: Option<&str>,
    last_error: Option<&str>,
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
    marker.last_error = last_error.map(str::to_string);
    let serialized = serde_json::to_string_pretty(&marker)
        .map_err(|error| format!("No se pudo serializar el estado administrado: {error}"))?;
    fs::write(marker_path, format!("{serialized}\n"))
        .map_err(|error| format!("No se pudo actualizar el estado administrado: {error}"))
}

fn target_is_safe(path: &Path, existing: &InstallationState) -> Result<(), String> {
    if product::is_lab() {
        safety::validated_descendant(path, &paths::authorized_nodes_root())?;
    }
    if existing.installed && !installation_owned_by_current_channel(existing) {
        return Err(format!(
            "La instalacion pertenece a otro canal y {} no puede adoptarla.",
            product::display_name()
        ));
    }
    let recognized_cli_installation = existing.installed
        && path.join("compose.yml").is_file()
        && (path.join("bootstrap.ps1").is_file() || path.join("bootstrap.sh").is_file());
    if !path.exists()
        || (existing.managed && installation_owned_by_current_channel(existing))
        || (!product::is_lab() && recognized_cli_installation)
    {
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

fn promoted_node_target(source: &Path, state: &InstallationState) -> Result<PathBuf, String> {
    if !path_is_within(source, &recovery_root_dir()) {
        return Err("El nodo no se encuentra dentro del area de recuperacion.".to_string());
    }
    let identity = state
        .deployment_code
        .as_deref()
        .or_else(|| installation_project_name(state))
        .ok_or_else(|| {
            "El nodo recuperable no conserva una identidad tecnica para promoverlo.".to_string()
        })?;
    let target = managed_nodes_dir().join(safe_archive_fragment(identity));
    if !path_is_within(&target, &managed_nodes_dir()) {
        return Err("El destino promovido no pertenece al inventario administrado.".to_string());
    }
    Ok(target)
}

fn promote_archived_directory(source: &Path, state: &InstallationState) -> Result<PathBuf, String> {
    let target = promoted_node_target(source, state)?;
    if path_identity(source) == path_identity(&target) {
        return Ok(target);
    }
    let target_state = inspect_path(&target);
    target_is_safe(&target, &target_state)?;
    if target_state.installed {
        return Err(format!(
            "El destino administrado {} ya pertenece a otra instalacion.",
            target.display()
        ));
    }
    fs::create_dir_all(managed_nodes_dir()).map_err(|error| {
        format!(
            "No se pudo crear el inventario administrado {}: {error}",
            managed_nodes_dir().display()
        )
    })?;
    if target.exists() {
        fs::remove_dir(&target).map_err(|error| {
            format!(
                "No se pudo retirar el destino administrado vacio {}: {error}",
                target.display()
            )
        })?;
    }

    fs::rename(source, &target).map_err(|error| {
        format!(
            "No se pudo promover {} hacia {}: {error}",
            source.display(),
            target.display()
        )
    })?;
    if let Err(error) = replace_registered_node_path(source, &target) {
        let rollback = fs::rename(&target, source);
        return Err(match rollback {
            Ok(()) => format!(
                "No se pudo actualizar el registro del nodo promovido; se restauro su ubicacion anterior: {error}"
            ),
            Err(rollback_error) => format!(
                "No se pudo actualizar el registro del nodo promovido ({error}) ni restaurar su ubicacion ({rollback_error})."
            ),
        });
    }
    Ok(target)
}

fn rollback_promoted_directory(target: &Path, source: &Path) -> Result<(), String> {
    fs::rename(target, source).map_err(|error| {
        format!(
            "No se pudo restaurar {} hacia {}: {error}",
            target.display(),
            source.display()
        )
    })?;
    replace_registered_node_path(target, source)
}

fn installation_project_name(existing: &InstallationState) -> Option<&str> {
    existing
        .config
        .get("ACTIUM_DATA_PLANE_PROJECT")
        .or_else(|| existing.config.get("ACTIUM_PROJECT_NAME"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

fn docker_project_container_ids(project_name: &str) -> Result<Vec<String>, String> {
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
            format!("No se pudo consultar Docker para el proyecto {project_name}: {error}")
        })?;
    if !output.status.success() {
        let details = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Docker no pudo consultar los contenedores del proyecto {project_name}: {}",
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

fn remove_project_containers(project_name: &str) -> Result<usize, String> {
    let containers = docker_project_container_ids(project_name)?;
    if containers.is_empty() {
        return Ok(0);
    }
    let output = Command::new("docker")
        .arg("rm")
        .arg("-f")
        .args(&containers)
        .output()
        .map_err(|error| {
            format!("No se pudieron retirar los contenedores parciales de {project_name}: {error}")
        })?;
    if !output.status.success() {
        return Err(format!(
            "Docker no pudo retirar los contenedores parciales de {project_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(containers.len())
}

const TELEMETRY_AUDIT_SQL: &str = r#"
with identities as (
  select organization_id, terminal_id from telemetry.terminal_location_current
  union
  select organization_id, terminal_id from telemetry.terminal_presence_current
  union
  select organization_id, terminal_id from telemetry.gps_batches
  union
  select organization_id, terminal_id from telemetry.gps_points
),
terminal_raw as (
  select
    i.organization_id,
    i.terminal_id as observed_terminal_id,
    coalesce(
      nullif(p.metadata->>'assignedDeviceId', ''),
      nullif(p.metadata->>'assigned_device_id', ''),
      nullif(l.metadata->>'assignedDeviceId', ''),
      nullif(l.metadata->>'assigned_device_id', ''),
      nullif(lp.metadata->>'assignedDeviceId', ''),
      nullif(lp.metadata->>'assigned_device_id', ''),
      nullif(p.metadata->>'terminalUuid', ''),
      nullif(p.metadata->>'terminal_uuid', ''),
      nullif(l.metadata->>'terminalUuid', ''),
      nullif(l.metadata->>'terminal_uuid', ''),
      nullif(lp.metadata->>'terminalUuid', ''),
      nullif(lp.metadata->>'terminal_uuid', ''),
      i.terminal_id
    ) as canonical_terminal_id,
    l.binding_epoch,
    l.sequence,
    l.fix_at,
    l.ingested_at,
    l.projected_at,
    l.latitude,
    l.longitude,
    l.accuracy,
    l.speed,
    l.heading,
    l.continuity_status,
    l.queue_lag_seconds,
    p.heartbeat_at,
    p.status as presence_status,
    p.app_state,
    p.battery_level,
    p.queue_depth,
    coalesce(
      nullif(p.metadata->>'terminalLabel', ''),
      nullif(p.metadata->>'terminal_label', ''),
      nullif(p.metadata->>'terminalName', ''),
      nullif(p.metadata->>'terminal_name', ''),
      nullif(p.metadata->>'deviceName', ''),
      nullif(p.metadata->>'device_name', ''),
      nullif(l.metadata->>'terminalLabel', ''),
      nullif(l.metadata->>'terminal_label', ''),
      nullif(l.metadata->>'terminalName', ''),
      nullif(l.metadata->>'terminal_name', ''),
      nullif(l.metadata->>'deviceName', ''),
      nullif(l.metadata->>'device_name', ''),
      nullif(lp.metadata->>'terminalLabel', ''),
      nullif(lp.metadata->>'terminal_label', ''),
      nullif(lp.metadata->>'terminalName', ''),
      nullif(lp.metadata->>'terminal_name', ''),
      nullif(lp.metadata->>'deviceName', ''),
      nullif(lp.metadata->>'device_name', '')
    ) as terminal_label,
    lower(coalesce(
      nullif(p.metadata->>'platform', ''),
      nullif(l.metadata->>'platform', ''),
      nullif(lp.metadata->>'platform', '')
    )) as terminal_platform,
    lower(coalesce(
      nullif(p.metadata->>'source', ''),
      nullif(l.metadata->>'source', ''),
      nullif(lp.metadata->>'source', '')
    )) as terminal_source,
    lower(coalesce(
      nullif(p.metadata->>'runtime', ''),
      nullif(p.metadata->>'clientRuntime', ''),
      nullif(p.metadata->>'client_runtime', ''),
      nullif(l.metadata->>'runtime', ''),
      nullif(l.metadata->>'clientRuntime', ''),
      nullif(l.metadata->>'client_runtime', ''),
      nullif(lp.metadata->>'runtime', ''),
      nullif(lp.metadata->>'clientRuntime', ''),
      nullif(lp.metadata->>'client_runtime', '')
    )) as terminal_runtime,
    lower(coalesce(
      nullif(p.metadata->>'deviceType', ''),
      nullif(p.metadata->>'device_type', ''),
      nullif(p.metadata->>'terminalDeviceType', ''),
      nullif(p.metadata->>'terminal_device_type', ''),
      nullif(l.metadata->>'deviceType', ''),
      nullif(l.metadata->>'device_type', ''),
      nullif(l.metadata->>'terminalDeviceType', ''),
      nullif(l.metadata->>'terminal_device_type', ''),
      nullif(lp.metadata->>'deviceType', ''),
      nullif(lp.metadata->>'device_type', ''),
      nullif(lp.metadata->>'terminalDeviceType', ''),
      nullif(lp.metadata->>'terminal_device_type', '')
    )) as terminal_device_type,
    lower(coalesce(
      nullif(p.metadata->>'terminalType', ''),
      nullif(p.metadata->>'terminal_type', ''),
      nullif(l.metadata->>'terminalType', ''),
      nullif(l.metadata->>'terminal_type', ''),
      nullif(lp.metadata->>'terminalType', ''),
      nullif(lp.metadata->>'terminal_type', '')
    )) as terminal_type,
    case lower(coalesce(
      nullif(p.metadata->>'isNative', ''),
      nullif(p.metadata->>'is_native', ''),
      nullif(l.metadata->>'isNative', ''),
      nullif(l.metadata->>'is_native', ''),
      nullif(lp.metadata->>'isNative', ''),
      nullif(lp.metadata->>'is_native', '')
    ))
      when 'true' then true
      when 'false' then false
      else null
    end as terminal_is_native,
    b.batch_id,
    b.received_at as batch_received_at,
    b.processed_at as batch_processed_at,
    b.status as batch_status,
    b.error_code as batch_error_code,
    b.point_count as batch_point_count,
    d.dvr_first_point_at,
    d.dvr_last_point_at,
    d.dvr_points_24h,
    d.dvr_session_id
  from identities i
  left join telemetry.terminal_location_current l
    on l.organization_id = i.organization_id and l.terminal_id = i.terminal_id
  left join telemetry.terminal_presence_current p
    on p.organization_id = i.organization_id and p.terminal_id = i.terminal_id
  left join lateral (
    select batch_id, received_at, processed_at, status, error_code, point_count
    from telemetry.gps_batches
    where organization_id = i.organization_id and terminal_id = i.terminal_id
    order by received_at desc
    limit 1
  ) b on true
  left join lateral (
    select metadata
    from telemetry.gps_points
    where organization_id = i.organization_id and terminal_id = i.terminal_id
    order by ingested_at desc, fix_at desc
    limit 1
  ) lp on true
  left join lateral (
    select
      min(fix_at) filter (where fix_at >= clock_timestamp() - interval '24 hours') as dvr_first_point_at,
      max(fix_at) filter (where fix_at >= clock_timestamp() - interval '24 hours') as dvr_last_point_at,
      count(*) filter (where fix_at >= clock_timestamp() - interval '24 hours')::bigint as dvr_points_24h,
      (array_agg(coalesce(metadata->>'dvrSessionId', metadata->>'dvr_session_id')
        order by fix_at desc) filter (
          where coalesce(metadata->>'dvrSessionId', metadata->>'dvr_session_id') is not null
        ))[1] as dvr_session_id
    from telemetry.gps_points
    where organization_id = i.organization_id and terminal_id = i.terminal_id
      and fix_at >= clock_timestamp() - interval '24 hours'
  ) d on true
),
terminal_consolidated as (
  select
    terminal_raw.*,
    max(terminal_label) over identity as canonical_terminal_label,
    max(terminal_platform) over identity as canonical_terminal_platform,
    max(terminal_runtime) over identity as canonical_terminal_runtime,
    max(terminal_device_type) over identity as canonical_terminal_device_type,
    max(terminal_type) over identity as canonical_terminal_type,
    bool_or(terminal_is_native) over identity as canonical_terminal_is_native,
    bool_or(
      terminal_source like 'native_%'
      or terminal_source in ('background_geolocation', 'capacitor')
    ) over identity as canonical_native_source,
    min(dvr_first_point_at) over identity as canonical_dvr_first_point_at,
    max(dvr_last_point_at) over identity as canonical_dvr_last_point_at,
    sum(coalesce(dvr_points_24h, 0)) over identity as canonical_dvr_points_24h,
    max(dvr_session_id) over identity as canonical_dvr_session_id,
    row_number() over (
      partition by organization_id, canonical_terminal_id
      order by coalesce(fix_at, heartbeat_at, batch_received_at) desc nulls last,
        observed_terminal_id
    ) as terminal_rank
  from terminal_raw
  window identity as (partition by organization_id, canonical_terminal_id)
),
terminal_audit as (
  select
    terminal_consolidated.*,
    case
      when canonical_terminal_platform in ('android', 'ios')
        then 'capacitor_mobile'
      when canonical_terminal_runtime = 'capacitor'
        and coalesce(canonical_terminal_device_type, canonical_terminal_type, '') in (
          'mobile', 'mobile_terminal', 'handheld', 'android_terminal'
        )
        then 'capacitor_mobile'
      when (
          canonical_terminal_is_native is true
          or canonical_native_source is true
        )
        and coalesce(canonical_terminal_device_type, canonical_terminal_type, '') in (
          'mobile', 'mobile_terminal', 'handheld', 'android_terminal'
        )
        then 'capacitor_mobile'
      when canonical_terminal_platform in ('web', 'windows', 'linux', 'macos')
        or canonical_terminal_runtime in ('web', 'tauri')
        or coalesce(canonical_terminal_device_type, canonical_terminal_type, '') in (
          'fixed', 'fijo', 'static', 'pc', 'web_station'
        )
        then 'non_mobile'
      else 'unknown'
    end as terminal_class
  from terminal_consolidated
  where terminal_rank = 1
)
select jsonb_build_object(
  'terminals',
  coalesce((
    select jsonb_agg(jsonb_build_object(
      'organizationId', organization_id,
      'terminalId', canonical_terminal_id,
      'bindingEpoch', binding_epoch,
      'sequence', sequence,
      'fixAt', fix_at,
      'ingestedAt', ingested_at,
      'projectedAt', projected_at,
      'latitude', latitude,
      'longitude', longitude,
      'accuracy', accuracy,
      'speed', speed,
      'heading', heading,
      'continuityStatus', continuity_status,
      'queueLagSeconds', queue_lag_seconds,
      'heartbeatAt', heartbeat_at,
      'presenceStatus', presence_status,
      'appState', app_state,
      'batteryLevel', battery_level,
      'queueDepth', queue_depth,
      'terminalLabel', canonical_terminal_label,
      'terminalPlatform', canonical_terminal_platform,
      'terminalRuntime', canonical_terminal_runtime,
      'terminalDeviceType', canonical_terminal_device_type,
      'terminalType', canonical_terminal_type,
      'terminalIsNative', canonical_terminal_is_native,
      'terminalClass', terminal_class,
      'lastBatchId', batch_id,
      'lastBatchReceivedAt', batch_received_at,
      'lastBatchProcessedAt', batch_processed_at,
      'lastBatchStatus', batch_status,
      'lastBatchErrorCode', batch_error_code,
      'lastBatchPointCount', batch_point_count,
      'dvrFirstPointAt', canonical_dvr_first_point_at,
      'dvrLastPointAt', canonical_dvr_last_point_at,
      'dvrPoints24h', coalesce(canonical_dvr_points_24h, 0),
      'dvrSessionId', canonical_dvr_session_id,
      'recentBatches', coalesce((
        select jsonb_agg(jsonb_build_object(
          'batchId', recent.batch_id,
          'receivedAt', recent.received_at,
          'processedAt', recent.processed_at,
          'status', recent.status,
          'errorCode', recent.error_code,
          'pointCount', recent.point_count,
          'firstSequence', recent.first_sequence
        ) order by recent.received_at desc)
        from (
          select
            rb.batch_id,
            rb.received_at,
            rb.processed_at,
            rb.status,
            rb.error_code,
            rb.point_count,
            rb.first_sequence
          from telemetry.gps_batches rb
          where rb.organization_id = terminal_audit.organization_id
            and rb.terminal_id in (
              terminal_audit.observed_terminal_id,
              terminal_audit.canonical_terminal_id
            )
          order by rb.received_at desc
          limit 8
        ) recent
      ), '[]'::jsonb),
      'recentPoints', coalesce((
        select jsonb_agg(jsonb_build_object(
          'sequence', recent.sequence,
          'fixAt', recent.fix_at,
          'ingestedAt', recent.ingested_at,
          'source', recent.metadata->>'source',
          'appState', recent.app_state,
          'provider', recent.provider,
          'accuracy', recent.accuracy,
          'latitude', recent.latitude,
          'longitude', recent.longitude,
          'dvrSessionId', coalesce(
            recent.metadata->>'dvrSessionId',
            recent.metadata->>'dvr_session_id'
          )
        ) order by recent.ingested_at desc, recent.fix_at desc)
        from (
          select
            rp.sequence,
            rp.fix_at,
            rp.ingested_at,
            rp.metadata,
            rp.app_state,
            rp.provider,
            rp.accuracy,
            rp.latitude,
            rp.longitude
          from telemetry.gps_points rp
          where rp.organization_id = terminal_audit.organization_id
            and (
              rp.terminal_id in (
                terminal_audit.observed_terminal_id,
                terminal_audit.canonical_terminal_id
              )
              or coalesce(
                nullif(rp.metadata->>'assignedDeviceId', ''),
                nullif(rp.metadata->>'assigned_device_id', ''),
                nullif(rp.metadata->>'terminalUuid', ''),
                nullif(rp.metadata->>'terminal_uuid', '')
              ) = terminal_audit.canonical_terminal_id
            )
          order by rp.ingested_at desc, rp.fix_at desc
          limit 12
        ) recent
      ), '[]'::jsonb)
    ) order by coalesce(fix_at, heartbeat_at, batch_received_at) desc nulls last)
    from terminal_audit
  ), '[]'::jsonb),
  'unresolvedDeadLetters', (
    select count(*) from telemetry.dead_letters where resolved_at is null
  ),
  'recentDeadLetters', coalesce((
    select jsonb_agg(jsonb_build_object(
      'stream', stream,
      'subject', subject,
      'category', category,
      'reason', reason,
      'failedAt', failed_at
    ) order by failed_at desc)
    from (
      select stream, subject, category, reason, failed_at
      from telemetry.dead_letters
      where resolved_at is null
      order by failed_at desc
      limit 20
    ) latest_dead_letters
  ), '[]'::jsonb)
);
"#;

fn project_service_audit(
    install_dir: &Path,
    project_name: &str,
) -> Result<(Vec<NodeAuditService>, Option<String>), String> {
    if let Some(client) = supervisor_client() {
        return match client.request(SupervisorCommand::ProjectAudit {
            install_dir: install_dir.to_string_lossy().into_owned(),
        })? {
            SupervisorReply::ProjectAudit(summary) => Ok((
                summary
                    .services
                    .into_iter()
                    .map(|service| NodeAuditService {
                        workload: service.workload,
                        container_name: service.container_name,
                        state: service.state,
                        health: service.health,
                    })
                    .collect(),
                summary.has_postgres.then(|| "supervisor-owned".to_string()),
            )),
            _ => Err(
                "Supervisor devolvio una respuesta inesperada al auditar servicios.".to_string(),
            ),
        };
    }
    let ids = docker_project_container_ids(project_name)?;
    if ids.is_empty() {
        return Err(format!(
            "El proyecto Docker {project_name} no tiene contenedores materializados."
        ));
    }
    let output = Command::new("docker")
        .arg("inspect")
        .args(&ids)
        .output()
        .map_err(|error| format!("No se pudo inspeccionar el proyecto {project_name}: {error}"))?;
    let raw = output_text(output)?;
    let containers = serde_json::from_str::<Vec<serde_json::Value>>(&raw)
        .map_err(|error| format!("Docker devolvio un inventario invalido: {error}"))?;
    let mut services = Vec::new();
    let mut postgres_id = None;
    for container in containers {
        let labels = container
            .get("Config")
            .and_then(|value| value.get("Labels"))
            .and_then(serde_json::Value::as_object);
        let workload = labels
            .and_then(|value| value.get("com.actium.workload"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("desconocido")
            .to_string();
        let id = container
            .get("Id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        if workload == "datastore_postgres" && !id.is_empty() {
            postgres_id = Some(id);
        }
        let state = container
            .get("State")
            .and_then(|value| value.get("Status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let health = container
            .get("State")
            .and_then(|value| value.get("Health"))
            .and_then(|value| value.get("Status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or(if state == "running" {
                "running"
            } else {
                "none"
            })
            .to_string();
        let container_name = container
            .get("Name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        services.push(NodeAuditService {
            workload,
            container_name,
            state,
            health,
        });
    }
    services.sort_by(|left, right| left.workload.cmp(&right.workload));
    Ok((services, postgres_id))
}

fn query_telemetry_audit(
    install_dir: &Path,
    postgres_id: &str,
) -> Result<serde_json::Value, String> {
    if let Some(client) = supervisor_client() {
        return match client.request(SupervisorCommand::TelemetryAudit {
            install_dir: install_dir.to_string_lossy().into_owned(),
        })? {
            SupervisorReply::Json { value } => serde_json::from_str(value.trim())
                .map_err(|error| format!("La auditoria local devolvio JSON invalido: {error}")),
            _ => Err(
                "Supervisor devolvio una respuesta inesperada al auditar telemetria.".to_string(),
            ),
        };
    }
    let shell = r#"export PGPASSWORD="$(cat /run/secrets/postgres_password)"; exec psql -U aegis_data_plane -d aegis_data_plane -At -v ON_ERROR_STOP=1 -c "$1""#;
    let output = Command::new("docker")
        .args(["exec", postgres_id, "sh", "-ec", shell, "actium-audit"])
        .arg(TELEMETRY_AUDIT_SQL)
        .output()
        .map_err(|error| format!("No se pudo consultar la telemetria local: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "PostgreSQL no pudo producir la auditoria: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let body = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(body.trim())
        .map_err(|error| format!("La auditoria local devolvio JSON invalido: {error}"))
}

fn collect_node_audit(install_dir: &Path) -> Result<NodeAuditSnapshot, String> {
    let state = inspect_path(install_dir);
    target_is_safe(install_dir, &state)?;
    if !state.operational {
        return Err("La auditoria requiere un nodo operativo administrado.".to_string());
    }
    if !state.profiles.iter().any(|profile| profile == "telemetry") {
        return Err("El nodo no tiene autorizado el perfil GPS + DVR.".to_string());
    }
    let project_name = installation_project_name(&state)
        .ok_or_else(|| "El nodo no conserva su nombre de proyecto Docker.".to_string())?
        .to_string();
    let (services, postgres_id) = project_service_audit(install_dir, &project_name)?;
    let (database_ok, database_error, telemetry) = match postgres_id {
        Some(postgres_id) => match query_telemetry_audit(install_dir, &postgres_id) {
            Ok(value) => (true, None, value),
            Err(error) => (
                false,
                Some(error),
                serde_json::json!({
                    "terminals": [],
                    "unresolvedDeadLetters": 0,
                    "recentDeadLetters": []
                }),
            ),
        },
        None => (
            false,
            Some("No se encontro el contenedor PostgreSQL del nodo.".to_string()),
            serde_json::json!({
                "terminals": [],
                "unresolvedDeadLetters": 0,
                "recentDeadLetters": []
            }),
        ),
    };
    Ok(NodeAuditSnapshot {
        generated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string(),
        project_name,
        services,
        database_ok,
        database_error,
        telemetry,
    })
}

fn endpoint_host(value: &str) -> Option<String> {
    let (_, remainder) = value.trim().split_once("://")?;
    let authority = remainder.split('/').next()?.rsplit('@').next()?;
    if authority.starts_with('[') {
        return authority
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('[').to_ascii_lowercase());
    }
    Some(
        authority
            .split(':')
            .next()
            .unwrap_or(authority)
            .to_ascii_lowercase(),
    )
}

fn endpoint_port(value: &str) -> Option<u16> {
    let (scheme, remainder) = value.trim().split_once("://")?;
    let authority = remainder.split('/').next()?.rsplit('@').next()?;
    if authority.starts_with('[') {
        let (_, suffix) = authority.split_once(']')?;
        return suffix.strip_prefix(':')?.parse::<u16>().ok();
    }
    authority
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .or_else(|| match scheme.to_ascii_lowercase().as_str() {
            "https" | "wss" => Some(443),
            "http" | "ws" => Some(80),
            _ => None,
        })
}

fn endpoint_is_plain_root(value: &str) -> bool {
    let Some((_, remainder)) = value.trim().split_once("://") else {
        return false;
    };
    if remainder.contains('?') || remainder.contains('#') {
        return false;
    }
    let path = remainder.find('/').map(|index| &remainder[index..]);
    matches!(path, None | Some("/"))
}

fn endpoint_from_base(base_url: &str, port: u16) -> String {
    format!("{}:{port}", base_url.trim_end_matches('/'))
}

fn derived_trusted_lan_endpoint(
    current: Option<&String>,
    previous_base_url: &str,
    next_base_url: &str,
    port: u16,
) -> String {
    let current = current.map(String::as_str).unwrap_or("").trim();
    if current.is_empty() {
        return endpoint_from_base(next_base_url, port);
    }
    let should_replace = endpoint_host(current) == endpoint_host(previous_base_url)
        && endpoint_port(current) == Some(port)
        && endpoint_is_plain_root(current);
    if should_replace {
        endpoint_from_base(next_base_url, port)
    } else {
        current.to_string()
    }
}

fn derived_trusted_lan_site_core_endpoint(
    current: Option<&String>,
    previous_base_url: &str,
    next_base_url: &str,
    port: u16,
) -> String {
    let current = current.map(String::as_str).unwrap_or("").trim();
    if current.is_empty() {
        return endpoint_from_base(next_base_url, port);
    }
    let current_host_is_ip = endpoint_host(current)
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some();
    let should_replace = endpoint_is_plain_root(current)
        && (current_host_is_ip || endpoint_host(current) == endpoint_host(previous_base_url));
    if should_replace {
        endpoint_from_base(next_base_url, port)
    } else {
        current.to_string()
    }
}

fn derived_trusted_lan_host(
    current: Option<&String>,
    previous_base_url: &str,
    next_base_url: &str,
) -> String {
    let current = current.map(String::as_str).unwrap_or("").trim();
    let previous_host = endpoint_host(previous_base_url).unwrap_or_default();
    let next_host = endpoint_host(next_base_url).unwrap_or_default();
    if current.is_empty() || current.eq_ignore_ascii_case(&previous_host) {
        next_host
    } else {
        current.to_string()
    }
}

fn reconcile_trusted_lan_document(current: &str, next_base_url: &str) -> Option<String> {
    let config = read_env_file_from_contents(current);
    if config.get("DATA_PLANE_NETWORK_MODE").map(String::as_str) != Some("trusted_lan") {
        return None;
    }

    let previous_base_url = config
        .get("DATA_PLANE_PUBLIC_BASE_URL")
        .map(String::as_str)
        .unwrap_or("")
        .trim_end_matches('/');
    if previous_base_url.is_empty() {
        return None;
    }

    let updates = BTreeMap::from([
        ("DATA_PLANE_BIND_ADDRESS", "0.0.0.0".to_string()),
        ("DATA_PLANE_PUBLIC_BASE_URL", next_base_url.to_string()),
        (
            "TELEMETRY_INGRESS_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("TELEMETRY_INGRESS_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "TELEMETRY_PORT", 8090),
            ),
        ),
        (
            "TELEMETRY_READ_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("TELEMETRY_READ_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "TELEMETRY_PORT", 8090),
            ),
        ),
        (
            "METRICS_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("METRICS_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "PROMETHEUS_PORT", 9090),
            ),
        ),
        (
            "RADIO_CONTROL_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("RADIO_CONTROL_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "RADIO_CONTROL_PORT", 8100),
            ),
        ),
        (
            "SITE_CORE_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("SITE_CORE_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "SITE_CORE_PORT", 8088),
            ),
        ),
        (
            "PEOPLE_RESOLVE_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("PEOPLE_RESOLVE_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "PEOPLE_PORT", 8092),
            ),
        ),
        (
            "CONTROL_RUNTIME_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("CONTROL_RUNTIME_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "CONTROL_RUNTIME_PORT", 8094),
            ),
        ),
        (
            "ACTIUM_SITE_CORE_ENDPOINT",
            // A direct IP belongs to the managed trusted-LAN route. Preserve
            // DNS/proxy routes, but repair both a moved LAN address and a
            // legacy Site Core port before the agent publishes its endpoint.
            derived_trusted_lan_site_core_endpoint(
                config.get("ACTIUM_SITE_CORE_ENDPOINT"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "SITE_CORE_PORT", 8088),
            ),
        ),
        (
            "LIVEKIT_PUBLIC_URL",
            derived_trusted_lan_endpoint(
                config.get("LIVEKIT_PUBLIC_URL"),
                previous_base_url,
                next_base_url,
                configured_port(&config, "LIVEKIT_HTTP_PORT", 7880),
            ),
        ),
        (
            "LIVEKIT_NODE_IP",
            derived_trusted_lan_host(
                config.get("LIVEKIT_NODE_IP"),
                previous_base_url,
                next_base_url,
            ),
        ),
        (
            "TURN_EXTERNAL_IP",
            derived_trusted_lan_host(
                config.get("TURN_EXTERNAL_IP"),
                previous_base_url,
                next_base_url,
            ),
        ),
    ]);
    let updated = updated_env_document(current, &updates);
    (updated != current).then_some(updated)
}

fn reconcile_trusted_lan_before_action(path: &Path) -> Result<Option<String>, String> {
    let node_env_path = path.join("node.env");
    let current = fs::read_to_string(&node_env_path)
        .map_err(|error| format!("No se pudo leer node.env para actualizar la LAN: {error}"))?;
    let config = read_env_file(&node_env_path);
    if config.get("DATA_PLANE_NETWORK_MODE").map(String::as_str) != Some("trusted_lan") {
        return Ok(None);
    }

    let next_base_url = suggested_public_base_url();
    let next_host = endpoint_host(&next_base_url).unwrap_or_default();
    if matches!(next_host.as_str(), "127.0.0.1" | "localhost" | "::1") {
        return Ok(None);
    }

    let mut reconciled_files = Vec::new();
    for relative in ["node.env", "secrets/data-plane.env"] {
        let env_path = path.join(relative);
        if !env_path.is_file() {
            continue;
        }
        let document = if relative == "node.env" {
            current.clone()
        } else {
            fs::read_to_string(&env_path).map_err(|error| {
                format!("No se pudo leer {relative} para actualizar la LAN: {error}")
            })?
        };
        if let Some(updated) = reconcile_trusted_lan_document(&document, &next_base_url) {
            write_secure(&env_path, &updated)?;
            reconciled_files.push(relative);
        }
    }

    if reconciled_files.is_empty() {
        Ok(None)
    } else {
        Ok(Some(format!(
            "LAN de confianza reconciliada antes de operar en {}: {next_base_url}.",
            reconciled_files.join(", ")
        )))
    }
}

fn configured_bool(config: &BTreeMap<String, String>, key: &str, fallback: bool) -> bool {
    config
        .get(key)
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(fallback)
}

fn read_ht_runtime_config(
    install_dir: &Path,
    project_name: &str,
) -> Result<serde_json::Value, String> {
    if let Some(client) = supervisor_client() {
        return match client.request(SupervisorCommand::NodeAgentRuntime {
            install_dir: install_dir.to_string_lossy().into_owned(),
        })? {
            SupervisorReply::Json { value } => serde_json::from_str(&value)
                .map_err(|error| format!("runtime.json no contiene JSON valido: {error}")),
            _ => Err("Supervisor devolvio una respuesta inesperada al auditar HT.".to_string()),
        };
    }
    let ids = docker_project_container_ids(project_name)?;
    if ids.is_empty() {
        return Err("El proyecto no tiene contenedores materializados.".to_string());
    }
    let output = Command::new("docker")
        .arg("inspect")
        .args(&ids)
        .output()
        .map_err(|error| format!("No se pudo ubicar el agente del nodo: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Docker no pudo inspeccionar el agente del nodo: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let containers = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout)
        .map_err(|error| format!("Docker devolvio un inventario invalido: {error}"))?;
    let agent_id = containers.iter().find_map(|container| {
        let workload = container
            .get("Config")
            .and_then(|value| value.get("Labels"))
            .and_then(|value| value.get("com.actium.workload"))
            .and_then(serde_json::Value::as_str);
        let state = container
            .get("State")
            .and_then(|value| value.get("Status"))
            .and_then(serde_json::Value::as_str);
        if workload == Some("node_agent") && state == Some("running") {
            container
                .get("Id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        } else {
            None
        }
    });
    let agent_id =
        agent_id.ok_or_else(|| "El agente del nodo no esta en ejecucion.".to_string())?;
    let output = Command::new("docker")
        .args([
            "exec",
            agent_id.as_str(),
            "cat",
            "/var/lib/actium-node-config/runtime.json",
        ])
        .output()
        .map_err(|error| format!("No se pudo leer la configuracion aplicada: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "El agente aun no publico runtime.json: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .map_err(|error| format!("runtime.json no contiene JSON valido: {error}"))
}

fn ht_finding(
    code: &str,
    tone: &str,
    title: &str,
    detail: impl Into<String>,
    action: &str,
) -> NodeHtAuditFinding {
    NodeHtAuditFinding {
        code: code.to_string(),
        tone: tone.to_string(),
        title: title.to_string(),
        detail: detail.into(),
        action: action.to_string(),
    }
}

fn collect_node_ht_audit(install_dir: &Path) -> Result<NodeHtAuditSnapshot, String> {
    let state = inspect_path(install_dir);
    target_is_safe(install_dir, &state)?;
    if !state.operational {
        return Err("La auditoria HT requiere un nodo operativo administrado.".to_string());
    }
    let radio_profiles = state
        .profiles
        .iter()
        .filter(|profile| profile.starts_with("radio-"))
        .cloned()
        .collect::<Vec<_>>();
    if radio_profiles.is_empty() {
        return Err("El nodo no tiene autorizado ningun perfil HT.".to_string());
    }
    let project_name = installation_project_name(&state)
        .ok_or_else(|| "El nodo no conserva su nombre de proyecto Docker.".to_string())?
        .to_string();
    let (all_services, _) = project_service_audit(install_dir, &project_name)?;
    let services = all_services
        .into_iter()
        .filter(|service| {
            service.workload.starts_with("radio_")
                || matches!(
                    service.workload.as_str(),
                    "broker_nats" | "object_storage" | "node_agent"
                )
        })
        .collect::<Vec<_>>();
    let runtime_result = read_ht_runtime_config(install_dir, &project_name);
    let (runtime, runtime_error) = match runtime_result {
        Ok(value) => (value, None),
        Err(error) => (serde_json::Value::Null, Some(error)),
    };

    let config = &state.config;
    let public_base_url = config
        .get("DATA_PLANE_PUBLIC_BASE_URL")
        .cloned()
        .unwrap_or_default();
    let radio_control_url = config
        .get("RADIO_CONTROL_PUBLIC_URL")
        .cloned()
        .unwrap_or_default();
    let turn_urls = config
        .get("TURN_URLS")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let livekit_public_url = config
        .get("LIVEKIT_PUBLIC_URL")
        .cloned()
        .unwrap_or_default();
    let saf_enabled = state.profiles.iter().any(|profile| profile == "radio-saf")
        && configured_bool(config, "RADIO_SAF_ENABLED", false);
    let turn_enabled = state.profiles.iter().any(|profile| profile == "radio-turn");
    let livekit_enabled = state
        .profiles
        .iter()
        .any(|profile| profile == "radio-livekit")
        && configured_bool(config, "RADIO_LIVEKIT_ENABLED", false);
    let base_host = endpoint_host(&public_base_url);
    let radio_host = endpoint_host(&radio_control_url);
    let endpoint_host_aligned = match (&base_host, &radio_host) {
        (Some(base), Some(radio)) => base == radio,
        _ => false,
    };

    let runtime_generation = runtime
        .get("generation")
        .and_then(serde_json::Value::as_i64);
    let runtime_checksum = runtime
        .get("checksum")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let runtime_radio_url = runtime
        .get("publicEndpoints")
        .and_then(|value| value.get("radio_control_url"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let radio_service = services
        .iter()
        .find(|service| service.workload == "radio_control");

    let mut findings = Vec::new();
    match radio_service {
        Some(service) if service.state == "running" && service.health == "healthy" => {
            findings.push(ht_finding(
                "RADIO_CONTROL_READY",
                "ok",
                "Radio Control local operativo",
                format!("{} esta healthy.", service.container_name),
                "Ninguna accion local requerida.",
            ));
        }
        Some(service) => findings.push(ht_finding(
            "RADIO_CONTROL_DEGRADED",
            "bad",
            "Radio Control local degradado",
            format!(
                "{} informa state={} y health={}.",
                service.container_name, service.state, service.health
            ),
            "Abrir registros HT y verificar el nodo antes de reiniciar.",
        )),
        None => findings.push(ht_finding(
            "RADIO_CONTROL_MISSING",
            "bad",
            "Radio Control no materializado",
            "El perfil esta autorizado, pero Docker no expone el workload radio_control.",
            "Actualizar o recrear el nodo y volver a auditar.",
        )),
    }
    if runtime_generation.is_none() {
        findings.push(ht_finding(
            "RUNTIME_CONFIG_UNAVAILABLE",
            "bad",
            "Configuracion aplicada no verificable",
            runtime_error
                .clone()
                .unwrap_or_else(|| "runtime.json no esta disponible.".to_string()),
            "Verificar el agente y revisar sus registros.",
        ));
    } else {
        findings.push(ht_finding(
            "RUNTIME_CONFIG_APPLIED",
            "ok",
            "Generacion local aplicada",
            format!(
                "Generacion {} con checksum {}.",
                runtime_generation.unwrap_or_default(),
                if runtime_checksum.is_empty() {
                    "no informado"
                } else {
                    runtime_checksum
                }
            ),
            "Comparar esta evidencia con desired_generation y desired_checksum en Actium Center.",
        ));
    }
    if !endpoint_host_aligned {
        findings.push(ht_finding(
            "RADIO_ENDPOINT_HOST_DIVERGENCE",
            "warning",
            "Endpoint HT fuera de la base publica del nodo",
            format!(
                "Base={} y Radio Control={}.",
                if public_base_url.is_empty() {
                    "sin configurar"
                } else {
                    public_base_url.as_str()
                },
                if radio_control_url.is_empty() {
                    "sin configurar"
                } else {
                    radio_control_url.as_str()
                }
            ),
            "Corregir la topologia local o republicar el manifiesto con el host efectivo.",
        ));
    }
    if !runtime_radio_url.is_empty()
        && !radio_control_url.is_empty()
        && runtime_radio_url.trim_end_matches('/') != radio_control_url.trim_end_matches('/')
    {
        findings.push(ht_finding(
            "RADIO_ENDPOINT_RUNTIME_DIVERGENCE",
            "warning",
            "Endpoint configurado y endpoint aplicado difieren",
            format!(
                "node.env={} y runtime.json={runtime_radio_url}.",
                radio_control_url
            ),
            "Aplicar la configuracion pendiente o corregir el manifiesto remoto.",
        ));
    }
    if turn_enabled && turn_urls.is_empty() {
        findings.push(ht_finding(
            "TURN_URLS_EMPTY",
            "warning",
            "TURN autorizado sin URLs publicadas",
            "El perfil radio-turn esta instalado, pero TURN_URLS esta vacio.",
            "Configurar las URLs TURN y recrear los servicios.",
        ));
    }
    if livekit_enabled && livekit_public_url.is_empty() {
        findings.push(ht_finding(
            "LIVEKIT_URL_EMPTY",
            "warning",
            "LiveKit autorizado sin URL publica",
            "El perfil radio-livekit esta instalado, pero LIVEKIT_PUBLIC_URL esta vacio.",
            "Configurar una URL wss:// valida antes de asignar canales LiveKit.",
        ));
    }
    findings.push(ht_finding(
        "CHANNEL_AUTHORITY_EXTERNAL",
        "info",
        "Catalogo de canales fuera del nodo",
        "El nodo ejecuta los motores HT, pero los canales pertenecen a la autoridad Actium y no se infieren desde Docker.",
        "Comparar el catalogo canonico de C.O.M. con cualquier configuracion legacy antes de migrar.",
    ));

    let configuration = serde_json::json!({
        "profiles": radio_profiles,
        "networkMode": config.get("DATA_PLANE_NETWORK_MODE"),
        "bindAddress": config.get("DATA_PLANE_BIND_ADDRESS"),
        "publicBaseUrl": public_base_url,
        "corsOriginCount": config
            .get("DATA_PLANE_CORS_ORIGINS")
            .map(|value| value.split(',').filter(|item| !item.trim().is_empty()).count())
            .unwrap_or(0),
        "radioControlPublicUrl": radio_control_url,
        "radioControlPort": config.get("RADIO_CONTROL_PORT"),
        "endpointHostAligned": endpoint_host_aligned,
        "safEnabled": saf_enabled,
        "turnEnabled": turn_enabled,
        "turnUrlCount": turn_urls.len(),
        "turnRealm": config.get("TURN_REALM"),
        "livekitEnabled": livekit_enabled,
        "livekitPublicUrl": livekit_public_url,
        "authorityBoundary": "Los motores y endpoints son locales; canales, permisos y manifiestos pertenecen a Actium Center."
    });

    Ok(NodeHtAuditSnapshot {
        generated_at: operation_timestamp().to_string(),
        project_name,
        services,
        configuration,
        runtime,
        runtime_error,
        findings,
    })
}

#[tauri::command]
async fn audit_node_telemetry(request: NodeAuditRequest) -> Result<NodeAuditSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let install_dir = validated_install_path(&request.install_dir)?;
        collect_node_audit(&install_dir)
    })
    .await
    .map_err(|error| format!("La auditoria del nodo fallo: {error}"))?
}

#[tauri::command]
async fn audit_node_ht(request: NodeAuditRequest) -> Result<NodeHtAuditSnapshot, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let install_dir = validated_install_path(&request.install_dir)?;
        collect_node_ht_audit(&install_dir)
    })
    .await
    .map_err(|error| format!("La auditoria HT del nodo fallo: {error}"))?
}

fn ensure_project_name_available(
    install_dir: &Path,
    requested_project: &str,
) -> Result<(), String> {
    let requested = requested_project.trim();
    if product::compose_project_name(requested) != requested
        || !product::project_name_allowed(requested)
    {
        return Err(if product::is_lab() {
            "El canal Lab exige un nombre tecnico con prefijo actium-lab-.".to_string()
        } else {
            "El canal Stable no puede operar un proyecto reservado al namespace actium-lab-."
                .to_string()
        });
    }
    for node in discover_managed_nodes()? {
        if path_identity(Path::new(&node.install_dir)) == path_identity(install_dir) {
            continue;
        }
        if node.project_name.as_deref() == Some(requested) {
            return Err(format!(
                "El nombre tecnico {requested} ya pertenece a {}. Cada nodo y organizacion debe usar un proyecto Docker unico.",
                node.display_name
            ));
        }
    }
    let current = inspect_path(install_dir);
    let owns_requested_project =
        installation_project_name(&current).is_some_and(|project| project == requested);
    if supervisor_client().is_none()
        && !owns_requested_project
        && command_succeeds("docker", &["info"])
    {
        let orphan_containers = docker_project_container_ids(requested)?;
        if !orphan_containers.is_empty() {
            return Err(format!(
                "El proyecto Docker {requested} ya tiene {} contenedor(es), pero no pertenece a este despliegue. No se modificaron: asigne otro nombre tecnico o recupere primero su instalacion propietaria.",
                orphan_containers.len()
            ));
        }
    }
    Ok(())
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
        let project_name = installation_project_name(&existing).ok_or_else(|| {
            "La preparacion incompleta no conserva el nombre de proyecto Docker.".to_string()
        })?;
        ensure_project_name_available(&install_dir, project_name)?;
        let removed_containers = if supervisor_client().is_some() {
            run_node_action(&install_dir, "stop")?;
            0
        } else {
            remove_project_containers(project_name)?
        };

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
            output: format!(
                "{}\nSe retiraron {removed_containers} contenedor(es) parciales; los volumenes Docker no fueron eliminados.",
                archive_path.to_string_lossy()
            ),
            installed_profiles: Vec::new(),
        })
    })
    .await
    .map_err(|error| format!("La recuperacion de la preparacion fallo: {error}"))?
}

fn run_installer(
    node_root: &Path,
    runtime_path: &Path,
    token: &str,
    prepare_only: bool,
    owned_plan: Option<&NetworkPortPlan>,
) -> Result<String, String> {
    let mut preflight_messages = Vec::new();
    if !prepare_only {
        if supervisor_client().is_none() {
            if let Some(message) = reconcile_trusted_lan_before_action(node_root)? {
                preflight_messages.push(message);
            }
        }
        let config = read_env_file(&node_root.join("node.env"));
        let profiles = split_profiles(
            config
                .get("ACTIUM_PROFILES")
                .map(String::as_str)
                .unwrap_or_default(),
        );
        let requested_plan = configured_network_port_plan(&config);
        if let Some(owned_plan) = owned_plan {
            ensure_network_ports_available_for_existing_runtime(
                node_root,
                &profiles,
                &requested_plan,
                owned_plan,
            )?;
        } else {
            ensure_network_ports_available(&profiles, &requested_plan)?;
        }
    }
    if supervisor_client().is_some() {
        return Err(
            "Actium Node Manager 0.7 ejecuta commissioning y configuracion mediante contratos tipados del Supervisor."
                .to_string(),
        );
    }
    let mut command = if cfg!(target_os = "windows") {
        let mut value = Command::new("powershell.exe");
        value
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(runtime_path.join("install-node.ps1"))
            .arg("-ConfigFile")
            .arg(node_root.join("node.env"));
        if prepare_only {
            value.arg("-PrepareOnly");
        }
        value
    } else {
        let mut value = Command::new("/bin/sh");
        value
            .arg(runtime_path.join("install-node.sh"))
            .arg("--config")
            .arg(node_root.join("node.env"));
        if prepare_only {
            value.arg("--prepare-only");
        }
        value
    };
    command
        .current_dir(runtime_path)
        .env("ACTIUM_SECRETS_DIR", node_root.join("secrets"));
    if !token.trim().is_empty() {
        command.env("ACTIUM_ENROLLMENT_TOKEN_OVERRIDE", token.trim());
    }
    let output = command
        .output()
        .map_err(|error| format!("No se pudo ejecutar el instalador del nodo: {error}"))?;
    let output = output_text(output)?;
    if preflight_messages.is_empty() {
        Ok(output)
    } else {
        Ok(format!("{}\n\n{output}", preflight_messages.join("\n")))
    }
}

#[tauri::command]
async fn apply_installation(
    app: AppHandle,
    request: InstallRequest,
) -> Result<ActionResult, String> {
    require_phase4_supervisor(supervisor_client().is_some())?;
    tauri::async_runtime::spawn_blocking(move || {
        let requested_install_dir = validated_install_path(&request.install_dir)?;
        let existing = inspect_path(&requested_install_dir);
        target_is_safe(&requested_install_dir, &existing)?;
        let payload = payload_dir(&app)?;
        let verified_payload = verify_payload(&payload)?;
        let manifest = match &verified_payload {
            VerifiedPayload::Schema3(manifest) => Some(manifest),
            VerifiedPayload::LegacyUnverified { .. } => None,
        };
        let (profiles, bootstrap) = validate_request(&request, &existing, manifest)?;
        let people_policy_cache = initial_people_policy_cache(&bootstrap)?;
        if let Some(path) = request.node_root_path.as_deref().filter(|p| !p.trim().is_empty()) {
            ensure_custom_storage_directory_if_external("directorio raíz del nodo", path, &requested_install_dir)?;
        }
        if profiles.contains(&"site-core".to_string()) {
            if let Some(path) = request.site_core_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de datos Site Core", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"telemetry".to_string()) {
            if let Some(path) = request.telemetry_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de telemetría", path, &requested_install_dir)?;
            }
            if let Some(path) = request.dvr_media_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de medios DVR", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"people".to_string()) {
            if let Some(path) = request.people_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de datos People", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"control".to_string()) {
            if let Some(path) = request.control_runtime_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de datos Control Runtime", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"radio-control".to_string()) {
            if let Some(path) = request.radio_control_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de datos HT Radio", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"radio-saf".to_string()) {
            if let Some(path) = request.radio_saf_storage_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de almacenamiento Store & Forward", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"radio-turn".to_string()) {
            if let Some(path) = request.turn_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de datos TURN", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"radio-livekit".to_string()) {
            if let Some(path) = request.livekit_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de datos LiveKit", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"observability".to_string()) {
            if let Some(path) = request.prometheus_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de TSDB Prometheus", path, &requested_install_dir)?;
            }
            if let Some(path) = request.grafana_data_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de Grafana Dashboards", path, &requested_install_dir)?;
            }
        }
        if profiles.contains(&"connectivity".to_string()) {
            if let Some(path) = request.connectivity_spool_path.as_deref().filter(|p| !p.trim().is_empty()) {
                ensure_custom_storage_directory_if_external("ruta de spool Connectivity", path, &requested_install_dir)?;
            }
        }
        ensure_project_name_available(&requested_install_dir, &request.project_name)?;
        ensure_network_ports_unreserved(
            &requested_install_dir,
            &profiles,
            &install_port_plan(&request),
        )?;
        if !request.prepare_only && !existing.operational {
            ensure_network_ports_available_for_existing_runtime(
                &requested_install_dir,
                &profiles,
                &install_port_plan(&request),
                &configured_network_port_plan(&existing.config),
            )?;
        }
        if existing.operational && path_is_within(&requested_install_dir, &recovery_root_dir()) {
            return Err(
                "El nodo ya es operativo pero sigue archivado. Use Promover nodo desde el gestor para moverlo de forma transaccional sin reimportar el .adpe."
                    .to_string(),
            );
        }
        if supervisor_client().is_some()
            && path_is_within(&requested_install_dir, &recovery_root_dir())
        {
            return Err(
                "Actium Node Manager 0.7 no promueve archivos recuperados desde la UI; commissioning exige un destino nuevo administrado por Supervisor."
                    .to_string(),
            );
        }
        let install_dir = if path_is_within(&requested_install_dir, &recovery_root_dir()) {
            promote_archived_directory(&requested_install_dir, &existing)?
        } else {
            requested_install_dir.clone()
        };
        let promoted = path_identity(&install_dir) != path_identity(&requested_install_dir);
        let payload_manifest = validate_payload_manifest(&payload)?;
        let version = payload_manifest.version;
        if let Some(client) = supervisor_client() {
            let resume_incomplete = incomplete_commission_resume_allowed(
                &existing,
                &install_dir,
                &bootstrap.deployment_id,
            )?;
            let has_material_files = install_dir.exists()
                && fs::read_dir(&install_dir)
                    .ok()
                    .map(|entries| {
                        entries.filter_map(Result::ok).any(|entry| {
                            let name = entry.file_name();
                            let name_str = name.to_string_lossy();
                            name_str == "compose.yml"
                                || name_str == "node.env"
                                || name_str == ".actium-node-installation.json"
                                || name_str == "installation.json"
                        })
                    })
                    .unwrap_or(false);
            if !resume_incomplete
                && (existing.installed || has_material_files)
            {
                return Err(
                    "El commissioning 0.7 solo acepta un destino nuevo y vacio; use las operaciones del nodo para instalaciones ya creadas."
                        .to_string(),
                );
            }
            let installation_id = if resume_incomplete {
                existing.installation_id.clone().ok_or_else(|| {
                    "La preparacion incompleta no conserva installationId.".to_string()
                })?
            } else {
                uuid::Uuid::new_v4().to_string()
            };
            let site_runtime_public_key = if profiles
                .iter()
                .any(|profile| profile == "site-core" || profile == "control")
            {
                Some(
                    bootstrap
                        .site_runtime_bundle_public_key_pem
                        .clone()
                        .ok_or_else(|| {
                            "El .adpe no contiene el trust anchor de Site Runtime.".to_string()
                        })?,
                )
            } else {
                None
            };
            let result = match client.request(SupervisorCommand::CommissionNode(
                CommissionNodeRequest {
                    install_dir: install_dir.to_string_lossy().into_owned(),
                    expected_release: version.clone(),
                    node_env: {
                        let generated = node_env_document(
                            &install_dir,
                            &request,
                            &bootstrap,
                            &profiles,
                            &installation_id,
                        );
                        let values = parse_env_document(&generated);
                        if resume_incomplete {
                            render_env_document(&merge_resume_env(
                                &existing.config,
                                &values,
                                &profiles,
                                request.network_configuration_deferred,
                            )?)
                        } else {
                            generated
                        }
                    },
                    marker: marker_document(
                        &version,
                        &profiles,
                        "installing",
                        &bootstrap,
                        &installation_id,
                        None,
                    )?,
                    terminal_public_key: format!(
                        "{}\n",
                        bootstrap.terminal_public_key_pem.trim()
                    ),
                    operator_public_key: format!(
                        "{}\n",
                        bootstrap.operator_public_key_pem.trim()
                    ),
                    site_runtime_public_key: site_runtime_public_key
                        .map(|value| format!("{}\n", value.trim())),
                    initial_people_policy_cache: people_policy_cache.clone(),
                    control_plane_ca_pem: None,
                    connectivity_edge_enrollment_token: profiles
                        .iter()
                        .any(|profile| profile == "connectivity")
                        .then(|| nonempty_secret(&request.connectivity_edge_enrollment_token))
                        .flatten(),
                    connectivity_internal_relay_token: profiles
                        .iter()
                        .any(|profile| profile == "connectivity")
                        .then(|| nonempty_secret(&request.connectivity_internal_relay_token))
                        .flatten(),
                    enrollment_token: bootstrap.enrollment_token.clone(),
                    radio_archive_host_path: profiles
                        .iter()
                        .any(|profile| profile == "radio-saf")
                        .then(|| request.radio_archive_host_path.trim().to_string()),
                    prepare_only: request.prepare_only,
                    connectivity_edge_control_url: None,
                    resume_incomplete,
                },
            ))? {
                SupervisorReply::RuntimeAction(result) => result,
                _ => {
                    return Err(
                        "Supervisor devolvio una respuesta inesperada al crear el nodo."
                            .to_string(),
                    )
                }
            };
            remember_node_path(&install_dir)?;
            return Ok(ActionResult {
                ok: true,
                message: result.message,
                output: result.output,
                installed_profiles: profiles,
            });
        }
        let release_manager = ReleaseManager::new(&install_dir);
        let transactional_install = product::is_lab() && !existing.operational;
        let mut release_transaction = None;
        let runtime_dir = if transactional_install {
            let prepared = release_manager.prepare(&payload)?;
            let transaction = release_manager.begin_promotion(prepared)?;
            let runtime = transaction
                .promoted_state()
                .active_release
                .as_ref()
                .map(|release| install_dir.join(&release.relative_path))
                .ok_or_else(|| "Promocion no materializo release candidato.".to_string())?;
            release_transaction = Some(transaction);
            runtime
        } else {
            let active = release_manager.active_runtime_dir()?;
            if active == install_dir {
                copy_payload(&payload, &install_dir)?;
            }
            active
        };
        fs::create_dir_all(install_dir.join("keys")).map_err(|error| format!("No se pudo crear keys: {error}"))?;
        fs::create_dir_all(install_dir.join("secrets"))
            .map_err(|error| format!("No se pudo crear secrets: {error}"))?;
        if let Some(value) = people_policy_cache.as_deref() {
            write_secure(&install_dir.join("state/agent/people-policy.json"), value)?;
        }
        write_secure(
            &install_dir.join("keys/actium-terminal-public.pem"),
            &format!("{}\n", bootstrap.terminal_public_key_pem.trim()),
        )?;
        write_secure(
            &install_dir.join("keys/actium-operator-public.pem"),
            &format!("{}\n", bootstrap.operator_public_key_pem.trim()),
        )?;
        if profiles.iter().any(|profile| profile == "site-core") {
            let public_key = bootstrap.site_runtime_bundle_public_key_pem.as_deref().ok_or_else(||
                "El .adpe no contiene el trust anchor de Site Runtime.".to_string()
            )?;
            write_secure(
                &install_dir.join("keys/actium-site-runtime-bundle-public.pem"),
                &format!("{}\n", public_key.trim()),
            )?;
        }
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
        if profiles.iter().any(|profile| profile == "radio-saf") {
            ensure_radio_archive_directory(&request.radio_archive_host_path)?;
        }
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
        let existing_plan = configured_network_port_plan(&existing.config);
        let installation_result = run_installer(
            &install_dir,
            &runtime_dir,
            &bootstrap.enrollment_token,
            request.prepare_only,
            Some(&existing_plan),
        )
        .and_then(|output| {
            if request.prepare_only {
                Ok(output)
            } else {
                require_node_health(&install_dir).map(|health| format!("{output}\n\n{health}"))
            }
        });
        match installation_result {
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
                if transactional_install {
                    let release_state = release_transaction
                        .take()
                        .ok_or_else(|| "Transaccion de install ausente.".to_string())?
                        .commit()?;
                    sync_release_marker(
                        &install_dir,
                        &release_state,
                        if request.prepare_only { "prepared" } else { "running" },
                        None,
                    )?;
                }
                Ok(ActionResult {
                    ok: true,
                    message: if promoted {
                        "Nodo recuperado, promovido al inventario administrado y enrolado bajo autoridad Actium.".to_string()
                    } else if existing.operational {
                        "Nodo actualizado y componentes ampliados sin reemplazar secretos ni volumenes.".to_string()
                    } else {
                        "Nodo instalado y enrolado bajo autoridad Actium.".to_string()
                    },
                    output: if promoted {
                        format!(
                            "Promovido a {}\n\n{output}",
                            install_dir.to_string_lossy()
                        )
                    } else {
                        output
                    },
                    installed_profiles: profiles,
                })
            }
            Err(error) => {
                let mut rollback = if existing.operational {
                    "No se retiraron contenedores porque el nodo ya era operativo.".to_string()
                } else {
                    match if supervisor_client().is_some() {
                        run_node_action(&install_dir, "stop").map(|_| 0)
                    } else {
                        remove_project_containers(request.project_name.trim())
                    } {
                        Ok(count) => format!(
                            "Rollback seguro: se retiraron {count} contenedor(es) parciales; secretos y volumenes fueron conservados."
                        ),
                        Err(rollback_error) => format!(
                            "Rollback incompleto: {rollback_error}. Los volumenes no fueron eliminados."
                        ),
                    }
                };
                let initial_error = format!("{error}\n\n{rollback}");
                let _ = write_marker(
                    &install_dir,
                    &version,
                    &profiles,
                    "failed",
                    &bootstrap,
                    &installation_id,
                    Some(&initial_error),
                );
                if transactional_install {
                    if let Some(transaction) = release_transaction.take() {
                        let aborted = transaction.abort().map_err(|abort_error| {
                            format!(
                                "{initial_error}\n\n[MANUAL_INTERVENTION_REQUIRED] El aborto transaccional no pudo persistirse: {abort_error}"
                            )
                        })?;
                        sync_release_marker(
                            &install_dir,
                            &aborted.state,
                            "failed",
                            Some(&initial_error),
                        )?;
                        }
                }
                if promoted {
                    rollback.push_str(
                        match rollback_promoted_directory(
                            &install_dir,
                            &requested_install_dir,
                        ) {
                            Ok(()) => {
                                " La promocion se revirtio y la evidencia recuperable regreso a su ubicacion anterior."
                            }
                            Err(rollback_error) => {
                                return Err(format!(
                                    "{initial_error}\n\nRollback de promocion incompleto: {rollback_error}"
                                ));
                            }
                        },
                    );
                }
                Err(format!("{error}\n\n{rollback}"))
            }
        }
    })
    .await
    .map_err(|error| format!("La tarea de instalacion fallo: {error}"))?
}

fn supervisor_configuration_write_request(
    request: &NodeConfigurationRequest,
    existing: &InstallationState,
) -> ConfigurationWriteRequest {
    let env_updates = BTreeMap::from([
        ("ACTIUM_INSTALLER_VERSION", INSTALLER_VERSION.to_string()),
        (
            "RADIO_SAF_ENABLED",
            existing
                .profiles
                .iter()
                .any(|profile| profile == "radio-saf")
                .to_string(),
        ),
        (
            "RADIO_LIVEKIT_ENABLED",
            existing
                .profiles
                .iter()
                .any(|profile| profile == "radio-livekit")
                .to_string(),
        ),
        (
            "DATA_PLANE_NETWORK_MODE",
            request.network_mode.trim().to_string(),
        ),
        (
            "DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED",
            "false".to_string(),
        ),
        (
            "ACTIUM_NETWORK_RECONCILIATION_POLICY",
            request.network_reconciliation_policy.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_INTERFACE",
            request.network_interface.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_ADDRESS",
            request.network_address.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_PLANE",
            request.network_plane.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_PRIORITY",
            request.network_priority.to_string(),
        ),
        (
            "DATA_PLANE_BIND_ADDRESS",
            request.bind_address.trim().to_string(),
        ),
        (
            "DATA_PLANE_PUBLIC_BASE_URL",
            request.public_base_url.trim_end_matches('/').to_string(),
        ),
        (
            "DATA_PLANE_CORS_ORIGINS",
            request.cors_origins.trim().to_string(),
        ),
        (
            "TELEMETRY_INGRESS_PUBLIC_URL",
            request
                .telemetry_ingress_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "TELEMETRY_READ_PUBLIC_URL",
            request
                .telemetry_read_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "METRICS_PUBLIC_URL",
            request.metrics_public_url.trim_end_matches('/').to_string(),
        ),
        (
            "RADIO_CONTROL_PUBLIC_URL",
            request
                .radio_control_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "SITE_CORE_PUBLIC_URL",
            request
                .site_core_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "PEOPLE_RESOLVE_PUBLIC_URL",
            request
                .people_resolve_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "CONTROL_RUNTIME_PUBLIC_URL",
            request
                .control_runtime_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        ("TURN_URLS", request.turn_urls.trim().to_string()),
        ("TELEMETRY_PORT", request.telemetry_port.to_string()),
        ("PEOPLE_PORT", request.people_port.to_string()),
        ("CONTROL_RUNTIME_PORT", request.control_runtime_port.to_string()),
        ("RADIO_CONTROL_PORT", request.radio_control_port.to_string()),
        ("RADIO_SAF_PORT", request.radio_saf_port.to_string()),
        ("SITE_CORE_PORT", request.site_core_port.to_string()),
        (
            "RADIO_ARCHIVE_HOST_PATH",
            request.radio_archive_host_path.trim().to_string(),
        ),
        ("PROMETHEUS_PORT", request.prometheus_port.to_string()),
        ("GRAFANA_PORT", request.grafana_port.to_string()),
        ("TURN_REALM", request.turn_realm.trim().to_string()),
        (
            "TURN_EXTERNAL_IP",
            request.turn_external_ip.trim().to_string(),
        ),
        ("TURN_PORT", request.turn_port.to_string()),
        ("TURN_TLS_PORT", request.turn_tls_port.to_string()),
        ("TURN_MIN_PORT", request.turn_min_port.to_string()),
        ("TURN_MAX_PORT", request.turn_max_port.to_string()),
        (
            "LIVEKIT_NODE_IP",
            request.livekit_node_ip.trim().to_string(),
        ),
        (
            "LIVEKIT_PUBLIC_URL",
            request.livekit_public_url.trim().to_string(),
        ),
        ("LIVEKIT_HTTP_PORT", request.livekit_http_port.to_string()),
        (
            "LIVEKIT_RTC_TCP_PORT",
            request.livekit_rtc_tcp_port.to_string(),
        ),
        (
            "LIVEKIT_UDP_MIN_PORT",
            request.livekit_udp_min_port.to_string(),
        ),
        (
            "LIVEKIT_UDP_MAX_PORT",
            request.livekit_udp_max_port.to_string(),
        ),
        (
            "CONNECTIVITY_EDGE_CONTROL_URL",
            request
                .connectivity_edge_control_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "CONNECTIVITY_NODE_ROLE",
            request.connectivity_node_role.trim().to_string(),
        ),
        (
            "CONNECTIVITY_NODE_PRIORITY",
            request.connectivity_node_priority.to_string(),
        ),
        (
            "CONNECTIVITY_PULL_LIMIT",
            request.connectivity_pull_limit.to_string(),
        ),
        (
            "CONNECTIVITY_SYNC_ENABLED",
            request.connectivity_sync_enabled.to_string(),
        ),
        (
            "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED",
            request
                .connectivity_direct_data_plane_fallback_enabled
                .to_string(),
        ),
        (
            "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED",
            request.connectivity_supabase_fallback_enabled.to_string(),
        ),
        (
            "CONNECTIVITY_FALLBACK_ORDER",
            request.connectivity_fallback_order.join(","),
        ),
        (
            "CONNECTIVITY_PREFERRED_TRANSPORT",
            request
                .connectivity_preferred_transport
                .as_deref()
                .unwrap_or("direct")
                .to_string(),
        ),
        (
            "CONNECTIVITY_ALLOWED_TRANSPORTS",
            request
                .connectivity_allowed_transports
                .as_deref()
                .map(|v| v.join(","))
                .unwrap_or_else(|| "direct".to_string()),
        ),
        (
            "CONNECTIVITY_GATEWAY_STRATEGY",
            request
                .connectivity_gateway_strategy
                .as_deref()
                .unwrap_or("node_direct")
                .to_string(),
        ),
        (
            "CONNECTIVITY_ROAMING_ALLOWED",
            request
                .connectivity_roaming_allowed
                .unwrap_or(true)
                .to_string(),
        ),
        (
            "ACTIUM_USE_PUBLISHED_IMAGES",
            request.use_published_images.to_string(),
        ),
    ])
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .filter(|(key, _)| {
        key == "ACTIUM_INSTALLER_VERSION" || key_is_authoritative(&existing.profiles, key)
    })
    .collect();
    ConfigurationWriteRequest {
        install_dir: request.install_dir.clone(),
        env_updates,
        connectivity_edge_enrollment_token: existing
            .profiles
            .iter()
            .any(|profile| profile == "connectivity")
            .then(|| nonempty_secret(&request.connectivity_edge_enrollment_token))
            .flatten(),
        connectivity_internal_relay_token: existing
            .profiles
            .iter()
            .any(|profile| profile == "connectivity")
            .then(|| nonempty_secret(&request.connectivity_internal_relay_token))
            .flatten(),
        radio_archive_host_path: existing
            .profiles
            .iter()
            .any(|profile| profile == "radio-saf")
            .then(|| request.radio_archive_host_path.trim().to_string()),
        prepare_rollback: request.restart_services,
    }
}

fn apply_node_configuration(request: NodeConfigurationRequest) -> Result<ActionResult, String> {
    let path = validated_install_path(&request.install_dir)?;
    let existing = inspect_path(&path);
    validate_node_configuration(&request, &existing, &path)?;
    if existing
        .profiles
        .iter()
        .any(|profile| profile == "radio-saf")
    {
        ensure_radio_archive_directory(&request.radio_archive_host_path)?;
    }
    ensure_network_ports_unreserved(
        &path,
        &existing.profiles,
        &configuration_port_plan(&request),
    )?;
    if request.restart_services {
        ensure_changed_network_ports_available(&existing, &configuration_port_plan(&request))?;
    }

    let node_env_path = path.join("node.env");
    let enrollment_path = path.join("secrets/connectivity_edge_enrollment_token");
    let relay_path = path.join("secrets/connectivity_internal_relay_token");
    let original_node_env = fs::read_to_string(&node_env_path)
        .map_err(|error| format!("No se pudo leer node.env: {error}"))?;
    let original_enrollment = fs::read_to_string(&enrollment_path).ok();
    let original_relay = fs::read_to_string(&relay_path).ok();

    let updates = BTreeMap::from([
        ("ACTIUM_INSTALLER_VERSION", INSTALLER_VERSION.to_string()),
        (
            "RADIO_SAF_ENABLED",
            existing
                .profiles
                .iter()
                .any(|profile| profile == "radio-saf")
                .to_string(),
        ),
        (
            "RADIO_LIVEKIT_ENABLED",
            existing
                .profiles
                .iter()
                .any(|profile| profile == "radio-livekit")
                .to_string(),
        ),
        (
            "DATA_PLANE_NETWORK_MODE",
            request.network_mode.trim().to_string(),
        ),
        (
            "DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED",
            "false".to_string(),
        ),
        (
            "ACTIUM_NETWORK_RECONCILIATION_POLICY",
            request.network_reconciliation_policy.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_INTERFACE",
            request.network_interface.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_ADDRESS",
            request.network_address.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_PLANE",
            request.network_plane.trim().to_string(),
        ),
        (
            "ACTIUM_NETWORK_PRIORITY",
            request.network_priority.to_string(),
        ),
        (
            "DATA_PLANE_BIND_ADDRESS",
            request.bind_address.trim().to_string(),
        ),
        (
            "DATA_PLANE_PUBLIC_BASE_URL",
            request.public_base_url.trim_end_matches('/').to_string(),
        ),
        (
            "DATA_PLANE_CORS_ORIGINS",
            request.cors_origins.trim().to_string(),
        ),
        (
            "TELEMETRY_INGRESS_PUBLIC_URL",
            request
                .telemetry_ingress_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "TELEMETRY_READ_PUBLIC_URL",
            request
                .telemetry_read_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "METRICS_PUBLIC_URL",
            request.metrics_public_url.trim_end_matches('/').to_string(),
        ),
        (
            "RADIO_CONTROL_PUBLIC_URL",
            request
                .radio_control_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "SITE_CORE_PUBLIC_URL",
            request
                .site_core_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "PEOPLE_RESOLVE_PUBLIC_URL",
            request
                .people_resolve_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "CONTROL_RUNTIME_PUBLIC_URL",
            request
                .control_runtime_public_url
                .trim_end_matches('/')
                .to_string(),
        ),
        ("TURN_URLS", request.turn_urls.trim().to_string()),
        ("TELEMETRY_PORT", request.telemetry_port.to_string()),
        ("PEOPLE_PORT", request.people_port.to_string()),
        ("CONTROL_RUNTIME_PORT", request.control_runtime_port.to_string()),
        ("RADIO_CONTROL_PORT", request.radio_control_port.to_string()),
        ("RADIO_SAF_PORT", request.radio_saf_port.to_string()),
        ("SITE_CORE_PORT", request.site_core_port.to_string()),
        (
            "RADIO_ARCHIVE_HOST_PATH",
            request.radio_archive_host_path.trim().to_string(),
        ),
        ("PROMETHEUS_PORT", request.prometheus_port.to_string()),
        ("GRAFANA_PORT", request.grafana_port.to_string()),
        ("TURN_REALM", request.turn_realm.trim().to_string()),
        (
            "TURN_EXTERNAL_IP",
            request.turn_external_ip.trim().to_string(),
        ),
        ("TURN_PORT", request.turn_port.to_string()),
        ("TURN_TLS_PORT", request.turn_tls_port.to_string()),
        ("TURN_MIN_PORT", request.turn_min_port.to_string()),
        ("TURN_MAX_PORT", request.turn_max_port.to_string()),
        (
            "LIVEKIT_NODE_IP",
            request.livekit_node_ip.trim().to_string(),
        ),
        (
            "LIVEKIT_PUBLIC_URL",
            request.livekit_public_url.trim().to_string(),
        ),
        ("LIVEKIT_HTTP_PORT", request.livekit_http_port.to_string()),
        (
            "LIVEKIT_RTC_TCP_PORT",
            request.livekit_rtc_tcp_port.to_string(),
        ),
        (
            "LIVEKIT_UDP_MIN_PORT",
            request.livekit_udp_min_port.to_string(),
        ),
        (
            "LIVEKIT_UDP_MAX_PORT",
            request.livekit_udp_max_port.to_string(),
        ),
        (
            "CONNECTIVITY_EDGE_CONTROL_URL",
            request
                .connectivity_edge_control_url
                .trim_end_matches('/')
                .to_string(),
        ),
        (
            "CONNECTIVITY_NODE_ROLE",
            request.connectivity_node_role.trim().to_string(),
        ),
        (
            "CONNECTIVITY_NODE_PRIORITY",
            request.connectivity_node_priority.to_string(),
        ),
        (
            "CONNECTIVITY_PULL_LIMIT",
            request.connectivity_pull_limit.to_string(),
        ),
        (
            "CONNECTIVITY_SYNC_ENABLED",
            request.connectivity_sync_enabled.to_string(),
        ),
        (
            "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED",
            request
                .connectivity_direct_data_plane_fallback_enabled
                .to_string(),
        ),
        (
            "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED",
            request.connectivity_supabase_fallback_enabled.to_string(),
        ),
        (
            "CONNECTIVITY_FALLBACK_ORDER",
            request.connectivity_fallback_order.join(","),
        ),
        (
            "CONNECTIVITY_PREFERRED_TRANSPORT",
            request
                .connectivity_preferred_transport
                .as_deref()
                .unwrap_or("direct")
                .to_string(),
        ),
        (
            "CONNECTIVITY_ALLOWED_TRANSPORTS",
            request
                .connectivity_allowed_transports
                .as_deref()
                .map(|v| v.join(","))
                .unwrap_or_else(|| "direct".to_string()),
        ),
        (
            "CONNECTIVITY_GATEWAY_STRATEGY",
            request
                .connectivity_gateway_strategy
                .as_deref()
                .unwrap_or("node_direct")
                .to_string(),
        ),
        (
            "CONNECTIVITY_ROAMING_ALLOWED",
            request
                .connectivity_roaming_allowed
                .unwrap_or(true)
                .to_string(),
        ),
        (
            "ACTIUM_USE_PUBLISHED_IMAGES",
            request.use_published_images.to_string(),
        ),
    ])
    .into_iter()
    .filter(|(key, _)| {
        *key == "ACTIUM_INSTALLER_VERSION" || key_is_authoritative(&existing.profiles, key)
    })
    .collect();
    let persist_result = (|| -> Result<(), String> {
        write_secure(
            &node_env_path,
            &updated_env_document(&original_node_env, &updates),
        )?;
        let has_connectivity = existing
            .profiles
            .iter()
            .any(|profile| profile == "connectivity");
        if has_connectivity && !request.connectivity_edge_enrollment_token.trim().is_empty() {
            write_secure(
                &enrollment_path,
                &format!("{}\n", request.connectivity_edge_enrollment_token.trim()),
            )?;
        }
        if has_connectivity && !request.connectivity_internal_relay_token.trim().is_empty() {
            write_secure(
                &relay_path,
                &format!("{}\n", request.connectivity_internal_relay_token.trim()),
            )?;
        }
        Ok(())
    })();
    if let Err(error) = persist_result {
        let mut rollback_errors = Vec::new();
        if let Err(rollback_error) = write_secure(&node_env_path, &original_node_env) {
            rollback_errors.push(rollback_error);
        }
        if let Err(rollback_error) =
            restore_optional_secure_file(&enrollment_path, original_enrollment.as_deref())
        {
            rollback_errors.push(rollback_error);
        }
        if let Err(rollback_error) =
            restore_optional_secure_file(&relay_path, original_relay.as_deref())
        {
            rollback_errors.push(rollback_error);
        }
        return Err(if rollback_errors.is_empty() {
            format!("No se pudo guardar la configuracion; se restauro la anterior: {error}")
        } else {
            format!(
                "No se pudo guardar la configuracion ({error}). Rollback incompleto: {}",
                rollback_errors.join(" | ")
            )
        });
    }

    if !request.restart_services {
        remember_node_path(&path)?;
        return Ok(ActionResult {
                ok: true,
                message:
                    "Configuracion guardada como pendiente; los servicios conservan el estado actual."
                        .to_string(),
                output: "Vuelva a Configurar y active Aplicar y recrear servicios cuando Docker este disponible."
                    .to_string(),
                installed_profiles: existing.profiles,
            });
    }

    let existing_plan = configured_network_port_plan(&existing.config);
    match run_installer(&path, &path, "", false, Some(&existing_plan)) {
        Ok(output) => {
            update_existing_marker(&path, Some("running"), None, None)?;
            remember_node_path(&path)?;
            Ok(ActionResult {
                ok: true,
                message: "Configuracion guardada y aplicada al nodo.".to_string(),
                output,
                installed_profiles: existing.profiles,
            })
        }
        Err(error) => {
            let mut rollback_errors = Vec::new();
            if let Err(rollback_error) = write_secure(&node_env_path, &original_node_env) {
                rollback_errors.push(rollback_error);
            }
            if let Err(rollback_error) =
                restore_optional_secure_file(&enrollment_path, original_enrollment.as_deref())
            {
                rollback_errors.push(rollback_error);
            }
            if let Err(rollback_error) =
                restore_optional_secure_file(&relay_path, original_relay.as_deref())
            {
                rollback_errors.push(rollback_error);
            }
            if rollback_errors.is_empty() {
                if let Err(rollback_error) =
                    run_installer(&path, &path, "", false, Some(&existing_plan))
                {
                    rollback_errors.push(format!(
                        "No se pudo reaplicar la configuracion anterior: {rollback_error}"
                    ));
                }
            }
            if rollback_errors.is_empty() {
                Err(format!(
                    "La nueva configuracion no pudo aplicarse y se restauro la anterior: {error}"
                ))
            } else {
                Err(format!(
                    "La nueva configuracion fallo ({error}). Rollback incompleto: {}",
                    rollback_errors.join(" | ")
                ))
            }
        }
    }
}

#[tauri::command]
async fn update_node_configuration(
    backend: tauri::State<'_, OperationBackend>,
    request: NodeConfigurationRequest,
) -> Result<ActionResult, String> {
    require_phase4_supervisor(backend.supervisor.is_some())?;
    if let Some(client) = &backend.supervisor {
        if request.restart_services {
            return Err(
                "Actium Node Manager 0.7 aplica configuraciones con cola durable; use enqueue_node_configuration."
                    .to_string(),
            );
        }
        let path = validated_install_path(&request.install_dir)?;
        let existing = inspect_path(&path);
        validate_node_configuration(&request, &existing, &path)?;
        let result = match client.request(SupervisorCommand::PersistConfiguration(
            supervisor_configuration_write_request(&request, &existing),
        ))? {
            SupervisorReply::RuntimeAction(result) => result,
            _ => {
                return Err(
                    "Supervisor devolvio una respuesta inesperada al persistir configuracion."
                        .to_string(),
                )
            }
        };
        return Ok(ActionResult {
            ok: true,
            message: result.message,
            output: result.output,
            installed_profiles: existing.profiles,
        });
    }
    tauri::async_runtime::spawn_blocking(move || apply_node_configuration(request))
        .await
        .map_err(|error| format!("La tarea de configuracion fallo: {error}"))?
}

fn run_node_action(path: &Path, action: &str) -> Result<String, String> {
    if let Some(client) = supervisor_client() {
        return match client.request(SupervisorCommand::ExecuteAction {
            install_dir: path.to_string_lossy().into_owned(),
            action: action.to_string(),
        })? {
            SupervisorReply::RuntimeAction(result) => Ok(result.output),
            _ => Err("Supervisor devolvio una respuesta inesperada al operar.".to_string()),
        };
    }
    let runtime_path = active_runtime_dir(path)?;
    run_node_action_at(path, &runtime_path, action)
}

fn run_node_action_at(path: &Path, runtime_path: &Path, action: &str) -> Result<String, String> {
    if action == "diagnostics" {
        let mut report = Vec::new();
        for nested_action in ["status", "verify", "logs"] {
            let title = nested_action.to_ascii_uppercase();
            let output = run_node_action(path, nested_action)
                .unwrap_or_else(|error| format!("[COMPROBACION FALLIDA]\n{error}"));
            report.push(format!(
                "================ {title} ================\n{output}"
            ));
        }
        return Ok(report.join("\n\n"));
    }

    if action == "verify" {
        let output = if cfg!(target_os = "windows") {
            Command::new("powershell.exe")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(runtime_path.join("verify-node.ps1"))
                .arg("-EnvironmentFile")
                .arg(path.join("secrets/data-plane.env"))
                .current_dir(path)
                .output()
        } else {
            Command::new("/bin/sh")
                .arg(runtime_path.join("verify-node.sh"))
                .env(
                    "ACTIUM_DATA_PLANE_ENV_FILE",
                    path.join("secrets/data-plane.env"),
                )
                .current_dir(runtime_path)
                .output()
        }
        .map_err(|error| format!("No se pudo verificar el nodo: {error}"))?;
        return output_text(output);
    }

    let mut preflight_messages = Vec::new();
    if matches!(action, "start" | "restart" | "update") {
        let state = inspect_path(path);
        if state.installed {
            let plan = configured_network_port_plan(&state.config);
            ensure_network_ports_available_for_existing_runtime(
                path,
                &state.profiles,
                &plan,
                &plan,
            )?;
            if let Some(message) = reconcile_trusted_lan_before_action(path)? {
                preflight_messages.push(message);
            }
        }
    }

    let output = if cfg!(target_os = "windows") {
        let mut command = Command::new("powershell.exe");
        command
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(runtime_path.join("manage-node.ps1"))
            .arg(action)
            .arg("-EnvironmentFile")
            .arg(path.join("secrets/data-plane.env"));
        if action == "logs" {
            command.arg("-NoFollow");
        }
        command.current_dir(runtime_path).output()
    } else {
        let mut command = Command::new("/bin/sh");
        command
            .arg(runtime_path.join("manage-node.sh"))
            .arg(action)
            .env(
                "ACTIUM_DATA_PLANE_ENV_FILE",
                path.join("secrets/data-plane.env"),
            )
            .current_dir(runtime_path);
        if action == "logs" {
            command.env("ACTIUM_LOGS_FOLLOW", "false");
        }
        command.output()
    }
    .map_err(|error| format!("No se pudo administrar el nodo: {error}"))?;
    let output = output_text(output)?;
    if preflight_messages.is_empty() {
        Ok(output)
    } else {
        Ok(format!("{}\n\n{output}", preflight_messages.join("\n")))
    }
}

fn require_node_health(path: &Path) -> Result<String, String> {
    if let Some(client) = supervisor_client() {
        return match client.request(SupervisorCommand::HealthGate {
            install_dir: path.to_string_lossy().into_owned(),
        })? {
            SupervisorReply::RuntimeAction(result) => Ok(result.output),
            _ => Err("Supervisor devolvio una respuesta inesperada al evaluar health.".to_string()),
        };
    }
    let state = inspect_path(path);
    let project_name = installation_project_name(&state).ok_or_else(|| {
        "El nodo no conserva su proyecto Compose para el health gate.".to_string()
    })?;
    let ids = docker_project_container_ids(project_name)?;
    if ids.is_empty() {
        return Err(
            "Health gate fallido: el proyecto no tiene contenedores observables.".to_string(),
        );
    }
    let output = Command::new("docker")
        .arg("inspect")
        .args(&ids)
        .output()
        .map_err(|error| format!("No se pudo observar el runtime para health gate: {error}"))?;
    let raw = output_text(output)?;
    let report = evaluate_docker_inspect(&raw)?;
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

fn execute_transactional_update(
    app: &AppHandle,
    path: &Path,
    progress: Option<&OperationProgress<'_>>,
) -> Result<(String, String), String> {
    if let Some(report) = progress {
        report("validating", "Verificando manifiesto y bytes del payload.");
    }
    let payload = payload_dir(app)?;
    let identity = validate_payload_update(&payload, path)?;
    if identity.schema != 3 {
        return Err("El update transaccional exige payload schema 3.".to_string());
    }
    let releases = ReleaseManager::new(path);
    if let Some(report) = progress {
        report(
            "staging",
            "Copiando y verificando el candidato en staging aislado.",
        );
    }
    let prepared = releases.prepare(&payload)?;

    let mutation = releases.lock_mutation()?;
    let current_runtime = releases.active_runtime_dir()?;
    let state = inspect_path(path);
    let legacy_version = state.version.as_deref().unwrap_or("legacy");
    if releases.load_state()?.active_release.is_none() {
        let legacy_digest = payload_identity(&current_runtime)
            .map(|value| value.digest)
            .unwrap_or_else(|_| format!("legacy-{}", operation_timestamp()));
        releases.snapshot_legacy_locked(legacy_version, &legacy_digest, &mutation)?;
    }

    // El candidato se valida, resuelve Compose y prepara imagenes antes de detener el LKG.
    run_node_action_at(path, &prepared.staging_path, "prepare-update")?;
    if let Some(report) = progress {
        report(
            "promoting",
            "Deteniendo LKG, promoviendo candidato y ejecutando health gate.",
        );
    }
    run_node_action_at(path, &current_runtime, "stop")?;
    let transaction = match releases.begin_promotion_locked(prepared, mutation) {
        Ok(transaction) => transaction,
        Err(error) => {
            let _ = run_node_action_at(path, &current_runtime, "start");
            return Err(format!(
                "No se pudo promover el candidato; el LKG fue reiniciado: {error}"
            ));
        }
    };
    let candidate_runtime = transaction
        .promoted_state()
        .active_release
        .as_ref()
        .map(|release| path.join(&release.relative_path))
        .ok_or_else(|| "Promocion no materializo release candidato.".to_string())?;
    let candidate_result =
        sync_release_marker(path, transaction.promoted_state(), "installing", None)
            .and_then(|_| run_node_action_at(path, &candidate_runtime, "start"))
            .and_then(|output| {
                require_node_health(path).map(|health| format!("{output}\n\n{health}"))
            });
    match candidate_result {
        Ok(output) => {
            let state = transaction.commit()?;
            sync_release_marker(path, &state, "running", None)?;
            Ok((identity.version, output))
        }
        Err(candidate_error) => {
            let _ = run_node_action_at(path, &candidate_runtime, "stop");
            let aborted = transaction.abort().map_err(|abort_error| {
                format!(
                    "[MANUAL_INTERVENTION_REQUIRED] Candidato fallo ({candidate_error}) y no se pudo persistir aborto ({abort_error})."
                )
            })?;
            if !aborted.recovery_required {
                let _ = sync_release_marker(path, &aborted.state, "failed", Some(&candidate_error));
                return Err(format!("[FIRST_INSTALL_ABORTED] {candidate_error}"));
            }
            let previous_runtime = aborted
                .state
                .active_release
                .as_ref()
                .map(|release| path.join(&release.relative_path))
                .ok_or_else(|| "Recovery no conserva LKG activo.".to_string())?;
            let recovery =
                run_node_action_at(path, &previous_runtime, "start").and_then(|output| {
                    require_node_health(path).map(|health| format!("{output}\n{health}"))
                });
            match recovery {
                Ok(recovery_output) => {
                    let rolled_back = aborted.complete_recovery()?;
                    let message = format!("Candidato rechazado por health gate: {candidate_error}");
                    sync_release_marker(path, &rolled_back, "running", Some(&message))?;
                    Err(format!("[ROLLED_BACK] {message}\n\n{recovery_output}"))
                }
                Err(recovery_error) => {
                    let manual = aborted.fail_recovery()?;
                    let message = format!(
                        "Candidato fallido: {candidate_error}. El LKG tampoco supero recovery: {recovery_error}"
                    );
                    sync_release_marker(path, &manual, "failed", Some(&message))?;
                    Err(format!("[MANUAL_INTERVENTION_REQUIRED] {message}"))
                }
            }
        }
    }
}

fn run_ht_logs(path: &Path) -> Result<String, String> {
    let state = inspect_path(path);
    target_is_safe(path, &state)?;
    let project_name = installation_project_name(&state)
        .ok_or_else(|| "El nodo no conserva su nombre de proyecto Docker.".to_string())?;
    let ids = docker_project_container_ids(project_name)?;
    if ids.is_empty() {
        return Err("No hay contenedores del nodo para consultar.".to_string());
    }
    let inspect = Command::new("docker")
        .arg("inspect")
        .args(&ids)
        .output()
        .map_err(|error| format!("No se pudo inspeccionar el plano HT: {error}"))?;
    if !inspect.status.success() {
        return Err(format!(
            "Docker no pudo inspeccionar el plano HT: {}",
            String::from_utf8_lossy(&inspect.stderr).trim()
        ));
    }
    let containers = serde_json::from_slice::<Vec<serde_json::Value>>(&inspect.stdout)
        .map_err(|error| format!("Docker devolvio un inventario invalido: {error}"))?;
    let allowed = [
        "radio_control",
        "radio_turn",
        "radio_livekit",
        "broker_nats",
        "object_storage",
        "node_agent",
    ];
    let targets = containers
        .iter()
        .filter_map(|container| {
            let workload = container
                .get("Config")
                .and_then(|value| value.get("Labels"))
                .and_then(|value| value.get("com.actium.workload"))
                .and_then(serde_json::Value::as_str)?;
            if !allowed.contains(&workload) {
                return None;
            }
            let id = container.get("Id").and_then(serde_json::Value::as_str)?;
            let name = container
                .get("Name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(id)
                .trim_start_matches('/');
            Some((workload.to_string(), id.to_string(), name.to_string()))
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        return Err("No se encontraron workloads HT ni sus dependencias.".to_string());
    }
    let mut sections = Vec::new();
    for (workload, id, name) in targets {
        let output = Command::new("docker")
            .args(["logs", "--tail", "250", "--timestamps", id.as_str()])
            .output();
        let body = match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let merged = format!("{}{}", stdout, stderr);
                if merged.trim().is_empty() {
                    "[Sin registros en la ventana consultada]".to_string()
                } else {
                    merged.trim().to_string()
                }
            }
            Err(error) => format!("[No se pudo consultar este contenedor: {error}]"),
        };
        sections.push(format!(
            "================ {workload} · {name} ================\n{body}"
        ));
    }
    Ok(sections.join("\n\n"))
}

#[tauri::command]
async fn promote_archived_node(
    app: AppHandle,
    request: InspectRequest,
) -> Result<ActionResult, String> {
    require_phase4_supervisor(supervisor_client().is_some())?;
    tauri::async_runtime::spawn_blocking(move || {
        let source = validated_install_path(&request.install_dir)?;
        if !path_is_within(&source, &recovery_root_dir()) {
            return Err("El nodo seleccionado ya pertenece al inventario administrado.".to_string());
        }
        let existing = inspect_path(&source);
        if !existing.operational {
            return Err(
                "La promocion directa requiere un nodo operativo. Las preparaciones incompletas se recuperan importando su .adpe."
                    .to_string(),
            );
        }
        target_is_safe(&source, &existing)?;
        let project_name = installation_project_name(&existing)
            .ok_or_else(|| "El nodo no conserva su proyecto Docker.".to_string())?;
        ensure_project_name_available(&source, project_name)?;
        let target = promoted_node_target(&source, &existing)?;
        let target_state = inspect_path(&target);
        target_is_safe(&target, &target_state)?;
        if target_state.installed {
            return Err(format!(
                "El destino administrado {} ya contiene otra instalacion.",
                target.display()
            ));
        }

        let original_node_env = fs::read_to_string(source.join("node.env"))
            .map_err(|error| format!("No se pudo respaldar node.env antes de promover: {error}"))?;
        let plan = suggest_available_network_ports(&existing.profiles, Some(&source))?;
        ensure_network_ports_unreserved(&source, &existing.profiles, &plan)?;
        let stop_output = run_node_action(&source, "stop")?;
        if let Err(error) = ensure_network_ports_available(&existing.profiles, &plan) {
            let restart = run_installer(&source, &source, "", false, None);
            return Err(match restart {
                Ok(_) => format!(
                    "La promocion se cancelo porque los nuevos puertos dejaron de estar disponibles; el nodo anterior fue reiniciado: {error}"
                ),
                Err(restart_error) => format!(
                    "La promocion se cancelo ({error}) y el nodo anterior no pudo reiniciarse: {restart_error}"
                ),
            });
        }

        let promoted = match promote_archived_directory(&source, &existing) {
            Ok(path) => path,
            Err(error) => {
                let restart = run_installer(&source, &source, "", false, None);
                return Err(match restart {
                    Ok(_) => format!(
                        "No se pudo promover el directorio; el nodo anterior fue reiniciado: {error}"
                    ),
                    Err(restart_error) => format!(
                        "No se pudo promover el directorio ({error}) ni reiniciar el nodo anterior ({restart_error})."
                    ),
                });
            }
        };

        let promote_result = (|| -> Result<String, String> {
            let payload = payload_dir(&app)?;
            let payload_manifest = validate_payload_manifest(&payload)?;
            copy_payload(&payload, &promoted)?;
            write_network_port_plan(&promoted, &plan)?;
            let output = run_installer(&promoted, &promoted, "", false, None)?;
            let version = payload_manifest.version;
            update_existing_marker(&promoted, Some("running"), Some(&version), None)?;
            remember_node_path(&promoted)?;
            Ok(output)
        })();

        match promote_result {
            Ok(output) => Ok(ActionResult {
                ok: true,
                message:
                    "Nodo promovido al inventario administrado sin reemplazar secretos ni volumenes."
                        .to_string(),
                output: format!(
                    "{stop_output}\n\nPromovido a {}\nPuertos: GPS/DVR {}, HT {}, S&F {}, Prometheus {}, Grafana {}, TURN {}/{}/{}, LiveKit {}/{}/{}-{}\n\n{output}",
                    promoted.display(),
                    plan.telemetry_port,
                    plan.radio_control_port,
                    plan.radio_saf_port,
                    plan.prometheus_port,
                    plan.grafana_port,
                    plan.turn_port,
                    plan.turn_min_port,
                    plan.turn_max_port,
                    plan.livekit_http_port,
                    plan.livekit_rtc_tcp_port,
                    plan.livekit_udp_min_port,
                    plan.livekit_udp_max_port,
                ),
                installed_profiles: existing.profiles,
            }),
            Err(error) => {
                let _ = run_node_action(&promoted, "stop");
                let mut rollback_errors = Vec::new();
                if let Err(rollback_error) =
                    write_secure(&promoted.join("node.env"), &original_node_env)
                {
                    rollback_errors.push(rollback_error);
                }
                if let Err(rollback_error) =
                    rollback_promoted_directory(&promoted, &source)
                {
                    rollback_errors.push(rollback_error);
                } else if let Err(rollback_error) = run_installer(&source, &source, "", false, None) {
                    rollback_errors.push(format!(
                        "El directorio fue restaurado, pero el nodo anterior no pudo reiniciarse: {rollback_error}"
                    ));
                }
                if rollback_errors.is_empty() {
                    Err(format!(
                        "La promocion fallo y se restauro el nodo en Recovery: {error}"
                    ))
                } else {
                    Err(format!(
                        "La promocion fallo ({error}). Rollback incompleto: {}",
                        rollback_errors.join(" | ")
                    ))
                }
            }
        }
    })
    .await
    .map_err(|error| format!("La promocion del nodo fallo: {error}"))?
}

fn node_action_allowed(action: &str) -> bool {
    [
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
        "purge",
    ]
    .contains(&action)
}

fn audit_report_value(terminal: Option<&serde_json::Value>, field: &str) -> serde_json::Value {
    terminal
        .and_then(|value| value.get(field))
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

fn audit_operation_report(
    snapshot: &NodeAuditSnapshot,
    action: &str,
    terminal_id: Option<&str>,
) -> Result<String, String> {
    let terminals = snapshot
        .telemetry
        .get("terminals")
        .and_then(serde_json::Value::as_array);
    let selected = terminals
        .and_then(|values| {
            terminal_id.and_then(|requested| {
                values.iter().find(|terminal| {
                    terminal
                        .get("terminalId")
                        .and_then(serde_json::Value::as_str)
                        == Some(requested)
                })
            })
        })
        .or_else(|| terminals.and_then(|values| values.first()));
    let terminal_label = selected
        .and_then(|terminal| terminal.get("terminalLabel"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("Terminal sin nombre");
    let terminal_identity = serde_json::json!({
        "terminalId": audit_report_value(selected, "terminalId"),
        "terminalLabel": audit_report_value(selected, "terminalLabel"),
        "terminalPlatform": audit_report_value(selected, "terminalPlatform"),
        "terminalRuntime": audit_report_value(selected, "terminalRuntime"),
        "terminalClass": audit_report_value(selected, "terminalClass"),
    });
    let (title, evidence) = match action {
        "audit_terminal" => (
            "ESTADO DE TERMINAL",
            serde_json::json!({
                "identity": terminal_identity,
                "heartbeatAt": audit_report_value(selected, "heartbeatAt"),
                "presenceStatus": audit_report_value(selected, "presenceStatus"),
                "appState": audit_report_value(selected, "appState"),
                "batteryLevel": audit_report_value(selected, "batteryLevel"),
                "queueDepth": audit_report_value(selected, "queueDepth"),
                "continuityStatus": audit_report_value(selected, "continuityStatus"),
            }),
        ),
        "audit_gps" => (
            "ESTADO GPS",
            serde_json::json!({
                "identity": terminal_identity,
                "sequence": audit_report_value(selected, "sequence"),
                "fixAt": audit_report_value(selected, "fixAt"),
                "ingestedAt": audit_report_value(selected, "ingestedAt"),
                "projectedAt": audit_report_value(selected, "projectedAt"),
                "latitude": audit_report_value(selected, "latitude"),
                "longitude": audit_report_value(selected, "longitude"),
                "accuracy": audit_report_value(selected, "accuracy"),
                "lastBatchId": audit_report_value(selected, "lastBatchId"),
                "lastBatchStatus": audit_report_value(selected, "lastBatchStatus"),
                "lastBatchReceivedAt": audit_report_value(selected, "lastBatchReceivedAt"),
                "lastBatchProcessedAt": audit_report_value(selected, "lastBatchProcessedAt"),
                "recentBatches": audit_report_value(selected, "recentBatches"),
                "recentPoints": audit_report_value(selected, "recentPoints"),
            }),
        ),
        "audit_dvr" => (
            "ESTADO DVR",
            serde_json::json!({
                "identity": terminal_identity,
                "dvrSessionId": audit_report_value(selected, "dvrSessionId"),
                "dvrFirstPointAt": audit_report_value(selected, "dvrFirstPointAt"),
                "dvrLastPointAt": audit_report_value(selected, "dvrLastPointAt"),
                "dvrPoints24h": audit_report_value(selected, "dvrPoints24h"),
                "recentPoints": audit_report_value(selected, "recentPoints"),
            }),
        ),
        _ => return Err("Alcance de auditoria no permitido.".to_string()),
    };
    let report = serde_json::json!({
        "schema": "actium-node-audit-operation/v1",
        "scope": action,
        "generatedAt": snapshot.generated_at,
        "projectName": snapshot.project_name,
        "terminal": terminal_label,
        "database": {
            "ok": snapshot.database_ok,
            "error": snapshot.database_error,
        },
        "services": snapshot.services,
        "unresolvedDeadLetters": snapshot
            .telemetry
            .get("unresolvedDeadLetters")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        "evidence": evidence,
    });
    let json = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("No se pudo serializar el reporte de auditoria: {error}"))?;
    Ok(format!(
        "ACTIUM TELEMETRY NODE MANAGER\n{title}\nTerminal: {terminal_label}\nProyecto: {}\n\n{json}",
        snapshot.project_name
    ))
}

fn execute_node_operation(
    app: &AppHandle,
    request: &NodeActionRequest,
    progress: Option<&OperationProgress<'_>>,
) -> Result<ActionResult, String> {
    if !node_action_allowed(&request.action) {
        return Err("Operacion de nodo no permitida.".to_string());
    }
    let path = validated_install_path(&request.install_dir)?;
    if request.action == "purge" {
        let node_name = path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("nodo");
        let mut filter_cmd = std::process::Command::new("docker");
        filter_cmd.args(["ps", "-a", "--filter", &format!("name={node_name}"), "--format", "{{.ID}}"]);
        if let Ok(out) = filter_cmd.output() {
            let ids = String::from_utf8_lossy(&out.stdout);
            let container_ids: Vec<&str> = ids.split_whitespace().collect();
            if !container_ids.is_empty() {
                let mut rm_cmd = std::process::Command::new("docker");
                rm_cmd.args(["rm", "-f"]);
                rm_cmd.args(&container_ids);
                let _ = rm_cmd.output();
            }
        }
        let _ = std::fs::remove_dir_all(&path);
        let _ = forget_node_path(&path);
        return Ok(ActionResult {
            ok: true,
            message: "Residuos del nodo eliminados correctamente.".to_string(),
            output: format!("Purga completada para {}", path.display()),
            installed_profiles: Vec::new(),
        });
    }
    let state = inspect_path(&path);
    if !state.operational {
        return Err(
            "No existe un nodo operativo administrado en ese directorio. Una preparacion fallida debe reintentarse o archivarse desde Autoridad Actium."
                .to_string(),
        );
    }
    if matches!(
        request.action.as_str(),
        "audit_terminal" | "audit_gps" | "audit_dvr"
    ) {
        let snapshot = collect_node_audit(&path)?;
        let output =
            audit_operation_report(&snapshot, &request.action, request.terminal_id.as_deref())?;
        let scope = match request.action.as_str() {
            "audit_terminal" => "terminal",
            "audit_gps" => "GPS",
            "audit_dvr" => "DVR",
            _ => unreachable!(),
        };
        return Ok(ActionResult {
            ok: true,
            message: format!("Reporte de {scope} actualizado."),
            output,
            installed_profiles: state.profiles,
        });
    }
    if request.action == "audit_ht" {
        let snapshot = collect_node_ht_audit(&path)?;
        let json = serde_json::to_string_pretty(&snapshot)
            .map_err(|error| format!("No se pudo serializar la auditoria HT: {error}"))?;
        return Ok(ActionResult {
            ok: true,
            message: "Reporte HT actualizado.".to_string(),
            output: format!(
                "ACTIUM TELEMETRY NODE MANAGER\nAUDITORIA HT\nProyecto: {}\n\n{json}",
                snapshot.project_name
            ),
            installed_profiles: state.profiles,
        });
    }
    if request.action == "logs_ht" {
        return Ok(ActionResult {
            ok: true,
            message: "Registros HT reunidos.".to_string(),
            output: run_ht_logs(&path)?,
            installed_profiles: state.profiles,
        });
    }
    if request.action == "update" {
        let (version, output) = execute_transactional_update(app, &path, progress)?;
        remember_node_path(&path)?;
        return Ok(ActionResult {
            ok: true,
            message: format!("Release {version} promovido y validado por health gate."),
            output,
            installed_profiles: inspect_path(&path).profiles,
        });
    }
    let payload_version: Option<String> = None;
    let output = match run_node_action(&path, &request.action) {
        Ok(output) => output,
        Err(error) => {
            if matches!(request.action.as_str(), "start" | "restart" | "update") {
                let _ = update_existing_marker(
                    &path,
                    Some("failed"),
                    payload_version.as_deref(),
                    Some(&error),
                );
            }
            return Err(error);
        }
    };
    let output = if matches!(request.action.as_str(), "start" | "restart") {
        format!("{output}\n\n{}", require_node_health(&path)?)
    } else {
        output
    };
    let next_status = match request.action.as_str() {
        "stop" => Some("stopped"),
        "start" | "restart" | "update" => Some("running"),
        _ => None,
    };
    if next_status.is_some() || payload_version.is_some() {
        update_existing_marker(&path, next_status, payload_version.as_deref(), None)?;
    }
    remember_node_path(&path)?;
    let refreshed = inspect_path(&path);
    Ok(ActionResult {
        ok: true,
        message: format!("Operacion {} completada.", request.action),
        output,
        installed_profiles: refreshed.profiles,
    })
}

fn operation_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
fn bounded_operation_output(value: String) -> String {
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
    format!("[Salida anterior truncada por superar {MAX_OUTPUT_CHARS} caracteres]\n\n{tail}")
}

#[tauri::command]
async fn enqueue_node_operation(
    _app: AppHandle,
    backend: tauri::State<'_, OperationBackend>,
    request: NodeActionRequest,
) -> Result<NodeOperationJob, String> {
    require_phase4_supervisor(backend.supervisor.is_some())?;
    if !node_action_allowed(&request.action) {
        return Err("Operacion de nodo no permitida.".to_string());
    }
    let path = validated_install_path(&request.install_dir)?;
    let state = inspect_path(&path);
    if !state.operational && request.action != "purge" {
        return Err("No existe un nodo operativo administrado en ese directorio.".to_string());
    }
    let install_dir = path.to_string_lossy().to_string();
    let node_key = request
        .node_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(240).collect::<String>())
        .unwrap_or_else(|| path_identity(&path));
    let node_label = request
        .node_label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(160).collect::<String>())
        .or(state.deployment_code)
        .or_else(|| state.config.get("ACTIUM_DATA_PLANE_PROJECT").cloned())
        .unwrap_or_else(|| "Nodo local".to_string());

    let terminal_id = request
        .terminal_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(240).collect::<String>());
    let client = backend
        .supervisor
        .as_ref()
        .ok_or_else(|| "Actium Node Supervisor no esta configurado.".to_string())?;
    enqueue_supervisor_job(
        client,
        install_dir,
        node_key,
        node_label,
        terminal_id,
        request.action,
    )
}

#[tauri::command]
async fn enqueue_node_configuration(
    _app: AppHandle,
    backend: tauri::State<'_, OperationBackend>,
    request: NodeConfigurationOperationRequest,
) -> Result<NodeOperationJob, String> {
    require_phase4_supervisor(backend.supervisor.is_some())?;
    let configuration = request.configuration;
    let path = validated_install_path(&configuration.install_dir)?;
    let state = inspect_path(&path);
    if !is_reconfigurable_installation(&path, &state) {
        return Err(
            "No existe una instalacion recuperable o administrable en ese directorio.".to_string(),
        );
    }
    validate_node_configuration(&configuration, &state, &path)?;
    let install_dir = path.to_string_lossy().to_string();
    let node_key = request
        .node_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(240).collect::<String>())
        .unwrap_or_else(|| path_identity(&path));
    let node_label = request
        .node_label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(160).collect::<String>())
        .or(state.deployment_code.clone())
        .or_else(|| state.config.get("ACTIUM_DATA_PLANE_PROJECT").cloned())
        .unwrap_or_else(|| "Nodo local".to_string());

    let client = backend
        .supervisor
        .as_ref()
        .ok_or_else(|| "Actium Node Supervisor no esta configurado.".to_string())?;
    let restart_services = configuration.restart_services;
    let write_request = supervisor_configuration_write_request(&configuration, &state);
    match client.request(SupervisorCommand::PersistConfiguration(write_request))? {
        SupervisorReply::RuntimeAction(_) => {}
        _ => {
            return Err(
                "Supervisor devolvio una respuesta inesperada al persistir configuracion."
                    .to_string(),
            )
        }
    }
    enqueue_supervisor_job(
        client,
        install_dir,
        node_key,
        node_label,
        None,
        if restart_services {
            "apply_configuration"
        } else {
            "save_configuration"
        }
        .to_string(),
    )
}

#[tauri::command]
fn list_node_operation_jobs(
    backend: tauri::State<'_, OperationBackend>,
) -> Result<Vec<NodeOperationJob>, String> {
    let Some(client) = backend.supervisor.as_ref() else {
        return Ok(Vec::new());
    };
    match client.request(SupervisorCommand::ListOperations { limit: 100 }) {
        Ok(SupervisorReply::Operations(operations)) => {
            Ok(operations.into_iter().map(job_from_journal).collect())
        }
        Ok(_) => Err("Supervisor devolvio una respuesta inesperada al listar.".to_string()),
        Err(_) => Ok(Vec::new()),
    }
}

#[tauri::command]
fn cancel_node_operation_job(
    backend: tauri::State<'_, OperationBackend>,
    request: NodeOperationJobRequest,
) -> Result<NodeOperationJob, String> {
    let client = backend
        .supervisor
        .as_ref()
        .ok_or_else(|| "Actium Node Supervisor no esta configurado.".to_string())?;
    match client.request(SupervisorCommand::CancelOperation {
        operation_id: request.job_id,
    })? {
        SupervisorReply::Operation(operation) => Ok(job_from_journal(*operation)),
        _ => Err("Supervisor devolvio una respuesta inesperada al cancelar.".to_string()),
    }
}

#[tauri::command]
async fn node_operation(
    app: AppHandle,
    backend: tauri::State<'_, OperationBackend>,
    request: NodeActionRequest,
) -> Result<ActionResult, String> {
    if let Some(client) = &backend.supervisor {
        let path = validated_install_path(&request.install_dir)?;
        let state = inspect_path(&path);
        let job = enqueue_supervisor_job(
            client,
            path.to_string_lossy().into_owned(),
            request
                .node_key
                .clone()
                .unwrap_or_else(|| path_identity(&path)),
            request
                .node_label
                .clone()
                .unwrap_or_else(|| "Nodo local".to_string()),
            request.terminal_id.clone(),
            request.action.clone(),
        )?;
        for _ in 0..7_200 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let operations =
                match client.request(SupervisorCommand::ListOperations { limit: 100 })? {
                    SupervisorReply::Operations(operations) => operations,
                    _ => return Err("Supervisor devolvio una respuesta inesperada.".to_string()),
                };
            if let Some(operation) = operations.into_iter().find(|item| item.id == job.id) {
                if matches!(
                    operation.state.as_str(),
                    "completed"
                        | "failed"
                        | "rolled_back"
                        | "manual_intervention_required"
                        | "cancelled"
                        | "interrupted"
                ) {
                    if operation.state == "completed" {
                        if request.action == "purge" {
                            let _ = forget_node_path(&path);
                        }
                        return Ok(ActionResult {
                            ok: true,
                            message: operation.current_step,
                            output: operation.output_redacted,
                            installed_profiles: state.profiles,
                        });
                    }
                    return Err(operation.output_redacted);
                }
            }
        }
        return Err("Supervisor no cerro la operacion dentro de 30 minutos.".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || execute_node_operation(&app, &request, None))
        .await
        .map_err(|error| format!("La operacion del nodo fallo: {error}"))?
}

#[tauri::command]
fn export_diagnostic_report(
    request: ExportDiagnosticRequest,
) -> Result<ExportDiagnosticResult, String> {
    const MAX_REPORT_BYTES: usize = 2_000_000;
    let report = request.report.trim();
    if report.is_empty() {
        return Err("El informe diagnostico esta vacio.".to_string());
    }
    if report.len() > MAX_REPORT_BYTES {
        return Err(format!(
            "El informe supera el limite seguro de {MAX_REPORT_BYTES} bytes."
        ));
    }
    let label = safe_archive_fragment(request.node_label.trim());
    let directory = paths::diagnostics_dir();
    let path = directory.join(format!("diagnostico-{label}-{}.txt", operation_timestamp()));
    write_secure(&path, &format!("{report}\n"))?;
    Ok(ExportDiagnosticResult {
        path: path.to_string_lossy().into_owned(),
        bytes: report.len(),
    })
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use super::{
        audience_contains_any, audit_operation_report, bounded_operation_output,
        derived_trusted_lan_endpoint, derived_trusted_lan_host,
        derived_trusted_lan_site_core_endpoint, incomplete_commission_resume_allowed, inspect_path,
        installation_owned_by_current_channel, is_connectivity_secret, is_operational_installation,
        is_recoverable_incomplete_preparation, is_recoverable_preparation_status,
        network_port_claims, node_action_allowed, supervisor_runtime_summary_eligible,
        parse_excluded_udp_port_ranges, path_is_within, reconcile_trusted_lan_document,
        reserved_port_sets, site_runtime_schema_version_for_profiles, updated_env_document, validate_connectivity_policy,
        validate_installer_min_version, validate_network_policy, validate_payload_transition,
        validate_runtime_capabilities_against_payload, validate_runtime_capabilities_claim,
        validate_site_core_intent, required_runtime_features, write_payload_version,
        BootstrapClaims, ConnectivityPolicy, InstallationState,
        NetworkPortPlan, NodeAuditSnapshot, PayloadIdentity, PayloadManifestV3, PortTransport,
        SiteCoreIntent, INSTALLER_VERSION,
        TRUSTED_BOOTSTRAP_AUDIENCES,
    };
    use uuid::Uuid;

    #[test]
    fn ownership_del_marker_no_cruza_canales() {
        let mut state = InstallationState {
            installed: true,
            ..InstallationState::default()
        };
        state.manager_channel = Some(super::product::PRODUCT_CHANNEL.to_string());
        assert!(installation_owned_by_current_channel(&state));
        state.manager_channel = Some(if super::product::is_lab() {
            "stable".to_string()
        } else {
            "lab".to_string()
        });
        assert!(!installation_owned_by_current_channel(&state));
    }

    fn incomplete_resume_state(status: &str) -> InstallationState {
        let mut state = InstallationState {
            installed: true,
            operational: false,
            managed: true,
            recoverable_incomplete_preparation: true,
            status: Some(status.to_string()),
            deployment_id: Some("7e207490-88fd-4e31-9684-d247475215ab".to_string()),
            installation_id: Some("e0864698-6978-4481-bfb2-76df5d9032bf".to_string()),
            promotion_status: Some("failed".to_string()),
            ..InstallationState::default()
        };
        state.manager_channel = Some(super::product::PRODUCT_CHANNEL.to_string());
        state
    }

    #[test]
    fn inspect_path_no_usa_host_installation_id_como_nodo() {
        let root = std::env::temp_dir().join(format!("actium-inspect-host-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("node.env"),
            "ACTIUM_HOST_INSTALLATION_ID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n\
ACTIUM_NODE_INSTALLATION_ID=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\n",
        )
        .unwrap();
        let without_marker = inspect_path(&root);
        assert!(without_marker.installation_id.is_none());
        assert_eq!(
            without_marker.host_installation_id.as_deref(),
            Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        );
        fs::write(
            root.join(".actium-node-installation.json"),
            serde_json::json!({
                "schema": 2,
                "version": "0.8.0-lab.22",
                "profiles": ["site-core"],
                "status": "failed",
                "updatedAtUnixSeconds": 1,
                "installationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "managerChannel": super::product::PRODUCT_CHANNEL,
            })
            .to_string(),
        )
        .unwrap();
        let with_marker = inspect_path(&root);
        assert_eq!(
            with_marker.installation_id.as_deref(),
            Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        );
        assert_eq!(
            with_marker.host_installation_id.as_deref(),
            Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        );
        assert_ne!(
            with_marker.installation_id,
            with_marker.host_installation_id
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_incompleto_reutiliza_installation_id_del_mismo_deployment() {
        let root = std::env::temp_dir().join(format!("actium-mgr-resume-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            &root.join("node.env"),
            "ACTIUM_HOST_INSTALLATION_ID=e0864698-6978-4481-bfb2-76df5d9032bf\n",
        )
        .unwrap();
        let allowed = incomplete_commission_resume_allowed(
            &incomplete_resume_state("failed"),
            &root,
            "7e207490-88fd-4e31-9684-d247475215ab",
        )
        .expect("el leftover pre-topology debe ser reanudable");
        assert!(allowed);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resume_incompleto_falla_cerrado_ante_otro_deployment_o_compose() {
        let root =
            std::env::temp_dir().join(format!("actium-mgr-resume-reject-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let other = incomplete_commission_resume_allowed(
            &incomplete_resume_state("failed"),
            &root,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        )
        .expect_err("otro deployment debe fallar cerrado");
        assert!(other.contains("otro despliegue"), "{other}");
        fs::write(root.join("compose.yml"), "services: {}\n").unwrap();
        let compose = incomplete_commission_resume_allowed(
            &incomplete_resume_state("failed"),
            &root,
            "7e207490-88fd-4e31-9684-d247475215ab",
        )
        .expect_err("Compose operativo no usa el camino de resume");
        assert!(compose.contains("Compose"), "{compose}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn commissioning_inicial_sigue_siendo_el_camino_por_defecto() {
        let root = std::env::temp_dir().join(format!("actium-mgr-fresh-{}", Uuid::new_v4()));
        let fresh = InstallationState::default();
        assert!(!incomplete_commission_resume_allowed(
            &fresh,
            &root,
            "7e207490-88fd-4e31-9684-d247475215ab",
        )
        .expect("un destino nuevo no es resume"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn acepta_actualizacion_con_version_nueva() {
        let source = PayloadIdentity {
            schema: super::product::PAYLOAD_SCHEMA_VERSION,
            version: INSTALLER_VERSION.to_string(),
            digest: "a".repeat(64),
            source_dirty: false,
        };
        assert!(validate_payload_transition(&source, "0.6.4", None).is_ok());
    }

    #[test]
    fn rechaza_payload_distinto_con_la_misma_version() {
        let source = PayloadIdentity {
            schema: super::product::PAYLOAD_SCHEMA_VERSION,
            version: INSTALLER_VERSION.to_string(),
            digest: "a".repeat(64),
            source_dirty: false,
        };
        let error = validate_payload_transition(&source, INSTALLER_VERSION, Some(&"b".repeat(64)))
            .expect_err("dos contenidos con la misma version deben rechazarse");
        assert!(error.contains("dos payloads distintos"));
    }

    #[test]
    fn rechaza_degradacion_de_payload() {
        let source = PayloadIdentity {
            schema: super::product::PAYLOAD_SCHEMA_VERSION,
            version: INSTALLER_VERSION.to_string(),
            digest: "a".repeat(64),
            source_dirty: false,
        };
        let error = validate_payload_transition(&source, "9.0.0", None)
            .expect_err("un payload anterior no debe degradar el nodo");
        assert!(error.contains("no puede degradar"));
    }

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
    fn consumer_adpe_acepta_audience_manager_y_legacy() {
        assert!(audience_contains_any(
            &serde_json::json!("actium-node-manager"),
            &TRUSTED_BOOTSTRAP_AUDIENCES,
        ));
        assert!(audience_contains_any(
            &serde_json::json!(["actium-telemetry-node-installer"]),
            &TRUSTED_BOOTSTRAP_AUDIENCES,
        ));
        assert!(!audience_contains_any(
            &serde_json::json!("actium-node-supervisor"),
            &TRUSTED_BOOTSTRAP_AUDIENCES,
        ));
    }

    #[test]
    fn acepta_modo_local_solo_con_loopback_real() {
        assert!(
            validate_network_policy("local_only", "127.0.0.1", "http://127.0.0.1:8090").is_ok()
        );
        assert!(validate_network_policy("local_only", "127.0.0.1", "https://localhost").is_ok());
    }

    #[test]
    fn rechaza_host_que_solo_imita_loopback() {
        assert!(
            validate_network_policy("local_only", "127.0.0.1", "http://127.0.0.1.example.com")
                .is_err()
        );
    }

    #[test]
    fn vpn_estable_requiere_una_base_no_loopback() {
        assert!(validate_network_policy("stable_vpn", "0.0.0.0", "http://127.0.0.1").is_err());
        assert!(
            validate_network_policy("stable_vpn", "0.0.0.0", "https://telemetry.vpn.example")
                .is_ok()
        );
    }

    #[test]
    fn acepta_politica_connectivity_firmable() {
        let policy = ConnectivityPolicy {
            edge_control_url: "https://connectivity.example.com".to_string(),
            node_role: "replica".to_string(),
            node_priority: 100,
            pull_limit: 25,
            sync_enabled: false,
            direct_data_plane_fallback_enabled: true,
            supabase_fallback_enabled: true,
            fallback_order: vec!["supabase".to_string(), "direct_data_plane".to_string()],
            preferred_transport: None,
            allowed_transports: None,
            gateway_strategy: None,
            roaming_allowed: None,
        };
        assert!(validate_connectivity_policy(&policy).is_ok());
    }

    #[test]
    fn adpe_connectivity_preserva_sync_enabled_y_default_legacy() {
        let base = serde_json::json!({
            "edgeControlUrl": "https://connectivity.example.com",
            "nodeRole": "replica",
            "nodePriority": 100,
            "pullLimit": 25,
            "directDataPlaneFallbackEnabled": true,
            "supabaseFallbackEnabled": false,
            "fallbackOrder": ["direct_data_plane"]
        });

        let legacy: ConnectivityPolicy = serde_json::from_value(base.clone())
            .expect("un .adpe legacy sin syncEnabled debe seguir siendo válido");
        assert!(!legacy.sync_enabled);

        let mut disabled_value = base.clone();
        disabled_value["syncEnabled"] = serde_json::json!(false);
        let disabled: ConnectivityPolicy = serde_json::from_value(disabled_value)
            .expect("syncEnabled=false debe deserializar");
        assert!(!disabled.sync_enabled);

        let mut enabled_value = base;
        enabled_value["syncEnabled"] = serde_json::json!(true);
        let enabled: ConnectivityPolicy = serde_json::from_value(enabled_value)
            .expect("syncEnabled=true debe deserializar");
        assert!(enabled.sync_enabled);

        let serialized = serde_json::to_value(&enabled)
            .expect("ConnectivityPolicy debe serializar hacia BootstrapValidation");
        assert_eq!(
            serialized
                .get("syncEnabled")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn rechaza_politica_connectivity_con_orden_inconsistente() {
        let policy = ConnectivityPolicy {
            edge_control_url: "https://connectivity.example.com".to_string(),
            node_role: "replica".to_string(),
            node_priority: 100,
            pull_limit: 25,
            sync_enabled: false,
            direct_data_plane_fallback_enabled: true,
            supabase_fallback_enabled: false,
            fallback_order: vec!["supabase".to_string()],
            preferred_transport: None,
            allowed_transports: None,
            gateway_strategy: None,
            roaming_allowed: None,
        };
        assert!(validate_connectivity_policy(&policy).is_err());
    }

    #[test]
    fn acepta_overlay_como_transporte_abstracto_rechaza_wireguard_como_dominio() {
        // Overlay is a valid abstract transport; wireguard is a provider_id, not a domain.
        let policy_overlay = ConnectivityPolicy {
            edge_control_url: "https://connectivity.example.com".to_string(),
            node_role: "primary".to_string(),
            node_priority: 10,
            pull_limit: 50,
            sync_enabled: true,
            direct_data_plane_fallback_enabled: false,
            supabase_fallback_enabled: false,
            fallback_order: vec![],
            preferred_transport: Some("overlay".to_string()),
            allowed_transports: Some(vec!["overlay".to_string(), "relay".to_string()]),
            gateway_strategy: Some("site_gateway".to_string()),
            roaming_allowed: Some(true),
        };
        assert!(
            validate_connectivity_policy(&policy_overlay).is_ok(),
            "overlay/relay/site_gateway must be accepted"
        );

        // wireguard as a transport domain must be rejected.
        let policy_wireguard = ConnectivityPolicy {
            edge_control_url: "https://connectivity.example.com".to_string(),
            node_role: "replica".to_string(),
            node_priority: 100,
            pull_limit: 25,
            sync_enabled: false,
            direct_data_plane_fallback_enabled: true,
            supabase_fallback_enabled: false,
            fallback_order: vec!["direct_data_plane".to_string()],
            preferred_transport: Some("wireguard".to_string()),
            allowed_transports: Some(vec!["wireguard".to_string()]),
            gateway_strategy: None,
            roaming_allowed: None,
        };
        assert!(
            validate_connectivity_policy(&policy_wireguard).is_err(),
            "wireguard as domain must be rejected by validate_access_transport_policy"
        );

        // preferred not in allowed must be rejected.
        let policy_mismatch = ConnectivityPolicy {
            edge_control_url: "https://connectivity.example.com".to_string(),
            node_role: "replica".to_string(),
            node_priority: 100,
            pull_limit: 25,
            sync_enabled: false,
            direct_data_plane_fallback_enabled: true,
            supabase_fallback_enabled: false,
            fallback_order: vec!["direct_data_plane".to_string()],
            preferred_transport: Some("overlay".to_string()),
            allowed_transports: Some(vec!["direct".to_string()]),
            gateway_strategy: None,
            roaming_allowed: None,
        };
        assert!(
            validate_connectivity_policy(&policy_mismatch).is_err(),
            "preferred transport not in allowed list must be rejected"
        );
    }

    #[test]
    fn actualiza_node_env_sin_tocar_identidad_ni_comentarios() {
        let current = "# gestionado\nACTIUM_DEPLOYMENT_ID=deployment-1\nTELEMETRY_PORT=8090\n";
        let updates = BTreeMap::from([
            ("TELEMETRY_PORT", "8190".to_string()),
            (
                "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED",
                "false".to_string(),
            ),
        ]);
        let result = updated_env_document(current, &updates);
        assert!(result.contains("# gestionado\n"));
        assert!(result.contains("ACTIUM_DEPLOYMENT_ID=deployment-1\n"));
        assert!(result.contains("TELEMETRY_PORT=8190\n"));
        assert!(result.contains("CONNECTIVITY_SUPABASE_FALLBACK_ENABLED=false\n"));
    }

    #[test]
    fn actualiza_la_version_del_payload_en_node_env() {
        let root = std::env::temp_dir().join(format!("actium-env-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("se crea el fixture");
        fs::write(
            root.join("node.env"),
            "# gestionado\nACTIUM_DEPLOYMENT_ID=deployment-1\nACTIUM_INSTALLER_VERSION=0.6.4\n",
        )
        .expect("se escribe node.env");
        fs::create_dir_all(root.join("secrets")).expect("se crea secrets");
        fs::write(
            root.join("secrets/data-plane.env"),
            "ACTIUM_INSTALLER_VERSION=0.6.4\nDATABASE_PASSWORD=valor-preservado\n",
        )
        .expect("se escribe el entorno runtime");
        write_payload_version(&root, INSTALLER_VERSION).expect("se actualiza la version");
        let updated = fs::read_to_string(root.join("node.env")).expect("se lee node.env");
        assert!(updated.contains(&format!("ACTIUM_INSTALLER_VERSION={INSTALLER_VERSION}\n")));
        assert!(updated.contains("ACTIUM_DEPLOYMENT_ID=deployment-1\n"));
        let runtime = fs::read_to_string(root.join("secrets/data-plane.env"))
            .expect("se lee el entorno runtime");
        assert!(runtime.contains(&format!("ACTIUM_INSTALLER_VERSION={INSTALLER_VERSION}\n")));
        assert!(runtime.contains("DATABASE_PASSWORD=valor-preservado\n"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn valida_secretos_connectivity_sin_exponer_su_valor() {
        let valid_enrollment = format!("{}{}", "acen_", "a".repeat(40));
        assert!(is_connectivity_secret(&valid_enrollment, "acen_"));
        assert!(!is_connectivity_secret("acen_corto", "acen_"));
        assert!(!is_connectivity_secret(
            "acer_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL$N",
            "acer_"
        ));
    }

    #[test]
    fn preparaciones_no_operativas_se_pueden_recuperar() {
        for status in ["failed", "installing", "prepared"] {
            assert!(is_recoverable_preparation_status(Some(status)));
            assert!(is_recoverable_incomplete_preparation(Some(status), None));
            assert!(!is_operational_installation(true, Some(status)));
        }
    }

    #[test]
    fn failed_con_active_release_no_es_preparacion_incompleta() {
        assert!(!is_recoverable_incomplete_preparation(
            Some("failed"),
            Some("0.8.0-lab.28-abc")
        ));
        assert!(is_recoverable_incomplete_preparation(Some("failed"), Some("  ")));
        assert!(is_recoverable_incomplete_preparation(Some("failed"), None));
    }

    #[test]
    fn supervisor_summary_cubre_recovery_sin_docker() {
        assert!(supervisor_runtime_summary_eligible(
            false,
            false,
            Some("0.8.0-lab.28-abc")
        ));
        assert!(supervisor_runtime_summary_eligible(true, false, None));
        assert!(!supervisor_runtime_summary_eligible(false, false, None));
        assert!(!supervisor_runtime_summary_eligible(
            true,
            true,
            Some("0.8.0-lab.28-abc")
        ));
    }

    #[test]
    fn solo_running_o_una_instalacion_legacy_son_operativos() {
        assert!(is_operational_installation(true, Some("running")));
        assert!(is_operational_installation(true, Some("stopped")));
        assert!(is_operational_installation(true, None));
        assert!(!is_operational_installation(false, Some("running")));
    }

    fn plan_multi_nodo_valido() -> NetworkPortPlan {
        NetworkPortPlan {
            telemetry_port: 8091,
            people_port: 8093,
            control_runtime_port: 8095,
            radio_control_port: 8101,
            radio_saf_port: 8102,
            site_core_port: 8089,
            prometheus_port: 9091,
            grafana_port: 3002,
            turn_port: 3479,
            turn_tls_port: 5350,
            turn_min_port: 49201,
            turn_max_port: 49241,
            livekit_http_port: 7882,
            livekit_rtc_tcp_port: 7883,
            livekit_udp_min_port: 50101,
            livekit_udp_max_port: 50201,
        }
    }

    #[test]
    fn acepta_topologia_completa_con_puertos_unicos() {
        let profiles = vec![
            "telemetry".to_string(),
            "people".to_string(),
            "radio-control".to_string(),
            "radio-saf".to_string(),
            "radio-turn".to_string(),
            "radio-livekit".to_string(),
            "observability".to_string(),
        ];
        let claims = network_port_claims(&profiles, &plan_multi_nodo_valido()).expect("claims");
        assert!(claims.contains_key(&(PortTransport::Tcp, 8093)));
    }

    #[test]
    fn people_reserva_un_puerto_distinto_por_node_en_el_mismo_host() {
        let profiles = vec!["people".to_string()];
        let first_plan = plan_multi_nodo_valido();
        let first_claims = network_port_claims(&profiles, &first_plan).expect("first claims");
        let reservations = first_claims
            .keys()
            .map(|claim| (*claim, "node-a".to_string()))
            .collect::<BTreeMap<_, _>>();

        let conflicting = network_port_claims(&profiles, &first_plan).expect("second claims");
        assert!(conflicting
            .keys()
            .any(|claim| reservations.contains_key(claim)));

        let mut second_plan = first_plan;
        second_plan.people_port = 8094;
        let second_claims = network_port_claims(&profiles, &second_plan).expect("second claims");
        assert!(second_claims
            .keys()
            .all(|claim| !reservations.contains_key(claim)));
    }

    #[test]
    fn control_negocia_reader_1_2_sin_romper_perfiles_legacy() {
        assert_eq!(
            site_runtime_schema_version_for_profiles(&["control".to_string()]),
            "1.2"
        );
        assert_eq!(
            site_runtime_schema_version_for_profiles(&["site-core".to_string()]),
            "1.1"
        );
    }

    #[test]
    fn radio_saf_tiene_claim_tcp_independiente_de_radio_control() {
        let profiles = vec!["radio-saf".to_string()];
        let claims = network_port_claims(&profiles, &plan_multi_nodo_valido()).expect("claims");
        assert!(claims.contains_key(&(PortTransport::Tcp, 8102)));
        assert!(!claims.contains_key(&(PortTransport::Tcp, 8101)));
    }

    #[test]
    fn rechaza_superposicion_udp_entre_turn_y_livekit() {
        let profiles = vec!["radio-turn".to_string(), "radio-livekit".to_string()];
        let mut plan = plan_multi_nodo_valido();
        plan.livekit_udp_min_port = plan.turn_max_port;
        let error = network_port_claims(&profiles, &plan)
            .expect_err("los rangos UDP no deben superponerse");
        assert!(error.contains("TURN relay") && error.contains("LiveKit RTC"));
    }

    #[test]
    fn recovery_no_confunde_directorios_hermanos() {
        assert!(path_is_within(
            std::path::Path::new(r"C:\Actium\Recovery\nodo-1"),
            std::path::Path::new(r"C:\Actium\Recovery"),
        ));
        assert!(!path_is_within(
            std::path::Path::new(r"C:\Actium\Recovery-legacy\nodo-1"),
            std::path::Path::new(r"C:\Actium\Recovery"),
        ));
    }

    #[test]
    fn reservas_persistentes_distinguen_tcp_y_udp() {
        let reservations = BTreeMap::from([
            ((PortTransport::Tcp, 3478), "nodo-a".to_string()),
            ((PortTransport::Udp, 49160), "nodo-a".to_string()),
        ]);
        let (tcp, udp) = reserved_port_sets(&reservations);
        assert!(tcp.contains(&3478));
        assert!(!tcp.contains(&49160));
        assert!(udp.contains(&49160));
        assert!(!udp.contains(&3478));
    }

    #[test]
    fn rangos_udp_reservados_por_windows_se_conservan_en_el_preflight() {
        let reserved = parse_excluded_udp_port_ranges(
            "\
Protocol udp Port Exclusion Ranges\n\
Start Port    End Port\n\
----------    --------\n\
49163         49262\n\
50000         50001\n",
        );
        assert!(reserved.contains(&49163));
        assert!(reserved.contains(&49262));
        assert!(reserved.contains(&50000));
        assert!(!reserved.contains(&49263));
    }

    #[test]
    fn lan_de_confianza_actualiza_solo_endpoints_derivados() {
        let previous = "http://192.168.0.95";
        let next = "http://192.168.0.117";
        assert_eq!(
            derived_trusted_lan_endpoint(
                Some(&"http://192.168.0.95:8100".to_string()),
                previous,
                next,
                8100,
            ),
            "http://192.168.0.117:8100"
        );
        assert_eq!(
            derived_trusted_lan_endpoint(
                Some(&"https://gateway.actiumsecurity.com".to_string()),
                previous,
                next,
                8100,
            ),
            "https://gateway.actiumsecurity.com"
        );
        assert_eq!(
            derived_trusted_lan_site_core_endpoint(
                Some(&"http://192.168.0.95:8088".to_string()),
                previous,
                next,
                8089,
            ),
            "http://192.168.0.117:8089"
        );
        assert_eq!(
            derived_trusted_lan_site_core_endpoint(
                Some(&"https://site.example.internal".to_string()),
                previous,
                next,
                8089,
            ),
            "https://site.example.internal"
        );
        assert_eq!(
            derived_trusted_lan_host(Some(&"192.168.0.95".to_string()), previous, next,),
            "192.168.0.117"
        );
        assert_eq!(
            derived_trusted_lan_host(Some(&"turn.actiumsecurity.com".to_string()), previous, next,),
            "turn.actiumsecurity.com"
        );
    }

    #[test]
    fn lan_de_confianza_reconcilia_el_entorno_que_realmente_usa_compose() {
        let runtime_env = "\
DATA_PLANE_NETWORK_MODE=trusted_lan\n\
DATA_PLANE_PUBLIC_BASE_URL=http://192.168.0.98\n\
SITE_CORE_PUBLIC_URL=http://192.168.0.98:8089\n\
RADIO_CONTROL_PUBLIC_URL=https://radio.example.internal\n\
SITE_CORE_PORT=8089\n";
        let updated = reconcile_trusted_lan_document(runtime_env, "http://192.168.0.138")
            .expect("el entorno runtime desactualizado se debe reconciliar");
        assert!(updated.contains("DATA_PLANE_PUBLIC_BASE_URL=http://192.168.0.138\n"));
        assert!(updated.contains("SITE_CORE_PUBLIC_URL=http://192.168.0.138:8089\n"));
        assert!(updated.contains("RADIO_CONTROL_PUBLIC_URL=https://radio.example.internal\n"));
    }

    #[test]
    fn cola_admite_solo_operaciones_de_nodo_conocidas() {
        for action in [
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
        ] {
            assert!(node_action_allowed(action));
        }
        assert!(!node_action_allowed("delete"));
        assert!(!node_action_allowed("update; stop"));
    }

    #[test]
    fn reportes_de_auditoria_respetan_terminal_y_alcance() {
        let snapshot = NodeAuditSnapshot {
            generated_at: "42".to_string(),
            project_name: "aegis-lake-edge-01".to_string(),
            services: Vec::new(),
            database_ok: true,
            database_error: None,
            telemetry: serde_json::json!({
                "terminals": [
                    {
                        "terminalId": "terminal-1",
                        "terminalLabel": "Moto 2",
                        "terminalPlatform": "android",
                        "terminalRuntime": "capacitor",
                        "sequence": 81,
                        "dvrSessionId": "session-9"
                    }
                ],
                "unresolvedDeadLetters": 0
            }),
        };

        let gps = audit_operation_report(&snapshot, "audit_gps", Some("terminal-1"))
            .expect("el reporte GPS debe serializarse");
        assert!(gps.contains("ESTADO GPS"));
        assert!(gps.contains("Moto 2"));
        assert!(gps.contains("\"sequence\": 81"));
        assert!(!gps.contains("\"dvrSessionId\""));

        let dvr = audit_operation_report(&snapshot, "audit_dvr", Some("terminal-1"))
            .expect("el reporte DVR debe serializarse");
        assert!(dvr.contains("ESTADO DVR"));
        assert!(dvr.contains("\"dvrSessionId\": \"session-9\""));
    }

    #[test]
    fn cola_limita_salidas_sin_perder_el_final() {
        let output = format!("inicio-{}", "x".repeat(500_010));
        let bounded = bounded_operation_output(output);
        assert!(bounded.starts_with("[Salida anterior truncada"));
        assert!(bounded.ends_with("xxxx"));
        assert!(bounded.chars().count() < 500_100);
    }

    fn runtime_capability_claim() -> (BootstrapClaims, PayloadManifestV3) {
        let profiles = super::product::RELEASE_SUPPORTED_PROFILES
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        let features = super::product::RELEASE_SUPPORTED_FEATURES
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        let files = vec![
            actium_node_core::PayloadFile {
                path: "VERSION".to_string(),
                size: 15,
                sha256: "a".repeat(64),
            },
            actium_node_core::PayloadFile {
                path: "release-capabilities.json".to_string(),
                size: 512,
                sha256: "b".repeat(64),
            },
        ];
        let claims = serde_json::from_value::<BootstrapClaims>(serde_json::json!({
            "schema_version": 1,
            "package_type": "actium-data-plane-enrollment",
            "installer_min_version": INSTALLER_VERSION,
            "enrollment_id": "11111111-1111-4111-8111-111111111111",
            "enrollment_token": format!("adpe_{}", "a".repeat(64)),
            "deployment_id": "22222222-2222-4222-8222-222222222222",
            "deployment_code": "runtime-contract",
            "deployment_name": "Runtime contract",
            "product_id": "aegis",
            "deployment_mode": "edge",
            "orchestrator": "docker_compose",
            "generation": 1,
            "checksum": "c".repeat(64),
            "control_endpoint": "https://center.example",
            "signing_key_ref": "fixture",
            "terminal_issuer": "https://center.example/terminal",
            "operator_issuer": "https://center.example/functions/v1/actium-telemetry-authority",
            "terminal_public_key_pem": "fixture",
            "operator_public_key_pem": "fixture",
            "profiles": ["telemetry"],
            "runtimeContractRevision": 1,
            "supportedProfiles": profiles,
            "supportedFeatures": features,
            "requiredFeatures": [],
            "runtimeCapabilities": {
                "schema": 1,
                "verified": true,
                "runtimeRelease": super::product::DATA_PLANE_RELEASE_VERSION,
                "payloadDigest": "d".repeat(64),
                "installerMinVersion": INSTALLER_VERSION,
                "sourceCommit": "e".repeat(40),
                "treeSha256": "d".repeat(64),
                "files": files,
                "supportedProfiles": profiles,
                "supportedFeatures": features,
            },
            "exp": 2_000_000_000,
            "iss": "https://center.example/bootstrap",
            "aud": "actium-node-manager",
            "sub": "deployment:22222222-2222-4222-8222-222222222222",
            "jti": "11111111-1111-4111-8111-111111111111"
        }))
        .unwrap();
        let payload = PayloadManifestV3 {
            schema: 3,
            release_version: super::product::DATA_PLANE_RELEASE_VERSION.to_string(),
            generated_at: "2026-08-20T00:00:00Z".to_string(),
            site_runtime_schema: "1.1".to_string(),
            supported_profiles: profiles,
            supported_features: features,
            files,
            tree_sha256: "d".repeat(64),
            source_commit: Some("e".repeat(40)),
            source_dirty: false,
        };
        (claims, payload)
    }

    #[test]
    fn runtime_capabilities_queda_ligado_al_payload_schema3_exacto() {
        let (claims, payload) = runtime_capability_claim();
        validate_runtime_capabilities_against_payload(&claims, Some(&payload)).unwrap();

        let mut mismatched = claims.clone();
        let capabilities = mismatched.runtime_capabilities.as_mut().unwrap();
        capabilities.payload_digest = "f".repeat(64);
        capabilities.tree_sha256 = "f".repeat(64);
        assert_eq!(
            validate_runtime_capabilities_against_payload(&mismatched, Some(&payload)),
            Err("RUNTIME_CAPABILITIES_PAYLOAD_MISMATCH".to_string())
        );
    }

    #[test]
    fn people_no_puede_declararse_sin_runtime_capabilities() {
        let (mut claims, _) = runtime_capability_claim();
        claims.supported_profiles.push("people".to_string());
        claims.supported_features = vec!["people_runtime_v1".to_string()];
        claims.required_features = vec!["people_runtime_v1".to_string()];
        claims.runtime_contract_revision = 0;
        claims.runtime_capabilities = None;
        assert_eq!(
            validate_runtime_capabilities_claim(&claims),
            Err("RUNTIME_CAPABILITIES_REQUIRED".to_string())
        );
    }

    #[test]
    fn candidate_site_core_deriva_feature_y_no_se_declara_en_lab32() {
        let (mut claims, _) = runtime_capability_claim();
        claims.deployment_id = "99999999-9999-4999-8999-999999999999".to_string();
        claims.site_id = Some("33333333-3333-4333-8333-333333333333".to_string());
        claims.site_core_deployment_id = Some("22222222-2222-4222-8222-222222222222".to_string());
        claims.profiles = vec!["site-core".to_string()];
        let intent = SiteCoreIntent {
            schema: 1,
            deployment_id: claims.deployment_id.clone(),
            site_id: claims.site_id.clone().unwrap(),
            role: "standby".to_string(),
            fencing_state: "fenced".to_string(),
            authority_mode: "disabled".to_string(),
            authority_epoch: None,
            effective_primary_deployment_id: claims.site_core_deployment_id.clone().unwrap(),
            required_feature: "site_core_candidate_v1".to_string(),
        };
        validate_site_core_intent(&intent, &claims).unwrap();
        assert_eq!(
            required_runtime_features(&claims.profiles, Some(&intent)),
            vec!["site_core_candidate_v1".to_string()]
        );
        assert!(!super::product::RELEASE_SUPPORTED_FEATURES.contains(&"site_core_candidate_v1"));

        let mut unsafe_intent = intent;
        unsafe_intent.authority_mode = "enabled".to_string();
        assert_eq!(
            validate_site_core_intent(&unsafe_intent, &claims),
            Err("SITE_CORE_CANDIDATE_INTENT_INVALID".to_string())
        );
    }
}

// ===========================================================================
// Privileged Connectivity Operation Bridge
//
// Safe, typed bridge for executing connectivity provider operations through
// the Supervisor. The frontend expresses connectivity INTENT only — never
// commands, never keys, never routes.
//
// Design principles:
//   - operation is always an enum variant, never a free string
//   - no arbitrary command/args/path/route injection
//   - private keys resolved via secret_ref, never transported
//   - Supervisor re-verifies material on every execution
//   - routes derived from policy, never client-supplied
// ===========================================================================

/// Execute a typed connectivity provider operation through the Supervisor.
///
/// SECURITY INVARIANTS (enforced by this bridge):
///   1. `operation` is an enum — never a free string
///   2. Material is re-verified via Supervisor before privilege escalation
///   3. No arbitrary private keys — resolved via secret_ref
///   4. No arbitrary routes — derived from policy only
///   5. No arbitrary commands or shell execution
///   6. node_id validated against Supervisor's deployment scope
#[tauri::command]
async fn exec_conn_op(
    _app: AppHandle,
    backend: tauri::State<'_, OperationBackend>,
    request: actium_node_core::ConnectivityOperationRequest,
) -> Result<actium_node_core::ConnectivityOperationResult, String> {
    // 1. Supervisor must be available for privileged operations
    if backend.supervisor.is_none() {
        return Err("CONNECTIVITY_SUPERVISOR_UNAVAILABLE".to_string());
    }
    let client = backend.supervisor.as_ref().unwrap();

    // 2. Validate endpoint — reject malformed or missing
    if request.endpoint.is_empty() || !request.endpoint.contains(':') {
        return Err("CONNECTIVITY_ENDPOINT_INVALID".to_string());
    }

    // 3. Build the Supervisor command — Supervisor re-verifies material,
    //    resolves secret_ref, validates scope, executes privileged operation.
    let reply = client
        .request(SupervisorCommand::ExecuteConnectivityOperation(request))
        .map_err(|e| format!("CONNECTIVITY_SUPERVISOR_OP_FAILED:{e}"))?;

    // 4. Extract result from reply
    match reply {
        SupervisorReply::ConnectivityOperationResult(result) => Ok(*result),
        SupervisorReply::Error { code: _, message } => {
            if message.contains("material") || message.contains("signature") || message.contains("scope") {
                Err(format!("SUPERVISOR_REJECTED:{}", message))
            } else {
                Err(format!("CONNECTIVITY_OP_FAILED:{}", message))
            }
        }
        _ => Err("CONNECTIVITY_UNEXPECTED_REPLY".to_string()),
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelSupervisorStatus {
    channel: String,
    installed: bool,
    available: bool,
    version: Option<String>,
    protocol: Option<u16>,
    features: Vec<String>,
    nodes_count: usize,
    nodes_root: String,
}

#[tauri::command]
fn get_channel_status(channel: String) -> ChannelSupervisorStatus {
    let key_path = paths::supervisor_key_path_for(&channel);
    let socket_path = paths::supervisor_socket_path_for(&channel);
    let nodes_root = paths::authorized_nodes_root_for(&channel);
    let installed = key_path.is_file();

    let mut nodes_count = 0;
    if let Ok(entries) = fs::read_dir(&nodes_root) {
        nodes_count = entries.flatten().filter(|e| e.path().is_dir()).count();
    }

    if !installed {
        return ChannelSupervisorStatus {
            channel,
            installed: false,
            available: false,
            version: None,
            protocol: None,
            features: Vec::new(),
            nodes_count,
            nodes_root: nodes_root.to_string_lossy().into_owned(),
        };
    }

    let client = SupervisorClient::new(&socket_path, &key_path);
    match client.request(SupervisorCommand::Ping) {
        Ok(SupervisorReply::Pong {
            supervisor_version,
            recovered_operations: _,
            protocol_version,
            features,
        }) => ChannelSupervisorStatus {
            channel,
            installed: true,
            available: true,
            version: Some(supervisor_version),
            protocol: Some(protocol_version),
            features,
            nodes_count,
            nodes_root: nodes_root.to_string_lossy().into_owned(),
        },
        _ => ChannelSupervisorStatus {
            channel,
            installed: true,
            available: false,
            version: None,
            protocol: None,
            features: Vec::new(),
            nodes_count,
            nodes_root: nodes_root.to_string_lossy().into_owned(),
        },
    }
}

#[tauri::command]
async fn install_channel_supervisor(channel: String) -> Result<String, String> {
    #[cfg(windows)]
    {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_dir = exe.parent().unwrap_or_else(|| Path::new("."));

        let supervisor_candidates = [
            exe_dir.join("resources").join("supervisor").join("actium-node-supervisor.exe"),
            exe_dir.join("resources").join("actium-node-supervisor.exe"),
            exe_dir.join("supervisor").join("actium-node-supervisor.exe"),
            exe_dir.join("actium-node-supervisor.exe"),
            exe_dir.join("..").join("release").join("actium-node-supervisor.exe"),
            exe_dir.join("..").join("target").join("release").join("actium-node-supervisor.exe"),
            exe_dir.join("..").join("..").join("target").join("release").join("actium-node-supervisor.exe"),
            exe_dir.join("..").join("target").join("debug").join("actium-node-supervisor.exe"),
            PathBuf::from(r"C:\Program Files\Actium Node Manager\resources\supervisor\actium-node-supervisor.exe"),
            PathBuf::from(r"C:\ProgramData\Actium\NodeManager\bin\actium-node-supervisor.exe"),
            PathBuf::from(r"C:\ProgramData\Actium\NodeManagerLab\bin\actium-node-supervisor.exe"),
        ];

        let supervisor_exe = supervisor_candidates
            .iter()
            .find(|p| p.is_file())
            .cloned()
            .ok_or_else(|| "No se encontró el ejecutable actium-node-supervisor.exe empaquetado.".to_string())?;

        let arg_list = format!("--install --channel {}", channel);

        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait",
                    supervisor_exe.display(),
                    arg_list
                ),
            ])
            .status()
            .map_err(|e| format!("Error al solicitar elevación UAC: {e}"))?;

        if !status.success() {
            return Err("La instalación del servicio de Windows fue cancelada o rechazada.".to_string());
        }
        Ok(format!("Supervisor canal {channel} instalado y activado exitosamente."))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;

        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let exe_dir = exe.parent().unwrap_or_else(|| Path::new("."));

        let script_candidates = [
            PathBuf::from("/usr/lib/Actium Node Manager/supervisor/install-supervisor-debian.sh"),
            PathBuf::from("/usr/lib/actium-node-manager/supervisor/install-supervisor-debian.sh"),
            exe_dir.join("..").join("lib").join("Actium Node Manager").join("supervisor").join("install-supervisor-debian.sh"),
            exe_dir.join("..").join("lib").join("actium-node-manager").join("supervisor").join("install-supervisor-debian.sh"),
            exe_dir.join("supervisor").join("install-supervisor-debian.sh"),
            exe_dir.join("resources").join("supervisor").join("install-supervisor-debian.sh"),
            exe_dir.join("install-supervisor-debian.sh"),
            exe_dir.join("..").join("supervisor").join("install-supervisor-debian.sh"),
            exe_dir.join("..").join("target").join("release").join("install-supervisor-debian.sh"),
            exe_dir.join("..").join("src-tauri").join("supervisor").join("install-supervisor-debian.sh"),
        ];

        let supervisor_candidates = [
            PathBuf::from("/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor"),
            PathBuf::from("/usr/lib/actium-node-manager/supervisor/actium-node-supervisor"),
            exe_dir.join("..").join("lib").join("Actium Node Manager").join("supervisor").join("actium-node-supervisor"),
            exe_dir.join("..").join("lib").join("actium-node-manager").join("supervisor").join("actium-node-supervisor"),
            exe_dir.join("supervisor").join("actium-node-supervisor"),
            exe_dir.join("resources").join("supervisor").join("actium-node-supervisor"),
            exe_dir.join("actium-node-supervisor"),
            exe_dir.join("..").join("target").join("release").join("actium-node-supervisor"),
            exe_dir.join("..").join("target").join("debug").join("actium-node-supervisor"),
            exe_dir.join("..").join("..").join("target").join("release").join("actium-node-supervisor"),
            exe_dir.join("..").join("src-tauri").join("target").join("release").join("actium-node-supervisor"),
        ];

        let payload_candidates = [
            PathBuf::from("/usr/lib/Actium Node Manager/node"),
            PathBuf::from("/usr/lib/actium-node-manager/node"),
            exe_dir.join("..").join("lib").join("Actium Node Manager").join("node"),
            exe_dir.join("..").join("lib").join("actium-node-manager").join("node"),
            exe_dir.join("node"),
            exe_dir.join("resources").join("node"),
            exe_dir.join("supervisor").join("payload"),
            exe_dir.join("resources").join("supervisor").join("payload"),
            exe_dir.join("..").join("resources").join("node"),
            exe_dir.join("..").join("..").join("resources").join("node"),
            exe_dir.join("..").join("src-tauri").join("resources").join("node"),
        ];

        let maybe_script = script_candidates.iter().find(|p| p.is_file()).cloned();
        let supervisor_bin = supervisor_candidates
            .iter()
            .find(|p| p.is_file())
            .cloned()
            .ok_or_else(|| "No se encontró el binario actium-node-supervisor empaquetado.".to_string())?;
        let maybe_payload = payload_candidates.iter().find(|p| p.join("PAYLOAD.json").is_file()).cloned();

        // Asegurar permisos de ejecución
        if let Ok(metadata) = std::fs::metadata(&supervisor_bin) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&supervisor_bin, perms);
        }
        if let Some(script_path) = &maybe_script {
            if let Ok(metadata) = std::fs::metadata(script_path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o755);
                let _ = std::fs::set_permissions(script_path, perms);
            }
        }

        // Construcción del comando de instalación
        let (exec_prog, exec_args, shell_cmd) = if let Some(script_path) = &maybe_script {
            let mut args = vec!["--channel".to_string(), channel.clone(), "--install".to_string()];
            args.push("--binary".to_string());
            args.push(supervisor_bin.to_string_lossy().to_string());
            if let Some(payload_dir) = &maybe_payload {
                args.push("--payload".to_string());
                args.push(payload_dir.to_string_lossy().to_string());
            }

            let mut quoted_args = vec![
                format!("--channel '{}'", channel),
                "--install".to_string(),
                format!("--binary '{}'", supervisor_bin.display()),
            ];
            if let Some(payload_dir) = &maybe_payload {
                quoted_args.push(format!("--payload '{}'", payload_dir.display()));
            }
            let shell_cmd = format!("sh '{}' {}", script_path.display(), quoted_args.join(" "));
            (script_path.clone(), args, shell_cmd)
        } else {
            let args = vec!["--install".to_string(), "--channel".to_string(), channel.clone()];
            let shell_cmd = format!("'{}' --install --channel '{}'", supervisor_bin.display(), channel);
            (supervisor_bin.clone(), args, shell_cmd)
        };

        // Intento 1: pkexec (Polkit gráfico estándar en Linux)
        let mut pkexec_cmd = if maybe_script.is_some() {
            let mut c = Command::new("pkexec");
            c.arg("sh").arg(exec_prog.to_str().unwrap());
            c.args(&exec_args);
            c
        } else {
            let mut c = Command::new("pkexec");
            c.arg(exec_prog.to_str().unwrap());
            c.args(&exec_args);
            c
        };

        if let Ok(status) = pkexec_cmd.status() {
            if status.success() {
                return Ok(format!("Supervisor canal {channel} instalado y activado exitosamente con systemd."));
            }
        }

        // Intento 2: Terminal con sudo interactivo como fallback
        let terminals = [
            ("x-terminal-emulator", vec!["-e"]),
            ("gnome-terminal", vec!["--"]),
            ("konsole", vec!["-e"]),
            ("xfce4-terminal", vec!["-x"]),
            ("xterm", vec!["-e"]),
        ];

        for (term, args) in terminals {
            let mut cmd = Command::new(term);
            for arg in args {
                cmd.arg(arg);
            }
            cmd.args(["sh", "-c", &format!("echo 'Instalando Actium Node Supervisor ({channel})...'; sudo {}; echo 'Presione Enter para cerrar...'; read _", shell_cmd)]);
            if let Ok(status) = cmd.status() {
                if status.success() {
                    return Ok(format!("Supervisor canal {channel} instalado y activado exitosamente."));
                }
            }
        }

        Err(format!("No se pudo obtener elevación de permisos. Ejecute manualmente: sudo {shell_cmd}"))
    }
}

#[tauri::command]
fn preview_promotion(
    source_channel: String,
    target_channel: String,
    deployment_code: String,
) -> Result<promotion::PromotionPreview, String> {
    promotion::preview_node_promotion(&source_channel, &target_channel, &deployment_code)
}

#[tauri::command]
fn execute_promotion(
    source_channel: String,
    target_channel: String,
    deployment_code: String,
) -> Result<promotion::PromotionResult, String> {
    promotion::execute_node_promotion(&source_channel, &target_channel, &deployment_code)
}

#[tauri::command]
async fn pick_directory(
    default_path: Option<String>,
    title: Option<String>,
) -> Result<Option<String>, String> {
    let mut dialog = rfd::AsyncFileDialog::new();
    if let Some(ref t) = title {
        dialog = dialog.set_title(t);
    }
    if let Some(ref p) = default_path {
        if !p.is_empty() && std::path::Path::new(p).exists() {
            dialog = dialog.set_directory(std::path::Path::new(p));
        }
    }
    let folder = dialog.pick_folder().await;
    Ok(folder.map(|f| f.path().to_string_lossy().to_string()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let operation_backend = OperationBackend::open()
        .unwrap_or_else(|error| panic!("No se pudo abrir el backend de ejecucion: {error}"));
    tauri::Builder::default()
        .manage(operation_backend)
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            inspect_installation,
            list_managed_nodes,
            runtime_unit_inventory,
            execute_runtime_unit,
            suggest_installation_target,
            suggest_network_ports,
            validate_bootstrap,
            validate_installation_request,
            install_dependencies,
            archive_incomplete_preparation,
            apply_installation,
            promote_archived_node,
            update_node_configuration,
            audit_node_telemetry,
            audit_node_ht,
            enqueue_node_operation,
            enqueue_node_configuration,
            list_node_operation_jobs,
            cancel_node_operation_job,
            node_operation,
            export_diagnostic_report,
            exec_conn_op,
            get_channel_status,
            install_channel_supervisor,
            preview_promotion,
            execute_promotion,
            pick_directory
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| panic!("error al iniciar {}: {error}", product::display_name()));
}
