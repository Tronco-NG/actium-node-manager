use crate::{
    HostIdentity as HostIdentityRecord, HostReadinessReport, JournalOperation, MutationStatus,
    NetworkAddress, RuntimeActionResult, RuntimeUnitActionRequest, RuntimeUnitInventory,
    StorageMount,
};
use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const IPC_PROTOCOL_VERSION: u16 = 3;
pub const SUPERVISOR_VERSION: &str = "0.5.21";
pub const IPC_FEATURES: [&str; 14] = [
    "resume_incomplete",
    "capability_scoped_config",
    "host_identity_v1",
    "material_plane_v1",
    "purge",
    "cancel_preparation",
    "mutation_status_v1",
    "host_readiness_v1",
    "host_enrollment_v1",
    "host_enrollment_v2",
    "extension_bundle_v1",
    "extension_lifecycle_v1",
    "runtime_descriptor_v1",
    "authority_ceremony_v1",
];
pub const REQUIRED_MANAGER_FEATURES: [&str; 4] = [
    "resume_incomplete",
    "capability_scoped_config",
    "host_identity_v1",
    "cancel_preparation",
];
pub const MAX_IPC_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupervisorOperationRequest {
    pub target_node_id: String,
    pub install_dir: String,
    pub node_label: String,
    pub terminal_id: Option<String>,
    pub action: String,
    pub requested_release: Option<String>,
}

/// Material enqueue request. Scope identifiers are forbidden here: Supervisor
/// builds TrustedNodeScope from installation evidence, not from IPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnqueueMaterialRequest {
    pub install_dir: String,
    pub capability: String,
    pub package_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetMaterialStateRequest {
    pub install_dir: String,
    pub capability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcileMaterialRequest {
    pub install_dir: String,
    pub capability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommissionNodeRequest {
    pub install_dir: String,
    pub expected_release: String,
    pub node_env: String,
    pub marker: String,
    pub terminal_public_key: String,
    pub operator_public_key: String,
    pub site_runtime_public_key: Option<String>,
    #[serde(default)]
    pub initial_people_policy_cache: Option<String>,
    #[serde(default)]
    pub control_plane_ca_pem: Option<String>,
    pub connectivity_edge_enrollment_token: Option<String>,
    pub connectivity_internal_relay_token: Option<String>,
    pub enrollment_token: String,
    pub radio_archive_host_path: Option<String>,
    pub prepare_only: bool,
    pub connectivity_edge_control_url: Option<String>,
    pub resume_incomplete: bool,
}

// ===========================================================================
// Connectivity Operation IPC — typed, safe, no command injection
// ===========================================================================

/// Allowed connectivity operations. Every variant is an enum — no free strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityOperation {
    Provision,
    Connect,
    Disconnect,
    Health,
    Rotate,
    Revoke,
    Reconcile,
}

/// Operation result reported back from Supervisor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityOperationResult {
    pub ok: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_state: Option<serde_json::Value>,
}

/// Request envelope for a connectivity provider operation.
/// Everything the Supervisor allows the frontend to express.
/// The Supervisor RE-VERIFIES all material before privilege escalation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityOperationRequest {
    /// The typed operation.
    pub operation: ConnectivityOperation,
    /// Provider kind: "direct" | "overlay" | "relay".
    pub provider: String,
    /// Logical reference to the secret in the material plane.
    pub secret_ref: Option<String>,
    /// Target endpoint (host:port).
    pub endpoint: String,
    /// Generation from material (anti-rollback).
    pub generation: u64,
    /// Policy revision from material.
    pub revision: u64,
    /// Optional gateway ID for gateway-bound operations.
    #[serde(default)]
    pub gateway_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationWriteRequest {
    pub install_dir: String,
    pub env_updates: BTreeMap<String, String>,
    pub connectivity_edge_enrollment_token: Option<String>,
    pub connectivity_internal_relay_token: Option<String>,
    pub radio_archive_host_path: Option<String>,
    pub prepare_rollback: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoragePreflightRequest {
    pub mountpoint: String,
    pub subpath: String,
    pub capability: String,
    #[serde(default)]
    pub deployment_id: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub site_id: Option<String>,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub host_installation_id: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub schema_version: u8,
    pub purpose: String,
    pub ticket_hash: String,
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_installation_id: String,
    pub binding_epoch: u64,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub environment: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentApplyRequest {
    pub center_bundle: crate::SignedEnvelope,
    pub enrollment_package: crate::SignedEnvelope,
    pub enrollment_nonce: String,
    pub node_public_key: String,
    pub challenge: EnrollmentChallenge,
    #[serde(default)]
    pub proof: Option<crate::SignedEnvelope>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentProofRequest {
    pub ticket: String,
    pub challenge: EnrollmentChallenge,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentProofResponse {
    pub proof: crate::SignedEnvelope,
    pub host_identity: HostIdentityRecord,
    pub supervisor_public_key: String,
    pub supervisor_key_id: String,
    pub binding_epoch: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentAckResponse {
    pub ack: crate::SignedEnvelope,
    pub supervisor_public_key: String,
    pub supervisor_key_id: String,
    pub enrollment_nonce: String,
    pub package_digest: String,
    pub binding_epoch: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageGrantApprovalRequest {
    pub preflight: crate::StorageGrantPreflight,
    pub approval: crate::SignedEnvelope,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageTransportDiscoveryRequest {
    pub scope: crate::StorageTransportScope,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeRuntimeSummary {
    pub project_name: String,
    pub total_services: usize,
    pub running_services: usize,
    pub starting_services: usize,
    pub unhealthy_services: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectServiceSummary {
    pub workload: String,
    pub container_name: String,
    pub state: String,
    pub health: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectAuditSummary {
    pub services: Vec<ProjectServiceSummary>,
    pub has_postgres: bool,
}

/// Input accepted by the Supervisor for the Owner-bound initial authority
/// ceremony.  The online authority paths are deliberately absent: the
/// Supervisor derives them from its signed/system configuration.
fn default_authority_trust_root_set() -> String {
    "actium-product-v1".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCeremonyRequest {
    pub ceremony_id: String,
    pub provider: String,
    pub offline_root_dir: String,
    pub recovery_dir: String,
    /// The requested trust root set is carried for durable correlation.  The
    /// Supervisor still validates it against the fixed ceremony contract; it
    /// is never accepted as authority merely because it came from the UI.
    #[serde(default = "default_authority_trust_root_set")]
    pub trust_root_set: String,
    #[serde(default)]
    pub owner_confirmation: bool,
}

/// Safe, non-secret progress returned by the Owner ceremony boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCeremonyProgress {
    pub ceremony_id: String,
    pub state: String,
    pub code: Option<String>,
    pub provider: String,
    pub offline_root_dir: String,
    pub recovery_dir: String,
    pub online_data_dir: String,
    pub root_key_id: Option<String>,
    pub root_fingerprint: Option<String>,
    pub trust_bundle_path: Option<String>,
    pub trust_bundle_digest: Option<String>,
    pub trust_epoch: Option<u64>,
    pub subordinate_count: usize,
    pub public_only_key_count: usize,
    pub recovery_path: Option<String>,
    pub recovery_status: String,
    pub authority_service_state: String,
    pub trust_store_state: String,
    pub updated_at: u64,
    /// Durable operation correlation.  Optional keeps pre-queue journals
    /// readable while new UI executions are owned by the operations queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum SupervisorCommand {
    Ping,
    EnqueueOperation(SupervisorOperationRequest),
    /// Enqueue the Owner ceremony in the same durable operations journal used
    /// by every other privileged lifecycle action.
    EnqueueAuthorityCeremony(AuthorityCeremonyRequest),
    ListOperations {
        limit: usize,
    },
    CancelOperation {
        operation_id: String,
    },
    MutationStatus,
    HostReadiness,
    NetworkInventory,
    NodeRuntimeSummary {
        install_dir: String,
    },
    RuntimeUnitInventory {
        install_dir: String,
    },
    ExecuteRuntimeUnit(RuntimeUnitActionRequest),
    CommissionNode(CommissionNodeRequest),
    PersistConfiguration(ConfigurationWriteRequest),
    HealthGate {
        install_dir: String,
    },
    ExecuteAction {
        install_dir: String,
        action: String,
    },
    ProjectAudit {
        install_dir: String,
    },
    TelemetryAudit {
        install_dir: String,
    },
    NodeAgentRuntime {
        install_dir: String,
    },
    EnqueueMaterial(EnqueueMaterialRequest),
    GetMaterialState(GetMaterialStateRequest),
    ReconcileMaterial(ReconcileMaterialRequest),
    /// Execute a typed, privileged connectivity provider operation.
    /// The Supervisor re-verifies material, resolves secret_ref, validates
    /// scope, and executes via the native provider.
    ExecuteConnectivityOperation(ConnectivityOperationRequest),
    /// Read the Supervisor-owned HostIdentity for host-bound enrollment checks.
    HostIdentity,
    /// Read-only public Trust Fabric state owned by Supervisor.
    TrustStoreStatus,
    /// Install a public Trust Fabric bundle atomically.
    TrustStoreInstall {
        bundle: crate::SignedTrustBundle,
    },
    /// Read-only preflight for the explicit Owner authority ceremony.
    AuthorityCeremonyPreflight(AuthorityCeremonyRequest),
    /// Execute the explicit Owner authority ceremony through fixed paths and
    /// the packaged ceremony binary; never a shell command from the UI.
    AuthorityCeremonyExecute(AuthorityCeremonyRequest),
    /// Retry recovery export for a previously completed ceremony.
    AuthorityCeremonyExportRecovery {
        ceremony_id: String,
    },
    /// Install first trust only when bound to the verified Owner ceremony.
    AuthorityCeremonyActivate {
        ceremony_id: String,
        expected_root_fingerprint: String,
        owner_confirmation: bool,
    },
    /// Read persisted safe ceremony progress.
    AuthorityCeremonyStatus {
        ceremony_id: String,
    },
    StorageDiscover,
    EnrollmentStatus,
    EnrollmentProof(EnrollmentProofRequest),
    EnrollmentApplySignedPackage(EnrollmentApplyRequest),
    StorageGrantPreflight(StoragePreflightRequest),
    StorageGrantApplySignedApproval(StorageGrantApprovalRequest),
    StorageGrantList,
    /// Sign a Supervisor-owned discovery snapshot for the configured Center transport.
    StorageTransportSignDiscovery(StorageTransportDiscoveryRequest),
    /// Sign a previously persisted preflight intent for the configured Center transport.
    StorageTransportSignIntent {
        intent_id: String,
    },
    /// Supervisor-authorized Product Extension Bundle lifecycle.
    ExtensionInstall {
        source_path: String,
    },
    ExtensionActivate {
        product_id: String,
    },
    ExtensionRollback {
        product_id: String,
    },
    ExtensionSetEnabled {
        product_id: String,
        enabled: bool,
    },
    ExtensionRemove {
        product_id: String,
    },
    ExtensionStatus,
    /// Sign a canonical runtime descriptor only after the Host is enrolled.
    /// Before enrollment the Manager may publish the same descriptor as
    /// DISCOVERED/UNTRUSTED, but it must never manufacture a signature.
    RuntimeDescriptorSign {
        descriptor: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum SupervisorReply {
    Pong {
        supervisor_version: String,
        recovered_operations: usize,
        protocol_version: u16,
        features: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_commit: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        build_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binary_sha256: Option<String>,
    },
    Operation(Box<JournalOperation>),
    Operations(Vec<JournalOperation>),
    MutationStatus(MutationStatus),
    HostReadiness(HostReadinessReport),
    NetworkInventory(Vec<NetworkAddress>),
    NodeRuntimeSummary(NodeRuntimeSummary),
    RuntimeUnitInventory(RuntimeUnitInventory),
    RuntimeAction(RuntimeActionResult),
    ProjectAudit(ProjectAuditSummary),
    Json {
        value: String,
    },
    MaterialState {
        capability: String,
        state_json: String,
    },
    ConnectivityOperationResult(Box<super::ipc::ConnectivityOperationResult>),
    HostIdentity {
        identity: Option<HostIdentityRecord>,
    },
    AuthorityCeremony(AuthorityCeremonyProgress),
    StorageInventory(Vec<StorageMount>),
    EnrollmentStatus {
        enrolled: bool,
        code: Option<String>,
        #[serde(default)]
        host_id: Option<String>,
        #[serde(default)]
        site_id: Option<String>,
        #[serde(default)]
        organization_id: Option<String>,
        #[serde(default)]
        deployment_id: Option<String>,
        #[serde(default)]
        binding_epoch: Option<u64>,
    },
    EnrollmentProof(EnrollmentProofResponse),
    EnrollmentAck(EnrollmentAckResponse),
    StoragePreflight {
        code: String,
        canonical_path: Option<String>,
        message: String,
        #[serde(default)]
        intent: Option<crate::StorageGrantPreflight>,
    },
    StorageGrantList {
        grants: Vec<crate::StorageGrant>,
    },
    StorageTransport {
        envelope: crate::SignedStorageTransport,
    },
    ExtensionStatus(crate::ExtensionRegistrySnapshot),
    ExtensionResult(crate::ExtensionSummary),
    RuntimeDescriptorSigned {
        descriptor: serde_json::Value,
        payload: String,
        signature: String,
        signer_key_id: String,
        public_key: String,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupervisorRequestEnvelope {
    pub protocol_version: u16,
    pub request_id: String,
    pub issued_at_unix_seconds: u64,
    pub nonce: String,
    pub command: SupervisorCommand,
    pub authentication: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupervisorResponseEnvelope {
    pub protocol_version: u16,
    pub request_id: String,
    pub issued_at_unix_seconds: u64,
    pub reply: SupervisorReply,
    pub authentication: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestSignature<'a> {
    protocol_version: u16,
    request_id: &'a str,
    issued_at_unix_seconds: u64,
    nonce: &'a str,
    command: &'a SupervisorCommand,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseSignature<'a> {
    protocol_version: u16,
    request_id: &'a str,
    issued_at_unix_seconds: u64,
    reply: &'a SupervisorReply,
}

impl SupervisorRequestEnvelope {
    pub fn signed(command: SupervisorCommand, key: &[u8]) -> Result<Self, String> {
        let mut request = Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            issued_at_unix_seconds: now(),
            nonce: Uuid::new_v4().to_string(),
            command,
            authentication: String::new(),
        };
        request.authentication = request.signature(key)?;
        Ok(request)
    }

    pub fn verify(&self, key: &[u8], current_time: u64) -> Result<(), String> {
        if self.protocol_version != IPC_PROTOCOL_VERSION {
            return Err(format!(
                "Version IPC incompatible: recibida={}, soportada={IPC_PROTOCOL_VERSION}.",
                self.protocol_version
            ));
        }
        let drift = current_time.abs_diff(self.issued_at_unix_seconds);
        if drift > MAX_CLOCK_SKEW_SECONDS {
            return Err(format!(
                "Solicitud IPC fuera de ventana temporal ({drift}s)."
            ));
        }
        verify_signature(&self.signature_bytes()?, &self.authentication, key)
    }

    fn signature(&self, key: &[u8]) -> Result<String, String> {
        sign(&self.signature_bytes()?, key)
    }

    fn signature_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&RequestSignature {
            protocol_version: self.protocol_version,
            request_id: &self.request_id,
            issued_at_unix_seconds: self.issued_at_unix_seconds,
            nonce: &self.nonce,
            command: &self.command,
        })
        .map_err(|error| format!("No se pudo serializar la firma IPC: {error}"))
    }
}

impl SupervisorResponseEnvelope {
    pub fn signed(
        request_id: impl Into<String>,
        reply: SupervisorReply,
        key: &[u8],
    ) -> Result<Self, String> {
        let mut response = Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: request_id.into(),
            issued_at_unix_seconds: now(),
            reply,
            authentication: String::new(),
        };
        response.authentication = sign(&response.signature_bytes()?, key)?;
        Ok(response)
    }

    pub fn verify(&self, request_id: &str, key: &[u8], current_time: u64) -> Result<(), String> {
        if self.protocol_version != IPC_PROTOCOL_VERSION || self.request_id != request_id {
            return Err("La respuesta IPC no corresponde a la solicitud.".to_string());
        }
        let drift = current_time.abs_diff(self.issued_at_unix_seconds);
        if drift > MAX_CLOCK_SKEW_SECONDS {
            return Err(format!(
                "Respuesta IPC fuera de ventana temporal ({drift}s)."
            ));
        }
        verify_signature(&self.signature_bytes()?, &self.authentication, key)
    }

    fn signature_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&ResponseSignature {
            protocol_version: self.protocol_version,
            request_id: &self.request_id,
            issued_at_unix_seconds: self.issued_at_unix_seconds,
            reply: &self.reply,
        })
        .map_err(|error| format!("No se pudo serializar la respuesta IPC: {error}"))
    }
}

#[derive(Debug, Clone)]
pub struct SupervisorClient {
    #[cfg_attr(not(any(unix, windows)), allow(dead_code))]
    socket_path: PathBuf,
    key_path: PathBuf,
}

impl SupervisorClient {
    pub fn new(socket_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            key_path: key_path.into(),
        }
    }

    /// Paths are exposed for frontends that share the typed client (Tauri and
    /// the headless Manager) without duplicating endpoint discovery logic.
    pub fn socket_path_for_manager(&self) -> PathBuf {
        self.socket_path.clone()
    }
    pub fn key_path_for_manager(&self) -> PathBuf {
        self.key_path.clone()
    }

    pub fn request(&self, command: SupervisorCommand) -> Result<SupervisorReply, String> {
        let key = load_ipc_key(&self.key_path)?;
        let request = SupervisorRequestEnvelope::signed(command, &key)?;
        self.request_envelope(request, &key)
    }

    #[cfg(unix)]
    fn request_envelope(
        &self,
        request: SupervisorRequestEnvelope,
        key: &[u8],
    ) -> Result<SupervisorReply, String> {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|error| {
            format!(
                "No se pudo conectar con Supervisor en {}: {error}",
                self.socket_path.display()
            )
        })?;
        let timeout_seconds = request_timeout_seconds(&request.command);
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(timeout_seconds)))
            .map_err(|error| format!("No se pudo configurar timeout IPC: {error}"))?;
        write_framed_json(&mut stream, &request)?;
        let response: SupervisorResponseEnvelope = read_framed_json(&mut stream)?;
        response.verify(&request.request_id, key, now())?;
        match response.reply {
            SupervisorReply::Error { code, message } => Err(format!("[{code}] {message}")),
            reply => Ok(reply),
        }
    }

    #[cfg(windows)]
    fn request_envelope(
        &self,
        request: SupervisorRequestEnvelope,
        key: &[u8],
    ) -> Result<SupervisorReply, String> {
        use interprocess::local_socket::{prelude::*, GenericNamespaced, Stream};

        let pipe_name = self.socket_path.to_string_lossy();
        let name = pipe_name
            .as_ref()
            .to_ns_name::<GenericNamespaced>()
            .map_err(|error| format!("Nombre de named pipe invalido: {error}"))?;
        let mut stream = Stream::connect(name).map_err(|error| {
            format!(
                "No se pudo conectar con Supervisor en \\\\.\\pipe\\{}: {error}",
                pipe_name
            )
        })?;
        let timeout_seconds = request_timeout_seconds(&request.command);
        let _ = stream.set_recv_timeout(Some(std::time::Duration::from_secs(timeout_seconds)));
        write_framed_json(&mut stream, &request)?;
        let response: SupervisorResponseEnvelope = read_framed_json(&mut stream)?;
        response.verify(&request.request_id, key, now())?;
        match response.reply {
            SupervisorReply::Error { code, message } => Err(format!("[{code}] {message}")),
            reply => Ok(reply),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn request_envelope(
        &self,
        _request: SupervisorRequestEnvelope,
        _key: &[u8],
    ) -> Result<SupervisorReply, String> {
        Err("Actium Node Supervisor solo esta habilitado en Linux y Windows.".to_string())
    }
}

fn request_timeout_seconds(command: &SupervisorCommand) -> u64 {
    match command {
        SupervisorCommand::CommissionNode(_)
        | SupervisorCommand::ExecuteAction { .. }
        | SupervisorCommand::ExecuteRuntimeUnit(_)
        | SupervisorCommand::AuthorityCeremonyExecute(_) => 1_800,
        SupervisorCommand::HealthGate { .. }
        | SupervisorCommand::ProjectAudit { .. }
        | SupervisorCommand::TelemetryAudit { .. }
        | SupervisorCommand::NodeAgentRuntime { .. }
        | SupervisorCommand::NodeRuntimeSummary { .. }
        | SupervisorCommand::EnqueueMaterial(_)
        | SupervisorCommand::ReconcileMaterial(_)
        | SupervisorCommand::GetMaterialState(_)
        | SupervisorCommand::AuthorityCeremonyPreflight(_)
        | SupervisorCommand::AuthorityCeremonyExportRecovery { .. }
        | SupervisorCommand::AuthorityCeremonyActivate { .. } => 120,
        _ => 30,
    }
}

pub fn load_ipc_key(path: &Path) -> Result<Vec<u8>, String> {
    let key = fs::read(path)
        .map_err(|error| format!("No se pudo leer la clave IPC {}: {error}", path.display()))?;
    let key = key
        .into_iter()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if key.len() < 32 {
        return Err("La clave IPC debe contener al menos 32 bytes aleatorios.".to_string());
    }
    Ok(key)
}

pub fn read_framed_json<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, String> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| format!("No se pudo leer el frame IPC: {error}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_IPC_FRAME_BYTES {
        return Err(format!("Tamano de frame IPC rechazado: {length}."));
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|error| format!("Frame IPC incompleto: {error}"))?;
    serde_json::from_slice(&body).map_err(|error| format!("JSON IPC invalido: {error}"))
}

pub fn write_framed_json(writer: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    let body = serde_json::to_vec(value)
        .map_err(|error| format!("No se pudo serializar el frame IPC: {error}"))?;
    if body.is_empty() || body.len() > MAX_IPC_FRAME_BYTES {
        return Err(format!("Tamano de frame IPC rechazado: {}.", body.len()));
    }
    writer
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(&body))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("No se pudo enviar el frame IPC: {error}"))
}

pub fn unix_timestamp() -> u64 {
    now()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn sign(bytes: &[u8], key: &[u8]) -> Result<String, String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| "La clave HMAC no es valida.".to_string())?;
    mac.update(bytes);
    Ok(hex(&mac.finalize().into_bytes()))
}

fn verify_signature(bytes: &[u8], signature: &str, key: &[u8]) -> Result<(), String> {
    let signature = decode_hex(signature)?;
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| "La clave HMAC no es valida.".to_string())?;
    mac.update(bytes);
    mac.verify_slice(&signature)
        .map_err(|_| "Autenticacion IPC invalida.".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupervisorCompatibility {
    pub compatible: bool,
    pub observed_protocol: Option<u16>,
    pub required_protocol: u16,
    pub observed_version: Option<String>,
    pub recovered_operations: usize,
    pub required_features: Vec<String>,
    pub observed_features: Vec<String>,
    pub reason: String,
}

pub fn evaluate_supervisor_compatibility(
    ping: Result<&SupervisorReply, &str>,
) -> SupervisorCompatibility {
    let required_features = REQUIRED_MANAGER_FEATURES
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    match ping {
        Ok(SupervisorReply::Pong {
            supervisor_version,
            recovered_operations,
            protocol_version,
            features,
            ..
        }) => {
            let missing = required_features
                .iter()
                .filter(|feature| !features.iter().any(|observed| observed == *feature))
                .cloned()
                .collect::<Vec<_>>();
            let compatible = *protocol_version == IPC_PROTOCOL_VERSION && missing.is_empty();
            SupervisorCompatibility {
                compatible,
                observed_protocol: Some(*protocol_version),
                required_protocol: IPC_PROTOCOL_VERSION,
                observed_version: Some(supervisor_version.clone()),
                recovered_operations: *recovered_operations,
                required_features: required_features.clone(),
                observed_features: features.clone(),
                reason: if compatible {
                    "Supervisor compatible".to_string()
                } else if *protocol_version != IPC_PROTOCOL_VERSION {
                    format!(
                        "Protocolo observado {protocol_version}, requerido {IPC_PROTOCOL_VERSION}."
                    )
                } else {
                    format!("Faltan features IPC: {}.", missing.join(", "))
                },
            }
        }
        Ok(_) => SupervisorCompatibility {
            compatible: false,
            observed_protocol: None,
            required_protocol: IPC_PROTOCOL_VERSION,
            observed_version: None,
            recovered_operations: 0,
            required_features,
            observed_features: Vec::new(),
            reason: "Supervisor disponible no es sinonimo de compatible; el ping no devolvio Pong."
                .to_string(),
        },
        Err(error) => SupervisorCompatibility {
            compatible: false,
            observed_protocol: None,
            required_protocol: IPC_PROTOCOL_VERSION,
            observed_version: None,
            recovered_operations: 0,
            required_features,
            observed_features: Vec::new(),
            reason: error.to_string(),
        },
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("Firma IPC hexadecimal invalida.".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "Firma IPC hexadecimal invalida.".to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_supervisor_compatibility, SupervisorCommand, SupervisorReply,
        SupervisorRequestEnvelope, IPC_FEATURES, IPC_PROTOCOL_VERSION, SUPERVISOR_VERSION,
    };

    #[test]
    fn firma_detecta_alteracion_y_replay_tardio() {
        let key = b"0123456789abcdef0123456789abcdef";
        let mut request = SupervisorRequestEnvelope::signed(SupervisorCommand::Ping, key).unwrap();
        request.verify(key, request.issued_at_unix_seconds).unwrap();
        request.nonce.push('x');
        assert!(request.verify(key, request.issued_at_unix_seconds).is_err());

        let request = SupervisorRequestEnvelope::signed(SupervisorCommand::Ping, key).unwrap();
        assert!(request
            .verify(key, request.issued_at_unix_seconds + 61)
            .is_err());
    }

    #[test]
    fn supervisor_viejo_sin_resume_queda_bloqueado() {
        let legacy = evaluate_supervisor_compatibility(Err(
            "Version IPC incompatible: recibida=3, soportada=2.",
        ));
        assert!(!legacy.compatible);
        assert!(legacy.reason.contains("incompatible"));

        let available_but_mute =
            evaluate_supervisor_compatibility(Ok(&SupervisorReply::Json { value: "{}".into() }));
        assert!(!available_but_mute.compatible);
        assert!(available_but_mute.reason.contains("no es sinonimo"));

        let current = evaluate_supervisor_compatibility(Ok(&SupervisorReply::Pong {
            supervisor_version: SUPERVISOR_VERSION.into(),
            recovered_operations: 0,
            protocol_version: IPC_PROTOCOL_VERSION,
            features: IPC_FEATURES
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            source_commit: None,
            build_id: None,
            binary_sha256: None,
        }));
        assert!(current.compatible);

        let lab21 = evaluate_supervisor_compatibility(Ok(&SupervisorReply::Pong {
            supervisor_version: "0.5.9".into(),
            recovered_operations: 0,
            protocol_version: IPC_PROTOCOL_VERSION,
            features: vec![
                "resume_incomplete".into(),
                "capability_scoped_config".into(),
            ],
            source_commit: None,
            build_id: None,
            binary_sha256: None,
        }));
        assert!(!lab21.compatible);
        assert!(
            lab21.reason.contains("host_identity_v1"),
            "{}",
            lab21.reason
        );

        let proto2 = evaluate_supervisor_compatibility(Ok(&SupervisorReply::Pong {
            supervisor_version: "0.5.7".into(),
            recovered_operations: 0,
            protocol_version: 2,
            features: vec!["resume_incomplete".into()],
            source_commit: None,
            build_id: None,
            binary_sha256: None,
        }));
        assert!(!proto2.compatible);
        assert!(proto2.reason.contains("Protocolo observado 2"));

        let missing_feature = evaluate_supervisor_compatibility(Ok(&SupervisorReply::Pong {
            supervisor_version: "0.5.9".into(),
            recovered_operations: 0,
            protocol_version: IPC_PROTOCOL_VERSION,
            features: Vec::new(),
            source_commit: None,
            build_id: None,
            binary_sha256: None,
        }));
        assert!(!missing_feature.compatible);
        assert!(missing_feature.reason.contains("Faltan features"));
    }

    #[test]
    fn pong_viejo_sin_features_no_deserializa() {
        let legacy =
            r#"{"type":"pong","payload":{"supervisor_version":"0.5.7","recovered_operations":0}}"#;
        let parsed = serde_json::from_str::<SupervisorReply>(legacy);
        assert!(parsed.is_err(), "un Pong 0.5.7 no puede parecer compatible");
    }

    #[test]
    fn resume_incomplete_es_campo_obligatorio() {
        let json = r#"{"installDir":"/tmp/n","expectedRelease":"x","nodeEnv":"","marker":"{}","terminalPublicKey":"k","operatorPublicKey":"k","enrollmentToken":"t","prepareOnly":false}"#;
        let parsed = serde_json::from_str::<super::CommissionNodeRequest>(json);
        assert!(
            parsed.is_err(),
            "sin resumeIncomplete no puede degenerar a fresh"
        );
    }

    #[test]
    fn enqueue_material_rejects_caller_scope_fields() {
        let json = r#"{"installDir":"/n","capability":"people","packageDir":"inbox/p","organizationId":"org-1"}"#;
        let parsed = serde_json::from_str::<super::EnqueueMaterialRequest>(json);
        assert!(parsed.is_err(), "IPC must not accept organizationId");
        let json =
            r#"{"installDir":"/n","capability":"people","packageDir":"inbox/p","siteId":"s"}"#;
        assert!(serde_json::from_str::<super::EnqueueMaterialRequest>(json).is_err());
        let json = r#"{"installDir":"/n","capability":"people","packageDir":"inbox/p","deploymentId":"d"}"#;
        assert!(serde_json::from_str::<super::EnqueueMaterialRequest>(json).is_err());
        let json =
            r#"{"installDir":"/n","capability":"people","packageDir":"inbox/p","nodeId":"n"}"#;
        assert!(serde_json::from_str::<super::EnqueueMaterialRequest>(json).is_err());
        let ok = r#"{"installDir":"/n","capability":"people","packageDir":"inbox/p"}"#;
        serde_json::from_str::<super::EnqueueMaterialRequest>(ok).unwrap();
    }

    #[test]
    fn manager_does_not_require_material_plane_feature() {
        let without_material = evaluate_supervisor_compatibility(Ok(&SupervisorReply::Pong {
            supervisor_version: SUPERVISOR_VERSION.into(),
            recovered_operations: 0,
            protocol_version: IPC_PROTOCOL_VERSION,
            features: vec![
                "resume_incomplete".into(),
                "capability_scoped_config".into(),
                "host_identity_v1".into(),
                "cancel_preparation".into(),
            ],
            source_commit: None,
            build_id: None,
            binary_sha256: None,
        }));
        assert!(
            without_material.compatible,
            "legacy Manager Ping must remain compatible: {}",
            without_material.reason
        );
        assert!(IPC_FEATURES.contains(&"material_plane_v1"));
        assert!(!super::REQUIRED_MANAGER_FEATURES.contains(&"material_plane_v1"));
    }
}
