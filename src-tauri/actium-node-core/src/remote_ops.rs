//! Remote Operations Foundation & Zero-SSH Execution Fabric V1
//!
//! Handles cryptographic verification of incoming Center connectivity jobs,
//! scope/TTL/anti-replay validation, typed execution with Health Gates,
//! LKG rollback, and durable receipt signing.

use crate::{
    canonical_json,
    authority::EnrolledAuthority,
    connectivity_fabric::{ConnectivityResolution, ConnectivityRouteState, ServiceRoute},
    AttestationSigner,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    fs::OpenOptions,
    io::Write,
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const CONNECTIVITY_JOB_SCHEMA: &str = "actium.connectivity.job.v1";
pub const JOB_RECEIPT_SCHEMA: &str = "actium.connectivity.receipt.v1";
pub const REMOTE_OPS_SERVICE_ID: &str = "actium-center";
pub const REMOTE_OPS_CAPABILITY: &str = "remote_operations";
pub const REMOTE_OPS_AUTHORITY_SCOPE: &str = "remote_operations:connectivity_job";
pub const REMOTE_OPS_ADAPTER_ACTIUM_CENTER_LOCAL: &str = "actium_center_local";
pub const REMOTE_OPS_ADAPTER_SUPABASE_HOSTED: &str = "supabase_hosted";
pub const REMOTE_OPS_ADAPTER_RELAY_CENTER: &str = "relay_center";
pub const REMOTE_OPS_ADAPTER_LEGACY_HTTPS_HOSTED: &str = "https_hosted_adapter";
pub const REMOTE_OPS_ADAPTER_RESOLUTION_LEGACY_COMPAT: &str = "LEGACY_COMPAT";
pub const HOST_MANAGEMENT_REQUEST_SCHEMA: &str = "actium.connectivity.management.request.v1";
pub const HOST_MANAGEMENT_SIGNATURE_ALGORITHM: &str = "Ed25519";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostManagementAction {
    PollJobs,
    ClaimJob,
    SubmitReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostManagementRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub action: HostManagementAction,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub binding_epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub nonce: String,
    pub body_digest: String,
    pub supervisor_key_id: String,
    pub signature_alg: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectivityJobOperation {
    RestartConnector,
    RepairConnectivity,
    ApplyConnectivityPolicy,
    TriggerDiagnostics,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobReceiptOutcome {
    Pending,
    Accepted,
    Running,
    Succeeded,
    Failed,
    RolledBack,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BreakGlassClaims {
    pub aal_level: String,
    pub authorizing_operator: String,
    pub justification: String,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityJobV1 {
    pub schema: String,
    pub job_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub operation: ConnectivityJobOperation,
    pub desired_generation: u64,
    #[serde(default)]
    pub payload: serde_json::Value,
    pub issued_at: String,
    pub expires_at: String,
    pub authority_key_id: String,
    pub signature_alg: String,
    pub signature: String,
    #[serde(default)]
    pub break_glass: Option<BreakGlassClaims>,
    /// Proof metadata emitted by the existing Authority Fabric.  It is not a
    /// new key or ceremony: the Supervisor checks it against the enrolled
    /// Center authority before accepting the job.
    #[serde(default)]
    pub authority_proof: Option<RemoteOpsAuthorityProofV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteOpsAuthorityProofV1 {
    pub trust_root_set: String,
    pub trust_bundle_id: String,
    pub trust_bundle_digest: String,
    pub authority_id: String,
    pub authority_key_id: String,
    pub capability: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub operation: ConnectivityJobOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct HealthGateResult {
    pub passed: bool,
    pub service_active: Option<bool>,
    pub health_endpoint_ready: Option<bool>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JobReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub job_id: String,
    pub site_id: String,
    pub host_id: String,
    pub operation: ConnectivityJobOperation,
    pub outcome: JobReceiptOutcome,
    pub started_at: String,
    pub completed_at: String,
    pub before_state: serde_json::Value,
    pub after_state: serde_json::Value,
    pub health_gate: HealthGateResult,
    pub error_code: Option<String>,
    pub details: serde_json::Value,
    pub host_identity: String,
    pub host_signature: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectWanAttestationV1 {
    pub schema: String,
    pub attestation_id: String,
    pub site_id: String,
    pub host_id: String,
    pub hostname: String,
    pub observed_ipv4: Option<String>,
    pub observed_ipv6: Option<String>,
    pub target_port: u16,
    pub tls_state: String,
    pub certificate_fingerprint: Option<String>,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub checked_at: String,
    pub expires_at: String,
    pub probe_identity: String,
    pub signature: String,
    #[serde(default)]
    pub dns_status: String,
    #[serde(default)]
    pub resolved_addresses: Vec<String>,
    #[serde(default)]
    pub tcp443_status: String,
    #[serde(default)]
    pub certificate_identity: Option<String>,
    #[serde(default)]
    pub site_identity_status: String,
    #[serde(default)]
    pub outside_in_status: String,
    #[serde(default)]
    pub probe_caller_ip: Option<String>,
    #[serde(default)]
    pub site_public_ingress_ip: Option<String>,
    #[serde(default)]
    pub ingress_gateway_status: String,
    #[serde(default)]
    pub direct_wan_status: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteType {
    SiteDirectLan,
    SiteDirectWanIpv4,
    SiteDirectWanIpv6,
    ActiumRelay,
    FederatedActiumNode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteCandidate {
    pub route_id: String,
    #[serde(rename = "type")]
    pub route_type: RouteType,
    pub endpoint: String,
    pub priority: u32,
    pub cost: u32,
    pub health: String,
    pub latency_ms: Option<u64>,
    pub failure_count: u32,
    pub generation: u64,
    pub expires_at: String,
    pub authority: String,
    pub attestation: Option<String>,
    #[serde(default)]
    pub trust: String,
    #[serde(default)]
    pub network_cost: u32,
    #[serde(default)]
    pub metered: bool,
    #[serde(default)]
    pub last_success: Option<String>,
    #[serde(default)]
    pub success_count: u32,
    #[serde(default)]
    pub relay_id: Option<String>,
    #[serde(default)]
    pub site_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteDecisionReceipt {
    pub decision_id: String,
    pub terminal_id: String,
    pub site_id: String,
    pub previous_route: Option<String>,
    pub selected_route: String,
    pub reason: String,
    pub failure_evidence: Option<serde_json::Value>,
    pub selected_at: String,
    pub policy_generation: u64,
    #[serde(default)]
    pub candidate_snapshot_digest: Option<String>,
}

/// Durable ledger to prevent replay attacks and store idempotent receipts
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RemoteOpsLedger {
    pub executed_jobs: HashMap<String, JobReceiptV1>,
}

impl RemoteOpsLedger {
    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::read_to_string(path) {
            Ok(content) => serde_json::from_str::<Self>(&content)
                .map_err(|_| "REMOTE_OPS_LEDGER_INVALID".to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err("REMOTE_OPS_LEDGER_READ_FAILED".to_string()),
        }
    }

    pub fn load_or_create(path: &Path) -> Self {
        Self::load(path).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("LEDGER_SERIALIZE_ERROR: {e}"))?;
        let temporary = path.with_extension("json.tmp");
        let mut file = fs::File::create(&temporary)
            .map_err(|e| format!("LEDGER_WRITE_ERROR: {e}"))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("LEDGER_WRITE_ERROR: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("LEDGER_SYNC_ERROR: {e}"))?;
        fs::rename(&temporary, path).map_err(|e| format!("LEDGER_COMMIT_ERROR: {e}"))
    }

    pub fn is_consumed(&self, job_id: &str) -> Option<&JobReceiptV1> {
        self.executed_jobs.get(job_id)
    }

    pub fn record_receipt(&mut self, receipt: JobReceiptV1, path: &Path) -> Result<(), String> {
        self.executed_jobs.insert(receipt.job_id.clone(), receipt);
        self.save(path)
    }
}

/// Provider-neutral transport contract.  The domain deals in jobs/receipts;
/// it does not know whether the selected adapter is Center Local, hosted
/// Supabase, or a future Relay transport.
pub trait RemoteOpsTransport: Send + Sync {
    fn descriptor(&self) -> &RemoteOpsTransportDescriptor;
    fn poll_jobs(&self, host_id: &str) -> Result<Vec<ConnectivityJobV1>, String>;
    /// Claims an accepted job as RUNNING. Unsupported or unauthenticated
    /// endpoints fail closed; there is no silent lifecycle downgrade.
    fn claim_job(&self, job_id: &str, host_id: &str) -> Result<bool, String>;
    fn submit_receipt(&self, receipt: &JobReceiptV1) -> Result<(), String>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteOpsTransportDescriptor {
    pub service_id: String,
    pub capability: String,
    pub endpoint: String,
    pub adapter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_resolution: Option<String>,
    pub resolution_source: String,
    pub expected_service_identity: String,
    pub authority_scope: String,
    pub binding_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct HttpRemoteOpsTransport {
    descriptor: RemoteOpsTransportDescriptor,
    host_binding: Option<RemoteOpsHostBinding>,
    signer: Option<AttestationSigner>,
}

#[derive(Debug, Clone)]
struct RemoteOpsHostBinding {
    organization_id: String,
    site_id: String,
    host_id: String,
    binding_epoch: u64,
}

impl HttpRemoteOpsTransport {
    pub fn from_route(route: ServiceRoute, resolution_source: impl Into<String>) -> Result<Self, String> {
        if route.service_id != REMOTE_OPS_SERVICE_ID
            || route.capability != REMOTE_OPS_CAPABILITY
            || !matches!(route.state, ConnectivityRouteState::Reachable)
            || route.endpoint.trim().is_empty()
        {
            return Err("REMOTE_OPS_TRANSPORT_ROUTE_INELIGIBLE".to_string());
        }
        let raw_adapter = route.adapter.as_deref().map(str::trim).filter(|value| !value.is_empty());
        let (adapter, adapter_resolution) = match raw_adapter {
            Some(REMOTE_OPS_ADAPTER_ACTIUM_CENTER_LOCAL) => (REMOTE_OPS_ADAPTER_ACTIUM_CENTER_LOCAL, None),
            Some(REMOTE_OPS_ADAPTER_SUPABASE_HOSTED) => (REMOTE_OPS_ADAPTER_SUPABASE_HOSTED, None),
            Some(REMOTE_OPS_ADAPTER_RELAY_CENTER) => (REMOTE_OPS_ADAPTER_RELAY_CENTER, None),
            Some(REMOTE_OPS_ADAPTER_LEGACY_HTTPS_HOSTED) => (
                REMOTE_OPS_ADAPTER_SUPABASE_HOSTED,
                Some(REMOTE_OPS_ADAPTER_RESOLUTION_LEGACY_COMPAT.to_string()),
            ),
            Some(_) | None => return Err("REMOTE_OPS_TRANSPORT_ADAPTER_UNRESOLVED".to_string()),
        };
        Ok(Self {
            descriptor: RemoteOpsTransportDescriptor {
                service_id: route.service_id,
                capability: route.capability,
                endpoint: route.endpoint,
                adapter: adapter.to_string(),
                adapter_resolution,
                resolution_source: resolution_source.into(),
                expected_service_identity: route.expected_service_identity,
                authority_scope: route.authority_scope,
                binding_epoch: route.binding_epoch,
            },
            host_binding: None,
            signer: None,
        })
    }

    /// Binds the transport to the already-enrolled Supervisor identity.  The
    /// transport never creates or imports a new authority key.  Legacy
    /// EnrollmentPackages may expose the same Supervisor key as
    /// `node_public_key`; that compatibility path is still required to match
    /// the persisted signer byte-for-byte.
    pub fn with_enrolled_identity(
        mut self,
        enrolled: &EnrolledAuthority,
        signer: &AttestationSigner,
    ) -> Result<Self, String> {
        let host_id = enrolled
            .enrollment
            .host_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "HOST_MANAGEMENT_HOST_ID_MISSING".to_string())?;
        let site_id = enrolled
            .enrollment
            .site_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| "HOST_MANAGEMENT_SITE_ID_MISSING".to_string())?;
        let enrolled_public_key = enrolled
            .enrollment
            .supervisor_public_key
            .as_deref()
            .unwrap_or(&enrolled.enrollment.node_public_key);
        if enrolled_public_key != signer.public_key() {
            return Err("HOST_MANAGEMENT_SUPERVISOR_KEY_MISMATCH".to_string());
        }
        self.descriptor.binding_epoch = enrolled.enrollment.binding_epoch;
        self.host_binding = Some(RemoteOpsHostBinding {
            organization_id: enrolled.enrollment.organization_id.clone(),
            site_id: site_id.to_string(),
            host_id: host_id.to_string(),
            binding_epoch: enrolled.enrollment.binding_epoch,
        });
        self.signer = Some(signer.clone());
        Ok(self)
    }
}

impl RemoteOpsTransport for HttpRemoteOpsTransport {
    fn descriptor(&self) -> &RemoteOpsTransportDescriptor {
        &self.descriptor
    }

    fn poll_jobs(&self, host_id: &str) -> Result<Vec<ConnectivityJobV1>, String> {
        let binding = self.host_binding.as_ref().ok_or_else(|| "HOST_MANAGEMENT_BINDING_UNAVAILABLE".to_string())?;
        if binding.host_id != host_id {
            return Err("HOST_MANAGEMENT_HOST_SCOPE_INVALID".to_string());
        }
        let signer = self.signer.as_ref().ok_or_else(|| "HOST_MANAGEMENT_SIGNER_UNAVAILABLE".to_string())?;
        poll_remote_jobs_http_authenticated(&self.descriptor.endpoint, binding, signer)
    }

    fn claim_job(&self, job_id: &str, host_id: &str) -> Result<bool, String> {
        let binding = self.host_binding.as_ref().ok_or_else(|| "HOST_MANAGEMENT_BINDING_UNAVAILABLE".to_string())?;
        if binding.host_id != host_id {
            return Err("HOST_MANAGEMENT_HOST_SCOPE_INVALID".to_string());
        }
        let signer = self.signer.as_ref().ok_or_else(|| "HOST_MANAGEMENT_SIGNER_UNAVAILABLE".to_string())?;
        claim_remote_job_http_authenticated(&self.descriptor.endpoint, job_id, binding, signer)
    }

    fn submit_receipt(&self, receipt: &JobReceiptV1) -> Result<(), String> {
        let binding = self.host_binding.as_ref().ok_or_else(|| "HOST_MANAGEMENT_BINDING_UNAVAILABLE".to_string())?;
        let signer = self.signer.as_ref().ok_or_else(|| "HOST_MANAGEMENT_SIGNER_UNAVAILABLE".to_string())?;
        submit_job_receipt_http_authenticated(&self.descriptor.endpoint, receipt, binding, signer)
    }
}

pub fn remote_ops_transport_from_resolution(
    resolution: &ConnectivityResolution,
    resolution_source: impl Into<String>,
) -> Result<HttpRemoteOpsTransport, String> {
    let route = resolution
        .preferred_route
        .as_ref()
        .filter(|candidate| candidate.service_id == REMOTE_OPS_SERVICE_ID && candidate.capability == REMOTE_OPS_CAPABILITY)
        .cloned()
        .or_else(|| {
            resolution
                .candidates
                .iter()
                .find(|candidate| {
                    candidate.service_id == REMOTE_OPS_SERVICE_ID
                        && candidate.capability == REMOTE_OPS_CAPABILITY
                        && matches!(candidate.state, ConnectivityRouteState::Reachable)
                })
                .cloned()
        })
        .ok_or_else(|| "REMOTE_OPS_TRANSPORT_UNRESOLVED".to_string())?;
    HttpRemoteOpsTransport::from_route(route, resolution_source)
}

/// Durable store boundary used by the execution domain.  Center adapters
/// implement the same shape on their side; this implementation is the local
/// anti-replay ledger only.
pub trait RemoteOpsStore {
    fn durable_job_count(&self) -> usize;
    fn last_receipt(&self) -> Option<JobReceiptV1>;
    fn record_receipt(&mut self, receipt: JobReceiptV1, path: &Path) -> Result<(), String>;
}

impl RemoteOpsStore for RemoteOpsLedger {
    fn durable_job_count(&self) -> usize { self.executed_jobs.len() }
    fn last_receipt(&self) -> Option<JobReceiptV1> {
        self.executed_jobs.values().max_by_key(|receipt| receipt.completed_at.clone()).cloned()
    }
    fn record_receipt(&mut self, receipt: JobReceiptV1, path: &Path) -> Result<(), String> {
        RemoteOpsLedger::record_receipt(self, receipt, path)
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Verifies a ConnectivityJobV1 against the enrolled authority, checking:
/// 1. Schema
/// 2. Scope (siteId, hostId, organizationId)
/// 3. Expiration / TTL
/// 4. Cryptographic Ed25519 signature
pub fn verify_connectivity_job(
    job: &ConnectivityJobV1,
    enrolled: Option<&EnrolledAuthority>,
) -> Result<(), String> {
    if job.schema != CONNECTIVITY_JOB_SCHEMA {
        return Err("JOB_SCHEMA_INVALID".to_string());
    }

    if job.signature_alg != "Ed25519" || job.signature.trim().is_empty() {
        return Err("JOB_SIGNATURE_ALGORITHM_INVALID".to_string());
    }

    // 1. Check expiration. Invalid timestamps are rejected, never treated as
    // a convenient future value.
    let issued_timestamp = parse_iso_or_unix(&job.issued_at)
        .map_err(|_| "JOB_ISSUED_AT_INVALID".to_string())?;
    let now = unix_timestamp();
    if issued_timestamp > now.saturating_add(60) {
        return Err("JOB_ISSUED_AT_IN_FUTURE".to_string());
    }
    let expires_timestamp = parse_iso_or_unix(&job.expires_at)
        .map_err(|_| "JOB_EXPIRY_INVALID".to_string())?;
    if expires_timestamp <= now || expires_timestamp <= issued_timestamp || expires_timestamp > issued_timestamp.saturating_add(3_600) {
        return Err("JOB_EXPIRED".to_string());
    }

    // 2. Scope verification
    let auth = enrolled.ok_or_else(|| "ENROLLMENT_REQUIRED".to_string())?;
    {
        if let Some(expected_site) = auth.enrollment.site_id.as_deref() {
            if !expected_site.is_empty() && job.site_id != expected_site {
                return Err("JOB_SITE_SCOPE_INVALID".to_string());
            }
        }
        if let Some(expected_host) = auth.enrollment.host_id.as_deref() {
            if !expected_host.is_empty() && job.host_id != expected_host {
                return Err("JOB_HOST_SCOPE_INVALID".to_string());
            }
        }
        if job.organization_id != auth.enrollment.organization_id {
            return Err("JOB_ORG_SCOPE_INVALID".to_string());
        }

        if job.authority_key_id != auth.center.kid {
            return Err("JOB_AUTHORITY_KEY_ID_MISMATCH".to_string());
        }
        let proof = job.authority_proof.as_ref().ok_or_else(|| "JOB_AUTHORITY_PROOF_MISSING".to_string())?;
        if proof.authority_id != auth.center.issuer_id
            || proof.authority_key_id != auth.center.kid
            || proof.organization_id != job.organization_id
            || proof.site_id != job.site_id
            || proof.host_id != job.host_id
            || proof.operation != job.operation
            || proof.capability != "remote_operations_signing"
            || proof.trust_root_set.trim().is_empty()
            || proof.trust_bundle_id.trim().is_empty()
            || proof.trust_bundle_digest.trim().is_empty()
            || auth.center.trust_bundle_digest.as_deref().is_some_and(|digest| digest != proof.trust_bundle_digest)
        {
            return Err("JOB_AUTHORITY_PROOF_SCOPE_INVALID".to_string());
        }

        // 3. Signature verification with the enrolled Center public key.
        // The enrollment was admitted by the existing Trust Fabric chain;
        // the job proof binds that admitted authority to this exact scope.
        let center_pk = &auth.center.center_public_key;
        if center_pk.trim().is_empty() {
            return Err("AUTHORITY_KEY_MISSING".to_string());
        }
        let vk_bytes = URL_SAFE_NO_PAD
            .decode(center_pk)
            .map_err(|_| "AUTHORITY_KEY_INVALID")?;
        let vk_array: [u8; 32] = vk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "AUTHORITY_KEY_INVALID")?;
        let vk = VerifyingKey::from_bytes(&vk_array).map_err(|_| "AUTHORITY_KEY_INVALID")?;

        // Canonicalize unsigned payload
        let mut unsigned = serde_json::json!({
            "schema": job.schema,
            "jobId": job.job_id,
            "organizationId": job.organization_id,
            "siteId": job.site_id,
            "hostId": job.host_id,
            "operation": job.operation,
            "desiredGeneration": job.desired_generation,
            "payload": job.payload,
            "issuedAt": job.issued_at,
            "expiresAt": job.expires_at,
            "authorityKeyId": job.authority_key_id,
            "signatureAlg": job.signature_alg,
        });
        if let Some(break_glass) = &job.break_glass {
            unsigned.as_object_mut().unwrap().insert("breakGlass".to_string(), serde_json::to_value(break_glass).map_err(|_| "JOB_PAYLOAD_INVALID")?);
        }
        unsigned.as_object_mut().unwrap().insert("authorityProof".to_string(), serde_json::to_value(proof).map_err(|_| "JOB_AUTHORITY_PROOF_INVALID")?);

        let canonical_str = canonical_json(&unsigned)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(&job.signature)
            .map_err(|_| "JOB_SIGNATURE_DECODE_FAILED")?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "JOB_SIGNATURE_LENGTH_INVALID")?;
        let sig = Signature::from_bytes(&sig_array);

        vk.verify(canonical_str.as_bytes(), &sig)
            .map_err(|_| "JOB_SIGNATURE_VERIFICATION_FAILED")?;
    }

    Ok(())
}

fn parse_iso_or_unix(s: &str) -> Result<u64, ()> {
    if let Ok(ts) = s.parse::<u64>() {
        return Ok(ts);
    }
    let (date, time) = s.strip_suffix('Z').ok_or(())
        .and_then(|value| value.split_once('T').ok_or(()))?;
    let mut date_parts = date.split('-');
    let year = date_parts.next().ok_or(())?.parse::<i64>().map_err(|_| ())?;
    let month = date_parts.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
    let day = date_parts.next().ok_or(())?.parse::<u32>().map_err(|_| ())?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || day == 0 || day > 31 { return Err(()); }
    let (clock, fraction) = time.split_once('.').map_or((time, None), |(clock, fraction)| (clock, Some(fraction)));
    let mut clock_parts = clock.split(':');
    let hour = clock_parts.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
    let minute = clock_parts.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
    let second = clock_parts.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 || fraction.is_some_and(|value| value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())) { return Err(()); }
    let days = days_from_civil(year, month, day).ok_or(())?;
    Ok((days * 86_400) as u64 + hour * 3_600 + minute * 60 + second.min(59))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let month_i = month as i64;
    let day_i = day as i64;
    let adjusted_year = year - i64::from(month <= 2);
    let era = (if adjusted_year >= 0 { adjusted_year } else { adjusted_year - 399 }) / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_of_year = month_i + if month_i > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_of_year + 2) / 5 + day_i - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146097 + day_of_era - 719468)
}

/// Checks if :8086/health/ready is returning ready
fn check_connector_health() -> bool {
    let output = Command::new("curl")
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "http://127.0.0.1:8086/health/ready"])
        .output();
    if let Ok(out) = output {
        let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
        return code == "200";
    }
    false
}

fn validate_lab_safe_connectivity_policy(
    payload: &serde_json::Value,
    desired_generation: u64,
) -> Result<serde_json::Value, String> {
    let object = payload
        .as_object()
        .ok_or_else(|| "POLICY_R1_PAYLOAD_INVALID".to_string())?;
    const ALLOWED_KEYS: &[&str] = &[
        "mode",
        "preferredRegion",
        "redundancy",
        "localTarget",
        "policyGeneration",
        "updatedAtUnix",
    ];
    if object.keys().any(|key| !ALLOWED_KEYS.contains(&key.as_str())) {
        return Err("POLICY_R1_SCOPE_INVALID".to_string());
    }
    if object.get("mode").and_then(|value| value.as_str()) != Some("AUTO") {
        return Err("POLICY_R1_MODE_UNSUPPORTED".to_string());
    }
    let preferred_region = object
        .get("preferredRegion")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty() && value.len() <= 64)
        .ok_or_else(|| "POLICY_R1_REGION_INVALID".to_string())?;
    if !preferred_region.is_ascii() {
        return Err("POLICY_R1_REGION_INVALID".to_string());
    }
    let redundancy = object
        .get("redundancy")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| "POLICY_R1_REDUNDANCY_INVALID".to_string())?;
    if !(1..=2).contains(&redundancy) {
        return Err("POLICY_R1_REDUNDANCY_INVALID".to_string());
    }
    if object.get("localTarget").and_then(|value| value.as_str()) != Some("http://127.0.0.1:8090") {
        return Err("POLICY_R1_LOCAL_TARGET_INVALID".to_string());
    }
    if object.get("policyGeneration").and_then(|value| value.as_u64()) != Some(desired_generation) {
        return Err("POLICY_R1_GENERATION_MISMATCH".to_string());
    }
    if object.get("updatedAtUnix").is_some_and(|value| value.as_u64().is_none()) {
        return Err("POLICY_R1_TIMESTAMP_INVALID".to_string());
    }

    Ok(serde_json::Value::Object(object.clone()))
}

fn write_atomic_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "POLICY_ATOMIC_PARENT_INVALID".to_string())?;
    fs::create_dir_all(parent).map_err(|error| format!("POLICY_DIRECTORY_CREATE_FAILED: {error}"))?;
    let file_name = path.file_name().and_then(|value| value.to_str()).ok_or_else(|| "POLICY_ATOMIC_PATH_INVALID".to_string())?;
    let temporary = parent.join(format!(".{file_name}.r1-tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("POLICY_ATOMIC_TEMP_CREATE_FAILED: {error}"))?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(format!("POLICY_ATOMIC_WRITE_FAILED: {error}"));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("POLICY_ATOMIC_RENAME_FAILED: {error}"));
    }
    Ok(())
}

/// Executes a verified ConnectivityJob with strict Health Gate and LKG Rollback
pub fn execute_connectivity_job(
    job: &ConnectivityJobV1,
    signer: &AttestationSigner,
    ledger_path: &Path,
) -> Result<JobReceiptV1, String> {
    let mut ledger = RemoteOpsLedger::load(ledger_path)?;

    // 1. Anti-replay: return existing receipt if already consumed
    if let Some(existing) = ledger.is_consumed(&job.job_id) {
        return Ok(existing.clone());
    }

    let started_at = chrono_or_timestamp();

    // 2. Precheck and capture before_state
    let before_ready = check_connector_health();
    let before_state = serde_json::json!({
        "healthEndpointReady": before_ready,
        "checkedAt": started_at.clone(),
    });

    let mut outcome = JobReceiptOutcome::Running;
    let mut health_gate = HealthGateResult::default();
    let mut error_code = None;
    let mut details = serde_json::json!({});

    match job.operation {
        ConnectivityJobOperation::RestartConnector => {
            // Apply: restart systemd service
            #[cfg(target_os = "linux")]
            let _cmd_res = Command::new("systemctl")
                .args(["restart", "actium-connectivity-connector.service"])
                .output();

            #[cfg(not(target_os = "linux"))]
            let _cmd_res: Result<(), String> = Ok(());

            // Verify: poll health gate up to 10 seconds
            let verify_start = Instant::now();
            let mut ready = false;
            while verify_start.elapsed() < Duration::from_secs(10) {
                if check_connector_health() {
                    ready = true;
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }

            health_gate.passed = ready;
            health_gate.service_active = Some(ready);
            health_gate.health_endpoint_ready = Some(ready);

            if ready {
                outcome = JobReceiptOutcome::Succeeded;
                details = serde_json::json!({
                    "action": "restart_completed",
                    "verifyElapsedMs": verify_start.elapsed().as_millis(),
                });
            } else {
                outcome = JobReceiptOutcome::Failed;
                error_code = Some("HEALTH_GATE_FAILED".to_string());
                health_gate.details = Some("Connector failed to return HTTP 200 on :8086 within 10s".to_string());
            }
        }

        ConnectivityJobOperation::ApplyConnectivityPolicy => {
            let policy_path = Path::new("/etc/actium/connectivity/policy.json");
            let lkg_path = Path::new("/etc/actium/connectivity/policy.json.lkg");

            let policy = match validate_lab_safe_connectivity_policy(&job.payload, job.desired_generation) {
                Ok(policy) => policy,
                Err(error) => {
                    outcome = JobReceiptOutcome::Failed;
                    error_code = Some(error);
                    health_gate.passed = false;
                    health_gate.details = Some("R1 accepts only the neutral LAB connectivity policy; no WAN, Relay, DNS, TLS, or router fields are permitted".to_string());
                    serde_json::Value::Null
                }
            };

            if policy.is_null() {
                // Validation failed before any filesystem or service mutation.
            } else {
                // Snapshot LKG only after the typed policy has passed.
                if policy_path.exists() {
                    let _ = fs::copy(policy_path, lkg_path);
                }

                let serialized = serde_json::to_vec_pretty(&policy).map_err(|_| "POLICY_SERIALIZE_FAILED").unwrap_or_default();
                let write_res = write_atomic_file(policy_path, &serialized);
                if let Err(_e) = write_res {
                    outcome = JobReceiptOutcome::Failed;
                    error_code = Some("POLICY_WRITE_FAILED".to_string());
                    health_gate.passed = false;
                } else {
                    // Restart and verify
                    let _ = Command::new("systemctl")
                        .args(["restart", "actium-connectivity-connector.service"])
                        .output();

                    let mut ready = false;
                    let start = Instant::now();
                    while start.elapsed() < Duration::from_secs(8) {
                        if check_connector_health() {
                            ready = true;
                            break;
                        }
                        thread::sleep(Duration::from_millis(500));
                    }

                    if ready {
                        outcome = JobReceiptOutcome::Succeeded;
                        health_gate.passed = true;
                        health_gate.health_endpoint_ready = Some(true);
                    } else {
                        // ROLLBACK to LKG!
                        if lkg_path.exists() {
                            if let Ok(previous) = fs::read(lkg_path) {
                                let _ = write_atomic_file(policy_path, &previous);
                            }
                            let _ = Command::new("systemctl")
                                .args(["restart", "actium-connectivity-connector.service"])
                                .output();
                        }
                        outcome = JobReceiptOutcome::RolledBack;
                        error_code = Some("POLICY_HEALTH_GATE_FAILED_ROLLED_BACK".to_string());
                        health_gate.passed = false;
                    }
                }
            }
        }

        ConnectivityJobOperation::TriggerDiagnostics => {
            let connector_ready = check_connector_health();
            let supervisor_healthy = true;

            health_gate.passed = true;
            health_gate.service_active = Some(connector_ready);
            health_gate.health_endpoint_ready = Some(connector_ready);
            outcome = JobReceiptOutcome::Succeeded;

            details = serde_json::json!({
                "connectorReady": connector_ready,
                "supervisorHealthy": supervisor_healthy,
                "timestamp": unix_timestamp(),
            });
        }

        ConnectivityJobOperation::RepairConnectivity => {
            // Ensure directory exists and has root permissions
            let _ = fs::create_dir_all("/etc/actium/connectivity");
            let _ = Command::new("systemctl").args(["daemon-reload"]).output();
            let _ = Command::new("systemctl")
                .args(["restart", "actium-connectivity-connector.service"])
                .output();

            thread::sleep(Duration::from_secs(2));
            let ready = check_connector_health();
            health_gate.passed = ready;
            health_gate.service_active = Some(ready);
            health_gate.health_endpoint_ready = Some(ready);

            if ready {
                outcome = JobReceiptOutcome::Succeeded;
            } else {
                outcome = JobReceiptOutcome::Failed;
                error_code = Some("REPAIR_HEALTH_GATE_FAILED".to_string());
            }
        }
    }

    let completed_at = chrono_or_timestamp();
    let after_ready = check_connector_health();
    let after_state = serde_json::json!({
        "healthEndpointReady": after_ready,
        "completedAt": completed_at.clone(),
    });

    let receipt_id = Uuid::new_v4().to_string();

    let unsigned_receipt = JobReceiptV1 {
        schema: JOB_RECEIPT_SCHEMA.to_string(),
        receipt_id: receipt_id.clone(),
        job_id: job.job_id.clone(),
        site_id: job.site_id.clone(),
        host_id: job.host_id.clone(),
        operation: job.operation,
        outcome,
        started_at,
        completed_at,
        before_state,
        after_state,
        health_gate,
        error_code,
        details,
        host_identity: signer.key_id(),
        host_signature: String::new(),
        generation: job.desired_generation,
    };

    let signed_receipt = sign_job_receipt(unsigned_receipt, signer)?;

    // Commit to durable anti-replay ledger
    ledger.record_receipt(signed_receipt.clone(), ledger_path)?;

    Ok(signed_receipt)
}

pub fn sign_job_receipt(
    unsigned_receipt: JobReceiptV1,
    signer: &AttestationSigner,
) -> Result<JobReceiptV1, String> {
    let host_signature = signer
        .sign_serializable(&unsigned_receipt)
        .map_err(|_| "HOST_RECEIPT_SIGNATURE_FAILED".to_string())?;
    Ok(JobReceiptV1 {
        host_signature,
        ..unsigned_receipt
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteOpsStatusSnapshot {
    pub is_worker_running: bool,
    pub last_poll_at: Option<String>,
    pub last_poll_status: Option<String>,
    pub jobs_executed_count: usize,
    #[serde(default)]
    pub runtime_session_job_count: usize,
    #[serde(default)]
    pub durable_ledger_job_count: usize,
    pub last_job_id: Option<String>,
    pub last_receipt: Option<JobReceiptV1>,
    #[serde(default)]
    pub last_receipt_scope: Option<String>,
    pub center_url: Option<String>,
    pub host_id: Option<String>,
    pub site_id: Option<String>,
    #[serde(default)]
    pub transport: Option<RemoteOpsTransportDescriptor>,
}

fn management_body(action: HostManagementAction, value: serde_json::Value) -> serde_json::Value {
    match action {
        HostManagementAction::PollJobs => serde_json::json!({ "since": value.get("since").cloned().unwrap_or(serde_json::Value::Null) }),
        HostManagementAction::ClaimJob => serde_json::json!({ "jobId": value.get("jobId").and_then(|v| v.as_str()).unwrap_or_default() }),
        HostManagementAction::SubmitReceipt => serde_json::json!({ "receipt": value.get("receipt").cloned().unwrap_or(serde_json::Value::Null) }),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn signed_management_request(
    action: HostManagementAction,
    action_body: &serde_json::Value,
    binding: &RemoteOpsHostBinding,
    signer: &AttestationSigner,
) -> Result<HostManagementRequestV1, String> {
    let body = management_body(action, action_body.clone());
    let body_digest = hex_sha256(&Sha256::digest(canonical_json(&body)?.as_bytes()));
    let now = unix_timestamp();
    let mut request = HostManagementRequestV1 {
        schema: HOST_MANAGEMENT_REQUEST_SCHEMA.to_string(),
        request_id: Uuid::new_v4().to_string(),
        action,
        organization_id: binding.organization_id.clone(),
        site_id: binding.site_id.clone(),
        host_id: binding.host_id.clone(),
        binding_epoch: binding.binding_epoch,
        issued_at: format!("{now}Z"),
        expires_at: format!("{}Z", now.saturating_add(45)),
        nonce: Uuid::new_v4().to_string(),
        body_digest,
        supervisor_key_id: signer.key_id(),
        signature_alg: HOST_MANAGEMENT_SIGNATURE_ALGORITHM.to_string(),
        signature: String::new(),
    };
    let mut unsigned = serde_json::to_value(&request).map_err(|_| "HOST_MANAGEMENT_REQUEST_SERIALIZE_FAILED".to_string())?;
    unsigned.as_object_mut().unwrap().remove("signature");
    request.signature = signer.sign_canonical_value(&unsigned)?;
    Ok(request)
}

fn post_host_management_request(
    center_url: &str,
    action: HostManagementAction,
    action_body: serde_json::Value,
    binding: &RemoteOpsHostBinding,
    signer: &AttestationSigner,
) -> Result<serde_json::Value, String> {
    let request = signed_management_request(action, &action_body, binding, signer)?;
    let body = serde_json::json!({
        "action": match action {
            HostManagementAction::PollJobs => "poll_jobs",
            HostManagementAction::ClaimJob => "claim_job",
            HostManagementAction::SubmitReceipt => "submit_receipt",
        },
        "request": request,
        "body": management_body(action, action_body),
    });
    let body_str = serde_json::to_string(&body).map_err(|e| e.to_string())?;
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "10", "-X", "POST", center_url, "-H", "content-type: application/json", "-d", &body_str])
        .output()
        .map_err(|e| format!("CURL_EXEC_FAILED: {e}"))?;

    if !output.status.success() {
        return Err(format!("CURL_HTTP_FAILED: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let val: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("JSON_PARSE_FAILED: {e}"))?;

    if val.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err = val.get("error").and_then(|v| v.as_str()).unwrap_or("UNKNOWN_ERROR");
        return Err(format!("CENTER_HOST_MANAGEMENT_REJECTED: {err}"));
    }
    Ok(val)
}

fn poll_remote_jobs_http_authenticated(
    center_url: &str,
    binding: &RemoteOpsHostBinding,
    signer: &AttestationSigner,
) -> Result<Vec<ConnectivityJobV1>, String> {
    let val = post_host_management_request(
        center_url,
        HostManagementAction::PollJobs,
        serde_json::json!({ "since": serde_json::Value::Null }),
        binding,
        signer,
    )?;

    let jobs = val.get("jobs").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut result = Vec::new();
    for j in jobs {
        if let Ok(job) = serde_json::from_value::<ConnectivityJobV1>(j) {
            result.push(job);
        }
    }
    Ok(result)
}

/// Kept as a compatibility symbol for older callers, but deliberately refuses
/// to issue an unsigned management request.  The Supervisor transport uses
/// the authenticated variant above.
pub fn poll_remote_jobs_http(_center_url: &str, _host_id: &str) -> Result<Vec<ConnectivityJobV1>, String> {
    Err("HOST_MANAGEMENT_AUTH_REQUIRED".to_string())
}

/// Atomically claims an accepted job as RUNNING.  R1 does not silently fall
/// back to the pre-lifecycle endpoint: an unsupported action is a hard error.
fn claim_remote_job_http_authenticated(
    center_url: &str,
    job_id: &str,
    binding: &RemoteOpsHostBinding,
    signer: &AttestationSigner,
) -> Result<bool, String> {
    let val = post_host_management_request(
        center_url,
        HostManagementAction::ClaimJob,
        serde_json::json!({ "jobId": job_id }),
        binding,
        signer,
    )?;
    Ok(val.get("claimed").and_then(|v| v.as_bool()).unwrap_or(true))
}

pub fn claim_remote_job_http(_center_url: &str, _job_id: &str, _host_id: &str) -> Result<bool, String> {
    Err("HOST_MANAGEMENT_AUTH_REQUIRED".to_string())
}

fn submit_job_receipt_http_authenticated(
    center_url: &str,
    receipt: &JobReceiptV1,
    binding: &RemoteOpsHostBinding,
    signer: &AttestationSigner,
) -> Result<(), String> {
    post_host_management_request(
        center_url,
        HostManagementAction::SubmitReceipt,
        serde_json::json!({ "receipt": receipt }),
        binding,
        signer,
    )?;
    Ok(())
}

/// Compatibility symbol retained for older callers, but deliberately refuses
/// the former unsigned receipt endpoint.  All live transport paths must use
/// HostManagementRequestV1 with the enrolled Supervisor identity.
pub fn submit_job_receipt_http(_center_url: &str, _receipt: &JobReceiptV1) -> Result<(), String> {
    Err("HOST_MANAGEMENT_AUTH_REQUIRED".to_string())
}

fn chrono_or_timestamp() -> String {
    format!("{}Z", unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connectivity_job_serialization() {
        let job = ConnectivityJobV1 {
            schema: CONNECTIVITY_JOB_SCHEMA.to_string(),
            job_id: "test-job-01".to_string(),
            organization_id: "org-01".to_string(),
            site_id: "site-01".to_string(),
            host_id: "host-01".to_string(),
            operation: ConnectivityJobOperation::RestartConnector,
            desired_generation: 1,
            payload: serde_json::json!({}),
            issued_at: "2026-09-13T10:00:00Z".to_string(),
            expires_at: "2026-09-13T11:00:00Z".to_string(),
            authority_key_id: "key-01".to_string(),
            signature_alg: "Ed25519".to_string(),
            signature: "test-sig".to_string(),
            break_glass: None,
            authority_proof: None,
        };

        let json_str = serde_json::to_string(&job).unwrap();
        let deserialized: ConnectivityJobV1 = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.operation, ConnectivityJobOperation::RestartConnector);
    }

    #[test]
    fn test_anti_replay_ledger() {
        let ledger_path = std::env::temp_dir().join(format!("test_ledger_{}.json", Uuid::new_v4()));
        let _ = fs::remove_file(&ledger_path);

        let mut ledger = RemoteOpsLedger::load_or_create(&ledger_path);
        assert!(ledger.is_consumed("job-01").is_none());

        let receipt = JobReceiptV1 {
            schema: JOB_RECEIPT_SCHEMA.to_string(),
            receipt_id: "rec-01".to_string(),
            job_id: "job-01".to_string(),
            site_id: "site-01".to_string(),
            host_id: "host-01".to_string(),
            operation: ConnectivityJobOperation::RestartConnector,
            outcome: JobReceiptOutcome::Succeeded,
            started_at: "1000".to_string(),
            completed_at: "1005".to_string(),
            before_state: serde_json::json!({}),
            after_state: serde_json::json!({}),
            health_gate: HealthGateResult {
                passed: true,
                service_active: Some(true),
                health_endpoint_ready: Some(true),
                details: None,
            },
            error_code: None,
            details: serde_json::json!({}),
            host_identity: "host-key".to_string(),
            host_signature: "sig".to_string(),
            generation: 1,
        };

        ledger.record_receipt(receipt.clone(), &ledger_path).unwrap();

        // Reload and verify idempotent consumption
        let reloaded = RemoteOpsLedger::load_or_create(&ledger_path);
        let consumed = reloaded.is_consumed("job-01").unwrap();
        assert_eq!(consumed.outcome, JobReceiptOutcome::Succeeded);
    }

    #[test]
    fn invalid_timestamp_is_not_treated_as_future() {
        assert!(parse_iso_or_unix("not-a-timestamp").is_err());
        assert!(parse_iso_or_unix("2026-09-13T10:00:00Z").is_ok());
    }

    fn reachable_remote_ops_route(adapter: Option<&str>) -> ServiceRoute {
        crate::connectivity_fabric::remote_ops_route(
            "https://center.example/remote-ops",
            adapter,
            ConnectivityRouteState::Reachable,
            0,
            1,
        )
        .unwrap()
    }

    #[test]
    fn remote_ops_requires_an_explicit_canonical_adapter() {
        let error = HttpRemoteOpsTransport::from_route(
            reachable_remote_ops_route(None),
            "test",
        )
        .unwrap_err();
        assert_eq!(error, "REMOTE_OPS_TRANSPORT_ADAPTER_UNRESOLVED");

        let error = HttpRemoteOpsTransport::from_route(
            reachable_remote_ops_route(Some("unknown_adapter")),
            "test",
        )
        .unwrap_err();
        assert_eq!(error, "REMOTE_OPS_TRANSPORT_ADAPTER_UNRESOLVED");
    }

    #[test]
    fn remote_ops_preserves_canonical_adapter_identity() {
        for adapter in [
            REMOTE_OPS_ADAPTER_ACTIUM_CENTER_LOCAL,
            REMOTE_OPS_ADAPTER_SUPABASE_HOSTED,
            REMOTE_OPS_ADAPTER_RELAY_CENTER,
        ] {
            let transport = HttpRemoteOpsTransport::from_route(
                reachable_remote_ops_route(Some(adapter)),
                "test",
            )
            .unwrap();
            assert_eq!(transport.descriptor().adapter, adapter);
            assert_eq!(transport.descriptor().adapter_resolution, None);
        }
    }

    #[test]
    fn remote_ops_marks_legacy_https_adapter_as_compatibility_only() {
        let transport = HttpRemoteOpsTransport::from_route(
            reachable_remote_ops_route(Some(REMOTE_OPS_ADAPTER_LEGACY_HTTPS_HOSTED)),
            "test",
        )
        .unwrap();

        assert_eq!(transport.descriptor().adapter, REMOTE_OPS_ADAPTER_SUPABASE_HOSTED);
        assert_eq!(
            transport.descriptor().adapter_resolution.as_deref(),
            Some(REMOTE_OPS_ADAPTER_RESOLUTION_LEGACY_COMPAT),
        );
    }

    #[test]
    fn host_management_request_is_signed_by_the_enrolled_supervisor_identity() {
        let root = std::env::temp_dir().join(format!("actium-remote-ops-signer-{}", Uuid::new_v4()));
        let key_path = root.join("attestation-identity.key");
        let signer = AttestationSigner::load_or_create(&key_path).unwrap();
        let binding = RemoteOpsHostBinding {
            organization_id: "org-1".into(),
            site_id: "site-1".into(),
            host_id: "host-1".into(),
            binding_epoch: 4,
        };
        let request = signed_management_request(
            HostManagementAction::PollJobs,
            &serde_json::json!({ "since": serde_json::Value::Null }),
            &binding,
            &signer,
        )
        .unwrap();
        assert_eq!(request.schema, HOST_MANAGEMENT_REQUEST_SCHEMA);
        assert_eq!(request.supervisor_key_id, signer.key_id());
        assert!(!request.signature.is_empty());
        let mut unsigned = serde_json::to_value(&request).unwrap();
        unsigned.as_object_mut().unwrap().remove("signature");
        let canonical = canonical_json(&unsigned).unwrap();
        let public_key = URL_SAFE_NO_PAD.decode(signer.public_key()).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public_key.try_into().unwrap()).unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(request.signature).unwrap()).unwrap();
        verifying_key.verify(canonical.as_bytes(), &signature).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn host_receipt_submission_uses_authenticated_management_body() {
        let root = std::env::temp_dir().join(format!("actium-remote-ops-receipt-signer-{}", Uuid::new_v4()));
        let key_path = root.join("attestation-identity.key");
        let signer = AttestationSigner::load_or_create(&key_path).unwrap();
        let binding = RemoteOpsHostBinding {
            organization_id: "org-1".into(),
            site_id: "site-1".into(),
            host_id: "host-1".into(),
            binding_epoch: 4,
        };
        let action_body = serde_json::json!({
            "receipt": {
                "jobId": "job-1",
                "outcome": "SUCCEEDED",
                "hostSignature": "signed",
            },
        });
        let request = signed_management_request(
            HostManagementAction::SubmitReceipt,
            &action_body,
            &binding,
            &signer,
        )
        .unwrap();
        assert_eq!(request.action, HostManagementAction::SubmitReceipt);
        assert_eq!(
            request.body_digest,
            hex_sha256(&Sha256::digest(canonical_json(&management_body(HostManagementAction::SubmitReceipt, action_body)).unwrap().as_bytes()))
        );
        assert_eq!(submit_job_receipt_http("https://center.invalid", &serde_json::from_value(serde_json::json!({
            "schema": JOB_RECEIPT_SCHEMA,
            "receiptId": "r",
            "jobId": "j",
            "siteId": "s",
            "hostId": "h",
            "operation": "RESTART_CONNECTOR",
            "outcome": "SUCCEEDED",
            "startedAt": "1",
            "completedAt": "2",
            "beforeState": {},
            "afterState": {},
            "healthGate": { "passed": true },
            "details": {},
            "hostIdentity": "host",
            "hostSignature": "sig",
            "generation": 1
        })).unwrap()).unwrap_err(), "HOST_MANAGEMENT_AUTH_REQUIRED");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lab_safe_policy_accepts_only_neutral_local_connector_contract() {
        let policy = serde_json::json!({
            "mode": "AUTO",
            "preferredRegion": "sa-east-1",
            "redundancy": 2,
            "localTarget": "http://127.0.0.1:8090",
            "policyGeneration": 7,
            "updatedAtUnix": 1_789_278_004u64,
        });
        assert_eq!(validate_lab_safe_connectivity_policy(&policy, 7).unwrap(), policy);
    }

    #[test]
    fn lab_safe_policy_rejects_wan_relay_router_and_generation_mutations() {
        let base = serde_json::json!({
            "mode": "AUTO",
            "preferredRegion": "sa-east-1",
            "redundancy": 2,
            "localTarget": "http://127.0.0.1:8090",
            "policyGeneration": 7,
        });
        let mut remote_target = base.clone();
        remote_target["localTarget"] = serde_json::json!("https://site.example");
        assert_eq!(validate_lab_safe_connectivity_policy(&remote_target, 7).unwrap_err(), "POLICY_R1_LOCAL_TARGET_INVALID");

        let mut relay = base.clone();
        relay["relayEndpoint"] = serde_json::json!("https://relay.example");
        assert_eq!(validate_lab_safe_connectivity_policy(&relay, 7).unwrap_err(), "POLICY_R1_SCOPE_INVALID");

        let mut stale = base;
        stale["policyGeneration"] = serde_json::json!(6);
        assert_eq!(validate_lab_safe_connectivity_policy(&stale, 7).unwrap_err(), "POLICY_R1_GENERATION_MISMATCH");
    }
}
