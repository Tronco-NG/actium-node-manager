//! Universal runtime governance for Actium Node Manager.
//!
//! This module deliberately contains policy and durable state, not Docker
//! commands.  Runtime-specific execution belongs behind `RuntimeAdapter` in
//! the Supervisor boundary.  The first rollout is compatible with the
//! existing topology: LEGACY preserves current behavior, OBSERVED records
//! policy decisions, and MANAGED is fail-closed and owns recovery decisions.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const RUNTIME_CONTROL_PLANE_CONTRACT: &str = "actium.runtime.control-plane.v1";
pub const RUNTIME_CONTROL_STATE_SCHEMA: u8 = 1;
pub const RUNTIME_CONTROL_STATE_RELATIVE_PATH: &str = "state/runtime-control-plane.json";
pub const RUNTIME_CONTROL_EVENT_LOG_RELATIVE_PATH: &str = "state/runtime-events.jsonl";
pub const RUNTIME_CONTROL_MAX_EVENTS: usize = 256;
pub const RUNTIME_CONTROL_MAX_RECEIPTS: usize = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuntimeRolloutMode {
    Legacy,
    Observed,
    Managed,
}

impl Default for RuntimeRolloutMode {
    fn default() -> Self {
        Self::Legacy
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuntimeLifecycleState {
    Discovered,
    Preflight,
    Admitted,
    Starting,
    Running,
    Ready,
    Degraded,
    Blocked,
    Quarantined,
    Recovering,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuntimeBackend {
    Docker,
    Systemd,
    Native,
    Containerd,
    Vm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HostPressureState {
    Healthy,
    Pressure,
    Critical,
    Emergency,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LeaseState {
    Valid,
    RenewalAvailable,
    RenewalRequired,
    Critical,
    Expired,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FailureClass {
    Deterministic,
    Transient,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeFailureCode {
    JwtExpired,
    SignatureInvalid,
    AuthorityRevoked,
    GenerationRollback,
    ConfigInvalid,
    MissingSecret,
    IncompatibleRuntime,
    PermissionDenied,
    DnsTimeout,
    RemoteDependencyUnavailable,
    DatabaseUnavailable,
    RelayUnavailable,
    ResourcePressure,
    DependencyNotReady,
    UnknownFailure,
}

impl RuntimeFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JwtExpired => "JWT_EXPIRED",
            Self::SignatureInvalid => "SIGNATURE_INVALID",
            Self::AuthorityRevoked => "AUTHORITY_REVOKED",
            Self::GenerationRollback => "GENERATION_ROLLBACK",
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::MissingSecret => "MISSING_SECRET",
            Self::IncompatibleRuntime => "INCOMPATIBLE_RUNTIME",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::DnsTimeout => "DNS_TIMEOUT",
            Self::RemoteDependencyUnavailable => "REMOTE_DEPENDENCY_UNAVAILABLE",
            Self::DatabaseUnavailable => "DATABASE_UNAVAILABLE",
            Self::RelayUnavailable => "RELAY_UNAVAILABLE",
            Self::ResourcePressure => "RESOURCE_PRESSURE",
            Self::DependencyNotReady => "DEPENDENCY_NOT_READY",
            Self::UnknownFailure => "UNKNOWN_FAILURE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeIdentityV1 {
    pub organization: String,
    pub product: String,
    pub site: String,
    pub host: String,
    pub node: String,
    pub capability: String,
    pub runtime_instance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAuthorityEvidenceV1 {
    pub required: bool,
    pub issuer: Option<String>,
    pub authority_id: Option<String>,
    pub key_id: Option<String>,
    pub trust_epoch: Option<u64>,
    pub generation: Option<u64>,
    pub expected_generation: Option<u64>,
    pub not_before: Option<u64>,
    pub expires_at: Option<u64>,
    pub offline_until: Option<u64>,
    pub renew_after: Option<u64>,
    pub signature_valid: Option<bool>,
    pub revoked: bool,
}

impl Default for RuntimeAuthorityEvidenceV1 {
    fn default() -> Self {
        Self {
            required: false,
            issuer: None,
            authority_id: None,
            key_id: None,
            trust_epoch: None,
            generation: None,
            expected_generation: None,
            not_before: None,
            expires_at: None,
            offline_until: None,
            renew_after: None,
            signature_valid: None,
            revoked: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeResourceSnapshotV1 {
    pub memory_available_bytes: Option<u64>,
    pub swap_total_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub cpu_pressure_micros: Option<u64>,
    pub io_pressure_micros: Option<u64>,
    pub load_1m_micros: Option<u64>,
    pub disk_available_bytes: Option<u64>,
    pub inode_available: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeResourcePolicyV1 {
    pub memory_soft_bytes: Option<u64>,
    pub memory_hard_bytes: Option<u64>,
    pub max_swap_used_bytes: Option<u64>,
    pub max_cpu_pressure_micros: Option<u64>,
    pub max_io_pressure_micros: Option<u64>,
    pub min_disk_available_bytes: Option<u64>,
    pub min_inode_available: Option<u64>,
}

impl Default for RuntimeResourcePolicyV1 {
    fn default() -> Self {
        Self {
            memory_soft_bytes: None,
            memory_hard_bytes: None,
            max_swap_used_bytes: None,
            max_cpu_pressure_micros: None,
            max_io_pressure_micros: None,
            min_disk_available_bytes: None,
            min_inode_available: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeHealthSignalsV1 {
    pub liveness: bool,
    pub readiness: bool,
    pub authority: bool,
    pub dependencies: bool,
    pub resource_health: bool,
}

impl Default for RuntimeHealthSignalsV1 {
    fn default() -> Self {
        Self {
            liveness: false,
            readiness: false,
            authority: false,
            dependencies: false,
            resource_health: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCapabilityManifestV1 {
    pub schema: u8,
    pub capability: String,
    pub backend: RuntimeBackend,
    pub authority: RuntimeAuthorityEvidenceV1,
    pub resources: RuntimeResourcePolicyV1,
    pub required_secrets: Vec<String>,
    pub mounts: Vec<String>,
    pub ports: Vec<u16>,
    pub dependencies: Vec<String>,
    pub requires_liveness: bool,
    pub requires_readiness: bool,
    pub supervised_recovery: bool,
    pub rollout_mode: RuntimeRolloutMode,
}

impl RuntimeCapabilityManifestV1 {
    pub fn new(capability: impl Into<String>, backend: RuntimeBackend) -> Self {
        Self {
            schema: 1,
            capability: capability.into(),
            backend,
            authority: RuntimeAuthorityEvidenceV1::default(),
            resources: RuntimeResourcePolicyV1::default(),
            required_secrets: Vec::new(),
            mounts: Vec::new(),
            ports: Vec::new(),
            dependencies: Vec::new(),
            requires_liveness: true,
            requires_readiness: true,
            supervised_recovery: true,
            rollout_mode: RuntimeRolloutMode::Legacy,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAdmissionContextV1 {
    pub identity: RuntimeIdentityV1,
    pub authority: RuntimeAuthorityEvidenceV1,
    pub config_valid: bool,
    pub required_secrets_present: bool,
    pub mounts_ready: bool,
    pub ports_ready: bool,
    pub dependencies_ready: bool,
    pub resources: RuntimeResourceSnapshotV1,
    pub resource_policy: RuntimeResourcePolicyV1,
    pub host_pressure: HostPressureState,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeAdmissionDecisionV1 {
    pub admitted: bool,
    pub lifecycle_state: RuntimeLifecycleState,
    pub reason_code: Option<String>,
    pub reason: String,
    pub intervention_required: bool,
}

pub fn evaluate_runtime_admission(ctx: &RuntimeAdmissionContextV1) -> RuntimeAdmissionDecisionV1 {
    let deny =
        |code: &str, reason: &str, state: RuntimeLifecycleState| RuntimeAdmissionDecisionV1 {
            admitted: false,
            lifecycle_state: state,
            reason_code: Some(code.to_string()),
            reason: reason.to_string(),
            intervention_required: true,
        };
    if matches!(
        ctx.host_pressure,
        HostPressureState::Critical | HostPressureState::Emergency
    ) {
        return deny(
            "HOST_PRESSURE",
            "Host pressure blocks new runtime starts.",
            RuntimeLifecycleState::Blocked,
        );
    }
    if !ctx.config_valid {
        return deny(
            "CONFIG_INVALID",
            "Runtime configuration is invalid.",
            RuntimeLifecycleState::Quarantined,
        );
    }
    if !ctx.required_secrets_present {
        return deny(
            "MISSING_SECRET",
            "A required runtime secret is unavailable.",
            RuntimeLifecycleState::Quarantined,
        );
    }
    if !ctx.mounts_ready {
        return deny(
            "MOUNT_UNAVAILABLE",
            "A required runtime mount is unavailable.",
            RuntimeLifecycleState::Blocked,
        );
    }
    if !ctx.ports_ready {
        return deny(
            "PORT_UNAVAILABLE",
            "A required runtime port is unavailable.",
            RuntimeLifecycleState::Blocked,
        );
    }
    if !ctx.dependencies_ready {
        return deny(
            "DEPENDENCY_NOT_READY",
            "A runtime dependency is not ready.",
            RuntimeLifecycleState::Blocked,
        );
    }
    let authority = &ctx.authority;
    if authority.required {
        if authority.authority_id.is_none()
            || authority.key_id.is_none()
            || authority.signature_valid != Some(true)
        {
            return deny(
                "AUTHORITY_EVIDENCE_MISSING",
                "Runtime authority evidence is incomplete.",
                RuntimeLifecycleState::Quarantined,
            );
        }
        if authority.revoked {
            return deny(
                "AUTHORITY_REVOKED",
                "Runtime authority is revoked.",
                RuntimeLifecycleState::Quarantined,
            );
        }
        if authority.signature_valid == Some(false) {
            return deny(
                "SIGNATURE_INVALID",
                "Runtime authority signature is invalid.",
                RuntimeLifecycleState::Quarantined,
            );
        }
        if let (Some(expected), Some(observed)) =
            (authority.expected_generation, authority.generation)
        {
            if observed < expected {
                return deny(
                    "GENERATION_ROLLBACK",
                    "Runtime authority generation rolled back.",
                    RuntimeLifecycleState::Quarantined,
                );
            }
        }
        if authority
            .expires_at
            .is_some_and(|value| ctx.now_unix_seconds >= value)
            || authority
                .offline_until
                .is_some_and(|value| ctx.now_unix_seconds >= value)
        {
            return deny(
                "AUTHORITY_LEASE_EXPIRED",
                "Runtime authority lease is expired.",
                RuntimeLifecycleState::Quarantined,
            );
        }
        if authority
            .not_before
            .is_some_and(|value| ctx.now_unix_seconds < value)
        {
            return deny(
                "AUTHORITY_NOT_YET_VALID",
                "Runtime authority is not yet valid.",
                RuntimeLifecycleState::Blocked,
            );
        }
    }
    if !resources_admit(&ctx.resources, &ctx.resource_policy) {
        return deny(
            "RESOURCE_PRESSURE",
            "Host resources do not satisfy the runtime policy.",
            RuntimeLifecycleState::Blocked,
        );
    }
    RuntimeAdmissionDecisionV1 {
        admitted: true,
        lifecycle_state: RuntimeLifecycleState::Admitted,
        reason_code: None,
        reason: "Runtime admission passed.".to_string(),
        intervention_required: false,
    }
}

fn resources_admit(snapshot: &RuntimeResourceSnapshotV1, policy: &RuntimeResourcePolicyV1) -> bool {
    if policy.memory_hard_bytes.is_some_and(|limit| {
        snapshot
            .memory_available_bytes
            .is_some_and(|value| value < limit)
    }) {
        return false;
    }
    if policy
        .max_swap_used_bytes
        .is_some_and(|limit| snapshot.swap_used_bytes.is_some_and(|value| value > limit))
    {
        return false;
    }
    if policy.max_cpu_pressure_micros.is_some_and(|limit| {
        snapshot
            .cpu_pressure_micros
            .is_some_and(|value| value > limit)
    }) {
        return false;
    }
    if policy.max_io_pressure_micros.is_some_and(|limit| {
        snapshot
            .io_pressure_micros
            .is_some_and(|value| value > limit)
    }) {
        return false;
    }
    if policy.min_disk_available_bytes.is_some_and(|limit| {
        snapshot
            .disk_available_bytes
            .is_some_and(|value| value < limit)
    }) {
        return false;
    }
    if policy
        .min_inode_available
        .is_some_and(|limit| snapshot.inode_available.is_some_and(|value| value < limit))
    {
        return false;
    }
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGuardV1 {
    pub runtime_id: String,
    pub policy: RuntimeResourcePolicyV1,
    pub sovereign_plane: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGuardDecisionV1 {
    pub admitted: bool,
    pub reason_code: Option<String>,
    pub reason: String,
}

impl ResourceGuardV1 {
    pub fn evaluate(&self, snapshot: &RuntimeResourceSnapshotV1) -> ResourceGuardDecisionV1 {
        if self.sovereign_plane {
            return ResourceGuardDecisionV1 {
                admitted: true,
                reason_code: None,
                reason: "Sovereign plane has priority.".to_string(),
            };
        }
        let admitted = resources_admit(snapshot, &self.policy);
        ResourceGuardDecisionV1 {
            admitted,
            reason_code: (!admitted).then(|| "RESOURCE_PRESSURE".to_string()),
            reason: if admitted {
                "Resource guard passed."
            } else {
                "Resource guard blocked workload admission."
            }
            .to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeFailureClassificationV1 {
    pub class: FailureClass,
    pub code: RuntimeFailureCode,
    pub retry_allowed: bool,
    pub quarantine: bool,
    pub reason: String,
}

pub fn classify_runtime_failure(message: &str) -> RuntimeFailureClassificationV1 {
    let text = message.to_ascii_lowercase();
    let deterministic: &[(RuntimeFailureCode, &[&str])] = &[
        (
            RuntimeFailureCode::JwtExpired,
            &[
                "jwtexpired",
                "err_jwt_expired",
                "offline_until",
                "token expired",
            ],
        ),
        (
            RuntimeFailureCode::SignatureInvalid,
            &["signature invalid", "invalid signature", "invalidissuer"],
        ),
        (
            RuntimeFailureCode::AuthorityRevoked,
            &["authority revoked", "revoked authority"],
        ),
        (
            RuntimeFailureCode::GenerationRollback,
            &["generation rollback", "anti-rollback", "rollback detected"],
        ),
        (
            RuntimeFailureCode::ConfigInvalid,
            &[
                "config invalid",
                "configuration invalid",
                "invalid configuration",
            ],
        ),
        (
            RuntimeFailureCode::MissingSecret,
            &["missing secret", "secret unavailable", "secret required"],
        ),
        (
            RuntimeFailureCode::IncompatibleRuntime,
            &[
                "incompatible runtime",
                "unsupported runtime",
                "schema mismatch",
            ],
        ),
        (
            RuntimeFailureCode::PermissionDenied,
            &["permission denied", "operation not permitted", "eacces"],
        ),
    ];
    for (code, needles) in deterministic {
        if needles.iter().any(|needle| text.contains(needle)) {
            return RuntimeFailureClassificationV1 {
                class: FailureClass::Deterministic,
                code: *code,
                retry_allowed: false,
                quarantine: true,
                reason: format!("{} requires operator or authority action.", code.as_str()),
            };
        }
    }
    let transient: &[(RuntimeFailureCode, &[&str])] = &[
        (
            RuntimeFailureCode::DnsTimeout,
            &[
                "dns",
                "name or service not known",
                "temporary failure in name resolution",
            ],
        ),
        (
            RuntimeFailureCode::RemoteDependencyUnavailable,
            &[
                "connection refused",
                "connection reset",
                "remote dependency",
                "temporarily unavailable",
            ],
        ),
        (
            RuntimeFailureCode::DatabaseUnavailable,
            &["database starting", "postgres", "database unavailable"],
        ),
        (
            RuntimeFailureCode::RelayUnavailable,
            &["relay unavailable", "relay timeout"],
        ),
    ];
    for (code, needles) in transient {
        if needles.iter().any(|needle| text.contains(needle)) {
            return RuntimeFailureClassificationV1 {
                class: FailureClass::Transient,
                code: *code,
                retry_allowed: true,
                quarantine: false,
                reason: format!("{} may recover after bounded backoff.", code.as_str()),
            };
        }
    }
    RuntimeFailureClassificationV1 {
        class: FailureClass::Unknown,
        code: RuntimeFailureCode::UnknownFailure,
        retry_allowed: true,
        quarantine: false,
        reason: "Unknown failure receives bounded retries only.".to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerV1 {
    pub state: CircuitState,
    pub failure_count: u32,
    pub failure_window_started_at: Option<u64>,
    pub last_failure_at: Option<u64>,
    pub backoff_until: Option<u64>,
    pub quarantine_reason: Option<String>,
}

impl Default for CircuitBreakerV1 {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            failure_window_started_at: None,
            last_failure_at: None,
            backoff_until: None,
            quarantine_reason: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CircuitBreakerPolicyV1 {
    pub max_failures: u32,
    pub failure_window_seconds: u64,
    pub max_unknown_retries: u32,
}

impl Default for CircuitBreakerPolicyV1 {
    fn default() -> Self {
        Self {
            max_failures: 3,
            failure_window_seconds: 300,
            max_unknown_retries: 3,
        }
    }
}

impl CircuitBreakerV1 {
    pub fn can_attempt(&self, now: u64) -> bool {
        match self.state {
            CircuitState::Closed => self.backoff_until.is_none_or(|value| now >= value),
            CircuitState::HalfOpen => true,
            CircuitState::Open => self.backoff_until.is_some_and(|value| now >= value),
        }
    }

    pub fn record_failure(
        &mut self,
        classification: &RuntimeFailureClassificationV1,
        now: u64,
        policy: CircuitBreakerPolicyV1,
        jitter_seed: u64,
    ) {
        if self
            .failure_window_started_at
            .is_none_or(|start| now.saturating_sub(start) > policy.failure_window_seconds)
        {
            self.failure_window_started_at = Some(now);
            self.failure_count = 0;
        }
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_failure_at = Some(now);
        if classification.quarantine
            || (classification.class == FailureClass::Unknown
                && self.failure_count >= policy.max_unknown_retries)
            || self.failure_count >= policy.max_failures
        {
            self.state = CircuitState::Open;
            self.quarantine_reason = Some(classification.code.as_str().to_string());
            self.backoff_until = None;
        } else {
            self.state = CircuitState::Closed;
            self.backoff_until =
                Some(now.saturating_add(bounded_backoff_seconds(self.failure_count, jitter_seed)));
        }
    }

    pub fn begin_half_open(&mut self, now: u64) -> bool {
        if self.state == CircuitState::Open && self.backoff_until.is_some_and(|value| now >= value)
        {
            self.state = CircuitState::HalfOpen;
            return true;
        }
        false
    }

    pub fn record_success(&mut self) {
        self.state = CircuitState::Closed;
        self.failure_count = 0;
        self.failure_window_started_at = None;
        self.last_failure_at = None;
        self.backoff_until = None;
        self.quarantine_reason = None;
    }
}

pub fn bounded_backoff_seconds(failure_count: u32, jitter_seed: u64) -> u64 {
    let base = match failure_count {
        0 | 1 => 5,
        2 => 15,
        3 => 30,
        4 => 60,
        5 => 120,
        _ => 300,
    };
    base + (jitter_seed % ((base / 5).max(1) as u64))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LeaseManagerV1 {
    pub lease_expires_at: Option<u64>,
    pub renew_after: Option<u64>,
    pub offline_until: Option<u64>,
    pub last_renewal: Option<u64>,
    pub renewal_state: LeaseState,
}

impl Default for LeaseManagerV1 {
    fn default() -> Self {
        Self {
            lease_expires_at: None,
            renew_after: None,
            offline_until: None,
            last_renewal: None,
            renewal_state: LeaseState::Unknown,
        }
    }
}

pub fn evaluate_lease(
    expires_at: Option<u64>,
    renew_after: Option<u64>,
    offline_until: Option<u64>,
    now: u64,
) -> LeaseState {
    let expiry = [expires_at, offline_until].into_iter().flatten().min();
    if expiry.is_some_and(|value| now >= value) {
        return LeaseState::Expired;
    }
    if renew_after.is_some_and(|value| now >= value) {
        return LeaseState::RenewalRequired;
    }
    if expiry.is_some_and(|value| value.saturating_sub(now) <= 7 * 24 * 60 * 60) {
        return LeaseState::RenewalAvailable;
    }
    if expiry.is_some() {
        LeaseState::Valid
    } else {
        LeaseState::Unknown
    }
}

pub fn evaluate_host_pressure(
    snapshot: &RuntimeResourceSnapshotV1,
    total_memory_bytes: Option<u64>,
) -> HostPressureState {
    let swap_ratio = snapshot
        .swap_total_bytes
        .zip(snapshot.swap_used_bytes)
        .map(|(total, swap)| {
            if total == 0 {
                0
            } else {
                swap.saturating_mul(100) / total
            }
        })
        .or_else(|| {
            total_memory_bytes
                .zip(snapshot.swap_used_bytes)
                .map(|(total, swap)| {
                    if total == 0 {
                        0
                    } else {
                        swap.saturating_mul(100) / total
                    }
                })
        });
    if snapshot
        .memory_available_bytes
        .is_some_and(|value| value < 128 * 1024 * 1024)
        || swap_ratio.is_some_and(|value| value >= 90)
        || snapshot
            .cpu_pressure_micros
            .is_some_and(|value| value >= 900_000)
        || snapshot
            .io_pressure_micros
            .is_some_and(|value| value >= 900_000)
    {
        return HostPressureState::Emergency;
    }
    if snapshot
        .memory_available_bytes
        .is_some_and(|value| value < 256 * 1024 * 1024)
        || swap_ratio.is_some_and(|value| value >= 75)
        || snapshot
            .cpu_pressure_micros
            .is_some_and(|value| value >= 700_000)
        || snapshot
            .io_pressure_micros
            .is_some_and(|value| value >= 700_000)
    {
        return HostPressureState::Critical;
    }
    if snapshot
        .memory_available_bytes
        .is_some_and(|value| value < 512 * 1024 * 1024)
        || swap_ratio.is_some_and(|value| value >= 50)
        || snapshot
            .cpu_pressure_micros
            .is_some_and(|value| value >= 500_000)
        || snapshot
            .io_pressure_micros
            .is_some_and(|value| value >= 500_000)
    {
        return HostPressureState::Pressure;
    }
    if snapshot.memory_available_bytes.is_some() || snapshot.load_1m_micros.is_some() {
        HostPressureState::Healthy
    } else {
        HostPressureState::Unknown
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostPressureControllerV1 {
    pub state: HostPressureState,
}

impl HostPressureControllerV1 {
    pub fn from_snapshot(snapshot: &RuntimeResourceSnapshotV1) -> Self {
        Self {
            state: evaluate_host_pressure(snapshot, None),
        }
    }

    pub fn allows_new_workload(&self) -> bool {
        matches!(
            self.state,
            HostPressureState::Healthy | HostPressureState::Pressure | HostPressureState::Unknown
        )
    }

    pub fn preserves_sovereign_plane(&self) -> bool {
        true
    }
}

pub fn collect_host_resource_snapshot() -> RuntimeResourceSnapshotV1 {
    #[cfg(unix)]
    {
        let mut snapshot = RuntimeResourceSnapshotV1::default();
        if let Ok(loadavg) = fs::read_to_string("/proc/loadavg") {
            if let Some(value) = loadavg
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<f64>().ok())
            {
                snapshot.load_1m_micros = Some((value * 1_000_000.0) as u64);
            }
        }
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            let value = |key: &str| {
                meminfo
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix(key)
                            .and_then(|rest| rest.split_whitespace().next())
                            .and_then(|value| value.parse::<u64>().ok())
                    })
                    .map(|kb| kb * 1024)
            };
            snapshot.memory_available_bytes = value("MemAvailable:");
            snapshot.swap_total_bytes = value("SwapTotal:");
            snapshot.swap_used_bytes = snapshot
                .swap_total_bytes
                .zip(value("SwapFree:"))
                .map(|(total, free)| total.saturating_sub(free));
        }
        let pressure = |path: &str| {
            fs::read_to_string(path).ok().and_then(|contents| {
                contents.lines().find_map(|line| {
                    line.strip_prefix("some ")?
                        .split_whitespace()
                        .find_map(|field| {
                            let value = field.strip_prefix("avg10=")?.parse::<f64>().ok()?;
                            Some((value * 1_000_000.0) as u64)
                        })
                })
            })
        };
        snapshot.cpu_pressure_micros = pressure("/proc/pressure/cpu");
        snapshot.io_pressure_micros = pressure("/proc/pressure/io");
        if let Ok(stat) = nix::sys::statvfs::statvfs("/") {
            snapshot.disk_available_bytes = Some(
                (stat.blocks_available() as u128)
                    .saturating_mul(stat.fragment_size() as u128)
                    .min(u64::MAX as u128) as u64,
            );
            snapshot.inode_available = Some(stat.files_available() as u64);
        }
        snapshot
    }
    #[cfg(not(unix))]
    {
        RuntimeResourceSnapshotV1::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeObservedStateV1 {
    pub lifecycle_state: RuntimeLifecycleState,
    pub health: RuntimeHealthSignalsV1,
    pub last_observed_at: u64,
    pub failure: Option<RuntimeFailureClassificationV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEventV1 {
    pub event_type: String,
    pub runtime_id: String,
    pub capability: String,
    pub reason_code: Option<String>,
    pub timestamp: u64,
    pub generation: Option<u64>,
    pub authority_generation: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReceiptV1 {
    pub schema: u8,
    pub runtime_id: String,
    pub previous_state: RuntimeLifecycleState,
    pub failure_reason: Option<String>,
    pub recovery_reason: String,
    pub attempt: u32,
    pub started_at: u64,
    pub completed_at: u64,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeControlRecordV1 {
    pub runtime_id: String,
    pub capability: String,
    pub manifest: RuntimeCapabilityManifestV1,
    pub desired_running: bool,
    pub observed: RuntimeObservedStateV1,
    pub circuit_breaker: CircuitBreakerV1,
    pub lease: LeaseManagerV1,
    pub last_event: Option<RuntimeEventV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeControlStateV1 {
    pub schema: u8,
    pub contract: String,
    pub node_id: String,
    pub rollout_mode: RuntimeRolloutMode,
    pub generation: u64,
    pub host_pressure: HostPressureState,
    pub last_heartbeat_at: Option<u64>,
    pub runtimes: Vec<RuntimeControlRecordV1>,
    pub events: Vec<RuntimeEventV1>,
    pub recovery_receipts: Vec<RecoveryReceiptV1>,
    pub updated_at: u64,
}

impl RuntimeControlStateV1 {
    pub fn new(node_id: impl Into<String>, now: u64) -> Self {
        Self {
            schema: RUNTIME_CONTROL_STATE_SCHEMA,
            contract: RUNTIME_CONTROL_PLANE_CONTRACT.to_string(),
            node_id: node_id.into(),
            rollout_mode: RuntimeRolloutMode::Legacy,
            generation: 0,
            host_pressure: HostPressureState::Unknown,
            last_heartbeat_at: None,
            runtimes: Vec::new(),
            events: Vec::new(),
            recovery_receipts: Vec::new(),
            updated_at: now,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != RUNTIME_CONTROL_STATE_SCHEMA {
            return Err("RUNTIME_CONTROL_STATE_SCHEMA_UNSUPPORTED".to_string());
        }
        if self.contract != RUNTIME_CONTROL_PLANE_CONTRACT {
            return Err("RUNTIME_CONTROL_PLANE_CONTRACT_MISMATCH".to_string());
        }
        if self
            .runtimes
            .iter()
            .map(|runtime| runtime.runtime_id.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.runtimes.len()
        {
            return Err("RUNTIME_CONTROL_DUPLICATE_RUNTIME".to_string());
        }
        Ok(())
    }

    pub fn heartbeat(&mut self, now: u64) {
        self.last_heartbeat_at = Some(now);
        self.updated_at = now;
    }

    pub fn record_event(&mut self, event: RuntimeEventV1) {
        self.events.push(event.clone());
        if self.events.len() > RUNTIME_CONTROL_MAX_EVENTS {
            let excess = self.events.len() - RUNTIME_CONTROL_MAX_EVENTS;
            self.events.drain(0..excess);
        }
        if let Some(runtime) = self
            .runtimes
            .iter_mut()
            .find(|runtime| runtime.runtime_id == event.runtime_id)
        {
            runtime.last_event = Some(event);
        }
    }

    pub fn record_receipt(&mut self, receipt: RecoveryReceiptV1) {
        self.recovery_receipts.push(receipt);
        if self.recovery_receipts.len() > RUNTIME_CONTROL_MAX_RECEIPTS {
            let excess = self.recovery_receipts.len() - RUNTIME_CONTROL_MAX_RECEIPTS;
            self.recovery_receipts.drain(0..excess);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeControlSnapshotV1 {
    pub contract: String,
    pub node_id: String,
    pub rollout_mode: RuntimeRolloutMode,
    pub host_pressure: HostPressureState,
    pub last_heartbeat_at: Option<u64>,
    pub runtimes: Vec<RuntimeControlRecordV1>,
    pub recent_events: Vec<RuntimeEventV1>,
}

pub fn load_runtime_control_state(
    path: &Path,
    node_id: &str,
) -> Result<RuntimeControlStateV1, String> {
    if !path.is_file() {
        return Ok(RuntimeControlStateV1::new(node_id, unix_timestamp()));
    }
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    let state = serde_json::from_str::<RuntimeControlStateV1>(&contents)
        .map_err(|error| format!("RuntimeControlState invalido: {error}"))?;
    state.validate()?;
    Ok(state)
}

pub fn persist_runtime_control_state(
    path: &Path,
    state: &RuntimeControlStateV1,
) -> Result<(), String> {
    state.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear {}: {error}", parent.display()))?;
    }
    let temp = path.with_extension(format!("json.tmp-{}", uuid::Uuid::new_v4()));
    let contents = serde_json::to_vec_pretty(state)
        .map_err(|error| format!("No se pudo serializar RuntimeControlState: {error}"))?;
    let mut file = fs::File::create(&temp)
        .map_err(|error| format!("No se pudo crear {}: {error}", temp.display()))?;
    file.write_all(&contents)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo escribir {}: {error}", temp.display()))?;
    replace_file(&temp, path)
        .map_err(|error| format!("No se pudo promover RuntimeControlState: {error}"))?;
    sync_parent_directory(path)
}

pub fn append_runtime_event(path: &Path, event: &RuntimeEventV1) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear {}: {error}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("No se pudo abrir {}: {error}", path.display()))?;
    let line = serde_json::to_vec(event)
        .map_err(|error| format!("No se pudo serializar RuntimeEvent: {error}"))?;
    file.write_all(&line)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo persistir {}: {error}", path.display()))
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupervisorWatchdogV1 {
    pub heartbeat_interval_seconds: u64,
    pub last_heartbeat_at: Option<u64>,
}

impl SupervisorWatchdogV1 {
    pub fn new(heartbeat_interval_seconds: u64) -> Self {
        Self {
            heartbeat_interval_seconds: heartbeat_interval_seconds.max(5),
            last_heartbeat_at: None,
        }
    }
    pub fn heartbeat(&mut self, now: u64) {
        self.last_heartbeat_at = Some(now);
    }
    pub fn is_alive(&self, now: u64) -> bool {
        self.last_heartbeat_at.is_some_and(|last| {
            now.saturating_sub(last) <= self.heartbeat_interval_seconds.saturating_mul(3)
        })
    }
}

pub fn snapshot(state: RuntimeControlStateV1) -> RuntimeControlSnapshotV1 {
    RuntimeControlSnapshotV1 {
        contract: state.contract,
        node_id: state.node_id,
        rollout_mode: state.rollout_mode,
        host_pressure: state.host_pressure,
        last_heartbeat_at: state.last_heartbeat_at,
        runtimes: state.runtimes,
        recent_events: state.events.into_iter().rev().take(32).collect(),
    }
}

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

pub trait RuntimeAdapter {
    type Error;
    fn backend(&self) -> RuntimeBackend;
    fn start(&mut self, runtime_id: &str) -> Result<(), Self::Error>;
    fn stop(&mut self, runtime_id: &str) -> Result<(), Self::Error>;
    fn restart(&mut self, runtime_id: &str) -> Result<(), Self::Error>;
    fn inspect(&mut self, runtime_id: &str) -> Result<RuntimeObservedStateV1, Self::Error>;
}

pub fn reconcile_runtime_state(
    desired_running: bool,
    current: &RuntimeObservedStateV1,
    admission: &RuntimeAdmissionDecisionV1,
    circuit: &CircuitBreakerV1,
    mode: RuntimeRolloutMode,
) -> RuntimeLifecycleState {
    if !desired_running {
        return RuntimeLifecycleState::Stopped;
    }
    if mode == RuntimeRolloutMode::Legacy {
        return current.lifecycle_state;
    }
    if !admission.admitted {
        return admission.lifecycle_state;
    }
    if circuit.state == CircuitState::Open {
        return RuntimeLifecycleState::Quarantined;
    }
    if current.health.readiness {
        RuntimeLifecycleState::Ready
    } else if current.health.liveness {
        RuntimeLifecycleState::Running
    } else {
        RuntimeLifecycleState::Starting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> RuntimeIdentityV1 {
        RuntimeIdentityV1 {
            organization: "org".into(),
            product: "product".into(),
            site: "site".into(),
            host: "host".into(),
            node: "node".into(),
            capability: "site-core".into(),
            runtime_instance: "runtime".into(),
        }
    }

    #[test]
    fn jwt_expired_is_deterministic_and_quarantined() {
        let result = classify_runtime_failure("AggregateError: JWTExpired ERR_JWT_EXPIRED");
        assert_eq!(result.class, FailureClass::Deterministic);
        assert_eq!(result.code, RuntimeFailureCode::JwtExpired);
        assert!(result.quarantine);
        assert!(!result.retry_allowed);
    }

    #[test]
    fn admission_expired_authority_denies_before_start() {
        let mut authority = RuntimeAuthorityEvidenceV1::default();
        authority.required = true;
        authority.authority_id = Some("authority".into());
        authority.key_id = Some("key".into());
        authority.signature_valid = Some(true);
        authority.expires_at = Some(10);
        let decision = evaluate_runtime_admission(&RuntimeAdmissionContextV1 {
            identity: identity(),
            authority,
            config_valid: true,
            required_secrets_present: true,
            mounts_ready: true,
            ports_ready: true,
            dependencies_ready: true,
            resources: RuntimeResourceSnapshotV1::default(),
            resource_policy: RuntimeResourcePolicyV1::default(),
            host_pressure: HostPressureState::Healthy,
            now_unix_seconds: 11,
        });
        assert!(!decision.admitted);
        assert_eq!(
            decision.reason_code.as_deref(),
            Some("AUTHORITY_LEASE_EXPIRED")
        );
        assert_eq!(decision.lifecycle_state, RuntimeLifecycleState::Quarantined);
    }

    #[test]
    fn deterministic_failure_opens_circuit_without_infinite_retry() {
        let mut circuit = CircuitBreakerV1::default();
        let policy = CircuitBreakerPolicyV1::default();
        let failure = classify_runtime_failure("JWTExpired");
        circuit.record_failure(&failure, 100, policy, 1);
        assert_eq!(circuit.state, CircuitState::Open);
        assert!(!circuit.can_attempt(101));
    }

    #[test]
    fn unknown_failure_is_bounded_and_then_quarantined() {
        let mut circuit = CircuitBreakerV1::default();
        let policy = CircuitBreakerPolicyV1::default();
        let failure = classify_runtime_failure("unexpected process exit");
        for attempt in 1..=3 {
            circuit.record_failure(&failure, attempt, policy, attempt as u64);
        }
        assert_eq!(circuit.state, CircuitState::Open);
        assert_eq!(
            circuit.quarantine_reason.as_deref(),
            Some("UNKNOWN_FAILURE")
        );
    }

    #[test]
    fn managed_reconciliation_never_converts_denied_admission_into_start() {
        let admission = RuntimeAdmissionDecisionV1 {
            admitted: false,
            lifecycle_state: RuntimeLifecycleState::Quarantined,
            reason_code: Some("AUTHORITY_LEASE_EXPIRED".into()),
            reason: "expired".into(),
            intervention_required: true,
        };
        let current = RuntimeObservedStateV1 {
            lifecycle_state: RuntimeLifecycleState::Failed,
            health: RuntimeHealthSignalsV1::default(),
            last_observed_at: 1,
            failure: None,
        };
        let next = reconcile_runtime_state(
            true,
            &current,
            &admission,
            &CircuitBreakerV1::default(),
            RuntimeRolloutMode::Managed,
        );
        assert_eq!(next, RuntimeLifecycleState::Quarantined);
    }

    #[test]
    fn resource_guard_blocks_workload_but_preserves_sovereign_plane() {
        let policy = RuntimeResourcePolicyV1 {
            memory_hard_bytes: Some(512),
            ..RuntimeResourcePolicyV1::default()
        };
        let snapshot = RuntimeResourceSnapshotV1 {
            memory_available_bytes: Some(128),
            ..RuntimeResourceSnapshotV1::default()
        };
        let workload = ResourceGuardV1 {
            runtime_id: "site-core".into(),
            policy: policy.clone(),
            sovereign_plane: false,
        };
        assert!(!workload.evaluate(&snapshot).admitted);
        let sovereign = ResourceGuardV1 {
            runtime_id: "supervisor".into(),
            policy,
            sovereign_plane: true,
        };
        assert!(sovereign.evaluate(&snapshot).admitted);
    }

    #[test]
    fn host_pressure_controller_blocks_new_workload_at_critical_pressure() {
        let snapshot = RuntimeResourceSnapshotV1 {
            memory_available_bytes: Some(200 * 1024 * 1024),
            ..RuntimeResourceSnapshotV1::default()
        };
        let controller = HostPressureControllerV1::from_snapshot(&snapshot);
        assert_eq!(controller.state, HostPressureState::Critical);
        assert!(!controller.allows_new_workload());
        assert!(controller.preserves_sovereign_plane());
    }

    #[test]
    fn supervisor_watchdog_requires_fresh_heartbeat() {
        let mut watchdog = SupervisorWatchdogV1::new(10);
        assert!(!watchdog.is_alive(10));
        watchdog.heartbeat(10);
        assert!(watchdog.is_alive(40));
        assert!(!watchdog.is_alive(41));
    }

    #[test]
    fn state_persistence_is_atomic_and_round_trips() {
        let root =
            std::env::temp_dir().join(format!("actium-runtime-control-{}", uuid::Uuid::new_v4()));
        let path = root.join("state/runtime-control-plane.json");
        let state = RuntimeControlStateV1::new("node", 1);
        persist_runtime_control_state(&path, &state).expect("persist");
        let loaded = load_runtime_control_state(&path, "node").expect("load");
        assert_eq!(loaded.contract, RUNTIME_CONTROL_PLANE_CONTRACT);
        let _ = fs::remove_dir_all(root);
    }
}
