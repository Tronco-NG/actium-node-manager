pub mod attestation;
pub mod capability_surface;
pub mod durability;
pub mod health;
pub mod host_identity;
pub mod ipc;
pub mod journal;
pub mod manifest;
pub mod material;
pub mod material_fs;
pub mod network;
#[cfg(unix)]
mod privileged_fs;
pub mod fabric_policy;
pub mod redaction;
pub mod releases;
pub mod runtime;
pub mod runtime_intent;
pub mod topology;

pub use attestation::{
    canonical_json, verify_material_attestation, verify_material_attestation_transport,
    AttestationAuthorityState, AttestationJournal, AttestationSigner, AttestedFabric,
    LocalJournalProof, MaterialAttestationEnvelope, MaterialAttestationStatement,
    MaterialAttestationTransport,
};
pub use capability_surface::{
    active_env_keys, active_port_keys, assert_resume_identity, assert_resume_profiles,
    effective_profiles, installer_min_version_for_profiles, is_known_profile, key_is_authoritative,
    key_is_install_material, merge_resume_env, parse_profile_list, preserve_leftover_network,
    profile_env_keys, sanitize_inactive_env, validate_active_configuration, KNOWN_PROFILES,
    RESUME_IMMUTABLE_ENV_KEYS,
};
pub use health::{evaluate_docker_inspect, HealthGateReport};
pub use host_identity::{
    apply_node_installation_id, load_host_identity, load_or_create_host_identity,
    reconcile_host_identity, require_node_installation_id, HostIdentity, HostIdentityScope,
    NodeInstallationIdentity, HOST_IDENTITY_CONFLICT, HOST_IDENTITY_ENV_KEYS,
    NODE_IDENTITY_MISSING, NODE_INSTALLATION_ENV_KEY,
};
pub use ipc::{
    evaluate_supervisor_compatibility, CommissionNodeRequest, ConfigurationWriteRequest,
    MaterialOperationRequest, NodeRuntimeSummary, ProjectAuditSummary, ProjectServiceSummary,
    SupervisorClient, SupervisorCommand, SupervisorCompatibility, SupervisorOperationRequest,
    SupervisorReply, SupervisorRequestEnvelope, SupervisorResponseEnvelope, IPC_FEATURES,
    IPC_PROTOCOL_VERSION, SUPERVISOR_VERSION,
};
pub use journal::{JournalOperation, JournalUpdate, OperationJournal};
pub use manifest::{tree_sha256, verify_payload, PayloadFile, PayloadManifestV3, VerifiedPayload};
pub use material::{
    key_id_for_public_key, MaterialContract, MaterialContractRegistry, MaterialManager,
    MaterialPackageV1, MaterialRef, MaterialResourceLimits, MaterialStateV1, MaterialTrustEntry,
    MaterialTrustStore, NodeScope, MATERIAL_CONTENT_DIGEST_ALG, MATERIAL_PACKAGE_SCHEMA,
};
pub use network::{
    network_inventory, reconcile_node_network, NetworkAddress, NetworkReconciliationPolicy,
    NetworkReconciliationResult,
};
pub use redaction::{redact_json_sensitive, redact_sensitive};
pub use releases::{
    NodeReleaseState, PreparedRelease, PromotionAbort, ReleaseManager, ReleaseMetadata,
    ReleasePromotion, ReleaseRecoveryHold,
};
pub use fabric_policy::{
    clamp_runtime_reconcile_parallelism, plan_fabric_release, FabricEnsureMode, FabricReleasePlan,
};
pub use runtime::{RuntimeActionResult, RuntimeOperator};
pub use runtime_intent::{
    decide_runtime_reconcile, migrate_runtime_desired_state, RuntimeDesiredState, RuntimeIntent,
    RuntimeIntentSource, RuntimeReconcileDecision, RuntimeStartupMode,
};
pub use topology::{
    FabricIdentity, RuntimeStartupCohort, RuntimeStartupGate, RuntimeTopology, RuntimeUnit,
    RuntimeUnitActionRequest, RuntimeUnitBinding, RuntimeUnitHealth, RuntimeUnitInventory,
    RuntimeUnitResourceBudget,
};
