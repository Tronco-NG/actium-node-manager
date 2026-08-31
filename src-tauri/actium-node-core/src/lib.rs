pub mod attestation;
pub mod authority;
pub mod capability_surface;
pub mod connectivity;
pub mod durability;
pub mod fabric_policy;
pub mod health;
pub mod host_identity;
pub mod ipc;
pub mod journal;
pub mod journal_continuity;
pub mod manifest;
pub mod material;
pub mod material_fs;
pub mod network;
#[cfg(unix)]
mod privileged_fs;
pub mod redaction;
pub mod releases;
pub mod runtime;
pub mod runtime_intent;
pub mod storage_grant;
pub mod storage_client;
pub mod topology;

pub use attestation::{
    canonical_json, verify_material_attestation, verify_material_attestation_transport,
    AttestationAuthorityState, AttestationJournal, AttestationSigner, AttestedFabric,
    LocalJournalProof, MaterialAttestationEnvelope, MaterialAttestationStatement,
    MaterialAttestationTransport,
};
pub use authority::{enroll, verify_storage_approval, CenterAuthorityBundle, EnrolledAuthority, EnrollmentPackage, SignedEnvelope, StorageApprovalClaims};
pub use storage_grant::{canonical_path, policy_hash, render_dropin, validate_filesystem_uuid, write_dropin, EnrollmentState, StorageGrant, StorageGrantPreflight, StorageGrantStore, StorageTransaction, StorageMount};
pub use storage_client::StorageBackend;
pub use capability_surface::{
    active_env_keys, active_port_keys, assert_resume_identity, assert_resume_profiles,
    effective_profiles, installer_min_version_for_profiles, is_known_profile, key_is_authoritative,
    key_is_install_material, merge_resume_env, parse_profile_list, preserve_leftover_network,
    profile_env_keys, sanitize_inactive_env, validate_active_configuration, KNOWN_PROFILES,
    RESUME_IMMUTABLE_ENV_KEYS,
};
pub use fabric_policy::{
    clamp_runtime_reconcile_parallelism, plan_fabric_release, FabricEnsureMode, FabricReleasePlan,
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
    ConnectivityOperation, ConnectivityOperationRequest, ConnectivityOperationResult,
    EnqueueMaterialRequest, GetMaterialStateRequest, NodeRuntimeSummary, ProjectAuditSummary, StoragePreflightRequest, EnrollmentApplyRequest, StorageGrantApprovalRequest,
    ProjectServiceSummary, ReconcileMaterialRequest, SupervisorClient, SupervisorCommand,
    SupervisorCompatibility, SupervisorOperationRequest, SupervisorReply,
    SupervisorRequestEnvelope, SupervisorResponseEnvelope, IPC_FEATURES, IPC_PROTOCOL_VERSION,
    SUPERVISOR_VERSION,
};
pub use journal::{JournalOperation, JournalUpdate, OperationJournal};
pub use journal_continuity::{
    continuity_gate_error, evaluate_continuity_status, evaluate_desired_payload_gate,
    evaluate_journal_supersede, host_deployment_attestation_dir, host_identities_have_canonical_journal,
    host_identities_root, host_identity_snapshot_dir, read_continuity_status, read_desired_payload_pin,
    restore_attestation_identity, restore_attestation_journal, snapshot_attestation_identity,
    snapshot_attestation_journal, ContinuityGate, DesiredPayloadPin, JournalSupersedeRequest,
    RemoteAttestationContinuity,
};
pub use manifest::{tree_sha256, verify_payload, PayloadFile, PayloadManifestV3, VerifiedPayload};
pub use material::{
    canonical_signed_envelope_v1, encode_ed25519_spki_der, key_id_for_spki_der,
    load_contract_registry, load_trust_store, parse_ed25519_spki_der, resolve_package_dir,
    trusted_scope_from_node_root, validate_access_transport_policy, AccessConnectivityPolicy,
    TransportKind, ActiveMaterial, HealthReceipt, MaterialContract,
    MaterialContractRegistry, MaterialManager, MaterialPackageV1, MaterialRef,
    MaterialResourceLimits, MaterialStateStore, MaterialStateV1, MaterialTrustEntry,
    MaterialTrustStore, SupervisorMaterialReader, SupervisorScopeEvidence, TrustedNodeScope,
    MATERIAL_CONTENT_DIGEST_ALG, MATERIAL_PACKAGE_SCHEMA, SIGNED_ENVELOPE_V1,
};
pub use material_fs::{material_capability_root, MATERIAL_PLANE_FEATURE};
pub use network::{
    network_inventory, reconcile_node_network, NetworkAddress, NetworkReconciliationPolicy,
    NetworkReconciliationResult,
};
pub use redaction::{redact_json_sensitive, redact_sensitive};
pub use releases::{
    NodeReleaseState, PreparedRelease, PromotionAbort, ReleaseManager, ReleaseMetadata,
    ReleasePromotion, ReleaseRecoveryHold,
};
pub use runtime::{is_dangerous_system_path, RuntimeActionResult, RuntimeOperator, RuntimeProgress};
pub use runtime_intent::{
    decide_runtime_reconcile, migrate_runtime_desired_state, RuntimeDesiredState, RuntimeIntent,
    RuntimeIntentSource, RuntimeReconcileDecision, RuntimeStartupMode,
};
pub use topology::{
    FabricIdentity, RuntimeStartupCohort, RuntimeStartupGate, RuntimeTopology, RuntimeUnit,
    RuntimeUnitActionRequest, RuntimeUnitBinding, RuntimeUnitHealth, RuntimeUnitInventory,
    RuntimeUnitResourceBudget,
};
