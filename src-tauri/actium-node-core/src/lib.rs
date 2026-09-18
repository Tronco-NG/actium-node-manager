pub mod attestation;
pub mod authority;
pub mod build_info {
    pub const SOURCE_COMMIT: &str = match option_env!("ACTIUM_SOURCE_COMMIT") {
        Some(value) => value,
        None => "unknown",
    };
    pub const BUILD_ID: &str = match option_env!("ACTIUM_BUILD_ID") {
        Some(value) => value,
        None => "unknown",
    };
    pub const BUILD_KIND: &str = match option_env!("ACTIUM_BUILD_KIND") {
        Some(value) => value,
        None => "development",
    };
    pub const RELEASE_STATUS: &str = match option_env!("ACTIUM_RELEASE_STATUS") {
        Some(value) => value,
        None => "UNRELEASED",
    };
}
pub mod capability_surface;
pub mod authority_lifecycle;
pub mod connectivity;
pub mod connectivity_fabric;
pub mod connectivity_session;
pub mod direct_wan;
pub mod path_resolver;
pub mod site_gateway;
pub mod site_identity;
pub use connectivity_fabric::{
    control_plane_route, remote_ops_route, resolve_service, route_is_eligible, ConnectivityAgentStatus, ConnectivityFabricStatus,
    ConnectivityResolution,
    ConnectorInstallationState, ConnectorInstallationStatus, RelayCandidateInfo, RelayDiagnosticItem,
    RelayFabricDiagnosticReport, RelayFabricStatus, RelayMetricsInfo, RelayTunnelInfo, SiteGatewayConnectorInfo,
    PolicyGovernanceKind, CONNECTIVITY_RESOLUTION_CONTRACT,
};
pub use connectivity_session::{
    verify_authenticated_session, AuthenticatedServiceSession,
    ConnectivityAuthenticationMethod, CONNECTIVITY_SESSION_CONTRACT,
};
pub mod durability;
pub mod extensions;
pub mod fabric_canonical;
pub mod fabric_policy;
pub mod health;
pub mod host_identity;
pub mod host_readiness;
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
pub mod mutation_coordinator;
pub mod storage_access_profile;
pub mod storage_intent;
pub mod storage_pool;
pub mod fabric_storage_binding;
pub mod storage_grant;
pub mod storage_client;
pub mod storage_transport;
pub mod topology;
pub mod trust_fabric;

pub mod cgnat_detector;
pub mod remote_ops;

pub use cgnat_detector::{
    apply_direct_wan_attestation, classify_topology, discover_wan_topology, is_global_ipv6, is_rfc1918, is_rfc6598,
    query_external_observed_ip, DirectWanStatus, IngressGatewayStatus, LocalRfc6598Observation,
    NatManagementRequirement, OutsideInStatus, PhysicalInterfaceInfo, PortForwardStatus,
    UpstreamCgnatStatus,
    WanDiscoveryReport, WanTopology, WanTopologyReport,
};
pub use remote_ops::{
    claim_remote_job_http, execute_connectivity_job, poll_remote_jobs_http, remote_ops_transport_from_resolution, sign_job_receipt, submit_job_receipt_http,
    verify_connectivity_job, BreakGlassClaims, ConnectivityJobOperation, ConnectivityJobV1,
    DirectWanAttestationV1, HealthGateResult, JobReceiptOutcome, JobReceiptV1, RemoteOpsLedger,
    HttpRemoteOpsTransport, RemoteOpsStatusSnapshot, RemoteOpsStore, RemoteOpsTransport, RemoteOpsTransportDescriptor,
    RemoteOpsAuthorityProofV1, RouteCandidate, RouteDecisionReceipt, RouteType,
    CONNECTIVITY_JOB_SCHEMA, JOB_RECEIPT_SCHEMA,
};
pub use authority_lifecycle::{
    host_trust_refresh_required, resolve_authority_lifecycle_plan, resolve_root_brief_successor_authority_id,
    AuthorityLifecyclePlanV1, AuthorityLifecycleState, ServedTrustBundleView, AUTHORITY_LIFECYCLE_CONTRACT,
};
pub use path_resolver::{
    is_active_route_type, path_resolver_candidate_snapshot_digest, policy_allows, resolve_path,
    PathResolverConfig, PathResolverState, PathResolveRequest, RoutePolicy, PATH_RESOLVER_CONTRACT,
    TEST_PRODUCT_CAPABILITY,
};
pub use site_identity::{dns_safe_site_label, site_network_identity, SiteNetworkIdentityV1, SITE_IDENTITY_DNS_ZONE};
pub use site_gateway::{
    adapter_for_path, dns_tls_provisioning_plan, start_site_gateway, CapabilityAdapterAllowlistV1,
    CertificateObservedStateV1, DnsDesiredStateV1, DnsObservedStateV1, ProvisionStatus,
    SiteGatewayConfigV1, SiteGatewayHandle, SiteGatewayProvisioningPlanV1, SiteGatewayTlsMaterialV1,
    TlsDesiredStateV1, SITE_GATEWAY_CONTRACT,
};
pub use direct_wan::{
    evaluate_direct_wan, validate_outside_in_proof, DirectWanAttestationDecisionV1, DirectWanEvidenceV1,
    DirectWanReadiness, DirectWanTargetV1, EvidenceStatus, OutsideInProofV1,
};

pub use attestation::{
    canonical_json, classify_material_attestation_artifact, quarantine_stale_attestation,
    verify_material_attestation, verify_material_attestation_transport,
    AttestationArtifactRequirements, AttestationArtifactStatus, AttestationAuthorityState,
    AttestationJournal, AttestationSigner, AttestedFabric, LocalJournalProof,
    MaterialAttestationEnvelope, MaterialAttestationStatement, MaterialAttestationTransport,
};
pub use authority::{center_public_key_fingerprint, enroll, enroll_with_proof, enroll_with_trust_bundle, signed_envelope_digest, verify_enrollment_ack, verify_enrollment_proof, verify_storage_approval, CenterAuthorityBundle, EnrolledAuthority, EnrollmentAckClaims, EnrollmentPackage, EnrollmentProofClaims, HostBindingProjection, SignedEnvelope, StorageApprovalClaims};
pub use storage_grant::{canonical_path, discover_mounts_from_findmnt, discovery_snapshot_hash, latest_effective_grants, latest_effective_transactions, policy_hash, render_dropin, validate_filesystem_uuid, write_dropin, EnrollmentState, StorageGrant, StorageGrantPreflight, StorageGrantStore, StorageTransaction, StorageMount};
pub use fabric_storage_binding::FabricStorageBinding;
pub use mutation_coordinator::{MutationCoordinator, MutationCoordinatorPhase, MutationCoordinatorStatus, MutationPriority};
pub use storage_access_profile::{provision_storage_directory, StorageAccessProfile};
pub use storage_intent::{execute_storage_probe, StorageIntent, StorageProbeResult};
pub use storage_pool::{discover_storage_pools, is_internal_system_mount, StorageClass, StoragePool};
pub use storage_client::StorageBackend;
pub use storage_transport::{
    discovery_snapshot_payload, sign_storage_transport, SignedStorageTransport,
    StorageDiscoveryMount, StorageDiscoverySnapshot, StorageGrantIntent,
    StorageTransportMessageType, StorageTransportScope, STORAGE_TRANSPORT_MAX_TTL_SECONDS,
    STORAGE_TRANSPORT_PROTOCOL, STORAGE_TRANSPORT_VERSION,
};

/// SHA-256 of the exact running executable. This is diagnostic identity only;
/// it never participates in trust decisions.
pub fn current_binary_sha256() -> Option<String> {
    use sha2::{Digest, Sha256};

    let executable = std::env::current_exe().ok()?;
    let bytes = std::fs::read(executable).ok()?;
    let digest = Sha256::digest(bytes);
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
pub use capability_surface::{
    active_env_keys, active_port_keys, assert_resume_identity, assert_resume_profiles,
    effective_profiles, installer_min_version_for_profiles, is_known_profile, key_is_authoritative,
    key_is_install_material, merge_resume_env, parse_profile_list, preserve_leftover_network,
    profile_env_keys, sanitize_inactive_env, validate_active_configuration, KNOWN_PROFILES,
    RESUME_IMMUTABLE_ENV_KEYS,
};
pub use fabric_canonical::{
    adopt_observed_fabric, auto_reconcile_to_desired, canonical_fabric_digest, compose_digest,
    evaluate_fabric_lifecycle, load_declared_fabric_material, parse_compose_declared_images,
    parse_install_mode, rollback_to_lkg, runtime_evidence_digest, DeclaredFabricImage,
    DeclaredFabricMaterial, FabricAdoptReceipt, FabricCanonicalState, FabricLifecycleStatus,
    FabricReconcileMode, PinnedFabricImage, FABRIC_ATTESTATION_SCHEMA_V2,
    FABRIC_CANONICALIZATION_VERSION, FABRIC_CANONICAL_STATE_SCHEMA,
};
pub use fabric_policy::{
    clamp_runtime_reconcile_parallelism, plan_fabric_release, FabricEnsureMode, FabricReleasePlan,
};
pub use extensions::{
    capabilities as extension_capabilities, disable as disable_extension, enable as enable_extension,
    get_extension, health as extension_health, install_bundle as install_extension_bundle,
    ensure_registry as ensure_extension_registry, load_registry as load_extension_registry, remove as remove_extension,
    rollback as rollback_extension, ExtensionArtifact, ExtensionBundleManifest,
    ExtensionBundleVerifier, ExtensionCapabilities, ExtensionCapability, ExtensionCompatibility,
    ExtensionDependency, ExtensionHealth, ExtensionProduct, ExtensionRegistry,
    ExtensionRegistrySnapshot, ExtensionSigning, ExtensionSummary, EXTENSION_CONTRACT,
    EXTENSION_MANIFEST_FILE, EXTENSION_REGISTRY_FILE, EXTENSION_STATES,
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
    EnqueueMaterialRequest, GetMaterialStateRequest, NodeRuntimeSummary, ProjectAuditSummary, StoragePreflightRequest, EnrollmentApplyRequest, StorageGrantApprovalRequest, StorageTransportDiscoveryRequest,
    ProjectServiceSummary, ReconcileMaterialRequest, AuthorityCeremonyPathRequest,
    AuthorityCeremonyPathStatus, AuthorityCeremonyProgress, AuthorityCeremonyRequest, SupervisorClient, SupervisorCommand,
    SupervisorCompatibility, SupervisorOperationRequest, SupervisorReply,
    SupervisorRequestEnvelope, SupervisorResponseEnvelope, EnrollmentAckResponse, EnrollmentChallenge, EnrollmentProofRequest, EnrollmentProofResponse, IPC_FEATURES, IPC_PROTOCOL_VERSION,
    SUPERVISOR_VERSION,
};
pub use host_readiness::{HostReadinessCheck, HostReadinessReport};
pub use journal::{JournalOperation, JournalUpdate, MutationStatus, OperationJournal, MUTATION_HEARTBEAT_SECONDS, MUTATION_LEASE_SECONDS};
pub use journal_continuity::{
    continuity_from_durable_agent_state, continuity_gate_error, evaluate_continuity_status,
    evaluate_desired_payload_gate,
    evaluate_journal_supersede, host_deployment_attestation_dir, host_identities_have_canonical_journal,
    host_identities_root, host_identity_snapshot_dir, read_continuity_status, read_desired_payload_pin,
    restore_attestation_identity, restore_attestation_journal, snapshot_attestation_identity,
    snapshot_attestation_journal, ContinuityGate, DesiredPayloadPin, JournalSupersedeRequest,
    DurableAgentContinuity, RemoteAttestationContinuity,
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
    network_inventory, node_network_policy, reconcile_node_network, NetworkAddress,
    NetworkReconciliationPolicy, NetworkReconciliationResult,
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
pub use trust_fabric::{
    authority_capability, AuthorityCertificate, AuthorityDescriptor, AuthorityKind,
    AuthorityService, AuthorityStatus, DurableAuthorityState, DurableIdempotencyRecord, HostIdentityRecord, KeyDescriptor, KeyProvider,
    ProductTrustRoot, ReleaseArtifact, ReleaseCompatibility, ReleaseManifestV1, ReleaseSigning, Revocation,
    RootTransition, CenterAuthorityReissueMaterialV1, CenterAuthorityReissueOwnerApprovalV1,
    CenterAuthorityReissuePreviewV1, CenterAuthorityReissueRequestV1, CenterAuthorityTransitionSignatureV1,
    CenterAuthorityTransitionStatus, CenterAuthorityTransitionV1, SealedKeyProvider, SignedAuthorityOperation, SignedReleaseManifest, SignedTrustBundle,
    TestEphemeralKeyProvider, TrustBundle,
    TrustRootSet, SoftwareSealedKeyProvider, center_authority_transition_digest, trust_bundle_digest,
    verify_center_authority_transition,
    verify_signed_trust_bundle_with_bootstrap,
    unix_now, verify_signed_trust_bundle, TRUST_BUNDLE_CONTRACT, TRUST_FABRIC_ALGORITHM,
    CENTER_AUTHORITY_REISSUE_CONTRACT, REMOTE_OPERATIONS_SIGNING_CAPABILITY,
};
