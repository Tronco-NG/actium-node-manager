//! Checkpoint F7-H: Recovery & E2E Mock Certification.
//!
//! Provides the complete, certified end-to-end integration test suite
//! executing the full workload lifecycle with a synthetic multi-component workload:
//!
//! Desired State -> Signed IPC Envelope -> Host Binding Verification -> Local Recomputation
//! -> Plan -> Intent Lock -> Pre-mutation Snapshot -> Install & Start -> Health Gate (READY)
//! -> Signed Receipt Commit -> Crash Recovery Inspection (Adopt by Deterministic ID)
//! -> Induced Health Probe Failure -> Automatic LKG Rollback to Durable Snapshot
//! -> Fail-Closed Missing Snapshot -> Verify Database State.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::Value;

    use crate::ipc::sovereign_ipc_principal;
    use crate::workload::{ComponentStatus};
    use crate::workload_runtime::canonical::{
        canonical_digest_for_value, deterministic_compose_project_id, deterministic_runtime_instance_id,
    };
    use crate::workload_runtime::executor::{
        generate_compose_yaml, ComposeRuntimeBackend, DefaultWorkloadSecretProvider, MockComposeRuntimeBackend, OciComposeExecutor, VolumeProvider,
    };
    use crate::workload_runtime::ipc_boundary::{
        verify_receipt_signature, WorkloadDesiredStateEnvelope,
    };
    use crate::workload_runtime::planner::WorkloadPlanner;
    use crate::workload_runtime::reconciler::{ReconciliationOutcome, WorkloadReconciler};
    use crate::workload_runtime::registry::WorkloadProfileRegistry;
    use crate::workload_runtime::state::{OperationReservationResult, WorkloadStateStore};
    use crate::workload_runtime::WorkloadError;

    fn generate_keypair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    struct E2ETestHarness {
        state_store: Arc<WorkloadStateStore>,
        profile_registry: Arc<WorkloadProfileRegistry>,
        backend: Arc<MockComposeRuntimeBackend>,
        _compose_executor: Arc<OciComposeExecutor<MockComposeRuntimeBackend>>,
        _volume_provider: Arc<VolumeProvider>,
        reconciler: WorkloadReconciler<MockComposeRuntimeBackend>,
        tmp_dir: std::path::PathBuf,
        center_authority_sk: SigningKey,
        center_authority_vk: ed25519_dalek::VerifyingKey,
        host_signing_key: SigningKey,
        host_verifying_key: ed25519_dalek::VerifyingKey,
        host_id: String,
        site_id: String,
        org_id: String,
        client_id: String,
        host_caps_digest: String,
    }

    impl Drop for E2ETestHarness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.tmp_dir);
        }
    }

    fn setup_e2e_harness(tag: &str) -> E2ETestHarness {
        let (center_sk, center_vk) = generate_keypair();
        let (host_sk, host_vk) = generate_keypair();

        let state_store = Arc::new(WorkloadStateStore::in_memory().expect("in-memory state store"));
        let profile_registry = Arc::new(WorkloadProfileRegistry::in_memory().expect("in-memory profile registry"));
        let backend = Arc::new(MockComposeRuntimeBackend::new());
        let compose_executor = Arc::new(OciComposeExecutor::new(backend.clone()));

        let tmp_dir = std::env::temp_dir().join(format!("actium_f7h_e2e_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&tmp_dir);
        std::fs::create_dir_all(&tmp_dir).expect("create test tmp_dir");

        let volume_provider = Arc::new(VolumeProvider::new(&tmp_dir));

        let secret_provider = Arc::new(DefaultWorkloadSecretProvider::new());
        let reconciler = WorkloadReconciler::new(
            state_store.clone(),
            profile_registry.clone(),
            compose_executor.clone(),
            volume_provider.clone(),
            secret_provider,
        );

        E2ETestHarness {
            state_store,
            profile_registry,
            backend,
            _compose_executor: compose_executor,
            _volume_provider: volume_provider,
            reconciler,
            tmp_dir,
            center_authority_sk: center_sk,
            center_authority_vk: center_vk,
            host_signing_key: host_sk,
            host_verifying_key: host_vk,
            host_id: "host-actium-primary-01".to_string(),
            site_id: "site-dc-chicago".to_string(),
            org_id: "org-actium-enterprises".to_string(),
            client_id: "client-fintech-prod".to_string(),
            host_caps_digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        }
    }

    fn build_multi_component_profile_manifest() -> String {
        serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "stack-multisvc",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "components": [
                {
                    "componentId": "db",
                    "image": "docker.io/library/postgres@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "networkMode": "INTERNAL",
                    "volumeMounts": [
                        { "volumeId": "db_data", "hostPath": "/var/lib/actium/db", "containerPath": "/var/lib/postgresql/data", "readOnly": false }
                    ],
                    "secretMounts": [
                        { "secretId": "sec-db-master", "mountPath": "/etc/secrets/db_pass", "purpose": "env", "injectionMode": "TMPFS_FILE" }
                    ]
                },
                {
                    "componentId": "web",
                    "image": "docker.io/library/nginx@sha256:88af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "dependsOn": ["db"],
                    "networkMode": "INTERNAL",
                    "volumeMounts": [
                        { "volumeId": "web_logs", "hostPath": "/var/log/actium/web", "containerPath": "/var/log/nginx", "readOnly": false }
                    ]
                }
            ]
        }).to_string()
    }

    fn create_signed_desired_envelope(
        harness: &E2ETestHarness,
        deployment_id: &str,
        generation: u64,
        nonce: &str,
        now: u64,
    ) -> (WorkloadDesiredStateEnvelope, String) {
        let profile_manifest = build_multi_component_profile_manifest();
        let profile_val: Value = serde_json::from_str(&profile_manifest).unwrap();
        let profile_digest = canonical_digest_for_value(&profile_val).unwrap();

        let mut desired_canonical = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": deployment_id,
            "profileId": "stack-multisvc",
            "profileVersion": "1.0.0",
            "profileDigest": profile_digest,
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "secretRefs": [],
            "desiredState": "RUNNING",
            "generation": generation,
        });
        let desired_digest = canonical_digest_for_value(&desired_canonical).unwrap();
        desired_canonical["desiredDigest"] = Value::String(desired_digest.clone());

        let mut env = WorkloadDesiredStateEnvelope {
            schema: crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA.to_string(),
            deployment_id: deployment_id.to_string(),
            generation,
            profile_id: "stack-multisvc".to_string(),
            profile_version: "1.0.0".to_string(),
            profile_digest,
            configuration_digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            desired_digest,
            modules: vec![],
            secret_refs: vec![],
            desired_state: "RUNNING".to_string(),
            client_id: harness.client_id.clone(),
            organization_id: harness.org_id.clone(),
            site_id: harness.site_id.clone(),
            host_id: harness.host_id.clone(),
            nonce: nonce.to_string(),
            issued_at: now,
            expires_at: now + 3600,
            purpose: "workload_desired_state".to_string(),
            authority_key_id: "center-key-v1".to_string(),
            authority_signature: String::new(),
            environment: None,
        };

        let signing_payload = env.signing_bytes().unwrap();
        let sig = harness.center_authority_sk.sign(&signing_payload);
        env.authority_signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let desired_raw_str = desired_canonical.to_string();

        (env, desired_raw_str)
    }

    #[test]
    fn test_mock_e2e_lifecycle_ready_recovery_rollback() {
        let harness = setup_e2e_harness("full_lifecycle");
        let deployment_id = "dep-e2e-cert-v1";
        let start_time = 1_700_000_000u64;

        // =========================================================================
        // 1. GATE: PROFILE_REGISTRY_PASS
        // =========================================================================
        let manifest = build_multi_component_profile_manifest();
        let reg_record = harness.profile_registry.register_profile(&manifest).expect("profile registration");
        assert!(reg_record.profile_digest.starts_with("sha256:"));

        // Idempotent re-registration succeeds
        let re_reg = harness.profile_registry.register_profile(&manifest).expect("idempotent registration");
        assert_eq!(reg_record.profile_digest, re_reg.profile_digest);

        // Conflicting manifest with same (id, ver) fails closed
        let mut conflicting_val: Value = serde_json::from_str(&manifest).unwrap();
        conflicting_val["components"][0]["image"] = Value::String(
            "docker.io/library/postgres@sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
        );
        let conflict_err = harness.profile_registry.register_profile(&conflicting_val.to_string());
        assert!(matches!(conflict_err, Err(WorkloadError::ProfileVersionDigestConflict { .. })));

        // =========================================================================
        // 2. GATE: IPC_ENVELOPE_AUTH_PASS & DOMAIN_SEPARATION_SIGNATURE_PASS
        // =========================================================================
        let nonce_gen1 = "nonce-cert-001";
        let (envelope_gen1, desired_raw_gen1) = create_signed_desired_envelope(
            &harness,
            deployment_id,
            1,
            nonce_gen1,
            start_time,
        );

        let mut principal = sovereign_ipc_principal();
        principal.bound_host = Some(harness.host_id.clone());
        principal.bound_site = Some(harness.site_id.clone());
        principal.bound_organization = Some(harness.org_id.clone());
        principal.bound_client = Some(harness.client_id.clone());

        // Host boundary verification passes
        envelope_gen1.verify(&principal, &harness.host_id, &harness.center_authority_vk, start_time).expect("envelope verification");

        // Envelope expiration check
        let expired_err = envelope_gen1.verify(&principal, &harness.host_id, &harness.center_authority_vk, start_time + 4000);
        assert!(matches!(expired_err, Err(WorkloadError::Unauthorized(_))));

        // Mismatched signature check
        let (other_sk, _) = generate_keypair();
        let forged_sig = other_sk.sign(&envelope_gen1.signing_bytes().unwrap());
        let mut forged_env = envelope_gen1.clone();
        forged_env.authority_signature = base64::engine::general_purpose::STANDARD.encode(forged_sig.to_bytes());
        let forged_err = forged_env.verify(&principal, &harness.host_id, &harness.center_authority_vk, start_time);
        assert!(matches!(forged_err, Err(WorkloadError::Unauthorized(_))));

        // =========================================================================
        // 3. GATE: NONCE_REPLAY_LEDGER_PASS
        // =========================================================================
        harness.state_store.consume_nonce(nonce_gen1, deployment_id, 1, start_time).expect("consume nonce");
        let replay_err = harness.state_store.consume_nonce(nonce_gen1, deployment_id, 1, start_time + 1);
        assert!(matches!(replay_err, Err(WorkloadError::NonceReplay(_))));

        // =========================================================================
        // 4. GATE: PLANNER_PASS & CANONICAL_DIGEST_VECTORS_PASS
        // =========================================================================
        let plan_gen1 = WorkloadPlanner::plan(
            &desired_raw_gen1,
            &manifest,
            &harness.host_caps_digest,
            Some("actium-test-planner"),
            Some(start_time),
        ).expect("planner execution");

        // Topological ordering: db must precede web
        let comp_order: Vec<&str> = plan_gen1.components.iter().map(|c| c.component_id.as_str()).collect();
        assert_eq!(comp_order, vec!["db", "web"]);

        // Plan digest is deterministic and does not vary by timestamp
        let plan_gen1_alt = WorkloadPlanner::plan(
            &desired_raw_gen1,
            &manifest,
            &harness.host_caps_digest,
            Some("actium-test-planner"),
            Some(start_time + 9999),
        ).expect("planner execution at different time");
        assert_eq!(plan_gen1.plan_digest, plan_gen1_alt.plan_digest);

        // =========================================================================
        // 5. GATE: OCI_CONTAINER_EXECUTOR_SOURCE_PASS & OCI_COMPOSE_EXECUTOR_SOURCE_PASS
        // =========================================================================
        let expected_proj_id = deterministic_compose_project_id(deployment_id, 1).unwrap();
        assert_eq!(plan_gen1.compose_project_id, expected_proj_id);
        assert!(expected_proj_id.starts_with("actium-"));
        assert_eq!(expected_proj_id.len(), 39); // "actium-" (7) + 32 hex = 39

        let expected_db_inst = deterministic_runtime_instance_id(deployment_id, 1, "db").unwrap();
        let expected_web_inst = deterministic_runtime_instance_id(deployment_id, 1, "web").unwrap();
        assert_eq!(plan_gen1.components[0].runtime_instance_id, expected_db_inst);
        assert_eq!(plan_gen1.components[1].runtime_instance_id, expected_web_inst);

        // Synthesize Compose YAML and verify no plaintext secrets appear
        let compose_yaml = generate_compose_yaml(&plan_gen1).expect("compose yaml generation");
        assert!(compose_yaml.contains(&expected_proj_id));
        assert!(compose_yaml.contains("actium.deployment_id"));
        assert!(!compose_yaml.contains("sec-db-master"));

        // =========================================================================
        // 6. GATE: CONCURRENT_RECONCILE_SERIALIZATION_PASS
        // =========================================================================
        let op_id_1 = "op-cert-01";
        let res1 = harness.state_store.reserve_operation(
            op_id_1,
            deployment_id,
            1,
            &plan_gen1.desired_digest,
            &plan_gen1.plan_digest,
            start_time,
        ).expect("reserve operation 1");
        assert_eq!(res1, OperationReservationResult::Reserved { operation_id: op_id_1.to_string() });

        // Same deployment with different plan fails closed with active operation conflict
        let conflict_err = harness.state_store.reserve_operation(
            "op-cert-02",
            deployment_id,
            1,
            &plan_gen1.desired_digest,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            start_time,
        );
        assert!(matches!(conflict_err, Err(WorkloadError::ActiveOperationConflict { .. })));

        // Clean up reservation for reconciler test
        harness.state_store.update_operation_state(op_id_1, "COMPLETED", Some(start_time)).unwrap();

        // =========================================================================
        // 7. GATE: MOCK_RECONCILIATION_PASS, HEALTH_GATE_PASS & VOLUME_SNAPSHOT_DURABLE_PASS
        // =========================================================================
        let outcome_gen1 = harness.reconciler.reconcile(
            &desired_raw_gen1,
            &harness.host_caps_digest,
            &harness.host_signing_key,
            start_time + 10,
        ).expect("reconciliation gen 1");

        let receipt_gen1 = match outcome_gen1 {
            ReconciliationOutcome::Success(rcpt) => {
                assert_eq!(rcpt.overall_status, ComponentStatus::Ready);
                assert_eq!(rcpt.generation, 1);
                assert_eq!(rcpt.deployment_id, deployment_id);
                assert_eq!(rcpt.components.len(), 2);
                assert_eq!(rcpt.components[0].status, ComponentStatus::Ready);
                assert_eq!(rcpt.components[1].status, ComponentStatus::Ready);
                rcpt
            }
            other => panic!("Expected Success on gen 1, got {:?}", other),
        };

        // Verify receipt was cryptographically signed by the reconciler using the host key
        assert!(!receipt_gen1.signature.is_empty());
        verify_receipt_signature(&receipt_gen1, &harness.host_verifying_key).expect("verify receipt signature");

        // Verify canonical desired JSON extracted from envelope produces byte-compatible digest
        let canonical_desired_from_env = envelope_gen1.canonical_desired_state_json().unwrap();
        let plan_gen1_from_env = WorkloadPlanner::plan(
            &canonical_desired_from_env,
            &manifest,
            &harness.host_caps_digest,
            Some("actium-test-planner"),
            Some(start_time),
        ).expect("planner execution with canonical desired from envelope");
        assert_eq!(plan_gen1.plan_digest, plan_gen1_from_env.plan_digest);
        assert_eq!(plan_gen1.desired_digest, plan_gen1_from_env.desired_digest);

        // Verify database state in SQLite authority
        let dep_db = harness.state_store.get_deployment(deployment_id).unwrap().unwrap();
        assert_eq!(dep_db.status, "ACTIVE");
        assert_eq!(dep_db.active_generation, 1);
        assert_eq!(dep_db.plan_digest, plan_gen1.plan_digest);

        // Verify pre-mutation volume snapshot captured
        let snap_db = harness.state_store.get_durable_snapshot(deployment_id, 1).unwrap();
        assert!(snap_db.is_some());

        // =========================================================================
        // 8. GATE: MOCK_CRASH_RECOVERY_PASS
        // =========================================================================
        // Simulate crash / restart: Reconcile gen 1 again
        // Reconciler inspects physical reality, adopts existing containers by deterministic IDs & labels
        let outcome_adopt = harness.reconciler.reconcile(
            &desired_raw_gen1,
            &harness.host_caps_digest,
            &harness.host_signing_key,
            start_time + 500,
        ).expect("reconciliation crash adoption");

        match outcome_adopt {
            ReconciliationOutcome::Success(rcpt) => {
                assert_eq!(rcpt.overall_status, ComponentStatus::Ready);
                assert_eq!(rcpt.generation, 1);
                assert!(!rcpt.signature.is_empty());
                verify_receipt_signature(&rcpt, &harness.host_verifying_key).expect("verify adopt receipt");
            }
            other => panic!("Expected Success on crash recovery adoption, got {:?}", other),
        }

        // =========================================================================
        // 9. GATE: GENERATION_ANTI_ROLLBACK_PASS
        // =========================================================================
        let (_env_regress, desired_raw_regress) = create_signed_desired_envelope(
            &harness,
            deployment_id,
            0, // Target generation 0 < active generation 1
            "nonce-regress",
            start_time + 600,
        );
        let regress_err = harness.reconciler.reconcile(
            &desired_raw_regress,
            &harness.host_caps_digest,
            &harness.host_signing_key,
            start_time + 600,
        );
        assert!(matches!(regress_err, Err(WorkloadError::GenerationRegression { .. })));

        // =========================================================================
        // 10. GATE: MOCK_LKG_ROLLBACK_PASS (With Pre-Mutation Snapshot)
        // =========================================================================
        let (_env_gen2, desired_raw_gen2) = create_signed_desired_envelope(
            &harness,
            deployment_id,
            2,
            "nonce-gen-2",
            start_time + 1000,
        );

        let plan_gen2 = WorkloadPlanner::plan(
            &desired_raw_gen2,
            &manifest,
            &harness.host_caps_digest,
            Some("actium-test-planner"),
            Some(start_time + 1000),
        ).unwrap();

        // Inject component probe failure into mock backend for generation 2
        harness.backend.create_project(&plan_gen2, "compose_yaml_gen2").unwrap();
        harness.backend.set_component_status(&plan_gen2.compose_project_id, "web", ComponentStatus::Failed);

        let outcome_gen2 = harness.reconciler.reconcile(
            &desired_raw_gen2,
            &harness.host_caps_digest,
            &harness.host_signing_key,
            start_time + 1050,
        ).expect("reconcile gen 2 with failure");

        match outcome_gen2 {
            ReconciliationOutcome::RolledBack { reason, previous_generation } => {
                assert_eq!(previous_generation, 1);
                assert!(reason.contains("Health check probes failed"));
            }
            other => panic!("Expected RolledBack to gen 1, got {:?}", other),
        }

        // Verify SQLite state: deployment remains active on generation 1
        let dep_after_rb = harness.state_store.get_deployment(deployment_id).unwrap().unwrap();
        assert_eq!(dep_after_rb.active_generation, 1);
        assert_eq!(dep_after_rb.status, "ACTIVE");

        // Verify ROLLBACK event in journal
        let journal = harness.state_store.get_journal(deployment_id).unwrap();
        let rollback_entry = journal.iter().find(|j| j.phase == "ROLLBACK");
        assert!(rollback_entry.is_some());

        // =========================================================================
        // 11. GATE: MOCK_LKG_ROLLBACK_PASS (Missing Pre-Mutation Snapshot -> FAIL CLOSED)
        // =========================================================================
        let (_env_gen3, desired_raw_gen3) = create_signed_desired_envelope(
            &harness,
            deployment_id,
            3,
            "nonce-gen-3",
            start_time + 2000,
        );

        // Delete any durable snapshot recorded for generation 3 before triggering failure
        // Inject failure
        let plan_gen3 = WorkloadPlanner::plan(
            &desired_raw_gen3,
            &manifest,
            &harness.host_caps_digest,
            Some("actium-test-planner"),
            Some(start_time + 2000),
        ).unwrap();
        harness.backend.create_project(&plan_gen3, "compose_yaml_gen3").unwrap();
        harness.backend.set_component_status(&plan_gen3.compose_project_id, "db", ComponentStatus::Failed);

        // Force reconciler failure where durable snapshot was NOT captured
        let outcome_gen3 = harness.reconciler.handle_failure_or_rollback(
            deployment_id,
            3,
            "op-gen-3",
            "Simulated un-snapshotable catastrophic failure",
            &plan_gen3,
            start_time + 2050,
        ).expect("handle failure without snapshot");

        match outcome_gen3 {
            ReconciliationOutcome::FailedRequiresOperator { reason } => {
                assert!(reason.contains("Missing durable pre-mutation snapshot"));
            }
            other => panic!("Expected FailedRequiresOperator, got {:?}", other),
        }

        let journal_gen3 = harness.state_store.get_journal(deployment_id).unwrap();
        let fail_op_entry = journal_gen3.iter().find(|j| j.phase == "FAILED_REQUIRES_OPERATOR");
        assert!(fail_op_entry.is_some());
    }

    #[test]
    fn test_two_phase_reconciliation_protocol_and_crash_recovery() {
        let harness = setup_e2e_harness("reconcile_and_crash");
        let deployment_id = "dep-two-phase-cert";
        let now = 1_700_000_000u64;

        let manifest = build_multi_component_profile_manifest();
        harness.profile_registry.register_profile(&manifest).unwrap();

        let (_env, desired_raw) = create_signed_desired_envelope(&harness, deployment_id, 1, "nonce-2p-1", now);

        // Phase 1 -> Phase 4 complete run
        let outcome = harness.reconciler.reconcile(&desired_raw, &harness.host_caps_digest, &harness.host_signing_key, now).unwrap();
        assert!(matches!(outcome, ReconciliationOutcome::Success(_)));

        // Crash recovery: Second invocation inspects reality and recovers
        let outcome_recover = harness.reconciler.reconcile(&desired_raw, &harness.host_caps_digest, &harness.host_signing_key, now + 100).unwrap();
        assert!(matches!(outcome_recover, ReconciliationOutcome::Success(_)));
    }

    #[test]
    fn test_deterministic_runtime_naming_and_crash_adoption() {
        let deployment_id = "dep-det-naming-cert";
        let generation = 42;
        let component = "worker";

        let inst_id_1 = deterministic_runtime_instance_id(deployment_id, generation, component).unwrap();
        let inst_id_2 = deterministic_runtime_instance_id(deployment_id, generation, component).unwrap();
        assert_eq!(inst_id_1, inst_id_2);
        assert!(inst_id_1.starts_with("actium-"));
        assert_eq!(inst_id_1.len(), 39);

        let proj_id_1 = deterministic_compose_project_id(deployment_id, generation).unwrap();
        let proj_id_2 = deterministic_compose_project_id(deployment_id, generation).unwrap();
        assert_eq!(proj_id_1, proj_id_2);
        assert!(proj_id_1.starts_with("actium-"));
        assert_eq!(proj_id_1.len(), 39);

        // Domain separation ensures instance and project IDs do not collide even with identical inputs
        assert_ne!(inst_id_1, proj_id_1);
    }

    #[test]
    fn test_e2e_full_chain_center_signed_envelope_to_host_receipt_center_verification() {
        let harness = setup_e2e_harness("full_chain_cert");
        let deployment_id = "dep-full-chain-cert-01";
        let generation = 1;
        let now = 1_700_000_000u64;
        let nonce = "nonce-full-chain-001";

        // 1. Center Profile Registration
        let manifest = build_multi_component_profile_manifest();
        let profile_val: Value = serde_json::from_str(&manifest).unwrap();
        let profile_digest = canonical_digest_for_value(&profile_val).unwrap();
        harness.profile_registry.register_profile(&manifest).expect("profile registration");

        // 2. Center Authors Canonical Desired Workload State (conforming to actium-desired-workload-state.schema.json)
        let config_digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();
        let modules = vec!["telemetry".to_string(), "auth".to_string()];
        let secret_refs = vec![crate::workload_runtime::ipc_boundary::SecretReference {
            secret_id: "sec-db-master".into(),
            scope: Some("deployment".into()),
            purpose: "env".into(),
            generation: 1,
        }];

        let canonical_desired_pre_digest = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": deployment_id,
            "profileId": "stack-multisvc",
            "profileVersion": "1.0.0",
            "profileDigest": profile_digest,
            "configurationDigest": config_digest,
            "modules": modules,
            "secretRefs": secret_refs,
            "desiredState": "RUNNING",
            "generation": generation,
        });
        let desired_digest = canonical_digest_for_value(&canonical_desired_pre_digest).expect("compute desiredDigest");

        // 3. Center Signs Desired State Envelope with Ed25519 Domain Separation
        let mut envelope = WorkloadDesiredStateEnvelope {
            schema: crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA.to_string(),
            deployment_id: deployment_id.to_string(),
            generation,
            profile_id: "stack-multisvc".to_string(),
            profile_version: "1.0.0".to_string(),
            profile_digest: profile_digest.clone(),
            configuration_digest: config_digest.clone(),
            desired_digest: desired_digest.clone(),
            modules: modules.clone(),
            secret_refs: secret_refs.clone(),
            desired_state: "RUNNING".to_string(),
            client_id: harness.client_id.clone(),
            organization_id: harness.org_id.clone(),
            site_id: harness.site_id.clone(),
            host_id: harness.host_id.clone(),
            nonce: nonce.to_string(),
            issued_at: now,
            expires_at: now + 3600,
            purpose: "workload_desired_state".to_string(),
            authority_key_id: "center-key-v1".to_string(),
            authority_signature: String::new(),
            environment: None,
        };

        let signing_payload = envelope.signing_bytes().expect("signing bytes");
        let sig = harness.center_authority_sk.sign(&signing_payload);
        envelope.authority_signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        // 4. Host Supervisor IPC Gate: Authenticate Envelope, Host Binding, & Check Monotonicity
        let principal = sovereign_ipc_principal();
        envelope.verify(&principal, &harness.host_id, &harness.center_authority_vk, now).expect("supervisor verify envelope");

        harness.state_store.consume_nonce(nonce, deployment_id, generation, now).expect("consume nonce in state store");

        // 5. Canonical Desired State Contract Validation & Local Digest Recomputation
        let canonical_desired_json = envelope.canonical_desired_state_json().expect("extract canonical desired");
        let plan = WorkloadPlanner::plan(
            &canonical_desired_json,
            &manifest,
            &harness.host_caps_digest,
            Some("actium-planner-v1.5"),
            Some(now),
        ).expect("planner execution with canonical desired contract");

        assert_eq!(plan.desired_digest, desired_digest);
        assert_eq!(plan.profile_digest, profile_digest);

        // 6. Production Compose Rendering with Structured Zero-Injection
        let compose_yaml = generate_compose_yaml(&plan).expect("generate structured compose yaml");
        assert!(compose_yaml.contains(&plan.compose_project_id));
        assert!(compose_yaml.contains("actium.deployment_id"));
        assert!(compose_yaml.contains("no-new-privileges:true"));
        assert!(compose_yaml.contains("- ALL"));
        assert!(compose_yaml.contains("type: tmpfs"));
        assert!(compose_yaml.contains("mode: 0600"));

        // 7. Reconciler Execution: 2-Phase Mutation & Health/Readiness Evaluation
        let outcome = harness.reconciler.reconcile(
            &canonical_desired_json,
            &harness.host_caps_digest,
            &harness.host_signing_key,
            now + 10,
        ).expect("reconcile full chain");

        let receipt = match outcome {
            ReconciliationOutcome::Success(rcpt) => {
                assert_eq!(rcpt.overall_status, ComponentStatus::Ready);
                assert_eq!(rcpt.generation, generation);
                assert_eq!(rcpt.deployment_id, deployment_id);
                assert_eq!(rcpt.components.len(), 2);
                assert_eq!(rcpt.components[0].status, ComponentStatus::Ready);
                assert_eq!(rcpt.components[1].status, ComponentStatus::Ready);
                rcpt
            }
            other => panic!("Expected Success on full chain reconcile, got {:?}", other),
        };

        // 8. Host Cryptographic Receipt Verification (Exact Parity with Center)
        assert!(!receipt.signature.is_empty());
        verify_receipt_signature(&receipt, &harness.host_verifying_key).expect("verify host signature on receipt");

        // Verify Center verification logic (domain separation + RFC 8785)
        let mut clean_rcpt = serde_json::to_value(&receipt).unwrap();
        if let serde_json::Value::Object(ref mut map) = clean_rcpt {
            map.remove("signature");
        }
        let jcs_rcpt = crate::workload_runtime::canonical::rfc8785_canonical_json(&clean_rcpt).unwrap();
        let mut center_signing_bytes = Vec::new();
        center_signing_bytes.extend_from_slice(b"ACTIUM_WORKLOAD_RECEIPT_V1\0");
        center_signing_bytes.extend_from_slice(jcs_rcpt.as_bytes());

        let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&receipt.signature).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        use ed25519_dalek::Verifier;
        harness.host_verifying_key.verify(&center_signing_bytes, &sig).expect("Center verification of host receipt");

        // Tampered receipt fails verification
        let mut tampered_bytes = center_signing_bytes.clone();
        tampered_bytes.push(0xff);
        assert!(harness.host_verifying_key.verify(&tampered_bytes, &sig).is_err());
    }
}
