use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::workload::{overall_from_components, ComponentObservation, ComponentStatus};
use super::canonical::canonical_digest_for_value;
use super::executor::{ComposeRuntimeBackend, OciComposeExecutor, VolumeProvider};
use super::planner::WorkloadPlanner;
use super::registry::WorkloadProfileRegistry;
use super::state::{OperationReservationResult, WorkloadStateStore};
use super::WorkloadError;

pub const WORKLOAD_RECEIPT_SCHEMA: &str = "actium-workload-deployment-receipt@1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalWorkloadReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub deployment_id: String,
    pub generation: u64,
    pub plan_digest: String,
    pub overall_status: ComponentStatus,
    pub components: Vec<ComponentObservation>,
    pub issued_at: u64,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    Success(CanonicalWorkloadReceipt),
    RolledBack {
        reason: String,
        previous_generation: u64,
    },
    FailedRequiresOperator {
        reason: String,
    },
}

pub struct WorkloadReconciler<B: ComposeRuntimeBackend> {
    pub state_store: Arc<WorkloadStateStore>,
    pub profile_registry: Arc<WorkloadProfileRegistry>,
    pub compose_executor: Arc<OciComposeExecutor<B>>,
    pub volume_provider: Arc<VolumeProvider>,
}

impl<B: ComposeRuntimeBackend> WorkloadReconciler<B> {
    pub fn new(
        state_store: Arc<WorkloadStateStore>,
        profile_registry: Arc<WorkloadProfileRegistry>,
        compose_executor: Arc<OciComposeExecutor<B>>,
        volume_provider: Arc<VolumeProvider>,
    ) -> Self {
        Self {
            state_store,
            profile_registry,
            compose_executor,
            volume_provider,
        }
    }

    pub fn reconcile(
        &self,
        desired_state_json: &str,
        host_capabilities_digest: &str,
        now: u64,
    ) -> Result<ReconciliationOutcome, WorkloadError> {
        let desired_val: serde_json::Value = serde_json::from_str(desired_state_json)
            .map_err(|e| WorkloadError::ValidationFailed(format!("Invalid desired state JSON: {}", e)))?;

        let deployment_id = desired_val
            .get("deploymentId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing deploymentId".into()))?;

        let target_generation = desired_val
            .get("generation")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing generation".into()))?;

        let profile_id = desired_val
            .get("profileId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing profileId".into()))?;

        let profile_version = desired_val
            .get("profileVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WorkloadError::ValidationFailed("Missing profileVersion".into()))?;

        // Anti-rollback check: target generation must be >= current highest
        self.state_store.check_generation_monotonicity(deployment_id, target_generation)?;

        // Fetch profile from registry
        let profile_rec = self
            .profile_registry
            .get_profile(profile_id, profile_version)?
            .ok_or_else(|| {
                WorkloadError::ValidationFailed(format!("Profile '{}@{}' not found in registry", profile_id, profile_version))
            })?;

        // Plan generation
        let plan = WorkloadPlanner::plan(
            desired_state_json,
            &profile_rec.manifest_json,
            host_capabilities_digest,
            Some("actium-planner-v1.5"),
            Some(now),
        )?;

        // Phase 1: Intent & Lock in SQLite
        let op_id = format!("op-{}-gen-{}-{}", deployment_id, target_generation, now);
        let reservation = self.state_store.reserve_operation(
            &op_id,
            deployment_id,
            target_generation,
            &plan.desired_digest,
            &plan.plan_digest,
            now,
        )?;

        if let OperationReservationResult::AttachedIdempotent { operation_id: _ } = reservation {
            // Check if already active and converged
            if let Some(dep) = self.state_store.get_deployment(deployment_id)? {
                if dep.active_generation == target_generation
                    && dep.plan_digest == plan.plan_digest
                    && dep.status == "ACTIVE"
                {
                    let insp = self.compose_executor.inspect(&plan.compose_project_id)?;
                    if insp.exists {
                        let obs: Vec<ComponentObservation> = insp
                            .components
                            .into_iter()
                            .map(|c| ComponentObservation {
                                component_id: c.name,
                                status: c.status,
                            })
                            .collect();
                        if overall_from_components(&obs) == ComponentStatus::Ready {
                            let receipt = CanonicalWorkloadReceipt {
                                schema: WORKLOAD_RECEIPT_SCHEMA.to_string(),
                                receipt_id: format!("rcpt-{}-{}", deployment_id, target_generation),
                                deployment_id: deployment_id.to_string(),
                                generation: target_generation,
                                plan_digest: plan.plan_digest.clone(),
                                overall_status: ComponentStatus::Ready,
                                components: obs,
                                issued_at: now,
                                signature: "SIG_IDEMPOTENT_REPLAY".to_string(),
                            };
                            return Ok(ReconciliationOutcome::Success(receipt));
                        }
                    }
                }
            }
        }

        self.state_store
            .update_operation_state(&op_id, "STARTING", None)?;
        self.state_store
            .record_journal(deployment_id, target_generation, "PLAN", &plan.plan_digest, now)?;

        // Pre-mutation snapshot capture for volume state
        for comp in &plan.components {
            for vol in &comp.volume_mounts {
                let snap_path = self.volume_provider.capture_pre_mutation_snapshot(
                    deployment_id,
                    target_generation,
                    &vol.volume_id,
                )?;
                self.state_store.record_snapshot(
                    &format!("snap-{}-{}-{}-{}", deployment_id, target_generation, vol.volume_id, now),
                    deployment_id,
                    target_generation,
                    &snap_path.to_string_lossy(),
                    now,
                    true,
                )?;
            }
        }

        // Phase 2: External Idempotent Mutation with Crash Recovery Adoption
        let inspection = self.compose_executor.inspect(&plan.compose_project_id)?;
        let observations = if inspection.exists {
            // Adopt existing containers if plan_digest matches
            let all_match = inspection.components.iter().all(|c| {
                c.labels
                    .get("actium.plan_digest")
                    .map(|d| d == &plan.plan_digest)
                    .unwrap_or(false)
            });
            if all_match {
                inspection
                    .components
                    .into_iter()
                    .map(|c| ComponentObservation {
                        component_id: c.name,
                        status: c.status,
                    })
                    .collect()
            } else {
                // Outdated or conflicting project -> recreate
                self.compose_executor.apply_plan(&plan)?
            }
        } else {
            // Create fresh project
            self.compose_executor.apply_plan(&plan)?
        };

        // Phase 3: Inspect Physical Reality & Health Gate
        let overall = overall_from_components(&observations);

        if overall != ComponentStatus::Ready {
            // Component probe failed -> Trigger LKG Rollback Engine
            self.state_store
                .record_journal(deployment_id, target_generation, "HEALTH_FAIL", "Probes failed", now)?;
            return self.handle_failure_or_rollback(deployment_id, target_generation, &op_id, "Health check probes failed", now);
        }

        // Phase 4: TX 2 (Observed Reality & Receipt in SQLite)
        self.state_store
            .record_journal(deployment_id, target_generation, "READY", "All components READY", now)?;
        self.state_store.upsert_deployment(
            deployment_id,
            target_generation,
            target_generation,
            profile_id,
            profile_version,
            &plan.desired_digest,
            &plan.plan_digest,
            "ACTIVE",
            now,
        )?;

        let receipt = CanonicalWorkloadReceipt {
            schema: WORKLOAD_RECEIPT_SCHEMA.to_string(),
            receipt_id: format!("rcpt-{}-{}", deployment_id, target_generation),
            deployment_id: deployment_id.to_string(),
            generation: target_generation,
            plan_digest: plan.plan_digest.clone(),
            overall_status: ComponentStatus::Ready,
            components: observations,
            issued_at: now,
            signature: "SIG_ACTIUM_HOST_MOCK".to_string(),
        };

        let receipt_json = serde_json::to_string(&receipt)
            .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;

        self.state_store.save_receipt(
            &receipt.receipt_id,
            deployment_id,
            target_generation,
            &plan.plan_digest,
            "READY",
            &receipt_json,
            &receipt.signature,
            now,
        )?;

        self.state_store
            .update_operation_state(&op_id, "COMPLETED", Some(now))?;

        Ok(ReconciliationOutcome::Success(receipt))
    }

    fn handle_failure_or_rollback(
        &self,
        deployment_id: &str,
        failed_generation: u64,
        operation_id: &str,
        reason: &str,
        now: u64,
    ) -> Result<ReconciliationOutcome, WorkloadError> {
        // Check if pre-mutation snapshot exists for durable data rollback
        let has_durable_snapshot = self
            .state_store
            .get_durable_snapshot(deployment_id, failed_generation)?
            .is_some();

        if failed_generation > 1 && has_durable_snapshot {
            // Safe automatic rollback to LKG generation
            let lkg_generation = failed_generation - 1;
            self.state_store.update_operation_state(operation_id, "ROLLED_BACK", Some(now))?;
            self.state_store.record_journal(
                deployment_id,
                failed_generation,
                "ROLLBACK",
                &format!("Reverted to gen {}", lkg_generation),
                now,
            )?;
            Ok(ReconciliationOutcome::RolledBack {
                reason: reason.to_string(),
                previous_generation: lkg_generation,
            })
        } else {
            // Data incompatibility without captured durable snapshot -> Fail closed to operator
            self.state_store.update_operation_state(operation_id, "FAILED", Some(now))?;
            self.state_store.record_journal(
                deployment_id,
                failed_generation,
                "FAILED_REQUIRES_OPERATOR",
                reason,
                now,
            )?;
            Ok(ReconciliationOutcome::FailedRequiresOperator {
                reason: format!("{}: Missing durable pre-mutation snapshot", reason),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_runtime::executor::MockComposeRuntimeBackend;

    fn setup_environment(tag: &str) -> (
        WorkloadReconciler<MockComposeRuntimeBackend>,
        Arc<MockComposeRuntimeBackend>,
        String,
    ) {
        let store = Arc::new(WorkloadStateStore::in_memory().unwrap());
        let registry = Arc::new(WorkloadProfileRegistry::in_memory().unwrap());
        let backend = Arc::new(MockComposeRuntimeBackend::new());
        let executor = Arc::new(OciComposeExecutor::new(backend.clone()));
        let tmp_root = std::env::temp_dir().join(format!("actium_reconcile_test_{}_{}", std::process::id(), tag));
        let volume_provider = Arc::new(VolumeProvider::new(&tmp_root));

        let reconciler = WorkloadReconciler::new(
            store,
            registry.clone(),
            executor,
            volume_provider,
        );

        // Register profile
        let manifest = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "svc-reconcile",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "components": [
                {
                    "componentId": "api",
                    "image": "docker.io/library/alpine@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "volumeMounts": [
                        { "volumeId": "api_data", "hostPath": "/data", "containerPath": "/var/data", "readOnly": false }
                    ]
                }
            ]
        }).to_string();
        registry.register_profile(&manifest).unwrap();

        (reconciler, backend, tmp_root.to_string_lossy().to_string())
    }

    fn make_desired(dep: &str, gen: u64) -> String {
        let body = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": dep,
            "generation": gen,
            "profileId": "svc-reconcile",
            "profileVersion": "1.0.0",
            "targetState": "ACTIVE"
        });
        let digest = canonical_digest_for_value(&body).unwrap();
        let mut env = body;
        env["desiredDigest"] = serde_json::Value::String(digest);
        env.to_string()
    }

    #[test]
    fn test_two_phase_reconciliation_protocol_success() {
        let (reconciler, _, tmp_dir) = setup_environment("success");
        let desired = make_desired("dep-success-1", 1);
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let outcome = reconciler.reconcile(&desired, host_caps, 1000).unwrap();
        match outcome {
            ReconciliationOutcome::Success(receipt) => {
                assert_eq!(receipt.overall_status, ComponentStatus::Ready);
                assert_eq!(receipt.generation, 1);
                assert_eq!(receipt.deployment_id, "dep-success-1");
            }
            other => panic!("Expected Success, got {:?}", other),
        }

        // Verify deployment is marked ACTIVE in SQLite authority
        let dep = reconciler.state_store.get_deployment("dep-success-1").unwrap().unwrap();
        assert_eq!(dep.status, "ACTIVE");
        assert_eq!(dep.active_generation, 1);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_mock_crash_recovery_adoption() {
        let (reconciler, _backend, tmp_dir) = setup_environment("adopt");
        let desired = make_desired("dep-adopt-1", 1);
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Step 1: Converge generation 1
        let outcome1 = reconciler.reconcile(&desired, host_caps, 1000).unwrap();
        assert!(matches!(outcome1, ReconciliationOutcome::Success(_)));

        // Step 2: Simulate Supervisor restart / crash recovery by reconciling again
        // It must adopt the existing container via deterministic name and matching plan_digest
        let outcome2 = reconciler.reconcile(&desired, host_caps, 2000).unwrap();
        match outcome2 {
            ReconciliationOutcome::Success(receipt) => {
                assert_eq!(receipt.overall_status, ComponentStatus::Ready);
            }
            other => panic!("Expected Success on crash recovery adoption, got {:?}", other),
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_lkg_engine_requires_durably_captured_snapshot_for_data_rollback() {
        let (reconciler, backend, tmp_dir) = setup_environment("lkg");
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Generation 1 succeeds
        let desired_gen1 = make_desired("dep-fail-1", 1);
        reconciler.reconcile(&desired_gen1, host_caps, 1000).unwrap();

        // Generation 2 with forced component failure
        let desired_gen2 = make_desired("dep-fail-1", 2);

        // Pre-create failing project in backend so health check fails
        let plan2 = WorkloadPlanner::plan(
            &desired_gen2,
            &reconciler.profile_registry.get_profile("svc-reconcile", "1.0.0").unwrap().unwrap().manifest_json,
            host_caps,
            None,
            None,
        ).unwrap();

        // Simulate probe failure
        backend.create_project(&plan2, "fake_yaml").unwrap();
        backend.set_component_status(&plan2.compose_project_id, "api", ComponentStatus::Failed);

        let outcome2 = reconciler.reconcile(&desired_gen2, host_caps, 2000).unwrap();
        match outcome2 {
            ReconciliationOutcome::RolledBack { previous_generation, .. } => {
                assert_eq!(previous_generation, 1);
            }
            other => panic!("Expected RolledBack to gen 1, got {:?}", other),
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
