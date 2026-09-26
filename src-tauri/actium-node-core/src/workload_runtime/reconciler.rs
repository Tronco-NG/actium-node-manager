use std::path::PathBuf;
use std::sync::Arc;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::workload::{overall_from_components, ComponentObservation, ComponentStatus};
use super::canonical::canonical_digest_for_value;
use super::executor::{
    validate_path_identifier, ComposeRuntimeBackend, OciComposeExecutor, VolumeProvider, WorkloadIngressProvider,
    WorkloadSecretProvider,
};
use super::planner::{CanonicalWorkloadPlan, WorkloadPlanner};
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
    pub secret_provider: Arc<dyn WorkloadSecretProvider>,
    pub ingress_provider: Arc<dyn WorkloadIngressProvider>,
}

impl<B: ComposeRuntimeBackend> WorkloadReconciler<B> {
    pub fn new(
        state_store: Arc<WorkloadStateStore>,
        profile_registry: Arc<WorkloadProfileRegistry>,
        compose_executor: Arc<OciComposeExecutor<B>>,
        volume_provider: Arc<VolumeProvider>,
        secret_provider: Arc<dyn WorkloadSecretProvider>,
        ingress_provider: Arc<dyn WorkloadIngressProvider>,
    ) -> Self {
        Self {
            state_store,
            profile_registry,
            compose_executor,
            volume_provider,
            secret_provider,
            ingress_provider,
        }
    }

    pub fn reconcile(
        &self,
        desired_state_json: &str,
        host_capabilities_digest: &str,
        host_signing_key: &SigningKey,
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

        let desired_digest = desired_val
            .get("desiredDigest")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| canonical_digest_for_value(&desired_val).unwrap_or_default());

        // Anti-rollback check: target generation must be >= current highest, and same gen requires matching digest
        self.state_store.check_generation_monotonicity(deployment_id, target_generation, &desired_digest)?;

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

        let is_stopped = plan.desired_state == "STOPPED";

        if let OperationReservationResult::AttachedIdempotent { operation_id: _ } = reservation {
            let expected_dep_status = if is_stopped { "STOPPED" } else { "ACTIVE" };
            let expected_overall = if is_stopped { ComponentStatus::Stopped } else { ComponentStatus::Ready };

            if let Some(dep) = self.state_store.get_deployment(deployment_id)? {
                if dep.active_generation == target_generation
                    && dep.plan_digest == plan.plan_digest
                    && dep.status == expected_dep_status
                {
                    let insp = self.compose_executor.inspect(&plan.compose_project_id)?;
                    let obs: Vec<ComponentObservation> = if insp.exists {
                        insp.components
                            .into_iter()
                            .map(|c| ComponentObservation {
                                component_id: c.name,
                                status: c.status,
                            })
                            .collect()
                    } else if is_stopped {
                        plan.components
                            .iter()
                            .map(|c| ComponentObservation {
                                component_id: c.component_id.clone(),
                                status: ComponentStatus::Stopped,
                            })
                            .collect()
                    } else {
                        vec![]
                    };

                    if overall_from_components(&obs) == expected_overall {
                        let mut receipt = CanonicalWorkloadReceipt {
                            schema: WORKLOAD_RECEIPT_SCHEMA.to_string(),
                            receipt_id: format!("rcpt-{}-{}", deployment_id, target_generation),
                            deployment_id: deployment_id.to_string(),
                            generation: target_generation,
                            plan_digest: plan.plan_digest.clone(),
                            overall_status: expected_overall,
                            components: obs,
                            issued_at: now,
                            signature: String::new(),
                        };
                        crate::workload_runtime::ipc_boundary::sign_receipt_with_key(&mut receipt, host_signing_key)?;
                        return Ok(ReconciliationOutcome::Success(receipt));
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
                    &vol.host_path,
                )?;
                self.state_store.record_snapshot(
                    &format!("snap-{}-{}-{}-{}", deployment_id, target_generation, vol.volume_id, now),
                    deployment_id,
                    target_generation,
                    &vol.volume_id,
                    &snap_path.to_string_lossy(),
                    now,
                    true,
                )?;
            }
        }

        // Secret Delivery into confined supervisor staging directory
        validate_path_identifier(deployment_id)?;
        let secret_staging_dir = self.volume_provider.base_root
            .join("secrets")
            .join(deployment_id)
            .join(format!("gen-{}", target_generation));
        std::fs::create_dir_all(&secret_staging_dir)
            .map_err(|e| WorkloadError::ExecutionError(format!("Failed to create secret dir: {}", e)))?;

        for comp in &plan.components {
            for sec_mount in &comp.secret_mounts {
                if sec_mount.injection_mode == "TMPFS_FILE" {
                    validate_path_identifier(&comp.component_id)?;
                    validate_path_identifier(&sec_mount.secret_id)?;
                    let secret = self.secret_provider.resolve_secret(
                        &sec_mount.secret_id,
                        &sec_mount.purpose,
                        sec_mount.secret_generation,
                    )?;
                    let comp_secret_dir = secret_staging_dir.join(&comp.component_id);
                    std::fs::create_dir_all(&comp_secret_dir)
                        .map_err(|e| WorkloadError::ExecutionError(format!("Failed to create comp secret dir: {}", e)))?;
                    let target_path = comp_secret_dir.join(&sec_mount.secret_id);
                    secret.mount_tmpfs(&target_path)?;
                }
            }
        }

        // Phase 2: External Idempotent Mutation with Crash Recovery Adoption
        let mutation_res = if is_stopped {
            let insp = self.compose_executor.inspect(&plan.compose_project_id)?;
            if insp.exists {
                self.compose_executor.stop_project(&plan.compose_project_id, 10)?;
                let post_insp = self.compose_executor.inspect(&plan.compose_project_id)?;
                Ok(post_insp
                    .components
                    .into_iter()
                    .map(|c| ComponentObservation {
                        component_id: c.name,
                        status: c.status,
                    })
                    .collect())
            } else {
                Ok(plan
                    .components
                    .iter()
                    .map(|c| ComponentObservation {
                        component_id: c.component_id.clone(),
                        status: ComponentStatus::Stopped,
                    })
                    .collect())
            }
        } else {
            // Upgrade Strategy enforcement: if "replace" and target_generation > 1, stop previous generation
            if plan.upgrade_policy.strategy == "replace" && target_generation > 1 {
                let prev_gen = target_generation - 1;
                if let Ok(prev_proj_id) = super::canonical::deterministic_compose_project_id(deployment_id, prev_gen) {
                    if let Ok(prev_insp) = self.compose_executor.inspect(&prev_proj_id) {
                        if prev_insp.exists {
                            self.state_store.record_journal(
                                deployment_id,
                                target_generation,
                                "UPGRADE_REPLACE_STOP_OLD",
                                &prev_proj_id,
                                now,
                            )?;
                            let _ = self.compose_executor.stop_project(&prev_proj_id, 10);
                        }
                    }
                }
            }

            let inspection = self.compose_executor.inspect(&plan.compose_project_id)?;
            if inspection.exists {
                // Adopt existing containers if plan_digest matches
                let all_match = inspection.components.iter().all(|c| {
                    c.labels
                        .get("actium.plan_digest")
                        .map(|d| d == &plan.plan_digest)
                        .unwrap_or(false)
                });
                if all_match {
                    Ok(inspection
                        .components
                        .into_iter()
                        .map(|c| ComponentObservation {
                            component_id: c.name,
                            status: c.status,
                        })
                        .collect())
                } else {
                    // Outdated or conflicting project -> recreate
                    self.compose_executor.apply_plan(&plan)
                }
            } else {
                // Create fresh project
                self.compose_executor.apply_plan(&plan)
            }
        };

        let observations = match mutation_res {
            Ok(obs) => obs,
            Err(e) => {
                self.state_store
                    .record_journal(deployment_id, target_generation, "MUTATION_FAIL", &e.to_string(), now)?;
                return self.handle_failure_or_rollback(
                    deployment_id,
                    target_generation,
                    &op_id,
                    &format!("Mutation failed: {}", e),
                    &plan,
                    now,
                );
            }
        };

        // Phase 3: Inspect Physical Reality & Health Gate
        let mut observations = observations;
        let mut overall = overall_from_components(&observations);

        if is_stopped {
            if overall != ComponentStatus::Stopped {
                self.state_store.record_journal(
                    deployment_id,
                    target_generation,
                    "STOP_FAIL",
                    "Components failed to converge to STOPPED",
                    now,
                )?;
                return self.handle_failure_or_rollback(
                    deployment_id,
                    target_generation,
                    &op_id,
                    "Components failed to stop",
                    &plan,
                    now,
                );
            }
        } else {
            // Convergence wait loop: allow initializing/pending containers time to start without premature rollback
            let convergence_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                let has_pending = observations.iter().any(|o| o.status == ComponentStatus::Pending);
                let has_failed = observations.iter().any(|o| o.status == ComponentStatus::Failed);
                if !has_pending || has_failed || std::time::Instant::now() >= convergence_deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
                if let Ok(insp) = self.compose_executor.inspect(&plan.compose_project_id) {
                    observations = insp.components.into_iter().map(|c| ComponentObservation {
                        component_id: c.name,
                        status: c.status,
                    }).collect();
                }
            }
            overall = overall_from_components(&observations);
            // Step 1: Health Gate (Liveness probe enforcement)
            for comp in &plan.components {
                if comp.health_check.is_some() {
                    if let Some(obs) = observations.iter().find(|o| o.component_id == comp.component_id) {
                        if obs.status != ComponentStatus::Ready {
                            self.state_store.record_journal(
                                deployment_id,
                                target_generation,
                                "HEALTH_FAIL",
                                &format!("Component '{}' liveness probe failed (status: {:?})", comp.component_id, obs.status),
                                now,
                            )?;
                            return self.handle_failure_or_rollback(
                                deployment_id,
                                target_generation,
                                &op_id,
                                &format!("Health check probe failed for component '{}'", comp.component_id),
                                &plan,
                                now,
                            );
                        }
                    }
                }
            }

            // Step 2: Readiness Gate (Readiness checks physical execution)
            if let Some(readiness_checks) = &plan.readiness_checks {
                for rc in readiness_checks {
                    let target_cid = rc.component_id.as_deref().unwrap_or("");
                    let probe_ok = self.compose_executor.execute_readiness_probe(
                        &plan.compose_project_id,
                        target_cid,
                        rc,
                    )?;
                    if !probe_ok {
                        self.state_store.record_journal(
                            deployment_id,
                            target_generation,
                            "READINESS_FAIL",
                            &format!("Component '{}' readiness probe failed execution", target_cid),
                            now,
                        )?;
                        return self.handle_failure_or_rollback(
                            deployment_id,
                            target_generation,
                            &op_id,
                            &format!("Readiness probe failed execution for component '{}'", target_cid),
                            &plan,
                            now,
                        );
                    }
                }
            }

            if overall != ComponentStatus::Ready {
                // Component probe failed -> Trigger LKG Rollback Engine
                self.state_store
                    .record_journal(deployment_id, target_generation, "HEALTH_FAIL", "Probes failed", now)?;
                return self.handle_failure_or_rollback(
                    deployment_id,
                    target_generation,
                    &op_id,
                    "Health and readiness checks failed",
                    &plan,
                    now,
                );
            }
        }

        // Ingress route materialization / teardown
        if is_stopped {
            let _ = self.ingress_provider.teardown_ingress(deployment_id, target_generation);
        } else {
            self.ingress_provider.configure_ingress(deployment_id, target_generation, &plan)?;
        }

        // Phase 4: TX 2 (Observed Reality & Receipt in SQLite atomically)
        let expected_overall = if is_stopped { ComponentStatus::Stopped } else { ComponentStatus::Ready };
        let overall_status_str = if is_stopped { "STOPPED" } else { "READY" };
        let deployment_status_str = if is_stopped { "STOPPED" } else { "ACTIVE" };

        let mut receipt = CanonicalWorkloadReceipt {
            schema: WORKLOAD_RECEIPT_SCHEMA.to_string(),
            receipt_id: format!("rcpt-{}-{}", deployment_id, target_generation),
            deployment_id: deployment_id.to_string(),
            generation: target_generation,
            plan_digest: plan.plan_digest.clone(),
            overall_status: expected_overall,
            components: observations,
            issued_at: now,
            signature: String::new(),
        };

        crate::workload_runtime::ipc_boundary::sign_receipt_with_key(&mut receipt, host_signing_key)?;

        let receipt_json = serde_json::to_string(&receipt)
            .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;

        self.state_store.commit_reconciliation_tx2(
            &op_id,
            deployment_id,
            target_generation,
            profile_id,
            profile_version,
            &plan.desired_digest,
            &plan.plan_digest,
            overall_status_str,
            deployment_status_str,
            &receipt.receipt_id,
            &receipt_json,
            &receipt.signature,
            now,
        )?;

        Ok(ReconciliationOutcome::Success(receipt))
    }

    pub fn handle_failure_or_rollback(
        &self,
        deployment_id: &str,
        failed_generation: u64,
        operation_id: &str,
        reason: &str,
        failed_plan: &CanonicalWorkloadPlan,
        now: u64,
    ) -> Result<ReconciliationOutcome, WorkloadError> {
        let _ = self.ingress_provider.teardown_ingress(deployment_id, failed_generation);

        // Collect all required volume mounts from failed_plan
        let mut required_volumes = Vec::new();
        for comp in &failed_plan.components {
            for vol in &comp.volume_mounts {
                required_volumes.push((vol.volume_id.clone(), vol.host_path.clone()));
            }
        }

        // Check if pre-mutation snapshots exist for all durable volume mounts
        let snapshots_map = self
            .state_store
            .get_durable_snapshots_for_generation(deployment_id, failed_generation)?;

        let has_all_snapshots = if required_volumes.is_empty() {
            true
        } else {
            required_volumes.iter().all(|(vol_id, _)| snapshots_map.contains_key(vol_id))
        };

        if failed_generation > 1 && has_all_snapshots {
            let lkg_generation = failed_generation - 1;

            // 1. Teardown failed generation project
            let _ = self.compose_executor.down_project(&failed_plan.compose_project_id);

            // 2. Restore durable volume snapshots per volume_id
            for (vol_id, host_path) in &required_volumes {
                if let Some(snap_path) = snapshots_map.get(vol_id) {
                    if let Err(e) = self.volume_provider.restore_snapshot(
                        &PathBuf::from(snap_path),
                        host_path,
                    ) {
                        self.state_store.update_operation_state(operation_id, "FAILED", Some(now))?;
                        self.state_store.record_journal(
                            deployment_id,
                            failed_generation,
                            "FAILED_REQUIRES_OPERATOR",
                            &format!("Snapshot restore failed for volume {}: {}", vol_id, e),
                            now,
                        )?;
                        return Ok(ReconciliationOutcome::FailedRequiresOperator {
                            reason: format!("Snapshot restore failed for volume {}: {}", vol_id, e),
                        });
                    }
                }
            }

            // 3. Reactivate / Start generation N (LKG)
            let lkg_project_id = super::canonical::deterministic_compose_project_id(deployment_id, lkg_generation)?;
            let lkg_insp = self.compose_executor.inspect(&lkg_project_id)?;
            if lkg_insp.exists {
                let _ = self.compose_executor.start_project(&lkg_project_id);
            } else if let Some(dep) = self.state_store.get_deployment(deployment_id)? {
                if let Some(profile_rec) = self.profile_registry.get_profile(&dep.profile_id, &dep.profile_version)? {
                    let prev_desired = serde_json::json!({
                        "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
                        "deploymentId": deployment_id,
                        "generation": lkg_generation,
                        "profileId": dep.profile_id,
                        "profileVersion": dep.profile_version,
                        "desiredDigest": dep.desired_digest,
                        "targetState": "ACTIVE"
                    });
                    if let Ok(lkg_plan) = WorkloadPlanner::plan(
                        &prev_desired.to_string(),
                        &profile_rec.manifest_json,
                        &failed_plan.host_capabilities_digest,
                        Some("actium-planner-v1.5"),
                        Some(now),
                    ) {
                        let _ = self.compose_executor.apply_plan(&lkg_plan);
                    }
                }
            }

            // 4. Verify physical reality returns to Ready
            let lkg_reality = self.compose_executor.inspect(&lkg_project_id)?;
            let lkg_obs: Vec<ComponentObservation> = lkg_reality
                .components
                .into_iter()
                .map(|c| ComponentObservation {
                    component_id: c.name,
                    status: c.status,
                })
                .collect();

            if !lkg_reality.exists || overall_from_components(&lkg_obs) != ComponentStatus::Ready {
                self.state_store.update_operation_state(operation_id, "FAILED", Some(now))?;
                self.state_store.record_journal(
                    deployment_id,
                    failed_generation,
                    "FAILED_REQUIRES_OPERATOR",
                    &format!("{}: LKG reactivation failed to achieve Ready", reason),
                    now,
                )?;
                return Ok(ReconciliationOutcome::FailedRequiresOperator {
                    reason: format!("{}: LKG reactivation failed to achieve Ready", reason),
                });
            }

            // 5. Commit atomic rollback in SQLite
            self.state_store.commit_rollback_tx(
                operation_id,
                deployment_id,
                failed_generation,
                lkg_generation,
                reason,
                now,
            )?;

            Ok(ReconciliationOutcome::RolledBack {
                reason: reason.to_string(),
                previous_generation: lkg_generation,
            })
        } else {
            // Data incompatibility without captured durable snapshot or gen 1 -> Fail closed to operator
            self.state_store.update_operation_state(operation_id, "FAILED", Some(now))?;
            self.state_store.record_journal(
                deployment_id,
                failed_generation,
                "FAILED_REQUIRES_OPERATOR",
                reason,
                now,
            )?;
            Ok(ReconciliationOutcome::FailedRequiresOperator {
                reason: format!("{}: Missing durable pre-mutation snapshot or initial generation failure", reason),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_runtime::executor::MockComposeRuntimeBackend;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn setup_environment(tag: &str) -> (
        WorkloadReconciler<MockComposeRuntimeBackend>,
        Arc<MockComposeRuntimeBackend>,
        String,
        SigningKey,
    ) {
        let store = Arc::new(WorkloadStateStore::in_memory().unwrap());
        let registry = Arc::new(WorkloadProfileRegistry::in_memory().unwrap());
        let backend = Arc::new(MockComposeRuntimeBackend::new());
        let executor = Arc::new(OciComposeExecutor::new(backend.clone()));
        let tmp_root = std::env::temp_dir().join(format!("actium_reconcile_test_{}_{}", std::process::id(), tag));
        let volume_provider = Arc::new(VolumeProvider::new(&tmp_root));
        let data_dir = tmp_root.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let _data_path_str = data_dir.to_string_lossy().replace('\\', "/");

        let secret_provider = Arc::new(crate::workload_runtime::executor::DefaultWorkloadSecretProvider::new());
        let ingress_provider = Arc::new(crate::workload_runtime::executor::DefaultWorkloadIngressProvider::new());
        let reconciler = WorkloadReconciler::new(
            store,
            registry.clone(),
            executor,
            volume_provider,
            secret_provider,
            ingress_provider,
        );

        // Register profile
        let manifest = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "svc-reconcile",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "api",
                    "image": "docker.io/library/alpine@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "volumes": ["api_data"],
                    "healthCheck": {
                        "type": "exec",
                        "command": ["echo", "ok"]
                    }
                }
            ],
            "volumes": [
                { "id": "api_data", "purpose": "data-storage", "size": "1Gi" }
            ],
            "secretRequirements": [],
            "healthChecks": [],
            "readinessChecks": [],
            "upgradePolicy": {
                "strategy": "replace",
                "requiresSnapshot": false,
                "databaseMigration": "none",
                "rollbackCompatibility": "runtime-only"
            },
            "rollbackPolicy": {
                "runtimeRollback": "previous-generation",
                "databaseRollback": "none"
            }
        }).to_string();
        registry.register_profile(&manifest).unwrap();

        let mut csprng = OsRng;
        let host_signing_key = SigningKey::generate(&mut csprng);

        (reconciler, backend, tmp_root.to_string_lossy().to_string(), host_signing_key)
    }

    fn make_desired(dep: &str, gen: u64) -> String {
        let body = serde_json::json!({
            "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
            "deploymentId": dep,
            "generation": gen,
            "profileId": "svc-reconcile",
            "profileVersion": "1.0.0",
            "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
            "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modules": [],
            "secretRefs": [],
            "desiredState": "RUNNING"
        });
        let digest = canonical_digest_for_value(&body).unwrap();
        let mut env = body;
        env["desiredDigest"] = serde_json::Value::String(digest);
        env.to_string()
    }

    #[test]
    fn test_two_phase_reconciliation_protocol_success() {
        let (reconciler, _, tmp_dir, host_sk) = setup_environment("success");
        let desired = make_desired("dep-success-1", 1);
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let outcome = reconciler.reconcile(&desired, host_caps, &host_sk, 1000).unwrap();
        match outcome {
            ReconciliationOutcome::Success(receipt) => {
                assert_eq!(receipt.overall_status, ComponentStatus::Ready);
                assert_eq!(receipt.generation, 1);
                assert_eq!(receipt.deployment_id, "dep-success-1");
                assert!(!receipt.signature.is_empty());
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
        let (reconciler, _backend, tmp_dir, host_sk) = setup_environment("adopt");
        let desired = make_desired("dep-adopt-1", 1);
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Step 1: Converge generation 1
        let outcome1 = reconciler.reconcile(&desired, host_caps, &host_sk, 1000).unwrap();
        assert!(matches!(outcome1, ReconciliationOutcome::Success(_)));

        // Step 2: Simulate Supervisor restart / crash recovery by reconciling again
        // It must adopt the existing container via deterministic name and matching plan_digest
        let outcome2 = reconciler.reconcile(&desired, host_caps, &host_sk, 2000).unwrap();
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
        let (reconciler, backend, tmp_dir, host_sk) = setup_environment("lkg");
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Generation 1 succeeds
        let desired_gen1 = make_desired("dep-fail-1", 1);
        reconciler.reconcile(&desired_gen1, host_caps, &host_sk, 1000).unwrap();

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

        let outcome2 = reconciler.reconcile(&desired_gen2, host_caps, &host_sk, 2000).unwrap();
        match outcome2 {
            ReconciliationOutcome::RolledBack { previous_generation, .. } => {
                assert_eq!(previous_generation, 1);
            }
            other => panic!("Expected RolledBack to gen 1, got {:?}", other),
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_reconciler_converges_to_stopped_state_and_idempotency() {
        let (reconciler, _backend, tmp_dir, host_sk) = setup_environment("stopped");
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Generation 1: Start running
        let desired_gen1 = make_desired("dep-stop-1", 1);
        let outcome1 = reconciler.reconcile(&desired_gen1, host_caps, &host_sk, 1000).unwrap();
        match outcome1 {
            ReconciliationOutcome::Success(receipt) => {
                assert_eq!(receipt.overall_status, ComponentStatus::Ready);
            }
            other => panic!("Expected Success for Gen 1, got {:?}", other),
        }

        let dep = reconciler.state_store.get_deployment("dep-stop-1").unwrap().unwrap();
        assert_eq!(dep.status, "ACTIVE");

        // Generation 2: Order STOPPED
        let mut desired_gen2_val: serde_json::Value = serde_json::from_str(&make_desired("dep-stop-1", 2)).unwrap();
        if let Some(obj) = desired_gen2_val.as_object_mut() {
            obj.remove("desiredDigest");
        }
        desired_gen2_val["desiredState"] = serde_json::Value::String("STOPPED".into());
        let digest2 = canonical_digest_for_value(&desired_gen2_val).unwrap();
        desired_gen2_val["desiredDigest"] = serde_json::Value::String(digest2);
        let desired_gen2_str = desired_gen2_val.to_string();

        let outcome2 = reconciler.reconcile(&desired_gen2_str, host_caps, &host_sk, 2000).unwrap();
        match outcome2 {
            ReconciliationOutcome::Success(receipt) => {
                assert_eq!(receipt.overall_status, ComponentStatus::Stopped);
                assert_eq!(receipt.components[0].status, ComponentStatus::Stopped);
            }
            other => panic!("Expected Success with STOPPED for Gen 2, got {:?}", other),
        }

        // Verify deployment state is STOPPED in DB
        let dep2 = reconciler.state_store.get_deployment("dep-stop-1").unwrap().unwrap();
        assert_eq!(dep2.status, "STOPPED");
        assert_eq!(dep2.active_generation, 2);

        // Idempotent re-reconciliation: must return immediately with STOPPED
        let outcome2_replay = reconciler.reconcile(&desired_gen2_str, host_caps, &host_sk, 3000).unwrap();
        match outcome2_replay {
            ReconciliationOutcome::Success(receipt) => {
                assert_eq!(receipt.overall_status, ComponentStatus::Stopped);
            }
            other => panic!("Expected idempotent Success with STOPPED, got {:?}", other),
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_readiness_probe_failure_triggers_lkg_rollback() {
        let (reconciler, backend, tmp_dir, host_sk) = setup_environment("probe_fail");
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let manifest = serde_json::json!({
            "schema": crate::workload::WORKLOAD_PROFILE_SCHEMA,
            "profileId": "svc-probe-test",
            "profileVersion": "1.0.0",
            "runtimeKind": "OCI_COMPOSE",
            "architecture": ["amd64"],
            "components": [
                {
                    "componentId": "web",
                    "image": "docker.io/library/alpine@sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "imageDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                    "network": "PRODUCT_INTERNAL",
                    "restartPolicy": "unless-stopped",
                    "healthCheck": {
                        "type": "exec",
                        "command": ["echo", "ok"]
                    }
                }
            ],
            "volumes": [],
            "secretRequirements": [],
            "healthChecks": [],
            "readinessChecks": [
                {
                    "type": "http",
                    "componentId": "web",
                    "path": "/ready",
                    "port": 8080
                }
            ],
            "upgradePolicy": {
                "strategy": "replace",
                "requiresSnapshot": false,
                "databaseMigration": "none",
                "rollbackCompatibility": "runtime-only"
            },
            "rollbackPolicy": {
                "runtimeRollback": "previous-generation",
                "databaseRollback": "none"
            }
        }).to_string();
        reconciler.profile_registry.register_profile(&manifest).unwrap();

        let make_probe_desired = |gen: u64| -> String {
            let body = serde_json::json!({
                "schema": crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA,
                "deploymentId": "dep-probe-1",
                "generation": gen,
                "profileId": "svc-probe-test",
                "profileVersion": "1.0.0",
                "profileDigest": "sha256:77af4d6b9f0213b293129485d11cbd720e973e49962c00d8e402b29410429605",
                "configurationDigest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "modules": [],
                "secretRefs": [],
                "desiredState": "RUNNING"
            });
            let digest = canonical_digest_for_value(&body).unwrap();
            let mut env = body;
            env["desiredDigest"] = serde_json::Value::String(digest);
            env.to_string()
        };

        // Gen 1: Succeeds
        let outcome1 = reconciler.reconcile(&make_probe_desired(1), host_caps, &host_sk, 1000).unwrap();
        assert!(matches!(outcome1, ReconciliationOutcome::Success(_)));

        // Gen 2: Force readiness probe failure on backend
        backend.set_probe_result("web", false);

        let outcome2 = reconciler.reconcile(&make_probe_desired(2), host_caps, &host_sk, 2000).unwrap();
        match outcome2 {
            ReconciliationOutcome::RolledBack { previous_generation, reason } => {
                assert_eq!(previous_generation, 1);
                assert!(reason.contains("Readiness probe failed execution"));
            }
            other => panic!("Expected RolledBack to gen 1, got {:?}", other),
        }

        // Verify journal recorded READINESS_FAIL
        let journals = reconciler.state_store.get_journal("dep-probe-1").unwrap();
        assert!(journals.iter().any(|j| j.phase == "READINESS_FAIL"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_reconciler_upgrade_replace_strategy_stops_previous_generation() {
        let (reconciler, backend, tmp_dir, host_sk) = setup_environment("upgrade-replace");
        let host_caps = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Step 1: Converge generation 1
        let desired_gen1 = make_desired("dep-upg-1", 1);
        let outcome1 = reconciler.reconcile(&desired_gen1, host_caps, &host_sk, 1000).unwrap();
        assert!(matches!(outcome1, ReconciliationOutcome::Success(_)));

        let proj_id_1 = super::super::canonical::deterministic_compose_project_id("dep-upg-1", 1).unwrap();
        let insp1 = backend.inspect_project(&proj_id_1).unwrap();
        assert!(insp1.exists);
        assert_eq!(insp1.components[0].status, ComponentStatus::Ready);

        // Step 2: Converge generation 2 (with strategy: replace)
        let desired_gen2 = make_desired("dep-upg-1", 2);
        let outcome2 = reconciler.reconcile(&desired_gen2, host_caps, &host_sk, 2000).unwrap();
        assert!(matches!(outcome2, ReconciliationOutcome::Success(_)));

        // Verify: Generation 1 project was stopped by replace strategy!
        let insp1_after = backend.inspect_project(&proj_id_1).unwrap();
        assert_eq!(insp1_after.components[0].status, ComponentStatus::Stopped);

        // Verify: Generation 2 project is Ready
        let proj_id_2 = super::super::canonical::deterministic_compose_project_id("dep-upg-1", 2).unwrap();
        let insp2 = backend.inspect_project(&proj_id_2).unwrap();
        assert!(insp2.exists);
        assert_eq!(insp2.components[0].status, ComponentStatus::Ready);

        // Verify journal recorded UPGRADE_REPLACE_STOP_OLD
        let journals = reconciler.state_store.get_journal("dep-upg-1").unwrap();
        assert!(journals.iter().any(|j| j.phase == "UPGRADE_REPLACE_STOP_OLD"));

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_safe_path_identifier_security_constraints() {
        assert!(validate_path_identifier("valid-id-1").is_ok());
        assert!(validate_path_identifier("component_app.sub-1").is_ok());
        assert!(validate_path_identifier("redis.server_0").is_ok());

        assert!(validate_path_identifier("").is_err());
        assert!(validate_path_identifier("../escape").is_err());
        assert!(validate_path_identifier("dir/nested").is_err());
        assert!(validate_path_identifier("dir\\nested").is_err());
        assert!(validate_path_identifier("id;rm").is_err());
        assert!(validate_path_identifier("ID_UPPERCASE").is_err());
        assert!(validate_path_identifier("-invalid-lead").is_err());
    }
}
