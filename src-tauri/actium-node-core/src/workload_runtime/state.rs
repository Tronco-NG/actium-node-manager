use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::BTreeMap;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use super::WorkloadError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationReservationResult {
    Reserved { operation_id: String },
    AttachedIdempotent { operation_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentRecord {
    pub deployment_id: String,
    pub active_generation: u64,
    pub target_generation: u64,
    pub profile_id: String,
    pub profile_version: String,
    pub desired_digest: String,
    pub plan_digest: String,
    pub status: String,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JournalEntry {
    pub deployment_id: String,
    pub generation: u64,
    pub phase: String,
    pub detail: String,
    pub created_at: u64,
}

pub struct WorkloadStateStore {
    conn: Mutex<Connection>,
}

impl WorkloadStateStore {
    pub fn new(conn: Connection) -> Result<Self, WorkloadError> {
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn open(path: &std::path::Path) -> Result<Self, WorkloadError> {
        let conn = Connection::open(path)
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to open SQLite state at {:?}: {}", path, e)))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;"
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to configure SQLite pragmas: {}", e)))?;
        Self::new(conn)
    }

    pub fn in_memory() -> Result<Self, WorkloadError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to open in-memory SQLite: {}", e)))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;"
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to configure SQLite pragmas: {}", e)))?;
        Self::new(conn)
    }

    fn init_schema(&self) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS workload_deployments (
                deployment_id TEXT PRIMARY KEY,
                active_generation INTEGER NOT NULL,
                target_generation INTEGER NOT NULL,
                profile_id TEXT NOT NULL,
                profile_version TEXT NOT NULL,
                desired_digest TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('PENDING', 'ACTIVE', 'DEGRADED', 'FAILED', 'STOPPED')),
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workload_journal (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                deployment_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                phase TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workload_receipts (
                receipt_id TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                plan_digest TEXT NOT NULL,
                overall_status TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workload_nonces (
                nonce TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                envelope_digest TEXT NOT NULL,
                consumed_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workload_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                volume_id TEXT NOT NULL DEFAULT '',
                snapshot_path TEXT NOT NULL,
                captured_at INTEGER NOT NULL,
                is_durable BOOLEAN NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_workload_snapshots_lookup
                ON workload_snapshots(deployment_id, generation, volume_id);

            CREATE TABLE IF NOT EXISTS workload_operations (
                operation_id TEXT PRIMARY KEY,
                deployment_id TEXT NOT NULL,
                target_generation INTEGER NOT NULL,
                desired_digest TEXT NOT NULL,
                plan_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('RESERVED', 'STARTING', 'COMPLETED', 'FAILED', 'ROLLED_BACK')),
                started_at INTEGER NOT NULL,
                completed_at INTEGER
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_workload_operations_active
                ON workload_operations(deployment_id)
                WHERE state IN ('RESERVED', 'STARTING');"
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to initialize workload schema: {}", e)))?;
        Ok(())
    }

    /// Atomically attempts to reserve or attach to a workload mutation operation.
    /// Invariant:
    /// An active operation may be attached idempotently only when ALL match:
    /// - deployment_id
    /// - target_generation
    /// - desired_digest
    /// - plan_digest
    /// Same generation/desired with a different planDigest MUST NOT attach; fail closed with typed conflict.
    pub fn reserve_operation(
        &self,
        operation_id: &str,
        deployment_id: &str,
        target_generation: u64,
        desired_digest: &str,
        plan_digest: &str,
        now: u64,
    ) -> Result<OperationReservationResult, WorkloadError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to begin immediate TX: {}", e)))?;

        // Check if there is an active operation for this deployment
        let mut check_stmt = tx
            .prepare(
                "SELECT operation_id, target_generation, desired_digest, plan_digest
                 FROM workload_operations
                 WHERE deployment_id = ?1 AND state IN ('RESERVED', 'STARTING')",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let existing_opt = check_stmt
            .query_row(params![deployment_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        drop(check_stmt);

        if let Some((active_op_id, active_gen, active_desired, active_plan)) = existing_opt {
            if active_gen == target_generation
                && active_desired == desired_digest
                && active_plan == plan_digest
            {
                // Exact idempotent replay: attach
                tx.commit()
                    .map_err(|e| WorkloadError::DatabaseError(format!("Failed to commit attach TX: {}", e)))?;
                return Ok(OperationReservationResult::AttachedIdempotent {
                    operation_id: active_op_id,
                });
            } else {
                // Conflict: fail closed
                let detail = format!(
                    "Active op '{}' in progress (gen {}, desired '{}', plan '{}'); incoming request has (gen {}, desired '{}', plan '{}')",
                    active_op_id, active_gen, active_desired, active_plan, target_generation, desired_digest, plan_digest
                );
                return Err(WorkloadError::ActiveOperationConflict {
                    deployment_id: deployment_id.to_string(),
                    operation_id: active_op_id,
                    detail,
                });
            }
        }

        // No active operation: reserve new operation
        tx.execute(
            "INSERT INTO workload_operations (operation_id, deployment_id, target_generation, desired_digest, plan_digest, state, started_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'RESERVED', ?6, NULL)",
            params![
                operation_id,
                deployment_id,
                target_generation,
                desired_digest,
                plan_digest,
                now
            ],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to insert operation reservation: {}", e)))?;

        tx.commit()
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to commit reservation TX: {}", e)))?;

        Ok(OperationReservationResult::Reserved {
            operation_id: operation_id.to_string(),
        })
    }

    pub fn update_operation_state(
        &self,
        operation_id: &str,
        new_state: &str,
        completed_at: Option<u64>,
    ) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE workload_operations
             SET state = ?1, completed_at = ?2
             WHERE operation_id = ?3",
            params![new_state, completed_at, operation_id],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to update operation state: {}", e)))?;
        Ok(())
    }

    pub fn check_generation_monotonicity(
        &self,
        deployment_id: &str,
        target_generation: u64,
        desired_digest: &str,
    ) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT target_generation, desired_digest
                 FROM workload_deployments
                 WHERE deployment_id = ?1",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let existing: Option<(u64, String)> = match stmt.query_row(params![deployment_id], |row| Ok((row.get(0)?, row.get(1)?))) {
            Ok(val) => Some(val),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(WorkloadError::DatabaseError(e.to_string())),
        };

        if let Some((highest, existing_desired)) = existing {
            if target_generation < highest {
                return Err(WorkloadError::GenerationRegression {
                    deployment_id: deployment_id.to_string(),
                    target_generation,
                    highest_generation: highest,
                });
            }
            if target_generation == highest && existing_desired != desired_digest {
                return Err(WorkloadError::GenerationDigestConflict {
                    deployment_id: deployment_id.to_string(),
                    generation: target_generation,
                    existing_digest: existing_desired,
                    new_digest: desired_digest.to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn consume_or_replay_nonce(
        &self,
        nonce: &str,
        deployment_id: &str,
        generation: u64,
        envelope_digest: &str,
        now: u64,
    ) -> Result<bool, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT envelope_digest FROM workload_nonces WHERE nonce = ?1")
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let existing: Option<String> = match stmt.query_row(params![nonce], |row| row.get(0)) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(WorkloadError::DatabaseError(e.to_string())),
        };

        if let Some(existing_digest) = existing {
            if existing_digest == envelope_digest {
                Ok(true)
            } else {
                Err(WorkloadError::NonceReplay(format!(
                    "Nonce '{}' reused with different digest: existing '{}', new '{}'",
                    nonce, existing_digest, envelope_digest
                )))
            }
        } else {
            conn.execute(
                "INSERT INTO workload_nonces (nonce, deployment_id, generation, envelope_digest, consumed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![nonce, deployment_id, generation, envelope_digest, now],
            ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to record nonce: {}", e)))?;
            Ok(false)
        }
    }

    pub fn consume_nonce(
        &self,
        nonce: &str,
        deployment_id: &str,
        generation: u64,
        now: u64,
    ) -> Result<(), WorkloadError> {
        let is_replay = self.consume_or_replay_nonce(nonce, deployment_id, generation, "sha256:legacy_single_use", now)?;
        if is_replay {
            return Err(WorkloadError::NonceReplay(nonce.to_string()));
        }
        Ok(())
    }

    pub fn record_snapshot(
        &self,
        snapshot_id: &str,
        deployment_id: &str,
        generation: u64,
        volume_id: &str,
        snapshot_path: &str,
        now: u64,
        is_durable: bool,
    ) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO workload_snapshots (snapshot_id, deployment_id, generation, volume_id, snapshot_path, captured_at, is_durable)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![snapshot_id, deployment_id, generation, volume_id, snapshot_path, now, is_durable],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to record snapshot: {}", e)))?;
        Ok(())
    }

    pub fn get_durable_snapshot(
        &self,
        deployment_id: &str,
        generation: u64,
    ) -> Result<Option<String>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT snapshot_path
                 FROM workload_snapshots
                 WHERE deployment_id = ?1 AND generation = ?2 AND is_durable = 1
                 ORDER BY captured_at DESC LIMIT 1",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let res = stmt.query_row(params![deployment_id, generation], |row| row.get(0));
        match res {
            Ok(path) => Ok(Some(path)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }

    pub fn get_durable_snapshot_for_volume(
        &self,
        deployment_id: &str,
        generation: u64,
        volume_id: &str,
    ) -> Result<Option<String>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT snapshot_path
                 FROM workload_snapshots
                 WHERE deployment_id = ?1 AND generation = ?2 AND volume_id = ?3 AND is_durable = 1
                 ORDER BY captured_at DESC LIMIT 1",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let res = stmt.query_row(params![deployment_id, generation, volume_id], |row| row.get(0));
        match res {
            Ok(path) => Ok(Some(path)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }

    pub fn get_durable_snapshots_for_generation(
        &self,
        deployment_id: &str,
        generation: u64,
    ) -> Result<BTreeMap<String, String>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT volume_id, snapshot_path
                 FROM workload_snapshots
                 WHERE deployment_id = ?1 AND generation = ?2 AND is_durable = 1
                 ORDER BY captured_at ASC",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let rows = stmt.query_map(params![deployment_id, generation], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let mut map = BTreeMap::new();
        for r in rows {
            let (vol_id, path) = r.map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;
            map.insert(vol_id, path);
        }
        Ok(map)
    }

    pub fn save_receipt(
        &self,
        receipt_id: &str,
        deployment_id: &str,
        generation: u64,
        plan_digest: &str,
        overall_status: &str,
        receipt_json: &str,
        signature: &str,
        now: u64,
    ) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO workload_receipts (receipt_id, deployment_id, generation, plan_digest, overall_status, receipt_json, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![receipt_id, deployment_id, generation, plan_digest, overall_status, receipt_json, signature, now],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to save receipt: {}", e)))?;
        Ok(())
    }

    pub fn record_journal(
        &self,
        deployment_id: &str,
        generation: u64,
        phase: &str,
        detail: &str,
        now: u64,
    ) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO workload_journal (deployment_id, generation, phase, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![deployment_id, generation, phase, detail, now],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to record journal: {}", e)))?;
        Ok(())
    }

    pub fn get_journal(&self, deployment_id: &str) -> Result<Vec<JournalEntry>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT deployment_id, generation, phase, detail, created_at
                 FROM workload_journal
                 WHERE deployment_id = ?1
                 ORDER BY entry_id ASC",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let entries = stmt
            .query_map(params![deployment_id], |row| {
                Ok(JournalEntry {
                    deployment_id: row.get(0)?,
                    generation: row.get(1)?,
                    phase: row.get(2)?,
                    detail: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        Ok(entries)
    }

    pub fn upsert_deployment(
        &self,
        deployment_id: &str,
        active_generation: u64,
        target_generation: u64,
        profile_id: &str,
        profile_version: &str,
        desired_digest: &str,
        plan_digest: &str,
        status: &str,
        now: u64,
    ) -> Result<(), WorkloadError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO workload_deployments (deployment_id, active_generation, target_generation, profile_id, profile_version, desired_digest, plan_digest, status, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(deployment_id) DO UPDATE SET
                 active_generation = excluded.active_generation,
                 target_generation = excluded.target_generation,
                 profile_id = excluded.profile_id,
                 profile_version = excluded.profile_version,
                 desired_digest = excluded.desired_digest,
                 plan_digest = excluded.plan_digest,
                 status = excluded.status,
                 updated_at = excluded.updated_at",
            params![deployment_id, active_generation, target_generation, profile_id, profile_version, desired_digest, plan_digest, status, now],
        ).map_err(|e| WorkloadError::DatabaseError(format!("Failed to upsert deployment: {}", e)))?;
        Ok(())
    }

    pub fn get_deployment(&self, deployment_id: &str) -> Result<Option<DeploymentRecord>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT deployment_id, active_generation, target_generation, profile_id, profile_version, desired_digest, plan_digest, status, updated_at
                 FROM workload_deployments
                 WHERE deployment_id = ?1",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let res = stmt.query_row(params![deployment_id], |row| {
            Ok(DeploymentRecord {
                deployment_id: row.get(0)?,
                active_generation: row.get(1)?,
                target_generation: row.get(2)?,
                profile_id: row.get(3)?,
                profile_version: row.get(4)?,
                desired_digest: row.get(5)?,
                plan_digest: row.get(6)?,
                status: row.get(7)?,
                updated_at: row.get(8)?,
            })
        });

        match res {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }

    pub fn get_latest_receipt(&self, deployment_id: &str) -> Result<Option<String>, WorkloadError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT receipt_json
                 FROM workload_receipts
                 WHERE deployment_id = ?1
                 ORDER BY generation DESC, created_at DESC LIMIT 1",
            )
            .map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        let res = stmt.query_row(params![deployment_id], |row| row.get(0));
        match res {
            Ok(json) => Ok(Some(json)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(WorkloadError::DatabaseError(e.to_string())),
        }
    }

    pub fn commit_reconciliation_tx2(
        &self,
        op_id: &str,
        deployment_id: &str,
        generation: u64,
        profile_id: &str,
        profile_version: &str,
        desired_digest: &str,
        plan_digest: &str,
        receipt_id: &str,
        receipt_json: &str,
        receipt_signature: &str,
        now: u64,
    ) -> Result<(), WorkloadError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to begin TX2: {}", e)))?;

        tx.execute(
            "INSERT INTO workload_journal (deployment_id, generation, phase, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![deployment_id, generation, "READY", "All components READY", now],
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        tx.execute(
            "INSERT INTO workload_deployments (deployment_id, active_generation, target_generation, profile_id, profile_version, desired_digest, plan_digest, status, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(deployment_id) DO UPDATE SET
                 active_generation = excluded.active_generation,
                 target_generation = excluded.target_generation,
                 profile_id = excluded.profile_id,
                 profile_version = excluded.profile_version,
                 desired_digest = excluded.desired_digest,
                 plan_digest = excluded.plan_digest,
                 status = excluded.status,
                 updated_at = excluded.updated_at",
            params![deployment_id, generation, generation, profile_id, profile_version, desired_digest, plan_digest, "ACTIVE", now],
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        tx.execute(
            "INSERT OR REPLACE INTO workload_receipts (receipt_id, deployment_id, generation, plan_digest, overall_status, receipt_json, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![receipt_id, deployment_id, generation, plan_digest, "READY", receipt_json, receipt_signature, now],
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        tx.execute(
            "UPDATE workload_operations
             SET state = 'COMPLETED', completed_at = ?2
             WHERE operation_id = ?1",
            params![op_id, now],
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        tx.commit()
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to commit TX2: {}", e)))?;
        Ok(())
    }

    pub fn commit_rollback_tx(
        &self,
        op_id: &str,
        deployment_id: &str,
        failed_generation: u64,
        lkg_generation: u64,
        reason: &str,
        now: u64,
    ) -> Result<(), WorkloadError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to begin rollback TX: {}", e)))?;

        tx.execute(
            "UPDATE workload_operations
             SET state = 'ROLLED_BACK', completed_at = ?2
             WHERE operation_id = ?1",
            params![op_id, now],
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        tx.execute(
            "INSERT INTO workload_journal (deployment_id, generation, phase, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![deployment_id, failed_generation, "ROLLBACK", &format!("Reverted to gen {}: {}", lkg_generation, reason), now],
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        tx.execute(
            "UPDATE workload_deployments
             SET active_generation = ?2, target_generation = ?2, status = 'ACTIVE', updated_at = ?3
             WHERE deployment_id = ?1",
            params![deployment_id, lkg_generation, now],
        ).map_err(|e| WorkloadError::DatabaseError(e.to_string()))?;

        tx.commit()
            .map_err(|e| WorkloadError::DatabaseError(format!("Failed to commit rollback TX: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concurrent_reconciliation_serialization_lock() {
        let store = WorkloadStateStore::in_memory().unwrap();
        let dep_id = "dep-concurrent-test";
        let desired = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let plan_1 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let plan_2 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // 1. Initial reservation succeeds
        let res1 = store
            .reserve_operation("op-1", dep_id, 1, desired, plan_1, 1000)
            .unwrap();
        assert_eq!(res1, OperationReservationResult::Reserved { operation_id: "op-1".into() });

        // 2. Exact match attach succeeds (idempotent replay)
        let res2 = store
            .reserve_operation("op-2-replay", dep_id, 1, desired, plan_1, 1050)
            .unwrap();
        assert_eq!(res2, OperationReservationResult::AttachedIdempotent { operation_id: "op-1".into() });

        // 3. Same generation & desired but DIFFERENT planDigest MUST NOT ATTACH -> Fail closed!
        let conflict_plan = store.reserve_operation("op-3-conflict", dep_id, 1, desired, plan_2, 1100);
        assert!(matches!(conflict_plan, Err(WorkloadError::ActiveOperationConflict { .. })));

        // 4. Different target generation while op is active MUST NOT ATTACH -> Fail closed!
        let conflict_gen = store.reserve_operation("op-4-diff-gen", dep_id, 2, desired, plan_1, 1150);
        assert!(matches!(conflict_gen, Err(WorkloadError::ActiveOperationConflict { .. })));

        // 5. Complete op-1
        store.update_operation_state("op-1", "COMPLETED", Some(1200)).unwrap();

        // 6. Now that op-1 is COMPLETED, next mutation is free to reserve
        let res3 = store
            .reserve_operation("op-5", dep_id, 2, desired, plan_2, 1300)
            .unwrap();
        assert_eq!(res3, OperationReservationResult::Reserved { operation_id: "op-5".into() });
    }

    #[test]
    fn test_generation_matrix_and_durable_nonce_ledger() {
        let store = WorkloadStateStore::in_memory().unwrap();
        let dep = "dep-mono-test";

        // Monotonicity test
        store.upsert_deployment(dep, 1, 2, "profile.1", "1.0", "sha256:d1", "sha256:p1", "ACTIVE", 100).unwrap();
        // Target generation 2 with matching digest ok
        assert!(store.check_generation_monotonicity(dep, 2, "sha256:d1").is_ok());
        // Target generation 2 with different digest fails with GenerationDigestConflict
        assert!(matches!(
            store.check_generation_monotonicity(dep, 2, "sha256:different").unwrap_err(),
            WorkloadError::GenerationDigestConflict { .. }
        ));
        // Target generation 3 ok
        assert!(store.check_generation_monotonicity(dep, 3, "sha256:d2").is_ok());

        let reg_err = store.check_generation_monotonicity(dep, 1, "sha256:d0").unwrap_err();
        match reg_err {
            WorkloadError::GenerationRegression { deployment_id, target_generation, highest_generation } => {
                assert_eq!(deployment_id, dep);
                assert_eq!(target_generation, 1);
                assert_eq!(highest_generation, 2);
            }
            other => panic!("Expected GenerationRegression, got {:?}", other),
        }

        // Nonce ledger test
        let nonce = "nonce-abc-123";
        let env_digest = "sha256:env111";
        assert_eq!(store.consume_or_replay_nonce(nonce, dep, 2, env_digest, 200).unwrap(), false);

        // Replaying same nonce with matching envelope digest succeeds as idempotent replay (true)
        assert_eq!(store.consume_or_replay_nonce(nonce, dep, 2, env_digest, 210).unwrap(), true);

        // Replaying same nonce with conflicting envelope digest fails closed as NonceReplay
        let replay_err = store.consume_or_replay_nonce(nonce, dep, 2, "sha256:tampered", 220).unwrap_err();
        match replay_err {
            WorkloadError::NonceReplay(replayed) => assert!(replayed.contains(nonce)),
            other => panic!("Expected NonceReplay, got {:?}", other),
        }
    }

    #[test]
    fn test_durable_snapshot_ledger() {
        let store = WorkloadStateStore::in_memory().unwrap();
        let dep = "dep-snap-test";

        // Record non-durable and durable snapshots
        store.record_snapshot("snap-1", dep, 1, "vol-a", "/vol/snap1", 100, false).unwrap();
        store.record_snapshot("snap-2", dep, 1, "vol-a", "/vol/snap2", 200, true).unwrap();
        store.record_snapshot("snap-3", dep, 1, "vol-b", "/vol/snap3", 205, true).unwrap();

        // Query returns latest durable snapshot (snap-3 was captured at 205 > snap-2 at 200)
        let retrieved = store.get_durable_snapshot(dep, 1).unwrap();
        assert_eq!(retrieved, Some("/vol/snap3".to_string()));

        // Query for volume returns specific snapshot
        let vol_a = store.get_durable_snapshot_for_volume(dep, 1, "vol-a").unwrap();
        assert_eq!(vol_a, Some("/vol/snap2".to_string()));
        let vol_b = store.get_durable_snapshot_for_volume(dep, 1, "vol-b").unwrap();
        assert_eq!(vol_b, Some("/vol/snap3".to_string()));

        let all_vols = store.get_durable_snapshots_for_generation(dep, 1).unwrap();
        assert_eq!(all_vols.len(), 2);
        assert_eq!(all_vols.get("vol-a"), Some(&"/vol/snap2".to_string()));
        assert_eq!(all_vols.get("vol-b"), Some(&"/vol/snap3".to_string()));

        // Gen 2 has no snapshots yet
        assert_eq!(store.get_durable_snapshot(dep, 2).unwrap(), None);
    }
}
