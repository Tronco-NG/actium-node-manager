use crate::redact_sensitive;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const ACTIVE_STATES: [&str; 5] = ["queued", "running", "validating", "staging", "promoting"];
pub const MUTATION_LEASE_SECONDS: i64 = 300;
pub const MUTATION_HEARTBEAT_SECONDS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JournalOperation {
    pub id: String,
    pub idempotency_key: String,
    pub actor: String,
    pub target_node_id: String,
    pub install_dir: String,
    pub node_label: String,
    pub terminal_id: Option<String>,
    pub action: String,
    pub requested_release: Option<String>,
    /// Non-secret operation context used to correlate typed workflows.  It
    /// is deliberately separate from requested_release for old journal
    /// compatibility and is redacted before persistence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_json: Option<String>,
    pub state: String,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub current_step: String,
    pub output_redacted: String,
    pub recovery_policy: String,
    pub error_code: Option<String>,
    #[serde(default)]
    pub attempt_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MutationStatus {
    pub observed_at: String,
    pub state: String,
    pub active_operations: usize,
    pub queued_operations: usize,
    pub recoverable_operations: usize,
    pub blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct JournalUpdate<'a> {
    pub state: &'a str,
    pub current_step: &'a str,
    pub output: &'a str,
    pub started_at: Option<&'a str>,
    pub finished_at: Option<&'a str>,
    pub error_code: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct OperationJournal {
    path: PathBuf,
}

impl OperationJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("No se pudo crear el directorio del journal: {error}"))?;
        }
        let journal = Self { path };
        let connection = journal.connection()?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS operations (
                   id TEXT PRIMARY KEY,
                   idempotency_key TEXT NOT NULL,
                   actor TEXT NOT NULL,
                   target_node_id TEXT NOT NULL,
                   install_dir TEXT NOT NULL,
                   node_label TEXT NOT NULL,
                   terminal_id TEXT,
                   action TEXT NOT NULL,
                   requested_release TEXT,
                   metadata_json TEXT,
                   state TEXT NOT NULL,
                   queued_at TEXT NOT NULL,
                   started_at TEXT,
                   finished_at TEXT,
                   current_step TEXT NOT NULL,
                   output_redacted TEXT NOT NULL,
                   recovery_policy TEXT NOT NULL,
                   error_code TEXT,
                   attempt_count INTEGER NOT NULL DEFAULT 0,
                   lease_expires_at TEXT
                 );
                 CREATE INDEX IF NOT EXISTS idx_operations_queued ON operations(queued_at DESC);
                 CREATE INDEX IF NOT EXISTS idx_operations_idempotency ON operations(idempotency_key, state);",
            )
            .map_err(|error| format!("No se pudo inicializar el journal: {error}"))?;
        journal.ensure_schema(&connection)?;
        Ok(journal)
    }

    fn ensure_schema(&self, connection: &Connection) -> Result<(), String> {
        let mut statement = connection
            .prepare("PRAGMA table_info(operations)")
            .map_err(|error| format!("No se pudo inspeccionar el schema del journal: {error}"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| format!("No se pudo leer el schema del journal: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("No se pudo enumerar el schema del journal: {error}"))?;
        if !columns.iter().any(|column| column == "attempt_count") {
            connection
                .execute(
                    "ALTER TABLE operations ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0",
                    [],
                )
                .map_err(|error| format!("No se pudo migrar attempt_count: {error}"))?;
        }
        if !columns.iter().any(|column| column == "lease_expires_at") {
            connection
                .execute(
                    "ALTER TABLE operations ADD COLUMN lease_expires_at TEXT",
                    [],
                )
                .map_err(|error| format!("No se pudo migrar lease_expires_at: {error}"))?;
        }
        if !columns.iter().any(|column| column == "metadata_json") {
            connection
                .execute("ALTER TABLE operations ADD COLUMN metadata_json TEXT", [])
                .map_err(|error| format!("No se pudo migrar metadata_json: {error}"))?;
        }
        connection
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_operations_lease ON operations(lease_expires_at)",
                [],
            )
            .map_err(|error| format!("No se pudo crear el indice de leases: {error}"))?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection, String> {
        let connection = Connection::open(&self.path)
            .map_err(|error| format!("No se pudo abrir {}: {error}", self.path.display()))?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|error| format!("No se pudo configurar SQLite: {error}"))?;
        Ok(connection)
    }

    pub fn enqueue(&self, operation: &JournalOperation) -> Result<JournalOperation, String> {
        let connection = self.connection()?;
        let states = ACTIVE_STATES.map(|value| format!("'{value}'")).join(",");
        let query = format!(
            "SELECT id, idempotency_key, actor, target_node_id, install_dir, node_label,
                    terminal_id, action, requested_release, metadata_json, state, queued_at, started_at,
                    finished_at, current_step, output_redacted, recovery_policy, error_code,
                    attempt_count, lease_expires_at
             FROM operations WHERE idempotency_key = ?1 AND state IN ({states})
             ORDER BY queued_at DESC LIMIT 1"
        );
        if let Some(existing) = connection
            .query_row(&query, [&operation.idempotency_key], map_operation)
            .optional()
            .map_err(|error| format!("No se pudo consultar idempotencia: {error}"))?
        {
            return Ok(existing);
        }
        connection
            .execute(
                "INSERT INTO operations (
                   id, idempotency_key, actor, target_node_id, install_dir, node_label,
                   terminal_id, action, requested_release, metadata_json, state, queued_at, started_at,
                   finished_at, current_step, output_redacted, recovery_policy, error_code,
                   attempt_count, lease_expires_at
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                params![
                    operation.id,
                    operation.idempotency_key,
                    operation.actor,
                    operation.target_node_id,
                    operation.install_dir,
                    operation.node_label,
                    operation.terminal_id,
                    operation.action,
                    operation.requested_release,
                    operation.metadata_json.as_deref().map(redact_sensitive),
                    operation.state,
                    operation.queued_at,
                    operation.started_at,
                    operation.finished_at,
                    operation.current_step,
                    redact_sensitive(&operation.output_redacted),
                    operation.recovery_policy,
                    operation.error_code,
                    operation.attempt_count,
                    operation.lease_expires_at,
                ],
            )
            .map_err(|error| format!("No se pudo persistir la operacion: {error}"))?;
        Ok(operation.clone())
    }

    /// Read the latest operation for an idempotency key across terminal and
    /// active states.  Typed workflows use this to prevent a retry from
    /// silently creating a second irreversible attempt.
    pub fn find_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<JournalOperation>, String> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, idempotency_key, actor, target_node_id, install_dir, node_label,
                        terminal_id, action, requested_release, metadata_json, state, queued_at, started_at,
                        finished_at, current_step, output_redacted, recovery_policy, error_code,
                        attempt_count, lease_expires_at
                 FROM operations WHERE idempotency_key=?1 ORDER BY queued_at DESC LIMIT 1",
                [idempotency_key],
                map_operation,
            )
            .optional()
            .map_err(|error| format!("No se pudo consultar la operacion por idempotencia: {error}"))
    }

    pub fn list(&self, limit: usize) -> Result<Vec<JournalOperation>, String> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, idempotency_key, actor, target_node_id, install_dir, node_label,
                        terminal_id, action, requested_release, metadata_json, state, queued_at, started_at,
                        finished_at, current_step, output_redacted, recovery_policy, error_code,
                        attempt_count, lease_expires_at
                 FROM operations ORDER BY queued_at DESC LIMIT ?1",
            )
            .map_err(|error| format!("No se pudo preparar el historial: {error}"))?;
        let rows = statement
            .query_map([limit as i64], map_operation)
            .map_err(|error| format!("No se pudo consultar el historial: {error}"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("No se pudo leer el historial: {error}"))
    }

    pub fn claim_next_queued(&self, started_at: &str) -> Result<Option<JournalOperation>, String> {
        let mut connection = self.connection()?;
        self.recover_expired_leases_at(&connection, unix_now())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("No se pudo bloquear la cola durable: {error}"))?;
        let operation = transaction
            .query_row(
                "SELECT id, idempotency_key, actor, target_node_id, install_dir, node_label,
                        terminal_id, action, requested_release, metadata_json, state, queued_at, started_at,
                        finished_at, current_step, output_redacted, recovery_policy, error_code,
                        attempt_count, lease_expires_at
                 FROM operations WHERE state='queued' ORDER BY queued_at ASC LIMIT 1",
                [],
                map_operation,
            )
            .optional()
            .map_err(|error| format!("No se pudo reclamar la siguiente operacion: {error}"))?;
        let Some(mut operation) = operation else {
            transaction
                .commit()
                .map_err(|error| format!("No se pudo liberar la cola durable: {error}"))?;
            return Ok(None);
        };
        let changed = transaction
            .execute(
                "UPDATE operations SET state='running', started_at=?2, current_step='executing',
                        attempt_count=attempt_count + 1, lease_expires_at=?3
                 WHERE id=?1 AND state='queued'",
                params![
                    operation.id,
                    started_at,
                    (unix_now() + MUTATION_LEASE_SECONDS).to_string()
                ],
            )
            .map_err(|error| format!("No se pudo iniciar la operacion durable: {error}"))?;
        if changed != 1 {
            return Err("La operacion cambio mientras se reclamaba la cola.".to_string());
        }
        transaction
            .commit()
            .map_err(|error| format!("No se pudo confirmar el inicio de la operacion: {error}"))?;
        operation.state = "running".to_string();
        operation.started_at = Some(started_at.to_string());
        operation.current_step = "executing".to_string();
        operation.attempt_count = operation.attempt_count.saturating_add(1);
        operation.lease_expires_at = Some((unix_now() + MUTATION_LEASE_SECONDS).to_string());
        Ok(Some(operation))
    }

    pub fn cancel_queued(&self, id: &str, finished_at: &str) -> Result<JournalOperation, String> {
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE operations SET state='cancelled', current_step='cancelled_by_user',
                   finished_at=?2, error_code='CANCELLED_BY_USER'
                 WHERE id=?1 AND state='queued'",
                params![id, finished_at],
            )
            .map_err(|error| format!("No se pudo cancelar la operacion: {error}"))?;
        if changed != 1 {
            return Err(
                "Solo se pueden cancelar operaciones que todavia estan en cola.".to_string(),
            );
        }
        connection
            .query_row(
                "SELECT id, idempotency_key, actor, target_node_id, install_dir, node_label,
                        terminal_id, action, requested_release, metadata_json, state, queued_at, started_at,
                        finished_at, current_step, output_redacted, recovery_policy, error_code,
                        attempt_count, lease_expires_at
                 FROM operations WHERE id=?1",
                [id],
                map_operation,
            )
            .map_err(|error| format!("No se pudo leer la operacion cancelada: {error}"))
    }

    pub fn update(&self, id: &str, update: JournalUpdate<'_>) -> Result<(), String> {
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE operations SET state=?2, current_step=?3,
                   output_redacted=CASE WHEN ?4 = '' THEN output_redacted ELSE ?4 END,
                   started_at=COALESCE(?5, started_at), finished_at=?6, error_code=?7,
                   lease_expires_at=CASE WHEN ?2 IN ('completed','failed','rolled_back','manual_intervention_required','cancelled','interrupted') THEN NULL ELSE lease_expires_at END
                 WHERE id=?1",
                params![
                    id,
                    update.state,
                    update.current_step,
                    redact_sensitive(update.output),
                    update.started_at,
                    update.finished_at,
                    update.error_code
                ],
            )
            .map_err(|error| format!("No se pudo actualizar la operacion: {error}"))?;
        if changed == 0 {
            return Err(format!("La operacion {id} no existe en el journal."));
        }
        Ok(())
    }

    pub fn recover_interrupted(&self, recovered_at: &str) -> Result<usize, String> {
        let connection = self.connection()?;
        connection
            .execute(
                "UPDATE operations SET state='interrupted', current_step='recovery_required',
                   finished_at=?1, error_code='PROCESS_INTERRUPTED', lease_expires_at=NULL
                 WHERE state IN ('running','validating','staging','promoting')",
                [recovered_at],
            )
            .map_err(|error| format!("No se pudo recuperar el journal: {error}"))
    }

    pub fn recover_expired_leases(&self, now: i64) -> Result<usize, String> {
        let connection = self.connection()?;
        self.recover_expired_leases_at(&connection, now)
    }

    fn recover_expired_leases_at(
        &self,
        connection: &Connection,
        now: i64,
    ) -> Result<usize, String> {
        connection
            .execute(
                "UPDATE operations
                 SET state='queued', started_at=NULL, finished_at=NULL,
                     current_step='lease_expired_requeued', error_code='LEASE_EXPIRED',
                     lease_expires_at=NULL
                 WHERE state IN ('running','validating','staging','promoting')
                   AND lease_expires_at IS NOT NULL
                   AND CAST(lease_expires_at AS INTEGER) <= ?1",
                [now],
            )
            .map_err(|error| format!("No se pudo recuperar leases vencidos: {error}"))
    }

    /// Renew only an already-live lease.  An expired lease is never revived,
    /// so a crashed worker remains recoverable by the next claimant.
    pub fn renew_lease(&self, id: &str) -> Result<bool, String> {
        self.renew_lease_at(id, unix_now())
    }

    pub fn renew_lease_at(&self, id: &str, now: i64) -> Result<bool, String> {
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE operations SET lease_expires_at=?2
                 WHERE id=?1 AND state IN ('running','validating','staging','promoting')
                   AND lease_expires_at IS NOT NULL
                   AND CAST(lease_expires_at AS INTEGER) > ?3",
                params![id, (now + MUTATION_LEASE_SECONDS).to_string(), now],
            )
            .map_err(|error| format!("No se pudo renovar el lease de la operacion: {error}"))?;
        Ok(changed == 1)
    }

    pub fn mutation_status(&self, observed_at: &str) -> Result<MutationStatus, String> {
        let connection = self.connection()?;
        let active = count_states(&connection, &ACTIVE_STATES)?;
        let queued = count_states(&connection, &["queued"])?;
        let recoverable = count_states(
            &connection,
            &["interrupted", "manual_intervention_required"],
        )?;
        let blocked_reason = if active > 0 && queued > 0 {
            Some("MUTATION_BUSY".to_string())
        } else if recoverable > 0 {
            // Never project a terminal error_code from an old operation as a
            // current blocker.  The state itself is the durable, actionable
            // reason and can be reconciled explicitly by the next operation.
            Some("MUTATION_RECOVERABLE".to_string())
        } else {
            None
        };
        let state = if active > 0 {
            "running"
        } else if queued > 0 {
            "queued"
        } else if recoverable > 0 {
            "blocked"
        } else {
            "idle"
        };
        Ok(MutationStatus {
            observed_at: observed_at.to_string(),
            state: state.to_string(),
            active_operations: active,
            queued_operations: queued,
            recoverable_operations: recoverable,
            blocked_reason,
        })
    }
}

fn count_states(connection: &Connection, states: &[&str]) -> Result<usize, String> {
    let quoted = states
        .iter()
        .map(|state| format!("'{state}'"))
        .collect::<Vec<_>>()
        .join(",");
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM operations WHERE state IN ({quoted})"),
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count.max(0) as usize)
        .map_err(|error| format!("No se pudo contar el estado de mutaciones: {error}"))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

fn map_operation(row: &rusqlite::Row<'_>) -> rusqlite::Result<JournalOperation> {
    Ok(JournalOperation {
        id: row.get(0)?,
        idempotency_key: row.get(1)?,
        actor: row.get(2)?,
        target_node_id: row.get(3)?,
        install_dir: row.get(4)?,
        node_label: row.get(5)?,
        terminal_id: row.get(6)?,
        action: row.get(7)?,
        requested_release: row.get(8)?,
        metadata_json: row.get(9)?,
        state: row.get(10)?,
        queued_at: row.get(11)?,
        started_at: row.get(12)?,
        finished_at: row.get(13)?,
        current_step: row.get(14)?,
        output_redacted: row.get(15)?,
        recovery_policy: row.get(16)?,
        error_code: row.get(17)?,
        attempt_count: row.get::<_, i64>(18)?.max(0) as u32,
        lease_expires_at: row.get(19)?,
    })
}

#[cfg(test)]
mod tests {
    use super::{JournalOperation, OperationJournal};
    use rusqlite::Connection;
    use uuid::Uuid;

    fn operation(id: &str) -> JournalOperation {
        JournalOperation {
            id: id.to_string(),
            idempotency_key: "node-1:restart".to_string(),
            actor: "local-user".to_string(),
            target_node_id: "node-1".to_string(),
            install_dir: "C:/ActiumLab/Nodes/node-1".to_string(),
            node_label: "Node 1".to_string(),
            terminal_id: None,
            action: "restart".to_string(),
            requested_release: None,
            metadata_json: None,
            state: "running".to_string(),
            queued_at: "2026-08-13T00:00:00Z".to_string(),
            started_at: Some("2026-08-13T00:00:01Z".to_string()),
            finished_at: None,
            current_step: "compose".to_string(),
            output_redacted: "token=secreto".to_string(),
            recovery_policy: "inspect_then_resume".to_string(),
            error_code: None,
            attempt_count: 0,
            lease_expires_at: None,
        }
    }

    fn queued_operation(id: &str) -> JournalOperation {
        let mut value = operation(id);
        value.state = "queued".to_string();
        value.started_at = None;
        value
    }

    #[test]
    fn persiste_idempotencia_redaccion_y_recovery() {
        let root = std::env::temp_dir().join(format!("actium-journal-{}", Uuid::new_v4()));
        let path = root.join("operations.sqlite3");
        let journal = OperationJournal::open(&path).expect("journal");
        let first = journal.enqueue(&operation("op-1")).expect("enqueue");
        let second = journal.enqueue(&operation("op-2")).expect("dedupe");
        assert_eq!(first.id, second.id);
        drop(journal);

        let reopened = OperationJournal::open(&path).expect("reopen");
        assert_eq!(
            reopened
                .recover_interrupted("2026-08-13T00:01:00Z")
                .expect("recover"),
            1
        );
        let rows = reopened.list(10).expect("list");
        assert_eq!(rows[0].state, "interrupted");
        assert!(!rows[0].output_redacted.contains("secreto"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn progress_sin_output_conserva_el_log() {
        let root = std::env::temp_dir().join(format!("actium-journal-keep-{}", Uuid::new_v4()));
        let path = root.join("operations.sqlite3");
        let journal = OperationJournal::open(&path).expect("journal");
        journal.enqueue(&operation("op-keep")).expect("enqueue");
        journal
            .update(
                "op-keep",
                super::JournalUpdate {
                    state: "running",
                    current_step: "runtime_synced",
                    output: "esperando autoridad",
                    started_at: None,
                    finished_at: None,
                    error_code: None,
                },
            )
            .expect("seed output");
        journal
            .update(
                "op-keep",
                super::JournalUpdate {
                    state: "running",
                    current_step: "runtime_synced",
                    output: "",
                    started_at: None,
                    finished_at: None,
                    error_code: None,
                },
            )
            .expect("empty progress");
        let rows = journal.list(10).expect("list");
        assert_eq!(rows[0].current_step, "runtime_synced");
        assert_eq!(rows[0].output_redacted, "esperando autoridad");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn migra_schema_legacy_y_reabre_con_attempt_y_lease() {
        let root = std::env::temp_dir().join(format!("actium-journal-legacy-{}", Uuid::new_v4()));
        let path = root.join("operations.sqlite3");
        std::fs::create_dir_all(&root).expect("legacy dir");
        let connection = Connection::open(&path).expect("legacy db");
        connection
            .execute_batch(
                "CREATE TABLE operations (
                   id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL, actor TEXT NOT NULL,
                   target_node_id TEXT NOT NULL, install_dir TEXT NOT NULL, node_label TEXT NOT NULL,
                   terminal_id TEXT, action TEXT NOT NULL, requested_release TEXT, state TEXT NOT NULL,
                   queued_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, current_step TEXT NOT NULL,
                   output_redacted TEXT NOT NULL, recovery_policy TEXT NOT NULL, error_code TEXT
                 );",
            )
            .expect("legacy schema");
        drop(connection);
        let journal = OperationJournal::open(&path).expect("upgrade");
        let row = journal
            .enqueue(&queued_operation("legacy-op"))
            .expect("enqueue");
        assert_eq!(row.attempt_count, 0);
        assert!(row.lease_expires_at.is_none());
        let reopened = OperationJournal::open(&path).expect("reopen");
        assert_eq!(reopened.list(10).expect("list")[0].id, "legacy-op");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lease_vencido_se_reencola_y_no_bloquea_por_error_historico() {
        let root = std::env::temp_dir().join(format!("actium-journal-lease-{}", Uuid::new_v4()));
        let path = root.join("operations.sqlite3");
        let journal = OperationJournal::open(&path).expect("journal");
        journal
            .enqueue(&queued_operation("lease-op"))
            .expect("enqueue");
        let claimed = journal
            .claim_next_queued("100")
            .expect("claim")
            .expect("operation");
        assert_eq!(claimed.attempt_count, 1);
        let connection = Connection::open(&path).expect("db");
        connection
            .execute(
                "UPDATE operations SET lease_expires_at='1' WHERE id='lease-op'",
                [],
            )
            .expect("expire");
        drop(connection);
        assert_eq!(journal.recover_expired_leases(2).expect("recover"), 1);
        let recovered = journal.list(10).expect("list");
        assert_eq!(recovered[0].state, "queued");
        assert_eq!(recovered[0].error_code.as_deref(), Some("LEASE_EXPIRED"));
        journal
            .update(
                "lease-op",
                super::JournalUpdate {
                    state: "failed",
                    current_step: "terminal_failure",
                    output: "",
                    started_at: None,
                    finished_at: Some("200"),
                    error_code: Some("OLD_TERMINAL_ERROR"),
                },
            )
            .expect("terminal");
        let status = journal.mutation_status("201").expect("status");
        assert_eq!(status.state, "idle");
        assert!(status.blocked_reason.is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mutation_status_es_read_only_y_no_repara_leases() {
        let root = std::env::temp_dir().join(format!("actium-journal-status-{}", Uuid::new_v4()));
        let path = root.join("operations.sqlite3");
        let journal = OperationJournal::open(&path).expect("journal");
        journal
            .enqueue(&queued_operation("status-op"))
            .expect("enqueue");
        journal
            .claim_next_queued("100")
            .expect("claim")
            .expect("operation");
        let connection = Connection::open(&path).expect("db");
        connection
            .execute(
                "UPDATE operations SET lease_expires_at='1' WHERE id='status-op'",
                [],
            )
            .expect("expire");
        drop(connection);
        let status = journal.mutation_status("101").expect("status");
        assert_eq!(status.state, "running");
        assert_eq!(
            journal.list(10).expect("list")[0]
                .lease_expires_at
                .as_deref(),
            Some("1")
        );
        assert_eq!(journal.recover_expired_leases(2).expect("recover"), 1);
        assert_eq!(journal.list(10).expect("list")[0].state, "queued");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn blocked_reason_no_reutiliza_error_terminal_historico() {
        let root = std::env::temp_dir().join(format!("actium-journal-blocked-{}", Uuid::new_v4()));
        let path = root.join("operations.sqlite3");
        let journal = OperationJournal::open(&path).expect("journal");
        journal
            .enqueue(&queued_operation("recoverable-op"))
            .expect("enqueue");
        let connection = Connection::open(&path).expect("db");
        connection.execute(
            "UPDATE operations SET state='interrupted', error_code='OLD_TERMINAL_ERROR', finished_at='100' WHERE id='recoverable-op'",
            [],
        ).expect("interrupt");
        drop(connection);
        let status = journal.mutation_status("101").expect("status");
        assert_eq!(status.state, "blocked");
        assert_eq!(
            status.blocked_reason.as_deref(),
            Some("MUTATION_RECOVERABLE")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn heartbeat_renueva_operacion_larga_y_abandono_se_recupera() {
        let root =
            std::env::temp_dir().join(format!("actium-journal-heartbeat-{}", Uuid::new_v4()));
        let path = root.join("operations.sqlite3");
        let journal = OperationJournal::open(&path).expect("journal");
        journal
            .enqueue(&queued_operation("long-op"))
            .expect("enqueue");
        journal
            .claim_next_queued("100")
            .expect("claim")
            .expect("operation");
        let connection = Connection::open(&path).expect("db");
        connection
            .execute(
                "UPDATE operations SET lease_expires_at='301' WHERE id='long-op'",
                [],
            )
            .expect("seed lease");
        drop(connection);
        assert!(journal.renew_lease_at("long-op", 200).expect("renew"));
        drop(journal);
        let reopened = OperationJournal::open(&path).expect("restart");
        assert_eq!(
            reopened.recover_expired_leases(400).expect("not abandoned"),
            0
        );
        assert_eq!(reopened.list(10).expect("list")[0].state, "running");
        assert_eq!(reopened.recover_expired_leases(501).expect("abandoned"), 1);
        assert_eq!(reopened.list(10).expect("list")[0].state, "queued");
        let _ = std::fs::remove_dir_all(root);
    }
}
