use crate::redact_sensitive;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

const ACTIVE_STATES: [&str; 5] = ["queued", "running", "validating", "staging", "promoting"];

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
    pub state: String,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub current_step: String,
    pub output_redacted: String,
    pub recovery_policy: String,
    pub error_code: Option<String>,
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
                   state TEXT NOT NULL,
                   queued_at TEXT NOT NULL,
                   started_at TEXT,
                   finished_at TEXT,
                   current_step TEXT NOT NULL,
                   output_redacted TEXT NOT NULL,
                   recovery_policy TEXT NOT NULL,
                   error_code TEXT
                 );
                 CREATE INDEX IF NOT EXISTS idx_operations_queued ON operations(queued_at DESC);
                 CREATE INDEX IF NOT EXISTS idx_operations_idempotency ON operations(idempotency_key, state);",
            )
            .map_err(|error| format!("No se pudo inicializar el journal: {error}"))?;
        Ok(journal)
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
                    terminal_id, action, requested_release, state, queued_at, started_at,
                    finished_at, current_step, output_redacted, recovery_policy, error_code
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
                   terminal_id, action, requested_release, state, queued_at, started_at,
                   finished_at, current_step, output_redacted, recovery_policy, error_code
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
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
                    operation.state,
                    operation.queued_at,
                    operation.started_at,
                    operation.finished_at,
                    operation.current_step,
                    redact_sensitive(&operation.output_redacted),
                    operation.recovery_policy,
                    operation.error_code,
                ],
            )
            .map_err(|error| format!("No se pudo persistir la operacion: {error}"))?;
        Ok(operation.clone())
    }

    pub fn list(&self, limit: usize) -> Result<Vec<JournalOperation>, String> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT id, idempotency_key, actor, target_node_id, install_dir, node_label,
                        terminal_id, action, requested_release, state, queued_at, started_at,
                        finished_at, current_step, output_redacted, recovery_policy, error_code
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
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| format!("No se pudo bloquear la cola durable: {error}"))?;
        let operation = transaction
            .query_row(
                "SELECT id, idempotency_key, actor, target_node_id, install_dir, node_label,
                        terminal_id, action, requested_release, state, queued_at, started_at,
                        finished_at, current_step, output_redacted, recovery_policy, error_code
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
                "UPDATE operations SET state='running', started_at=?2, current_step='executing'
                 WHERE id=?1 AND state='queued'",
                params![operation.id, started_at],
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
                        terminal_id, action, requested_release, state, queued_at, started_at,
                        finished_at, current_step, output_redacted, recovery_policy, error_code
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
                "UPDATE operations SET state=?2, current_step=?3, output_redacted=?4,
                   started_at=COALESCE(?5, started_at), finished_at=?6, error_code=?7 WHERE id=?1",
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
                   finished_at=?1, error_code='PROCESS_INTERRUPTED'
                 WHERE state IN ('running','validating','staging','promoting')",
                [recovered_at],
            )
            .map_err(|error| format!("No se pudo recuperar el journal: {error}"))
    }
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
        state: row.get(9)?,
        queued_at: row.get(10)?,
        started_at: row.get(11)?,
        finished_at: row.get(12)?,
        current_step: row.get(13)?,
        output_redacted: row.get(14)?,
        recovery_policy: row.get(15)?,
        error_code: row.get(16)?,
    })
}

#[cfg(test)]
mod tests {
    use super::{JournalOperation, OperationJournal};
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
            state: "running".to_string(),
            queued_at: "2026-08-13T00:00:00Z".to_string(),
            started_at: Some("2026-08-13T00:00:01Z".to_string()),
            finished_at: None,
            current_step: "compose".to_string(),
            output_redacted: "token=secreto".to_string(),
            recovery_policy: "inspect_then_resume".to_string(),
            error_code: None,
        }
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
}
