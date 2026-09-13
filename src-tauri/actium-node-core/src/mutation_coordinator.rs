use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

static INTERACTIVE_TARGETS: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPriority {
    BackgroundAttestation = 0,
    ScheduledReconciliation = 1,
    Interactive = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationCoordinatorPhase {
    Idle,
    Queued,
    Waiting,
    Granted,
    Executing,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationCoordinatorStatus {
    pub active_phase: MutationCoordinatorPhase,
    pub interactive_pending: bool,
    pub active_lock_path: Option<String>,
}

pub struct MutationCoordinator;

impl MutationCoordinator {
    /// Indica si un root específico tiene una mutación interactiva encolada o en curso.
    pub fn should_yield_to_interactive_for(root: &Path) -> bool {
        if let Ok(guard) = INTERACTIVE_TARGETS.lock() {
            if let Some(set) = guard.as_ref() {
                return set.contains(root);
            }
        }
        false
    }

    /// Indica a nivel global si existe alguna mutación interactiva encolada.
    pub fn should_yield_to_interactive() -> bool {
        if let Ok(guard) = INTERACTIVE_TARGETS.lock() {
            if let Some(set) = guard.as_ref() {
                return !set.is_empty();
            }
        }
        false
    }

    /// Notifica que una mutación interactiva fue requerida sobre un nodo o fabric específico.
    pub fn signal_interactive_request(root: &Path) {
        if let Ok(mut guard) = INTERACTIVE_TARGETS.lock() {
            let set = guard.get_or_insert_with(HashSet::new);
            set.insert(root.to_path_buf());
        }
    }

    /// Limpia la señal de mutación interactiva para ese root.
    pub fn clear_interactive_request(root: &Path) {
        if let Ok(mut guard) = INTERACTIVE_TARGETS.lock() {
            if let Some(set) = guard.as_mut() {
                set.remove(root);
            }
        }
    }

    /// Estado general del coordinador.
    pub fn current_status() -> MutationCoordinatorStatus {
        let pending = Self::should_yield_to_interactive();
        MutationCoordinatorStatus {
            active_phase: if pending {
                MutationCoordinatorPhase::Waiting
            } else {
                MutationCoordinatorPhase::Idle
            },
            interactive_pending: pending,
            active_lock_path: None,
        }
    }

    /// Adquisición coordinada y resiliente del lock de mutación sobre un root dado
    /// (sea un nodo o un fabric). Soporta prioridades, timeout con backoff exponencial
    /// y cede cooperativamente si un proceso interactivo sobre ese root tiene precedencia.
    pub fn acquire_mutation_lock(
        node_or_fabric_root: &Path,
        priority: MutationPriority,
        timeout: Duration,
    ) -> Result<crate::releases::ReleaseMutationGuard, String> {
        let is_interactive = priority == MutationPriority::Interactive;
        if is_interactive {
            Self::signal_interactive_request(node_or_fabric_root);
        }

        let state_dir = node_or_fabric_root.join("state");
        if !state_dir.exists() {
            let _ = fs::create_dir_all(&state_dir);
        }
        let lock_path = state_dir.join("release-mutation.lock");

        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                if is_interactive {
                    Self::clear_interactive_request(node_or_fabric_root);
                }
                format!("No se pudo abrir el lock {}: {error}", lock_path.display())
            })?;

        let start = Instant::now();
        let mut backoff = Duration::from_millis(50);
        let max_backoff = Duration::from_millis(500);

        loop {
            // Si una tarea de fondo ve que hay una mutación interactiva encolada para este root, cede inmediatamente.
            if !is_interactive && Self::should_yield_to_interactive_for(node_or_fabric_root) {
                return Err("MUTATION_BUSY: Cediendo lock ante mutacion interactiva prioritaria.".to_string());
            }

            match file.try_lock_exclusive() {
                Ok(()) => {
                    if is_interactive {
                        Self::clear_interactive_request(node_or_fabric_root);
                    }
                    return Ok(crate::releases::ReleaseMutationGuard::new_raw(
                        file,
                        node_or_fabric_root.to_path_buf(),
                    ));
                }
                Err(error) => {
                    if !crate::releases::lock_is_contended(&error) {
                        if is_interactive {
                            Self::clear_interactive_request(node_or_fabric_root);
                        }
                        return Err(format!(
                            "Falla de E/S adquiriendo lock sobre {}: {error}",
                            node_or_fabric_root.display()
                        ));
                    }

                    if start.elapsed() >= timeout {
                        if is_interactive {
                            Self::clear_interactive_request(node_or_fabric_root);
                        }
                        return Err(format!(
                            "MUTATION_BUSY: Tiempo de espera agotado ({:?}) adquiriendo autoridad sobre {}.",
                            timeout,
                            node_or_fabric_root.display()
                        ));
                    }

                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }
}
