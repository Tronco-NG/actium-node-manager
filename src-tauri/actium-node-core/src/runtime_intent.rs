use serde::{Deserialize, Serialize};

pub const RUNTIME_INTENT_SCHEMA: u32 = 1;
pub const RUNTIME_INTENT_RELATIVE_PATH: &str = "state/runtime-intent.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDesiredState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeIntentSource {
    Commissioning,
    Operator,
    Migration,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeIntent {
    pub schema: u32,
    pub revision: u64,
    pub desired_state: RuntimeDesiredState,
    pub source: RuntimeIntentSource,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStartupMode {
    Commissioning,
    LocalOperational,
}

impl RuntimeIntent {
    pub fn new(
        desired_state: RuntimeDesiredState,
        source: RuntimeIntentSource,
        updated_at: impl Into<String>,
    ) -> Self {
        Self {
            schema: RUNTIME_INTENT_SCHEMA,
            revision: 1,
            desired_state,
            source,
            updated_at: updated_at.into(),
        }
    }

    pub fn successor(
        &self,
        desired_state: RuntimeDesiredState,
        source: RuntimeIntentSource,
        updated_at: impl Into<String>,
    ) -> Self {
        Self {
            schema: RUNTIME_INTENT_SCHEMA,
            revision: self.revision.saturating_add(1),
            desired_state,
            source,
            updated_at: updated_at.into(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != RUNTIME_INTENT_SCHEMA {
            return Err(format!(
                "RUNTIME_INTENT_SCHEMA_UNSUPPORTED: {}",
                self.schema
            ));
        }
        if self.revision == 0 {
            return Err("RUNTIME_INTENT_REVISION_INVALID".to_string());
        }
        if self.updated_at.trim().is_empty() {
            return Err("RUNTIME_INTENT_UPDATED_AT_INVALID".to_string());
        }
        Ok(())
    }
}

pub fn marker_represents_empty_initial_commissioning(
    marker_status: Option<&str>,
    active_release_present: bool,
) -> bool {
    !active_release_present
        && matches!(
            marker_status.map(str::trim),
            None | Some("") | Some("failed") | Some("installing") | Some("prepared")
        )
}

pub fn migrate_runtime_desired_state(
    marker_status: Option<&str>,
    active_release_present: bool,
) -> Option<RuntimeDesiredState> {
    if marker_status.map(str::trim) == Some("stopped") {
        return Some(RuntimeDesiredState::Stopped);
    }
    if active_release_present
        && !marker_represents_empty_initial_commissioning(marker_status, active_release_present)
    {
        return Some(RuntimeDesiredState::Running);
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeReconcileDecision {
    SkipNoIntent,
    EnsureStopped,
    AlreadyHealthy,
    StartActiveRelease,
}

pub fn decide_runtime_reconcile(
    intent: Option<RuntimeDesiredState>,
    locally_healthy: bool,
) -> RuntimeReconcileDecision {
    match intent {
        None => RuntimeReconcileDecision::SkipNoIntent,
        Some(RuntimeDesiredState::Stopped) => RuntimeReconcileDecision::EnsureStopped,
        Some(RuntimeDesiredState::Running) if locally_healthy => {
            RuntimeReconcileDecision::AlreadyHealthy
        }
        Some(RuntimeDesiredState::Running) => RuntimeReconcileDecision::StartActiveRelease,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decide_runtime_reconcile, marker_represents_empty_initial_commissioning,
        migrate_runtime_desired_state, RuntimeDesiredState, RuntimeIntent, RuntimeIntentSource,
        RuntimeReconcileDecision,
    };

    #[test]
    fn fixture_failed_con_lkg_migra_a_running() {
        assert_eq!(
            migrate_runtime_desired_state(Some("failed"), true),
            Some(RuntimeDesiredState::Running)
        );
        assert!(!marker_represents_empty_initial_commissioning(
            Some("failed"),
            true
        ));
    }

    #[test]
    fn marker_stopped_migra_a_stopped() {
        assert_eq!(
            migrate_runtime_desired_state(Some("stopped"), true),
            Some(RuntimeDesiredState::Stopped)
        );
    }

    #[test]
    fn commissioning_vacio_no_inventa_running() {
        assert!(marker_represents_empty_initial_commissioning(
            Some("failed"),
            false
        ));
        assert_eq!(migrate_runtime_desired_state(Some("failed"), false), None);
        assert_eq!(
            migrate_runtime_desired_state(Some("installing"), false),
            None
        );
        assert_eq!(migrate_runtime_desired_state(Some("prepared"), false), None);
    }

    #[test]
    fn sucesor_incrementa_revision_y_conserva_schema() {
        let first = RuntimeIntent::new(
            RuntimeDesiredState::Running,
            RuntimeIntentSource::Commissioning,
            "2026-08-19T00:00:00Z",
        );
        let next = first.successor(
            RuntimeDesiredState::Stopped,
            RuntimeIntentSource::Operator,
            "2026-08-19T00:01:00Z",
        );
        assert_eq!(next.schema, 1);
        assert_eq!(next.revision, 2);
        assert_eq!(next.desired_state, RuntimeDesiredState::Stopped);
        next.validate().unwrap();
    }

    #[test]
    fn reconciler_no_recrea_si_esta_sano() {
        assert_eq!(
            decide_runtime_reconcile(Some(RuntimeDesiredState::Running), true),
            RuntimeReconcileDecision::AlreadyHealthy
        );
    }

    #[test]
    fn reconciler_inicia_si_faltan_contenedores() {
        assert_eq!(
            decide_runtime_reconcile(Some(RuntimeDesiredState::Running), false),
            RuntimeReconcileDecision::StartActiveRelease
        );
    }

    #[test]
    fn reconciler_no_inicia_si_esta_stopped() {
        assert_eq!(
            decide_runtime_reconcile(Some(RuntimeDesiredState::Stopped), false),
            RuntimeReconcileDecision::EnsureStopped
        );
    }

    #[test]
    fn reconciler_omite_sin_intent() {
        assert_eq!(
            decide_runtime_reconcile(None, false),
            RuntimeReconcileDecision::SkipNoIntent
        );
    }
}
