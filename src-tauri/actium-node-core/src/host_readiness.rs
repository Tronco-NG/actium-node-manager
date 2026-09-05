use serde::{Deserialize, Serialize};
use crate::HostBindingProjection;

/// Read-only projection of Host readiness.  It deliberately carries
/// diagnostics and public metadata only; it is not a second authority for
/// enrollment, grants or signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostReadinessCheck {
    pub state: String,
    pub code: Option<String>,
    pub detail: String,
}

impl HostReadinessCheck {
    pub fn ready(detail: impl Into<String>) -> Self {
        Self { state: "READY".into(), code: None, detail: detail.into() }
    }

    pub fn warning(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { state: "READY_WITH_WARNINGS".into(), code: Some(code.into()), detail: detail.into() }
    }

    pub fn degraded(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { state: "DEGRADED".into(), code: Some(code.into()), detail: detail.into() }
    }

    pub fn blocked(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { state: "BLOCKED".into(), code: Some(code.into()), detail: detail.into() }
    }

    pub fn unknown(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { state: "UNKNOWN".into(), code: Some(code.into()), detail: detail.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostReadinessReport {
    pub global_state: String,
    pub observed_at_unix_seconds: u64,
    pub identity: HostReadinessCheck,
    pub site_binding: HostReadinessCheck,
    pub supervisor: HostReadinessCheck,
    pub ipc: HostReadinessCheck,
    pub mutation_arbiter: HostReadinessCheck,
    pub runtime: HostReadinessCheck,
    pub storage: HostReadinessCheck,
    pub storage_grants: HostReadinessCheck,
    pub transactions: HostReadinessCheck,
    pub signing_trust: HostReadinessCheck,
    pub center_approval_signer: HostReadinessCheck,
    pub material_attestation: HostReadinessCheck,
    pub system: HostReadinessCheck,
    pub clock: HostReadinessCheck,
    pub network: HostReadinessCheck,
    pub nats: HostReadinessCheck,
    #[serde(default)]
    pub host_binding: Option<HostBindingProjection>,
}

impl HostReadinessReport {
    pub fn from_checks(observed_at_unix_seconds: u64, checks: [HostReadinessCheck; 16]) -> Self {
        // NATS es diagnóstico independiente: no debe degradar ni bloquear el
        // Host Readiness cuando Storage/Supervisor no dependen de él.
        let global_state = aggregate_state(&checks[..15]);
        let [identity, site_binding, supervisor, ipc, mutation_arbiter, runtime, storage,
            storage_grants, transactions, signing_trust, center_approval_signer,
            material_attestation, system, clock, network, nats] = checks;
        Self {
            global_state,
            observed_at_unix_seconds,
            identity,
            site_binding,
            supervisor,
            ipc,
            mutation_arbiter,
            runtime,
            storage,
            storage_grants,
            transactions,
            signing_trust,
            center_approval_signer,
            material_attestation,
            system,
            clock,
            network,
            nats,
            host_binding: None,
        }
    }
}

fn aggregate_state(checks: &[HostReadinessCheck]) -> String {
    if checks.iter().any(|check| check.state == "BLOCKED") {
        return "BLOCKED".into();
    }
    if checks.iter().any(|check| check.state == "DEGRADED") {
        return "DEGRADED".into();
    }
    if checks.iter().any(|check| check.state == "UNKNOWN") {
        return "UNKNOWN".into();
    }
    if checks.iter().any(|check| check.state == "READY_WITH_WARNINGS") {
        return "READY_WITH_WARNINGS".into();
    }
    "READY".into()
}

#[cfg(test)]
mod tests {
    use super::{HostReadinessCheck, HostReadinessReport};

    fn checks() -> [HostReadinessCheck; 16] {
        std::array::from_fn(|_| HostReadinessCheck::ready("ok"))
    }

    #[test]
    fn readiness_prioriza_bloqueo_y_degradacion() {
        let mut values = checks();
        values[0] = HostReadinessCheck::warning("WARN", "warning");
        assert_eq!(HostReadinessReport::from_checks(1, values).global_state, "READY_WITH_WARNINGS");
        let mut values = checks();
        values[1] = HostReadinessCheck::degraded("DEGRADED", "degraded");
        assert_eq!(HostReadinessReport::from_checks(1, values).global_state, "DEGRADED");
        let mut values = checks();
        values[2] = HostReadinessCheck::blocked("BLOCKED", "blocked");
        assert_eq!(HostReadinessReport::from_checks(1, values).global_state, "BLOCKED");
    }

    #[test]
    fn nats_diagnostico_no_contamina_estado_global() {
        let mut values = checks();
        values[15] = HostReadinessCheck::unknown("NATS_DIAGNOSTIC_ONLY", "nats");
        assert_eq!(HostReadinessReport::from_checks(1, values).global_state, "READY");
    }

    #[test]
    fn unknown_no_se_presenta_como_ready() {
        let mut values = checks();
        values[14] = HostReadinessCheck::unknown("NETWORK_OBSERVATION_INCOMPLETE", "sin contrato");
        assert_eq!(HostReadinessReport::from_checks(1, values).global_state, "UNKNOWN");
    }
}
