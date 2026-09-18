//! Direct WAN attestation state machine.
//!
//! Probe-caller IP is not the Site public ingress IP.  READY requires DNS,
//! TLS, TCP 443, Site identity and Outside-In evidence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Unknown,
    NotProvisioned,
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectWanReadiness {
    NotReady,
    Ready,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectWanEvidenceV1 {
    pub dns_status: EvidenceStatus,
    pub resolved_addresses: Vec<String>,
    pub tcp443_status: EvidenceStatus,
    pub tls_status: EvidenceStatus,
    pub certificate_identity: Option<String>,
    pub certificate_fingerprint: Option<String>,
    pub site_identity_status: EvidenceStatus,
    pub outside_in_status: EvidenceStatus,
    pub latency_ms: Option<u64>,
    pub checked_at: String,
    pub expires_at: String,
    pub probe_caller_ip: Option<String>,
    pub site_public_ingress_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectWanAttestationDecisionV1 {
    pub ready: DirectWanReadiness,
    pub reason: String,
    pub evidence: DirectWanEvidenceV1,
}

pub fn evaluate_direct_wan(evidence: DirectWanEvidenceV1) -> DirectWanAttestationDecisionV1 {
    let required = [
        ("dns", evidence.dns_status),
        ("tls", evidence.tls_status),
        ("tcp443", evidence.tcp443_status),
        ("site_identity", evidence.site_identity_status),
        ("outside_in", evidence.outside_in_status),
    ];
    if let Some((name, _)) = required.iter().find(|(_, status)| *status != EvidenceStatus::Pass) {
        return DirectWanAttestationDecisionV1 {
            ready: DirectWanReadiness::NotReady,
            reason: format!("{name}_not_pass"),
            evidence,
        };
    }
    if evidence.resolved_addresses.is_empty() {
        return DirectWanAttestationDecisionV1 {
            ready: DirectWanReadiness::NotReady,
            reason: "dns_addresses_missing".into(),
            evidence,
        };
    }
    DirectWanAttestationDecisionV1 {
        ready: DirectWanReadiness::Ready,
        reason: "dns_tls_tcp443_site_identity_outside_in_pass".into(),
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(pass: bool) -> DirectWanEvidenceV1 {
        let status = if pass {
            EvidenceStatus::Pass
        } else {
            EvidenceStatus::Unknown
        };
        DirectWanEvidenceV1 {
            dns_status: status,
            resolved_addresses: if pass {
                vec!["203.0.113.10".into()]
            } else {
                Vec::new()
            },
            tcp443_status: status,
            tls_status: status,
            certificate_identity: Some("00ed1921098e4efdb71dfbc220278486.sites.actiumsecurity.com".into()),
            certificate_fingerprint: Some("sha256:abc".into()),
            site_identity_status: status,
            outside_in_status: status,
            latency_ms: Some(42),
            checked_at: "1".into(),
            expires_at: "2".into(),
            probe_caller_ip: Some("198.51.100.9".into()),
            site_public_ingress_ip: Some("203.0.113.10".into()),
        }
    }

    #[test]
    fn https_alone_is_not_ready() {
        let mut value = evidence(true);
        value.outside_in_status = EvidenceStatus::Unknown;
        value.tls_status = EvidenceStatus::Pass;
        value.tcp443_status = EvidenceStatus::Pass;
        let decision = evaluate_direct_wan(value);
        assert_eq!(decision.ready, DirectWanReadiness::NotReady);
        assert_eq!(decision.reason, "outside_in_not_pass");
    }

    #[test]
    fn all_gates_pass_is_ready() {
        let decision = evaluate_direct_wan(evidence(true));
        assert_eq!(decision.ready, DirectWanReadiness::Ready);
    }

    #[test]
    fn probe_caller_ip_is_not_used_as_ingress_ip() {
        let mut value = evidence(true);
        value.probe_caller_ip = Some("198.51.100.9".into());
        value.site_public_ingress_ip = Some("203.0.113.10".into());
        let decision = evaluate_direct_wan(value);
        assert_ne!(
            decision.evidence.probe_caller_ip,
            decision.evidence.site_public_ingress_ip
        );
        assert_eq!(decision.ready, DirectWanReadiness::Ready);
    }
}
