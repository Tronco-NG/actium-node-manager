//! Common Connectivity Client v1.
//!
//! Product → Common Connectivity Client → Connectivity Fabric
//! → LOCAL / PRIVATE / REMOTE → DIRECT / RELAY
//!
//! Center governs policy. This client executes a deterministic fail-closed
//! pipeline. Aegis is the first consumer; the client is product-neutral.

use crate::canonical_scope::{CanonicalConnectivityScopeV1, RequestedConnectivityScope};
use crate::connectivity_fabric::{ConnectivityRouteKind, ConnectivityRouteState, ServiceRoute};
use crate::relay_trust::CanonicalTrustState;
use serde::{Deserialize, Serialize};

pub const COMMON_CONNECTIVITY_CLIENT_CONTRACT: &str = "actium.connectivity.common-client.v1";
pub const COMMON_CONNECTIVITY_CLIENT_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommonRoutePolicy {
    Auto,
    DirectPreferred,
    RelayOnly,
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommonRouteKind {
    Local,
    Private,
    Remote,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CommonTransport {
    Local,
    Private,
    DirectWan,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommonConnectivityRequestV1 {
    pub contract: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub product_id: String,
    pub service_id: String,
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_generation: Option<u64>,
    pub route_policy: CommonRoutePolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_service_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommonConnectivityCandidateV1 {
    pub organization_id: Option<String>,
    pub client_id: Option<String>,
    pub site_id: Option<String>,
    pub host_id: Option<String>,
    pub product_id: Option<String>,
    pub service_id: String,
    pub capability: String,
    pub route_kind: CommonRouteKind,
    pub transport: CommonTransport,
    pub endpoint: String,
    pub expected_service_identity: String,
    pub authority_scope: String,
    pub trust_state: CanonicalTrustState,
    pub health: String,
    pub readiness: bool,
    pub priority: u16,
    pub binding_epoch: u64,
    pub configuration_version: u64,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CommonConnectivityResolutionV1 {
    pub contract: String,
    pub version: String,
    pub selected: Option<CommonConnectivityCandidateV1>,
    pub reason_code: Option<String>,
    pub candidates_considered: usize,
}

impl CommonConnectivityCandidateV1 {
    pub fn from_service_route(route: &ServiceRoute, trust_state: CanonicalTrustState) -> Self {
        let transport = classify_transport(route);
        let route_kind = match route.route_kind {
            ConnectivityRouteKind::Local => CommonRouteKind::Local,
            ConnectivityRouteKind::Private => CommonRouteKind::Private,
            ConnectivityRouteKind::Remote => CommonRouteKind::Remote,
        };
        let readiness = matches!(route.state, ConnectivityRouteState::Reachable)
            && route_health_ready(&route.health);
        Self {
            organization_id: route.organization_id.clone(),
            client_id: None,
            site_id: route.site_id.clone(),
            host_id: route.host_id.clone(),
            product_id: None,
            service_id: route.service_id.clone(),
            capability: route.capability.clone(),
            route_kind,
            transport,
            endpoint: route.endpoint.clone(),
            expected_service_identity: route.expected_service_identity.clone(),
            authority_scope: route.authority_scope.clone(),
            trust_state,
            health: route.health.clone(),
            readiness,
            priority: route.priority,
            binding_epoch: route.binding_epoch,
            configuration_version: route.configuration_version,
            reason: None,
        }
    }
}

fn classify_transport(route: &ServiceRoute) -> CommonTransport {
    let transport = route.transport.trim().to_ascii_lowercase();
    if transport == "relay" {
        return CommonTransport::Relay;
    }
    match route.route_kind {
        ConnectivityRouteKind::Local => CommonTransport::Local,
        ConnectivityRouteKind::Private => CommonTransport::Private,
        ConnectivityRouteKind::Remote => {
            if transport.contains("relay") {
                CommonTransport::Relay
            } else {
                CommonTransport::DirectWan
            }
        }
    }
}

fn route_health_ready(health: &str) -> bool {
    !matches!(
        health.trim().to_ascii_uppercase().as_str(),
        "UNREACHABLE" | "UNKNOWN" | "UNHEALTHY" | "FAILED" | "DOWN"
    )
}

fn policy_allows(policy: CommonRoutePolicy, transport: CommonTransport) -> Result<(), String> {
    match policy {
        CommonRoutePolicy::Disabled => Err("POLICY_BLOCKED".to_string()),
        CommonRoutePolicy::RelayOnly => {
            if matches!(transport, CommonTransport::Relay) {
                Ok(())
            } else {
                Err("POLICY_BLOCKED".to_string())
            }
        }
        CommonRoutePolicy::Auto | CommonRoutePolicy::DirectPreferred => Ok(()),
    }
}

fn transport_rank(policy: CommonRoutePolicy, transport: CommonTransport) -> u8 {
    match policy {
        CommonRoutePolicy::RelayOnly => 0,
        CommonRoutePolicy::Auto | CommonRoutePolicy::DirectPreferred | CommonRoutePolicy::Disabled => {
            match transport {
                CommonTransport::Local => 0,
                CommonTransport::Private => 1,
                CommonTransport::DirectWan => 2,
                CommonTransport::Relay => 3,
            }
        }
    }
}

fn candidate_sort_key(
    policy: CommonRoutePolicy,
    candidate: &CommonConnectivityCandidateV1,
) -> (u8, u16, String, String) {
    (
        transport_rank(policy, candidate.transport),
        candidate.priority,
        candidate.endpoint.clone(),
        candidate.service_id.clone(),
    )
}

fn scope_of_candidate(
    candidate: &CommonConnectivityCandidateV1,
    bound: &CanonicalConnectivityScopeV1,
) -> Result<(), String> {
    if candidate.organization_id.as_deref() != Some(bound.organization_id.as_str()) {
        return Err("SCOPE_MISMATCH".to_string());
    }
    if candidate.site_id.as_deref() != Some(bound.site_id.as_str()) {
        return Err("SCOPE_MISMATCH".to_string());
    }
    if candidate.host_id.as_deref() != Some(bound.host_id.as_str()) {
        return Err("SCOPE_MISMATCH".to_string());
    }
    match (&bound.client_id, &candidate.client_id) {
        (Some(bound_client), Some(candidate_client)) if bound_client == candidate_client => Ok(()),
        (None, None) => Ok(()),
        _ => Err("SCOPE_MISMATCH".to_string()),
    }
}

pub fn resolve_common_connectivity(
    bound: &CanonicalConnectivityScopeV1,
    request: &CommonConnectivityRequestV1,
    candidates: &[CommonConnectivityCandidateV1],
) -> CommonConnectivityResolutionV1 {
    fn fail(code: &str, considered: usize) -> CommonConnectivityResolutionV1 {
        CommonConnectivityResolutionV1 {
            contract: COMMON_CONNECTIVITY_CLIENT_CONTRACT.to_string(),
            version: COMMON_CONNECTIVITY_CLIENT_VERSION.to_string(),
            selected: None,
            reason_code: Some(code.to_string()),
            candidates_considered: considered,
        }
    }

    if request.contract != COMMON_CONNECTIVITY_CLIENT_CONTRACT {
        return fail("NO_ROUTE_AVAILABLE", 0);
    }
    if bound.validate().is_err() {
        return fail("SCOPE_UNRESOLVED", 0);
    }
    if bound
        .matches_request(&RequestedConnectivityScope {
            organization_id: request.organization_id.clone(),
            client_id: request.client_id.clone(),
            site_id: request.site_id.clone(),
            host_id: request.host_id.clone(),
            binding_epoch: request.binding_epoch,
            policy_generation: request.policy_generation,
        })
        .is_err()
    {
        let requested = RequestedConnectivityScope {
            organization_id: request.organization_id.clone(),
            client_id: request.client_id.clone(),
            site_id: request.site_id.clone(),
            host_id: request.host_id.clone(),
            binding_epoch: request.binding_epoch,
            policy_generation: request.policy_generation,
        };
        return fail(
            &bound.matches_request(&requested).unwrap_err(),
            0,
        );
    }
    if matches!(request.route_policy, CommonRoutePolicy::Disabled) {
        return fail("POLICY_BLOCKED", candidates.len());
    }

    let capability: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            candidate.service_id == request.service_id && candidate.capability == request.capability
        })
        .cloned()
        .collect();
    if capability.is_empty() {
        return fail("NO_ROUTE_AVAILABLE", 0);
    }
    let considered = capability.len();

    let mut remaining = Vec::new();
    for candidate in capability {
        if scope_of_candidate(&candidate, bound).is_err() {
            continue;
        }
        remaining.push(candidate);
    }
    if remaining.is_empty() {
        return fail("SCOPE_MISMATCH", considered);
    }

    if let Some(expected) = request
        .expected_service_identity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        remaining.retain(|candidate| candidate.expected_service_identity == expected);
        if remaining.is_empty() {
            return fail("SERVICE_IDENTITY_MISMATCH", considered);
        }
    } else {
        remaining.retain(|candidate| !candidate.expected_service_identity.trim().is_empty());
        if remaining.is_empty() {
            return fail("SERVICE_IDENTITY_MISMATCH", considered);
        }
    }

    let mut trusted = Vec::new();
    let mut saw_unknown = false;
    let mut saw_rejected = false;
    for candidate in remaining {
        match candidate.trust_state {
            CanonicalTrustState::Trusted => trusted.push(candidate),
            CanonicalTrustState::Unknown => saw_unknown = true,
            CanonicalTrustState::Untrusted => saw_rejected = true,
        }
    }
    if trusted.is_empty() {
        return fail(
            if saw_unknown && !saw_rejected {
                "TRUST_UNKNOWN"
            } else {
                "TRUST_REJECTED"
            },
            considered,
        );
    }
    let mut remaining = trusted;

    remaining.retain(|candidate| candidate.binding_epoch == bound.binding_epoch);
    if remaining.is_empty() {
        return fail("BINDING_EPOCH_MISMATCH", considered);
    }

    remaining.retain(|candidate| candidate.configuration_version == bound.policy_generation);
    if remaining.is_empty() {
        return fail("CONFIGURATION_STALE", considered);
    }

    let mut allowed = Vec::new();
    let mut saw_direct = false;
    let mut saw_relay = false;
    for candidate in remaining {
        match candidate.transport {
            CommonTransport::Relay => saw_relay = true,
            _ => saw_direct = true,
        }
        match policy_allows(request.route_policy, candidate.transport) {
            Ok(()) => allowed.push(candidate),
            Err(_) => {}
        }
    }
    if allowed.is_empty() {
        return fail(
            if matches!(request.route_policy, CommonRoutePolicy::RelayOnly) && !saw_relay {
                "RELAY_UNAVAILABLE"
            } else if !saw_direct {
                "DIRECT_UNAVAILABLE"
            } else {
                "POLICY_BLOCKED"
            },
            considered,
        );
    }

    allowed.retain(|candidate| candidate.readiness && route_health_ready(&candidate.health));
    if allowed.is_empty() {
        return fail("ROUTE_UNHEALTHY", considered);
    }

    allowed.sort_by(|left, right| {
        candidate_sort_key(request.route_policy, left).cmp(&candidate_sort_key(request.route_policy, right))
    });
    CommonConnectivityResolutionV1 {
        contract: COMMON_CONNECTIVITY_CLIENT_CONTRACT.to_string(),
        version: COMMON_CONNECTIVITY_CLIENT_VERSION.to_string(),
        selected: allowed.into_iter().next(),
        reason_code: None,
        candidates_considered: considered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_scope::CANONICAL_SCOPE_CONTRACT;

    fn bound() -> CanonicalConnectivityScopeV1 {
        CanonicalConnectivityScopeV1 {
            contract: CANONICAL_SCOPE_CONTRACT.into(),
            organization_id: "org-a".into(),
            client_id: Some("client-a".into()),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            binding_epoch: 7,
            policy_generation: 3,
        }
    }

    fn request(policy: CommonRoutePolicy) -> CommonConnectivityRequestV1 {
        CommonConnectivityRequestV1 {
            contract: COMMON_CONNECTIVITY_CLIENT_CONTRACT.into(),
            organization_id: "org-a".into(),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            product_id: "actium-product".into(),
            service_id: "site-gateway".into(),
            capability: "telemetry.gps.batch".into(),
            client_id: Some("client-a".into()),
            binding_epoch: Some(7),
            policy_generation: Some(3),
            route_policy: policy,
            expected_service_identity: Some("site-gateway-v1".into()),
        }
    }

    fn candidate(transport: CommonTransport, endpoint: &str) -> CommonConnectivityCandidateV1 {
        CommonConnectivityCandidateV1 {
            organization_id: Some("org-a".into()),
            client_id: Some("client-a".into()),
            site_id: Some("site-a".into()),
            host_id: Some("host-a".into()),
            product_id: Some("actium-product".into()),
            service_id: "site-gateway".into(),
            capability: "telemetry.gps.batch".into(),
            route_kind: match transport {
                CommonTransport::Local => CommonRouteKind::Local,
                CommonTransport::Private => CommonRouteKind::Private,
                _ => CommonRouteKind::Remote,
            },
            transport,
            endpoint: endpoint.into(),
            expected_service_identity: "site-gateway-v1".into(),
            authority_scope: "site:host:telemetry".into(),
            trust_state: CanonicalTrustState::Trusted,
            health: "HEALTHY".into(),
            readiness: true,
            priority: 10,
            binding_epoch: 7,
            configuration_version: 3,
            reason: None,
        }
    }

    #[test]
    fn auto_selects_local_then_private_then_direct_then_relay() {
        let resolution = resolve_common_connectivity(
            &bound(),
            &request(CommonRoutePolicy::Auto),
            &[
                candidate(CommonTransport::Relay, "https://relay.example"),
                candidate(CommonTransport::DirectWan, "https://wan.example"),
                candidate(CommonTransport::Private, "https://lan.example"),
                candidate(CommonTransport::Local, "https://127.0.0.1:9443"),
            ],
        );
        assert_eq!(resolution.selected.unwrap().endpoint, "https://127.0.0.1:9443");
    }

    #[test]
    fn auto_falls_back_to_relay_when_direct_unavailable() {
        let mut direct = candidate(CommonTransport::DirectWan, "https://wan.example");
        direct.readiness = false;
        let resolution = resolve_common_connectivity(
            &bound(),
            &request(CommonRoutePolicy::Auto),
            &[direct, candidate(CommonTransport::Relay, "https://relay.example")],
        );
        assert_eq!(resolution.selected.unwrap().transport, CommonTransport::Relay);
    }

    #[test]
    fn relay_only_ignores_direct() {
        let resolution = resolve_common_connectivity(
            &bound(),
            &request(CommonRoutePolicy::RelayOnly),
            &[
                candidate(CommonTransport::DirectWan, "https://wan.example"),
                candidate(CommonTransport::Relay, "https://relay.example"),
            ],
        );
        assert_eq!(resolution.selected.unwrap().endpoint, "https://relay.example");
    }

    #[test]
    fn disabled_and_isolation_and_gates_fail_closed() {
        assert_eq!(
            resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Disabled), &[candidate(CommonTransport::Local, "https://127.0.0.1")]).reason_code.as_deref(),
            Some("POLICY_BLOCKED")
        );
        let mut cross = request(CommonRoutePolicy::Auto);
        cross.organization_id = "org-b".into();
        assert_eq!(
            resolve_common_connectivity(&bound(), &cross, &[candidate(CommonTransport::Local, "https://127.0.0.1")]).reason_code.as_deref(),
            Some("SCOPE_MISMATCH")
        );
        let mut revoked = candidate(CommonTransport::Local, "https://127.0.0.1");
        revoked.trust_state = CanonicalTrustState::Untrusted;
        assert_eq!(
            resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Auto), &[revoked]).reason_code.as_deref(),
            Some("TRUST_REJECTED")
        );
        let mut unknown = candidate(CommonTransport::Local, "https://127.0.0.1");
        unknown.trust_state = CanonicalTrustState::Unknown;
        assert_eq!(
            resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Auto), &[unknown]).reason_code.as_deref(),
            Some("TRUST_UNKNOWN")
        );
        let mut epoch = candidate(CommonTransport::Local, "https://127.0.0.1");
        epoch.binding_epoch = 1;
        assert_eq!(
            resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Auto), &[epoch]).reason_code.as_deref(),
            Some("BINDING_EPOCH_MISMATCH")
        );
        let mut identity = candidate(CommonTransport::Local, "https://127.0.0.1");
        identity.expected_service_identity = "other".into();
        assert_eq!(
            resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Auto), &[identity]).reason_code.as_deref(),
            Some("SERVICE_IDENTITY_MISMATCH")
        );
        let mut other_client = candidate(CommonTransport::Local, "https://127.0.0.1");
        other_client.client_id = Some("client-b".into());
        assert_eq!(
            resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Auto), &[other_client]).reason_code.as_deref(),
            Some("SCOPE_MISMATCH")
        );
    }

    #[test]
    fn same_state_and_request_are_deterministic() {
        let candidates = vec![
            candidate(CommonTransport::Relay, "https://relay.example"),
            candidate(CommonTransport::DirectWan, "https://wan.example"),
        ];
        let first = resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Auto), &candidates);
        let second = resolve_common_connectivity(&bound(), &request(CommonRoutePolicy::Auto), &candidates);
        assert_eq!(first, second);
        assert_eq!(first.selected.unwrap().endpoint, "https://wan.example");
    }
}
