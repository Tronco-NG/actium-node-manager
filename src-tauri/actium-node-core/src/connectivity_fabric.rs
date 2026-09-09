//! Versioned, provider-neutral Connectivity Fabric contract.
//!
//! The Fabric resolves an already-authorized route. It never grants scope,
//! signs authority, or treats reachability as capability readiness.

use serde::{Deserialize, Serialize};

pub const CONNECTIVITY_RESOLUTION_CONTRACT: &str = "actium-connectivity-service-resolution@1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityRouteKind { Local, Private, Remote }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityRouteState { Configured, Reachable, Unreachable, Unauthorized, Unconfigured }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRoute {
    pub organization_id: Option<String>,
    pub site_id: Option<String>,
    pub host_id: Option<String>,
    pub service_id: String,
    pub capability: String,
    pub route_kind: ConnectivityRouteKind,
    pub endpoint: String,
    pub expected_service_identity: String,
    pub transport: String,
    pub authority_scope: String,
    pub state: ConnectivityRouteState,
    pub health: String,
    pub priority: u16,
    pub binding_epoch: u64,
    pub configuration_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectivityResolution {
    pub contract: String,
    pub environment: Option<String>,
    pub preferred_route: Option<ServiceRoute>,
    pub candidates: Vec<ServiceRoute>,
    pub resolved_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectivityAgentStatus {
    pub state: String,
    pub owner: String,
    pub transport: String,
    pub authenticated: bool,
    pub session_state: String,
    pub authenticated_service_identity: Option<String>,
    pub authenticated_scope: Option<String>,
    pub authenticated_binding_epoch: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectivityFabricStatus {
    pub contract: String,
    pub agent: ConnectivityAgentStatus,
    pub control_plane_url: Option<String>,
    pub environment: Option<String>,
    pub routes: Vec<ServiceRoute>,
    pub selected_routes: Vec<ConnectivityResolution>,
    pub observed_at_unix_seconds: u64,
}

fn loopback_http_endpoint(endpoint: &str) -> bool {
    let authority = endpoint
        .strip_prefix("http://")
        .and_then(|value| value.split('/').next())
        .unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = if authority.starts_with('[') {
        let Some(close) = authority.find(']') else { return false; };
        let remainder = &authority[close + 1..];
        if !remainder.is_empty() {
            let Some(port) = remainder.strip_prefix(':') else { return false; };
            if port.is_empty() || port.parse::<u16>().is_err() { return false; }
        }
        &authority[1..close]
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') || port.is_empty() || port.parse::<u16>().is_err() { return false; }
        host
    } else {
        authority
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub fn control_plane_route(endpoint: &str, now: u64) -> Result<ServiceRoute, String> {
    let endpoint = endpoint.trim().trim_end_matches('/');
    let is_https = endpoint.starts_with("https://");
    let is_local_http = endpoint.starts_with("http://") && loopback_http_endpoint(endpoint);
    let authority = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .and_then(|value| value.split('/').next())
        .unwrap_or("");
    if endpoint.is_empty()
        || authority.is_empty()
        || authority.contains('@')
        || (!is_https && !is_local_http)
        || endpoint.chars().any(char::is_whitespace)
        || endpoint.contains('?')
        || endpoint.contains('#') {
        return Err("CONNECTIVITY_CONTROL_PLANE_ENDPOINT_INVALID".to_string());
    }
    let host = if authority.starts_with('[') {
        authority.split(']').next().unwrap_or("").trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err("CONNECTIVITY_CONTROL_PLANE_ENDPOINT_INVALID".to_string());
    }
    let route_kind = if matches!(host, "localhost" | "127.0.0.1" | "::1") { ConnectivityRouteKind::Local } else { ConnectivityRouteKind::Remote };
    Ok(ServiceRoute {
        organization_id: None,
        site_id: None,
        host_id: None,
        service_id: "actium-center".to_string(),
        capability: "host_enrollment".to_string(),
        route_kind,
        endpoint: endpoint.to_string(),
        expected_service_identity: "actium-center-control-plane".to_string(),
        transport: if is_local_http { "local_http_bootstrap" } else { "https_bootstrap" }.to_string(),
        authority_scope: "host_enrollment:bootstrap".to_string(),
        state: ConnectivityRouteState::Configured,
        health: "not_probed".to_string(),
        priority: 0,
        binding_epoch: 0,
        configuration_version: now,
    })
}

pub fn resolve_service(routes: &[ServiceRoute], service_id: &str, capability: &str) -> ConnectivityResolution {
    let mut candidates: Vec<ServiceRoute> = routes.iter().filter(|route| route.service_id == service_id && route.capability == capability).cloned().collect();
    candidates.sort_by_key(|route| (
        if route_is_eligible(route) { 0 } else { 1 },
        match route.route_kind { ConnectivityRouteKind::Local => 0, ConnectivityRouteKind::Private => 1, ConnectivityRouteKind::Remote => 2 },
        match route.state { ConnectivityRouteState::Reachable => 0, ConnectivityRouteState::Configured => 1, ConnectivityRouteState::Unreachable => 2, ConnectivityRouteState::Unauthorized => 3, ConnectivityRouteState::Unconfigured => 4 },
        route.priority,
    ));
    let preferred_route = candidates.iter().find(|route| route_is_eligible(route)).cloned();
    ConnectivityResolution { contract: CONNECTIVITY_RESOLUTION_CONTRACT.to_string(), environment: None, preferred_route, candidates, resolved_at_unix_seconds: 0 }
}

/// A route is executable only after the transport adapter reports it as
/// reachable and the public identity/scope binding is present. Supervisor
/// liveness by itself does not satisfy this predicate.
pub fn route_is_eligible(route: &ServiceRoute) -> bool {
    matches!(route.state, ConnectivityRouteState::Reachable)
        && !route.endpoint.trim().is_empty()
        && !route.expected_service_identity.trim().is_empty()
        && !route.authority_scope.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_route_is_canonical_and_non_authoritative() {
        let route = control_plane_route("https://center.example/gateway/", 7).unwrap();
        assert_eq!(route.endpoint, "https://center.example/gateway");
        assert_eq!(route.authority_scope, "host_enrollment:bootstrap");
        assert_eq!(route.route_kind, ConnectivityRouteKind::Remote);
    }

    #[test]
    fn local_route_precedes_remote_without_changing_authority() {
        let local = ServiceRoute { endpoint: "https://localhost:9443".into(), route_kind: ConnectivityRouteKind::Local, priority: 100, state: ConnectivityRouteState::Reachable, ..control_plane_route("https://remote.example", 1).unwrap() };
        let remote = ServiceRoute { endpoint: "https://remote.example".into(), route_kind: ConnectivityRouteKind::Remote, priority: 1, state: ConnectivityRouteState::Reachable, ..control_plane_route("https://remote.example", 1).unwrap() };
        let resolution = resolve_service(&[remote, local], "actium-center", "host_enrollment");
        assert_eq!(resolution.preferred_route.unwrap().endpoint, "https://localhost:9443");
    }

    #[test]
    fn configured_and_unauthorized_routes_are_never_preferred() {
        let configured = control_plane_route("https://center.example", 1).unwrap();
        let unauthorized = ServiceRoute { state: ConnectivityRouteState::Unauthorized, ..configured.clone() };
        let resolution = resolve_service(&[unauthorized, configured], "actium-center", "host_enrollment");
        assert!(resolution.preferred_route.is_none());
    }

    #[test]
    fn a_reachable_remote_can_be_selected_when_local_is_unreachable() {
        let local = ServiceRoute { endpoint: "https://localhost:9443".into(), route_kind: ConnectivityRouteKind::Local, state: ConnectivityRouteState::Unreachable, ..control_plane_route("https://remote.example", 1).unwrap() };
        let remote = ServiceRoute { endpoint: "https://remote.example".into(), route_kind: ConnectivityRouteKind::Remote, state: ConnectivityRouteState::Reachable, ..control_plane_route("https://remote.example", 1).unwrap() };
        let resolution = resolve_service(&[remote, local], "actium-center", "host_enrollment");
        assert_eq!(resolution.preferred_route.unwrap().endpoint, "https://remote.example");
    }

    #[test]
    fn endpoint_never_accepts_query_fragment_or_http() {
        for endpoint in ["http://center.example", "https://center.example?x=1", "https://center.example#x", "https://user:secret@center.example", "https://"] {
            assert_eq!(control_plane_route(endpoint, 1).unwrap_err(), "CONNECTIVITY_CONTROL_PLANE_ENDPOINT_INVALID");
        }
    }

    #[test]
    fn local_classification_requires_exact_hostname() {
        assert_eq!(control_plane_route("https://localhost.evil.example", 1).unwrap().route_kind, ConnectivityRouteKind::Remote);
        assert_eq!(control_plane_route("https://127.0.0.1:9443", 1).unwrap().route_kind, ConnectivityRouteKind::Local);
        assert_eq!(control_plane_route("https://[::1]:9443", 1).unwrap().route_kind, ConnectivityRouteKind::Local);
    }

    #[test]
    fn local_http_route_is_loopback_only_and_explicitly_classified() {
        let route = control_plane_route("http://127.0.0.1:18083/", 1).unwrap();
        assert_eq!(route.endpoint, "http://127.0.0.1:18083");
        assert_eq!(route.route_kind, ConnectivityRouteKind::Local);
        assert_eq!(route.transport, "local_http_bootstrap");
        assert!(control_plane_route("http://10.77.10.226:18083", 1).is_err());
    }
}
