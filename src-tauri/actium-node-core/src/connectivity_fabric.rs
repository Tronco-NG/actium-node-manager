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

pub fn control_plane_route(endpoint: &str, now: u64) -> Result<ServiceRoute, String> {
    let endpoint = endpoint.trim().trim_end_matches('/');
    let authority = endpoint
        .strip_prefix("https://")
        .and_then(|value| value.split('/').next())
        .unwrap_or("");
    if endpoint.is_empty()
        || authority.is_empty()
        || authority.contains('@')
        || !endpoint.starts_with("https://")
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
        transport: "https_bootstrap".to_string(),
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
        match route.state { ConnectivityRouteState::Reachable => 0, ConnectivityRouteState::Configured => 1, ConnectivityRouteState::Unreachable => 2, ConnectivityRouteState::Unauthorized => 3, ConnectivityRouteState::Unconfigured => 4 },
        match route.route_kind { ConnectivityRouteKind::Local => 0, ConnectivityRouteKind::Private => 1, ConnectivityRouteKind::Remote => 2 },
        route.priority,
    ));
    let preferred_route = candidates.first().cloned();
    ConnectivityResolution { contract: CONNECTIVITY_RESOLUTION_CONTRACT.to_string(), environment: None, preferred_route, candidates, resolved_at_unix_seconds: 0 }
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
        let local = ServiceRoute { endpoint: "https://localhost:9443".into(), route_kind: ConnectivityRouteKind::Local, priority: 100, ..control_plane_route("https://remote.example", 1).unwrap() };
        let remote = ServiceRoute { endpoint: "https://remote.example".into(), route_kind: ConnectivityRouteKind::Remote, priority: 1, ..control_plane_route("https://remote.example", 1).unwrap() };
        let resolution = resolve_service(&[remote, local], "actium-center", "host_enrollment");
        assert_eq!(resolution.preferred_route.unwrap().endpoint, "https://localhost:9443");
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
}
