//! Authenticated Connectivity Fabric session contract.
//!
//! Route metadata is public discovery data. This contract is the boundary
//! used by a transport adapter after TLS/mTLS, signed bootstrap, or the
//! existing Host Enrollment proof has authenticated the peer. Supervisor
//! liveness alone is never accepted as a session.

use crate::connectivity_fabric::ServiceRoute;
use serde::{Deserialize, Serialize};

pub const CONNECTIVITY_SESSION_CONTRACT: &str =
    "actium-connectivity-authenticated-session@1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityAuthenticationMethod {
    TlsPeerIdentity,
    SignedBootstrap,
    SupervisorProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedServiceSession {
    pub contract: String,
    pub service_id: String,
    pub capability: String,
    pub service_identity: String,
    pub authority_scope: String,
    pub binding_epoch: u64,
    pub transport: String,
    pub request_id: String,
    pub authenticated: bool,
    pub authentication_method: ConnectivityAuthenticationMethod,
    pub established_at_unix_seconds: u64,
}

pub fn verify_authenticated_session(
    route: &ServiceRoute,
    session: &AuthenticatedServiceSession,
) -> Result<(), String> {
    if session.contract != CONNECTIVITY_SESSION_CONTRACT || !session.authenticated {
        return Err("CONNECTIVITY_SESSION_NOT_AUTHENTICATED".to_string());
    }
    if session.request_id.trim().is_empty()
        || session.service_id != route.service_id
        || session.capability != route.capability
        || session.service_identity != route.expected_service_identity
        || session.authority_scope != route.authority_scope
        || session.transport != route.transport
        || session.binding_epoch < route.binding_epoch
    {
        return Err("CONNECTIVITY_SESSION_BINDING_INVALID".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectivity_fabric::{control_plane_route, ConnectivityRouteState};

    fn session(route: &ServiceRoute) -> AuthenticatedServiceSession {
        AuthenticatedServiceSession {
            contract: CONNECTIVITY_SESSION_CONTRACT.to_string(),
            service_id: route.service_id.clone(),
            capability: route.capability.clone(),
            service_identity: route.expected_service_identity.clone(),
            authority_scope: route.authority_scope.clone(),
            binding_epoch: route.binding_epoch,
            transport: route.transport.clone(),
            request_id: "request-1".to_string(),
            authenticated: true,
            authentication_method: ConnectivityAuthenticationMethod::SignedBootstrap,
            established_at_unix_seconds: 1,
        }
    }

    #[test]
    fn exact_identity_scope_and_epoch_are_required() {
        let route = ServiceRoute { state: ConnectivityRouteState::Reachable, binding_epoch: 4, ..control_plane_route("https://center.example", 1).unwrap() };
        assert!(verify_authenticated_session(&route, &session(&route)).is_ok());
        let mut wrong = session(&route);
        wrong.service_identity = "spoofed-center".to_string();
        assert_eq!(verify_authenticated_session(&route, &wrong).unwrap_err(), "CONNECTIVITY_SESSION_BINDING_INVALID");
        let mut lower = session(&route);
        lower.binding_epoch = 3;
        assert_eq!(verify_authenticated_session(&route, &lower).unwrap_err(), "CONNECTIVITY_SESSION_BINDING_INVALID");
    }

    #[test]
    fn supervisor_liveness_without_authentication_is_rejected() {
        let route = control_plane_route("https://center.example", 1).unwrap();
        let mut value = session(&route);
        value.authenticated = false;
        assert_eq!(verify_authenticated_session(&route, &value).unwrap_err(), "CONNECTIVITY_SESSION_NOT_AUTHENTICATED");
    }
}
