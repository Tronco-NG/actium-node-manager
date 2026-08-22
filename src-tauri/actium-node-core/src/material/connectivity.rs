//! Access / Runtime / Connectivity material plane.
//!
//! Secrets belong in Supervisor material (`state/supervisor/material/connectivity`).
//! `state/agent` is never authority. WireGuard is a TransportProvider, not the domain.

use super::types::{MaterialContract, ACTIVATION_VERIFY_ONLY};

pub const CONNECTIVITY_MATERIAL_CAPABILITY: &str = "connectivity";
pub const CONNECTIVITY_MATERIAL_RELATIVE: &str = "state/supervisor/material/connectivity";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Direct,
    Overlay,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectivityStatus {
    Disconnected,
    Provisioning,
    Connecting,
    Connected,
    Degraded,
    Reconnecting,
    Failed,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessConnectivityPolicy {
    pub preferred: TransportKind,
    pub allowed: Vec<TransportKind>,
    pub gateway_strategy: &'static str,
    pub roaming_allowed: bool,
}

pub fn connectivity_material_contract() -> MaterialContract {
    MaterialContract {
        capability: CONNECTIVITY_MATERIAL_CAPABILITY.to_string(),
        allowed_path_prefixes: vec!["provider/".to_string(), "policy/".to_string()],
        max_total_bytes: 256 * 1024,
        max_file_bytes: 64 * 1024,
        max_file_count: 16,
        activation_policy: ACTIVATION_VERIFY_ONLY.to_string(),
        allowed_extensions: vec!["json".to_string()],
    }
}

pub fn reject_agent_material_path(path: &str) -> Result<(), String> {
    let normalized = path.replace('\\', "/");
    if normalized.contains("/state/agent/") || normalized.ends_with("/state/agent") {
        return Err("CONNECTIVITY_AGENT_NOT_AUTHORITY".into());
    }
    Ok(())
}

pub fn parse_transport_kind(value: &str) -> Result<TransportKind, String> {
    match value.trim() {
        "" | "direct" => Ok(TransportKind::Direct),
        "overlay" => Ok(TransportKind::Overlay),
        "relay" => Ok(TransportKind::Relay),
        "wireguard" | "tailscale" | "vpn" => {
            Err("CONNECTIVITY_TRANSPORT_MUST_BE_ABSTRACT".into())
        }
        other => Err(format!("CONNECTIVITY_TRANSPORT_UNKNOWN:{other}")),
    }
}

pub fn parse_gateway_strategy(value: &str) -> Result<&'static str, String> {
    match value.trim() {
        "" | "node_direct" => Ok("node_direct"),
        "site_gateway" => Ok("site_gateway"),
        "cloud_runtime" => Ok("cloud_runtime"),
        other => Err(format!("CONNECTIVITY_GATEWAY_STRATEGY_UNKNOWN:{other}")),
    }
}

pub fn validate_access_transport_policy(
    preferred: &str,
    allowed: &[String],
    gateway_strategy: &str,
) -> Result<AccessConnectivityPolicy, String> {
    let preferred_kind = parse_transport_kind(preferred)?;
    let mut allowed_kinds = Vec::new();
    if allowed.is_empty() {
        allowed_kinds.push(preferred_kind);
    } else {
        for item in allowed {
            allowed_kinds.push(parse_transport_kind(item)?);
        }
    }
    if !allowed_kinds.contains(&preferred_kind) {
        return Err("CONNECTIVITY_PREFERRED_TRANSPORT_NOT_ALLOWED".into());
    }
    Ok(AccessConnectivityPolicy {
        preferred: preferred_kind,
        allowed: allowed_kinds,
        gateway_strategy: parse_gateway_strategy(gateway_strategy)?,
        roaming_allowed: true,
    })
}

pub fn materialize_provider(
    policy: &AccessConnectivityPolicy,
    requested: TransportKind,
    unsigned: bool,
) -> Result<&'static str, String> {
    if unsigned {
        return Err("CONNECTIVITY_MATERIAL_UNSIGNED".into());
    }
    if !policy.allowed.contains(&requested) {
        return Err("TRANSPORT_PROVIDER_OUTSIDE_POLICY".into());
    }
    match requested {
        TransportKind::Direct => Ok("direct"),
        TransportKind::Overlay => Ok("overlay"),
        TransportKind::Relay => Ok("relay"),
    }
}

pub fn apply_network_transition(
    status: ConnectivityStatus,
    event: &str,
) -> ConnectivityStatus {
    match event {
        "airplane" => ConnectivityStatus::Disconnected,
        "wifi_lost" | "wifi_to_cellular" | "cellular_to_5g" => {
            if matches!(
                status,
                ConnectivityStatus::Connected | ConnectivityStatus::Degraded
            ) {
                ConnectivityStatus::Reconnecting
            } else {
                ConnectivityStatus::Connecting
            }
        }
        "restored" => ConnectivityStatus::Connected,
        _ => status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_vendor_transport_as_domain() {
        assert_eq!(
            parse_transport_kind("wireguard").unwrap_err(),
            "CONNECTIVITY_TRANSPORT_MUST_BE_ABSTRACT"
        );
        assert_eq!(
            parse_transport_kind("tailscale").unwrap_err(),
            "CONNECTIVITY_TRANSPORT_MUST_BE_ABSTRACT"
        );
    }

    #[test]
    fn agent_path_is_never_authority() {
        assert_eq!(
            reject_agent_material_path("C:/nodes/n1/state/agent/connectivity.json").unwrap_err(),
            "CONNECTIVITY_AGENT_NOT_AUTHORITY"
        );
        assert!(reject_agent_material_path(CONNECTIVITY_MATERIAL_RELATIVE).is_ok());
    }

    #[test]
    fn unsigned_or_out_of_policy_provider_is_rejected() {
        let policy = validate_access_transport_policy("direct", &["direct".into()], "node_direct")
            .expect("policy");
        assert_eq!(
            materialize_provider(&policy, TransportKind::Overlay, false).unwrap_err(),
            "TRANSPORT_PROVIDER_OUTSIDE_POLICY"
        );
        assert_eq!(
            materialize_provider(&policy, TransportKind::Direct, true).unwrap_err(),
            "CONNECTIVITY_MATERIAL_UNSIGNED"
        );
    }

    #[test]
    fn roaming_preserves_reconnect_without_revoke() {
        assert_eq!(
            apply_network_transition(ConnectivityStatus::Connected, "wifi_to_cellular"),
            ConnectivityStatus::Reconnecting
        );
    }
}
