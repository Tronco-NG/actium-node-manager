//! Direct WAN Discovery & CGNAT Classification Engine V1
//!
//! Evaluates physical network interfaces, default routes, IPv4/IPv6 addresses,
//! and determines carrier-grade NAT (RFC 6598), private NAT (RFC 1918),
//! or public reachability.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WanTopology {
    PublicIpv4,
    PrivateNat,
    Cgnat,
    Ipv6Global,
    DualStack,
    NoWan,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NatManagementRequirement {
    NatNotRequired,
    NatManualRequired,
    NatUpnpAvailable,
    NatPcpAvailable,
    NatManagedGateway,
    NatUnsupported,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalRfc6598Observation { NotObserved, Observed }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpstreamCgnatStatus { Unknown, NotDetected, Detected, ConfirmedByRouter, ConfirmedByExternalEvidence }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IngressGatewayStatus { NotProvisioned, Provisioned }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PortForwardStatus { NotApplicable, RequiredAfterIngressProvisioning, Verified }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutsideInStatus { Unknown, Pass, Fail }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectWanStatus { NotReady, Ready }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalInterfaceInfo {
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub is_default_gateway: bool,
    pub metric: Option<u32>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WanDiscoveryReport {
    pub topology: WanTopology,
    pub nat_requirement: NatManagementRequirement,
    pub local_ipv4: Option<String>,
    pub local_ipv6: Option<String>,
    pub observed_public_ipv4: Option<String>,
    pub observed_public_ipv6: Option<String>,
    pub default_gateway: Option<String>,
    pub default_interface: Option<String>,
    pub is_cgnat: bool,
    pub is_rfc1918: bool,
    /// RFC 6598 observed on a local interface only.  This is not an upstream
    /// carrier classification.
    pub local_rfc6598_observed: LocalRfc6598Observation,
    pub upstream_cgnat_status: UpstreamCgnatStatus,
    pub has_global_ipv6: bool,
    pub manual_port_forward_required: bool,
    pub ingress_gateway: IngressGatewayStatus,
    pub planned_target: Option<String>,
    pub port_forward_status: PortForwardStatus,
    pub outside_in_status: OutsideInStatus,
    pub direct_wan_status: DirectWanStatus,
    #[serde(default)]
    pub required_port_forward: Option<String>,
    pub interfaces: Vec<PhysicalInterfaceInfo>,
}

/// Checks if an IPv4 address is in RFC 1918 private space:
/// - 10.0.0.0/8
/// - 172.16.0.0/12
/// - 192.168.0.0/16
pub fn is_rfc1918(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    match octets[0] {
        10 => true,
        172 if (16..=31).contains(&octets[1]) => true,
        192 if octets[1] == 168 => true,
        _ => false,
    }
}

/// Checks if an IPv4 address is in RFC 6598 Carrier-Grade NAT (CGNAT) space:
/// - 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
pub fn is_rfc6598(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// Checks if an IPv6 address is Global Unicast (2000::/3)
pub fn is_global_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    // 2000::/3 covers 0x2000 through 0x3fff
    (0x2000..=0x3fff).contains(&segments[0])
}

/// Classifies network topology given local and observed addresses
pub fn classify_topology(
    local_ipv4: Option<Ipv4Addr>,
    local_ipv6: Option<Ipv6Addr>,
    observed_ipv4: Option<Ipv4Addr>,
    observed_ipv6: Option<Ipv6Addr>,
) -> (WanTopology, NatManagementRequirement) {
    let has_global_v6 = local_ipv6.map_or(false, |ip| is_global_ipv6(&ip));
    let has_observed_v6 = observed_ipv6.is_some();
    let ipv6_ready = has_global_v6 && has_observed_v6;

    if local_ipv4.is_none() && !has_global_v6 {
        return (WanTopology::NoWan, NatManagementRequirement::NatUnsupported);
    }

    if let Some(v4) = local_ipv4 {
        if is_rfc6598(&v4) {
            let top = if ipv6_ready {
                WanTopology::DualStack
            } else {
                WanTopology::Cgnat
            };
            return (top, NatManagementRequirement::NatUnsupported);
        }

        if is_rfc1918(&v4) {
            let top = if ipv6_ready {
                WanTopology::DualStack
            } else {
                WanTopology::PrivateNat
            };
            return (top, NatManagementRequirement::NatManualRequired);
        }

        // Check if local IPv4 matches external observation
        if let Some(obs) = observed_ipv4 {
            if v4 == obs {
                let top = if ipv6_ready {
                    WanTopology::DualStack
                } else {
                    WanTopology::PublicIpv4
                };
                return (top, NatManagementRequirement::NatNotRequired);
            }
        }

        // A differing public observation does not identify the upstream
        // topology.  It may be a proxy, another egress, or carrier NAT; keep
        // the upstream classification unknown until external evidence exists.
        return (WanTopology::Unknown, NatManagementRequirement::NatUnsupported);
    }

    if ipv6_ready {
        (WanTopology::Ipv6Global, NatManagementRequirement::NatNotRequired)
    } else {
        (WanTopology::Unknown, NatManagementRequirement::NatUnsupported)
    }
}

/// Queries external probe to observe the Host's egress public IP
pub fn query_external_observed_ip(probe_url: Option<&str>) -> Option<String> {
    let configured_url = probe_url
        .map(String::from)
        .or_else(|| std::env::var("ACTIUM_CONNECTIVITY_PROBE_URL").ok())?;
    let url = configured_url.trim();
    if url.is_empty() || !(url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")) {
        return None;
    }
    let output = Command::new("curl")
        .args(["-sS", "--max-time", "5", url])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let val: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    val.get("observedIp").and_then(|v| v.as_str()).map(String::from)
}

/// Discovers the live physical network topology on the Host
#[allow(unused_mut)]
pub fn discover_wan_topology(observed_public_ip: Option<&str>) -> WanTopologyReport {
    let mut interfaces = Vec::new();
    let mut default_gw = None;
    let mut default_iface = None;
    let mut primary_v4 = None;
    let mut primary_v6 = None;

    #[cfg(target_os = "linux")]
    {
        // 1. Get default route from iproute2
        if let Ok(output) = Command::new("ip").args(["-j", "route", "show", "default"]).output() {
            if output.status.success() {
                if let Ok(routes) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) {
                    if let Some(first) = routes.first() {
                        default_gw = first.get("gateway").and_then(|v| v.as_str()).map(String::from);
                        default_iface = first.get("dev").and_then(|v| v.as_str()).map(String::from);
                    }
                }
            }
        }

        // 2. Query interfaces
        if let Ok(output) = Command::new("ip").args(["-j", "addr", "show"]).output() {
            if output.status.success() {
                if let Ok(links) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) {
                    for link in links {
                        let name = link.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        if name.is_empty() || name == "lo" || name.starts_with("docker") || name.starts_with("br-") {
                            continue;
                        }
                        let state = link.get("operstate").and_then(|v| v.as_str()).unwrap_or("UNKNOWN").to_string();
                        let mac = link.get("address").and_then(|v| v.as_str()).map(String::from);
                        let is_def = default_iface.as_deref() == Some(&name);

                        let mut iface_v4 = None;
                        let mut iface_v6 = None;

                        if let Some(addr_info) = link.get("addr_info").and_then(|v| v.as_array()) {
                            for addr in addr_info {
                                let family = addr.get("family").and_then(|v| v.as_str()).unwrap_or("");
                                let local = addr.get("local").and_then(|v| v.as_str()).unwrap_or("");
                                let scope = addr.get("scope").and_then(|v| v.as_str()).unwrap_or("");

                                if family == "inet" && !local.is_empty() && iface_v4.is_none() {
                                    iface_v4 = Some(local.to_string());
                                    if is_def && primary_v4.is_none() {
                                        primary_v4 = local.parse::<Ipv4Addr>().ok();
                                    }
                                } else if family == "inet6" && scope == "global" && iface_v6.is_none() {
                                    iface_v6 = Some(local.to_string());
                                    if is_def && primary_v6.is_none() {
                                        primary_v6 = local.parse::<Ipv6Addr>().ok();
                                    }
                                }
                            }
                        }

                        interfaces.push(PhysicalInterfaceInfo {
                            name,
                            mac,
                            ipv4: iface_v4,
                            ipv6: iface_v6,
                            is_default_gateway: is_def,
                            metric: None,
                            state,
                        });
                    }
                }
            }
        }
    }

    // Query external observed IP if not supplied
    let resolved_obs = observed_public_ip
        .map(String::from)
        .or_else(|| query_external_observed_ip(None));

    // Parse observed IP
    let obs_v4 = resolved_obs.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok());
    let obs_v6 = resolved_obs.as_deref().and_then(|s| s.parse::<Ipv6Addr>().ok());

    let (topology, nat_req) = classify_topology(primary_v4, primary_v6, obs_v4, obs_v6);

    let local_rfc6598 = primary_v4.map_or(false, |ip| is_rfc6598(&ip));
    let is_cgnat_flag = local_rfc6598;
    let is_rfc1918_flag = primary_v4.map_or(false, |ip| is_rfc1918(&ip));
    let has_global_v6 = primary_v6.map_or(false, |ip| is_global_ipv6(&ip));

    let manual_forward = nat_req == NatManagementRequirement::NatManualRequired;
    let planned_target = primary_v4.map(|ip| format!("{}:443", ip));

    WanTopologyReport {
        topology,
        nat_requirement: nat_req,
        local_ipv4: primary_v4.map(|ip| ip.to_string()),
        local_ipv6: primary_v6.map(|ip| ip.to_string()),
        observed_public_ipv4: obs_v4.map(|ip| ip.to_string()),
        observed_public_ipv6: obs_v6.map(|ip| ip.to_string()),
        default_gateway: default_gw,
        default_interface: default_iface,
        is_cgnat: is_cgnat_flag,
        is_rfc1918: is_rfc1918_flag,
        local_rfc6598_observed: if local_rfc6598 { LocalRfc6598Observation::Observed } else { LocalRfc6598Observation::NotObserved },
        upstream_cgnat_status: if local_rfc6598 { UpstreamCgnatStatus::Detected } else { UpstreamCgnatStatus::Unknown },
        has_global_ipv6: has_global_v6,
        manual_port_forward_required: manual_forward,
        ingress_gateway: IngressGatewayStatus::NotProvisioned,
        planned_target,
        port_forward_status: if manual_forward { PortForwardStatus::RequiredAfterIngressProvisioning } else { PortForwardStatus::NotApplicable },
        outside_in_status: OutsideInStatus::Unknown,
        direct_wan_status: DirectWanStatus::NotReady,
        required_port_forward: None,
        interfaces,
    }
}

pub fn apply_direct_wan_attestation(
    mut report: WanDiscoveryReport,
    evidence: crate::direct_wan::DirectWanEvidenceV1,
) -> WanDiscoveryReport {
    let decision = crate::direct_wan::evaluate_direct_wan(evidence);
    report.outside_in_status = match decision.evidence.outside_in_status {
        crate::direct_wan::EvidenceStatus::Pass => OutsideInStatus::Pass,
        crate::direct_wan::EvidenceStatus::Fail => OutsideInStatus::Fail,
        _ => OutsideInStatus::Unknown,
    };
    report.direct_wan_status = match decision.ready {
        crate::direct_wan::DirectWanReadiness::Ready => DirectWanStatus::Ready,
        crate::direct_wan::DirectWanReadiness::NotReady => DirectWanStatus::NotReady,
    };
    if decision.ready == crate::direct_wan::DirectWanReadiness::Ready {
        report.ingress_gateway = IngressGatewayStatus::Provisioned;
        report.port_forward_status = PortForwardStatus::Verified;
    }
    report
}

pub type WanTopologyReport = WanDiscoveryReport;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc1918_detection() {
        assert!(is_rfc1918(&"10.77.10.226".parse().unwrap()));
        assert!(is_rfc1918(&"172.16.0.1".parse().unwrap()));
        assert!(is_rfc1918(&"172.31.255.254".parse().unwrap()));
        assert!(is_rfc1918(&"192.168.1.50".parse().unwrap()));

        assert!(!is_rfc1918(&"172.32.0.1".parse().unwrap()));
        assert!(!is_rfc1918(&"8.8.8.8".parse().unwrap()));
        assert!(!is_rfc1918(&"100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn test_rfc6598_cgnat_detection() {
        assert!(is_rfc6598(&"100.64.0.1".parse().unwrap()));
        assert!(is_rfc6598(&"100.127.255.254".parse().unwrap()));

        assert!(!is_rfc6598(&"100.63.255.255".parse().unwrap()));
        assert!(!is_rfc6598(&"100.128.0.0".parse().unwrap()));
        assert!(!is_rfc6598(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_classification() {
        // 1. Private NAT (RFC 1918)
        let (top, nat) = classify_topology(
            Some("10.77.10.226".parse().unwrap()),
            None,
            Some("153.67.181.226".parse().unwrap()),
            None,
        );
        assert_eq!(top, WanTopology::PrivateNat);
        assert_eq!(nat, NatManagementRequirement::NatManualRequired);

        // 2. CGNAT (RFC 6598)
        let (top, nat) = classify_topology(
            Some("100.64.5.10".parse().unwrap()),
            None,
            Some("153.67.181.226".parse().unwrap()),
            None,
        );
        assert_eq!(top, WanTopology::Cgnat);
        assert_eq!(nat, NatManagementRequirement::NatUnsupported);

        // 3. Public IPv4
        let (top, nat) = classify_topology(
            Some("153.67.181.226".parse().unwrap()),
            None,
            Some("153.67.181.226".parse().unwrap()),
            None,
        );
        assert_eq!(top, WanTopology::PublicIpv4);
        assert_eq!(nat, NatManagementRequirement::NatNotRequired);
    }

    #[test]
    fn private_lan_does_not_prove_upstream_cgnat_or_direct_wan() {
        let report = discover_from_addresses(
            Some("10.77.10.226".parse().unwrap()),
            None,
            Some("153.67.181.226".parse().unwrap()),
            None,
        );
        assert_eq!(report.topology, WanTopology::PrivateNat);
        assert_eq!(report.local_rfc6598_observed, LocalRfc6598Observation::NotObserved);
        assert_eq!(report.upstream_cgnat_status, UpstreamCgnatStatus::Unknown);
        assert_eq!(report.direct_wan_status, DirectWanStatus::NotReady);
        assert_eq!(report.ingress_gateway, IngressGatewayStatus::NotProvisioned);
        assert_eq!(report.port_forward_status, PortForwardStatus::RequiredAfterIngressProvisioning);

        let ready = apply_direct_wan_attestation(
            report,
            crate::direct_wan::DirectWanEvidenceV1 {
                dns_status: crate::direct_wan::EvidenceStatus::Pass,
                resolved_addresses: vec!["203.0.113.10".into()],
                tcp443_status: crate::direct_wan::EvidenceStatus::Pass,
                tls_status: crate::direct_wan::EvidenceStatus::Pass,
                certificate_identity: Some("site.example".into()),
                certificate_fingerprint: Some("sha256:x".into()),
                site_identity_status: crate::direct_wan::EvidenceStatus::Pass,
                outside_in_status: crate::direct_wan::EvidenceStatus::Pass,
                latency_ms: Some(12),
                checked_at: "1".into(),
                expires_at: "2".into(),
                probe_caller_ip: Some("198.51.100.9".into()),
                site_public_ingress_ip: Some("203.0.113.10".into()),
            },
        );
        assert_eq!(ready.direct_wan_status, DirectWanStatus::Ready);
        assert_eq!(ready.outside_in_status, OutsideInStatus::Pass);
    }

    fn discover_from_addresses(
        local_ipv4: Option<Ipv4Addr>,
        local_ipv6: Option<Ipv6Addr>,
        observed_ipv4: Option<Ipv4Addr>,
        observed_ipv6: Option<Ipv6Addr>,
    ) -> WanDiscoveryReport {
        let (topology, nat_requirement) = classify_topology(local_ipv4, local_ipv6, observed_ipv4, observed_ipv6);
        let local_rfc6598 = local_ipv4.is_some_and(|ip| is_rfc6598(&ip));
        WanDiscoveryReport {
            topology,
            nat_requirement,
            local_ipv4: local_ipv4.map(|ip| ip.to_string()),
            local_ipv6: local_ipv6.map(|ip| ip.to_string()),
            observed_public_ipv4: observed_ipv4.map(|ip| ip.to_string()),
            observed_public_ipv6: observed_ipv6.map(|ip| ip.to_string()),
            default_gateway: None,
            default_interface: None,
            is_cgnat: local_rfc6598,
            is_rfc1918: local_ipv4.is_some_and(|ip| is_rfc1918(&ip)),
            local_rfc6598_observed: if local_rfc6598 { LocalRfc6598Observation::Observed } else { LocalRfc6598Observation::NotObserved },
            upstream_cgnat_status: if local_rfc6598 { UpstreamCgnatStatus::Detected } else { UpstreamCgnatStatus::Unknown },
            has_global_ipv6: local_ipv6.is_some_and(|ip| is_global_ipv6(&ip)),
            manual_port_forward_required: nat_requirement == NatManagementRequirement::NatManualRequired,
            ingress_gateway: IngressGatewayStatus::NotProvisioned,
            planned_target: local_ipv4.map(|ip| format!("{ip}:443")),
            port_forward_status: if nat_requirement == NatManagementRequirement::NatManualRequired { PortForwardStatus::RequiredAfterIngressProvisioning } else { PortForwardStatus::NotApplicable },
            outside_in_status: OutsideInStatus::Unknown,
            direct_wan_status: DirectWanStatus::NotReady,
            required_port_forward: None,
            interfaces: Vec::new(),
        }
    }
}
