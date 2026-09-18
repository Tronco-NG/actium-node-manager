//! Hybrid Connectivity Fabric path resolver (R5).
//!
//! One product-neutral engine for SITE_DIRECT_LAN / WAN IPv4 / WAN IPv6 /
//! ACTIUM_RELAY.  Future path types may be represented but are not active.
//! Aegis, AirShield and ACF consume this engine through adapters; they must
//! not fork a second resolver.

use crate::remote_ops::{RouteCandidate, RouteDecisionReceipt, RouteType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PATH_RESOLVER_CONTRACT: &str = "actium.connectivity.path-resolver.v1";
pub const TEST_PRODUCT_CAPABILITY: &str = "test-product-capability";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RoutePolicy {
    Auto,
    DirectOnly,
    RelayOnly,
    HighAvailability,
    CostOptimized,
    LowLatency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathResolverConfig {
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub minimum_hold_ms: u64,
    pub latency_hysteresis_ms: u64,
    pub probe_backoff_ms: u64,
    pub stickiness: bool,
}

impl Default for PathResolverConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            recovery_threshold: 2,
            minimum_hold_ms: 15_000,
            latency_hysteresis_ms: 40,
            probe_backoff_ms: 2_000,
            stickiness: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PathResolverState {
    pub selected_route_id: Option<String>,
    pub selected_at_ms: u64,
    pub last_probe_at_ms: u64,
}

impl Default for PathResolverState {
    fn default() -> Self {
        Self {
            selected_route_id: None,
            selected_at_ms: 0,
            last_probe_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PathResolveRequest<'a> {
    pub policy: RoutePolicy,
    pub capability: &'a str,
    pub site_id: &'a str,
    pub policy_generation: u64,
    pub now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Eligibility {
    Eligible,
    Recovering,
    Expired,
    Unhealthy,
    PolicyDenied,
    FutureInactive,
}

pub fn is_active_route_type(route_type: &RouteType) -> bool {
    matches!(
        route_type,
        RouteType::SiteDirectLan
            | RouteType::SiteDirectWanIpv4
            | RouteType::SiteDirectWanIpv6
            | RouteType::ActiumRelay
    )
}

pub fn policy_allows(policy: RoutePolicy, route_type: &RouteType) -> bool {
    if !is_active_route_type(route_type) {
        return false;
    }
    match policy {
        RoutePolicy::Auto | RoutePolicy::HighAvailability | RoutePolicy::CostOptimized | RoutePolicy::LowLatency => {
            true
        }
        RoutePolicy::DirectOnly => !matches!(route_type, RouteType::ActiumRelay),
        RoutePolicy::RelayOnly => matches!(route_type, RouteType::ActiumRelay),
    }
}

fn health_rank(health: &str) -> u8 {
    match health {
        "HEALTHY" => 0,
        "DEGRADED" => 1,
        _ => 2,
    }
}

fn type_rank(route_type: &RouteType) -> u8 {
    match route_type {
        RouteType::SiteDirectLan => 0,
        RouteType::SiteDirectWanIpv6 => 1,
        RouteType::SiteDirectWanIpv4 => 2,
        RouteType::ActiumRelay => 3,
        RouteType::FederatedActiumNode => 9,
    }
}

fn parse_expiry_ms(expires_at: &str) -> Option<u64> {
    if let Ok(ms) = expires_at.parse::<u64>() {
        return Some(ms);
    }
    None
}

fn eligibility(candidate: &RouteCandidate, policy: RoutePolicy, now_ms: u64) -> Eligibility {
    if !is_active_route_type(&candidate.route_type) {
        return Eligibility::FutureInactive;
    }
    if !policy_allows(policy, &candidate.route_type) {
        return Eligibility::PolicyDenied;
    }
    if let Some(expires) = parse_expiry_ms(&candidate.expires_at) {
        if expires <= now_ms {
            return Eligibility::Expired;
        }
    }
    if candidate.health == "UNREACHABLE" || candidate.health == "UNKNOWN" {
        return Eligibility::Unhealthy;
    }
    if candidate.failure_count > 0 && candidate.success_count < 2 && candidate.health != "HEALTHY" {
        return Eligibility::Recovering;
    }
    Eligibility::Eligible
}

fn score(policy: RoutePolicy, candidate: &RouteCandidate) -> (u8, u64, u32, u8, u32) {
    let latency = candidate.latency_ms.unwrap_or(u64::MAX);
    let cost = candidate.network_cost.max(candidate.cost);
    match policy {
        RoutePolicy::LowLatency => (
            health_rank(&candidate.health),
            latency,
            cost,
            type_rank(&candidate.route_type),
            candidate.failure_count,
        ),
        RoutePolicy::CostOptimized => (
            health_rank(&candidate.health),
            if candidate.metered { 1 } else { 0 },
            cost,
            type_rank(&candidate.route_type),
            candidate.failure_count,
        ),
        RoutePolicy::HighAvailability => (
            health_rank(&candidate.health),
            candidate.failure_count as u64,
            latency.min(1_000_000) as u32,
            type_rank(&candidate.route_type),
            candidate.priority,
        ),
        RoutePolicy::Auto | RoutePolicy::DirectOnly | RoutePolicy::RelayOnly => (
            health_rank(&candidate.health),
            type_rank(&candidate.route_type) as u64,
            latency.min(1_000_000) as u32,
            0,
            cost,
        ),
    }
}

fn candidate_digest(candidates: &[RouteCandidate]) -> String {
    let mut hasher = Sha256::new();
    for candidate in candidates {
        hasher.update(candidate.route_id.as_bytes());
        hasher.update(b"|");
        hasher.update(format!("{:?}", candidate.route_type).as_bytes());
        hasher.update(b"|");
        hasher.update(candidate.endpoint.as_bytes());
        hasher.update(b"|");
        hasher.update(candidate.health.as_bytes());
        hasher.update(b"|");
        hasher.update(candidate.generation.to_string().as_bytes());
        hasher.update(b";");
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn better_enough(
    policy: RoutePolicy,
    config: &PathResolverConfig,
    current: &RouteCandidate,
    candidate: &RouteCandidate,
) -> bool {
    if !config.stickiness {
        return score(policy, candidate) < score(policy, current);
    }
    if current.failure_count >= config.failure_threshold {
        return true;
    }
    let current_latency = current.latency_ms.unwrap_or(u64::MAX);
    let next_latency = candidate.latency_ms.unwrap_or(u64::MAX);
    if next_latency + config.latency_hysteresis_ms < current_latency {
        return true;
    }
    score(policy, candidate) < score(policy, current)
        && candidate.health == "HEALTHY"
        && current.health != "HEALTHY"
}

pub fn resolve_path(
    candidates: &[RouteCandidate],
    request: PathResolveRequest<'_>,
    config: &PathResolverConfig,
    state: &mut PathResolverState,
) -> Result<RouteDecisionReceipt, String> {
    if request.now_ms < state.last_probe_at_ms.saturating_add(config.probe_backoff_ms)
        && state.selected_route_id.is_some()
    {
        let selected = state.selected_route_id.clone().unwrap();
        return Ok(receipt(
            request,
            candidates,
            state.selected_route_id.clone(),
            &selected,
            "probe_backoff_hold",
            None,
        ));
    }
    state.last_probe_at_ms = request.now_ms;

    let mut eligible: Vec<&RouteCandidate> = candidates
        .iter()
        .filter(|candidate| {
            eligibility(candidate, request.policy, request.now_ms) == Eligibility::Eligible
                && (candidate.site_id.is_empty() || candidate.site_id == request.site_id)
        })
        .collect();
    eligible.sort_by_key(|candidate| score(request.policy, candidate));

    let current = state
        .selected_route_id
        .as_ref()
        .and_then(|id| candidates.iter().find(|candidate| &candidate.route_id == id));
    let hold_active = current
        .map(|candidate| {
            config.stickiness
                && request.now_ms.saturating_sub(state.selected_at_ms) < config.minimum_hold_ms
                && candidate.failure_count < config.failure_threshold
                && eligibility(candidate, request.policy, request.now_ms) == Eligibility::Eligible
        })
        .unwrap_or(false);

    let selected = if hold_active {
        current
    } else {
        let best = eligible.first().copied();
        match (current, best) {
            (Some(current), Some(best)) if current.route_id == best.route_id => Some(current),
            (Some(current), Some(best))
                if !better_enough(request.policy, config, current, best)
                    && eligibility(current, request.policy, request.now_ms) == Eligibility::Eligible =>
            {
                Some(current)
            }
            (_, Some(best)) => Some(best),
            (Some(current), None)
                if eligibility(current, request.policy, request.now_ms) == Eligibility::Eligible =>
            {
                Some(current)
            }
            _ => None,
        }
    };

    let Some(selected) = selected else {
        return Err(format!(
            "PATH_RESOLVER_POLICY_UNSATISFIED:{}",
            format!("{:?}", request.policy).to_ascii_uppercase()
        ));
    };

    let reason = if current.map(|c| c.route_id.as_str()) == Some(selected.route_id.as_str()) {
        if hold_active {
            "sticky_minimum_hold"
        } else {
            "sticky_current_healthy"
        }
    } else if current.is_some() {
        "failover_better_candidate"
    } else {
        "initial_select"
    };

    let previous = state.selected_route_id.clone();
    if previous.as_deref() != Some(selected.route_id.as_str()) {
        state.selected_route_id = Some(selected.route_id.clone());
        state.selected_at_ms = request.now_ms;
    }

    Ok(receipt(
        request,
        candidates,
        previous,
        &selected.route_id,
        reason,
        None,
    ))
}

fn receipt(
    request: PathResolveRequest<'_>,
    candidates: &[RouteCandidate],
    previous: Option<String>,
    selected: &str,
    reason: &str,
    failure: Option<serde_json::Value>,
) -> RouteDecisionReceipt {
    RouteDecisionReceipt {
        decision_id: format!("prd-{}", request.now_ms),
        terminal_id: request.capability.to_string(),
        site_id: request.site_id.to_string(),
        previous_route: previous,
        selected_route: selected.to_string(),
        reason: reason.to_string(),
        failure_evidence: failure,
        selected_at: request.now_ms.to_string(),
        policy_generation: request.policy_generation,
        candidate_snapshot_digest: Some(candidate_digest(candidates)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_ops::RouteCandidate;

    fn candidate(
        id: &str,
        route_type: RouteType,
        health: &str,
        latency: Option<u64>,
        cost: u32,
        failure: u32,
        expires: &str,
    ) -> RouteCandidate {
        RouteCandidate {
            route_id: id.into(),
            route_type,
            endpoint: format!("https://{id}.example"),
            priority: 10,
            cost,
            health: health.into(),
            latency_ms: latency,
            failure_count: failure,
            generation: 1,
            expires_at: expires.into(),
            authority: "actium".into(),
            attestation: None,
            trust: "enrolled".into(),
            network_cost: cost,
            metered: matches!(route_type, RouteType::ActiumRelay),
            last_success: None,
            success_count: if health == "HEALTHY" { 5 } else { 0 },
            relay_id: if matches!(route_type, RouteType::ActiumRelay) {
                Some("relay-a".into())
            } else {
                None
            },
            site_id: "site-1".into(),
        }
    }

    fn set(
        lan: &str,
        wan: &str,
        relay: &str,
        now: u64,
    ) -> Vec<RouteCandidate> {
        vec![
            candidate("lan", RouteType::SiteDirectLan, lan, Some(2), 1, 0, &(now + 60_000).to_string()),
            candidate("wan4", RouteType::SiteDirectWanIpv4, wan, Some(40), 5, 0, &(now + 60_000).to_string()),
            candidate("relay", RouteType::ActiumRelay, relay, Some(80), 20, 0, &(now + 60_000).to_string()),
        ]
    }

    #[test]
    fn auto_prefers_lan_over_wan_and_relay() {
        let mut state = PathResolverState::default();
        let receipt = resolve_path(
            &set("HEALTHY", "HEALTHY", "HEALTHY", 1_000),
            PathResolveRequest {
                policy: RoutePolicy::Auto,
                capability: TEST_PRODUCT_CAPABILITY,
                site_id: "site-1",
                policy_generation: 3,
                now_ms: 1_000,
            },
            &PathResolverConfig::default(),
            &mut state,
        )
        .unwrap();
        assert_eq!(receipt.selected_route, "lan");
        assert_eq!(receipt.terminal_id, TEST_PRODUCT_CAPABILITY);
        assert!(receipt.candidate_snapshot_digest.is_some());
    }

    #[test]
    fn direct_only_fails_closed_without_direct_candidates() {
        let mut state = PathResolverState::default();
        let candidates = vec![candidate(
            "relay",
            RouteType::ActiumRelay,
            "HEALTHY",
            Some(10),
            1,
            0,
            "100000",
        )];
        let error = resolve_path(
            &candidates,
            PathResolveRequest {
                policy: RoutePolicy::DirectOnly,
                capability: TEST_PRODUCT_CAPABILITY,
                site_id: "site-1",
                policy_generation: 1,
                now_ms: 10,
            },
            &PathResolverConfig::default(),
            &mut state,
        )
        .unwrap_err();
        assert!(error.contains("PATH_RESOLVER_POLICY_UNSATISFIED"));
    }

    #[test]
    fn stickiness_holds_until_failure_threshold_and_min_hold() {
        let mut config = PathResolverConfig::default();
        config.minimum_hold_ms = 10_000;
        config.failure_threshold = 3;
        let mut state = PathResolverState {
            selected_route_id: Some("wan4".into()),
            selected_at_ms: 1_000,
            last_probe_at_ms: 0,
        };
        let mut candidates = set("HEALTHY", "HEALTHY", "HEALTHY", 2_000);
        candidates[1].latency_ms = Some(200);
        let receipt = resolve_path(
            &candidates,
            PathResolveRequest {
                policy: RoutePolicy::Auto,
                capability: TEST_PRODUCT_CAPABILITY,
                site_id: "site-1",
                policy_generation: 1,
                now_ms: 2_000,
            },
            &config,
            &mut state,
        )
        .unwrap();
        assert_eq!(receipt.selected_route, "wan4");
        assert_eq!(receipt.reason, "sticky_minimum_hold");
    }

    #[test]
    fn failover_after_failure_threshold() {
        let mut config = PathResolverConfig::default();
        config.minimum_hold_ms = 0;
        config.failure_threshold = 3;
        config.probe_backoff_ms = 0;
        let mut state = PathResolverState {
            selected_route_id: Some("lan".into()),
            selected_at_ms: 1,
            last_probe_at_ms: 0,
        };
        let mut candidates = set("DEGRADED", "HEALTHY", "HEALTHY", 20_000);
        candidates[0].failure_count = 3;
        candidates[0].success_count = 0;
        let receipt = resolve_path(
            &candidates,
            PathResolveRequest {
                policy: RoutePolicy::HighAvailability,
                capability: TEST_PRODUCT_CAPABILITY,
                site_id: "site-1",
                policy_generation: 1,
                now_ms: 20_000,
            },
            &config,
            &mut state,
        )
        .unwrap();
        assert_eq!(receipt.selected_route, "wan4");
        assert_eq!(receipt.previous_route.as_deref(), Some("lan"));
    }

    #[test]
    fn expired_and_future_federated_routes_are_ignored() {
        let mut state = PathResolverState::default();
        let candidates = vec![
            candidate("old", RouteType::SiteDirectLan, "HEALTHY", Some(1), 1, 0, "5"),
            candidate(
                "fed",
                RouteType::FederatedActiumNode,
                "HEALTHY",
                Some(1),
                1,
                0,
                "999999",
            ),
            candidate("relay", RouteType::ActiumRelay, "HEALTHY", Some(9), 9, 0, "999999"),
        ];
        let receipt = resolve_path(
            &candidates,
            PathResolveRequest {
                policy: RoutePolicy::Auto,
                capability: TEST_PRODUCT_CAPABILITY,
                site_id: "site-1",
                policy_generation: 1,
                now_ms: 10,
            },
            &PathResolverConfig::default(),
            &mut state,
        )
        .unwrap();
        assert_eq!(receipt.selected_route, "relay");
    }

    #[test]
    fn cost_optimized_prefers_unmetered_direct() {
        let mut state = PathResolverState::default();
        let mut candidates = set("HEALTHY", "HEALTHY", "HEALTHY", 1);
        candidates[0].network_cost = 50;
        candidates[1].network_cost = 2;
        candidates[1].metered = false;
        candidates[2].network_cost = 1;
        let receipt = resolve_path(
            &candidates,
            PathResolveRequest {
                policy: RoutePolicy::CostOptimized,
                capability: TEST_PRODUCT_CAPABILITY,
                site_id: "site-1",
                policy_generation: 1,
                now_ms: 1,
            },
            &PathResolverConfig::default(),
            &mut state,
        )
        .unwrap();
        assert_eq!(receipt.selected_route, "wan4");
    }
}
