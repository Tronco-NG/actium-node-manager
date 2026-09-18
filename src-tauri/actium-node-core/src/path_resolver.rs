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
    Untrusted,
    Unauthorized,
    PolicyDenied,
    FutureInactive,
    WrongSite,
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

fn normalize_authority(value: &str) -> bool {
    matches!(value.trim().to_ascii_uppercase().as_str(), "AUTHORIZED" | "VALID")
}

fn normalize_trust(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_uppercase().as_str() {
        "TRUSTED" => Some("TRUSTED"),
        "AUTHORIZED" => Some("AUTHORIZED"),
        "ENROLLED" => Some("ENROLLED"),
        "UNTRUSTED" => Some("UNTRUSTED"),
        "UNAUTHORIZED" => Some("UNAUTHORIZED"),
        _ => None,
    }
}

fn trust_class(trust: &str) -> &str {
    normalize_trust(trust).unwrap_or("UNKNOWN")
}

fn canonical_trust(trust: &str) -> &'static str {
    match trust_class(trust) {
        "TRUSTED" | "AUTHORIZED" | "ENROLLED" => "TRUSTED",
        "UNTRUSTED" | "UNAUTHORIZED" => "UNTRUSTED",
        _ => "UNKNOWN",
    }
}

fn canonical_attestation(attestation: Option<&String>) -> Option<&'static str> {
    match attestation.map(|value| value.trim().to_ascii_uppercase()).as_deref() {
        Some("READY") | Some("PASS") | Some("VALID") => Some("READY"),
        Some("INVALID")
        | Some("FAILED")
        | Some("REVOKED")
        | Some("FAIL")
        | Some("MISMATCH")
        | Some("EXPIRED")
        | Some("UNTRUSTED") => Some("INVALID"),
        Some(_) => Some("UNKNOWN"),
        None => None,
    }
}

fn attestation_ready(attestation: Option<&String>) -> bool {
    matches!(
        attestation.map(|value| value.trim().to_ascii_uppercase()).as_deref(),
        Some("READY") | Some("PASS") | Some("VALID")
    )
}

fn trust_eligible(candidate: &RouteCandidate) -> Eligibility {
    let class = trust_class(&candidate.trust);
    if class == "UNKNOWN" || class == "UNTRUSTED" || class == "UNAUTHORIZED" {
        return Eligibility::Untrusted;
    }
    match candidate.route_type {
        RouteType::SiteDirectLan => Eligibility::Eligible,
        RouteType::SiteDirectWanIpv4 | RouteType::SiteDirectWanIpv6 => {
            if attestation_ready(candidate.attestation.as_ref()) {
                Eligibility::Eligible
            } else {
                Eligibility::Unauthorized
            }
        }
        RouteType::ActiumRelay => {
            if (class == "TRUSTED" || class == "AUTHORIZED")
                && candidate
                    .relay_id
                    .as_ref()
                    .is_some_and(|relay_id| !relay_id.trim().is_empty())
            {
                Eligibility::Eligible
            } else {
                Eligibility::Untrusted
            }
        }
        RouteType::FederatedActiumNode => Eligibility::FutureInactive,
    }
}

fn eligibility(
    candidate: &RouteCandidate,
    policy: RoutePolicy,
    now_ms: u64,
    config: &PathResolverConfig,
    site_id: &str,
) -> Eligibility {
    if !is_active_route_type(&candidate.route_type) {
        return Eligibility::FutureInactive;
    }
    if !policy_allows(policy, &candidate.route_type) {
        return Eligibility::PolicyDenied;
    }
    if !normalize_authority(&candidate.authority) {
        return Eligibility::Unauthorized;
    }
    if candidate.site_id.trim().is_empty() || candidate.site_id != site_id {
        return Eligibility::WrongSite;
    }
    if let Some(expires) = candidate.expires_at_ms {
        if expires <= now_ms {
            return Eligibility::Expired;
        }
    }
    match trust_eligible(candidate) {
        Eligibility::Eligible => {}
        other => return other,
    }
    if candidate.health == "UNREACHABLE" || candidate.health == "UNKNOWN" {
        return Eligibility::Unhealthy;
    }
    if candidate.failure_count >= 1 && candidate.success_count < config.recovery_threshold {
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

fn route_type_name(route_type: RouteType) -> &'static str {
    match route_type {
        RouteType::SiteDirectLan => "SITE_DIRECT_LAN",
        RouteType::SiteDirectWanIpv4 => "SITE_DIRECT_WAN_IPV4",
        RouteType::SiteDirectWanIpv6 => "SITE_DIRECT_WAN_IPV6",
        RouteType::ActiumRelay => "ACTIUM_RELAY",
        RouteType::FederatedActiumNode => "FEDERATED_ACTIUM_NODE",
    }
}

pub fn path_resolver_candidate_snapshot_digest(candidates: &[RouteCandidate]) -> String {
    let mut ordered = candidates.to_vec();
    ordered.sort_by(|left, right| left.route_id.cmp(&right.route_id));
    let snapshot = ordered
        .iter()
        .map(|candidate| {
            serde_json::json!({
                "authority": if normalize_authority(&candidate.authority) { "AUTHORIZED" } else { "UNKNOWN" },
                "attestation": canonical_attestation(candidate.attestation.as_ref()),
                "endpoint": candidate.endpoint,
                "expiresAtMs": candidate.expires_at_ms,
                "failureCount": candidate.failure_count,
                "generation": candidate.generation,
                "health": candidate.health,
                "latencyMs": candidate.latency_ms,
                "metered": candidate.metered,
                "networkCost": candidate.network_cost.max(candidate.cost),
                "priority": candidate.priority,
                "relayId": candidate.relay_id,
                "routeId": candidate.route_id,
                "siteId": candidate.site_id,
                "successCount": candidate.success_count,
                "trust": canonical_trust(&candidate.trust),
                "type": route_type_name(candidate.route_type),
            })
        })
        .collect::<Vec<_>>();
    let canonical = crate::canonical_json(&serde_json::Value::Array(snapshot))
        .unwrap_or_else(|_| "[]".into());
    let digest = Sha256::digest(canonical.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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
    let mut eligible: Vec<&RouteCandidate> = candidates
        .iter()
        .filter(|candidate| {
            eligibility(candidate, request.policy, request.now_ms, config, request.site_id)
                == Eligibility::Eligible
        })
        .collect();
    eligible.sort_by_key(|candidate| score(request.policy, candidate));

    let current = state
        .selected_route_id
        .as_ref()
        .and_then(|id| candidates.iter().find(|candidate| &candidate.route_id == id));
    if request.now_ms < state.last_probe_at_ms.saturating_add(config.probe_backoff_ms)
        && current.is_some_and(|candidate| {
            eligibility(candidate, request.policy, request.now_ms, config, request.site_id)
                == Eligibility::Eligible
        })
    {
        let selected = current.expect("current route checked above");
        return Ok(receipt(
            request,
            candidates,
            state.selected_route_id.clone(),
            &selected.route_id,
            "probe_backoff_hold",
            None,
        ));
    }
    state.last_probe_at_ms = request.now_ms;
    let hold_active = current
        .map(|candidate| {
            config.stickiness
                && request.now_ms.saturating_sub(state.selected_at_ms) < config.minimum_hold_ms
                && candidate.failure_count < config.failure_threshold
                && eligibility(candidate, request.policy, request.now_ms, config, request.site_id)
                    == Eligibility::Eligible
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
                    && eligibility(current, request.policy, request.now_ms, config, request.site_id)
                        == Eligibility::Eligible =>
            {
                Some(current)
            }
            (_, Some(best)) => Some(best),
            (Some(current), None)
                if eligibility(current, request.policy, request.now_ms, config, request.site_id)
                    == Eligibility::Eligible =>
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
        candidate_snapshot_digest: Some(path_resolver_candidate_snapshot_digest(candidates)),
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
            expires_at_ms: expires.parse().ok(),
            authority: "AUTHORIZED".into(),
            attestation: if matches!(
                route_type,
                RouteType::SiteDirectWanIpv4 | RouteType::SiteDirectWanIpv6
            ) {
                Some("READY".into())
            } else {
                None
            },
            trust: if matches!(route_type, RouteType::ActiumRelay) {
                "TRUSTED".into()
            } else {
                "ENROLLED".into()
            },
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

    #[test]
    fn recovery_threshold_comes_from_config() {
        for (threshold, expect_ok) in [(1u32, true), (2, true), (4, false)] {
            let mut config = PathResolverConfig::default();
            config.recovery_threshold = threshold;
            config.minimum_hold_ms = 0;
            config.probe_backoff_ms = 0;
            let mut candidate = candidate(
                "lan",
                RouteType::SiteDirectLan,
                "DEGRADED",
                Some(2),
                1,
                1,
                "999999",
            );
            candidate.success_count = 2;
            let mut state = PathResolverState::default();
            let result = resolve_path(
                &[candidate],
                PathResolveRequest {
                    policy: RoutePolicy::Auto,
                    capability: TEST_PRODUCT_CAPABILITY,
                    site_id: "site-1",
                    policy_generation: 1,
                    now_ms: 10,
                },
                &config,
                &mut state,
            );
            assert_eq!(result.is_ok(), expect_ok, "threshold={threshold}");
        }
    }

    #[test]
    fn untrusted_and_unattested_wan_are_not_eligible() {
        let mut untrusted = candidate(
            "lan",
            RouteType::SiteDirectLan,
            "HEALTHY",
            Some(1),
            1,
            0,
            "999999",
        );
        untrusted.trust = "UNKNOWN".into();
        let mut wan = candidate(
            "wan4",
            RouteType::SiteDirectWanIpv4,
            "HEALTHY",
            Some(1),
            1,
            0,
            "999999",
        );
        wan.attestation = None;
        let mut state = PathResolverState::default();
        assert!(resolve_path(
            &[untrusted, wan],
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
        .is_err());
    }

    #[test]
    fn snapshot_digest_is_stable_sha256() {
        let candidates = set("HEALTHY", "HEALTHY", "HEALTHY", 1);
        let first = path_resolver_candidate_snapshot_digest(&candidates);
        let second = path_resolver_candidate_snapshot_digest(&candidates);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn snapshot_digest_changes_for_security_and_route_metrics() {
        let baseline = set("HEALTHY", "HEALTHY", "HEALTHY", 1_000);
        let digest = path_resolver_candidate_snapshot_digest(&baseline);
        for mutation in 0..10 {
            let mut changed = baseline.clone();
            match mutation {
                0 => changed[0].attestation = Some("READY".into()),
                1 => changed[0].trust = "UNTRUSTED".into(),
                2 => changed[0].trust = "UNKNOWN".into(),
                3 => changed[0].attestation = Some("INVALID".into()),
                4 => changed[0].attestation = Some("UNKNOWN".into()),
                5 => changed[0].authority = "UNKNOWN".into(),
                6 => changed[0].expires_at_ms = Some(99_999),
                7 => changed[0].cost = changed[0].cost.saturating_add(1),
                8 => changed[0].latency_ms = Some(999),
                9 => changed.reverse(),
                _ => unreachable!(),
            }
            if mutation == 9 {
                assert_eq!(digest, path_resolver_candidate_snapshot_digest(&changed));
            } else {
                assert_ne!(digest, path_resolver_candidate_snapshot_digest(&changed));
            }
        }
        let mut untrusted = baseline.clone();
        untrusted[0].trust = "UNTRUSTED".into();
        let mut unknown_trust = baseline.clone();
        unknown_trust[0].trust = "UNKNOWN".into();
        assert_ne!(
            path_resolver_candidate_snapshot_digest(&untrusted),
            path_resolver_candidate_snapshot_digest(&unknown_trust),
        );
        let mut invalid_attestation = baseline.clone();
        invalid_attestation[0].attestation = Some("INVALID".into());
        let mut unknown_attestation = baseline.clone();
        unknown_attestation[0].attestation = Some("UNKNOWN".into());
        assert_ne!(
            path_resolver_candidate_snapshot_digest(&invalid_attestation),
            path_resolver_candidate_snapshot_digest(&unknown_attestation),
        );
    }

    #[derive(Debug, Deserialize)]
    struct ConformanceFile {
        vectors: Vec<ConformanceVector>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConformanceVector {
        id: String,
        request: ConformanceRequest,
        config: PathResolverConfig,
        state: PathResolverState,
        candidates: Vec<RouteCandidate>,
        expected: ConformanceExpected,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConformanceRequest {
        policy: RoutePolicy,
        capability: String,
        site_id: String,
        policy_generation: u64,
        now_ms: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConformanceExpected {
        selected_route: Option<String>,
        fail_closed: bool,
        reason_class: String,
        error_class: Option<String>,
        candidate_snapshot_digest: String,
        final_state: PathResolverState,
    }

    fn conformance_reason_class(reason: &str) -> &str {
        match reason {
            "initial_select" => "INITIAL_SELECT",
            "probe_backoff_hold" => "PROBE_BACKOFF_HOLD",
            "failover_better_candidate" => "FAILOVER",
            "sticky_minimum_hold" | "sticky_current_healthy" => "STICKY",
            _ => reason,
        }
    }

    #[test]
    fn canonical_path_resolver_vectors_match_expected_outputs() {
        let file: ConformanceFile = serde_json::from_str(include_str!(
            "../../../contracts/connectivity/v1/path-resolver-vectors.v1.json"
        ))
        .expect("canonical vectors must parse");
        for vector in file.vectors {
            let mut state = vector.state.clone();
            let request = PathResolveRequest {
                policy: vector.request.policy,
                capability: &vector.request.capability,
                site_id: &vector.request.site_id,
                policy_generation: vector.request.policy_generation,
                now_ms: vector.request.now_ms,
            };
            let result = resolve_path(&vector.candidates, request, &vector.config, &mut state);
            let digest = path_resolver_candidate_snapshot_digest(&vector.candidates);
            assert_eq!(digest, vector.expected.candidate_snapshot_digest, "{} digest", vector.id);
            match result {
                Ok(receipt) => {
                    assert!(!vector.expected.fail_closed, "{} unexpectedly succeeded", vector.id);
                    assert_eq!(Some(receipt.selected_route.clone()), vector.expected.selected_route, "{} route", vector.id);
                    assert_eq!(conformance_reason_class(&receipt.reason), vector.expected.reason_class, "{} reason", vector.id);
                    assert_eq!(vector.expected.error_class, None, "{} error", vector.id);
                }
                Err(error) => {
                    assert!(vector.expected.fail_closed, "{} unexpectedly failed open", vector.id);
                    assert_eq!(vector.expected.selected_route, None, "{} route", vector.id);
                    assert_eq!(vector.expected.reason_class, "POLICY_UNSATISFIED", "{} reason", vector.id);
                    assert_eq!(error.split(':').next(), vector.expected.error_class.as_deref(), "{} error", vector.id);
                }
            }
            assert_eq!(state, vector.expected.final_state, "{} state", vector.id);
        }
    }
}
