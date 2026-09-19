//! Shared R3/R6 conformance vectors loaded from the canonical JSON contract.

#[cfg(test)]
mod tests {
    use crate::canonical_scope::{CanonicalConnectivityScopeV1, CANONICAL_SCOPE_CONTRACT};
    use crate::common_connectivity_client::{
        resolve_common_connectivity, CommonConnectivityCandidateV1, CommonConnectivityRequestV1,
        CommonRouteKind, CommonRoutePolicy, CommonTransport, InMemoryProductAssignmentAuthorizer,
        ProductAssignmentGrantV1, RouteSharingScope, COMMON_CONNECTIVITY_CLIENT_CONTRACT,
    };
    use crate::relay_trust::{
        snapshot_payload_digest, CanonicalTrustState, InMemoryTrustedIssuerResolver,
        RelayTrustSnapshotV1, RelayTrustSnapshotVerifier, TrustedRelaySnapshotIssuer,
        RELAY_SNAPSHOT_ISSUER_PURPOSE,
    };
    use serde::Deserialize;
    use std::fs;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorFile {
        contract: String,
        payload_digest: String,
        signed_snapshot: RelayTrustSnapshotV1,
        canonical_scope: CanonicalConnectivityScopeV1,
        #[serde(default)]
        trusted_issuers: Vec<TrustedRelaySnapshotIssuer>,
        vectors: Vec<VectorCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct VectorCase {
        id: String,
        kind: String,
        #[serde(default)]
        policy: Option<String>,
        #[serde(default)]
        direct_ready: Option<bool>,
        #[serde(default)]
        include_relay: Option<bool>,
        #[serde(default)]
        trust_state: Option<String>,
        #[serde(default)]
        candidate_host_id: Option<String>,
        #[serde(default)]
        candidate_site_id: Option<String>,
        #[serde(default)]
        request_organization_id: Option<String>,
        #[serde(default)]
        candidate_binding_epoch: Option<u64>,
        #[serde(default)]
        candidate_service_identity: Option<String>,
        #[serde(default)]
        candidate_configuration_version: Option<u64>,
        #[serde(default)]
        empty_candidates: Option<bool>,
        #[serde(default)]
        candidate_client_id: Option<String>,
        #[serde(default)]
        include_local: Option<bool>,
        #[serde(default)]
        include_private: Option<bool>,
        #[serde(default)]
        sharing_scope: Option<String>,
        #[serde(default)]
        product_id: Option<String>,
        #[serde(default)]
        product_assignment_id: Option<String>,
        #[serde(default)]
        candidate_product_id: Option<String>,
        #[serde(default)]
        assignment_authorized: Option<bool>,
        #[serde(default)]
        expected_endpoint: Option<String>,
        #[serde(default)]
        expected_reason: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        now_unix: Option<u64>,
        #[serde(default)]
        #[allow(dead_code)]
        expected_accept: Option<bool>,
        #[serde(default)]
        #[allow(dead_code)]
        expected_error: Option<String>,
    }

    fn load() -> VectorFile {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/connectivity/v1/r3-r6-conformance-vectors.v1.json");
        let raw = fs::read_to_string(&path).expect("shared vectors");
        serde_json::from_str(&raw).expect("shared vectors json")
    }

    fn policy(value: Option<&String>) -> CommonRoutePolicy {
        match value.map(String::as_str).unwrap_or("AUTO") {
            "RELAY_ONLY" => CommonRoutePolicy::RelayOnly,
            "DISABLED" => CommonRoutePolicy::Disabled,
            "DIRECT_PREFERRED" => CommonRoutePolicy::DirectPreferred,
            _ => CommonRoutePolicy::Auto,
        }
    }

    fn trust(value: Option<&String>) -> CanonicalTrustState {
        CanonicalTrustState::parse(value.map(String::as_str).unwrap_or("TRUSTED"))
    }

    fn request(scope: &CanonicalConnectivityScopeV1, case: &VectorCase) -> CommonConnectivityRequestV1 {
        CommonConnectivityRequestV1 {
            contract: COMMON_CONNECTIVITY_CLIENT_CONTRACT.into(),
            client_id: scope.client_id.clone(),
            organization_id: case
                .request_organization_id
                .clone()
                .unwrap_or_else(|| scope.organization_id.clone()),
            site_id: scope.site_id.clone(),
            host_id: scope.host_id.clone(),
            product_id: case
                .product_id
                .clone()
                .unwrap_or_else(|| "actium-product".into()),
            product_assignment_id: case.product_assignment_id.clone(),
            service_id: "site-gateway".into(),
            capability: "telemetry.gps.batch".into(),
            binding_epoch: Some(scope.binding_epoch),
            policy_generation: Some(scope.policy_generation),
            route_policy: policy(case.policy.as_ref()),
            expected_service_identity: Some("site-gateway-v1".into()),
        }
    }

    fn candidates(scope: &CanonicalConnectivityScopeV1, case: &VectorCase) -> Vec<CommonConnectivityCandidateV1> {
        if case.empty_candidates.unwrap_or(false) {
            return Vec::new();
        }
        let make = |transport: CommonTransport, endpoint: &str, ready: bool| CommonConnectivityCandidateV1 {
            organization_id: Some(scope.organization_id.clone()),
            client_id: Some(
                case.candidate_client_id
                    .clone()
                    .unwrap_or_else(|| scope.client_id.clone()),
            ),
            site_id: Some(case.candidate_site_id.clone().unwrap_or_else(|| scope.site_id.clone())),
            host_id: Some(case.candidate_host_id.clone().unwrap_or_else(|| scope.host_id.clone())),
            product_id: Some(
                case.candidate_product_id
                    .clone()
                    .or_else(|| case.product_id.clone())
                    .unwrap_or_else(|| "actium-product".into()),
            ),
            service_id: "site-gateway".into(),
            capability: "telemetry.gps.batch".into(),
            route_kind: match transport {
                CommonTransport::Local => CommonRouteKind::Local,
                CommonTransport::Private => CommonRouteKind::Private,
                _ => CommonRouteKind::Remote,
            },
            transport,
            endpoint: endpoint.into(),
            expected_service_identity: case
                .candidate_service_identity
                .clone()
                .unwrap_or_else(|| "site-gateway-v1".into()),
            authority_scope: "site:host:telemetry".into(),
            trust_state: trust(case.trust_state.as_ref()),
            health: if ready { "HEALTHY".into() } else { "UNREACHABLE".into() },
            readiness: ready,
            priority: 10,
            binding_epoch: case.candidate_binding_epoch.unwrap_or(scope.binding_epoch),
            configuration_version: case
                .candidate_configuration_version
                .unwrap_or(scope.policy_generation),
            sharing_scope: match case.sharing_scope.as_deref() {
                Some("PRODUCT_SCOPED") => RouteSharingScope::ProductScoped,
                _ => RouteSharingScope::HostShared,
            },
            reason: None,
        };
        let direct_ready = case.direct_ready.unwrap_or(true);
        let include_relay = case.include_relay.unwrap_or(true);
        let mut list = Vec::new();
        if case.include_local.unwrap_or(false) {
            list.push(make(
                CommonTransport::Local,
                "https://127.0.0.1:9443",
                true,
            ));
        }
        if case.include_private.unwrap_or(false) {
            list.push(make(CommonTransport::Private, "https://lan.example", true));
        }
        list.push(make(
            CommonTransport::DirectWan,
            "https://wan.example",
            direct_ready,
        ));
        if include_relay {
            list.push(make(CommonTransport::Relay, "https://relay.example", true));
        }
        list
    }

    fn assignment_authorizer(case: &VectorCase) -> Option<InMemoryProductAssignmentAuthorizer> {
        let assignment_id = case.product_assignment_id.as_deref()?;
        if assignment_id == "assign-missing" {
            return Some(InMemoryProductAssignmentAuthorizer::new(vec![]));
        }
        Some(InMemoryProductAssignmentAuthorizer::new(vec![
            ProductAssignmentGrantV1 {
                product_assignment_id: assignment_id.to_string(),
                product_id: case
                    .product_id
                    .clone()
                    .unwrap_or_else(|| "actium-product".into()),
                client_id: "client-a".into(),
                organization_id: "org-a".into(),
                capability: "telemetry.gps.batch".into(),
                service_id: Some("site-gateway".into()),
                authorized: case.assignment_authorized.unwrap_or(true),
            },
        ]))
    }

    #[test]
    fn shared_vectors_have_stable_payload_digest_and_scope_contract() {
        let file = load();
        assert_eq!(file.contract, "actium.connectivity.r3-r6-conformance.v1");
        assert_eq!(file.canonical_scope.contract, CANONICAL_SCOPE_CONTRACT);
        assert_eq!(
            snapshot_payload_digest(&file.signed_snapshot.body).unwrap(),
            file.payload_digest
        );
        assert_eq!(file.signed_snapshot.payload_digest, file.payload_digest);
    }

    #[test]
    fn r6_vectors_select_or_fail_closed_identically() {
        let file = load();
        for case in file.vectors.iter().filter(|case| case.kind == "r6") {
            let resolution = resolve_common_connectivity(
                &file.canonical_scope,
                &request(&file.canonical_scope, case),
                &candidates(&file.canonical_scope, case),
                None,
            );
            assert_eq!(
                resolution.selected.as_ref().map(|route| route.endpoint.as_str()),
                case.expected_endpoint.as_deref(),
                "{}",
                case.id
            );
            assert_eq!(
                resolution.reason_code.as_deref(),
                case.expected_reason.as_deref(),
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn r6_assignment_vectors_enforce_host_shared_and_product_scoped() {
        let file = load();
        for case in file.vectors.iter().filter(|case| case.kind == "r6-assignment") {
            let authorizer = assignment_authorizer(case);
            let resolution = resolve_common_connectivity(
                &file.canonical_scope,
                &request(&file.canonical_scope, case),
                &candidates(&file.canonical_scope, case),
                authorizer
                    .as_ref()
                    .map(|value| value as &dyn crate::ProductAssignmentAuthorizer),
            );
            assert_eq!(
                resolution.selected.as_ref().map(|route| route.endpoint.as_str()),
                case.expected_endpoint.as_deref(),
                "{}",
                case.id
            );
            assert_eq!(
                resolution.reason_code.as_deref(),
                case.expected_reason.as_deref(),
                "{}",
                case.id
            );
        }
    }

    #[test]
    fn r3_issuer_vectors_reject_rogue_unknown_and_mismatched_keys() {
        let file = load();
        let issuers = InMemoryTrustedIssuerResolver::new(file.trusted_issuers.clone());
        for case in file.vectors.iter().filter(|case| case.kind == "r3-issuer") {
            let mut snapshot = file.signed_snapshot.clone();
            snapshot.body.nonce = format!("issuer-{}", case.id);
            snapshot.payload_digest = snapshot_payload_digest(&snapshot.body).unwrap();
            let error = match case.id.as_str() {
                "rogue-self-signed-trusted-snapshot" | "unknown-snapshot-issuer" => {
                    RelayTrustSnapshotVerifier::new(60)
                        .verify(&snapshot, 1_800_000_000, &InMemoryTrustedIssuerResolver::default())
                        .unwrap_err()
                }
                "issuer-public-key-mismatch" => {
                    let mismatched = InMemoryTrustedIssuerResolver::new(vec![TrustedRelaySnapshotIssuer {
                        key_id: snapshot.body.issuer_key_id.clone(),
                        public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                        public_identity: snapshot.body.issuer_public_identity.clone(),
                        purpose: RELAY_SNAPSHOT_ISSUER_PURPOSE.into(),
                        status: "ACTIVE".into(),
                    }]);
                    RelayTrustSnapshotVerifier::new(60)
                        .verify(&snapshot, 1_800_000_000, &mismatched)
                        .unwrap_err()
                }
                "issuer-key-id-mismatch" => {
                    snapshot.body.issuer_key_id = "sha256:deadbeefdeadbeef".into();
                    snapshot.payload_digest = snapshot_payload_digest(&snapshot.body).unwrap();
                    RelayTrustSnapshotVerifier::new(60)
                        .verify(&snapshot, 1_800_000_000, &issuers)
                        .unwrap_err()
                }
                other => panic!("unhandled r3-issuer vector {other}"),
            };
            assert_eq!(error, case.expected_error.as_deref().unwrap(), "{}", case.id);
        }
    }

    #[test]
    fn r3_snapshot_vectors_accept_valid_and_reject_replay_stale_and_bad_signature() {
        let file = load();
        let issuers = if file.trusted_issuers.is_empty() {
            InMemoryTrustedIssuerResolver::new(vec![TrustedRelaySnapshotIssuer {
                key_id: file.signed_snapshot.body.issuer_key_id.clone(),
                public_key: file.signed_snapshot.body.issuer_public_key.clone(),
                public_identity: file.signed_snapshot.body.issuer_public_identity.clone(),
                purpose: RELAY_SNAPSHOT_ISSUER_PURPOSE.into(),
                status: "ACTIVE".into(),
            }])
        } else {
            InMemoryTrustedIssuerResolver::new(file.trusted_issuers.clone())
        };
        let mut verifier = RelayTrustSnapshotVerifier::new(60);
        let accepted = verifier
            .verify(&file.signed_snapshot, 1_800_000_000, &issuers)
            .expect("valid snapshot");
        assert_eq!(accepted.host_id, "host-a");
        assert_eq!(
            verifier.verify(&file.signed_snapshot, 1_800_000_000, &issuers).unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_NONCE_REPLAY"
        );

        let mut stale_verifier = RelayTrustSnapshotVerifier::new(0);
        assert_eq!(
            stale_verifier
                .verify(&file.signed_snapshot, 2_000_000_000, &issuers)
                .unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_STALE"
        );

        let mut bad = file.signed_snapshot.clone();
        bad.signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        let mut bad_verifier = RelayTrustSnapshotVerifier::new(60);
        assert_eq!(
            bad_verifier.verify(&bad, 1_800_000_000, &issuers).unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_SIGNATURE_INVALID"
        );
        assert_eq!(
            RelayTrustSnapshotVerifier::new(60)
                .verify(
                    &file.signed_snapshot,
                    1_800_000_000,
                    &InMemoryTrustedIssuerResolver::default()
                )
                .unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN"
        );
    }
}
