//! Canonical current Host connectivity trust.
//!
//! Historical enrollment verification is not current Trust Fabric
//! authorization. Trust is derived from canonical enrollment plus the
//! current Trust Store / Trust Bundle, authority status, binding epoch,
//! and connectivity policy generation.

use crate::authority::{AuthorityIdentityRef, HostBindingProjection};
use crate::relay_trust::{
    CanonicalTrustState, TrustedRelaySnapshotIssuer, TrustedRelaySnapshotIssuerResolver,
    RELAY_SNAPSHOT_ISSUER_PURPOSE,
};
use crate::trust_fabric::{AuthorityDescriptor, AuthorityKind, AuthorityStatus, Revocation, SignedTrustBundle};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

pub const CONFIGURATION_UNAVAILABLE: &str = "CONFIGURATION_UNAVAILABLE";
pub const TRUST_STORE_UNAVAILABLE: &str = "TRUST_STORE_UNAVAILABLE";

pub trait ConnectivityPolicyGenerationProvider {
    fn current_policy_generation(&self) -> Result<u64, String>;
}

#[derive(Debug, Default)]
pub struct UnavailableConnectivityPolicyGeneration;

impl ConnectivityPolicyGenerationProvider for UnavailableConnectivityPolicyGeneration {
    fn current_policy_generation(&self) -> Result<u64, String> {
        Err(CONFIGURATION_UNAVAILABLE.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct InMemoryConnectivityPolicyGeneration {
    generation: u64,
}

impl InMemoryConnectivityPolicyGeneration {
    pub fn new(generation: u64) -> Self {
        Self { generation }
    }
}

impl ConnectivityPolicyGenerationProvider for InMemoryConnectivityPolicyGeneration {
    fn current_policy_generation(&self) -> Result<u64, String> {
        Ok(self.generation)
    }
}

#[derive(Debug, Clone)]
pub struct FileConnectivityPolicyGeneration {
    path: PathBuf,
}

impl FileConnectivityPolicyGeneration {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ConnectivityPolicyGenerationProvider for FileConnectivityPolicyGeneration {
    fn current_policy_generation(&self) -> Result<u64, String> {
        let raw = fs::read_to_string(&self.path).map_err(|_| CONFIGURATION_UNAVAILABLE.to_string())?;
        let value: serde_json::Value =
            serde_json::from_str(&raw).map_err(|_| CONFIGURATION_UNAVAILABLE.to_string())?;
        value
            .get("policyGeneration")
            .or_else(|| value.get("policy_generation"))
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| CONFIGURATION_UNAVAILABLE.to_string())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalTrustStoreViewV1 {
    pub ready: bool,
    pub trust_bundle_id: Option<String>,
    pub trust_epoch: Option<u64>,
    pub expires_at: Option<u64>,
    pub authorities: Vec<AuthorityDescriptor>,
    pub revocations: Vec<Revocation>,
}

impl CanonicalTrustStoreViewV1 {
    pub fn from_signed_bundle(bundle: &SignedTrustBundle) -> Self {
        let mut authorities = Vec::new();
        if let Some(center) = &bundle.bundle.center_authority {
            authorities.push(center.clone());
        }
        authorities.extend(bundle.bundle.predecessor_center_authorities.iter().cloned());
        authorities.extend(bundle.bundle.enrollment_authorities.iter().cloned());
        authorities.extend(bundle.bundle.product_signing_authorities.iter().cloned());
        Self {
            ready: true,
            trust_bundle_id: Some(bundle.bundle.trust_bundle_id.clone()),
            trust_epoch: Some(bundle.bundle.trust_epoch),
            expires_at: bundle.bundle.expires_at,
            authorities,
            revocations: bundle.bundle.revocations.clone(),
        }
    }

    pub fn unavailable() -> Self {
        Self::default()
    }

    fn status_for(&self, key_id: &str) -> Option<AuthorityStatus> {
        if self
            .revocations
            .iter()
            .any(|revocation| revocation.key_id == key_id)
        {
            return Some(AuthorityStatus::Revoked);
        }
        self.authorities
            .iter()
            .find(|authority| authority.key_id == key_id)
            .map(|authority| authority.status)
    }
}

impl TrustedRelaySnapshotIssuerResolver for CanonicalTrustStoreViewV1 {
    fn resolve_trusted_issuer(&self, key_id: &str) -> Result<TrustedRelaySnapshotIssuer, String> {
        if !self.ready {
            return Err("RELAY_TRUST_SNAPSHOT_TRUST_UNAVAILABLE".to_string());
        }
        let key_id = key_id.trim();
        if key_id.is_empty() {
            return Err("RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN".to_string());
        }
        if matches!(self.status_for(key_id), Some(AuthorityStatus::Revoked) | Some(AuthorityStatus::Retired))
        {
            return Err("RELAY_TRUST_SNAPSHOT_ISSUER_UNTRUSTED".to_string());
        }
        let authority = self
            .authorities
            .iter()
            .find(|item| item.key_id == key_id)
            .ok_or_else(|| "RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN".to_string())?;
        match authority.status {
            AuthorityStatus::Active | AuthorityStatus::Rotating => Ok(TrustedRelaySnapshotIssuer {
                key_id: authority.key_id.clone(),
                public_key: authority.public_key.clone(),
                public_identity: authority.fingerprint.clone(),
                purpose: RELAY_SNAPSHOT_ISSUER_PURPOSE.to_string(),
                status: "ACTIVE".to_string(),
            }),
            _ => Err("RELAY_TRUST_SNAPSHOT_ISSUER_UNTRUSTED".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedConnectivityTrust {
    pub trust_state: CanonicalTrustState,
    pub policy_generation: u64,
    pub trust_bundle_id: Option<String>,
    pub binding_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorityResolution {
    Valid,
    Unknown,
    Untrusted,
}

fn resolve_role_authority(
    store: &CanonicalTrustStoreViewV1,
    identity: Option<&AuthorityIdentityRef>,
    expected_kind: AuthorityKind,
) -> AuthorityResolution {
    let Some(identity) = identity else { return AuthorityResolution::Unknown; };
    if !identity.is_valid_for_role(expected_kind) {
        return AuthorityResolution::Untrusted;
    }
    if store.revocations.iter().any(|revocation| revocation.key_id == identity.key_id) {
        return AuthorityResolution::Untrusted;
    }

    let by_authority_id: Vec<&AuthorityDescriptor> = store
        .authorities
        .iter()
        .filter(|authority| authority.authority_id == identity.authority_id)
        .collect();
    let exact: Vec<&AuthorityDescriptor> = by_authority_id
        .iter()
        .copied()
        .filter(|authority| {
            authority.kind == expected_kind
                && authority.key_id == identity.key_id
                && authority.public_key == identity.public_key
                && authority.fingerprint == identity.fingerprint
        })
        .collect();
    if exact.len() > 1 {
        return AuthorityResolution::Unknown;
    }
    if let Some(authority) = exact.first() {
        return match authority.status {
            AuthorityStatus::Active | AuthorityStatus::Rotating => AuthorityResolution::Valid,
            AuthorityStatus::Retired | AuthorityStatus::Revoked => AuthorityResolution::Untrusted,
        };
    }

    // A matching key/fingerprint under another authority id is an explicit
    // identity mismatch, not an unavailable lookup.
    if by_authority_id.iter().any(|authority| {
        authority.kind == expected_kind
            || authority.key_id == identity.key_id
            || authority.fingerprint == identity.fingerprint
    }) || store.authorities.iter().any(|authority| {
        authority.key_id == identity.key_id && authority.fingerprint == identity.fingerprint
    }) {
        AuthorityResolution::Untrusted
    } else {
        AuthorityResolution::Unknown
    }
}

pub fn evaluate_canonical_connectivity_trust(
    binding: &HostBindingProjection,
    store: &CanonicalTrustStoreViewV1,
    policy: &dyn ConnectivityPolicyGenerationProvider,
    expected_binding_epoch: Option<u64>,
    now_unix: u64,
) -> Result<DerivedConnectivityTrust, String> {
    let policy_generation = policy.current_policy_generation()?;
    if expected_binding_epoch.is_some_and(|epoch| epoch != binding.binding_epoch) {
        return Err("BINDING_EPOCH_MISMATCH".to_string());
    }
    if !store.ready || store.trust_bundle_id.as_deref().unwrap_or("").trim().is_empty() {
        return Err(TRUST_STORE_UNAVAILABLE.to_string());
    }
    let trust_state = if store.expires_at.is_some_and(|expires| now_unix > expires) {
        CanonicalTrustState::Untrusted
    } else if !binding.verified {
        CanonicalTrustState::Unknown
    } else {
        match (
            resolve_role_authority(
                store,
                binding.center_authority_identity.as_ref(),
                AuthorityKind::CenterAuthority,
            ),
            resolve_role_authority(
                store,
                binding.enrollment_authority_identity.as_ref(),
                AuthorityKind::EnrollmentAuthority,
            ),
        ) {
            (AuthorityResolution::Valid, AuthorityResolution::Valid) => CanonicalTrustState::Trusted,
            (AuthorityResolution::Untrusted, _) | (_, AuthorityResolution::Untrusted) => {
                CanonicalTrustState::Untrusted
            }
            _ => CanonicalTrustState::Unknown,
        }
    };
    Ok(DerivedConnectivityTrust {
        trust_state,
        policy_generation,
        trust_bundle_id: store.trust_bundle_id.clone(),
        binding_epoch: binding.binding_epoch,
    })
}

pub fn require_trusted_connectivity(
    derived: &DerivedConnectivityTrust,
) -> Result<(), String> {
    match derived.trust_state {
        CanonicalTrustState::Trusted => Ok(()),
        CanonicalTrustState::Untrusted => Err("TRUST_REJECTED".to_string()),
        CanonicalTrustState::Unknown => Err("TRUST_UNKNOWN".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_fabric::AuthorityKind;

    fn binding() -> HostBindingProjection {
        HostBindingProjection {
            source: "enrollment_signed".into(),
            verified: true,
            client_id: Some("client-a".into()),
            organization_id: "org-a".into(),
            site_id: Some("site-a".into()),
            host_id: Some("host-a".into()),
            host_installation_id: "install-a".into(),
            deployment_id: Some("deploy-a".into()),
            binding_epoch: 7,
            center_authority_identity: Some(AuthorityIdentityRef {
                authority_id: "center-A".into(),
                kind: AuthorityKind::CenterAuthority,
                key_id: "center-key-A".into(),
                public_key: "center-public-A".into(),
                fingerprint: "center-fp-A".into(),
            }),
            enrollment_authority_identity: Some(AuthorityIdentityRef {
                authority_id: "enrollment-A".into(),
                kind: AuthorityKind::EnrollmentAuthority,
                key_id: "enrollment-key-A".into(),
                public_key: "enrollment-public-A".into(),
                fingerprint: "enrollment-fp-A".into(),
            }),
            center_key_id: "center-key-A".into(),
            center_public_key_fingerprint: "center-fp-A".into(),
        }
    }

    fn authority(
        authority_id: &str,
        kind: AuthorityKind,
        key_id: &str,
        public_key: &str,
        fingerprint: &str,
        status: AuthorityStatus,
    ) -> AuthorityDescriptor {
        AuthorityDescriptor {
            authority_id: authority_id.into(),
            kind,
            key_id: key_id.into(),
            public_key: public_key.into(),
            fingerprint: fingerprint.into(),
            algorithm: "Ed25519".into(),
            status,
            valid_from: 1,
            valid_until: None,
            issuer_authority_id: None,
            issuer_key_id: None,
            serial: "1".into(),
            version: 1,
            capabilities: vec!["authority:issue-enrollment".into()],
            certificate: None,
            created_at: 1,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    fn store(center_status: AuthorityStatus, enrollment_status: AuthorityStatus) -> CanonicalTrustStoreViewV1 {
        CanonicalTrustStoreViewV1 {
            ready: true,
            trust_bundle_id: Some("bundle-1".into()),
            trust_epoch: Some(2),
            expires_at: Some(2_000_000_000),
            authorities: vec![
                authority("center-A", AuthorityKind::CenterAuthority, "center-key-A", "center-public-A", "center-fp-A", center_status),
                authority("enrollment-A", AuthorityKind::EnrollmentAuthority, "enrollment-key-A", "enrollment-public-A", "enrollment-fp-A", enrollment_status),
            ],
            revocations: vec![],
        }
    }

    #[test]
    fn historically_verified_enrollment_plus_current_trust_is_trusted() {
        let derived = evaluate_canonical_connectivity_trust(
            &binding(),
            &store(AuthorityStatus::Active, AuthorityStatus::Active),
            &InMemoryConnectivityPolicyGeneration::new(3),
            Some(7),
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Trusted);
        assert_eq!(derived.policy_generation, 3);
        assert_eq!(derived.trust_bundle_id.as_deref(), Some("bundle-1"));
    }

    #[test]
    fn verified_enrollment_with_revoked_authority_is_not_trusted() {
        let derived = evaluate_canonical_connectivity_trust(
            &binding(),
            &store(AuthorityStatus::Revoked, AuthorityStatus::Active),
            &InMemoryConnectivityPolicyGeneration::new(3),
            None,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
        assert_eq!(
            require_trusted_connectivity(&derived).unwrap_err(),
            "TRUST_REJECTED"
        );
    }

    #[test]
    fn retired_center_authority_is_not_trusted() {
        let derived = evaluate_canonical_connectivity_trust(
            &binding(),
            &store(AuthorityStatus::Retired, AuthorityStatus::Active),
            &InMemoryConnectivityPolicyGeneration::new(3),
            None,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn trust_store_unavailable_fails_closed() {
        assert_eq!(
            evaluate_canonical_connectivity_trust(
                &binding(),
                &CanonicalTrustStoreViewV1::unavailable(),
                &InMemoryConnectivityPolicyGeneration::new(3),
                None,
                1_800_000_000,
            )
            .unwrap_err(),
            TRUST_STORE_UNAVAILABLE
        );
    }

    #[test]
    fn stale_trust_bundle_is_not_trusted() {
        let mut view = store(AuthorityStatus::Active, AuthorityStatus::Active);
        view.expires_at = Some(10);
        let derived = evaluate_canonical_connectivity_trust(
            &binding(),
            &view,
            &InMemoryConnectivityPolicyGeneration::new(3),
            None,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn binding_epoch_mismatch_is_rejected() {
        assert_eq!(
            evaluate_canonical_connectivity_trust(
                &binding(),
                &store(AuthorityStatus::Active, AuthorityStatus::Active),
                &InMemoryConnectivityPolicyGeneration::new(3),
                Some(1),
                1_800_000_000,
            )
            .unwrap_err(),
            "BINDING_EPOCH_MISMATCH"
        );
    }

    #[test]
    fn policy_generation_unavailable_is_rejected() {
        assert_eq!(
            evaluate_canonical_connectivity_trust(
                &binding(),
                &store(AuthorityStatus::Active, AuthorityStatus::Active),
                &UnavailableConnectivityPolicyGeneration,
                None,
                1_800_000_000,
            )
            .unwrap_err(),
            CONFIGURATION_UNAVAILABLE
        );
    }

    #[test]
    fn binding_verified_alone_does_not_imply_trusted() {
        assert_eq!(
            evaluate_canonical_connectivity_trust(
                &binding(),
                &CanonicalTrustStoreViewV1::unavailable(),
                &InMemoryConnectivityPolicyGeneration::new(3),
                None,
                1_800_000_000,
            )
            .unwrap_err(),
            TRUST_STORE_UNAVAILABLE
        );
    }

    #[test]
    fn center_key_with_enrollment_fingerprint_is_not_trusted() {
        let mut value = binding();
        value.center_authority_identity.as_mut().unwrap().fingerprint = "enrollment-fp-A".into();
        let derived = evaluate_canonical_connectivity_trust(&value, &store(AuthorityStatus::Active, AuthorityStatus::Active), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn enrollment_key_with_center_fingerprint_is_not_trusted() {
        let mut value = binding();
        value.enrollment_authority_identity.as_mut().unwrap().fingerprint = "center-fp-A".into();
        let derived = evaluate_canonical_connectivity_trust(&value, &store(AuthorityStatus::Active, AuthorityStatus::Active), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn retired_enrollment_authority_is_not_trusted() {
        let derived = evaluate_canonical_connectivity_trust(&binding(), &store(AuthorityStatus::Active, AuthorityStatus::Retired), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn center_role_swap_is_not_trusted() {
        let mut value = binding();
        value.center_authority_identity.as_mut().unwrap().kind = AuthorityKind::EnrollmentAuthority;
        let derived = evaluate_canonical_connectivity_trust(&value, &store(AuthorityStatus::Active, AuthorityStatus::Active), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn enrollment_role_swap_is_not_trusted() {
        let mut value = binding();
        value.enrollment_authority_identity.as_mut().unwrap().kind = AuthorityKind::CenterAuthority;
        let derived = evaluate_canonical_connectivity_trust(&value, &store(AuthorityStatus::Active, AuthorityStatus::Active), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn legacy_binding_without_explicit_role_evidence_is_unknown() {
        let mut value = binding();
        value.verified = false;
        value.center_authority_identity = None;
        value.enrollment_authority_identity = None;
        let derived = evaluate_canonical_connectivity_trust(&value, &store(AuthorityStatus::Active, AuthorityStatus::Active), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Unknown);
        assert_eq!(require_trusted_connectivity(&derived).unwrap_err(), "TRUST_UNKNOWN");
    }

    #[test]
    fn wrong_center_authority_id_is_not_trusted() {
        let mut value = binding();
        value.center_authority_identity.as_mut().unwrap().authority_id = "wrong-center".into();
        let derived = evaluate_canonical_connectivity_trust(&value, &store(AuthorityStatus::Active, AuthorityStatus::Active), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn wrong_enrollment_authority_id_is_not_trusted() {
        let mut value = binding();
        value.enrollment_authority_identity.as_mut().unwrap().authority_id = "wrong-enrollment".into();
        let derived = evaluate_canonical_connectivity_trust(&value, &store(AuthorityStatus::Active, AuthorityStatus::Active), &InMemoryConnectivityPolicyGeneration::new(3), None, 1_800_000_000).unwrap();
        assert_eq!(derived.trust_state, CanonicalTrustState::Untrusted);
    }

    #[test]
    fn canonical_issuer_resolver_rejects_same_file_independence_violations() {
        let view = store(AuthorityStatus::Active, AuthorityStatus::Active);
        let issuer = view.resolve_trusted_issuer("center-key-A").unwrap();
        assert_eq!(issuer.purpose, RELAY_SNAPSHOT_ISSUER_PURPOSE);
        assert_eq!(
            view.resolve_trusted_issuer("unknown").unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN"
        );
        let revoked = store(AuthorityStatus::Revoked, AuthorityStatus::Active);
        assert_eq!(
            revoked.resolve_trusted_issuer("center-key-A").unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_ISSUER_UNTRUSTED"
        );
        assert_eq!(
            CanonicalTrustStoreViewV1::unavailable()
                .resolve_trusted_issuer("center-key-A")
                .unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_TRUST_UNAVAILABLE"
        );
    }
}
