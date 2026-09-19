//! Relay Trust Snapshot v1.
//!
//! Relay transports public trust evidence. It does not own trust, mint
//! authority, or decrypt product payloads. Snapshots contain no secrets.

use crate::canonical_json;
use crate::canonical_scope::CanonicalConnectivityScopeV1;
use crate::AttestationSigner;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const RELAY_TRUST_SNAPSHOT_CONTRACT: &str = "actium.connectivity.relay-trust-snapshot.v1";
pub const RELAY_TRUST_SNAPSHOT_DOMAIN: &str = "actium.connectivity.relay-trust-snapshot.v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalTrustState {
    Trusted,
    Untrusted,
    Unknown,
}

impl CanonicalTrustState {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "TRUSTED" | "AUTHORIZED" | "ENROLLED" => Self::Trusted,
            "UNTRUSTED" | "UNAUTHORIZED" | "REVOKED" => Self::Untrusted,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Untrusted => "UNTRUSTED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrustSnapshotUnsignedV1 {
    pub contract: String,
    pub snapshot_id: String,
    pub relay_identity: String,
    pub scope: CanonicalConnectivityScopeV1,
    pub trust_state: CanonicalTrustState,
    pub binding_epoch: u64,
    pub policy_generation: u64,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub nonce: String,
    pub issuer_public_identity: String,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayTrustSnapshotV1 {
    #[serde(flatten)]
    pub body: RelayTrustSnapshotUnsignedV1,
    pub payload_digest: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalHostTrust {
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub key_id: String,
    pub fingerprint: String,
    pub public_key: String,
    pub binding_epoch: u64,
    pub policy_generation: u64,
    pub trust_state: CanonicalTrustState,
    pub snapshot_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustedRelaySnapshotIssuer {
    pub key_id: String,
    pub public_key: String,
    pub public_identity: String,
    pub purpose: String,
    pub status: String,
}

pub const RELAY_SNAPSHOT_ISSUER_PURPOSE: &str = "relay_trust_snapshot";

pub trait TrustedRelaySnapshotIssuerResolver {
    fn resolve_trusted_issuer(&self, key_id: &str) -> Result<TrustedRelaySnapshotIssuer, String>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryTrustedIssuerResolver {
    issuers: Vec<TrustedRelaySnapshotIssuer>,
}

impl InMemoryTrustedIssuerResolver {
    pub fn new(issuers: Vec<TrustedRelaySnapshotIssuer>) -> Self {
        Self { issuers }
    }
}

impl TrustedRelaySnapshotIssuerResolver for InMemoryTrustedIssuerResolver {
    fn resolve_trusted_issuer(&self, key_id: &str) -> Result<TrustedRelaySnapshotIssuer, String> {
        let key_id = key_id.trim();
        if key_id.is_empty() {
            return Err("RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN".to_string());
        }
        let matches: Vec<_> = self
            .issuers
            .iter()
            .filter(|issuer| issuer.key_id == key_id)
            .cloned()
            .collect();
        match matches.len() {
            0 => Err("RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN".to_string()),
            1 => {
                let issuer = matches.into_iter().next().unwrap();
                if issuer.purpose != RELAY_SNAPSHOT_ISSUER_PURPOSE {
                    return Err("RELAY_TRUST_SNAPSHOT_ISSUER_PURPOSE_INVALID".to_string());
                }
                match issuer.status.to_ascii_uppercase().as_str() {
                    "ACTIVE" | "TRUSTED" => Ok(issuer),
                    "REVOKED" | "UNTRUSTED" | "RETIRED" => {
                        Err("RELAY_TRUST_SNAPSHOT_ISSUER_UNTRUSTED".to_string())
                    }
                    _ => Err("RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN".to_string()),
                }
            }
            _ => Err("RELAY_TRUST_SNAPSHOT_ISSUER_AMBIGUOUS".to_string()),
        }
    }
}

pub struct UnavailableTrustedIssuerResolver;

impl TrustedRelaySnapshotIssuerResolver for UnavailableTrustedIssuerResolver {
    fn resolve_trusted_issuer(&self, _key_id: &str) -> Result<TrustedRelaySnapshotIssuer, String> {
        Err("RELAY_TRUST_SNAPSHOT_TRUST_UNAVAILABLE".to_string())
    }
}

pub trait RelayTrustProvider {
    fn resolve_canonical_host_scope(
        &self,
        scope: &CanonicalConnectivityScopeV1,
    ) -> Result<Option<CanonicalHostTrust>, String>;
}

#[derive(Debug, Clone)]
pub struct SnapshotRelayTrustProvider {
    hosts: Vec<CanonicalHostTrust>,
}

impl SnapshotRelayTrustProvider {
    pub fn from_verified_snapshots(snapshots: Vec<RelayTrustSnapshotV1>) -> Result<Self, String> {
        let mut hosts = Vec::new();
        for snapshot in snapshots {
            snapshot.body.scope.validate()?;
            let host = CanonicalHostTrust {
                client_id: snapshot.body.scope.client_id.clone(),
                organization_id: snapshot.body.scope.organization_id.clone(),
                site_id: snapshot.body.scope.site_id.clone(),
                host_id: snapshot.body.scope.host_id.clone(),
                key_id: snapshot.body.issuer_key_id.clone(),
                fingerprint: snapshot.body.issuer_public_identity.clone(),
                public_key: snapshot.body.issuer_public_key.clone(),
                binding_epoch: snapshot.body.binding_epoch,
                policy_generation: snapshot.body.policy_generation,
                trust_state: snapshot.body.trust_state,
                snapshot_id: snapshot.body.snapshot_id.clone(),
            };
            if hosts.iter().any(|existing: &CanonicalHostTrust| {
                existing.client_id == host.client_id
                    && existing.organization_id == host.organization_id
                    && existing.site_id == host.site_id
                    && existing.host_id == host.host_id
            }) {
                return Err("R3_CLIENT_SCOPE_RESOLUTION_AMBIGUOUS".to_string());
            }
            hosts.push(host);
        }
        Ok(Self { hosts })
    }
}

impl RelayTrustProvider for SnapshotRelayTrustProvider {
    fn resolve_canonical_host_scope(
        &self,
        scope: &CanonicalConnectivityScopeV1,
    ) -> Result<Option<CanonicalHostTrust>, String> {
        scope.validate()?;
        let matches: Vec<_> = self
            .hosts
            .iter()
            .filter(|host| {
                host.client_id == scope.client_id
                    && host.organization_id == scope.organization_id
                    && host.site_id == scope.site_id
                    && host.host_id == scope.host_id
            })
            .cloned()
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(matches.into_iter().next().unwrap())),
            _ => Err("R3_CLIENT_SCOPE_RESOLUTION_AMBIGUOUS".to_string()),
        }
    }
}

pub struct UnavailableRelayTrustProvider;

impl RelayTrustProvider for UnavailableRelayTrustProvider {
    fn resolve_canonical_host_scope(
        &self,
        _scope: &CanonicalConnectivityScopeV1,
    ) -> Result<Option<CanonicalHostTrust>, String> {
        Err("R3_CLIENT_SCOPE_RESOLUTION_BLOCKED".to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayTrustSnapshotSignIntentV1 {
    pub relay_identity: String,
    pub nonce: String,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

pub fn snapshot_payload_digest(body: &RelayTrustSnapshotUnsignedV1) -> Result<String, String> {
    let canonical = canonical_json(&serde_json::to_value(body).map_err(|error| error.to_string())?)?;
    Ok(format!("sha256:{}", hex_lower(&Sha256::digest(canonical.as_bytes()))))
}

pub fn publish_relay_trust_snapshot(
    signer: &AttestationSigner,
    mut body: RelayTrustSnapshotUnsignedV1,
) -> Result<RelayTrustSnapshotV1, String> {
    body.scope.validate()?;
    if body.contract != RELAY_TRUST_SNAPSHOT_CONTRACT {
        return Err("RELAY_TRUST_SNAPSHOT_CONTRACT_INVALID".to_string());
    }
    if body.relay_identity.trim().is_empty()
        || body.snapshot_id.trim().is_empty()
        || body.nonce.trim().is_empty()
    {
        return Err("RELAY_TRUST_SNAPSHOT_INVALID".to_string());
    }
    if body.not_after_unix <= body.not_before_unix {
        return Err("RELAY_TRUST_SNAPSHOT_VALIDITY_INVALID".to_string());
    }
    if body.binding_epoch != body.scope.binding_epoch
        || body.policy_generation != body.scope.policy_generation
    {
        return Err("RELAY_TRUST_SNAPSHOT_EPOCH_INVALID".to_string());
    }
    body.issuer_key_id = signer.key_id();
    body.issuer_public_key = signer.public_key();
    body.issuer_public_identity = public_identity_from_key(&body.issuer_public_key)?;
    let payload_digest = snapshot_payload_digest(&body)?;
    let signature = signer.sign_domain_separated(
        RELAY_TRUST_SNAPSHOT_DOMAIN,
        &serde_json::to_value(&body).map_err(|error| error.to_string())?,
    )?;
    Ok(RelayTrustSnapshotV1 {
        body,
        payload_digest,
        signature,
    })
}

pub fn derive_relay_trust_snapshot(
    signer: &AttestationSigner,
    binding: &crate::HostBindingProjection,
    intent: &RelayTrustSnapshotSignIntentV1,
    policy_generation: u64,
    trust_state: CanonicalTrustState,
    now_unix: u64,
) -> Result<RelayTrustSnapshotV1, String> {
    let scope = CanonicalConnectivityScopeV1::from_binding(binding, policy_generation)?;
    if intent.relay_identity.trim().is_empty() || intent.nonce.trim().is_empty() {
        return Err("RELAY_TRUST_SNAPSHOT_INTENT_INVALID".to_string());
    }
    if intent.not_after_unix <= intent.not_before_unix || intent.not_after_unix <= now_unix {
        return Err("RELAY_TRUST_SNAPSHOT_VALIDITY_INVALID".to_string());
    }
    let body = RelayTrustSnapshotUnsignedV1 {
        contract: RELAY_TRUST_SNAPSHOT_CONTRACT.to_string(),
        snapshot_id: intent
            .snapshot_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("snap-{}", intent.nonce)),
        relay_identity: intent.relay_identity.trim().to_string(),
        scope,
        trust_state,
        binding_epoch: binding.binding_epoch,
        policy_generation,
        not_before_unix: intent.not_before_unix,
        not_after_unix: intent.not_after_unix,
        nonce: intent.nonce.trim().to_string(),
        issuer_public_identity: String::new(),
        issuer_key_id: String::new(),
        issuer_public_key: String::new(),
    };
    publish_relay_trust_snapshot(signer, body)
}

#[derive(Debug, Default)]
pub struct RelayTrustSnapshotVerifier {
    seen_nonces: BTreeSet<String>,
    max_clock_skew_secs: u64,
}

impl RelayTrustSnapshotVerifier {
    pub fn new(max_clock_skew_secs: u64) -> Self {
        Self {
            seen_nonces: BTreeSet::new(),
            max_clock_skew_secs,
        }
    }

    pub fn verify(
        &mut self,
        snapshot: &RelayTrustSnapshotV1,
        now_unix: u64,
        issuer_resolver: &dyn TrustedRelaySnapshotIssuerResolver,
    ) -> Result<CanonicalHostTrust, String> {
        snapshot.body.scope.validate()?;
        if snapshot.body.contract != RELAY_TRUST_SNAPSHOT_CONTRACT {
            return Err("RELAY_TRUST_SNAPSHOT_CONTRACT_INVALID".to_string());
        }
        let expected_digest = snapshot_payload_digest(&snapshot.body)?;
        if snapshot.payload_digest != expected_digest {
            return Err("RELAY_TRUST_SNAPSHOT_DIGEST_MISMATCH".to_string());
        }
        let trusted_issuer = issuer_resolver.resolve_trusted_issuer(&snapshot.body.issuer_key_id)?;
        if trusted_issuer.public_key != snapshot.body.issuer_public_key
            || trusted_issuer.public_identity != snapshot.body.issuer_public_identity
            || trusted_issuer.key_id != snapshot.body.issuer_key_id
        {
            return Err("RELAY_TRUST_SNAPSHOT_ISSUER_MISMATCH".to_string());
        }
        let expected_identity = public_identity_from_key(&trusted_issuer.public_key)?;
        if snapshot.body.issuer_public_identity != expected_identity
            || trusted_issuer.public_identity != expected_identity
        {
            return Err("RELAY_TRUST_SNAPSHOT_ISSUER_MISMATCH".to_string());
        }
        verify_snapshot_signature_with_key(snapshot, &trusted_issuer.public_key)?;
        if now_unix + self.max_clock_skew_secs < snapshot.body.not_before_unix {
            return Err("RELAY_TRUST_SNAPSHOT_NOT_YET_VALID".to_string());
        }
        if now_unix > snapshot.body.not_after_unix + self.max_clock_skew_secs {
            return Err("RELAY_TRUST_SNAPSHOT_STALE".to_string());
        }
        if snapshot.body.nonce.trim().is_empty() {
            return Err("RELAY_TRUST_SNAPSHOT_NONCE_INVALID".to_string());
        }
        if !self.seen_nonces.insert(snapshot.body.nonce.clone()) {
            return Err("RELAY_TRUST_SNAPSHOT_NONCE_REPLAY".to_string());
        }
        if snapshot.body.trust_state != CanonicalTrustState::Trusted {
            return Err(match snapshot.body.trust_state {
                CanonicalTrustState::Unknown => "TRUST_UNKNOWN".to_string(),
                _ => "TRUST_REJECTED".to_string(),
            });
        }
        Ok(CanonicalHostTrust {
            host_id: snapshot.body.scope.host_id.clone(),
            site_id: snapshot.body.scope.site_id.clone(),
            client_id: snapshot.body.scope.client_id.clone(),
            organization_id: snapshot.body.scope.organization_id.clone(),
            key_id: snapshot.body.issuer_key_id.clone(),
            fingerprint: snapshot.body.issuer_public_identity.clone(),
            public_key: snapshot.body.issuer_public_key.clone(),
            binding_epoch: snapshot.body.binding_epoch,
            policy_generation: snapshot.body.policy_generation,
            trust_state: snapshot.body.trust_state,
            snapshot_id: snapshot.body.snapshot_id.clone(),
        })
    }
}

fn verify_snapshot_signature_with_key(
    snapshot: &RelayTrustSnapshotV1,
    public_key: &str,
) -> Result<(), String> {
    let raw = URL_SAFE_NO_PAD
        .decode(public_key.trim())
        .map_err(|_| "RELAY_TRUST_SNAPSHOT_ISSUER_KEY_INVALID".to_string())?;
    let key_bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "RELAY_TRUST_SNAPSHOT_ISSUER_KEY_INVALID".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| "RELAY_TRUST_SNAPSHOT_ISSUER_KEY_INVALID".to_string())?;
    let payload = serde_json::to_value(&snapshot.body).map_err(|error| error.to_string())?;
    let canonical = crate::domain_separated_canonical(RELAY_TRUST_SNAPSHOT_DOMAIN, &payload)?;
    let signature_raw = URL_SAFE_NO_PAD
        .decode(snapshot.signature.trim())
        .map_err(|_| "RELAY_TRUST_SNAPSHOT_SIGNATURE_INVALID".to_string())?;
    let signature = Signature::from_slice(&signature_raw)
        .map_err(|_| "RELAY_TRUST_SNAPSHOT_SIGNATURE_INVALID".to_string())?;
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| "RELAY_TRUST_SNAPSHOT_SIGNATURE_INVALID".to_string())
}

fn public_identity_from_key(public_key: &str) -> Result<String, String> {
    let raw = URL_SAFE_NO_PAD
        .decode(public_key.trim())
        .map_err(|_| "RELAY_TRUST_SNAPSHOT_ISSUER_KEY_INVALID".to_string())?;
    if raw.len() != 32 {
        return Err("RELAY_TRUST_SNAPSHOT_ISSUER_KEY_INVALID".to_string());
    }
    Ok(format!("sha256:{}", hex_lower(&Sha256::digest(raw))))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn snapshot_from_value(value: &Value) -> Result<RelayTrustSnapshotV1, String> {
    serde_json::from_value(value.clone()).map_err(|error| format!("RELAY_TRUST_SNAPSHOT_INVALID:{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_scope::CanonicalConnectivityScopeV1;
    use crate::HostBindingProjection;
    use std::time::{SystemTime, UNIX_EPOCH};

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
            center_authority_identity: None,
            enrollment_authority_identity: None,
            center_key_id: "kid".into(),
            center_public_key_fingerprint: "sha256:abc".into(),
        }
    }

    fn unsigned() -> RelayTrustSnapshotUnsignedV1 {
        let scope = CanonicalConnectivityScopeV1::from_binding(&binding(), 3).unwrap();
        RelayTrustSnapshotUnsignedV1 {
            contract: RELAY_TRUST_SNAPSHOT_CONTRACT.into(),
            snapshot_id: "snap-1".into(),
            relay_identity: "relay-lab-01".into(),
            scope,
            trust_state: CanonicalTrustState::Trusted,
            binding_epoch: 7,
            policy_generation: 3,
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_893_456_000,
            nonce: "nonce-1".into(),
            issuer_public_identity: String::new(),
            issuer_key_id: String::new(),
            issuer_public_key: String::new(),
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or(1_800_000_000)
    }

    fn resolver_for(signer: &AttestationSigner) -> InMemoryTrustedIssuerResolver {
        InMemoryTrustedIssuerResolver::new(vec![TrustedRelaySnapshotIssuer {
            key_id: signer.key_id(),
            public_key: signer.public_key(),
            public_identity: public_identity_from_key(&signer.public_key()).unwrap(),
            purpose: RELAY_SNAPSHOT_ISSUER_PURPOSE.into(),
            status: "ACTIVE".into(),
        }])
    }

    #[test]
    fn publisher_emits_public_snapshot_without_private_material() {
        let dir = std::env::temp_dir().join(format!("actium-r3-snap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let snapshot = publish_relay_trust_snapshot(&signer, unsigned()).unwrap();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(!encoded.to_ascii_lowercase().contains("private"));
        assert!(!encoded.contains("BEGIN"));
        assert_eq!(snapshot.body.issuer_key_id, signer.key_id());
        assert_eq!(snapshot.payload_digest, snapshot_payload_digest(&snapshot.body).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn verifier_accepts_valid_and_rejects_replay_stale_and_bad_signature() {
        let dir = std::env::temp_dir().join(format!("actium-r3-verify-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let snapshot = publish_relay_trust_snapshot(&signer, unsigned()).unwrap();
        let issuers = resolver_for(&signer);
        let mut verifier = RelayTrustSnapshotVerifier::new(60);
        assert_eq!(
            verifier.verify(&snapshot, now(), &issuers).unwrap().host_id,
            "host-a"
        );
        assert_eq!(
            verifier.verify(&snapshot, now(), &issuers).unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_NONCE_REPLAY"
        );

        let mut stale = snapshot.clone();
        stale.body.nonce = "nonce-stale".into();
        stale.body.not_after_unix = 10;
        stale.payload_digest = snapshot_payload_digest(&stale.body).unwrap();
        stale.signature = signer
            .sign_domain_separated(
                RELAY_TRUST_SNAPSHOT_DOMAIN,
                &serde_json::to_value(&stale.body).unwrap(),
            )
            .unwrap();
        let mut stale_verifier = RelayTrustSnapshotVerifier::new(0);
        assert_eq!(
            stale_verifier.verify(&stale, 1_800_000_000, &issuers).unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_STALE"
        );

        let mut bad_sig = snapshot.clone();
        bad_sig.body.nonce = "nonce-bad-sig".into();
        bad_sig.payload_digest = snapshot_payload_digest(&bad_sig.body).unwrap();
        bad_sig.signature = snapshot.signature.clone();
        let mut sig_verifier = RelayTrustSnapshotVerifier::new(60);
        assert_eq!(
            sig_verifier.verify(&bad_sig, now(), &issuers).unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_SIGNATURE_INVALID"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn revoked_and_unknown_never_become_trusted() {
        assert_eq!(CanonicalTrustState::parse("REVOKED"), CanonicalTrustState::Untrusted);
        assert_eq!(CanonicalTrustState::parse("UNKNOWN"), CanonicalTrustState::Unknown);
        assert_ne!(CanonicalTrustState::parse("REVOKED"), CanonicalTrustState::Trusted);
        let dir = std::env::temp_dir().join(format!("actium-r3-revoked-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let mut body = unsigned();
        body.trust_state = CanonicalTrustState::Untrusted;
        body.nonce = "nonce-revoked".into();
        let snapshot = publish_relay_trust_snapshot(&signer, body).unwrap();
        let mut verifier = RelayTrustSnapshotVerifier::new(60);
        assert_eq!(
            verifier.verify(&snapshot, now(), &resolver_for(&signer)).unwrap_err(),
            "TRUST_REJECTED"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_provider_and_unknown_issuer_fail_closed() {
        let provider = UnavailableRelayTrustProvider;
        let scope = CanonicalConnectivityScopeV1::from_binding(&binding(), 3).unwrap();
        assert_eq!(
            provider.resolve_canonical_host_scope(&scope).unwrap_err(),
            "R3_CLIENT_SCOPE_RESOLUTION_BLOCKED"
        );
        let dir = std::env::temp_dir().join(format!("actium-r3-rogue-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let snapshot = publish_relay_trust_snapshot(&signer, unsigned()).unwrap();
        let mut verifier = RelayTrustSnapshotVerifier::new(60);
        assert_eq!(
            verifier
                .verify(&snapshot, now(), &UnavailableTrustedIssuerResolver)
                .unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_TRUST_UNAVAILABLE"
        );
        assert_eq!(
            verifier
                .verify(&snapshot, now(), &InMemoryTrustedIssuerResolver::default())
                .unwrap_err(),
            "RELAY_TRUST_SNAPSHOT_ISSUER_UNKNOWN"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn supervisor_derives_trust_and_ignores_caller_trust_fields() {
        let dir = std::env::temp_dir().join(format!("actium-r3-derive-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let intent = RelayTrustSnapshotSignIntentV1 {
            relay_identity: "relay-lab-01".into(),
            nonce: "intent-nonce".into(),
            not_before_unix: 1_700_000_000,
            not_after_unix: 1_893_456_000,
            snapshot_id: None,
        };
        let snapshot = derive_relay_trust_snapshot(
            &signer,
            &binding(),
            &intent,
            3,
            CanonicalTrustState::Trusted,
            1_800_000_000,
        )
        .unwrap();
        assert_eq!(snapshot.body.trust_state, CanonicalTrustState::Trusted);
        assert_eq!(snapshot.body.binding_epoch, 7);
        assert_eq!(snapshot.body.policy_generation, 3);
        assert_eq!(snapshot.body.scope.client_id, "client-a");
        assert_eq!(snapshot.body.scope.organization_id, "org-a");
        let _ = std::fs::remove_dir_all(dir);
    }
}
