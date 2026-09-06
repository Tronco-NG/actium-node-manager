//! Bootstrap chain for offline Actium authority. Runtime never creates Root or
//! Center authority keys; test fixtures may create ephemeral keys only.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct SignedEnvelope { pub payload:String, pub signature:String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct CenterAuthorityBundle {
    pub issuer_id:String,
    pub kid:String,
    pub center_public_key:String,
    pub issued_at:u64,
    pub expires_at:u64,
    pub binding_epoch:u64,
    /// Digest of the public Trust Bundle used to authorize this package.
    /// Optional for compatibility with pre-M4 fixtures; new ceremonies set it.
    #[serde(default)]
    pub trust_bundle_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct EnrollmentPackage { pub issuer_id:String, pub kid:String, pub host_installation_id:String, pub enrollment_nonce:String, pub node_public_key:String, #[serde(default)] pub supervisor_public_key:Option<String>, #[serde(default)] pub client_id:Option<String>, pub organization_id:String, #[serde(default)] pub site_id:Option<String>, #[serde(default)] pub host_id:Option<String>, #[serde(default)] pub deployment_id:Option<String>, pub binding_epoch:u64, pub expires_at:u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct EnrolledAuthority { pub center:CenterAuthorityBundle, pub enrollment:EnrollmentPackage }

/// Signed Supervisor/Enrollment projection used by the Manager infrastructure
/// page.  It is deliberately read-only metadata and never derives Host scope
/// from Storage grants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct HostBindingProjection {
    pub source: String,
    pub verified: bool,
    pub client_id: Option<String>,
    pub organization_id: String,
    pub site_id: Option<String>,
    pub host_id: Option<String>,
    pub host_installation_id: String,
    pub deployment_id: Option<String>,
    pub binding_epoch: u64,
    pub center_key_id: String,
    pub center_public_key_fingerprint: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case", deny_unknown_fields)]
pub struct StorageApprovalClaims {
    pub iss:String,pub sub:String,pub jti:String,pub aud:String,pub organization_id:String,
    #[serde(default)] pub client_id:Option<String>,
    #[serde(default)] pub site_id:Option<String>,
    #[serde(default)] pub host_id:Option<String>,
    #[serde(default)] pub host_installation_id:Option<String>,
    pub action:String,pub intent_id:String,pub deployment_id:String,pub capability:String,
    pub canonical_mountpoint:String,pub canonical_path:String,
    #[serde(default)] pub subpath:String,
    #[serde(default)] pub filesystem:String,
    pub filesystem_uuid:String,
    pub policy_hash:String,pub binding_epoch:u64,pub iat:u64,pub nbf:u64,pub exp:u64
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct EnrollmentProofClaims {
    pub schema_version: u8,
    pub purpose: String,
    pub ticket_hash: String,
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_installation_id: String,
    pub supervisor_public_key: String,
    pub binding_epoch: u64,
    pub nonce: String,
    pub environment: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct EnrollmentAckClaims {
    pub schema_version: u8,
    pub purpose: String,
    pub ticket_hash: String,
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_installation_id: String,
    pub supervisor_public_key: String,
    pub supervisor_key_id: String,
    pub binding_epoch: u64,
    pub enrollment_nonce: String,
    pub package_digest: String,
    pub applied_at: u64,
    pub status: String,
}

pub fn center_public_key_fingerprint(public_key: &str) -> Result<String, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(public_key)
        .map_err(|_| "AUTHORITY_KEY_INVALID")?;
    if bytes.len() != 32 {
        return Err("AUTHORITY_KEY_INVALID".into());
    }
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{}", hex_lower(&digest)))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

impl EnrolledAuthority {
    pub fn host_binding(&self) -> Result<HostBindingProjection, String> {
        Ok(HostBindingProjection {
            source: "enrollment_signed".into(),
            verified: true,
            client_id: self.enrollment.client_id.clone(),
            organization_id: self.enrollment.organization_id.clone(),
            site_id: self.enrollment.site_id.clone(),
            host_id: self.enrollment.host_id.clone(),
            host_installation_id: self.enrollment.host_installation_id.clone(),
            deployment_id: self.enrollment.deployment_id.clone(),
            binding_epoch: self.enrollment.binding_epoch,
            center_key_id: self.center.kid.clone(),
            center_public_key_fingerprint: center_public_key_fingerprint(&self.center.center_public_key)?,
        })
    }
}

fn verify(key:&str, envelope:&SignedEnvelope)->Result<Vec<u8>,String>{let raw=URL_SAFE_NO_PAD.decode(key).map_err(|_|"AUTHORITY_KEY_INVALID")?;let vk=VerifyingKey::from_bytes(raw.as_slice().try_into().map_err(|_|"AUTHORITY_KEY_INVALID")?).map_err(|_|"AUTHORITY_KEY_INVALID")?;let payload=URL_SAFE_NO_PAD.decode(&envelope.payload).map_err(|_|"AUTHORITY_ENVELOPE_INVALID")?;let sig=Signature::from_slice(&URL_SAFE_NO_PAD.decode(&envelope.signature).map_err(|_|"AUTHORITY_SIGNATURE_INVALID")?).map_err(|_|"AUTHORITY_SIGNATURE_INVALID")?;vk.verify(&payload,&sig).map_err(|_|"AUTHORITY_SIGNATURE_INVALID")?;Ok(payload)}
fn enroll_verified(root_public_key:&str, center_envelope:&SignedEnvelope, enrollment_envelope:&SignedEnvelope, expected_host:&str, expected_nonce:&str, node_public_key:&str, now:u64)->Result<EnrolledAuthority,String>{let center:CenterAuthorityBundle=serde_json::from_slice(&verify(root_public_key,center_envelope)?).map_err(|_|"CENTER_BUNDLE_INVALID")?;if center.expires_at<=now{return Err("CENTER_BUNDLE_EXPIRED".into())};let enrollment:EnrollmentPackage=serde_json::from_slice(&verify(&center.center_public_key,enrollment_envelope)?).map_err(|_|"ENROLLMENT_PACKAGE_INVALID")?;if enrollment.issuer_id!=center.issuer_id||enrollment.kid!=center.kid||enrollment.expires_at<=now{return Err("ENROLLMENT_UNTRUSTED_OR_EXPIRED".into())};if enrollment.host_installation_id!=expected_host||enrollment.enrollment_nonce!=expected_nonce||enrollment.node_public_key!=node_public_key{return Err("ENROLLMENT_BINDING_MISMATCH".into())};if enrollment.binding_epoch!=center.binding_epoch{return Err("ENROLLMENT_EPOCH_MISMATCH".into())};Ok(EnrolledAuthority{center,enrollment})}
pub fn enroll(root_public_key:&str, center_envelope:&SignedEnvelope, enrollment_envelope:&SignedEnvelope, expected_host:&str, expected_nonce:&str, node_public_key:&str, now:u64)->Result<EnrolledAuthority,String>{enroll_verified(root_public_key,center_envelope,enrollment_envelope,expected_host,expected_nonce,node_public_key,now)}

pub fn verify_enrollment_proof(proof: &SignedEnvelope, supervisor_public_key: &str, expected: &EnrollmentProofClaims, now: u64) -> Result<(), String> {
    let claims: EnrollmentProofClaims = serde_json::from_slice(&verify(supervisor_public_key, proof)?).map_err(|_| "ENROLLMENT_PROOF_INVALID")?;
    if claims != *expected { return Err("ENROLLMENT_PROOF_SCOPE_INVALID".into()); }
    if claims.purpose != "HOST_ENROLL" { return Err("ENROLLMENT_PROOF_PURPOSE_INVALID".into()); }
    if claims.expires_at <= now || claims.issued_at > now + 60 || claims.expires_at > claims.issued_at + 300 { return Err("ENROLLMENT_PROOF_EXPIRED".into()); }
    Ok(())
}

pub fn enroll_with_proof(root_public_key:&str, center_envelope:&SignedEnvelope, enrollment_envelope:&SignedEnvelope, proof:&SignedEnvelope, expected_host:&str, expected_nonce:&str, node_public_key:&str, expected_proof:&EnrollmentProofClaims, now:u64)->Result<EnrolledAuthority,String>{
    verify_enrollment_proof(proof, node_public_key, expected_proof, now)?;
    let enrolled = enroll_verified(root_public_key, center_envelope, enrollment_envelope, expected_host, expected_nonce, node_public_key, now)?;
    if enrolled.enrollment.supervisor_public_key.as_deref().is_some_and(|key| key != node_public_key) { return Err("ENROLLMENT_PROOF_KEY_MISMATCH".into()); }
    Ok(enrolled)
}

/// Trust Fabric enrollment path. Authority selection comes from the verified
/// public Trust Bundle held by Supervisor; no root key environment variable is
/// consulted and no private material crosses this boundary.
pub fn enroll_with_trust_bundle(trust_bundle:&crate::SignedTrustBundle, center_envelope:&SignedEnvelope, enrollment_envelope:&SignedEnvelope, proof:&SignedEnvelope, expected_host:&str, expected_nonce:&str, node_public_key:&str, expected_proof:&EnrollmentProofClaims, now:u64)->Result<EnrolledAuthority,String>{
    verify_enrollment_proof(proof, node_public_key, expected_proof, now)?;
    let center_payload = decode_payload(center_envelope, "CENTER_BUNDLE_INVALID")?;
    let center:CenterAuthorityBundle = serde_json::from_slice(&center_payload).map_err(|_|"CENTER_BUNDLE_INVALID")?;
    if center.expires_at<=now{return Err("CENTER_BUNDLE_EXPIRED".into())};
    let center_authority = trust_bundle.bundle.center_authority.as_ref().filter(|authority| authority.authority_id == center.issuer_id && authority.key_id == center.kid && authority.kind == crate::AuthorityKind::CenterAuthority && authority.status == crate::AuthorityStatus::Active).ok_or("CENTER_AUTHORITY_UNTRUSTED")?;
    verify(center_authority.public_key.as_str(), center_envelope)?;
    let enrollment_payload = decode_payload(enrollment_envelope, "ENROLLMENT_PACKAGE_INVALID")?;
    let enrollment:EnrollmentPackage = serde_json::from_slice(&enrollment_payload).map_err(|_|"ENROLLMENT_PACKAGE_INVALID")?;
    let enrollment_authority = trust_bundle.bundle.enrollment_authorities.iter().find(|authority| authority.authority_id == enrollment.issuer_id && authority.key_id == enrollment.kid && authority.kind == crate::AuthorityKind::EnrollmentAuthority && authority.status == crate::AuthorityStatus::Active).ok_or("ENROLLMENT_AUTHORITY_UNTRUSTED")?;
    verify(enrollment_authority.public_key.as_str(), enrollment_envelope)?;
    if enrollment.expires_at<=now{return Err("ENROLLMENT_UNTRUSTED_OR_EXPIRED".into())};
    if enrollment.host_installation_id!=expected_host||enrollment.enrollment_nonce!=expected_nonce||enrollment.node_public_key!=node_public_key{return Err("ENROLLMENT_BINDING_MISMATCH".into())};
    if enrollment.binding_epoch!=center.binding_epoch{return Err("ENROLLMENT_EPOCH_MISMATCH".into())};
    if center.center_public_key != enrollment_authority.public_key { return Err("ENROLLMENT_AUTHORITY_KEY_MISMATCH".into()); }
    if let Some(expected_digest) = center.trust_bundle_digest.as_deref() {
        if crate::trust_bundle_digest(&trust_bundle.bundle)? != expected_digest { return Err("ENROLLMENT_TRUST_BUNDLE_MISMATCH".into()); }
    }
    Ok(EnrolledAuthority{center,enrollment})
}

fn decode_payload(envelope:&SignedEnvelope, error:&str)->Result<Vec<u8>,String>{URL_SAFE_NO_PAD.decode(&envelope.payload).map_err(|_|error.to_string())}

pub fn signed_envelope_digest(envelope: &SignedEnvelope) -> Result<String, String> {
    let value = serde_json::to_value(envelope).map_err(|_| "AUTHORITY_ENVELOPE_INVALID")?;
    let canonical = crate::canonical_json(&value)?;
    Ok(hex_lower(&Sha256::digest(canonical.as_bytes())))
}

pub fn verify_enrollment_ack(ack: &SignedEnvelope, supervisor_public_key: &str, expected: &EnrollmentAckClaims, now: u64) -> Result<(), String> {
    let claims: EnrollmentAckClaims = serde_json::from_slice(&verify(supervisor_public_key, ack)?).map_err(|_| "ENROLLMENT_ACK_INVALID")?;
    if claims != *expected { return Err("ENROLLMENT_ACK_SCOPE_INVALID".into()); }
    if claims.purpose != "HOST_ENROLL_ACK" || claims.status != "applied" || claims.applied_at > now + 60 {
        return Err("ENROLLMENT_ACK_INVALID".into());
    }
    Ok(())
}
pub fn verify_storage_approval(center_public_key:&str,enrolled:&EnrolledAuthority,envelope:&SignedEnvelope,expected:&crate::StorageGrantPreflight,consumed:&[String],now:u64)->Result<StorageApprovalClaims,String>{
    let c:StorageApprovalClaims=serde_json::from_slice(&verify(center_public_key,envelope)?).map_err(|_|"STORAGE_APPROVAL_INVALID")?;
    if c.iss!=enrolled.center.issuer_id||c.aud!=enrolled.enrollment.host_installation_id||c.organization_id!=enrolled.enrollment.organization_id||c.action!="storage_grant_approve"||c.binding_epoch!=enrolled.center.binding_epoch{return Err("STORAGE_APPROVAL_SCOPE_INVALID".into())};
    if c.subpath.trim().is_empty() || c.filesystem.trim().is_empty() || expected.subpath.trim().is_empty() || expected.filesystem.trim().is_empty() { return Err("STORAGE_APPROVAL_SCOPE_INVALID".into()); }
    if c.exp<=now||c.nbf>now||c.exp>c.iat+600{return Err("STORAGE_APPROVAL_EXPIRED".into())};
    if consumed.iter().any(|v|v==&c.jti||v==&c.intent_id){return Err("STORAGE_APPROVAL_REPLAY".into())};
    if c.intent_id!=expected.intent_id||c.deployment_id!=expected.deployment_id||c.capability!=expected.capability||c.canonical_mountpoint!=expected.canonical_mountpoint||c.canonical_path!=expected.canonical_path||c.subpath!=expected.subpath||c.filesystem!=expected.filesystem||c.filesystem_uuid!=expected.filesystem_uuid||c.policy_hash!=expected.policy_hash{return Err("STORAGE_APPROVAL_INTENT_MISMATCH".into())};
    if expected.client_id.as_ref().is_some_and(|v| c.client_id.as_ref()!=Some(v))
        || expected.site_id.as_ref().is_some_and(|v| c.site_id.as_ref()!=Some(v))
        || expected.host_id.as_ref().is_some_and(|v| c.host_id.as_ref()!=Some(v))
        || expected.host_installation_id.as_ref().is_some_and(|v| c.host_installation_id.as_ref()!=Some(v))
    { return Err("STORAGE_APPROVAL_SCOPE_INVALID".into()); }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StorageGrantPreflight;
    use crate::KeyProvider;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn sign<T: Serialize>(key: &SigningKey, value: &T) -> SignedEnvelope {
        let bytes = serde_json::to_vec(value).unwrap();
        SignedEnvelope {
            payload: URL_SAFE_NO_PAD.encode(&bytes),
            signature: URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()),
        }
    }

    #[test]
    fn root_center_enrollment_chain_is_bound() {
        let root = SigningKey::generate(&mut OsRng);
        let center = SigningKey::generate(&mut OsRng);
        let bundle = CenterAuthorityBundle {
            issuer_id: "center".into(), kid: "c1".into(),
            center_public_key: URL_SAFE_NO_PAD.encode(center.verifying_key().as_bytes()),
            issued_at: 1, expires_at: 1000, binding_epoch: 2, trust_bundle_digest: None,
        };
        let enrollment = EnrollmentPackage {
            issuer_id: "center".into(), kid: "c1".into(), host_installation_id: "host".into(),
            enrollment_nonce: "nonce".into(), node_public_key: "node".into(), supervisor_public_key: None,
            client_id: Some("client".into()), organization_id: "org".into(), site_id: Some("site".into()),
            host_id: Some("host-id".into()), deployment_id: Some("deployment".into()), binding_epoch: 2, expires_at: 900,
        };
        let chain = enroll(&URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()), &sign(&root, &bundle), &sign(&center, &enrollment), "host", "nonce", "node", 10).unwrap();
        let binding = chain.host_binding().expect("binding");
        assert!(binding.verified);
        assert_eq!(binding.source, "enrollment_signed");
        assert_eq!(binding.host_id.as_deref(), Some("host-id"));
        assert_eq!(binding.client_id.as_deref(), Some("client"));
        assert!(binding.center_public_key_fingerprint.starts_with("sha256:"));
        let pre = StorageGrantPreflight {
            intent_id: "i".into(), deployment_id: "d".into(), capability: "telemetry".into(),
            canonical_mountpoint: "/mnt/data".into(), canonical_path: "/mnt/data/telemetry".into(),
            subpath: "telemetry".into(), filesystem: "ext4".into(),
            filesystem_uuid: "550e8400-e29b-41d4-a716-446655440000".into(), policy_hash: "p".into(),
            client_id: None, organization_id: Some("org".into()), site_id: Some("site".into()),
            host_id: Some("host-id".into()), host_installation_id: Some("host".into()),
            idempotency_key: None, report_generation: 1, snapshot_hash: "snapshot".into(), created_at_unix_seconds: 10,
        };
        let approval = serde_json::json!({
            "iss":"center", "sub":"owner", "jti":"j1", "aud":"host", "organization_id":"org",
            "action":"storage_grant_approve", "intent_id":"i", "deployment_id":"d", "capability":"telemetry",
            "canonical_mountpoint":"/mnt/data", "canonical_path":"/mnt/data/telemetry", "subpath":"telemetry",
            "filesystem":"ext4", "filesystem_uuid":"550e8400-e29b-41d4-a716-446655440000", "policy_hash":"p",
            "binding_epoch":2, "iat":10, "nbf":10, "exp":600, "site_id":"site", "host_id":"host-id",
            "host_installation_id":"host"
        });
        assert_eq!(verify_storage_approval(&chain.center.center_public_key, &chain, &sign(&center, &approval), &pre, &[], 11).unwrap().jti, "j1");
        assert_eq!(verify_storage_approval(&chain.center.center_public_key, &chain, &sign(&center, &approval), &pre, &["j1".into()], 11).unwrap_err(), "STORAGE_APPROVAL_REPLAY");
        assert_eq!(enroll(&URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()), &sign(&root, &bundle), &sign(&center, &enrollment), "other", "nonce", "node", 10).unwrap_err(), "ENROLLMENT_BINDING_MISMATCH");
    }

    #[test]
    fn enrollment_proof_binds_supervisor_scope_and_expiry() {
        let root = SigningKey::generate(&mut OsRng);
        let center = SigningKey::generate(&mut OsRng);
        let supervisor = SigningKey::generate(&mut OsRng);
        let bundle = CenterAuthorityBundle { issuer_id: "center".into(), kid: "c1".into(), center_public_key: URL_SAFE_NO_PAD.encode(center.verifying_key().as_bytes()), issued_at: 10, expires_at: 1000, binding_epoch: 1, trust_bundle_digest: None };
        let supervisor_public_key = URL_SAFE_NO_PAD.encode(supervisor.verifying_key().as_bytes());
        let enrollment = EnrollmentPackage { issuer_id: "center".into(), kid: "c1".into(), host_installation_id: "host".into(), enrollment_nonce: "nonce".into(), node_public_key: supervisor_public_key.clone(), supervisor_public_key: Some(supervisor_public_key.clone()), client_id: Some("client".into()), organization_id: "org".into(), site_id: Some("site".into()), host_id: Some("host-id".into()), deployment_id: None, binding_epoch: 1, expires_at: 900 };
        let expected = EnrollmentProofClaims { schema_version: 1, purpose: "HOST_ENROLL".into(), ticket_hash: "a".repeat(64), client_id: "client".into(), organization_id: "org".into(), site_id: "site".into(), host_id: "host-id".into(), host_installation_id: "host".into(), supervisor_public_key: supervisor_public_key.clone(), binding_epoch: 1, nonce: "nonce".into(), environment: "lab".into(), issued_at: 10, expires_at: 300 };
        let proof = sign(&supervisor, &expected);
        let enrolled = enroll_with_proof(&URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()), &sign(&root, &bundle), &sign(&center, &enrollment), &proof, "host", "nonce", &supervisor_public_key, &expected, 11).expect("proof accepted");
        assert_eq!(enrolled.enrollment.supervisor_public_key.as_deref(), Some(supervisor_public_key.as_str()));
        let mut tampered_package = sign(&center, &enrollment);
        let mut tampered_payload = URL_SAFE_NO_PAD.decode(&tampered_package.payload).unwrap();
        tampered_payload[0] ^= 1;
        tampered_package.payload = URL_SAFE_NO_PAD.encode(tampered_payload);
        assert_eq!(enroll_with_proof(&URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()), &sign(&root, &bundle), &tampered_package, &proof, "host", "nonce", &supervisor_public_key, &expected, 11).unwrap_err(), "AUTHORITY_SIGNATURE_INVALID");
        let wrong_proof = sign(&center, &expected);
        assert_eq!(verify_enrollment_proof(&wrong_proof, &supervisor_public_key, &expected, 11).unwrap_err(), "AUTHORITY_SIGNATURE_INVALID");
        let mut stale_bundle = bundle.clone();
        stale_bundle.binding_epoch = 2;
        assert_eq!(enroll_with_proof(&URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()), &sign(&root, &stale_bundle), &sign(&center, &enrollment), &proof, "host", "nonce", &supervisor_public_key, &expected, 11).unwrap_err(), "ENROLLMENT_EPOCH_MISMATCH");
        let mut wrong = expected.clone(); wrong.host_id = "other".into();
        assert_eq!(verify_enrollment_proof(&proof, &supervisor_public_key, &wrong, 11).unwrap_err(), "ENROLLMENT_PROOF_SCOPE_INVALID");
        assert_eq!(verify_enrollment_proof(&proof, &supervisor_public_key, &expected, 301).unwrap_err(), "ENROLLMENT_PROOF_EXPIRED");
    }

    #[test]
    fn enrollment_ack_is_signed_and_scope_bound() {
        let supervisor = SigningKey::generate(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(supervisor.verifying_key().as_bytes());
        let expected = EnrollmentAckClaims {
            schema_version: 1,
            purpose: "HOST_ENROLL_ACK".into(),
            ticket_hash: "a".repeat(64),
            client_id: "client".into(),
            organization_id: "org".into(),
            site_id: "site".into(),
            host_id: "host-id".into(),
            host_installation_id: "installation".into(),
            supervisor_public_key: public_key.clone(),
            supervisor_key_id: "supervisor-v1".into(),
            binding_epoch: 3,
            enrollment_nonce: "nonce".into(),
            package_digest: "b".repeat(64),
            applied_at: 100,
            status: "applied".into(),
        };
        let ack = sign(&supervisor, &expected);
        assert_eq!(verify_enrollment_ack(&ack, &public_key, &expected, 101), Ok(()));
        let mut wrong = expected.clone();
        wrong.package_digest = "c".repeat(64);
        assert_eq!(verify_enrollment_ack(&ack, &public_key, &wrong, 101).unwrap_err(), "ENROLLMENT_ACK_SCOPE_INVALID");
        let other = SigningKey::generate(&mut OsRng);
        assert_eq!(verify_enrollment_ack(&sign(&other, &expected), &public_key, &expected, 101).unwrap_err(), "AUTHORITY_SIGNATURE_INVALID");
    }

    #[test]
    fn trust_bundle_enrollment_separates_center_and_enrollment_signers() {
        let mut authorities = crate::AuthorityService::new(crate::TestEphemeralKeyProvider::default(), "set");
        authorities.initialize_root("root", 1).unwrap();
        authorities.issue_subordinate("root", "deployment-authority", crate::AuthorityKind::DeploymentAuthority, vec![crate::authority_capability(crate::AuthorityKind::DeploymentAuthority).into()], 1, None).unwrap();
        authorities.issue_subordinate("deployment-authority", "deployment-root", crate::AuthorityKind::DeploymentRoot, vec![crate::authority_capability(crate::AuthorityKind::DeploymentRoot).into()], 1, None).unwrap();
        authorities.issue_subordinate("deployment-root", "center", crate::AuthorityKind::CenterAuthority, vec![crate::authority_capability(crate::AuthorityKind::CenterAuthority).into(), "center_bundle_signing".into()], 1, None).unwrap();
        authorities.issue_subordinate("center", "enrollment", crate::AuthorityKind::EnrollmentAuthority, vec!["host_enrollment".into()], 1, None).unwrap();
        let center = authorities.authorities().find(|authority| authority.authority_id == "center").unwrap().clone();
        let enrollment_authority = authorities.authorities().find(|authority| authority.authority_id == "enrollment").unwrap().clone();
        let bundle = CenterAuthorityBundle { issuer_id: center.authority_id.clone(), kid: center.key_id.clone(), center_public_key: enrollment_authority.public_key.clone(), issued_at: 10, expires_at: 1000, binding_epoch: 1, trust_bundle_digest: None };
        let supervisor = SigningKey::generate(&mut OsRng);
        let supervisor_public_key = URL_SAFE_NO_PAD.encode(supervisor.verifying_key().as_bytes());
        let enrollment = EnrollmentPackage { issuer_id: enrollment_authority.authority_id.clone(), kid: enrollment_authority.key_id.clone(), host_installation_id: "host".into(), enrollment_nonce: "nonce".into(), node_public_key: supervisor_public_key.clone(), supervisor_public_key: Some(supervisor_public_key.clone()), client_id: Some("client".into()), organization_id: "org".into(), site_id: Some("site".into()), host_id: Some("host-id".into()), deployment_id: None, binding_epoch: 1, expires_at: 900 };
        let expected = EnrollmentProofClaims { schema_version: 1, purpose: "HOST_ENROLL".into(), ticket_hash: "a".repeat(64), client_id: "client".into(), organization_id: "org".into(), site_id: "site".into(), host_id: "host-id".into(), host_installation_id: "host".into(), supervisor_public_key: supervisor_public_key.clone(), binding_epoch: 1, nonce: "nonce".into(), environment: "lab".into(), issued_at: 10, expires_at: 300 };
        let sign_authority = |authority_id: &str, value: &serde_json::Value| {
            let authority = authorities.authorities().find(|authority| authority.authority_id == authority_id).unwrap();
            let bytes = serde_json::to_vec(value).unwrap();
            SignedEnvelope { payload: URL_SAFE_NO_PAD.encode(&bytes), signature: URL_SAFE_NO_PAD.encode(authorities.provider().sign(&authority.key_id, &bytes).unwrap()) }
        };
        let center_envelope = sign_authority("center", &serde_json::to_value(&bundle).unwrap());
        let enrollment_envelope = sign_authority("enrollment", &serde_json::to_value(&enrollment).unwrap());
        let proof = sign(&supervisor, &expected);
        let signed_bundle = authorities.trust_bundle("root", 10, None).unwrap();
        let result = enroll_with_trust_bundle(&signed_bundle, &center_envelope, &enrollment_envelope, &proof, "host", "nonce", &supervisor_public_key, &expected, 11).unwrap();
        assert_eq!(result.center.kid, center.key_id);
        assert_eq!(result.enrollment.kid, enrollment_authority.key_id);
    }
}
