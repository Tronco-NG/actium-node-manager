//! Bootstrap chain for offline Actium authority. Runtime never creates Root or
//! Center authority keys; test fixtures may create ephemeral keys only.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct SignedEnvelope { pub payload:String, pub signature:String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct CenterAuthorityBundle { pub issuer_id:String, pub kid:String, pub center_public_key:String, pub issued_at:u64, pub expires_at:u64, pub binding_epoch:u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct EnrollmentPackage { pub issuer_id:String, pub kid:String, pub host_installation_id:String, pub enrollment_nonce:String, pub node_public_key:String, pub organization_id:String, #[serde(default)] pub site_id:Option<String>, pub binding_epoch:u64, pub expires_at:u64 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub struct EnrolledAuthority { pub center:CenterAuthorityBundle, pub enrollment:EnrollmentPackage }
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

fn verify(key:&str, envelope:&SignedEnvelope)->Result<Vec<u8>,String>{let raw=URL_SAFE_NO_PAD.decode(key).map_err(|_|"AUTHORITY_KEY_INVALID")?;let vk=VerifyingKey::from_bytes(raw.as_slice().try_into().map_err(|_|"AUTHORITY_KEY_INVALID")?).map_err(|_|"AUTHORITY_KEY_INVALID")?;let payload=URL_SAFE_NO_PAD.decode(&envelope.payload).map_err(|_|"AUTHORITY_ENVELOPE_INVALID")?;let sig=Signature::from_slice(&URL_SAFE_NO_PAD.decode(&envelope.signature).map_err(|_|"AUTHORITY_SIGNATURE_INVALID")?).map_err(|_|"AUTHORITY_SIGNATURE_INVALID")?;vk.verify(&payload,&sig).map_err(|_|"AUTHORITY_SIGNATURE_INVALID")?;Ok(payload)}
pub fn enroll(root_public_key:&str, center_envelope:&SignedEnvelope, enrollment_envelope:&SignedEnvelope, expected_host:&str, expected_nonce:&str, node_public_key:&str, now:u64)->Result<EnrolledAuthority,String>{let center:CenterAuthorityBundle=serde_json::from_slice(&verify(root_public_key,center_envelope)?).map_err(|_|"CENTER_BUNDLE_INVALID")?;if center.expires_at<=now{return Err("CENTER_BUNDLE_EXPIRED".into())};let enrollment:EnrollmentPackage=serde_json::from_slice(&verify(&center.center_public_key,enrollment_envelope)?).map_err(|_|"ENROLLMENT_PACKAGE_INVALID")?;if enrollment.issuer_id!=center.issuer_id||enrollment.kid!=center.kid||enrollment.expires_at<=now{return Err("ENROLLMENT_UNTRUSTED_OR_EXPIRED".into())};if enrollment.host_installation_id!=expected_host||enrollment.enrollment_nonce!=expected_nonce||enrollment.node_public_key!=node_public_key{return Err("ENROLLMENT_BINDING_MISMATCH".into())};if enrollment.binding_epoch!=center.binding_epoch{return Err("ENROLLMENT_EPOCH_MISMATCH".into())};Ok(EnrolledAuthority{center,enrollment})}
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
            issued_at: 1, expires_at: 1000, binding_epoch: 2,
        };
        let enrollment = EnrollmentPackage {
            issuer_id: "center".into(), kid: "c1".into(), host_installation_id: "host".into(),
            enrollment_nonce: "nonce".into(), node_public_key: "node".into(),
            organization_id: "org".into(), site_id: None, binding_epoch: 2, expires_at: 900,
        };
        let chain = enroll(&URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()), &sign(&root, &bundle), &sign(&center, &enrollment), "host", "nonce", "node", 10).unwrap();
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
}
