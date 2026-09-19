//! Typed Host Identity signing boundary.
//!
//! Consumers request a typed privileged operation. Supervisor/Node signs a
//! domain-separated canonical admission. Private keys never cross IPC and
//! arbitrary "sign bytes" is not exposed.

use crate::canonical_json;
use crate::canonical_scope::{CanonicalConnectivityScopeV1, RequestedConnectivityScope};
use crate::AttestationSigner;
use crate::HostBindingProjection;
use base64::Engine;
use serde::{Deserialize, Serialize};

pub const HOST_IDENTITY_ADMISSION_CONTRACT: &str = "actium.connectivity.host-identity-admission.v2";
pub const HOST_IDENTITY_SIGN_FEATURE: &str = "host_identity_sign_v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentityAdmissionSignRequest {
    pub client_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_identity_key_id: String,
    pub host_identity_fingerprint: String,
    pub binding_epoch: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentityAdmissionUnsignedV2 {
    pub protocol_version: u8,
    pub client_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_identity_key_id: String,
    pub host_identity_fingerprint: String,
    pub binding_epoch: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundle_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostIdentityAdmissionSignedV2 {
    pub admission: HostIdentityAdmissionUnsignedV2,
    pub signature: String,
    pub signer_key_id: String,
    pub public_key: String,
}

pub fn sign_host_identity_admission(
    signer: &AttestationSigner,
    binding: &HostBindingProjection,
    request: &HostIdentityAdmissionSignRequest,
    policy_generation: u64,
    now_unix: u64,
) -> Result<HostIdentityAdmissionSignedV2, String> {
    let scope = CanonicalConnectivityScopeV1::from_binding(binding, policy_generation)?;
    scope.matches_request(&RequestedConnectivityScope {
        organization_id: binding.organization_id.clone(),
        client_id: Some(request.client_id.clone()),
        site_id: request.site_id.clone(),
        host_id: request.host_id.clone(),
        binding_epoch: Some(request.binding_epoch),
        policy_generation: None,
    })?;
    if request.host_identity_key_id.trim() != signer.key_id() {
        return Err("HOST_IDENTITY_KEY_MISMATCH".to_string());
    }
    if request.host_identity_fingerprint.trim() != format!("sha256:{}", signer_fingerprint(signer)?) {
        return Err("HOST_IDENTITY_FINGERPRINT_MISMATCH".to_string());
    }
    if request.nonce.trim().is_empty() {
        return Err("HOST_IDENTITY_ADMISSION_NONCE_INVALID".to_string());
    }
    if request.expires_at_unix <= request.issued_at_unix || request.expires_at_unix <= now_unix {
        return Err("HOST_IDENTITY_ADMISSION_EXPIRED".to_string());
    }
    if request.issued_at_unix > now_unix + 60 {
        return Err("HOST_IDENTITY_ADMISSION_NOT_YET_VALID".to_string());
    }
    let admission = HostIdentityAdmissionUnsignedV2 {
        protocol_version: 2,
        client_id: request.client_id.clone(),
        site_id: request.site_id.clone(),
        host_id: request.host_id.clone(),
        host_identity_key_id: signer.key_id(),
        host_identity_fingerprint: request.host_identity_fingerprint.clone(),
        binding_epoch: request.binding_epoch,
        issued_at_unix: request.issued_at_unix,
        expires_at_unix: request.expires_at_unix,
        nonce: request.nonce.clone(),
        allowed_capabilities: request.allowed_capabilities.clone(),
        trust_bundle_id: request.trust_bundle_id.clone(),
    };
    let signature = signer.sign_canonical_value(
        &serde_json::to_value(&admission).map_err(|error| error.to_string())?,
    )?;
    Ok(HostIdentityAdmissionSignedV2 {
        admission,
        signature,
        signer_key_id: signer.key_id(),
        public_key: signer.public_key(),
    })
}

fn signer_fingerprint(signer: &AttestationSigner) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signer.public_key())
        .map_err(|_| "HOST_IDENTITY_PUBLIC_KEY_INVALID".to_string())?;
    Ok(Sha256::digest(raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn admission_canonical_bytes(admission: &HostIdentityAdmissionUnsignedV2) -> Result<String, String> {
    canonical_json(&serde_json::to_value(admission).map_err(|error| error.to_string())?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            center_key_id: "kid".into(),
            center_public_key_fingerprint: "sha256:abc".into(),
        }
    }

    fn request(signer: &AttestationSigner) -> HostIdentityAdmissionSignRequest {
        HostIdentityAdmissionSignRequest {
            client_id: "client-a".into(),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            host_identity_key_id: signer.key_id(),
            host_identity_fingerprint: format!("sha256:{}", signer_fingerprint(signer).unwrap()),
            binding_epoch: 7,
            issued_at_unix: 1_800_000_000,
            expires_at_unix: 1_800_000_600,
            nonce: "admission-nonce-1".into(),
            allowed_capabilities: Some(vec!["telemetry.gps.batch".into()]),
            trust_bundle_id: None,
        }
    }

    #[test]
    fn typed_admission_signs_without_generic_sign_bytes() {
        let dir = std::env::temp_dir().join(format!("actium-r3-sign-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let signed = sign_host_identity_admission(&signer, &binding(), &request(&signer), 3, 1_800_000_010).unwrap();
        assert_eq!(signed.admission.protocol_version, 2);
        assert_eq!(signed.signer_key_id, signer.key_id());
        assert!(!signed.signature.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn host_and_scope_mismatch_fail_closed() {
        let dir = std::env::temp_dir().join(format!("actium-r3-mismatch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let mut wrong_host = request(&signer);
        wrong_host.host_id = "host-b".into();
        assert_eq!(
            sign_host_identity_admission(&signer, &binding(), &wrong_host, 3, 1_800_000_010).unwrap_err(),
            "SCOPE_MISMATCH"
        );
        let mut wrong_key = request(&signer);
        wrong_key.host_identity_key_id = "other-key".into();
        assert_eq!(
            sign_host_identity_admission(&signer, &binding(), &wrong_key, 3, 1_800_000_010).unwrap_err(),
            "HOST_IDENTITY_KEY_MISMATCH"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unverified_binding_is_signer_unavailable() {
        let dir = std::env::temp_dir().join(format!("actium-r3-unavail-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let mut unverified = binding();
        unverified.verified = false;
        assert_eq!(
            sign_host_identity_admission(&signer, &unverified, &request(&signer), 3, 1_800_000_010).unwrap_err(),
            "SCOPE_UNRESOLVED"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
