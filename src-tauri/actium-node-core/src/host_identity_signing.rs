//! Typed Host Identity signing boundary.
//!
//! Consumers request a typed privileged operation. Supervisor/Node signs a
//! domain-separated canonical admission. Private keys never cross IPC and
//! arbitrary "sign bytes" is not exposed.

use crate::canonical_json;
use crate::canonical_scope::{CanonicalConnectivityScopeV1, RequestedConnectivityScope};
use crate::common_connectivity_client::{
    ProductAssignmentAuthorizer, COMMON_CONNECTIVITY_CLIENT_CONTRACT, CommonConnectivityRequestV1,
    CommonRoutePolicy,
};
use crate::AttestationSigner;
use crate::HostBindingProjection;
use base64::Engine;
use serde::{Deserialize, Serialize};

pub const HOST_IDENTITY_ADMISSION_CONTRACT: &str = "actium.connectivity.host-identity-admission.v3";
pub const HOST_IDENTITY_ADMISSION_DOMAIN: &str = "actium.connectivity.host-identity-admission.v3";
pub const HOST_IDENTITY_SIGN_FEATURE: &str = "host_identity_sign_v1";
pub const RELAY_TRUST_SNAPSHOT_SIGN_FEATURE: &str = "relay_trust_snapshot_sign_v1";
pub const CONNECTIVITY_IPC_FEATURE: &str = "connectivity_ipc_v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentityAdmissionSignRequest {
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_identity_key_id: String,
    pub host_identity_fingerprint: String,
    pub binding_epoch: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: String,
    pub product_id: String,
    pub product_assignment_id: String,
    pub requested_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_bundle_id: Option<String>,
}

pub struct AdmissionAuthorizationContext<'a> {
    pub assignment: &'a dyn ProductAssignmentAuthorizer,
    pub canonical_trust_bundle_id: Option<&'a str>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentityAdmissionUnsignedV3 {
    pub protocol_version: u8,
    pub client_id: String,
    pub organization_id: String,
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
pub struct HostIdentityAdmissionSignedV3 {
    pub admission: HostIdentityAdmissionUnsignedV3,
    pub signature: String,
    pub signer_key_id: String,
    pub public_key: String,
}

fn authorize_requested_capabilities(
    assignment: &dyn ProductAssignmentAuthorizer,
    request: &HostIdentityAdmissionSignRequest,
) -> Result<Vec<String>, String> {
    if request.product_id.trim().is_empty() || request.product_assignment_id.trim().is_empty() {
        return Err("PRODUCT_ASSIGNMENT_UNAVAILABLE".to_string());
    }
    if request.requested_capabilities.is_empty() {
        return Err("CAPABILITY_UNAUTHORIZED".to_string());
    }
    let mut authorized = Vec::new();
    for capability in &request.requested_capabilities {
        let ccc = CommonConnectivityRequestV1 {
            contract: COMMON_CONNECTIVITY_CLIENT_CONTRACT.to_string(),
            client_id: request.client_id.clone(),
            organization_id: request.organization_id.clone(),
            site_id: request.site_id.clone(),
            host_id: request.host_id.clone(),
            product_id: request.product_id.clone(),
            product_assignment_id: Some(request.product_assignment_id.clone()),
            service_id: request
                .service_id
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "relay-tunnel".to_string()),
            capability: capability.clone(),
            binding_epoch: Some(request.binding_epoch),
            policy_generation: None,
            route_policy: CommonRoutePolicy::Auto,
            expected_service_identity: None,
        };
        assignment.authorize(&ccc)?;
        authorized.push(capability.clone());
    }
    Ok(authorized)
}

pub fn sign_host_identity_admission(
    signer: &AttestationSigner,
    binding: &HostBindingProjection,
    request: &HostIdentityAdmissionSignRequest,
    policy_generation: u64,
    now_unix: u64,
    authorization: &AdmissionAuthorizationContext<'_>,
) -> Result<HostIdentityAdmissionSignedV3, String> {
    let scope = CanonicalConnectivityScopeV1::from_binding(binding, policy_generation)?;
    scope.matches_request(&RequestedConnectivityScope {
        client_id: request.client_id.clone(),
        organization_id: request.organization_id.clone(),
        site_id: request.site_id.clone(),
        host_id: request.host_id.clone(),
        binding_epoch: Some(binding.binding_epoch),
        policy_generation: None,
    })?;
    if request.binding_epoch != binding.binding_epoch {
        return Err("BINDING_EPOCH_MISMATCH".to_string());
    }
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
    let allowed_capabilities = authorize_requested_capabilities(authorization.assignment, request)?;
    let trust_bundle_id = match (
        request.trust_bundle_id.as_deref().map(str::trim).filter(|value| !value.is_empty()),
        authorization.canonical_trust_bundle_id.map(str::trim).filter(|value| !value.is_empty()),
    ) {
        (_, None) => return Err("TRUST_BUNDLE_ID_UNAVAILABLE".to_string()),
        (None, Some(canonical)) => canonical.to_string(),
        (Some(requested), Some(canonical)) if requested == canonical => canonical.to_string(),
        (Some(_), Some(_)) => return Err("TRUST_BUNDLE_ID_MISMATCH".to_string()),
    };
    let admission = HostIdentityAdmissionUnsignedV3 {
        protocol_version: 3,
        client_id: scope.client_id,
        organization_id: scope.organization_id,
        site_id: scope.site_id,
        host_id: scope.host_id,
        host_identity_key_id: signer.key_id(),
        host_identity_fingerprint: request.host_identity_fingerprint.clone(),
        binding_epoch: binding.binding_epoch,
        issued_at_unix: request.issued_at_unix,
        expires_at_unix: request.expires_at_unix,
        nonce: request.nonce.clone(),
        allowed_capabilities: Some(allowed_capabilities),
        trust_bundle_id: Some(trust_bundle_id),
    };
    let signature = signer.sign_domain_separated(
        HOST_IDENTITY_ADMISSION_DOMAIN,
        &serde_json::to_value(&admission).map_err(|error| error.to_string())?,
    )?;
    Ok(HostIdentityAdmissionSignedV3 {
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
            organization_id: "org-a".into(),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            host_identity_key_id: signer.key_id(),
            host_identity_fingerprint: format!("sha256:{}", signer_fingerprint(signer).unwrap()),
            binding_epoch: 7,
            issued_at_unix: 1_800_000_000,
            expires_at_unix: 1_800_000_600,
            nonce: "admission-nonce-1".into(),
            product_id: "aegis-control".into(),
            product_assignment_id: "assign-a".into(),
            requested_capabilities: vec!["telemetry.gps.batch".into()],
            service_id: Some("relay-tunnel".into()),
            trust_bundle_id: None,
        }
    }

    fn authorization() -> crate::InMemoryProductAssignmentAuthorizer {
        crate::InMemoryProductAssignmentAuthorizer::new(vec![crate::ProductAssignmentGrantV1 {
            product_assignment_id: "assign-a".into(),
            product_id: "aegis-control".into(),
            client_id: "client-a".into(),
            organization_id: "org-a".into(),
            site_id: Some("site-a".into()),
            host_id: Some("host-a".into()),
            capability: "telemetry.gps.batch".into(),
            service_id: Some("relay-tunnel".into()),
            authorized: true,
        }])
    }

    fn sign(
        signer: &AttestationSigner,
        binding: &HostBindingProjection,
        request: &HostIdentityAdmissionSignRequest,
    ) -> Result<HostIdentityAdmissionSignedV3, String> {
        let assignment = authorization();
        sign_host_identity_admission(
            signer,
            binding,
            request,
            3,
            1_800_000_010,
            &AdmissionAuthorizationContext {
                assignment: &assignment,
                canonical_trust_bundle_id: Some("bundle-1"),
            },
        )
    }

    #[test]
    fn typed_admission_signs_without_generic_sign_bytes() {
        let dir = std::env::temp_dir().join(format!("actium-r3-sign-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let signed = sign(&signer, &binding(), &request(&signer)).unwrap();
        assert_eq!(signed.admission.protocol_version, 3);
        assert_eq!(signed.admission.organization_id, "org-a");
        assert_eq!(
            signed.admission.allowed_capabilities,
            Some(vec!["telemetry.gps.batch".into()])
        );
        assert_eq!(signed.admission.trust_bundle_id.as_deref(), Some("bundle-1"));
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
            sign(&signer, &binding(), &wrong_host).unwrap_err(),
            "SCOPE_MISMATCH"
        );
        let mut wrong_key = request(&signer);
        wrong_key.host_identity_key_id = "other-key".into();
        assert_eq!(
            sign(&signer, &binding(), &wrong_key).unwrap_err(),
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
            sign(&signer, &unverified, &request(&signer)).unwrap_err(),
            "SCOPE_UNRESOLVED"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn admission_signature_does_not_verify_as_relay_snapshot() {
        let dir = std::env::temp_dir().join(format!("actium-r3-domain-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let signed = sign(&signer, &binding(), &request(&signer)).unwrap();
        let snapshot_canonical = crate::domain_separated_canonical(
            crate::RELAY_TRUST_SNAPSHOT_DOMAIN,
            &serde_json::to_value(&signed.admission).unwrap(),
        )
        .unwrap();
        let admission_canonical = crate::domain_separated_canonical(
            HOST_IDENTITY_ADMISSION_DOMAIN,
            &serde_json::to_value(&signed.admission).unwrap(),
        )
        .unwrap();
        assert_ne!(snapshot_canonical, admission_canonical);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn supervisor_derives_capabilities_and_rejects_unauthorized_or_wrong_bundle() {
        let dir = std::env::temp_dir().join(format!("actium-r3-caps-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let signer = AttestationSigner::load_or_create(dir.join("identity.key")).unwrap();
        let mut unauthorized = request(&signer);
        unauthorized.requested_capabilities = vec!["authority.ceremony".into()];
        assert_eq!(
            sign(&signer, &binding(), &unauthorized).unwrap_err(),
            "PRODUCT_ASSIGNMENT_UNAUTHORIZED"
        );
        let mut unknown = request(&signer);
        unknown.product_assignment_id = "assign-missing".into();
        assert_eq!(
            sign(&signer, &binding(), &unknown).unwrap_err(),
            "PRODUCT_ASSIGNMENT_UNAUTHORIZED"
        );
        let mut cross_client = request(&signer);
        cross_client.client_id = "client-b".into();
        assert_eq!(
            sign(&signer, &binding(), &cross_client).unwrap_err(),
            "SCOPE_MISMATCH"
        );
        let assignment = authorization();
        let mut wrong_bundle = request(&signer);
        wrong_bundle.trust_bundle_id = Some("bundle-other".into());
        assert_eq!(
            sign_host_identity_admission(
                &signer,
                &binding(),
                &wrong_bundle,
                3,
                1_800_000_010,
                &AdmissionAuthorizationContext {
                    assignment: &assignment,
                    canonical_trust_bundle_id: Some("bundle-1"),
                },
            )
            .unwrap_err(),
            "TRUST_BUNDLE_ID_MISMATCH"
        );
        assert_eq!(
            sign_host_identity_admission(
                &signer,
                &binding(),
                &request(&signer),
                3,
                1_800_000_010,
                &AdmissionAuthorizationContext {
                    assignment: &crate::UnavailableProductAssignmentAuthorizer,
                    canonical_trust_bundle_id: Some("bundle-1"),
                },
            )
            .unwrap_err(),
            "PRODUCT_ASSIGNMENT_UNAVAILABLE"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
