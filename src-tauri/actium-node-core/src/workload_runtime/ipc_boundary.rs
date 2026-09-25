use std::collections::BTreeMap;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ipc::IpcPrincipal;
use super::canonical::{rfc8785_canonical_json, DOMAIN_DESIRED_STATE, DOMAIN_RECEIPT};
use super::reconciler::CanonicalWorkloadReceipt;
use super::WorkloadError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadDesiredStateEnvelope {
    pub schema: String,
    pub deployment_id: String,
    pub generation: u64,
    pub profile_id: String,
    pub profile_version: String,
    pub profile_digest: String,
    pub desired_digest: String,
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub purpose: String,
    pub authority_key_id: String,
    pub authority_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<BTreeMap<String, String>>,
}

impl WorkloadDesiredStateEnvelope {
    /// Computes the domain-separated signing payload:
    /// `ACTIUM_WORKLOAD_DESIRED_STATE_V1\0 || JCS(clean_envelope)`
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WorkloadError> {
        let mut clean = serde_json::to_value(self)
            .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;
        if let serde_json::Value::Object(ref mut map) = clean {
            map.remove("authoritySignature");
        }
        let jcs = rfc8785_canonical_json(&clean)?;
        let mut bytes = Vec::with_capacity(DOMAIN_DESIRED_STATE.len() + jcs.len());
        bytes.extend_from_slice(DOMAIN_DESIRED_STATE);
        bytes.extend_from_slice(jcs.as_bytes());
        Ok(bytes)
    }

    /// Verifies the envelope purpose, expiration, sovereign host binding, IPC principal context, and cryptographic Ed25519 signature.
    pub fn verify(
        &self,
        principal: &IpcPrincipal,
        expected_host_id: &str,
        verifying_key: &VerifyingKey,
        now: u64,
    ) -> Result<(), WorkloadError> {
        // 1. Schema check
        if self.schema != crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA {
            return Err(WorkloadError::Unauthorized(format!(
                "Invalid schema '{}', expected '{}'",
                self.schema,
                crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA
            )));
        }

        // 2. Purpose check
        if self.purpose != "workload_desired_state" {
            return Err(WorkloadError::Unauthorized(format!(
                "Invalid envelope purpose '{}': expected 'workload_desired_state'",
                self.purpose
            )));
        }

        // 3. Expiration check
        if self.expires_at > 0 && now > self.expires_at {
            return Err(WorkloadError::Unauthorized(format!(
                "Desired state envelope expired at {} (current time {})",
                self.expires_at, now
            )));
        }

        // 4. Strict Host binding check
        if self.host_id != expected_host_id {
            return Err(WorkloadError::Unauthorized(format!(
                "Host mismatch: envelope target host is '{}', expected local host is '{}'",
                self.host_id, expected_host_id
            )));
        }

        // 5. Principal context binding check
        if let Some(ref bound_host) = principal.bound_host {
            if bound_host != &self.host_id {
                return Err(WorkloadError::Unauthorized(format!(
                    "Host binding mismatch: principal bound to '{}', envelope target is '{}'",
                    bound_host, self.host_id
                )));
            }
        }
        if let Some(ref bound_site) = principal.bound_site {
            if bound_site != &self.site_id {
                return Err(WorkloadError::Unauthorized(format!(
                    "Site binding mismatch: principal bound to '{}', envelope target is '{}'",
                    bound_site, self.site_id
                )));
            }
        }
        if let Some(ref bound_org) = principal.bound_organization {
            if bound_org != &self.organization_id {
                return Err(WorkloadError::Unauthorized(format!(
                    "Organization binding mismatch: principal bound to '{}', envelope target is '{}'",
                    bound_org, self.organization_id
                )));
            }
        }
        if let Some(ref bound_client) = principal.bound_client {
            if bound_client != &self.client_id {
                return Err(WorkloadError::Unauthorized(format!(
                    "Client binding mismatch: principal bound to '{}', envelope target is '{}'",
                    bound_client, self.client_id
                )));
            }
        }

        // 6. Cryptographic signature check (MANDATORY FAIL-CLOSED)
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.authority_signature)
            .map_err(|e| WorkloadError::Unauthorized(format!("Invalid base64 signature: {}", e)))?;

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| WorkloadError::Unauthorized(format!("Invalid signature slice: {}", e)))?;

        let signing_payload = self.signing_bytes()?;
        verifying_key.verify(&signing_payload, &signature)
            .map_err(|e| WorkloadError::Unauthorized(format!("Signature verification failed: {}", e)))?;

        Ok(())
    }
}

/// Signs a CanonicalWorkloadReceipt using domain separation `ACTIUM_WORKLOAD_RECEIPT_V1\0`.
pub fn sign_receipt_with_key(
    receipt: &mut CanonicalWorkloadReceipt,
    signing_key: &SigningKey,
) -> Result<(), WorkloadError> {
    let mut clean = serde_json::to_value(&*receipt)
        .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;
    if let serde_json::Value::Object(ref mut map) = clean {
        map.remove("signature");
    }
    let jcs = rfc8785_canonical_json(&clean)?;
    let mut bytes = Vec::with_capacity(DOMAIN_RECEIPT.len() + jcs.len());
    bytes.extend_from_slice(DOMAIN_RECEIPT);
    bytes.extend_from_slice(jcs.as_bytes());

    let sig = signing_key.sign(&bytes);
    receipt.signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    Ok(())
}

/// Verifies a CanonicalWorkloadReceipt signature using domain separation `ACTIUM_WORKLOAD_RECEIPT_V1\0`.
pub fn verify_receipt_signature(
    receipt: &CanonicalWorkloadReceipt,
    verifying_key: &VerifyingKey,
) -> Result<(), WorkloadError> {
    let mut clean = serde_json::to_value(receipt)
        .map_err(|e| WorkloadError::SerializationError(e.to_string()))?;
    if let serde_json::Value::Object(ref mut map) = clean {
        map.remove("signature");
    }
    let jcs = rfc8785_canonical_json(&clean)?;
    let mut bytes = Vec::with_capacity(DOMAIN_RECEIPT.len() + jcs.len());
    bytes.extend_from_slice(DOMAIN_RECEIPT);
    bytes.extend_from_slice(jcs.as_bytes());

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature)
        .map_err(|e| WorkloadError::Unauthorized(format!("Invalid base64 signature: {}", e)))?;

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| WorkloadError::Unauthorized(format!("Invalid signature slice: {}", e)))?;

    verifying_key
        .verify(&bytes, &signature)
        .map_err(|e| WorkloadError::Unauthorized(format!("Receipt signature verification failed: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use crate::ipc::{sovereign_ipc_principal, IpcPrincipalKind};
    use crate::workload::ComponentStatus;

    fn generate_test_keys() -> (SigningKey, VerifyingKey) {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn test_domain_separated_signing_and_purpose_verification() {
        let (sk, vk) = generate_test_keys();
        let now = 1000u64;

        let mut envelope = WorkloadDesiredStateEnvelope {
            schema: crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA.to_string(),
            deployment_id: "dep-auth-1".into(),
            generation: 1,
            profile_id: "test-profile".into(),
            profile_version: "1.0.0".into(),
            profile_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            desired_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            client_id: "client-a".into(),
            organization_id: "org-a".into(),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            nonce: "nonce-1".into(),
            issued_at: now,
            expires_at: now + 3600_000,
            purpose: "workload_desired_state".into(),
            authority_key_id: "key-1".into(),
            authority_signature: "".into(),
            environment: None,
        };

        // Sign with domain separation
        let payload = envelope.signing_bytes().unwrap();
        let sig = sk.sign(&payload);
        envelope.authority_signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        // Sovereign principal verifies successfully with matching host
        let sov_principal = sovereign_ipc_principal();
        assert!(envelope.verify(&sov_principal, "host-a", &vk, now).is_ok());

        // Mismatched expected host fails closed even for Sovereign
        assert!(matches!(
            envelope.verify(&sov_principal, "host-other", &vk, now),
            Err(WorkloadError::Unauthorized(_))
        ));

        // Wrong purpose fails closed
        let mut bad_purpose = envelope.clone();
        bad_purpose.purpose = "wrong_purpose".into();
        assert!(matches!(bad_purpose.verify(&sov_principal, "host-a", &vk, now), Err(WorkloadError::Unauthorized(_))));

        // Tampered payload fails signature verification
        let mut tampered = envelope.clone();
        tampered.profile_version = "2.0.0".into();
        assert!(matches!(tampered.verify(&sov_principal, "host-a", &vk, now), Err(WorkloadError::Unauthorized(_))));
    }

    #[test]
    fn test_ipc_envelope_host_binding_verification() {
        let (sk, vk) = generate_test_keys();
        let now = 1000u64;

        let mut envelope = WorkloadDesiredStateEnvelope {
            schema: crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA.to_string(),
            deployment_id: "dep-bound-1".into(),
            generation: 1,
            profile_id: "test-profile".into(),
            profile_version: "1.0.0".into(),
            profile_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            desired_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            client_id: "client-a".into(),
            organization_id: "org-a".into(),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            nonce: "nonce-1".into(),
            issued_at: now,
            expires_at: now + 3600_000,
            purpose: "workload_desired_state".into(),
            authority_key_id: "key-1".into(),
            authority_signature: "".into(),
            environment: None,
        };

        let payload = envelope.signing_bytes().unwrap();
        let sig = sk.sign(&payload);
        envelope.authority_signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        // Principal matching binding succeeds
        let matching_principal = IpcPrincipal {
            principal_id: "host-manager".into(),
            principal_kind: IpcPrincipalKind::ConnectivityProduct,
            allowed_operations: vec!["*".into()],
            bound_client: Some("client-a".into()),
            bound_organization: Some("org-a".into()),
            bound_site: Some("site-a".into()),
            bound_host: Some("host-a".into()),
        };
        assert!(envelope.verify(&matching_principal, "host-a", &vk, now).is_ok());

        // Principal with mismatched host fails closed
        let mismatched_host = IpcPrincipal {
            bound_host: Some("host-other".into()),
            ..matching_principal.clone()
        };
        assert!(matches!(envelope.verify(&mismatched_host, "host-a", &vk, now), Err(WorkloadError::Unauthorized(_))));

        // Principal with mismatched site fails closed
        let mismatched_site = IpcPrincipal {
            bound_site: Some("site-other".into()),
            ..matching_principal.clone()
        };
        assert!(matches!(envelope.verify(&mismatched_site, "host-a", &vk, now), Err(WorkloadError::Unauthorized(_))));
    }

    #[test]
    fn test_ipc_envelope_expiration() {
        let (sk, vk) = generate_test_keys();
        let now = 2000u64;

        let mut envelope = WorkloadDesiredStateEnvelope {
            schema: crate::workload::DESIRED_WORKLOAD_STATE_SCHEMA.to_string(),
            deployment_id: "dep-exp-1".into(),
            generation: 1,
            profile_id: "test-profile".into(),
            profile_version: "1.0.0".into(),
            profile_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000".into(),
            desired_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111".into(),
            client_id: "client-a".into(),
            organization_id: "org-a".into(),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            nonce: "nonce-1".into(),
            issued_at: 1000,
            expires_at: 1500, // already expired at now=2000
            purpose: "workload_desired_state".into(),
            authority_key_id: "key-1".into(),
            authority_signature: "".into(),
            environment: None,
        };

        let payload = envelope.signing_bytes().unwrap();
        let sig = sk.sign(&payload);
        envelope.authority_signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let sov = sovereign_ipc_principal();
        assert!(matches!(envelope.verify(&sov, "host-a", &vk, now), Err(WorkloadError::Unauthorized(_))));
    }

    #[test]
    fn test_signed_receipt_verification() {
        let (sk, vk) = generate_test_keys();
        let mut receipt = CanonicalWorkloadReceipt {
            schema: crate::workload::WORKLOAD_RECEIPT_SCHEMA.to_string(),
            receipt_id: "rcpt-1".into(),
            deployment_id: "dep-1".into(),
            generation: 1,
            plan_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222".into(),
            overall_status: ComponentStatus::Ready,
            components: vec![],
            issued_at: 1000,
            signature: "".into(),
        };

        sign_receipt_with_key(&mut receipt, &sk).unwrap();
        assert!(!receipt.signature.is_empty());
        assert!(verify_receipt_signature(&receipt, &vk).is_ok());

        // Tamper with receipt
        let mut tampered = receipt.clone();
        tampered.overall_status = ComponentStatus::Failed;
        assert!(verify_receipt_signature(&tampered, &vk).is_err());
    }
}
