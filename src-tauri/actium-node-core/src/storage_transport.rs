//! Signed storage transport shared by Supervisor, Manager and Center.
//!
//! The Supervisor is the only component allowed to sign discovery and intent
//! envelopes.  Owner approvals continue to be issued by Center and are never
//! manufactured locally.

use crate::{canonical_json, AttestationSigner, StorageGrantPreflight, StorageMount};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub const STORAGE_TRANSPORT_PROTOCOL: &str = "actium.storage.transport";
pub const STORAGE_TRANSPORT_VERSION: u8 = 1;
pub const STORAGE_TRANSPORT_MAX_TTL_SECONDS: u64 = 600;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageTransportScope {
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_installation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageTransportMessageType {
    DiscoverySnapshot,
    StorageGrantIntent,
    StorageGrantApproval,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedStorageTransport {
    pub protocol: String,
    pub version: u8,
    pub message_type: StorageTransportMessageType,
    pub message_id: String,
    pub idempotency_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub scope: StorageTransportScope,
    pub payload: Value,
    pub signer_key_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageDiscoveryMount {
    pub mountpoint: String,
    pub source: String,
    pub filesystem: String,
    pub filesystem_uuid: Option<String>,
    pub label: Option<String>,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub read_only: bool,
    pub is_root: bool,
}

impl From<&StorageMount> for StorageDiscoveryMount {
    fn from(mount: &StorageMount) -> Self {
        Self {
            mountpoint: mount.mountpoint.clone(),
            source: mount.source.clone(),
            filesystem: mount.filesystem.clone(),
            filesystem_uuid: mount.filesystem_uuid.clone(),
            label: mount.label.clone(),
            total_bytes: mount.total_bytes,
            free_bytes: mount.free_bytes,
            read_only: mount.readonly,
            is_root: mount.root,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageDiscoverySnapshot {
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_installation_id: String,
    pub report_generation: u64,
    pub observed_at: u64,
    pub snapshot_hash: String,
    pub mounts: Vec<StorageDiscoveryMount>,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageGrantIntent {
    pub intent_id: String,
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub host_installation_id: String,
    pub deployment_id: String,
    pub capability: String,
    pub canonical_mountpoint: String,
    pub subpath: String,
    pub canonical_path: String,
    pub filesystem: String,
    pub filesystem_uuid: String,
    pub policy_hash: String,
    pub binding_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub idempotency_key: String,
}

impl StorageGrantIntent {
    pub fn from_preflight(preflight: &StorageGrantPreflight, binding_epoch: u64, now: u64) -> Result<Self, String> {
        let client_id = preflight.client_id.clone().ok_or("STORAGE_TRANSPORT_CLIENT_REQUIRED")?;
        let organization_id = preflight.organization_id.clone().ok_or("STORAGE_TRANSPORT_ORGANIZATION_REQUIRED")?;
        let site_id = preflight.site_id.clone().ok_or("STORAGE_TRANSPORT_SITE_REQUIRED")?;
        let host_id = preflight.host_id.clone().ok_or("STORAGE_TRANSPORT_HOST_REQUIRED")?;
        let host_installation_id = preflight.host_installation_id.clone().ok_or("STORAGE_TRANSPORT_HOST_INSTALLATION_REQUIRED")?;
        let idempotency_key = preflight.idempotency_key.clone().ok_or("STORAGE_TRANSPORT_IDEMPOTENCY_REQUIRED")?;
        if preflight.deployment_id.trim().is_empty() || preflight.capability.trim().is_empty() {
            return Err("STORAGE_TRANSPORT_SCOPE_INVALID".to_string());
        }
        Ok(Self {
            intent_id: preflight.intent_id.clone(),
            client_id,
            organization_id,
            site_id,
            host_id,
            host_installation_id,
            deployment_id: preflight.deployment_id.clone(),
            capability: preflight.capability.clone(),
            canonical_mountpoint: preflight.canonical_mountpoint.clone(),
            subpath: preflight.subpath.clone(),
            canonical_path: preflight.canonical_path.clone(),
            filesystem: preflight.filesystem.clone(),
            filesystem_uuid: preflight.filesystem_uuid.clone(),
            policy_hash: preflight.policy_hash.clone(),
            binding_epoch,
            issued_at: now,
            expires_at: now.saturating_add(STORAGE_TRANSPORT_MAX_TTL_SECONDS),
            idempotency_key,
        })
    }
}

pub fn sign_storage_transport(
    signer: &AttestationSigner,
    message_type: StorageTransportMessageType,
    scope: StorageTransportScope,
    idempotency_key: String,
    payload: Value,
    now: u64,
) -> Result<SignedStorageTransport, String> {
    if idempotency_key.trim().is_empty() {
        return Err("STORAGE_TRANSPORT_IDEMPOTENCY_REQUIRED".to_string());
    }
    if scope.client_id.trim().is_empty()
        || scope.organization_id.trim().is_empty()
        || scope.site_id.trim().is_empty()
        || scope.host_id.trim().is_empty()
        || scope.host_installation_id.trim().is_empty()
    {
        return Err("STORAGE_TRANSPORT_SCOPE_INVALID".to_string());
    }
    if !matches!(message_type, StorageTransportMessageType::DiscoverySnapshot)
        && (scope.deployment_id.as_deref().is_none_or(str::is_empty)
            || scope.capability.as_deref().is_none_or(str::is_empty))
    {
        return Err("STORAGE_TRANSPORT_SCOPE_INVALID".to_string());
    }
    let mut envelope = SignedStorageTransport {
        protocol: STORAGE_TRANSPORT_PROTOCOL.to_string(),
        version: STORAGE_TRANSPORT_VERSION,
        message_type,
        message_id: Uuid::new_v4().to_string(),
        idempotency_key,
        issued_at: now,
        expires_at: now.saturating_add(STORAGE_TRANSPORT_MAX_TTL_SECONDS),
        scope,
        payload,
        signer_key_id: signer.key_id(),
        signature: String::new(),
    };
    let mut unsigned = serde_json::to_value(&envelope)
        .map_err(|error| format!("STORAGE_TRANSPORT_SERIALIZATION_FAILED: {error}"))?;
    if let Value::Object(fields) = &mut unsigned {
        fields.remove("signature");
    }
    let _ = canonical_json(&unsigned)?;
    envelope.signature = signer.sign_canonical_value(&unsigned)?;
    Ok(envelope)
}

pub fn discovery_snapshot_payload(
    mounts: &[StorageMount],
    client_id: String,
    organization_id: String,
    site_id: String,
    host_id: String,
    host_installation_id: String,
    report_generation: u64,
    observed_at: u64,
    snapshot_hash: String,
    idempotency_key: String,
) -> StorageDiscoverySnapshot {
    StorageDiscoverySnapshot {
        client_id,
        organization_id,
        site_id,
        host_id,
        host_installation_id,
        report_generation,
        observed_at,
        snapshot_hash,
        mounts: mounts.iter().map(StorageDiscoveryMount::from).collect(),
        idempotency_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{discovery_snapshot_hash, AttestationAuthorityState};
    use serde_json::json;
    use std::path::PathBuf;

    #[test]
    fn envelope_uses_manager_compatible_field_names_and_signature() {
        let root = std::env::temp_dir().join(format!("actium-storage-transport-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_for_authority(
            root.join("attestation-identity.key"),
            AttestationAuthorityState::NewInstallation,
        )
        .unwrap();
        let envelope = sign_storage_transport(
            &signer,
            StorageTransportMessageType::StorageGrantIntent,
            StorageTransportScope {
                client_id: "client".into(), organization_id: "org".into(), site_id: "site".into(),
                host_id: "host".into(), host_installation_id: "installation".into(),
                deployment_id: Some("deployment".into()), capability: Some("telemetry".into()),
            },
            "idem".into(), json!({"intentId":"intent"}), 100,
        ).unwrap();
        let value = serde_json::to_value(&envelope).unwrap();
        assert_eq!(value["messageType"], "storage_grant_intent");
        assert_eq!(value["signerKeyId"], signer.key_id());
        assert!(!value["signature"].as_str().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(PathBuf::from(root));
    }

    #[test]
    fn discovery_payload_maps_read_only_and_root_contract() {
        let mount = StorageMount {
            mountpoint: "/srv/actium-lab".into(), source: "/dev/sdb1".into(),
            filesystem_uuid: Some("e0aca9ce-07a5-4d89-aa7f-cac467879f0a".into()), label: Some("ACTIUM_LAB".into()),
            filesystem: "ext4".into(), readonly: false, total_bytes: 200, free_bytes: 100,
            root: false, observed_at_unix_seconds: 1, report_generation: 1, freshness_state: "fresh".into(),
        };
        let snapshot = discovery_snapshot_payload(&[mount.clone()], "client".into(), "org".into(), "site".into(), "host".into(), "installation".into(), 1, 1, discovery_snapshot_hash(&[mount]), "idem".into());
        let value = serde_json::to_value(snapshot).unwrap();
        assert_eq!(value["mounts"][0]["readOnly"], false);
        assert_eq!(value["mounts"][0]["isRoot"], false);
    }
}
