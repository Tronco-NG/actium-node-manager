use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const HOST_IDENTITIES_DIR: &str = "host-identities";
pub const CONTINUITY_STATUS_RELATIVE: &str = "state/agent/remote-attestation-continuity-v1.json";
pub const DESIRED_PAYLOAD_RELATIVE: &str = "state/agent/desired-payload-v1.json";
pub const JOURNAL_METADATA_FILE: &str = "attestation-journal-v1.initialized.json";

const JOURNAL_FILES: [&str; 5] = [
    JOURNAL_METADATA_FILE,
    "material-attestation-head-v1.json",
    "material-attestation.json",
    "material-attestation-transports-head-v1.json",
    "material-attestation-anchor-v1.json",
];

const JOURNAL_DIRS: [&str; 2] = [
    "material-attestations-v1",
    "material-attestation-transports-v1",
];

const IDENTITY_FILES: [&str; 2] = ["attestation-identity.json", "attestation-identity.key"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityGate {
    Current,
    Pending,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RemoteAttestationContinuity {
    pub schema: u8,
    pub decision: String,
    pub continuity_state: String,
    pub reason_code: Option<String>,
    pub journal_id: Option<String>,
    pub observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesiredPayloadPin {
    pub schema: u8,
    pub runtime_release: String,
    pub payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSupersedeRequest<'a> {
    pub owner_authorized: bool,
    pub pinned_journal_id: &'a str,
    pub incoming_journal_id: &'a str,
    pub reason: &'a str,
    pub confirmation: &'a str,
}

pub fn host_identities_root(authorized_nodes_root: &Path) -> PathBuf {
    authorized_nodes_root
        .parent()
        .unwrap_or(authorized_nodes_root)
        .join(HOST_IDENTITIES_DIR)
}

pub fn host_deployment_attestation_dir(
    host_identities_root: &Path,
    host_id: &str,
    deployment_id: &str,
) -> PathBuf {
    host_identities_root
        .join(host_id)
        .join("deployments")
        .join(deployment_id)
        .join("attestation")
}

pub fn host_identity_snapshot_dir(host_identities_root: &Path, host_id: &str) -> PathBuf {
    host_identities_root.join(host_id).join("identity")
}

pub fn durable_journal_exists(dir: &Path) -> bool {
    dir.join(JOURNAL_METADATA_FILE).is_file()
}

pub fn host_identities_have_canonical_journal(host_identities_root: &Path) -> bool {
    let Ok(hosts) = fs::read_dir(host_identities_root) else {
        return false;
    };
    for host in hosts.flatten() {
        let deployments = host.path().join("deployments");
        let Ok(entries) = fs::read_dir(deployments) else {
            continue;
        };
        if entries.flatten().any(|entry| {
            durable_journal_exists(&entry.path().join("attestation"))
        }) {
            return true;
        }
    }
    false
}

pub fn snapshot_attestation_journal(source: &Path, durable: &Path) -> Result<(), String> {
    if !durable_journal_exists(source) {
        return Ok(());
    }
    fs::create_dir_all(durable)
        .map_err(|error| format!("No se pudo crear journal durable: {error}"))?;
    copy_journal_artifacts(source, durable)
}

pub fn restore_attestation_journal(durable: &Path, dest: &Path) -> Result<bool, String> {
    if !durable_journal_exists(durable) {
        return Ok(false);
    }
    if durable_journal_exists(dest) {
        return Ok(false);
    }
    fs::create_dir_all(dest)
        .map_err(|error| format!("No se pudo recrear state/supervisor: {error}"))?;
    copy_journal_artifacts(durable, dest)?;
    Ok(true)
}

pub fn snapshot_attestation_identity(source_dir: &Path, durable: &Path) -> Result<(), String> {
    if !IDENTITY_FILES
        .iter()
        .any(|name| source_dir.join(name).is_file())
    {
        return Ok(());
    }
    fs::create_dir_all(durable)
        .map_err(|error| format!("No se pudo crear identidad durable: {error}"))?;
    for name in IDENTITY_FILES {
        copy_if_present(&source_dir.join(name), &durable.join(name))?;
    }
    Ok(())
}

pub fn restore_attestation_identity(durable: &Path, dest_dir: &Path) -> Result<bool, String> {
    let key = dest_dir.join("attestation-identity.key");
    let meta = dest_dir.join("attestation-identity.json");
    if key.is_file() && meta.is_file() {
        return Ok(false);
    }
    if !IDENTITY_FILES
        .iter()
        .any(|name| durable.join(name).is_file())
    {
        return Ok(false);
    }
    fs::create_dir_all(dest_dir)
        .map_err(|error| format!("No se pudo recrear identidad de host: {error}"))?;
    for name in IDENTITY_FILES {
        copy_if_present(&durable.join(name), &dest_dir.join(name))?;
    }
    Ok(true)
}

pub fn evaluate_continuity_status(status: Option<&RemoteAttestationContinuity>) -> ContinuityGate {
    let Some(status) = status else {
        return ContinuityGate::Pending;
    };
    let haystack = format!(
        "{} {} {}",
        status.decision,
        status.continuity_state,
        status.reason_code.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    if haystack.contains("migration_required")
        || haystack.contains("rotation_required")
        || haystack.contains("reanchor_required")
        || haystack.contains("journal_change")
        || haystack.contains("fatal")
        || haystack.contains("center_ahead")
    {
        return ContinuityGate::Blocked;
    }
    if status.continuity_state == "current"
        || status.continuity_state == "continuity_restored"
        || status.decision == "accepted"
        || status.decision == "accepted_duplicate"
        || status.decision == "accepted_first"
        || status.decision == "accepted_first_legacy"
        || status.decision == "accepted_advance"
    {
        return ContinuityGate::Current;
    }
    ContinuityGate::Pending
}

pub fn read_continuity_status(node_root: &Path) -> Result<Option<RemoteAttestationContinuity>, String> {
    let path = node_root.join(CONTINUITY_STATUS_RELATIVE);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("No se pudo leer continuidad remota: {error}"))?;
    let status = serde_json::from_slice::<RemoteAttestationContinuity>(&bytes)
        .map_err(|error| format!("ATTESTATION_CONTINUITY_CORRUPT: {error}"))?;
    Ok(Some(status))
}

pub fn continuity_gate_error(gate: ContinuityGate, status: Option<&RemoteAttestationContinuity>) -> Option<String> {
    match gate {
        ContinuityGate::Current => None,
        ContinuityGate::Pending => Some(
            "ATTESTATION_CONTINUITY_PENDING: el Agent aun no confirmo aceptacion remota.".to_string(),
        ),
        ContinuityGate::Blocked => {
            let reason = status
                .and_then(|value| value.reason_code.clone())
                .or_else(|| status.map(|value| value.decision.clone()))
                .unwrap_or_else(|| "remote_attestation_blocked".to_string());
            Some(format!("ATTESTATION_CONTINUITY_BLOCKED: {reason}"))
        }
    }
}

pub fn evaluate_desired_payload_gate(
    local_runtime_release: &str,
    local_payload_digest: &str,
    desired: Option<&DesiredPayloadPin>,
) -> Result<(), String> {
    let Some(desired) = desired else {
        return Ok(());
    };
    if desired.runtime_release != local_runtime_release
        || desired.payload_digest != local_payload_digest
    {
        return Err(format!(
            "PAYLOAD_DESIRED_MISMATCH: local {}/{} no coincide con desired {}/{}.",
            local_runtime_release,
            &local_payload_digest[..local_payload_digest.len().min(12)],
            desired.runtime_release,
            &desired.payload_digest[..desired.payload_digest.len().min(12)]
        ));
    }
    Ok(())
}

pub fn read_desired_payload_pin(node_root: &Path) -> Result<Option<DesiredPayloadPin>, String> {
    let path = node_root.join(DESIRED_PAYLOAD_RELATIVE);
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("No se pudo leer desired payload: {error}"))?;
    let pin = serde_json::from_slice::<DesiredPayloadPin>(&bytes)
        .map_err(|error| format!("DESIRED_PAYLOAD_CORRUPT: {error}"))?;
    if pin.runtime_release.is_empty() || pin.payload_digest.len() != 64 {
        return Err("DESIRED_PAYLOAD_CORRUPT".to_string());
    }
    Ok(Some(pin))
}

pub fn evaluate_journal_supersede(request: JournalSupersedeRequest<'_>) -> Result<(), String> {
    if !request.owner_authorized {
        return Err("JOURNAL_SUPERSEDE_OWNER_REQUIRED".to_string());
    }
    if request.pinned_journal_id.is_empty() || request.incoming_journal_id.is_empty() {
        return Err("JOURNAL_SUPERSEDE_SCOPE_INVALID".to_string());
    }
    if request.pinned_journal_id == request.incoming_journal_id {
        return Err("JOURNAL_SUPERSEDE_NO_CHANGE".to_string());
    }
    if request.confirmation != request.pinned_journal_id {
        return Err("JOURNAL_SUPERSEDE_CONFIRMATION_MISMATCH".to_string());
    }
    if !matches!(
        request.reason,
        "disk_wipe" | "key_compromise" | "host_rebuild" | "reinstall"
    ) {
        return Err("JOURNAL_SUPERSEDE_REASON_INVALID".to_string());
    }
    Ok(())
}

fn copy_journal_artifacts(source: &Path, dest: &Path) -> Result<(), String> {
    for name in JOURNAL_FILES {
        copy_if_present(&source.join(name), &dest.join(name))?;
    }
    for name in JOURNAL_DIRS {
        copy_dir_files(&source.join(name), &dest.join(name))?;
    }
    Ok(())
}

fn copy_if_present(source: &Path, dest: &Path) -> Result<(), String> {
    if !source.is_file() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("No se pudo crear {}: {error}", parent.display()))?;
    }
    fs::copy(source, dest).map_err(|error| {
        format!(
            "No se pudo copiar {} -> {}: {error}",
            source.display(),
            dest.display()
        )
    })?;
    Ok(())
}

fn copy_dir_files(source: &Path, dest: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dest)
        .map_err(|error| format!("No se pudo crear {}: {error}", dest.display()))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("No se pudo leer {}: {error}", source.display()))?
    {
        let entry = entry.map_err(|error| format!("Entrada invalida: {error}"))?;
        let path = entry.path();
        if path.is_file() {
            let dest_file = dest.join(entry.file_name());
            fs::copy(&path, &dest_file).map_err(|error| {
                format!("No se pudo copiar {}: {error}", path.display())
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("actium-continuity-{label}-{}", Uuid::new_v4()))
    }

    fn write_file(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    #[test]
    fn journal_sobrevive_wipe_del_nodo() {
        let root = temp_root("wipe");
        let supervisor = root.join("nodes/home/state/supervisor");
        let durable = host_deployment_attestation_dir(
            &host_identities_root(&root.join("nodes")),
            "host-1",
            "deploy-1",
        );
        write_file(
            &supervisor.join(JOURNAL_METADATA_FILE),
            r#"{"journalId":"8653442c-aa85-47fa-a902-22430a9e0fb6"}"#,
        );
        write_file(&supervisor.join("material-attestations-v1/0001.json"), "{\"seq\":1}");
        snapshot_attestation_journal(&supervisor, &durable).unwrap();

        fs::remove_dir_all(root.join("nodes/home")).unwrap();
        let restored = root.join("nodes/home/state/supervisor");
        assert!(restore_attestation_journal(&durable, &restored).unwrap());
        let meta = fs::read_to_string(restored.join(JOURNAL_METADATA_FILE)).unwrap();
        assert!(meta.contains("8653442c-aa85-47fa-a902-22430a9e0fb6"));
        assert!(restored.join("material-attestations-v1/0001.json").is_file());
        assert!(!restore_attestation_journal(&durable, &restored).unwrap());
    }

    #[test]
    fn no_restaura_si_no_hay_journal_durable() {
        let root = temp_root("empty");
        let dest = root.join("state/supervisor");
        assert!(!restore_attestation_journal(&root.join("missing"), &dest).unwrap());
        assert!(!dest.join(JOURNAL_METADATA_FILE).exists());
    }

    #[test]
    fn continuidad_bloquea_migration_required() {
        let blocked = RemoteAttestationContinuity {
            schema: 1,
            decision: "migration_required".into(),
            continuity_state: "migration_required".into(),
            reason_code: Some("REMOTE_JOURNAL_CHANGE_REQUIRES_CEREMONY".into()),
            journal_id: Some("7252d9b2-0850-4825-85a1-4c7e7dbc3230".into()),
            observed_at: "2026-08-29T13:13:24Z".into(),
        };
        assert_eq!(
            evaluate_continuity_status(Some(&blocked)),
            ContinuityGate::Blocked
        );
        let error = continuity_gate_error(ContinuityGate::Blocked, Some(&blocked)).unwrap();
        assert!(error.starts_with("ATTESTATION_CONTINUITY_BLOCKED"));
        assert!(error.contains("REMOTE_JOURNAL_CHANGE_REQUIRES_CEREMONY"));
    }

    #[test]
    fn continuidad_aceptada_y_pendiente() {
        let current = RemoteAttestationContinuity {
            schema: 1,
            decision: "accepted_advance".into(),
            continuity_state: "current".into(),
            reason_code: None,
            journal_id: None,
            observed_at: "2026-08-29T13:13:24Z".into(),
        };
        assert_eq!(
            evaluate_continuity_status(Some(&current)),
            ContinuityGate::Current
        );
        assert_eq!(evaluate_continuity_status(None), ContinuityGate::Pending);
        assert!(continuity_gate_error(ContinuityGate::Pending, None)
            .unwrap()
            .starts_with("ATTESTATION_CONTINUITY_PENDING"));
    }

    #[test]
    fn payload_gate_falla_si_desired_diverge() {
        let desired = DesiredPayloadPin {
            schema: 1,
            runtime_release: "0.8.0-rc.1".into(),
            payload_digest: "d".repeat(64),
        };
        let err = evaluate_desired_payload_gate("0.8.0-lab.32", &"e".repeat(64), Some(&desired))
            .unwrap_err();
        assert!(err.starts_with("PAYLOAD_DESIRED_MISMATCH"));
        evaluate_desired_payload_gate("0.8.0-rc.1", &"d".repeat(64), Some(&desired)).unwrap();
        evaluate_desired_payload_gate("0.8.0-lab.32", &"e".repeat(64), None).unwrap();
    }

    #[test]
    fn ceremonia_exige_owner_razon_y_confirmacion() {
        let pinned = "8653442c-aa85-47fa-a902-22430a9e0fb6";
        let incoming = "7252d9b2-0850-4825-85a1-4c7e7dbc3230";
        assert_eq!(
            evaluate_journal_supersede(JournalSupersedeRequest {
                owner_authorized: false,
                pinned_journal_id: pinned,
                incoming_journal_id: incoming,
                reason: "disk_wipe",
                confirmation: pinned,
            })
            .unwrap_err(),
            "JOURNAL_SUPERSEDE_OWNER_REQUIRED"
        );
        evaluate_journal_supersede(JournalSupersedeRequest {
            owner_authorized: true,
            pinned_journal_id: pinned,
            incoming_journal_id: incoming,
            reason: "disk_wipe",
            confirmation: pinned,
        })
        .unwrap();
        assert_eq!(
            evaluate_journal_supersede(JournalSupersedeRequest {
                owner_authorized: true,
                pinned_journal_id: pinned,
                incoming_journal_id: incoming,
                reason: "porque-si",
                confirmation: pinned,
            })
            .unwrap_err(),
            "JOURNAL_SUPERSEDE_REASON_INVALID"
        );
    }

    #[test]
    fn host_identities_detecta_journal_canonico() {
        let nodes = temp_root("scan").join("nodes");
        let durable = host_deployment_attestation_dir(
            &host_identities_root(&nodes),
            "host-1",
            "deploy-1",
        );
        write_file(&durable.join(JOURNAL_METADATA_FILE), "{}");
        assert!(host_identities_have_canonical_journal(&host_identities_root(
            &nodes
        )));
        assert!(!host_identities_have_canonical_journal(
            &temp_root("scan-empty").join("host-identities")
        ));
    }
}
