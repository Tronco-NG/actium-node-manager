use crate::durability::{
    publish_immutable, replace_durable, DurabilityGuarantee, PublicationFailure, PublicationOutcome,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const MATERIAL_ATTESTATION_SCHEMA: u8 = 1;
const ATTESTATION_RECORD_SCHEMA: u8 = 2;
const ATTESTATION_JOURNAL_SCHEMA: u8 = 2;
const ATTESTATION_HEAD_SCHEMA: u8 = 1;
const ATTESTATION_ANCHOR_SCHEMA: u8 = 1;
const MAX_RETAINED_RECORDS: usize = 256;
const COMPACT_TO_RECORDS: usize = 128;
const MAX_UNCHANGED_SECONDS: u64 = 240;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialAttestationEnvelope {
    pub schema: u8,
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub statement: MaterialAttestationStatement,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialAttestationStatement {
    pub host_id: String,
    pub deployment_id: String,
    pub sequence: u64,
    pub generation: u64,
    pub runtime_release: Option<String>,
    pub payload_digest: Option<String>,
    pub material_digest: String,
    pub observed_at: String,
    pub runtime_units: Vec<AttestedRuntimeUnit>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub journal_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attestation_identity_id: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub identity_epoch: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub release_revision: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub topology_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub configuration_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observation_started_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub observation_completed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestedRuntimeUnit {
    pub runtime_unit_id: String,
    pub capability: String,
    pub dependency_scope: String,
    pub compose_project: String,
    pub effective_config_digest: String,
    pub health: String,
    pub lifecycle_state: String,
    pub started_at: Option<String>,
    pub containers: Vec<AttestedContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestedContainer {
    pub workload_code: Option<String>,
    pub compose_service: String,
    pub container_id: String,
    pub image_reference: String,
    pub image_id: String,
    pub repo_digest: Option<String>,
    pub effective_config_digest: String,
    pub health: String,
    pub lifecycle_state: String,
    pub started_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttestationSigner {
    key_path: PathBuf,
    signing_key: SigningKey,
    identity_id: String,
    identity_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationAuthorityState {
    NewInstallation,
    LegacyJournal,
    CanonicalJournal,
}

#[derive(Debug, Clone)]
pub struct AttestationJournal {
    supervisor_state: PathBuf,
    persistence_faults: Arc<Mutex<VecDeque<String>>>,
    metrics: Arc<AttestationJournalMetrics>,
}

#[derive(Debug, Default)]
struct AttestationJournalMetrics {
    head_reads: AtomicU64,
    record_reads: AtomicU64,
    directory_scans: AtomicU64,
    signature_verifications: AtomicU64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestationJournalStats {
    pub head_reads: u64,
    pub record_reads: u64,
    pub directory_scans: u64,
    pub signature_verifications: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationPublishDisposition {
    Published,
    ReusedUnchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPublishResult {
    pub envelope: MaterialAttestationEnvelope,
    pub disposition: AttestationPublishDisposition,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationIdentityMetadata {
    schema: u8,
    identity_id: String,
    identity_epoch: u64,
    key_id: String,
    public_key: String,
    previous_key_id: Option<String>,
    rotation_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationJournalMetadata {
    schema: u8,
    journal_id: String,
    identity_id: String,
    identity_epoch: u64,
    key_id: String,
    public_key: String,
    host_id: String,
    deployment_id: String,
    genesis_sequence: u64,
    genesis_record_sha256: String,
    legacy_migrated: bool,
    initialized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationHead {
    schema: u8,
    journal_id: String,
    identity_id: String,
    identity_epoch: u64,
    key_id: String,
    host_id: String,
    deployment_id: String,
    sequence: u64,
    record_sha256: String,
    record_file: String,
    material_snapshot_sha256: String,
    published_at_unix: u64,
    anchor_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PendingAttestationPublication {
    schema: u8,
    journal_id: String,
    sequence: u64,
    record_sha256: String,
    record_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationAnchorBody {
    schema: u8,
    journal_id: String,
    identity_id: String,
    identity_epoch: u64,
    key_id: String,
    host_id: String,
    deployment_id: String,
    sequence: u64,
    record_sha256: String,
    previous_anchor_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationAnchor {
    #[serde(flatten)]
    body: AttestationAnchorBody,
    public_key: String,
    signature: String,
    anchor_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationRecordBody {
    schema: u8,
    sequence: u64,
    previous_record_sha256: Option<String>,
    envelope: MaterialAttestationEnvelope,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    journal_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    identity_id: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    identity_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationRecord {
    #[serde(flatten)]
    body: AttestationRecordBody,
    record_sha256: String,
}

impl AttestationSigner {
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::load(path.into(), AttestationAuthorityState::NewInstallation)
    }

    pub fn load_existing(path: impl Into<PathBuf>) -> Result<Self, String> {
        Self::load(path.into(), AttestationAuthorityState::CanonicalJournal)
    }

    pub fn load_for_authority(
        path: impl Into<PathBuf>,
        authority: AttestationAuthorityState,
    ) -> Result<Self, String> {
        Self::load(path.into(), authority)
    }

    fn load(key_path: PathBuf, authority: AttestationAuthorityState) -> Result<Self, String> {
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("No se pudo crear el directorio de atestacion: {error}")
            })?;
        }
        let identity_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(key_path.with_extension("identity.lock"))
            .map_err(|error| format!("No se pudo abrir lock de identidad: {error}"))?;
        identity_lock
            .lock_exclusive()
            .map_err(|error| format!("No se pudo adquirir lock de identidad: {error}"))?;
        let metadata_path = identity_metadata_path(&key_path);
        let existing_metadata = metadata_path
            .is_file()
            .then(|| read_identity_metadata(&metadata_path))
            .transpose()?;
        if authority == AttestationAuthorityState::CanonicalJournal && existing_metadata.is_none() {
            return Err(
                "ATTESTATION_IDENTITY_MISSING: journal canonico existe sin metadata de identidad."
                    .to_string(),
            );
        }
        if existing_metadata.is_some() && !key_path.is_file() {
            return Err(
                "ATTESTATION_IDENTITY_MISSING: existe identidad fijada sin clave privada."
                    .to_string(),
            );
        }
        if !key_path.is_file() {
            if authority != AttestationAuthorityState::NewInstallation {
                return Err("ATTESTATION_IDENTITY_MISSING: no existe clave privada.".to_string());
            }
            let candidate = SigningKey::generate(&mut OsRng);
            persist_secret_create_new(&key_path, &hex(candidate.as_bytes()))?;
        }
        let signing_key = read_signing_key(&key_path)?;
        let key_id = key_id_for(&signing_key.verifying_key());
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
        let metadata = match existing_metadata {
            Some(metadata) => {
                if metadata.key_id != key_id || metadata.public_key != public_key {
                    return Err(
                        "ATTESTATION_IDENTITY_MISMATCH: la clave privada no coincide con la identidad fijada."
                            .to_string(),
                    );
                }
                if metadata.rotation_status != "active" {
                    return Err(
                        "ATTESTATION_ROTATION_REQUIRED: la identidad no esta activa.".to_string(),
                    );
                }
                metadata
            }
            None => {
                let metadata = AttestationIdentityMetadata {
                    schema: 1,
                    identity_id: Uuid::new_v4().to_string(),
                    identity_epoch: 1,
                    key_id,
                    public_key,
                    previous_key_id: None,
                    rotation_status: "active".to_string(),
                };
                let bytes = serde_json::to_vec_pretty(&metadata)
                    .map_err(|error| format!("No se pudo serializar identidad: {error}"))?;
                strict_immutable_publication(
                    &metadata_path,
                    &bytes,
                    |_| Ok(()),
                    "ATTESTATION_IDENTITY",
                )?;
                metadata
            }
        };
        let _ = FileExt::unlock(&identity_lock);
        Ok(Self {
            key_path,
            signing_key,
            identity_id: metadata.identity_id,
            identity_epoch: metadata.identity_epoch,
        })
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn key_id(&self) -> String {
        key_id_for(&self.signing_key.verifying_key())
    }

    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn identity_epoch(&self) -> u64 {
        self.identity_epoch
    }

    pub fn identity_id(&self) -> String {
        self.identity_id.clone()
    }

    pub fn sign(
        &self,
        statement: MaterialAttestationStatement,
    ) -> Result<MaterialAttestationEnvelope, String> {
        let value = serde_json::to_value(&statement)
            .map_err(|error| format!("No se pudo serializar la atestacion: {error}"))?;
        let canonical = canonical_json(&value)?;
        let signature = self.signing_key.sign(canonical.as_bytes());
        Ok(MaterialAttestationEnvelope {
            schema: MATERIAL_ATTESTATION_SCHEMA,
            algorithm: "Ed25519".to_string(),
            key_id: self.key_id(),
            public_key: self.public_key(),
            statement,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    fn sign_serializable(&self, value: &impl Serialize) -> Result<String, String> {
        let value = serde_json::to_value(value)
            .map_err(|error| format!("No se pudo serializar anchor: {error}"))?;
        Ok(URL_SAFE_NO_PAD.encode(
            self.signing_key
                .sign(canonical_json(&value)?.as_bytes())
                .to_bytes(),
        ))
    }
}

pub fn verify_material_attestation(envelope: &MaterialAttestationEnvelope) -> Result<(), String> {
    if envelope.schema != MATERIAL_ATTESTATION_SCHEMA || envelope.algorithm != "Ed25519" {
        return Err("Atestacion material usa schema o algoritmo incompatible.".to_string());
    }
    let key = verifying_key(&envelope.public_key)?;
    if envelope.key_id != key_id_for(&key) {
        return Err("keyId de atestacion no coincide con su public key.".to_string());
    }
    verify_serialized(&key, &envelope.statement, &envelope.signature)
        .map_err(|_| "Firma material Ed25519 no verificable.".to_string())
}

impl AttestationJournal {
    pub fn new(supervisor_state: impl Into<PathBuf>) -> Self {
        Self {
            supervisor_state: supervisor_state.into(),
            persistence_faults: Arc::new(Mutex::new(VecDeque::new())),
            metrics: Arc::new(AttestationJournalMetrics::default()),
        }
    }

    #[cfg(any(test, feature = "fault-injection"))]
    pub fn with_persistence_faults(
        supervisor_state: impl Into<PathBuf>,
        faults: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            supervisor_state: supervisor_state.into(),
            persistence_faults: Arc::new(Mutex::new(faults.into_iter().map(Into::into).collect())),
            metrics: Arc::new(AttestationJournalMetrics::default()),
        }
    }

    pub fn stats(&self) -> AttestationJournalStats {
        AttestationJournalStats {
            head_reads: self.metrics.head_reads.load(Ordering::Relaxed),
            record_reads: self.metrics.record_reads.load(Ordering::Relaxed),
            directory_scans: self.metrics.directory_scans.load(Ordering::Relaxed),
            signature_verifications: self.metrics.signature_verifications.load(Ordering::Relaxed),
        }
    }

    pub fn sign_and_publish<F>(
        &self,
        signer: &AttestationSigner,
        build_statement: F,
    ) -> Result<MaterialAttestationEnvelope, String>
    where
        F: FnOnce(u64) -> Result<MaterialAttestationStatement, String>,
    {
        self.sign_and_publish_result(signer, build_statement)
            .map(|result| result.envelope)
    }

    pub fn sign_and_publish_result<F>(
        &self,
        signer: &AttestationSigner,
        build_statement: F,
    ) -> Result<AttestationPublishResult, String>
    where
        F: FnOnce(u64) -> Result<MaterialAttestationStatement, String>,
    {
        fs::create_dir_all(&self.supervisor_state)
            .map_err(|error| format!("No se pudo crear estado autoritativo: {error}"))?;
        let lock = self.acquire_lock(false)?;
        let latest = self.load_latest_record(Some(signer))?;
        let sequence = latest
            .as_ref()
            .map(|(record, _)| record.body.sequence)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| "Secuencia de atestacion agotada.".to_string())?;
        let mut statement = build_statement(sequence)?;
        if statement.sequence != sequence {
            return Err("Builder de atestacion altero la secuencia asignada.".to_string());
        }
        validate_uuid_scope(&statement.host_id, &statement.deployment_id)?;
        let mut metadata = self.ensure_metadata(signer, &statement, latest.as_ref())?;
        statement.journal_id = metadata.journal_id.clone();
        statement.attestation_identity_id = metadata.identity_id.clone();
        statement.identity_epoch = metadata.identity_epoch;
        let fingerprint = material_snapshot_sha256(&statement)?;
        if let Some((record, head)) = latest.as_ref() {
            if head.material_snapshot_sha256 == fingerprint
                && now_unix().saturating_sub(head.published_at_unix) < MAX_UNCHANGED_SECONDS
            {
                let _ = self.sync_derived_views(&record.body.envelope);
                let _ = FileExt::unlock(&lock);
                return Ok(AttestationPublishResult {
                    envelope: record.body.envelope.clone(),
                    disposition: AttestationPublishDisposition::ReusedUnchanged,
                });
            }
        }
        let envelope = signer.sign(statement)?;
        self.validate_envelope_scope(&metadata, &envelope, signer)?;
        let body = AttestationRecordBody {
            schema: ATTESTATION_RECORD_SCHEMA,
            sequence,
            previous_record_sha256: latest
                .as_ref()
                .map(|(record, _)| record.record_sha256.clone()),
            envelope: envelope.clone(),
            journal_id: metadata.journal_id.clone(),
            identity_id: metadata.identity_id.clone(),
            identity_epoch: metadata.identity_epoch,
        };
        let record = AttestationRecord {
            record_sha256: sha256_json(&body)?,
            body,
        };
        if metadata.genesis_record_sha256.is_empty() {
            metadata.genesis_record_sha256 = record.record_sha256.clone();
            metadata.genesis_sequence = record.body.sequence;
            self.persist_metadata_replace(&metadata)?;
        }
        let record_file = record_file_name(&record);
        let pending = PendingAttestationPublication {
            schema: 1,
            journal_id: metadata.journal_id.clone(),
            sequence,
            record_sha256: record.record_sha256.clone(),
            record_file: record_file.clone(),
        };
        self.write_pending(&pending)?;
        self.persist_record_strict(&record)?;
        let anchor_sequence = self
            .load_anchor(Some(&metadata))?
            .map_or(0, |value| value.body.sequence);
        let head = AttestationHead {
            schema: ATTESTATION_HEAD_SCHEMA,
            journal_id: metadata.journal_id.clone(),
            identity_id: metadata.identity_id.clone(),
            identity_epoch: metadata.identity_epoch,
            key_id: metadata.key_id.clone(),
            host_id: metadata.host_id.clone(),
            deployment_id: metadata.deployment_id.clone(),
            sequence,
            record_sha256: record.record_sha256.clone(),
            record_file,
            material_snapshot_sha256: fingerprint,
            published_at_unix: now_unix(),
            anchor_sequence,
        };
        self.persist_head(&head)?;
        self.clear_pending()?;
        if !metadata.initialized {
            metadata.initialized = true;
            self.persist_metadata_replace(&metadata)?;
        }
        self.compact_if_needed(signer, &metadata, &head)?;
        let _ = self.sync_derived_views(&envelope);
        let _ = FileExt::unlock(&lock);
        Ok(AttestationPublishResult {
            envelope,
            disposition: AttestationPublishDisposition::Published,
        })
    }

    pub fn latest(&self) -> Result<Option<MaterialAttestationEnvelope>, String> {
        fs::create_dir_all(&self.supervisor_state)
            .map_err(|error| format!("No se pudo crear estado autoritativo: {error}"))?;
        let lock = self.acquire_lock(false)?;
        let result = self
            .load_latest_record(None)?
            .map(|(record, _)| record.body.envelope);
        if let Some(envelope) = result.as_ref() {
            let _ = self.sync_derived_views(envelope);
        }
        let _ = FileExt::unlock(&lock);
        Ok(result)
    }

    pub fn audit_retained_chain(&self) -> Result<usize, String> {
        let lock = self.acquire_lock(false)?;
        let metadata = self
            .load_metadata()?
            .ok_or_else(|| "ATTESTATION_JOURNAL_NOT_INITIALIZED".to_string())?;
        let anchor = self.load_anchor(Some(&metadata))?;
        let mut paths = self.record_paths()?;
        paths.sort();
        let mut previous_sequence = anchor
            .as_ref()
            .map(|value| value.body.sequence)
            .unwrap_or(metadata.genesis_sequence.saturating_sub(1));
        let mut previous_hash = anchor
            .as_ref()
            .map(|value| value.body.record_sha256.clone());
        for path in &paths {
            let record = self.read_record(path)?;
            self.validate_record_scope(&metadata, &record)?;
            if record.body.sequence != previous_sequence.saturating_add(1)
                || record.body.previous_record_sha256 != previous_hash
            {
                return Err("ATTESTATION_STATE_CORRUPT: cadena retenida invalida.".to_string());
            }
            previous_sequence = record.body.sequence;
            previous_hash = Some(record.record_sha256.clone());
        }
        let head = self
            .load_head()?
            .ok_or_else(|| "ATTESTATION_HEAD_MISSING".to_string())?;
        if previous_sequence != head.sequence
            || previous_hash.as_deref() != Some(head.record_sha256.as_str())
        {
            return Err("ATTESTATION_HEAD_MISMATCH".to_string());
        }
        let _ = FileExt::unlock(&lock);
        Ok(paths.len())
    }

    fn acquire_lock(&self, nonblocking: bool) -> Result<File, String> {
        let path = self.supervisor_state.join("attestation-mutation.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("No se pudo abrir lock de atestacion: {error}"))?;
        let result = if nonblocking {
            file.try_lock_exclusive()
        } else {
            file.lock_exclusive()
        };
        result.map_err(|error| {
            if nonblocking && error.kind() == std::io::ErrorKind::WouldBlock {
                "ATTESTATION_BUSY".to_string()
            } else {
                format!("No se pudo adquirir lock de atestacion: {error}")
            }
        })?;
        Ok(file)
    }

    fn records_path(&self) -> PathBuf {
        self.supervisor_state.join("material-attestations-v1")
    }

    fn metadata_path(&self) -> PathBuf {
        self.supervisor_state
            .join("attestation-journal-v1.initialized.json")
    }

    fn head_path(&self) -> PathBuf {
        self.supervisor_state
            .join("material-attestation-head-v1.json")
    }

    fn anchor_path(&self) -> PathBuf {
        self.supervisor_state
            .join("material-attestation-anchor-v1.json")
    }

    fn pending_path(&self) -> PathBuf {
        self.supervisor_state
            .join("attestation-publication-pending-v1.json")
    }

    fn load_latest_record(
        &self,
        signer: Option<&AttestationSigner>,
    ) -> Result<Option<(AttestationRecord, AttestationHead)>, String> {
        if let Some(mut metadata) = self.load_metadata()? {
            if let Some(signer) = signer {
                self.validate_signer(&metadata, signer)?;
            }
            self.recover_pending(&metadata)?;
            if !metadata.initialized {
                if self.load_head()?.is_none() && !has_json_records(&self.records_path())? {
                    return Ok(None);
                }
                let head = self
                    .load_head()?
                    .ok_or_else(|| "ATTESTATION_GENESIS_INCOMPLETE".to_string())?;
                self.validate_head_scope(&metadata, &head)?;
                let record_path = self.records_path().join(&head.record_file);
                let record = self.read_record(&record_path)?;
                self.validate_record_scope(&metadata, &record)?;
                if record.body.sequence != head.sequence
                    || record.record_sha256 != head.record_sha256
                {
                    return Err("ATTESTATION_GENESIS_INCOMPLETE".to_string());
                }
                metadata.initialized = true;
                self.persist_metadata_replace(&metadata)?;
            }
            let head = self.load_head()?.ok_or_else(|| {
                "ATTESTATION_JOURNAL_MISSING: canonical head ausente.".to_string()
            })?;
            self.validate_head_scope(&metadata, &head)?;
            let record_path = self.records_path().join(&head.record_file);
            if !record_path.is_file() {
                return Err(
                    "ATTESTATION_JOURNAL_MISSING: head apunta a record ausente.".to_string()
                );
            }
            let record = self.read_record(&record_path)?;
            self.validate_record_scope(&metadata, &record)?;
            if record.body.sequence != head.sequence || record.record_sha256 != head.record_sha256 {
                return Err("ATTESTATION_HEAD_MISMATCH".to_string());
            }
            return Ok(Some((record, head)));
        }
        self.migrate_legacy(signer)
    }

    fn migrate_legacy(
        &self,
        signer: Option<&AttestationSigner>,
    ) -> Result<Option<(AttestationRecord, AttestationHead)>, String> {
        let mut paths = self.record_paths()?;
        paths.sort();
        if !paths.is_empty() {
            let mut previous_hash = None;
            let mut previous_sequence = 0;
            let mut first = None;
            let mut latest = None;
            for path in &paths {
                let record = self.read_record(path)?;
                if record.body.schema >= ATTESTATION_RECORD_SCHEMA
                    || !record.body.envelope.statement.journal_id.is_empty()
                {
                    return Err(
                        "ATTESTATION_JOURNAL_MARKER_MISSING: records administrados no pueden remigrarse."
                            .to_string(),
                    );
                }
                if previous_sequence == 0 && record.body.sequence != 1 {
                    return Err("ATTESTATION_JOURNAL_GENESIS_MISSING".to_string());
                }
                if previous_sequence > 0
                    && (record.body.sequence != previous_sequence + 1
                        || record.body.previous_record_sha256 != previous_hash)
                {
                    return Err("ATTESTATION_STATE_CORRUPT: cadena legacy invalida.".to_string());
                }
                if let Some(first) = first.as_ref() {
                    ensure_same_envelope_scope(first, &record.body.envelope)?;
                } else {
                    first = Some(record.body.envelope.clone());
                }
                previous_sequence = record.body.sequence;
                previous_hash = Some(record.record_sha256.clone());
                latest = Some(record);
            }
            let latest = latest.expect("paths no vacio");
            let first = first.expect("paths no vacio");
            if let Some(signer) = signer {
                if signer.key_id() != first.key_id || signer.public_key() != first.public_key {
                    return Err("ATTESTATION_IDENTITY_MISMATCH".to_string());
                }
            }
            let metadata =
                self.create_metadata(signer, &first, 1, &read_record_sha(&paths[0])?, true, true)?;
            let head = self.head_from_record(&metadata, &latest)?;
            self.persist_head(&head)?;
            return Ok(Some((latest, head)));
        }
        let Some(envelope) = self.load_legacy_envelope()? else {
            return Ok(None);
        };
        if let Some(signer) = signer {
            if signer.key_id() != envelope.key_id || signer.public_key() != envelope.public_key {
                return Err("ATTESTATION_IDENTITY_MISMATCH".to_string());
            }
        }
        let body = AttestationRecordBody {
            schema: 1,
            sequence: envelope.statement.sequence,
            previous_record_sha256: None,
            envelope: envelope.clone(),
            journal_id: String::new(),
            identity_id: String::new(),
            identity_epoch: 0,
        };
        let record = AttestationRecord {
            record_sha256: sha256_json(&body)?,
            body,
        };
        let metadata = self.create_metadata(
            signer,
            &envelope,
            record.body.sequence,
            &record.record_sha256,
            true,
            false,
        )?;
        self.persist_record_without_faults(&record)?;
        let head = self.head_from_record(&metadata, &record)?;
        self.persist_head(&head)?;
        let mut initialized = metadata;
        initialized.initialized = true;
        self.persist_metadata_replace(&initialized)?;
        Ok(Some((record, head)))
    }

    fn ensure_metadata(
        &self,
        signer: &AttestationSigner,
        statement: &MaterialAttestationStatement,
        latest: Option<&(AttestationRecord, AttestationHead)>,
    ) -> Result<AttestationJournalMetadata, String> {
        if let Some(metadata) = self.load_metadata()? {
            if !metadata.initialized && latest.is_none() {
                let updated = AttestationJournalMetadata {
                    host_id: statement.host_id.clone(),
                    deployment_id: statement.deployment_id.clone(),
                    key_id: signer.key_id(),
                    public_key: signer.public_key(),
                    identity_id: signer.identity_id(),
                    identity_epoch: signer.identity_epoch(),
                    ..metadata
                };
                self.persist_metadata_replace(&updated)?;
                return Ok(updated);
            }
            self.validate_signer(&metadata, signer)?;
            if metadata.host_id != statement.host_id
                || metadata.deployment_id != statement.deployment_id
            {
                return Err("ATTESTATION_SCOPE_MISMATCH".to_string());
            }
            return Ok(metadata);
        }
        let journal_id = Uuid::new_v4().to_string();
        let metadata = AttestationJournalMetadata {
            schema: ATTESTATION_JOURNAL_SCHEMA,
            journal_id,
            identity_id: signer.identity_id(),
            identity_epoch: signer.identity_epoch(),
            key_id: signer.key_id(),
            public_key: signer.public_key(),
            host_id: statement.host_id.clone(),
            deployment_id: statement.deployment_id.clone(),
            genesis_sequence: statement.sequence,
            genesis_record_sha256: String::new(),
            legacy_migrated: false,
            initialized: false,
        };
        self.persist_metadata_create(&metadata)?;
        Ok(metadata)
    }

    fn create_metadata(
        &self,
        signer: Option<&AttestationSigner>,
        envelope: &MaterialAttestationEnvelope,
        genesis_sequence: u64,
        genesis_record_sha256: &str,
        legacy_migrated: bool,
        initialized: bool,
    ) -> Result<AttestationJournalMetadata, String> {
        validate_uuid_scope(
            &envelope.statement.host_id,
            &envelope.statement.deployment_id,
        )?;
        let metadata = AttestationJournalMetadata {
            schema: ATTESTATION_JOURNAL_SCHEMA,
            journal_id: if envelope.statement.journal_id.is_empty() {
                Uuid::new_v4().to_string()
            } else {
                envelope.statement.journal_id.clone()
            },
            identity_id: signer
                .map(AttestationSigner::identity_id)
                .ok_or_else(|| "ATTESTATION_LEGACY_MIGRATION_REQUIRES_IDENTITY".to_string())?,
            identity_epoch: signer.map_or(1, AttestationSigner::identity_epoch),
            key_id: envelope.key_id.clone(),
            public_key: envelope.public_key.clone(),
            host_id: envelope.statement.host_id.clone(),
            deployment_id: envelope.statement.deployment_id.clone(),
            genesis_sequence,
            genesis_record_sha256: genesis_record_sha256.to_string(),
            legacy_migrated,
            initialized,
        };
        self.persist_metadata_create(&metadata)?;
        Ok(metadata)
    }

    fn persist_metadata_create(&self, metadata: &AttestationJournalMetadata) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(metadata)
            .map_err(|error| format!("No se pudo serializar genesis de atestacion: {error}"))?;
        strict_immutable_publication(
            &self.metadata_path(),
            &bytes,
            |_| Ok(()),
            "ATTESTATION_GENESIS",
        )
    }

    fn persist_metadata_replace(
        &self,
        metadata: &AttestationJournalMetadata,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(metadata)
            .map_err(|error| format!("No se pudo serializar genesis de atestacion: {error}"))?;
        strict_replace_publication(
            &self.metadata_path(),
            &bytes,
            |_| Ok(()),
            "ATTESTATION_GENESIS",
        )
    }

    fn load_metadata(&self) -> Result<Option<AttestationJournalMetadata>, String> {
        let path = self.metadata_path();
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("No se pudo leer genesis de atestacion: {error}"))?;
        let metadata = serde_json::from_slice::<AttestationJournalMetadata>(&bytes)
            .map_err(|error| format!("ATTESTATION_JOURNAL_METADATA_CORRUPT: {error}"))?;
        if metadata.schema != ATTESTATION_JOURNAL_SCHEMA
            || Uuid::parse_str(&metadata.journal_id).is_err()
            || Uuid::parse_str(&metadata.identity_id).is_err()
            || metadata.identity_epoch == 0
            || !valid_key_id(&metadata.key_id)
            || metadata.public_key.len() != 43
            || Uuid::parse_str(&metadata.host_id).is_err()
            || Uuid::parse_str(&metadata.deployment_id).is_err()
            || metadata.genesis_sequence == 0
            || (metadata.initialized && metadata.genesis_record_sha256.len() != 64)
        {
            return Err("ATTESTATION_JOURNAL_METADATA_CORRUPT".to_string());
        }
        Ok(Some(metadata))
    }

    fn persist_record_strict(&self, record: &AttestationRecord) -> Result<(), String> {
        match self.persist_record(record) {
            Ok(_) => Ok(()),
            Err(failure) => match failure.outcome {
                PublicationOutcome::PublishedDurably(_) => Ok(()),
                PublicationOutcome::NotPublished
                | PublicationOutcome::PublishedButDurabilityUnknown => {
                    Err(format_publication_failure("ATTESTATION", failure))
                }
            },
        }
    }

    fn persist_record(
        &self,
        record: &AttestationRecord,
    ) -> Result<DurabilityGuarantee, PublicationFailure> {
        let final_path = self.records_path().join(record_file_name(record));
        let bytes = serde_json::to_vec_pretty(record).map_err(|error| PublicationFailure {
            outcome: PublicationOutcome::NotPublished,
            message: format!("No se pudo serializar record de atestacion: {error}"),
        })?;
        publish_immutable(&final_path, &bytes, |stage| {
            self.persistence_fault(&format!("attestation.{stage}"))
        })
    }

    fn persist_record_without_faults(&self, record: &AttestationRecord) -> Result<(), String> {
        let final_path = self.records_path().join(record_file_name(record));
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|error| format!("No se pudo serializar record legacy: {error}"))?;
        strict_immutable_publication(
            &final_path,
            &bytes,
            |_| Ok(()),
            "ATTESTATION_LEGACY_MIGRATION",
        )
    }

    fn persist_head(&self, head: &AttestationHead) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(head)
            .map_err(|error| format!("No se pudo serializar head de atestacion: {error}"))?;
        strict_replace_publication(
            &self.head_path(),
            &bytes,
            |stage| self.persistence_fault(&format!("attestation.head.{stage}")),
            "ATTESTATION_HEAD",
        )
    }

    fn load_head(&self) -> Result<Option<AttestationHead>, String> {
        let path = self.head_path();
        if !path.is_file() {
            return Ok(None);
        }
        self.metrics.head_reads.fetch_add(1, Ordering::Relaxed);
        let bytes = fs::read(&path)
            .map_err(|error| format!("No se pudo leer head de atestacion: {error}"))?;
        let head = serde_json::from_slice::<AttestationHead>(&bytes)
            .map_err(|error| format!("ATTESTATION_HEAD_CORRUPT: {error}"))?;
        if head.schema != ATTESTATION_HEAD_SCHEMA
            || Uuid::parse_str(&head.identity_id).is_err()
            || head.sequence == 0
            || head.record_sha256.len() != 64
            || Path::new(&head.record_file)
                .file_name()
                .and_then(|value| value.to_str())
                != Some(head.record_file.as_str())
        {
            return Err("ATTESTATION_HEAD_CORRUPT".to_string());
        }
        Ok(Some(head))
    }

    fn write_pending(&self, pending: &PendingAttestationPublication) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(pending)
            .map_err(|error| format!("No se pudo serializar pending de atestacion: {error}"))?;
        strict_replace_publication(
            &self.pending_path(),
            &bytes,
            |_| Ok(()),
            "ATTESTATION_PENDING",
        )
    }

    fn recover_pending(&self, metadata: &AttestationJournalMetadata) -> Result<(), String> {
        let path = self.pending_path();
        if !path.is_file() {
            return Ok(());
        }
        let pending = serde_json::from_slice::<PendingAttestationPublication>(
            &fs::read(&path).map_err(|error| format!("No se pudo leer pending: {error}"))?,
        )
        .map_err(|error| format!("ATTESTATION_PENDING_CORRUPT: {error}"))?;
        if pending.journal_id != metadata.journal_id {
            return Err("ATTESTATION_PENDING_SCOPE_MISMATCH".to_string());
        }
        let record_exists = self.records_path().join(&pending.record_file).is_file();
        let committed = self.load_head()?.is_some_and(|head| {
            head.sequence == pending.sequence && head.record_sha256 == pending.record_sha256
        });
        if committed {
            return self.clear_pending();
        }
        if record_exists {
            return Err(
                "ATTESTATION_DURABILITY_RECOVERY_REQUIRED: record visible sin head durable."
                    .to_string(),
            );
        }
        self.clear_pending()
    }

    fn clear_pending(&self) -> Result<(), String> {
        let path = self.pending_path();
        if !path.exists() {
            return Ok(());
        }
        fs::remove_file(&path)
            .map_err(|error| format!("No se pudo retirar pending de atestacion: {error}"))?;
        sync_directory(self.supervisor_state.as_path())
    }

    fn compact_if_needed(
        &self,
        signer: &AttestationSigner,
        metadata: &AttestationJournalMetadata,
        head: &AttestationHead,
    ) -> Result<(), String> {
        let retained_from = self
            .load_anchor(Some(metadata))?
            .map_or(metadata.genesis_sequence, |anchor| anchor.body.sequence + 1);
        if head.sequence.saturating_sub(retained_from) < MAX_RETAINED_RECORDS as u64 {
            return Ok(());
        }
        let mut paths = self.record_paths()?;
        paths.sort();
        if paths.len() <= MAX_RETAINED_RECORDS {
            return Ok(());
        }
        let prune_count = paths.len().saturating_sub(COMPACT_TO_RECORDS);
        let anchor_record = self.read_record(&paths[prune_count - 1])?;
        self.validate_record_scope(metadata, &anchor_record)?;
        let previous_anchor = self.load_anchor(Some(metadata))?;
        let body = AttestationAnchorBody {
            schema: ATTESTATION_ANCHOR_SCHEMA,
            journal_id: metadata.journal_id.clone(),
            identity_id: metadata.identity_id.clone(),
            identity_epoch: metadata.identity_epoch,
            key_id: metadata.key_id.clone(),
            host_id: metadata.host_id.clone(),
            deployment_id: metadata.deployment_id.clone(),
            sequence: anchor_record.body.sequence,
            record_sha256: anchor_record.record_sha256,
            previous_anchor_sha256: previous_anchor.map(|value| value.anchor_sha256),
        };
        let signature = signer.sign_serializable(&body)?;
        let public_key = signer.public_key();
        let anchor_sha256 = sha256_json(&(body.clone(), &public_key, &signature))?;
        let anchor = AttestationAnchor {
            body,
            public_key,
            signature,
            anchor_sha256,
        };
        let bytes = serde_json::to_vec_pretty(&anchor)
            .map_err(|error| format!("No se pudo serializar anchor: {error}"))?;
        strict_replace_publication(
            &self.anchor_path(),
            &bytes,
            |_| Ok(()),
            "ATTESTATION_ANCHOR",
        )?;
        for path in paths.into_iter().take(prune_count) {
            fs::remove_file(&path)
                .map_err(|error| format!("No se pudo compactar {}: {error}", path.display()))?;
        }
        sync_directory(&self.records_path())?;
        let mut compacted_head = head.clone();
        compacted_head.anchor_sequence = anchor.body.sequence;
        self.persist_head(&compacted_head)
    }

    fn load_anchor(
        &self,
        metadata: Option<&AttestationJournalMetadata>,
    ) -> Result<Option<AttestationAnchor>, String> {
        let path = self.anchor_path();
        if !path.is_file() {
            return Ok(None);
        }
        let anchor = serde_json::from_slice::<AttestationAnchor>(
            &fs::read(&path).map_err(|error| format!("No se pudo leer anchor: {error}"))?,
        )
        .map_err(|error| format!("ATTESTATION_ANCHOR_CORRUPT: {error}"))?;
        let key = verifying_key(&anchor.public_key)?;
        verify_serialized(&key, &anchor.body, &anchor.signature)
            .map_err(|_| "ATTESTATION_ANCHOR_SIGNATURE_INVALID".to_string())?;
        if sha256_json(&(anchor.body.clone(), &anchor.public_key, &anchor.signature))?
            != anchor.anchor_sha256
        {
            return Err("ATTESTATION_ANCHOR_CORRUPT".to_string());
        }
        if let Some(metadata) = metadata {
            if anchor.body.journal_id != metadata.journal_id
                || anchor.body.identity_id != metadata.identity_id
                || anchor.body.identity_epoch != metadata.identity_epoch
                || anchor.body.key_id != metadata.key_id
                || anchor.body.host_id != metadata.host_id
                || anchor.body.deployment_id != metadata.deployment_id
                || anchor.public_key != metadata.public_key
            {
                return Err("ATTESTATION_ANCHOR_SCOPE_MISMATCH".to_string());
            }
        }
        Ok(Some(anchor))
    }

    fn head_from_record(
        &self,
        metadata: &AttestationJournalMetadata,
        record: &AttestationRecord,
    ) -> Result<AttestationHead, String> {
        Ok(AttestationHead {
            schema: ATTESTATION_HEAD_SCHEMA,
            journal_id: metadata.journal_id.clone(),
            identity_id: metadata.identity_id.clone(),
            identity_epoch: metadata.identity_epoch,
            key_id: metadata.key_id.clone(),
            host_id: metadata.host_id.clone(),
            deployment_id: metadata.deployment_id.clone(),
            sequence: record.body.sequence,
            record_sha256: record.record_sha256.clone(),
            record_file: record_file_name(record),
            material_snapshot_sha256: material_snapshot_sha256(&record.body.envelope.statement)?,
            published_at_unix: now_unix(),
            anchor_sequence: self
                .load_anchor(Some(metadata))?
                .map_or(0, |value| value.body.sequence),
        })
    }

    fn validate_signer(
        &self,
        metadata: &AttestationJournalMetadata,
        signer: &AttestationSigner,
    ) -> Result<(), String> {
        if metadata.key_id != signer.key_id()
            || metadata.public_key != signer.public_key()
            || metadata.identity_id != signer.identity_id()
            || metadata.identity_epoch != signer.identity_epoch()
        {
            return Err("ATTESTATION_IDENTITY_MISMATCH".to_string());
        }
        Ok(())
    }

    fn validate_envelope_scope(
        &self,
        metadata: &AttestationJournalMetadata,
        envelope: &MaterialAttestationEnvelope,
        signer: &AttestationSigner,
    ) -> Result<(), String> {
        self.validate_signer(metadata, signer)?;
        verify_material_attestation(envelope)?;
        if envelope.statement.host_id != metadata.host_id
            || envelope.statement.deployment_id != metadata.deployment_id
            || envelope.statement.journal_id != metadata.journal_id
            || envelope.statement.attestation_identity_id != metadata.identity_id
            || envelope.statement.identity_epoch != metadata.identity_epoch
        {
            return Err("ATTESTATION_SCOPE_MISMATCH".to_string());
        }
        Ok(())
    }

    fn validate_record_scope(
        &self,
        metadata: &AttestationJournalMetadata,
        record: &AttestationRecord,
    ) -> Result<(), String> {
        let envelope = &record.body.envelope;
        if envelope.key_id != metadata.key_id
            || envelope.public_key != metadata.public_key
            || envelope.statement.host_id != metadata.host_id
            || envelope.statement.deployment_id != metadata.deployment_id
        {
            return Err("ATTESTATION_SCOPE_MISMATCH".to_string());
        }
        if record.body.schema >= ATTESTATION_RECORD_SCHEMA
            && (record.body.journal_id != metadata.journal_id
                || record.body.identity_id != metadata.identity_id
                || record.body.identity_epoch != metadata.identity_epoch
                || envelope.statement.journal_id != metadata.journal_id
                || envelope.statement.attestation_identity_id != metadata.identity_id
                || envelope.statement.identity_epoch != metadata.identity_epoch)
        {
            return Err("ATTESTATION_IDENTITY_MISMATCH".to_string());
        }
        Ok(())
    }

    fn validate_head_scope(
        &self,
        metadata: &AttestationJournalMetadata,
        head: &AttestationHead,
    ) -> Result<(), String> {
        if head.journal_id != metadata.journal_id
            || head.identity_id != metadata.identity_id
            || head.identity_epoch != metadata.identity_epoch
            || head.key_id != metadata.key_id
            || head.host_id != metadata.host_id
            || head.deployment_id != metadata.deployment_id
        {
            return Err("ATTESTATION_HEAD_SCOPE_MISMATCH".to_string());
        }
        Ok(())
    }

    fn read_record(&self, path: &Path) -> Result<AttestationRecord, String> {
        self.metrics.record_reads.fetch_add(1, Ordering::Relaxed);
        let record = read_attestation_record(path)?;
        self.metrics
            .signature_verifications
            .fetch_add(1, Ordering::Relaxed);
        Ok(record)
    }

    fn record_paths(&self) -> Result<Vec<PathBuf>, String> {
        self.metrics.directory_scans.fetch_add(1, Ordering::Relaxed);
        let directory = self.records_path();
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        fs::read_dir(&directory)
            .map_err(|error| format!("No se pudo leer journal de atestacion: {error}"))?
            .filter_map(|entry| match entry {
                Ok(entry)
                    if entry.path().extension().and_then(|value| value.to_str())
                        == Some("json") =>
                {
                    Some(Ok(entry.path()))
                }
                Ok(_) => None,
                Err(error) => Some(Err(format!("Entrada de atestacion invalida: {error}"))),
            })
            .collect()
    }

    fn load_legacy_envelope(&self) -> Result<Option<MaterialAttestationEnvelope>, String> {
        let evidence_path = self.supervisor_state.join("material-attestation.json");
        let sequence_path = self.supervisor_state.join("attestation-sequence");
        if !evidence_path.is_file() {
            if sequence_path.exists() {
                return Err(
                    "ATTESTATION_STATE_CORRUPT: contador existe sin evidencia firmada.".to_string(),
                );
            }
            return Ok(None);
        }
        let envelope = serde_json::from_slice::<MaterialAttestationEnvelope>(
            &fs::read(&evidence_path)
                .map_err(|error| format!("No se pudo leer atestacion legacy: {error}"))?,
        )
        .map_err(|error| format!("ATTESTATION_STATE_CORRUPT: evidencia legacy: {error}"))?;
        verify_material_attestation(&envelope)?;
        if sequence_path.is_file() {
            let sequence = fs::read_to_string(&sequence_path)
                .map_err(|error| format!("No se pudo leer secuencia legacy: {error}"))?
                .trim()
                .parse::<u64>()
                .map_err(|_| {
                    "ATTESTATION_STATE_CORRUPT: secuencia legacy no es u64.".to_string()
                })?;
            if sequence != envelope.statement.sequence {
                return Err(
                    "ATTESTATION_STATE_CORRUPT: contador y evidencia legacy divergen.".to_string(),
                );
            }
        }
        Ok(Some(envelope))
    }

    fn sync_derived_views(&self, envelope: &MaterialAttestationEnvelope) -> Result<(), String> {
        self.persistence_fault("attestation.before_mirrors")?;
        write_json_derived(
            &self.supervisor_state.join("material-attestation.json"),
            envelope,
        )?;
        self.persistence_fault("attestation.mirror.sequence")?;
        write_text_derived(
            &self.supervisor_state.join("attestation-sequence"),
            &format!("{}\n", envelope.statement.sequence),
        )
    }

    fn persistence_fault(&self, stage: &str) -> Result<(), String> {
        let mut faults = self
            .persistence_faults
            .lock()
            .map_err(|_| "Fault injector de atestacion envenenado.".to_string())?;
        if faults.front().is_some_and(|value| value == stage) {
            faults.pop_front();
            return Err(format!("PERSISTENCE_FAULT_INJECTED:{stage}"));
        }
        Ok(())
    }
}

pub fn canonical_json(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value)
            .map_err(|error| format!("No se pudo canonicalizar string JSON: {error}")),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let ordered = values.iter().collect::<BTreeMap<_, _>>();
            let fields = ordered
                .into_iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key).map_err(|error| {
                            format!("No se pudo canonicalizar clave JSON: {error}")
                        })?,
                        canonical_json(value)?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

fn material_snapshot_sha256(statement: &MaterialAttestationStatement) -> Result<String, String> {
    let mut value = serde_json::to_value(statement)
        .map_err(|error| format!("No se pudo serializar snapshot material: {error}"))?;
    if let Value::Object(fields) = &mut value {
        for temporal in [
            "sequence",
            "observedAt",
            "observationStartedAt",
            "observationCompletedAt",
        ] {
            fields.remove(temporal);
        }
    }
    Ok(hex(&Sha256::digest(canonical_json(&value)?.as_bytes())))
}

fn persist_secret_create_new(path: &Path, value: &str) -> Result<(), String> {
    strict_immutable_publication(
        path,
        format!("{value}\n").as_bytes(),
        |_| Ok(()),
        "ATTESTATION_IDENTITY",
    )?;
    set_secret_mode(path)
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("No se pudo leer la identidad de atestacion: {error}"))?;
    let bytes = decode_hex(raw.trim())?;
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "La identidad de atestacion debe contener 32 bytes.".to_string())?;
    Ok(SigningKey::from_bytes(&secret))
}

fn identity_metadata_path(key_path: &Path) -> PathBuf {
    key_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("attestation-identity.json")
}

fn read_identity_metadata(path: &Path) -> Result<AttestationIdentityMetadata, String> {
    let metadata = serde_json::from_slice::<AttestationIdentityMetadata>(
        &fs::read(path).map_err(|error| format!("No se pudo leer identidad fijada: {error}"))?,
    )
    .map_err(|error| format!("ATTESTATION_IDENTITY_CORRUPT: {error}"))?;
    if metadata.schema != 1
        || Uuid::parse_str(&metadata.identity_id).is_err()
        || metadata.identity_epoch == 0
        || !valid_key_id(&metadata.key_id)
        || metadata.public_key.len() != 43
    {
        return Err("ATTESTATION_IDENTITY_CORRUPT".to_string());
    }
    Ok(metadata)
}

fn read_attestation_record(path: &Path) -> Result<AttestationRecord, String> {
    let record = serde_json::from_slice::<AttestationRecord>(
        &fs::read(path).map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("ATTESTATION_STATE_CORRUPT en {}: {error}", path.display()))?;
    if sha256_json(&record.body)? != record.record_sha256
        || record.body.envelope.statement.sequence != record.body.sequence
        || !matches!(record.body.schema, 1 | ATTESTATION_RECORD_SCHEMA)
        || (record.body.schema >= ATTESTATION_RECORD_SCHEMA
            && Uuid::parse_str(&record.body.identity_id).is_err())
    {
        return Err(format!(
            "ATTESTATION_STATE_CORRUPT: digest o secuencia invalida en {}.",
            path.display()
        ));
    }
    verify_material_attestation(&record.body.envelope)?;
    if path.file_name().and_then(|value| value.to_str()) != Some(record_file_name(&record).as_str())
    {
        return Err(format!(
            "ATTESTATION_STATE_CORRUPT: nombre no coincide en {}.",
            path.display()
        ));
    }
    Ok(record)
}

fn record_file_name(record: &AttestationRecord) -> String {
    format!("{:020}-{}.json", record.body.sequence, record.record_sha256)
}

fn read_record_sha(path: &Path) -> Result<String, String> {
    Ok(read_attestation_record(path)?.record_sha256)
}

fn ensure_same_envelope_scope(
    first: &MaterialAttestationEnvelope,
    current: &MaterialAttestationEnvelope,
) -> Result<(), String> {
    if first.key_id != current.key_id
        || first.public_key != current.public_key
        || first.statement.host_id != current.statement.host_id
        || first.statement.deployment_id != current.statement.deployment_id
    {
        return Err("ATTESTATION_SCOPE_MISMATCH: journal legacy mezcla autoridades.".to_string());
    }
    Ok(())
}

fn validate_uuid_scope(host_id: &str, deployment_id: &str) -> Result<(), String> {
    if Uuid::parse_str(host_id).is_err() || Uuid::parse_str(deployment_id).is_err() {
        return Err("ATTESTATION_SCOPE_INVALID".to_string());
    }
    Ok(())
}

fn valid_key_id(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn key_id_for(key: &VerifyingKey) -> String {
    format!("sha256:{}", hex(&Sha256::digest(key.as_bytes())))
}

fn verifying_key(encoded: &str) -> Result<VerifyingKey, String> {
    let public = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "Public key de atestacion invalida.".to_string())?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| "Public key de atestacion no posee 32 bytes.".to_string())?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| "Public key Ed25519 de atestacion invalida.".to_string())
}

fn verify_serialized(
    key: &VerifyingKey,
    value: &impl Serialize,
    encoded_signature: &str,
) -> Result<(), String> {
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| "Firma de atestacion invalida.".to_string())?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "Firma de atestacion no posee 64 bytes.".to_string())?;
    let value = serde_json::to_value(value)
        .map_err(|error| format!("No se pudo serializar evidencia: {error}"))?;
    key.verify(
        canonical_json(&value)?.as_bytes(),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| "Firma Ed25519 no verificable.".to_string())
}

fn strict_immutable_publication<F>(
    path: &Path,
    bytes: &[u8],
    fault: F,
    prefix: &str,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    match publish_immutable(path, bytes, fault) {
        Ok(_) => Ok(()),
        Err(failure) if matches!(failure.outcome, PublicationOutcome::PublishedDurably(_)) => {
            Ok(())
        }
        Err(failure) => Err(format_publication_failure(prefix, failure)),
    }
}

fn strict_replace_publication<F>(
    path: &Path,
    bytes: &[u8],
    fault: F,
    prefix: &str,
) -> Result<(), String>
where
    F: FnMut(&str) -> Result<(), String>,
{
    match replace_durable(path, bytes, fault) {
        Ok(_) => Ok(()),
        Err(failure) if matches!(failure.outcome, PublicationOutcome::PublishedDurably(_)) => {
            Ok(())
        }
        Err(failure) => Err(format_publication_failure(prefix, failure)),
    }
}

fn format_publication_failure(prefix: &str, failure: PublicationFailure) -> String {
    let state = match failure.outcome {
        PublicationOutcome::NotPublished => "NOT_PUBLISHED",
        PublicationOutcome::PublishedButDurabilityUnknown => "DURABILITY_UNKNOWN",
        PublicationOutcome::PublishedDurably(_) => "PUBLISHED_DURABLY",
    };
    format!("{prefix}_{state}: {}", failure.message)
}

fn sha256_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("No se pudo canonicalizar record: {error}"))?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn write_json_derived(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("No se pudo serializar vista de atestacion: {error}"))?;
    write_bytes_derived(path, &bytes)
}

fn write_text_derived(path: &Path, value: &str) -> Result<(), String> {
    write_bytes_derived(path, value.as_bytes())
}

fn write_bytes_derived(path: &Path, bytes: &[u8]) -> Result<(), String> {
    replace_durable(path, bytes, |_| Ok(()))
        .map(|_| ())
        .or_else(|failure| {
            if matches!(failure.outcome, PublicationOutcome::PublishedDurably(_)) {
                Ok(())
            } else {
                Err(failure)
            }
        })
        .map_err(|failure| format_publication_failure("ATTESTATION_MIRROR", failure))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn has_json_records(path: &Path) -> Result<bool, String> {
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(path)
        .map_err(|error| format!("No se pudo leer journal de atestacion: {error}"))?
    {
        let path = entry
            .map_err(|error| format!("Entrada de atestacion invalida: {error}"))?
            .path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("No se pudo sincronizar {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_secret_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("No se pudo restringir la identidad de atestacion: {error}"))
}

#[cfg(not(unix))]
fn set_secret_mode(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("La identidad de atestacion no contiene hexadecimal valido.".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| {
                "La identidad de atestacion no contiene hexadecimal valido.".to_string()
            })
        })
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::Arc, thread};

    fn scope() -> (String, String) {
        (Uuid::new_v4().to_string(), Uuid::new_v4().to_string())
    }

    fn statement(
        sequence: u64,
        host_id: &str,
        deployment_id: &str,
        material: &str,
    ) -> MaterialAttestationStatement {
        MaterialAttestationStatement {
            host_id: host_id.to_string(),
            deployment_id: deployment_id.to_string(),
            sequence,
            generation: 7,
            runtime_release: Some("0.8.0-lab.test".to_string()),
            payload_digest: Some("a".repeat(64)),
            material_digest: material.repeat(64),
            observed_at: "2026-08-15T00:00:00Z".to_string(),
            runtime_units: Vec::new(),
            journal_id: String::new(),
            attestation_identity_id: String::new(),
            identity_epoch: 0,
            release_revision: 3,
            topology_digest: "c".repeat(64),
            configuration_digest: "d".repeat(64),
            observation_started_at: "2026-08-15T00:00:00Z".to_string(),
            observation_completed_at: "2026-08-15T00:00:01Z".to_string(),
        }
    }

    #[test]
    fn canonicaliza_objetos_sin_depender_del_orden() {
        assert_eq!(
            canonical_json(&serde_json::json!({"z": 1, "a": {"b": true, "a": false}})).unwrap(),
            r#"{"a":{"a":false,"b":true},"z":1}"#
        );
    }

    #[test]
    fn identidad_y_scope_quedan_fijados_y_perdida_falla_cerrado() {
        let root = std::env::temp_dir().join(format!("actium-att-identity-{}", Uuid::new_v4()));
        let key = root.join("identity.key");
        let signer = AttestationSigner::load_or_create(&key).unwrap();
        let (host, deployment) = scope();
        let journal = AttestationJournal::new(root.join("state"));
        let first = journal
            .sign_and_publish(&signer, |sequence| {
                Ok(statement(sequence, &host, &deployment, "b"))
            })
            .unwrap();
        assert_eq!(first.statement.sequence, 1);
        assert_eq!(first.statement.identity_epoch, 1);
        assert!(!first.statement.journal_id.is_empty());

        let other_host = Uuid::new_v4().to_string();
        assert!(journal
            .sign_and_publish(&signer, |sequence| Ok(statement(
                sequence,
                &other_host,
                &deployment,
                "c"
            )))
            .unwrap_err()
            .contains("ATTESTATION_SCOPE_MISMATCH"));
        let other_deployment = Uuid::new_v4().to_string();
        assert!(journal
            .sign_and_publish(&signer, |sequence| Ok(statement(
                sequence,
                &host,
                &other_deployment,
                "c"
            )))
            .unwrap_err()
            .contains("ATTESTATION_SCOPE_MISMATCH"));

        fs::remove_file(&key).unwrap();
        assert!(AttestationSigner::load_or_create(&key)
            .unwrap_err()
            .contains("ATTESTATION_IDENTITY_MISSING"));
        let replacement = SigningKey::generate(&mut OsRng);
        fs::write(&key, format!("{}\n", hex(replacement.as_bytes()))).unwrap();
        assert!(AttestationSigner::load_or_create(&key)
            .unwrap_err()
            .contains("ATTESTATION_IDENTITY_MISMATCH"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identidad_canonica_no_se_recrea_y_rotacion_local_no_autorizada_falla_cerrado() {
        let root = std::env::temp_dir().join(format!("actium-att-pin-{}", Uuid::new_v4()));
        let key = root.join("identity.key");
        let signer = AttestationSigner::load_or_create(&key).unwrap();
        let (host, deployment) = scope();
        AttestationJournal::new(root.join("state"))
            .sign_and_publish(&signer, |sequence| {
                Ok(statement(sequence, &host, &deployment, "b"))
            })
            .unwrap();
        let identity_path = identity_metadata_path(&key);
        fs::remove_file(&identity_path).unwrap();
        assert!(AttestationSigner::load_for_authority(
            &key,
            AttestationAuthorityState::CanonicalJournal
        )
        .unwrap_err()
        .contains("ATTESTATION_IDENTITY_MISSING"));

        let identity = AttestationIdentityMetadata {
            schema: 1,
            identity_id: signer.identity_id(),
            identity_epoch: signer.identity_epoch(),
            key_id: signer.key_id(),
            public_key: signer.public_key(),
            previous_key_id: None,
            rotation_status: "rotation_required".to_string(),
        };
        fs::write(
            &identity_path,
            serde_json::to_vec_pretty(&identity).unwrap(),
        )
        .unwrap();
        assert!(AttestationSigner::load_existing(&key)
            .unwrap_err()
            .contains("ATTESTATION_ROTATION_REQUIRED"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migracion_legacy_es_one_shot_y_fija_genesis_scope_e_identidad() {
        let root = std::env::temp_dir().join(format!("actium-att-legacy-{}", Uuid::new_v4()));
        let key = root.join("identity.key");
        let signer = AttestationSigner::load_or_create(&key).unwrap();
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let (host, deployment) = scope();
        let legacy = signer.sign(statement(8, &host, &deployment, "b")).unwrap();
        fs::write(
            state.join("material-attestation.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();
        fs::write(state.join("attestation-sequence"), b"8\n").unwrap();
        fs::remove_file(identity_metadata_path(&key)).unwrap();

        let migrated_signer =
            AttestationSigner::load_for_authority(&key, AttestationAuthorityState::LegacyJournal)
                .unwrap();
        let journal = AttestationJournal::new(&state);
        let migrated = journal
            .sign_and_publish(&migrated_signer, |sequence| {
                Ok(statement(sequence, &host, &deployment, "c"))
            })
            .unwrap();
        assert_eq!(migrated.statement.sequence, 9);
        let metadata = journal.load_metadata().unwrap().unwrap();
        assert!(metadata.legacy_migrated);
        assert_eq!(metadata.genesis_sequence, 8);
        assert_eq!(metadata.identity_id, migrated_signer.identity_id());
        fs::remove_dir_all(journal.records_path()).unwrap();
        assert!(journal
            .latest()
            .unwrap_err()
            .contains("ATTESTATION_JOURNAL_MISSING"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unchanged_reusa_envelope_y_latest_es_bounded() {
        let root = std::env::temp_dir().join(format!("actium-att-bounded-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let journal = AttestationJournal::new(root.join("state"));
        let (host, deployment) = scope();
        let first = journal
            .sign_and_publish_result(&signer, |sequence| {
                Ok(statement(sequence, &host, &deployment, "b"))
            })
            .unwrap();
        assert_eq!(first.disposition, AttestationPublishDisposition::Published);
        for _ in 0..100 {
            let reused = journal
                .sign_and_publish_result(&signer, |sequence| {
                    Ok(statement(sequence, &host, &deployment, "b"))
                })
                .unwrap();
            assert_eq!(
                reused.disposition,
                AttestationPublishDisposition::ReusedUnchanged
            );
            assert_eq!(reused.envelope.statement.sequence, 1);
        }
        let before = journal.stats();
        assert_eq!(journal.latest().unwrap().unwrap().statement.sequence, 1);
        let after = journal.stats();
        assert_eq!(after.record_reads - before.record_reads, 1);
        assert_eq!(after.directory_scans - before.directory_scans, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn miles_de_records_compactan_y_head_permanece_o1() {
        let root = std::env::temp_dir().join(format!("actium-att-stress-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let journal = AttestationJournal::new(root.join("state"));
        let (host, deployment) = scope();
        let first = journal
            .sign_and_publish(&signer, |sequence| {
                Ok(statement(sequence, &host, &deployment, "b"))
            })
            .unwrap();
        let mut previous_hash = journal.load_head().unwrap().unwrap().record_sha256;
        let mut latest_record = None;
        for sequence in 2..=2_000_u64 {
            let mut value = statement(sequence, &host, &deployment, "b");
            value.generation = sequence;
            value.journal_id = first.statement.journal_id.clone();
            value.attestation_identity_id = first.statement.attestation_identity_id.clone();
            value.identity_epoch = first.statement.identity_epoch;
            let envelope = signer.sign(value).unwrap();
            let body = AttestationRecordBody {
                schema: ATTESTATION_RECORD_SCHEMA,
                sequence,
                previous_record_sha256: Some(previous_hash),
                envelope,
                journal_id: first.statement.journal_id.clone(),
                identity_id: first.statement.attestation_identity_id.clone(),
                identity_epoch: first.statement.identity_epoch,
            };
            let record = AttestationRecord {
                record_sha256: sha256_json(&body).unwrap(),
                body,
            };
            previous_hash = record.record_sha256.clone();
            fs::write(
                journal.records_path().join(record_file_name(&record)),
                serde_json::to_vec_pretty(&record).unwrap(),
            )
            .unwrap();
            latest_record = Some(record);
        }
        let metadata = journal.load_metadata().unwrap().unwrap();
        let latest_record = latest_record.unwrap();
        let head = journal.head_from_record(&metadata, &latest_record).unwrap();
        journal.persist_head(&head).unwrap();
        journal
            .compact_if_needed(&signer, &metadata, &head)
            .unwrap();
        let retained = journal.audit_retained_chain().unwrap();
        assert!(retained <= MAX_RETAINED_RECORDS);
        let before = journal.stats();
        assert_eq!(journal.latest().unwrap().unwrap().statement.sequence, 2_000);
        let after = journal.stats();
        assert_eq!(after.record_reads - before.record_reads, 1);
        assert_eq!(after.directory_scans - before.directory_scans, 0);
        assert!(after.directory_scans < 40, "stats={after:?}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn perdida_canonica_no_reinterpreta_mirrors_como_legacy() {
        let root = std::env::temp_dir().join(format!("actium-att-loss-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let journal = AttestationJournal::new(root.join("state"));
        let (host, deployment) = scope();
        journal
            .sign_and_publish(&signer, |sequence| {
                Ok(statement(sequence, &host, &deployment, "b"))
            })
            .unwrap();
        fs::remove_dir_all(root.join("state/material-attestations-v1")).unwrap();
        assert!(journal
            .latest()
            .unwrap_err()
            .contains("ATTESTATION_JOURNAL_MISSING"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fallos_de_durabilidad_no_se_convierten_en_exito_visible() {
        for (index, stage) in [
            "attestation.before_temp_write",
            "attestation.after_temp_sync",
        ]
        .into_iter()
        .enumerate()
        {
            let root = std::env::temp_dir().join(format!(
                "actium-att-not-published-{index}-{}",
                Uuid::new_v4()
            ));
            let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
            let (host, deployment) = scope();
            let journal = AttestationJournal::with_persistence_faults(root.join("state"), [stage]);
            assert!(journal
                .sign_and_publish(&signer, |sequence| {
                    Ok(statement(sequence, &host, &deployment, "b"))
                })
                .unwrap_err()
                .contains("ATTESTATION_NOT_PUBLISHED"));
            AttestationJournal::new(root.join("state"))
                .sign_and_publish(&signer, |sequence| {
                    Ok(statement(sequence, &host, &deployment, "b"))
                })
                .unwrap();
            let _ = fs::remove_dir_all(root);
        }

        for stage in [
            "attestation.after_rename_before_directory_sync",
            "attestation.directory_sync",
        ] {
            let root = std::env::temp_dir().join(format!("actium-att-unknown-{}", Uuid::new_v4()));
            let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
            let (host, deployment) = scope();
            let journal = AttestationJournal::with_persistence_faults(root.join("state"), [stage]);
            assert!(journal
                .sign_and_publish(&signer, |sequence| {
                    Ok(statement(sequence, &host, &deployment, "b"))
                })
                .unwrap_err()
                .contains("ATTESTATION_DURABILITY_UNKNOWN"));
            assert!(journal
                .latest()
                .unwrap_err()
                .contains("ATTESTATION_DURABILITY_RECOVERY_REQUIRED"));
            let _ = fs::remove_dir_all(root);
        }

        let root = std::env::temp_dir().join(format!("actium-att-durable-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let (host, deployment) = scope();
        let journal = AttestationJournal::with_persistence_faults(
            root.join("state"),
            ["attestation.after_durable_publication"],
        );
        assert_eq!(
            journal
                .sign_and_publish(&signer, |sequence| {
                    Ok(statement(sequence, &host, &deployment, "b"))
                })
                .unwrap()
                .statement
                .sequence,
            1
        );
        let _ = fs::remove_dir_all(root);

        let root = std::env::temp_dir().join(format!("actium-att-mirror-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let state = root.join("state");
        fs::create_dir_all(state.join("material-attestation.json")).unwrap();
        let (host, deployment) = scope();
        let journal = AttestationJournal::new(&state);
        journal
            .sign_and_publish(&signer, |sequence| {
                Ok(statement(sequence, &host, &deployment, "b"))
            })
            .unwrap();
        assert_eq!(journal.latest().unwrap().unwrap().statement.sequence, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refreshes_concurrentes_serializan_material_distinto() {
        let root = std::env::temp_dir().join(format!("actium-att-concurrent-{}", Uuid::new_v4()));
        let signer =
            Arc::new(AttestationSigner::load_or_create(root.join("identity.key")).unwrap());
        let journal = Arc::new(AttestationJournal::new(root.join("state")));
        let (host, deployment) = scope();
        let threads = (0..8_u64)
            .map(|generation| {
                let signer = signer.clone();
                let journal = journal.clone();
                let host = host.clone();
                let deployment = deployment.clone();
                thread::spawn(move || {
                    journal
                        .sign_and_publish(&signer, |sequence| {
                            let mut value = statement(sequence, &host, &deployment, "b");
                            value.generation = generation;
                            Ok(value)
                        })
                        .unwrap()
                        .statement
                        .sequence
                })
            })
            .collect::<Vec<_>>();
        let mut sequences = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
        let _ = fs::remove_dir_all(root);
    }
}
