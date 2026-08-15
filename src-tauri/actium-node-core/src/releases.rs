use crate::{
    durability::{publish_immutable, replace_durable, PublicationFailure, PublicationOutcome},
    verify_payload, PayloadManifestV3, VerifiedPayload,
};
use fs2::{available_space, FileExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseMetadata {
    pub release_id: String,
    pub release_version: String,
    pub release_digest: String,
    pub payload_schema: u8,
    pub source_commit: Option<String>,
    pub relative_path: String,
}

const RELEASE_STATE_SCHEMA: u8 = 2;
const RELEASE_JOURNAL_SCHEMA: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ReleaseJournalMetadata {
    schema: u8,
    journal_id: String,
    genesis_revision: u64,
    genesis_record_sha256: String,
    legacy_migrated: bool,
    initialized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PendingReleasePublication {
    schema: u8,
    revision: u64,
    record_sha256: String,
    record_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NodeReleaseState {
    #[serde(default = "release_state_schema")]
    pub schema: u8,
    #[serde(default)]
    pub revision: u64,
    pub active_release: Option<ReleaseMetadata>,
    pub previous_release: Option<ReleaseMetadata>,
    pub promotion_status: String,
    pub last_successful_release: Option<ReleaseMetadata>,
    pub last_failed_release: Option<ReleaseMetadata>,
    #[serde(default)]
    pub promotion_id: Option<String>,
    #[serde(default)]
    pub promotion_base_revision: Option<u64>,
}

impl Default for NodeReleaseState {
    fn default() -> Self {
        Self {
            schema: RELEASE_STATE_SCHEMA,
            revision: 0,
            active_release: None,
            previous_release: None,
            promotion_status: String::new(),
            last_successful_release: None,
            last_failed_release: None,
            promotion_id: None,
            promotion_base_revision: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PreparedRelease {
    pub staging_path: PathBuf,
    pub metadata: ReleaseMetadata,
}

#[derive(Debug, Clone)]
pub struct ReleaseManager {
    node_root: PathBuf,
    persistence_faults: Arc<Mutex<VecDeque<String>>>,
}

#[derive(Debug)]
pub struct ReleasePromotion {
    manager: ReleaseManager,
    promoted: NodeReleaseState,
    promotion_id: String,
    candidate_release_id: String,
    lock: Option<ReleaseMutationGuard>,
    finalized: bool,
}

#[derive(Debug)]
pub struct PromotionAbort {
    pub state: NodeReleaseState,
    pub recovery_required: bool,
    manager: ReleaseManager,
    lock: Option<ReleaseMutationGuard>,
    finalized: bool,
}

#[derive(Debug)]
pub struct ReleaseMutationGuard {
    file: File,
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ReleaseStateRecordBody {
    schema: u8,
    revision: u64,
    previous_record_sha256: Option<String>,
    state: NodeReleaseState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ReleaseStateRecord {
    #[serde(flatten)]
    body: ReleaseStateRecordBody,
    record_sha256: String,
}

fn release_state_schema() -> u8 {
    RELEASE_STATE_SCHEMA
}

impl ReleaseManager {
    pub fn new(node_root: impl AsRef<Path>) -> Self {
        Self {
            node_root: node_root.as_ref().to_path_buf(),
            persistence_faults: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    #[cfg(any(test, feature = "fault-injection"))]
    pub fn with_persistence_faults(
        node_root: impl AsRef<Path>,
        faults: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            node_root: node_root.as_ref().to_path_buf(),
            persistence_faults: Arc::new(Mutex::new(faults.into_iter().map(Into::into).collect())),
        }
    }

    #[cfg(any(test, feature = "fault-injection"))]
    pub fn inject_persistence_fault(&self, stage: impl Into<String>) {
        self.persistence_faults
            .lock()
            .expect("fault injector")
            .push_back(stage.into());
    }

    pub fn ensure_layout(&self) -> Result<(), String> {
        for directory in [
            "releases",
            "staging",
            "state",
            "state/release-state-v2",
            "secrets",
            "persistent",
        ] {
            fs::create_dir_all(self.node_root.join(directory)).map_err(|error| {
                format!(
                    "No se pudo crear {directory} en {}: {error}",
                    self.node_root.display()
                )
            })?;
        }
        Ok(())
    }

    pub fn load_state(&self) -> Result<NodeReleaseState, String> {
        if let Some(record) = self.load_latest_record()? {
            if let Ok(bytes) = fs::read(self.state_path()) {
                if let Ok(witness) = serde_json::from_slice::<NodeReleaseState>(&bytes) {
                    if witness.revision > record.body.revision
                        || (witness.revision == record.body.revision
                            && witness != record.body.state)
                    {
                        return Err(
                            "RELEASE_STATE_TRUNCATED: la vista durable conoce una revision canonica ausente o divergente."
                                .to_string(),
                        );
                    }
                }
            }
            let state = record.body.state;
            let _ = self.sync_derived_views(&state);
            return Ok(state);
        }
        let path = self.state_path();
        if path.is_file() {
            let contents = fs::read_to_string(&path)
                .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
            let mut state = serde_json::from_str::<NodeReleaseState>(&contents)
                .map_err(|error| format!("Estado de releases legacy invalido: {error}"))?;
            if state.schema == 0 {
                state.schema = RELEASE_STATE_SCHEMA;
            }
            return self.migrate_legacy_state(state);
        }
        if self.has_release_evidence()? {
            return Err(
                "RELEASE_STATE_MISSING: existen artefactos administrados sin checkpoint canonico."
                    .to_string(),
            );
        }
        Ok(NodeReleaseState {
            promotion_status: "legacy_unmanaged".to_string(),
            ..Default::default()
        })
    }

    pub fn lock_mutation(&self) -> Result<ReleaseMutationGuard, String> {
        self.ensure_layout()?;
        let path = self.node_root.join("state/release-mutation.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("No se pudo abrir el lock {}: {error}", path.display()))?;
        if let Err(error) = file.try_lock_exclusive() {
            return if lock_is_contended(&error) {
                Err(format!(
                    "MUTATION_BUSY: otra operacion posee la autoridad de mutacion sobre {}.",
                    self.node_root.display()
                ))
            } else {
                Err(format!(
                    "No se pudo adquirir el lock de mutacion sobre {}: {error}",
                    self.node_root.display()
                ))
            };
        }
        Ok(ReleaseMutationGuard {
            file,
            root: self.node_root.clone(),
        })
    }

    pub fn active_runtime_dir(&self) -> Result<PathBuf, String> {
        let state = self.load_state()?;
        Ok(state
            .active_release
            .map(|release| self.node_root.join(release.relative_path))
            .unwrap_or_else(|| self.node_root.clone()))
    }

    pub fn prepare(&self, payload_root: &Path) -> Result<PreparedRelease, String> {
        self.ensure_layout()?;
        let manifest = match verify_payload(payload_root)? {
            VerifiedPayload::Schema3(manifest) => manifest,
            VerifiedPayload::LegacyUnverified { .. } => {
                return Err("Un payload schema 2 es legacy-unverified y no puede promoverse transaccionalmente.".to_string())
            }
        };
        let required = manifest
            .files
            .iter()
            .try_fold(0_u64, |total, file| total.checked_add(file.size))
            .ok_or_else(|| "El tamano declarado del payload desborda u64.".to_string())?;
        let free = available_space(&self.node_root)
            .map_err(|error| format!("No se pudo verificar espacio disponible: {error}"))?;
        if free < required.saturating_mul(2).saturating_add(32 * 1024 * 1024) {
            return Err(format!(
                "Espacio insuficiente para staging: libres={free}, payload={required}."
            ));
        }
        let release_id = release_id(&manifest);
        let staging_path = self
            .node_root
            .join("staging")
            .join(format!("{release_id}-{}", Uuid::new_v4()));
        fs::create_dir_all(&staging_path)
            .map_err(|error| format!("No se pudo crear staging: {error}"))?;
        if let Err(error) = copy_manifest_files(payload_root, &staging_path, &manifest) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(error);
        }
        fs::copy(
            payload_root.join("PAYLOAD.json"),
            staging_path.join("PAYLOAD.json"),
        )
        .map_err(|error| format!("No se pudo copiar PAYLOAD.json a staging: {error}"))?;
        if let Err(error) = verify_payload(&staging_path) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(format!(
                "La copia de staging no preservo integridad: {error}"
            ));
        }
        Ok(PreparedRelease {
            staging_path,
            metadata: ReleaseMetadata {
                release_id: release_id.clone(),
                release_version: manifest.release_version,
                release_digest: manifest.tree_sha256,
                payload_schema: 3,
                source_commit: manifest.source_commit,
                relative_path: format!("releases/{release_id}"),
            },
        })
    }

    pub fn snapshot_legacy(&self, version: &str, digest: &str) -> Result<ReleaseMetadata, String> {
        self.ensure_layout()?;
        let lock = self.lock_mutation()?;
        self.snapshot_legacy_locked(version, digest, &lock)
    }

    pub fn snapshot_legacy_locked(
        &self,
        version: &str,
        digest: &str,
        lock: &ReleaseMutationGuard,
    ) -> Result<ReleaseMetadata, String> {
        lock.assert_root(&self.node_root)?;
        let mut state = self.load_state()?;
        if let Some(active) = state.active_release {
            return Ok(active);
        }
        let safe_version = sanitize(version);
        let digest = if digest.len() >= 12 {
            &digest[..12]
        } else {
            digest
        };
        let release_id = format!("legacy-{safe_version}-{digest}");
        let relative_path = format!("releases/{release_id}");
        let target = self.node_root.join(&relative_path);
        copy_legacy_tree(&self.node_root, &target)?;
        let metadata = ReleaseMetadata {
            release_id,
            release_version: version.to_string(),
            release_digest: digest.to_string(),
            payload_schema: 2,
            source_commit: None,
            relative_path,
        };
        state.active_release = Some(metadata.clone());
        state.last_successful_release = Some(metadata.clone());
        state.promotion_status = "legacy_lkg".to_string();
        state.promotion_id = None;
        state.promotion_base_revision = None;
        self.write_state_transition(state.revision, &mut state)?;
        Ok(metadata)
    }

    pub fn begin_promotion(&self, prepared: PreparedRelease) -> Result<ReleasePromotion, String> {
        let lock = self.lock_mutation()?;
        self.begin_promotion_locked(prepared, lock)
    }

    pub fn begin_promotion_locked(
        &self,
        prepared: PreparedRelease,
        lock: ReleaseMutationGuard,
    ) -> Result<ReleasePromotion, String> {
        lock.assert_root(&self.node_root)?;
        self.ensure_layout()?;
        verify_payload(&prepared.staging_path)?;
        let mut state = self.load_state()?;
        if matches!(
            state.promotion_status.as_str(),
            "promoting" | "recovery_pending" | "manual_intervention_required"
        ) {
            return Err(format!(
                "RELEASE_RECOVERY_REQUIRED: no puede comenzar otra promocion desde {}.",
                state.promotion_status
            ));
        }
        let target = self.node_root.join(&prepared.metadata.relative_path);
        if target.exists() {
            let existing = verify_payload(&target)?;
            if existing.digest() != prepared.metadata.release_digest {
                return Err(format!(
                    "El release {} ya existe con contenido distinto.",
                    prepared.metadata.release_id
                ));
            }
            fs::remove_dir_all(&prepared.staging_path)
                .map_err(|error| format!("No se pudo limpiar staging repetido: {error}"))?;
        } else {
            fs::rename(&prepared.staging_path, &target)
                .map_err(|error| format!("No se pudo promover staging a releases: {error}"))?;
        }
        let base_revision = state.revision;
        let promotion_id = Uuid::new_v4().to_string();
        let candidate_release_id = prepared.metadata.release_id.clone();
        state.previous_release = state.active_release.take();
        state.active_release = Some(prepared.metadata);
        state.promotion_status = "promoting".to_string();
        state.promotion_id = Some(promotion_id.clone());
        state.promotion_base_revision = Some(base_revision);
        if let Err(error) = self.write_state_transition(base_revision, &mut state) {
            if error.contains("DURABILITY_UNKNOWN") {
                return Err(error);
            }
            if base_revision == 0
                && self.load_latest_record()?.is_none()
                && !self.state_path().is_file()
            {
                let _ = fs::remove_dir_all(&target);
            }
            return Err(error);
        }
        Ok(ReleasePromotion {
            manager: self.clone(),
            promoted: state,
            promotion_id,
            candidate_release_id,
            lock: Some(lock),
            finalized: false,
        })
    }

    fn mark_success_owned(
        &self,
        promotion_id: &str,
        candidate_release_id: &str,
        promoted_revision: u64,
    ) -> Result<NodeReleaseState, String> {
        let mut state = self.load_state()?;
        self.validate_promotion_owner(
            &state,
            promotion_id,
            candidate_release_id,
            promoted_revision,
        )?;
        let base_revision = state.revision;
        state.last_successful_release = state.active_release.clone();
        state.promotion_status = "active".to_string();
        state.promotion_id = None;
        state.promotion_base_revision = None;
        self.write_state_transition(base_revision, &mut state)?;
        Ok(state)
    }

    pub fn rollback(&self) -> Result<NodeReleaseState, String> {
        let aborted = self.abort_promotion()?;
        if !aborted.recovery_required {
            return Err("No existe LKG anterior para rollback.".to_string());
        }
        aborted.complete_recovery()
    }

    pub fn mark_failed_without_rollback(&self) -> Result<NodeReleaseState, String> {
        Ok(self.abort_promotion()?.state.clone())
    }

    pub fn abort_promotion(&self) -> Result<PromotionAbort, String> {
        let lock = self.lock_mutation()?;
        self.abort_interrupted_locked(lock)
    }

    pub fn recover_interrupted(&self) -> Result<Option<PromotionAbort>, String> {
        let lock = self.lock_mutation()?;
        let state = self.load_state()?;
        match state.promotion_status.as_str() {
            "promoting" => self.abort_interrupted_locked(lock).map(Some),
            "recovery_pending" | "manual_intervention_required" => Ok(Some(PromotionAbort {
                recovery_required: true,
                state,
                manager: self.clone(),
                lock: Some(lock),
                finalized: false,
            })),
            _ => Ok(None),
        }
    }

    fn abort_interrupted_locked(
        &self,
        lock: ReleaseMutationGuard,
    ) -> Result<PromotionAbort, String> {
        let mut state = self.load_state()?;
        if state.promotion_status != "promoting" {
            return Ok(PromotionAbort {
                recovery_required: matches!(
                    state.promotion_status.as_str(),
                    "recovery_pending" | "manual_intervention_required"
                ),
                state,
                manager: self.clone(),
                lock: Some(lock),
                finalized: false,
            });
        }
        let base_revision = state.revision;
        self.abort_state(&mut state)?;
        self.write_state_transition(base_revision, &mut state)?;
        let recovery_required = state.promotion_status == "recovery_pending";
        Ok(PromotionAbort {
            state,
            recovery_required,
            manager: self.clone(),
            lock: Some(lock),
            finalized: !recovery_required,
        })
    }

    fn abort_owned(
        &self,
        promotion_id: &str,
        candidate_release_id: &str,
        promoted_revision: u64,
    ) -> Result<NodeReleaseState, String> {
        let mut state = self.load_state()?;
        self.validate_promotion_owner(
            &state,
            promotion_id,
            candidate_release_id,
            promoted_revision,
        )?;
        let base_revision = state.revision;
        self.abort_state(&mut state)?;
        self.write_state_transition(base_revision, &mut state)?;
        Ok(state)
    }

    fn abort_state(&self, state: &mut NodeReleaseState) -> Result<(), String> {
        let failed = state
            .active_release
            .take()
            .ok_or_else(|| "Promocion activa sin release candidato.".to_string())?;
        state.last_failed_release = Some(failed.clone());
        let recovery_required = if let Some(previous) = state.previous_release.take() {
            state.last_successful_release = Some(previous.clone());
            state.active_release = Some(previous);
            state.previous_release = Some(failed);
            state.promotion_status = "recovery_pending".to_string();
            true
        } else {
            state.previous_release = None;
            state.promotion_status = "failed".to_string();
            false
        };
        let _ = recovery_required;
        state.promotion_id = None;
        state.promotion_base_revision = None;
        Ok(())
    }

    pub fn mark_recovery_success(&self) -> Result<NodeReleaseState, String> {
        let _lock = self.lock_mutation()?;
        self.mark_recovery_success_locked()
    }

    fn mark_recovery_success_locked(&self) -> Result<NodeReleaseState, String> {
        let mut state = self.load_state()?;
        if state.promotion_status != "recovery_pending"
            && state.promotion_status != "manual_intervention_required"
        {
            return Err(format!(
                "Recovery no puede completarse desde {}.",
                state.promotion_status
            ));
        }
        if state.active_release.is_none() {
            return Err("Recovery no posee LKG activo.".to_string());
        }
        let base_revision = state.revision;
        state.promotion_status = "rolled_back".to_string();
        self.write_state_transition(base_revision, &mut state)?;
        Ok(state)
    }

    pub fn mark_recovery_failed(&self) -> Result<NodeReleaseState, String> {
        let _lock = self.lock_mutation()?;
        self.mark_recovery_failed_locked()
    }

    fn mark_recovery_failed_locked(&self) -> Result<NodeReleaseState, String> {
        let mut state = self.load_state()?;
        if state.promotion_status != "recovery_pending"
            && state.promotion_status != "manual_intervention_required"
        {
            return Err(format!(
                "Recovery fallido no puede persistirse desde {}.",
                state.promotion_status
            ));
        }
        let base_revision = state.revision;
        state.promotion_status = "manual_intervention_required".to_string();
        self.write_state_transition(base_revision, &mut state)?;
        Ok(state)
    }

    fn state_path(&self) -> PathBuf {
        self.node_root.join("state").join("release-state.json")
    }

    fn checkpoints_path(&self) -> PathBuf {
        self.node_root.join("state/release-state-v2")
    }

    fn journal_metadata_path(&self) -> PathBuf {
        self.node_root.join("state/release-journal-v2.json")
    }

    fn pending_publication_path(&self) -> PathBuf {
        self.node_root
            .join("state/release-publication-pending-v2.json")
    }

    fn migrate_legacy_state(
        &self,
        mut state: NodeReleaseState,
    ) -> Result<NodeReleaseState, String> {
        let init_lock_path = self.node_root.join("state/release-journal-init.lock");
        let init_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&init_lock_path)
            .map_err(|error| format!("No se pudo abrir lock de genesis de releases: {error}"))?;
        init_lock
            .lock_exclusive()
            .map_err(|error| format!("No se pudo adquirir genesis de releases: {error}"))?;
        if let Some(record) = self.load_latest_record()? {
            return Ok(record.body.state);
        }
        state.schema = RELEASE_STATE_SCHEMA;
        state.revision = state.revision.max(1);
        let body = ReleaseStateRecordBody {
            schema: RELEASE_STATE_SCHEMA,
            revision: state.revision,
            previous_record_sha256: None,
            state: state.clone(),
        };
        let record = ReleaseStateRecord {
            record_sha256: sha256_json(&body)?,
            body,
        };
        self.initialize_journal_metadata(&record, true)?;
        self.write_pending_publication(&record)?;
        self.persist_record_strict(&record)?;
        self.clear_pending_publication()?;
        self.finalize_journal_metadata()?;
        let _ = self.sync_derived_views(&state);
        Ok(state)
    }

    fn initialize_journal_metadata(
        &self,
        genesis: &ReleaseStateRecord,
        legacy_migrated: bool,
    ) -> Result<ReleaseJournalMetadata, String> {
        let path = self.journal_metadata_path();
        if path.is_file() {
            let mut current = read_release_journal_metadata(&path)?;
            if !current.initialized && !has_json_records(&self.checkpoints_path())? {
                current.genesis_revision = genesis.body.revision;
                current.genesis_record_sha256 = genesis.record_sha256.clone();
                current.legacy_migrated = legacy_migrated;
                let bytes = serde_json::to_vec_pretty(&current)
                    .map_err(|error| format!("No se pudo serializar genesis pendiente: {error}"))?;
                replace_durable(&path, &bytes, |_| Ok(()))
                    .map_err(|failure| format_publication_failure("RELEASE_GENESIS", failure))?;
            }
            return Ok(current);
        }
        let metadata = ReleaseJournalMetadata {
            schema: RELEASE_JOURNAL_SCHEMA,
            journal_id: Uuid::new_v4().to_string(),
            genesis_revision: genesis.body.revision,
            genesis_record_sha256: genesis.record_sha256.clone(),
            legacy_migrated,
            initialized: false,
        };
        let bytes = serde_json::to_vec_pretty(&metadata)
            .map_err(|error| format!("No se pudo serializar genesis de releases: {error}"))?;
        match publish_immutable(&path, &bytes, |_| Ok(())) {
            Ok(_) => Ok(metadata),
            Err(_) if path.is_file() => read_release_journal_metadata(&path),
            Err(failure) => Err(format_publication_failure("RELEASE_GENESIS", failure)),
        }
    }

    fn finalize_journal_metadata(&self) -> Result<(), String> {
        let path = self.journal_metadata_path();
        let mut metadata = read_release_journal_metadata(&path)?;
        if metadata.initialized {
            return Ok(());
        }
        metadata.initialized = true;
        let bytes = serde_json::to_vec_pretty(&metadata)
            .map_err(|error| format!("No se pudo serializar genesis de releases: {error}"))?;
        replace_durable(&path, &bytes, |_| Ok(()))
            .map(|_| ())
            .map_err(|failure| format_publication_failure("RELEASE_GENESIS", failure))
    }

    fn write_pending_publication(&self, record: &ReleaseStateRecord) -> Result<(), String> {
        let pending = PendingReleasePublication {
            schema: 1,
            revision: record.body.revision,
            record_sha256: record.record_sha256.clone(),
            record_file: release_record_file_name(record),
        };
        let bytes = serde_json::to_vec_pretty(&pending)
            .map_err(|error| format!("No se pudo serializar pending de release: {error}"))?;
        match replace_durable(&self.pending_publication_path(), &bytes, |_| Ok(())) {
            Ok(_) => Ok(()),
            Err(failure) if matches!(failure.outcome, PublicationOutcome::PublishedDurably(_)) => {
                Ok(())
            }
            Err(failure) => Err(format_publication_failure("RELEASE_PENDING", failure)),
        }
    }

    fn clear_pending_publication(&self) -> Result<(), String> {
        let path = self.pending_publication_path();
        if !path.exists() {
            return Ok(());
        }
        fs::remove_file(&path)
            .map_err(|error| format!("No se pudo retirar pending de release: {error}"))?;
        sync_release_directory(
            path.parent()
                .ok_or_else(|| "Pending de release sin parent.".to_string())?,
        )
    }

    fn recover_pending_publication(&self) -> Result<(), String> {
        let path = self.pending_publication_path();
        if !path.is_file() {
            return Ok(());
        }
        let pending = serde_json::from_slice::<PendingReleasePublication>(
            &fs::read(&path)
                .map_err(|error| format!("No se pudo leer pending release: {error}"))?,
        )
        .map_err(|error| format!("RELEASE_PENDING_CORRUPT: {error}"))?;
        if pending.schema != 1 {
            return Err("RELEASE_PENDING_CORRUPT".to_string());
        }
        if self.checkpoints_path().join(&pending.record_file).is_file() {
            return Err(
                "RELEASE_DURABILITY_RECOVERY_REQUIRED: record visible sin confirmacion durable."
                    .to_string(),
            );
        }
        self.clear_pending_publication()
    }

    fn validate_promotion_owner(
        &self,
        state: &NodeReleaseState,
        promotion_id: &str,
        candidate_release_id: &str,
        promoted_revision: u64,
    ) -> Result<(), String> {
        if state.promotion_status != "promoting"
            || state.promotion_id.as_deref() != Some(promotion_id)
            || state.revision != promoted_revision
            || state
                .active_release
                .as_ref()
                .map(|release| release.release_id.as_str())
                != Some(candidate_release_id)
        {
            return Err(format!(
                "STALE_PROMOTION_OWNER: promocion {promotion_id}/{candidate_release_id}@{promoted_revision} no posee el estado actual {}@{}.",
                state.promotion_status, state.revision
            ));
        }
        Ok(())
    }

    fn write_state_transition(
        &self,
        expected_revision: u64,
        state: &mut NodeReleaseState,
    ) -> Result<(), String> {
        self.ensure_layout()?;
        let latest = self.load_latest_record()?;
        let current_revision = latest
            .as_ref()
            .map(|record| record.body.revision)
            .unwrap_or_else(|| {
                if self.state_path().is_file() {
                    expected_revision
                } else {
                    0
                }
            });
        if current_revision != expected_revision {
            return Err(format!(
                "RELEASE_REVISION_CONFLICT: esperado {expected_revision}, actual {current_revision}."
            ));
        }
        state.schema = RELEASE_STATE_SCHEMA;
        state.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| "Revision de release agotada.".to_string())?;
        let body = ReleaseStateRecordBody {
            schema: RELEASE_STATE_SCHEMA,
            revision: state.revision,
            previous_record_sha256: latest.as_ref().map(|record| record.record_sha256.clone()),
            state: state.clone(),
        };
        let record_sha256 = sha256_json(&body)?;
        let record = ReleaseStateRecord {
            body,
            record_sha256,
        };
        if latest.is_none() {
            self.initialize_journal_metadata(&record, false)?;
        }
        self.write_pending_publication(&record)?;
        self.persist_record_strict(&record)?;
        self.clear_pending_publication()?;
        self.finalize_journal_metadata()?;
        let _ = self.sync_derived_views(state);
        Ok(())
    }

    fn persist_record_strict(&self, record: &ReleaseStateRecord) -> Result<(), String> {
        match self.persist_record(record) {
            Ok(_) => Ok(()),
            Err(failure) => match failure.outcome {
                PublicationOutcome::PublishedDurably(_) => Ok(()),
                PublicationOutcome::NotPublished
                | PublicationOutcome::PublishedButDurabilityUnknown => {
                    Err(format_publication_failure("RELEASE", failure))
                }
            },
        }
    }

    fn persist_record(
        &self,
        record: &ReleaseStateRecord,
    ) -> Result<crate::durability::DurabilityGuarantee, PublicationFailure> {
        let directory = self.checkpoints_path();
        let final_path = directory.join(format!(
            "{:020}-{}.json",
            record.body.revision, record.record_sha256
        ));
        if final_path.exists() {
            let existing =
                read_release_record(&final_path).map_err(|message| PublicationFailure {
                    outcome: PublicationOutcome::NotPublished,
                    message,
                })?;
            return if existing == *record {
                Ok(platform_existing_guarantee())
            } else {
                Err(PublicationFailure {
                    outcome: PublicationOutcome::NotPublished,
                    message:
                        "RELEASE_RECORD_COLLISION: revision ya materializada con otro contenido."
                            .to_string(),
                })
            };
        }
        let bytes = serde_json::to_vec_pretty(record).map_err(|error| PublicationFailure {
            outcome: PublicationOutcome::NotPublished,
            message: format!("No se pudo serializar checkpoint: {error}"),
        })?;
        publish_immutable(&final_path, &bytes, |stage| {
            self.persistence_fault(&format!("release.{stage}"))
        })
    }

    fn load_latest_record(&self) -> Result<Option<ReleaseStateRecord>, String> {
        self.recover_pending_publication()?;
        let directory = self.checkpoints_path();
        let metadata_path = self.journal_metadata_path();
        let metadata = metadata_path
            .is_file()
            .then(|| read_release_journal_metadata(&metadata_path))
            .transpose()?;
        if !directory.is_dir() {
            return if metadata.is_some() {
                Err("RELEASE_JOURNAL_MISSING: genesis existe sin journal canonico.".to_string())
            } else {
                Ok(None)
            };
        }
        let mut paths = fs::read_dir(&directory)
            .map_err(|error| format!("No se pudo leer journal de releases: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Checkpoint de release invalido: {error}"))?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        paths.sort();
        if paths.is_empty() {
            return if metadata.as_ref().is_some_and(|value| value.initialized) {
                Err("RELEASE_JOURNAL_MISSING: genesis existe sin records canonicos.".to_string())
            } else {
                Ok(None)
            };
        }
        let mut previous_hash = None;
        let mut previous_revision = metadata
            .as_ref()
            .map(|value| value.genesis_revision.saturating_sub(1))
            .unwrap_or(0);
        let mut latest = None;
        for (index, path) in paths.iter().enumerate() {
            let record = read_release_record(path)?;
            if record.body.schema != RELEASE_STATE_SCHEMA
                || record.body.state.schema != RELEASE_STATE_SCHEMA
                || record.body.state.revision != record.body.revision
                || record.body.revision != previous_revision.saturating_add(1)
                || record.body.previous_record_sha256 != previous_hash
            {
                return Err(format!(
                    "RELEASE_STATE_CORRUPT: cadena invalida en {}.",
                    path.display()
                ));
            }
            if index == 0 {
                if let Some(metadata) = metadata.as_ref() {
                    if record.body.revision != metadata.genesis_revision
                        || record.record_sha256 != metadata.genesis_record_sha256
                    {
                        return Err("RELEASE_JOURNAL_GENESIS_MISMATCH".to_string());
                    }
                } else if record.body.revision != 1 {
                    return Err("RELEASE_JOURNAL_GENESIS_MISSING".to_string());
                }
            }
            previous_revision = record.body.revision;
            previous_hash = Some(record.record_sha256.clone());
            latest = Some(record);
        }
        if metadata.is_none() {
            let first = read_release_record(&paths[0])?;
            self.initialize_journal_metadata(&first, true)?;
            self.finalize_journal_metadata()?;
        } else if metadata.as_ref().is_some_and(|value| !value.initialized) {
            self.finalize_journal_metadata()?;
        }
        Ok(latest)
    }

    fn sync_derived_views(&self, state: &NodeReleaseState) -> Result<(), String> {
        self.persistence_fault("release.before_mirrors")?;
        write_json_derived(&self.state_path(), state)?;
        let active = self.node_root.join("state").join("active-release.json");
        let previous = self.node_root.join("state").join("previous-release.json");
        self.persistence_fault("release.mirror.active")?;
        write_json_derived(&active, &state.active_release)?;
        write_json_derived(&previous, &state.previous_release)?;
        write_json_derived(&self.node_root.join("current"), &state.active_release)?;
        Ok(())
    }

    fn has_release_evidence(&self) -> Result<bool, String> {
        for path in [
            self.node_root.join("current"),
            self.node_root.join("state/active-release.json"),
            self.node_root.join("state/previous-release.json"),
        ] {
            if path.exists() {
                return Ok(true);
            }
        }
        let releases = self.node_root.join("releases");
        if releases.is_dir() {
            return fs::read_dir(&releases)
                .map(|mut entries| entries.next().is_some())
                .map_err(|error| format!("No se pudo inspeccionar releases: {error}"));
        }
        Ok(false)
    }

    fn persistence_fault(&self, stage: &str) -> Result<(), String> {
        let mut faults = self
            .persistence_faults
            .lock()
            .map_err(|_| "Fault injector de persistencia envenenado.".to_string())?;
        if faults.front().is_some_and(|value| value == stage) {
            faults.pop_front();
            return Err(format!("PERSISTENCE_FAULT_INJECTED:{stage}"));
        }
        Ok(())
    }
}

impl ReleasePromotion {
    pub fn promoted_state(&self) -> &NodeReleaseState {
        &self.promoted
    }

    #[cfg(any(test, feature = "fault-injection"))]
    pub fn simulate_process_crash(mut self) {
        self.finalized = true;
        self.lock.take();
    }

    pub fn commit(mut self) -> Result<NodeReleaseState, String> {
        let state = self.manager.mark_success_owned(
            &self.promotion_id,
            &self.candidate_release_id,
            self.promoted.revision,
        )?;
        self.finalized = true;
        self.lock.take();
        Ok(state)
    }

    pub fn abort(mut self) -> Result<PromotionAbort, String> {
        let state = self.manager.abort_owned(
            &self.promotion_id,
            &self.candidate_release_id,
            self.promoted.revision,
        )?;
        let recovery_required = state.promotion_status == "recovery_pending";
        self.finalized = true;
        Ok(PromotionAbort {
            state,
            recovery_required,
            manager: self.manager.clone(),
            lock: self.lock.take(),
            finalized: !recovery_required,
        })
    }
}

impl Drop for ReleasePromotion {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = self.manager.abort_owned(
                &self.promotion_id,
                &self.candidate_release_id,
                self.promoted.revision,
            );
        }
    }
}

impl PromotionAbort {
    pub fn complete_recovery(mut self) -> Result<NodeReleaseState, String> {
        if !self.recovery_required {
            return Err("No existe recovery pendiente para completar.".to_string());
        }
        let state = self.manager.mark_recovery_success_locked()?;
        self.finalized = true;
        self.lock.take();
        Ok(state)
    }

    pub fn fail_recovery(mut self) -> Result<NodeReleaseState, String> {
        if !self.recovery_required {
            return Err("No existe recovery pendiente para marcar fallido.".to_string());
        }
        let state = self.manager.mark_recovery_failed_locked()?;
        self.finalized = true;
        self.lock.take();
        Ok(state)
    }
}

impl Drop for PromotionAbort {
    fn drop(&mut self) {
        if self.recovery_required && !self.finalized {
            let _ = self.manager.mark_recovery_failed_locked();
        }
    }
}

impl Drop for ReleaseMutationGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

impl ReleaseMutationGuard {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn assert_root(&self, root: &Path) -> Result<(), String> {
        if self.root == root {
            Ok(())
        } else {
            Err("El lock de mutacion no pertenece a este release root.".to_string())
        }
    }
}

fn release_id(manifest: &PayloadManifestV3) -> String {
    format!(
        "{}-{}",
        sanitize(&manifest.release_version),
        &manifest.tree_sha256[..12]
    )
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-') {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn copy_manifest_files(
    source: &Path,
    target: &Path,
    manifest: &PayloadManifestV3,
) -> Result<(), String> {
    for file in &manifest.files {
        let source_path = source.join(&file.path);
        let target_path = target.join(&file.path);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("No se pudo crear staging: {error}"))?;
        }
        fs::copy(&source_path, &target_path)
            .map_err(|error| format!("No se pudo copiar {} a staging: {error}", file.path))?;
    }
    Ok(())
}

fn copy_legacy_tree(source: &Path, target: &Path) -> Result<(), String> {
    let excluded = BTreeSet::from([
        "releases",
        "staging",
        "state",
        "secrets",
        "persistent",
        "current",
        "keys",
        "node.env",
        ".actium-node.json",
    ]);
    fs::create_dir_all(target)
        .map_err(|error| format!("No se pudo crear snapshot legacy: {error}"))?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| format!("No se pudo leer el nodo legacy: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Entrada legacy invalida: {error}"))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if excluded.contains(name.as_str()) {
            continue;
        }
        copy_entry(&entry.path(), &target.join(&name))?;
    }
    Ok(())
}

fn copy_entry(source: &Path, target: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("No se pudo inspeccionar {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "El snapshot legacy rechazo un symlink: {}.",
            source.display()
        ));
    }
    if metadata.is_dir() {
        fs::create_dir_all(target)
            .map_err(|error| format!("No se pudo crear {}: {error}", target.display()))?;
        let mut entries = fs::read_dir(source)
            .map_err(|error| format!("No se pudo leer {}: {error}", source.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Entrada legacy invalida: {error}"))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            copy_entry(&entry.path(), &target.join(entry.file_name()))?;
        }
    } else if metadata.is_file() {
        fs::copy(source, target)
            .map_err(|error| format!("No se pudo copiar {}: {error}", source.display()))?;
    } else {
        return Err(format!("Entrada legacy no regular: {}.", source.display()));
    }
    Ok(())
}

fn read_release_record(path: &Path) -> Result<ReleaseStateRecord, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    let record = serde_json::from_slice::<ReleaseStateRecord>(&bytes)
        .map_err(|error| format!("RELEASE_STATE_CORRUPT en {}: {error}", path.display()))?;
    if sha256_json(&record.body)? != record.record_sha256 {
        return Err(format!(
            "RELEASE_STATE_CORRUPT: digest invalido en {}.",
            path.display()
        ));
    }
    let expected_name = format!("{:020}-{}.json", record.body.revision, record.record_sha256);
    if path.file_name().and_then(|value| value.to_str()) != Some(expected_name.as_str()) {
        return Err(format!(
            "RELEASE_STATE_CORRUPT: nombre no coincide en {}.",
            path.display()
        ));
    }
    Ok(record)
}

fn release_record_file_name(record: &ReleaseStateRecord) -> String {
    format!("{:020}-{}.json", record.body.revision, record.record_sha256)
}

fn read_release_journal_metadata(path: &Path) -> Result<ReleaseJournalMetadata, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("No se pudo leer genesis de releases: {error}"))?;
    let metadata = serde_json::from_slice::<ReleaseJournalMetadata>(&bytes)
        .map_err(|error| format!("RELEASE_JOURNAL_METADATA_CORRUPT: {error}"))?;
    if metadata.schema != RELEASE_JOURNAL_SCHEMA
        || Uuid::parse_str(&metadata.journal_id).is_err()
        || metadata.genesis_revision == 0
        || metadata.genesis_record_sha256.len() != 64
    {
        return Err("RELEASE_JOURNAL_METADATA_CORRUPT".to_string());
    }
    Ok(metadata)
}

fn has_json_records(path: &Path) -> Result<bool, String> {
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in
        fs::read_dir(path).map_err(|error| format!("No se pudo leer journal canonico: {error}"))?
    {
        let path = entry
            .map_err(|error| format!("Entrada canonica invalida: {error}"))?
            .path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn format_publication_failure(prefix: &str, failure: PublicationFailure) -> String {
    let state = match failure.outcome {
        PublicationOutcome::NotPublished => "NOT_PUBLISHED",
        PublicationOutcome::PublishedButDurabilityUnknown => "DURABILITY_UNKNOWN",
        PublicationOutcome::PublishedDurably(_) => "PUBLISHED_DURABLY",
    };
    format!("{prefix}_{state}: {}", failure.message)
}

#[cfg(unix)]
fn platform_existing_guarantee() -> crate::durability::DurabilityGuarantee {
    crate::durability::DurabilityGuarantee::PosixDirectorySynced
}

#[cfg(unix)]
fn sync_release_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("No se pudo sincronizar {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn sync_release_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn platform_existing_guarantee() -> crate::durability::DurabilityGuarantee {
    crate::durability::DurabilityGuarantee::WindowsWriteThrough
}

fn sha256_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("No se pudo canonicalizar estado: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn write_json_derived(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let contents = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("No se pudo serializar estado: {error}"))?;
    let mut file = File::create(&temporary)
        .map_err(|error| format!("No se pudo crear vista temporal: {error}"))?;
    file.write_all(&contents)
        .map_err(|error| format!("No se pudo escribir vista temporal: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("No se pudo sincronizar vista temporal: {error}"))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("No se pudo retirar vista {}: {error}", path.display()))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo publicar vista {}: {error}", path.display()))
}

fn lock_is_contended(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // ERROR_LOCK_VIOLATION: LockFileEx informa contencion como PermissionDenied.
        error.raw_os_error() == Some(33)
    }
    #[cfg(not(windows))]
    false
}

#[cfg(test)]
mod tests {
    use super::{NodeReleaseState, ReleaseManager};
    use crate::{manifest::tree_sha256, PayloadFile, PayloadManifestV3};
    use sha2::{Digest, Sha256};
    use std::fs;
    use uuid::Uuid;

    fn hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn payload(root: &std::path::Path, version: &str) {
        fs::create_dir_all(root).expect("payload");
        fs::write(root.join("VERSION"), format!("{version}\n")).expect("version");
        fs::write(root.join("compose.yml"), "services: {}\n").expect("compose");
        let files = ["VERSION", "compose.yml"]
            .into_iter()
            .map(|name| {
                let bytes = fs::read(root.join(name)).expect("read");
                PayloadFile {
                    path: name.to_string(),
                    size: bytes.len() as u64,
                    sha256: hex(&Sha256::digest(bytes)),
                }
            })
            .collect::<Vec<_>>();
        let manifest = PayloadManifestV3 {
            schema: 3,
            release_version: version.to_string(),
            generated_at: "now".to_string(),
            site_runtime_schema: "1.1".to_string(),
            tree_sha256: tree_sha256(&files),
            files,
            source_commit: Some("abc".to_string()),
            source_dirty: false,
        };
        fs::write(
            root.join("PAYLOAD.json"),
            serde_json::to_vec_pretty(&manifest).expect("json"),
        )
        .expect("manifest");
    }

    #[test]
    fn staging_promocion_y_rollback_preservan_lkg() {
        let root = std::env::temp_dir().join(format!("actium-releases-{}", Uuid::new_v4()));
        let node = root.join("node");
        let first = root.join("first");
        let second = root.join("second");
        payload(&first, "0.7.0-lab.1");
        payload(&second, "0.7.0-lab.2");
        let manager = ReleaseManager::new(&node);
        manager
            .begin_promotion(manager.prepare(&first).expect("prepare first"))
            .expect("promote first")
            .commit()
            .expect("success");
        let rolled_back = manager
            .begin_promotion(manager.prepare(&second).expect("prepare second"))
            .expect("promote second")
            .abort()
            .expect("abort")
            .complete_recovery()
            .expect("rollback");
        assert_eq!(
            rolled_back.active_release.expect("active").release_version,
            "0.7.0-lab.1"
        );
        assert_eq!(rolled_back.promotion_status, "rolled_back");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn byte_alterado_en_staging_se_rechaza() {
        let root = std::env::temp_dir().join(format!("actium-staging-{}", Uuid::new_v4()));
        let source = root.join("source");
        payload(&source, "0.7.0-lab.1");
        let manager = ReleaseManager::new(root.join("node"));
        let prepared = manager.prepare(&source).expect("prepare");
        fs::write(prepared.staging_path.join("compose.yml"), "alterado").expect("alterar");
        assert!(manager.begin_promotion(prepared).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn first_install_abortado_no_deja_candidato_activo() {
        let root = std::env::temp_dir().join(format!("actium-first-abort-{}", Uuid::new_v4()));
        let source = root.join("source");
        payload(&source, "0.8.0-lab.test");
        let manager = ReleaseManager::new(root.join("node"));
        let transaction = manager
            .begin_promotion(manager.prepare(&source).expect("prepare"))
            .expect("begin");
        let aborted = transaction.abort().expect("abort");
        assert!(!aborted.recovery_required);
        assert!(aborted.state.active_release.is_none());
        assert!(aborted.state.previous_release.is_none());
        assert_eq!(aborted.state.promotion_status, "failed");
        assert_eq!(
            aborted
                .state
                .last_failed_release
                .as_ref()
                .expect("failed")
                .release_version,
            "0.8.0-lab.test"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn drop_del_guard_aborta_upgrade_y_deja_recovery_pendiente() {
        let root = std::env::temp_dir().join(format!("actium-upgrade-abort-{}", Uuid::new_v4()));
        let first = root.join("first");
        let second = root.join("second");
        payload(&first, "0.8.0-lab.1");
        payload(&second, "0.8.0-lab.2");
        let manager = ReleaseManager::new(root.join("node"));
        manager
            .begin_promotion(manager.prepare(&first).expect("prepare first"))
            .expect("begin first")
            .commit()
            .expect("commit first");
        {
            let _interrupted = manager
                .begin_promotion(manager.prepare(&second).expect("prepare second"))
                .expect("begin second");
        }
        let pending = manager.load_state().expect("pending");
        assert_eq!(pending.promotion_status, "recovery_pending");
        assert_eq!(
            pending
                .active_release
                .as_ref()
                .expect("lkg")
                .release_version,
            "0.8.0-lab.1"
        );
        assert_eq!(
            pending
                .last_failed_release
                .as_ref()
                .expect("failed")
                .release_version,
            "0.8.0-lab.2"
        );
        let recovered = manager.mark_recovery_success().expect("recovered");
        assert_eq!(recovered.promotion_status, "rolled_back");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fallo_precommit_first_install_deja_retry_seguro() {
        let root = std::env::temp_dir().join(format!("actium-first-retry-{}", Uuid::new_v4()));
        let source = root.join("source");
        payload(&source, "0.8.0-lab.retry");
        let node = root.join("node");
        let failing = ReleaseManager::with_persistence_faults(&node, ["release.after_temp_sync"]);
        let prepared = failing.prepare(&source).unwrap();
        assert!(failing.begin_promotion(prepared).is_err());
        let retry = ReleaseManager::new(&node)
            .begin_promotion(ReleaseManager::new(&node).prepare(&source).unwrap())
            .expect("retry")
            .commit()
            .expect("commit retry");
        assert_eq!(retry.promotion_status, "active");
        assert_eq!(retry.revision, 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn commit_canonico_no_falla_por_mirror_derivado() {
        let root = std::env::temp_dir().join(format!("actium-mirror-{}", Uuid::new_v4()));
        let source = root.join("source");
        payload(&source, "0.8.0-lab.mirror");
        let node = root.join("node");
        let manager = ReleaseManager::with_persistence_faults(&node, ["release.mirror.active"]);
        let state = manager
            .begin_promotion(manager.prepare(&source).unwrap())
            .expect("begin no depende del mirror")
            .commit()
            .expect("commit");
        assert_eq!(state.promotion_status, "active");
        assert_eq!(ReleaseManager::new(&node).load_state().unwrap(), state);
        assert!(node.join("state/active-release.json").is_file());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_post_rename_reabre_promocion_sin_perder_estado() {
        let root = std::env::temp_dir().join(format!("actium-post-rename-{}", Uuid::new_v4()));
        let source = root.join("source");
        payload(&source, "0.8.0-lab.post-rename");
        let node = root.join("node");
        let manager = ReleaseManager::with_persistence_faults(&node, ["release.after_rename"]);
        manager
            .begin_promotion(manager.prepare(&source).unwrap())
            .expect("checkpoint visible equivale a begin exitoso")
            .simulate_process_crash();
        let reopened = ReleaseManager::new(&node);
        assert_eq!(reopened.load_state().unwrap().promotion_status, "promoting");
        let aborted = reopened.recover_interrupted().unwrap().unwrap();
        assert!(!aborted.recovery_required);
        assert_eq!(aborted.state.promotion_status, "failed");
        assert!(aborted.state.active_release.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lock_rechaza_promociones_concurrentes_y_owner_stale() {
        let root = std::env::temp_dir().join(format!("actium-lock-{}", Uuid::new_v4()));
        let first = root.join("first");
        let second = root.join("second");
        payload(&first, "0.8.0-lab.lock-a");
        payload(&second, "0.8.0-lab.lock-b");
        let node = root.join("node");
        let manager = ReleaseManager::new(&node);
        let transaction = manager
            .begin_promotion(manager.prepare(&first).unwrap())
            .unwrap();
        let concurrent = ReleaseManager::new(&node)
            .begin_promotion(ReleaseManager::new(&node).prepare(&second).unwrap())
            .unwrap_err();
        assert!(concurrent.contains("MUTATION_BUSY"));
        assert!(manager
            .mark_success_owned("otro", "otro", transaction.promoted.revision)
            .unwrap_err()
            .contains("STALE_PROMOTION_OWNER"));
        transaction.abort().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn checkpoint_canonico_corrupto_falla_cerrado() {
        let root = std::env::temp_dir().join(format!("actium-state-corrupt-{}", Uuid::new_v4()));
        let source = root.join("source");
        payload(&source, "0.8.0-lab.corrupt");
        let node = root.join("node");
        let manager = ReleaseManager::new(&node);
        manager
            .begin_promotion(manager.prepare(&source).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let record = fs::read_dir(node.join("state/release-state-v2"))
            .unwrap()
            .last()
            .unwrap()
            .unwrap()
            .path();
        fs::write(record, b"{}").unwrap();
        assert!(manager
            .load_state()
            .unwrap_err()
            .contains("RELEASE_STATE_CORRUPT"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn truncado_de_ultimo_checkpoint_no_retrocede_silenciosamente() {
        let root = std::env::temp_dir().join(format!("actium-state-truncate-{}", Uuid::new_v4()));
        let source = root.join("source");
        payload(&source, "0.8.0-lab.truncate");
        let node = root.join("node");
        let manager = ReleaseManager::new(&node);
        manager
            .begin_promotion(manager.prepare(&source).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let mut records = fs::read_dir(node.join("state/release-state-v2"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        records.sort();
        fs::remove_file(records.last().unwrap()).unwrap();
        assert!(manager
            .load_state()
            .unwrap_err()
            .contains("RELEASE_STATE_TRUNCATED"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fallos_de_commit_abort_y_recovery_quedan_terminales() {
        let root = std::env::temp_dir().join(format!("actium-terminal-faults-{}", Uuid::new_v4()));
        let first = root.join("first");
        let second = root.join("second");
        payload(&first, "0.8.0-lab.terminal-a");
        payload(&second, "0.8.0-lab.terminal-b");

        let first_node = root.join("first-node");
        let manager = ReleaseManager::new(&first_node);
        let transaction = manager
            .begin_promotion(manager.prepare(&first).unwrap())
            .unwrap();
        manager.inject_persistence_fault("release.after_temp_sync");
        assert!(transaction.commit().is_err());
        assert_eq!(manager.load_state().unwrap().promotion_status, "failed");

        let abort_node = root.join("abort-node");
        let manager = ReleaseManager::new(&abort_node);
        let transaction = manager
            .begin_promotion(manager.prepare(&first).unwrap())
            .unwrap();
        manager.inject_persistence_fault("release.after_temp_sync");
        assert!(transaction.abort().is_err());
        assert_eq!(manager.load_state().unwrap().promotion_status, "failed");

        let recovery_node = root.join("recovery-node");
        let manager = ReleaseManager::new(&recovery_node);
        manager
            .begin_promotion(manager.prepare(&first).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        let recovery = manager
            .begin_promotion(manager.prepare(&second).unwrap())
            .unwrap()
            .abort()
            .unwrap();
        manager.inject_persistence_fault("release.after_temp_sync");
        assert!(recovery.complete_recovery().is_err());
        assert_eq!(
            manager.load_state().unwrap().promotion_status,
            "manual_intervention_required"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn adopcion_legacy_reutiliza_authority_existente_sin_reentrada() {
        let root = std::env::temp_dir().join(format!("actium-legacy-lock-{}", Uuid::new_v4()));
        let node = root.join("node");
        fs::create_dir_all(&node).unwrap();
        fs::write(node.join("compose.yml"), "services: {}\n").unwrap();
        let manager = ReleaseManager::new(&node);
        let guard = manager.lock_mutation().unwrap();
        let adopted = manager
            .snapshot_legacy_locked("0.6.6", "legacy-digest", &guard)
            .unwrap();
        assert!(adopted.release_id.starts_with("legacy-0.6.6"));
        assert_eq!(manager.load_state().unwrap().promotion_status, "legacy_lkg");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migracion_legacy_revision_ocho_declara_genesis_coherente() {
        let root = std::env::temp_dir().join(format!("actium-release-genesis-{}", Uuid::new_v4()));
        let node = root.join("node");
        fs::create_dir_all(node.join("state")).unwrap();
        let legacy = NodeReleaseState {
            revision: 8,
            promotion_status: "active".to_string(),
            ..NodeReleaseState::default()
        };
        fs::write(
            node.join("state/release-state.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();
        let manager = ReleaseManager::new(&node);
        assert_eq!(manager.load_state().unwrap().revision, 8);
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(node.join("state/release-journal-v2.json")).unwrap())
                .unwrap();
        assert_eq!(metadata["genesisRevision"], 8);
        assert_eq!(
            fs::read_dir(node.join("state/release-state-v2"))
                .unwrap()
                .filter_map(Result::ok)
                .count(),
            1
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn perdida_de_journal_canonico_no_usa_mirrors_derivados() {
        let root = std::env::temp_dir().join(format!("actium-release-loss-{}", Uuid::new_v4()));
        let source = root.join("source");
        let node = root.join("node");
        payload(&source, "0.8.0-lab.loss");
        let manager = ReleaseManager::new(&node);
        manager
            .begin_promotion(manager.prepare(&source).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        assert!(node.join("state/release-state.json").is_file());
        fs::remove_dir_all(node.join("state/release-state-v2")).unwrap();
        assert!(manager
            .load_state()
            .unwrap_err()
            .contains("RELEASE_JOURNAL_MISSING"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stages_de_durabilidad_distinguen_no_publicado_unknown_y_durable() {
        for (index, stage) in ["release.before_temp_write", "release.after_temp_sync"]
            .into_iter()
            .enumerate()
        {
            let root =
                std::env::temp_dir().join(format!("actium-rel-np-{index}-{}", Uuid::new_v4()));
            let source = root.join("source");
            let node = root.join("node");
            payload(&source, "0.8.0-lab.not-published");
            let manager = ReleaseManager::with_persistence_faults(&node, [stage]);
            assert!(manager
                .begin_promotion(manager.prepare(&source).unwrap())
                .unwrap_err()
                .contains("RELEASE_NOT_PUBLISHED"));
            let retry = ReleaseManager::new(&node);
            retry
                .begin_promotion(retry.prepare(&source).unwrap())
                .unwrap()
                .commit()
                .unwrap();
            let _ = fs::remove_dir_all(root);
        }

        for stage in [
            "release.after_rename_before_directory_sync",
            "release.directory_sync",
        ] {
            let root =
                std::env::temp_dir().join(format!("actium-release-unknown-{}", Uuid::new_v4()));
            let source = root.join("source");
            let node = root.join("node");
            payload(&source, "0.8.0-lab.unknown");
            let manager = ReleaseManager::with_persistence_faults(&node, [stage]);
            let error = manager
                .begin_promotion(manager.prepare(&source).unwrap())
                .unwrap_err();
            assert!(
                error.contains("RELEASE_DURABILITY_UNKNOWN"),
                "{stage}: {error}"
            );
            assert!(ReleaseManager::new(&node)
                .load_state()
                .unwrap_err()
                .contains("RELEASE_DURABILITY_RECOVERY_REQUIRED"));
            let _ = fs::remove_dir_all(root);
        }

        let root = std::env::temp_dir().join(format!("actium-release-durable-{}", Uuid::new_v4()));
        let source = root.join("source");
        let node = root.join("node");
        payload(&source, "0.8.0-lab.durable");
        let manager =
            ReleaseManager::with_persistence_faults(&node, ["release.after_durable_publication"]);
        manager
            .begin_promotion(manager.prepare(&source).unwrap())
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(manager.load_state().unwrap().promotion_status, "active");
        let _ = fs::remove_dir_all(root);
    }
}
