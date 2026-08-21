use super::types::{material_now_ts, MaterialRef, MaterialStateV1, MATERIAL_STATE_SCHEMA};
use crate::durability::{publish_immutable, replace_durable};
use crate::material_fs::{MaterialFilesystemBackend, StdMaterialFilesystem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct MaterialStateRecordBody {
    schema: u8,
    state_revision: u64,
    previous_record_sha256: Option<String>,
    state: MaterialStateV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct MaterialStateRecord {
    #[serde(flatten)]
    body: MaterialStateRecordBody,
    record_sha256: String,
}

pub struct MaterialStateStore {
    capability_root: std::path::PathBuf,
    fs: Arc<dyn MaterialFilesystemBackend>,
}

impl MaterialStateStore {
    pub fn open(capability_root: std::path::PathBuf) -> Result<Self, String> {
        Self::open_with_backend(capability_root, Arc::new(StdMaterialFilesystem))
    }

    pub fn open_with_backend(
        capability_root: std::path::PathBuf,
        fs: Arc<dyn MaterialFilesystemBackend>,
    ) -> Result<Self, String> {
        let store = Self {
            capability_root,
            fs,
        };
        store.fs.ensure_dir(&store.journal_dir())?;
        store.fs.ensure_dir(&store.generations_dir())?;
        Ok(store)
    }

    pub fn journal_dir(&self) -> std::path::PathBuf {
        self.capability_root.join("journal")
    }

    pub fn generations_dir(&self) -> std::path::PathBuf {
        self.capability_root.join("generations")
    }

    pub fn capability_root(&self) -> &std::path::PathBuf {
        &self.capability_root
    }

    pub fn load(&self) -> Result<MaterialStateV1, String> {
        let journal = self.load_latest_record()?;
        let mirrors_exist = self.any_mirror_exists()?;
        match journal {
            None if mirrors_exist => Err("MATERIAL_STATE_JOURNAL_MISSING".into()),
            None => Ok(MaterialStateV1 {
                schema: MATERIAL_STATE_SCHEMA,
                state_revision: 0,
                capability: self
                    .capability_root
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                deployment_id: String::new(),
                status: "idle".into(),
                active: None,
                lkg: None,
                candidate: None,
                promotion_id: None,
                promotion_base_state_revision: None,
                last_error: None,
                updated_at: material_now_ts(),
            }),
            Some(record) => {
                if let Some(mirror_revision) = self.mirror_state_revision()? {
                    if mirror_revision > record.body.state.state_revision {
                        return Err("MATERIAL_STATE_MIRROR_AHEAD".into());
                    }
                }
                self.sync_derived_views(&record.body.state)?;
                Ok(record.body.state)
            }
        }
    }

    pub fn commit_transition(
        &self,
        expected_revision: u64,
        mut next: MaterialStateV1,
    ) -> Result<MaterialStateV1, String> {
        let latest = self.load_latest_record()?;
        let current = latest.as_ref().map(|r| r.body.state_revision).unwrap_or(0);
        if current != expected_revision {
            return Err(format!(
                "MATERIAL_STATE_REVISION_CONFLICT: expected {expected_revision}, actual {current}"
            ));
        }
        next.schema = MATERIAL_STATE_SCHEMA;
        next.state_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| "MATERIAL_STATE_REVISION_OVERFLOW".to_string())?;
        next.updated_at = material_now_ts();
        let body = MaterialStateRecordBody {
            schema: MATERIAL_STATE_SCHEMA,
            state_revision: next.state_revision,
            previous_record_sha256: latest.as_ref().map(|r| r.record_sha256.clone()),
            state: next.clone(),
        };
        let record = MaterialStateRecord {
            record_sha256: sha256_json(&body)?,
            body,
        };
        let path = self.journal_dir().join(format!(
            "{:020}-{}.json",
            record.body.state_revision, record.record_sha256
        ));
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|e| format!("MATERIAL_STATE_SERIALIZE: {e}"))?;
        publish_immutable(&path, &bytes, |_| Ok(()))
            .map_err(|f| format!("MATERIAL_STATE_PUBLISH: {}", f.message))?;
        self.sync_derived_views(&next)?;
        Ok(next)
    }

    fn load_latest_record(&self) -> Result<Option<MaterialStateRecord>, String> {
        let dir = self.journal_dir();
        if !self.fs.is_dir(&dir) {
            return Ok(None);
        }
        let mut names = self.fs.list_relative_files(&dir)?;
        names.retain(|name| name.ends_with(".json") && !name.contains('/'));
        names.sort();
        if names.is_empty() {
            return Ok(None);
        }
        let mut prev_hash = None;
        let mut prev_rev = 0u64;
        let mut seen_revs = std::collections::BTreeSet::new();
        let mut latest = None;
        for name in names {
            let path = dir.join(&name);
            let bytes = self.fs.read_regular_file_bounded(&path, 1024 * 1024)?;
            let record: MaterialStateRecord = serde_json::from_slice(&bytes)
                .map_err(|e| format!("MATERIAL_STATE_CORRUPT: {e}"))?;
            if sha256_json(&record.body)? != record.record_sha256 {
                return Err("MATERIAL_STATE_CORRUPT: digest mismatch".into());
            }
            if !seen_revs.insert(record.body.state_revision) {
                return Err(format!(
                    "MATERIAL_STATE_CORRUPT: duplicate revision {} at {}",
                    record.body.state_revision,
                    path.display()
                ));
            }
            if record.body.state_revision != prev_rev.saturating_add(1)
                || record.body.previous_record_sha256 != prev_hash
            {
                return Err(format!(
                    "MATERIAL_STATE_CORRUPT: chain break at {}",
                    path.display()
                ));
            }
            prev_rev = record.body.state_revision;
            prev_hash = Some(record.record_sha256.clone());
            latest = Some(record);
        }
        Ok(latest)
    }

    fn mirror_names() -> [&'static str; 4] {
        [
            "active.json",
            "lkg.json",
            "candidate.json",
            "material-state.json",
        ]
    }

    fn any_mirror_exists(&self) -> Result<bool, String> {
        for name in Self::mirror_names() {
            if self.fs.path_exists(&self.capability_root.join(name)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn mirror_state_revision(&self) -> Result<Option<u64>, String> {
        let path = self.capability_root.join("material-state.json");
        if !self.fs.path_exists(&path) {
            return Ok(None);
        }
        let bytes = match self.fs.read_regular_file_bounded(&path, 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(None),
        };
        match serde_json::from_slice::<MaterialStateV1>(&bytes) {
            Ok(state) => Ok(Some(state.state_revision)),
            Err(_) => Ok(None),
        }
    }

    fn sync_derived_views(&self, state: &MaterialStateV1) -> Result<(), String> {
        for (name, value) in [
            ("active.json", serde_json::to_vec_pretty(&state.active)),
            ("lkg.json", serde_json::to_vec_pretty(&state.lkg)),
            (
                "candidate.json",
                serde_json::to_vec_pretty(&state.candidate),
            ),
            ("material-state.json", serde_json::to_vec_pretty(state)),
        ] {
            let bytes = value.map_err(|e| format!("MATERIAL_VIEW_SERIALIZE: {e}"))?;
            replace_durable(&self.capability_root.join(name), &bytes, |_| Ok(()))
                .map_err(|f| format!("MATERIAL_VIEW: {}", f.message))?;
        }
        Ok(())
    }
}

fn sha256_json(value: &impl Serialize) -> Result<String, String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(&serde_json::to_vec(value).map_err(|e| format!("json: {e}"))?)
    ))
}

#[allow(dead_code)]
pub type _MaterialRefKeep = MaterialRef;
