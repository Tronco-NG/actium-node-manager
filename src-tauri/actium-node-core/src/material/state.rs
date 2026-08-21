use crate::durability::{publish_immutable, replace_durable};
use crate::material_fs::MaterialFilesystemBackend;
use crate::material_fs::StdMaterialFilesystem;
use super::types::{MaterialRef, MaterialStateV1, MATERIAL_STATE_SCHEMA};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

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
    capability_root: PathBuf,
    fs: StdMaterialFilesystem,
}

impl MaterialStateStore {
    pub fn open(capability_root: PathBuf) -> Result<Self, String> {
        let store = Self {
            capability_root,
            fs: StdMaterialFilesystem,
        };
        store.fs.ensure_dir(&store.journal_dir())?;
        store.fs.ensure_dir(&store.generations_dir())?;
        Ok(store)
    }

    pub fn journal_dir(&self) -> PathBuf {
        self.capability_root.join("journal")
    }

    pub fn generations_dir(&self) -> PathBuf {
        self.capability_root.join("generations")
    }

    pub fn capability_root(&self) -> &PathBuf {
        &self.capability_root
    }

    pub fn load(&self) -> Result<MaterialStateV1, String> {
        match self.load_latest_record()? {
            Some(record) => {
                self.sync_derived_views(&record.body.state)?;
                Ok(record.body.state)
            }
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
                updated_at: now_ts(),
            }),
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
        next.updated_at = now_ts();
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
        if !dir.is_dir() {
            return Ok(None);
        }
        let mut paths: Vec<_> = fs::read_dir(&dir)
            .map_err(|e| format!("MATERIAL_JOURNAL_READ: {e}"))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|v| v.to_str()) == Some("json"))
            .collect();
        paths.sort();
        if paths.is_empty() {
            return Ok(None);
        }
        let mut prev_hash = None;
        let mut prev_rev = 0u64;
        let mut latest = None;
        for path in paths {
            let bytes = fs::read(&path).map_err(|e| format!("MATERIAL_JOURNAL_READ: {e}"))?;
            let record: MaterialStateRecord = serde_json::from_slice(&bytes)
                .map_err(|e| format!("MATERIAL_STATE_CORRUPT: {e}"))?;
            if sha256_json(&record.body)? != record.record_sha256 {
                return Err("MATERIAL_STATE_CORRUPT: digest mismatch".into());
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

    fn sync_derived_views(&self, state: &MaterialStateV1) -> Result<(), String> {
        for (name, value) in [
            ("active.json", serde_json::to_vec_pretty(&state.active)),
            ("lkg.json", serde_json::to_vec_pretty(&state.lkg)),
            ("candidate.json", serde_json::to_vec_pretty(&state.candidate)),
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

fn now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs:020}")
}

#[allow(dead_code)]
pub type _MaterialRefKeep = MaterialRef;
