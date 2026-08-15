use crate::{verify_payload, PayloadManifestV3, VerifiedPayload};
use fs2::available_space;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct NodeReleaseState {
    pub active_release: Option<ReleaseMetadata>,
    pub previous_release: Option<ReleaseMetadata>,
    pub promotion_status: String,
    pub last_successful_release: Option<ReleaseMetadata>,
    pub last_failed_release: Option<ReleaseMetadata>,
}

#[derive(Debug, Clone)]
pub struct PreparedRelease {
    pub staging_path: PathBuf,
    pub metadata: ReleaseMetadata,
}

#[derive(Debug, Clone)]
pub struct ReleaseManager {
    node_root: PathBuf,
}

impl ReleaseManager {
    pub fn new(node_root: impl AsRef<Path>) -> Self {
        Self {
            node_root: node_root.as_ref().to_path_buf(),
        }
    }

    pub fn ensure_layout(&self) -> Result<(), String> {
        for directory in ["releases", "staging", "state", "secrets", "persistent"] {
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
        let path = self.state_path();
        if !path.exists() {
            return Ok(NodeReleaseState {
                promotion_status: "legacy_unmanaged".to_string(),
                ..Default::default()
            });
        }
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
        serde_json::from_str(&contents)
            .map_err(|error| format!("Estado de releases invalido: {error}"))
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
        self.write_state(&state)?;
        Ok(metadata)
    }

    pub fn promote(&self, prepared: PreparedRelease) -> Result<NodeReleaseState, String> {
        self.ensure_layout()?;
        verify_payload(&prepared.staging_path)?;
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
        let mut state = self.load_state()?;
        state.previous_release = state.active_release.take();
        state.active_release = Some(prepared.metadata);
        state.promotion_status = "promoting".to_string();
        self.write_state(&state)?;
        Ok(state)
    }

    pub fn mark_success(&self) -> Result<NodeReleaseState, String> {
        let mut state = self.load_state()?;
        state.last_successful_release = state.active_release.clone();
        state.promotion_status = "active".to_string();
        self.write_state(&state)?;
        Ok(state)
    }

    pub fn rollback(&self) -> Result<NodeReleaseState, String> {
        let mut state = self.load_state()?;
        let failed = state
            .active_release
            .take()
            .ok_or_else(|| "No existe release candidato activo para rollback.".to_string())?;
        let previous = state
            .previous_release
            .take()
            .ok_or_else(|| "No existe LKG anterior para rollback.".to_string())?;
        state.active_release = Some(previous.clone());
        state.previous_release = Some(failed.clone());
        state.last_failed_release = Some(failed);
        state.last_successful_release = Some(previous);
        state.promotion_status = "rolled_back".to_string();
        self.write_state(&state)?;
        Ok(state)
    }

    pub fn mark_failed_without_rollback(&self) -> Result<NodeReleaseState, String> {
        let mut state = self.load_state()?;
        state.last_failed_release = state.active_release.take();
        if let Some(previous) = state.previous_release.take() {
            state.last_successful_release = Some(previous.clone());
            state.active_release = Some(previous);
            state.promotion_status = "rolled_back".to_string();
        } else {
            state.promotion_status = "failed".to_string();
        }
        self.write_state(&state)?;
        Ok(state)
    }

    fn state_path(&self) -> PathBuf {
        self.node_root.join("state").join("release-state.json")
    }

    fn write_state(&self, state: &NodeReleaseState) -> Result<(), String> {
        self.ensure_layout()?;
        write_json_atomic(&self.state_path(), state)?;
        let active = self.node_root.join("state").join("active-release.json");
        let previous = self.node_root.join("state").join("previous-release.json");
        write_json_atomic(&active, &state.active_release)?;
        write_json_atomic(&previous, &state.previous_release)?;
        write_json_atomic(&self.node_root.join("current"), &state.active_release)?;
        Ok(())
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

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let contents = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("No se pudo serializar estado: {error}"))?;
    fs::write(&temporary, contents)
        .map_err(|error| format!("No se pudo escribir estado temporal: {error}"))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("No se pudo reemplazar {}: {error}", path.display()))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo promover {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::ReleaseManager;
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
            .promote(manager.prepare(&first).expect("prepare first"))
            .expect("promote first");
        manager.mark_success().expect("success");
        manager
            .promote(manager.prepare(&second).expect("prepare second"))
            .expect("promote second");
        let rolled_back = manager.rollback().expect("rollback");
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
        assert!(manager.promote(prepared).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
