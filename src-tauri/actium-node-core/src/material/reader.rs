//! Read-only Supervisor-authoritative material consumption.
//!
//! Legacy workloads may keep reading `state/agent`. New-capable workloads should
//! consume `state/supervisor/material/<capability>` through this reader only.

use super::state::MaterialStateStore;
use super::types::MaterialRef;
use super::verify::compute_content_digest_from_disk;
use crate::material_fs::{
    material_capability_root, normalize_relative_path, MaterialFilesystemBackend,
    StdMaterialFilesystem,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveMaterial {
    pub capability: String,
    pub generation: u64,
    pub authority_epoch: u64,
    pub revision: u64,
    pub material_digest: String,
    pub package_dir_name: String,
    pub root: PathBuf,
}

pub struct SupervisorMaterialReader {
    node_root: PathBuf,
    fs: Arc<dyn MaterialFilesystemBackend>,
}

impl SupervisorMaterialReader {
    pub fn new(node_root: impl AsRef<Path>) -> Self {
        Self::with_backend(node_root, Arc::new(StdMaterialFilesystem))
    }

    pub fn with_backend(
        node_root: impl AsRef<Path>,
        fs: Arc<dyn MaterialFilesystemBackend>,
    ) -> Self {
        Self {
            node_root: node_root.as_ref().to_path_buf(),
            fs,
        }
    }

    pub fn resolve_active(&self, capability: &str) -> Result<ActiveMaterial, String> {
        if capability.trim().is_empty() {
            return Err("MATERIAL_CAPABILITY_INVALID".into());
        }
        let store = MaterialStateStore::open_with_backend(
            material_capability_root(&self.node_root, capability),
            Arc::clone(&self.fs),
        )?;
        let state = store.load()?;
        let active = state
            .active
            .ok_or_else(|| "MATERIAL_ACTIVE_MISSING".to_string())?;
        self.active_from_ref(capability, &store, &active)
    }

    pub fn verify_digest(&self, active: &ActiveMaterial) -> Result<(), String> {
        let package_bytes = self
            .fs
            .read_regular_file_bounded(&active.root.join("package.json"), 1024 * 1024)?;
        let package: super::types::MaterialPackageV1 = serde_json::from_slice(&package_bytes)
            .map_err(|e| format!("MATERIAL_PACKAGE_INVALID: {e}"))?;
        if package.body.material_content_digest != active.material_digest {
            return Err("MATERIAL_ACTIVE_DIGEST_MISMATCH".into());
        }
        if package.body.generation != active.generation
            || package.body.authority_epoch != active.authority_epoch
            || package.body.revision != active.revision
        {
            return Err("MATERIAL_ACTIVE_IDENTITY_MISMATCH".into());
        }
        let computed = compute_content_digest_from_disk(
            self.fs.as_ref(),
            &active.root.join("content"),
            &package.body.content_manifest,
        )?;
        if computed != active.material_digest {
            return Err("MATERIAL_ACTIVE_CONTENT_TAMPERED".into());
        }
        Ok(())
    }

    pub fn read_file(
        &self,
        capability: &str,
        relative: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        let active = self.resolve_active(capability)?;
        self.verify_digest(&active)?;
        let rel = normalize_relative_path(relative)?;
        let path = active.root.join("content").join(&rel);
        self.fs.read_regular_file_bounded(&path, max_bytes)
    }

    fn active_from_ref(
        &self,
        capability: &str,
        store: &MaterialStateStore,
        active: &MaterialRef,
    ) -> Result<ActiveMaterial, String> {
        let root = store.generations_dir().join(&active.package_dir_name);
        if !self.fs.is_dir(&root) {
            return Err("MATERIAL_ACTIVE_MISSING".into());
        }
        let resolved = ActiveMaterial {
            capability: capability.to_string(),
            generation: active.generation,
            authority_epoch: active.authority_epoch,
            revision: active.revision,
            material_digest: active.material_content_digest.clone(),
            package_dir_name: active.package_dir_name.clone(),
            root,
        };
        self.verify_digest(&resolved)?;
        Ok(resolved)
    }
}
