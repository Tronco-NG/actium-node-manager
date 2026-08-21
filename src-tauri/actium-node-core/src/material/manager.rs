use super::state::MaterialStateStore;
use super::trust::MaterialTrustStore;
use super::types::*;
use super::verify::{
    compute_content_digest_from_disk, compute_manifest_digest, hex_sha256, key_id_for_public_key,
    verify_ed25519_signature,
};
use crate::material_fs::{
    generation_dir_name, material_capability_root, normalize_relative_path, path_under_prefix,
    MaterialFilesystemBackend, StdMaterialFilesystem,
};
use fs2::FileExt;
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct MaterialMutationGuard {
    file: File,
}

impl Drop for MaterialMutationGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub struct MaterialManager {
    node_root: PathBuf,
    trust: MaterialTrustStore,
    contracts: MaterialContractRegistry,
    limits: MaterialResourceLimits,
    fs: StdMaterialFilesystem,
}

impl MaterialManager {
    pub fn new(
        node_root: impl AsRef<Path>,
        trust: MaterialTrustStore,
        contracts: MaterialContractRegistry,
        limits: MaterialResourceLimits,
    ) -> Self {
        Self {
            node_root: node_root.as_ref().to_path_buf(),
            trust,
            contracts,
            limits,
            fs: StdMaterialFilesystem,
        }
    }

    pub fn lock_mutation(&self) -> Result<MaterialMutationGuard, String> {
        let path = self.node_root.join("state/material-mutation.lock");
        if let Some(parent) = path.parent() {
            self.fs.ensure_dir(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("MATERIAL_LOCK_OPEN: {e}"))?;
        file.try_lock_exclusive()
            .map_err(|_| "MATERIAL_MUTATION_BUSY".to_string())?;
        Ok(MaterialMutationGuard { file })
    }

    pub fn get_state(&self, capability: &str) -> Result<MaterialStateV1, String> {
        MaterialStateStore::open(material_capability_root(&self.node_root, capability))?.load()
    }

    pub fn stage_verify_to_candidate(
        &self,
        package_dir: &Path,
        scope: &NodeScope,
        _activate: bool,
    ) -> Result<MaterialStateV1, String> {
        let _lock = self.lock_mutation()?;
        let package = self.verify_package_dir(package_dir, scope)?;
        let store = MaterialStateStore::open(material_capability_root(
            &self.node_root,
            &package.body.capability,
        ))?;
        let state = store.load()?;
        self.enforce_lineage(&state, &package)?;
        if let Some(until) = &package.body.valid_until {
            if now_ts().as_str() > until.as_str() {
                return Err("MATERIAL_PACKAGE_EXPIRED".into());
            }
        }
        let dir_name = generation_dir_name(
            package.body.authority_epoch,
            package.body.generation,
            package.body.revision,
            &package.body.material_content_digest,
        );
        let gen_root = store.generations_dir().join(&dir_name);
        if !gen_root.exists() {
            self.materialize_generation(package_dir, &package, &gen_root)?;
        }
        let _ = self.limits.max_generations;
        let material_ref = MaterialRef {
            material_id: package.body.material_id.clone(),
            authority_epoch: package.body.authority_epoch,
            generation: package.body.generation,
            revision: package.body.revision,
            material_content_digest: package.body.material_content_digest.clone(),
            package_dir_name: dir_name,
            verified_at: Some(now_ts()),
            health_at: None,
        };
        let base = state.state_revision;
        let mut next = state;
        next.deployment_id = scope.deployment_id.clone();
        next.capability = package.body.capability.clone();
        next.candidate = Some(material_ref);
        next.status = "stage_verified".into();
        next.last_error = None;
        store.commit_transition(base, next)
    }

    pub fn complete_health_and_commit(
        &self,
        capability: &str,
        expected_digest: &str,
    ) -> Result<MaterialStateV1, String> {
        let _lock = self.lock_mutation()?;
        let store =
            MaterialStateStore::open(material_capability_root(&self.node_root, capability))?;
        let state = store.load()?;
        let candidate = state
            .candidate
            .clone()
            .ok_or_else(|| "MATERIAL_NO_CANDIDATE".to_string())?;
        if candidate.material_content_digest != expected_digest {
            return Err("MATERIAL_CANDIDATE_DIGEST_MISMATCH".into());
        }
        let base = state.state_revision;
        let mut next = state;
        if let Some(prev) = next.active.take() {
            next.lkg = Some(prev);
        }
        let mut committed = candidate;
        committed.health_at = Some(now_ts());
        next.active = Some(committed);
        next.candidate = None;
        next.status = "active".into();
        next.last_error = None;
        store.commit_transition(base, next)
    }

    pub fn recover_to_lkg_internal(&self, capability: &str) -> Result<MaterialStateV1, String> {
        let _lock = self.lock_mutation()?;
        let store =
            MaterialStateStore::open(material_capability_root(&self.node_root, capability))?;
        let state = store.load()?;
        let base = state.state_revision;
        let mut next = state;
        if let Some(lkg) = next.lkg.clone() {
            next.active = Some(lkg);
            next.status = "active".into();
        } else if next.active.is_some() {
            next.status = "active".into();
        } else {
            next.status = "idle".into();
        }
        next.candidate = None;
        next.last_error.replace("MATERIAL_RECOVERY_TO_LKG".into());
        store.commit_transition(base, next)
    }

    pub fn verify_package_dir(
        &self,
        package_dir: &Path,
        scope: &NodeScope,
    ) -> Result<MaterialPackageV1, String> {
        let bytes = self
            .fs
            .read_regular_file_bounded(&package_dir.join("package.json"), 1024 * 1024)?;
        let package: MaterialPackageV1 =
            serde_json::from_slice(&bytes).map_err(|e| format!("MATERIAL_PACKAGE_INVALID: {e}"))?;
        self.verify_package(&package, package_dir, scope)?;
        Ok(package)
    }

    pub fn verify_package(
        &self,
        package: &MaterialPackageV1,
        content_root: &Path,
        scope: &NodeScope,
    ) -> Result<(), String> {
        let b = &package.body;
        if b.schema != MATERIAL_PACKAGE_SCHEMA || b.typ != "actium.material.v1" {
            return Err("MATERIAL_PACKAGE_SCHEMA".into());
        }
        if b.content_digest_alg != MATERIAL_CONTENT_DIGEST_ALG
            || b.manifest_digest_alg != MATERIAL_MANIFEST_DIGEST_ALG
        {
            return Err("MATERIAL_DIGEST_ALG_UNSUPPORTED".into());
        }
        if b.organization_id != scope.organization_id
            || b.site_id != scope.site_id
            || b.deployment_id != scope.deployment_id
        {
            return Err("MATERIAL_SCOPE_MISMATCH".into());
        }
        if let Some(node_id) = &b.node_id {
            if scope.node_id.as_ref() != Some(node_id) {
                return Err("MATERIAL_NODE_MISMATCH".into());
            }
        }
        if !b.audience.iter().any(|a| {
            a == "actium-node-supervisor"
                || a == &format!("urn:actium:deployment:{}", scope.deployment_id)
        }) {
            return Err("MATERIAL_AUDIENCE_REJECTED".into());
        }
        for feature in &b.feature_requirements {
            if !scope.supervisor_features.iter().any(|f| f == feature) {
                return Err(format!("MATERIAL_FEATURE_UNSATISFIED:{feature}"));
            }
        }
        let contract = self.contracts.get(&b.capability)?;
        if b.content_manifest.len() > contract.max_file_count {
            return Err("MATERIAL_FILE_COUNT_EXCEEDED".into());
        }
        let mut total = 0u64;
        for entry in &b.content_manifest {
            let rel = normalize_relative_path(&entry.path)?;
            if !path_under_prefix(&rel, &contract.allowed_path_prefixes) {
                return Err(format!("MATERIAL_PATH_NOT_ALLOWED:{rel}"));
            }
            if entry.size > contract.max_file_bytes {
                return Err(format!("MATERIAL_FILE_TOO_LARGE:{rel}"));
            }
            total = total.saturating_add(entry.size);
            if total > contract.max_total_bytes {
                return Err("MATERIAL_TOTAL_BYTES_EXCEEDED".into());
            }
        }
        self.fs.reject_unsafe_tree(
            &content_root.join("content"),
            contract.max_file_count,
            contract.max_total_bytes,
        )?;
        if compute_manifest_digest(&b.content_manifest)? != b.material_manifest_digest {
            return Err("MATERIAL_MANIFEST_DIGEST_MISMATCH".into());
        }
        if compute_content_digest_from_disk(
            &self.fs,
            &content_root.join("content"),
            &b.content_manifest,
        )? != b.material_content_digest
        {
            return Err("MATERIAL_CONTENT_DIGEST_MISMATCH".into());
        }
        let trusted = self.trust.resolve_and_authorize(
            &package.signature.key_id,
            &b.issuer,
            &b.capability,
            &b.organization_id,
            &b.site_id,
            &b.deployment_id,
            &b.issued_at,
            false,
        )?;
        verify_ed25519_signature(package, &trusted)?;
        Ok(())
    }

    fn enforce_lineage(
        &self,
        state: &MaterialStateV1,
        package: &MaterialPackageV1,
    ) -> Result<(), String> {
        let baseline = state
            .active
            .as_ref()
            .or(state.lkg.as_ref())
            .or(state.candidate.as_ref());
        let Some(baseline) = baseline else {
            return Ok(());
        };
        let b = &package.body;
        if b.authority_epoch < baseline.authority_epoch {
            return Err("MATERIAL_AUTHORITY_EPOCH_REGRESSION".into());
        }
        if b.authority_epoch == baseline.authority_epoch {
            if b.generation < baseline.generation {
                return Err("MATERIAL_GENERATION_REGRESSION".into());
            }
            if b.generation == baseline.generation {
                if b.revision < baseline.revision {
                    return Err("MATERIAL_REVISION_REGRESSION".into());
                }
                if b.revision == baseline.revision
                    && b.material_content_digest != baseline.material_content_digest
                {
                    return Err("MATERIAL_REVISION_COLLISION".into());
                }
            }
            if b.generation > baseline.generation {
                let _ = self.trust.resolve_and_authorize(
                    &package.signature.key_id,
                    &b.issuer,
                    &b.capability,
                    &b.organization_id,
                    &b.site_id,
                    &b.deployment_id,
                    &b.issued_at,
                    true,
                )?;
            }
        }
        if b.authority_epoch > baseline.authority_epoch {
            let _ = self.trust.resolve_and_authorize(
                &package.signature.key_id,
                &b.issuer,
                &b.capability,
                &b.organization_id,
                &b.site_id,
                &b.deployment_id,
                &b.issued_at,
                true,
            )?;
        }
        if let Some(pred) = &b.predecessor_material_digest {
            let ok = state
                .active
                .as_ref()
                .map(|a| &a.material_content_digest == pred)
                .unwrap_or(false)
                || state
                    .lkg
                    .as_ref()
                    .map(|a| &a.material_content_digest == pred)
                    .unwrap_or(false);
            if !ok && pred != &baseline.material_content_digest {
                return Err("MATERIAL_PREDECESSOR_UNKNOWN".into());
            }
        }
        Ok(())
    }

    fn materialize_generation(
        &self,
        package_dir: &Path,
        package: &MaterialPackageV1,
        generation_root: &Path,
    ) -> Result<(), String> {
        self.fs.ensure_dir(generation_root)?;
        let content_src = package_dir.join("content");
        let content_dst = generation_root.join("content");
        self.fs.ensure_dir(&content_dst)?;
        for entry in &package.body.content_manifest {
            let rel = normalize_relative_path(&entry.path)?;
            let bytes = self
                .fs
                .read_regular_file_bounded(&content_src.join(&rel), entry.size as usize + 1)?;
            if bytes.len() as u64 != entry.size || hex_sha256(&bytes) != entry.sha256 {
                return Err(format!("MATERIAL_FILE_DIGEST_MISMATCH:{rel}"));
            }
            self.fs
                .write_bytes_exclusive(&content_dst.join(&rel), &bytes)?;
        }
        let package_bytes = serde_json::to_vec_pretty(package)
            .map_err(|e| format!("MATERIAL_PACKAGE_SERIALIZE: {e}"))?;
        self.fs
            .write_bytes_exclusive(&generation_root.join("package.json"), &package_bytes)?;
        let verify = serde_json::json!({
            "schema": 1,
            "verifiedAt": now_ts(),
            "materialContentDigest": package.body.material_content_digest,
        });
        self.fs.write_bytes_exclusive(
            &generation_root.join("VERIFY.json"),
            &serde_json::to_vec_pretty(&verify).unwrap(),
        )?;
        Ok(())
    }
}

fn now_ts() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs:020}")
}

#[allow(dead_code)]
fn _keep_key_id() {
    let _ = key_id_for_public_key;
}
