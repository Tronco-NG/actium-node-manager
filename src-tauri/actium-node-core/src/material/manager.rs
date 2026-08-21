use super::state::MaterialStateStore;
use super::trust::MaterialTrustStore;
use super::types::*;
use super::verify::{
    compute_content_digest_from_disk, compute_manifest_digest, hex_sha256, verify_ed25519_signature,
};
use crate::material_fs::{
    generation_dir_name, material_capability_root, material_inbox_root, material_root,
    normalize_relative_path, path_under_prefix, MaterialFilesystemBackend, StdMaterialFilesystem,
};
use fs2::FileExt;
use std::sync::Arc;
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
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
    fs: Arc<dyn MaterialFilesystemBackend>,
    allow_fixture_health: bool,
}

impl MaterialManager {
    pub fn new(
        node_root: impl AsRef<Path>,
        trust: MaterialTrustStore,
        contracts: MaterialContractRegistry,
        limits: MaterialResourceLimits,
    ) -> Self {
        Self::with_backend(
            node_root,
            trust,
            contracts,
            limits,
            Arc::new(StdMaterialFilesystem),
            false,
        )
    }

    pub fn with_backend(
        node_root: impl AsRef<Path>,
        trust: MaterialTrustStore,
        contracts: MaterialContractRegistry,
        limits: MaterialResourceLimits,
        fs: Arc<dyn MaterialFilesystemBackend>,
        allow_fixture_health: bool,
    ) -> Self {
        Self {
            node_root: node_root.as_ref().to_path_buf(),
            trust,
            contracts,
            limits,
            fs,
            allow_fixture_health,
        }
    }

    #[cfg(test)]
    pub fn for_tests(
        node_root: impl AsRef<Path>,
        trust: MaterialTrustStore,
        contracts: MaterialContractRegistry,
        limits: MaterialResourceLimits,
    ) -> Self {
        Self::with_backend(
            node_root,
            trust,
            contracts,
            limits,
            Arc::new(StdMaterialFilesystem),
            true,
        )
    }

    fn store(&self, capability: &str) -> Result<MaterialStateStore, String> {
        MaterialStateStore::open_with_backend(
            material_capability_root(&self.node_root, capability),
            Arc::clone(&self.fs),
        )
    }

    pub fn lock_mutation(&self) -> Result<MaterialMutationGuard, String> {
        let path = material_root(&self.node_root).join(".mutation.lock");
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
        self.store(capability)?.load()
    }

    pub fn stage_verify(
        &self,
        package_dir: &Path,
        scope: &TrustedNodeScope,
    ) -> Result<MaterialStateV1, String> {
        let _lock = self.lock_mutation()?;
        let package = self.verify_package_dir(package_dir, scope)?;
        let store = self.store(&package.body.capability)?;
        let state = store.load()?;
        self.enforce_lineage(&state, &package)?;
        if let Some(until) = &package.body.valid_until {
            if material_now_ts().as_str() > until.as_str() {
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
        let mut creating_generation = !self.fs.path_exists(&gen_root);
        if !creating_generation && !self.generation_matches_package(&gen_root, &package)? {
            self.fs.remove_path_if_exists(&gen_root)?;
            creating_generation = true;
        }
        self.enforce_resource_limits(
            &package.body.capability,
            package_content_bytes(&package),
            creating_generation,
        )?;
        if creating_generation {
            self.materialize_generation(package_dir, &package, &gen_root)?;
        }
        let material_ref = MaterialRef {
            material_id: package.body.material_id.clone(),
            authority_epoch: package.body.authority_epoch,
            generation: package.body.generation,
            revision: package.body.revision,
            material_content_digest: package.body.material_content_digest.clone(),
            package_dir_name: dir_name,
            verified_at: Some(material_now_ts()),
            health_at: None,
        };
        let base = state.state_revision;
        let mut next = state;
        next.deployment_id = scope.deployment_id().to_string();
        next.capability = package.body.capability.clone();
        next.candidate = Some(material_ref);
        next.status = "stage_verified".into();
        next.last_error = None;
        store.commit_transition(base, next)
    }

    pub fn promote_candidate(
        &self,
        capability: &str,
        receipt: &HealthReceipt,
    ) -> Result<MaterialStateV1, String> {
        let _lock = self.lock_mutation()?;
        let store = self.store(capability)?;
        let state = store.load()?;
        let candidate = state
            .candidate
            .clone()
            .ok_or_else(|| "MATERIAL_NO_CANDIDATE".to_string())?;
        receipt.validate_for_candidate(&candidate, capability)?;
        let contract = self.contracts.get(capability)?;
        if contract.activation_policy == "noop" {
            return Err("MATERIAL_HEALTH_NOOP_FORBIDDEN".into());
        }
        if contract.activation_policy == ACTIVATION_VERIFY_ONLY && !self.allow_fixture_health {
            return Err("MATERIAL_HEALTH_VERIFY_ONLY_FORBIDDEN".into());
        }
        if contract.activation_policy != ACTIVATION_VERIFY_ONLY
            && contract.activation_policy != ACTIVATION_HEALTH_RECEIPT
        {
            return Err(format!(
                "MATERIAL_HEALTH_POLICY_UNSUPPORTED:{}",
                contract.activation_policy
            ));
        }
        if receipt.result != "pass" {
            let base = state.state_revision;
            let mut next = state;
            next.status = "health_failed".into();
            next.last_error = Some("MATERIAL_HEALTH_FAILED".into());
            store.commit_transition(base, next)?;
            return Err("MATERIAL_HEALTH_FAILED".into());
        }
        let gen_root = store.generations_dir().join(&candidate.package_dir_name);
        let package_bytes = self
            .fs
            .read_regular_file_bounded(&gen_root.join("package.json"), 1024 * 1024)?;
        let package: MaterialPackageV1 = serde_json::from_slice(&package_bytes)
            .map_err(|e| format!("MATERIAL_PACKAGE_INVALID: {e}"))?;
        if let Some(until) = &package.body.valid_until {
            if material_now_ts().as_str() > until.as_str() {
                return Err("MATERIAL_PACKAGE_EXPIRED".into());
            }
        }
        let base = state.state_revision;
        let mut next = state;
        let mut committed = candidate;
        committed.health_at = Some(receipt.checked_at.clone());
        if let Some(prev) = next.active.take() {
            next.lkg = Some(prev);
        } else {
            next.lkg = Some(committed.clone());
        }
        next.active = Some(committed);
        next.candidate = None;
        next.status = "active".into();
        next.last_error = None;
        store.commit_transition(base, next)
    }

    pub fn rollback_internal(&self, capability: &str) -> Result<MaterialStateV1, String> {
        let _lock = self.lock_mutation()?;
        let store = self.store(capability)?;
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
        scope: &TrustedNodeScope,
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
        scope: &TrustedNodeScope,
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
        let now = material_now_ts();
        if let Some(from) = &b.valid_from {
            if now.as_str() < from.as_str() {
                return Err("MATERIAL_PACKAGE_NOT_YET_VALID".into());
            }
        }
        if b.organization_id != scope.organization_id()
            || b.site_id != scope.site_id()
            || b.deployment_id != scope.deployment_id()
        {
            return Err("MATERIAL_SCOPE_MISMATCH".into());
        }
        if let Some(node_id) = &b.node_id {
            if scope.node_id() != Some(node_id.as_str()) {
                return Err("MATERIAL_NODE_MISMATCH".into());
            }
        }
        if !b.audience.iter().any(|a| {
            a == "actium-node-supervisor"
                || a == &format!("urn:actium:deployment:{}", scope.deployment_id())
        }) {
            return Err("MATERIAL_AUDIENCE_REJECTED".into());
        }
        for feature in &b.feature_requirements {
            if !scope.supervisor_features().iter().any(|f| f == feature) {
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
            self.fs.as_ref(),
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

    fn enforce_resource_limits(
        &self,
        capability: &str,
        incoming_bytes: u64,
        creating_generation: bool,
    ) -> Result<(), String> {
        let inbox = material_inbox_root(&self.node_root);
        let pending_count = self.fs.child_dir_count(&inbox)?;
        let (_pending_files, pending_bytes) = self.fs.directory_stats(&inbox)?;
        if pending_count >= self.limits.max_pending_package_count {
            return Err("MATERIAL_PENDING_COUNT_EXCEEDED".into());
        }
        if pending_bytes.saturating_add(incoming_bytes) > self.limits.max_pending_inbox_bytes {
            return Err("MATERIAL_PENDING_BYTES_EXCEEDED".into());
        }
        let gens = material_capability_root(&self.node_root, capability).join("generations");
        let gen_count = self.fs.child_dir_count(&gens)?;
        if creating_generation && gen_count >= self.limits.max_generations {
            return Err("MATERIAL_GENERATIONS_EXCEEDED".into());
        }
        let (_files, global_bytes) = self.fs.directory_stats(&material_root(&self.node_root))?;
        if global_bytes.saturating_add(incoming_bytes) > self.limits.max_global_material_bytes {
            return Err("MATERIAL_GLOBAL_BYTES_EXCEEDED".into());
        }
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

    fn generation_matches_package(
        &self,
        generation_root: &Path,
        package: &MaterialPackageV1,
    ) -> Result<bool, String> {
        let package_path = generation_root.join("package.json");
        let content_root = generation_root.join("content");
        if !self.fs.path_exists(&package_path) || !self.fs.is_dir(&content_root) {
            return Ok(false);
        }
        match compute_content_digest_from_disk(
            self.fs.as_ref(),
            &content_root,
            &package.body.content_manifest,
        ) {
            Ok(digest) => Ok(digest == package.body.material_content_digest),
            Err(_) => Ok(false),
        }
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
            "verifiedAt": material_now_ts(),
            "materialContentDigest": package.body.material_content_digest,
            "signedEnvelopeAlg": SIGNED_ENVELOPE_V1,
        });
        self.fs.write_bytes_exclusive(
            &generation_root.join("VERIFY.json"),
            &serde_json::to_vec_pretty(&verify).unwrap(),
        )?;
        Ok(())
    }
}
