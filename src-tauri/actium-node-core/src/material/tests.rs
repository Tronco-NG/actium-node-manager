use super::*;
use crate::material_fs::{
    generation_dir_name, material_capability_root, material_trust_store_path,
    normalize_relative_path, MaterialFilesystemBackend, StdMaterialFilesystem,
};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

struct TempRoot(PathBuf);
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scope() -> TrustedNodeScope {
    TrustedNodeScope::for_tests(
        "org-1",
        "site-1",
        "dep-1",
        Some("node-1".into()),
        vec!["material_plane_v1".into()],
    )
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn test_spki(signing: &SigningKey) -> Vec<u8> {
    encode_ed25519_spki_der(&signing.verifying_key().to_bytes())
}

fn trust_entry(signing: &SigningKey, allow_gen: bool) -> MaterialTrustEntry {
    let spki = test_spki(signing);
    MaterialTrustEntry {
        key_id: key_id_for_spki_der(&spki),
        public_key_spki_der_b64: b64(&spki),
        signer_id: "test".into(),
        allowed_issuers: vec!["urn:actium:test-issuer".into()],
        allowed_capabilities: vec!["fixture".into()],
        allow_generation_advance: allow_gen,
        organization_id: Some("org-1".into()),
        site_id: Some("site-1".into()),
        deployment_id: Some("dep-1".into()),
        valid_from: "00000000000000000000".into(),
        valid_until: None,
        revoked_at: None,
        is_root: true,
    }
}

fn sign_and_write(
    signing: &SigningKey,
    content: &[u8],
    epoch: u64,
    gen: u64,
    rev: u64,
) -> (MaterialPackageV1, TempRoot) {
    sign_and_write_valid(
        signing,
        content,
        epoch,
        gen,
        rev,
        None,
        Some("99999999999999999999"),
    )
}

fn sign_and_write_valid(
    signing: &SigningKey,
    content: &[u8],
    epoch: u64,
    gen: u64,
    rev: u64,
    valid_from: Option<&str>,
    valid_until: Option<&str>,
) -> (MaterialPackageV1, TempRoot) {
    let root = TempRoot(std::env::temp_dir().join(format!("mat-{}", Uuid::new_v4())));
    fs::create_dir_all(root.0.join("content/policy")).unwrap();
    fs::write(root.0.join("content/policy/policy.json"), content).unwrap();
    let file_digest = hex_sha256(content);
    let entries = vec![MaterialContentEntry {
        path: "policy/policy.json".into(),
        size: content.len() as u64,
        sha256: file_digest,
    }];
    let manifest_digest = compute_manifest_digest(&entries).unwrap();
    let content_digest =
        compute_content_digest_from_disk(&StdMaterialFilesystem, &root.0.join("content"), &entries)
            .unwrap();
    let body = MaterialPackageBodyV1 {
        schema: 1,
        material_id: Uuid::new_v4().to_string(),
        capability: "fixture".into(),
        authority_epoch: epoch,
        generation: gen,
        revision: rev,
        organization_id: "org-1".into(),
        site_id: "site-1".into(),
        deployment_id: "dep-1".into(),
        node_id: Some("node-1".into()),
        lineage_id: None,
        predecessor_material_digest: None,
        runtime_release: None,
        payload_digest: None,
        material_content_digest: content_digest,
        material_manifest_digest: manifest_digest,
        content_digest_alg: MATERIAL_CONTENT_DIGEST_ALG.into(),
        manifest_digest_alg: MATERIAL_MANIFEST_DIGEST_ALG.into(),
        issuer: "urn:actium:test-issuer".into(),
        audience: vec!["actium-node-supervisor".into()],
        typ: "actium.material.v1".into(),
        issued_at: "00000000000000010000".into(),
        valid_from: valid_from.map(|v| v.to_string()),
        valid_until: valid_until.map(|v| v.to_string()),
        feature_requirements: vec!["material_plane_v1".into()],
        content_manifest: entries,
        extensions: Default::default(),
        anti_rollback: MaterialAntiRollback {
            min_authority_epoch: epoch,
            min_generation: gen,
            previous_material_digest: None,
        },
    };
    let envelope = canonical_signed_envelope_v1(&body).unwrap();
    let sig = signing.sign(&envelope);
    let spki = test_spki(signing);
    let package = MaterialPackageV1 {
        body,
        signature: MaterialSignature {
            alg: "Ed25519".into(),
            key_id: key_id_for_spki_der(&spki),
            signature: b64(&sig.to_bytes()),
            public_key: Some(b64(&signing.verifying_key().to_bytes())),
        },
    };
    fs::write(
        root.0.join("package.json"),
        serde_json::to_vec_pretty(&package).unwrap(),
    )
    .unwrap();
    (package, root)
}

fn mgr_with_limits(
    signing: &SigningKey,
    allow_gen: bool,
    limits: MaterialResourceLimits,
) -> (MaterialManager, TempRoot) {
    let node = TempRoot(std::env::temp_dir().join(format!("node-{}", Uuid::new_v4())));
    fs::create_dir_all(node.0.join("state/supervisor")).unwrap();
    let trust = MaterialTrustStore::from_entries(vec![trust_entry(signing, allow_gen)]).unwrap();
    let mut contracts = MaterialContractRegistry::new();
    contracts.insert(MaterialContract {
        capability: "fixture".into(),
        allowed_path_prefixes: vec!["policy".into()],
        max_total_bytes: 1_000_000,
        max_file_bytes: 64_000,
        max_file_count: 16,
        activation_policy: ACTIVATION_VERIFY_ONLY.into(),
        allowed_extensions: vec![],
    });
    (
        MaterialManager::for_tests(node.0.clone(), trust, contracts, limits),
        node,
    )
}

fn mgr(signing: &SigningKey, allow_gen: bool) -> (MaterialManager, TempRoot) {
    mgr_with_limits(signing, allow_gen, MaterialResourceLimits::default())
}

fn promote_ok(manager: &MaterialManager, capability: &str, digest: &str) -> MaterialStateV1 {
    let state = manager.get_state(capability).unwrap();
    let candidate = state.candidate.expect("candidate");
    assert_eq!(candidate.material_content_digest, digest);
    let receipt = HealthReceipt::verify_only_fixture(&candidate, capability);
    manager.promote_candidate(capability, &receipt).unwrap()
}

struct CountingFs {
    inner: StdMaterialFilesystem,
    writes: AtomicUsize,
}

impl CountingFs {
    fn new() -> Self {
        Self {
            inner: StdMaterialFilesystem,
            writes: AtomicUsize::new(0),
        }
    }
}

impl MaterialFilesystemBackend for CountingFs {
    fn ensure_dir(&self, path: &Path) -> Result<(), String> {
        self.inner.ensure_dir(path)
    }
    fn write_bytes_exclusive(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write_bytes_exclusive(path, bytes)
    }
    fn read_regular_file_bounded(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
        self.inner.read_regular_file_bounded(path, max_bytes)
    }
    fn inspect_regular_file(&self, path: &Path) -> Result<(u64, u64), String> {
        self.inner.inspect_regular_file(path)
    }
    fn reject_unsafe_tree(
        &self,
        root: &Path,
        max_files: usize,
        max_total: u64,
    ) -> Result<(), String> {
        self.inner.reject_unsafe_tree(root, max_files, max_total)
    }
    fn list_relative_files(&self, root: &Path) -> Result<Vec<String>, String> {
        self.inner.list_relative_files(root)
    }
    fn remove_path_if_exists(&self, path: &Path) -> Result<(), String> {
        self.inner.remove_path_if_exists(path)
    }
    fn rename_path(&self, from: &Path, to: &Path) -> Result<(), String> {
        self.inner.rename_path(from, to)
    }
    fn path_exists(&self, path: &Path) -> bool {
        self.inner.path_exists(path)
    }
    fn is_dir(&self, path: &Path) -> bool {
        self.inner.is_dir(path)
    }
    fn inspect_secure_file(
        &self,
        path: &Path,
    ) -> Result<crate::material_fs::SecureFileMeta, String> {
        self.inner.inspect_secure_file(path)
    }
    fn directory_stats(&self, root: &Path) -> Result<(usize, u64), String> {
        self.inner.directory_stats(root)
    }
    fn child_dir_count(&self, root: &Path) -> Result<usize, String> {
        self.inner.child_dir_count(root)
    }
}

#[test]
fn agent_tamper_does_not_alter_active() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, _d1) = sign_and_write(&signing, b"{\"v\":1}", 1, 1, 1);
    manager.stage_verify(&_d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    fs::create_dir_all(node.0.join("state/agent")).unwrap();
    fs::write(node.0.join("state/agent/policy.json"), b"EVIL").unwrap();
    fs::write(
        node.0.join("state/supervisor/material/fixture/active.json"),
        b"{\"materialContentDigest\":\"tampered\"}",
    )
    .ok();
    let after = manager.get_state("fixture").unwrap();
    assert_eq!(
        after.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert!(node
        .0
        .join("state/supervisor/material/fixture/journal")
        .is_dir());
}

#[test]
fn epoch_regression_rejected() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 2, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 9, 9);
    let err = manager.stage_verify(&d2.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_AUTHORITY_EPOCH_REGRESSION"), "{err}");
}

#[test]
fn generation_advance_requires_trust_flag() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, false);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 2, 1);
    let err = manager.stage_verify(&d2.0, &scope()).unwrap_err();
    assert!(
        err.contains("MATERIAL_GENERATION_ADVANCE_UNAUTHORIZED"),
        "{err}"
    );
}

#[test]
fn health_fail_keeps_active_and_lkg() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (p2, d2) = sign_and_write(&signing, b"b", 1, 1, 2);
    manager.stage_verify(&d2.0, &scope()).unwrap();
    let mut receipt = HealthReceipt::verify_only_fixture(
        &manager.get_state("fixture").unwrap().candidate.unwrap(),
        "fixture",
    );
    receipt.result = "fail".into();
    let err = manager.promote_candidate("fixture", &receipt).unwrap_err();
    assert!(err.contains("MATERIAL_HEALTH_FAILED"), "{err}");
    let after = manager.get_state("fixture").unwrap();
    assert_eq!(
        after.active.as_ref().unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert_eq!(
        after.lkg.as_ref().unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert_eq!(
        after.candidate.as_ref().unwrap().material_content_digest,
        p2.body.material_content_digest
    );
}

#[test]
fn rollback_internal_keeps_lkg() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 1, 2);
    manager.stage_verify(&d2.0, &scope()).unwrap();
    let recovered = manager.rollback_internal("fixture").unwrap();
    assert_eq!(
        recovered.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
}

#[test]
fn path_traversal_rejected() {
    assert!(normalize_relative_path("../x").is_err());
}

#[test]
fn spki_parser_rejects_last_32_bytes_trick() {
    let signing = SigningKey::generate(&mut OsRng);
    let raw = signing.verifying_key().to_bytes();
    let mut garbage = vec![0xff; 20];
    garbage.extend_from_slice(&raw);
    assert!(parse_ed25519_spki_der(&garbage).is_err());
    let spki = encode_ed25519_spki_der(&raw);
    assert_eq!(parse_ed25519_spki_der(&spki).unwrap(), raw);
    let mut trailing = spki.clone();
    trailing.push(0x00);
    assert!(parse_ed25519_spki_der(&trailing).is_err());
}

#[test]
fn key_id_is_sha256_of_spki_der() {
    let signing = SigningKey::generate(&mut OsRng);
    let spki = test_spki(&signing);
    assert_eq!(
        key_id_for_spki_der(&spki),
        format!("sha256:{}", hex_sha256(&spki))
    );
    assert_ne!(
        key_id_for_spki_der(&spki),
        format!("sha256:{}", hex_sha256(&signing.verifying_key().to_bytes()))
    );
}

#[test]
fn signature_over_hex_digest_is_rejected() {
    let signing = SigningKey::generate(&mut OsRng);
    let (mut package, dir) = sign_and_write(&signing, b"a", 1, 1, 1);
    let digest = signed_envelope_digest(&package).unwrap();
    let bad = signing.sign(digest.as_bytes());
    package.signature.signature = b64(&bad.to_bytes());
    fs::write(
        dir.0.join("package.json"),
        serde_json::to_vec_pretty(&package).unwrap(),
    )
    .unwrap();
    let (manager, _node) = mgr(&signing, true);
    let err = manager.stage_verify(&dir.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_SIGNATURE_VERIFY_FAILED"), "{err}");
}

#[test]
fn package_public_key_is_not_trust_anchor() {
    let trusted = SigningKey::generate(&mut OsRng);
    let untrusted = SigningKey::generate(&mut OsRng);
    let (mut package, dir) = sign_and_write(&trusted, b"a", 1, 1, 1);
    package.signature.public_key = Some(b64(&untrusted.verifying_key().to_bytes()));
    fs::write(
        dir.0.join("package.json"),
        serde_json::to_vec_pretty(&package).unwrap(),
    )
    .unwrap();
    let (manager, _node) = mgr(&trusted, true);
    manager.stage_verify(&dir.0, &scope()).unwrap();
}

#[test]
fn trusted_node_scope_requires_installation_evidence() {
    let err = TrustedNodeScope::from_supervisor_evidence(SupervisorScopeEvidence {
        organization_id: "org-1".into(),
        site_id: "site-1".into(),
        deployment_id: "dep-1".into(),
        node_id: None,
        installation_id: "".into(),
        active_payload_digest: None,
        active_runtime_release: None,
        supervisor_features: vec![],
    })
    .unwrap_err();
    assert!(err.contains("MATERIAL_SCOPE_INSTALLATION_MISSING"), "{err}");
}

#[test]
fn valid_from_future_rejected() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (_p, dir) = sign_and_write_valid(
        &signing,
        b"a",
        1,
        1,
        1,
        Some("99999999999999999999"),
        Some("99999999999999999999"),
    );
    let err = manager.stage_verify(&dir.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_PACKAGE_NOT_YET_VALID"), "{err}");
}

#[test]
fn valid_until_blocks_new_promotion_not_active() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (_p2, d2) =
        sign_and_write_valid(&signing, b"b", 1, 1, 2, None, Some("00000000000000000001"));
    let err = manager.stage_verify(&d2.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_PACKAGE_EXPIRED"), "{err}");
    let after = manager.get_state("fixture").unwrap();
    assert_eq!(
        after.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
}

#[test]
fn resource_limits_generations_enforced() {
    let signing = SigningKey::generate(&mut OsRng);
    let limits = MaterialResourceLimits {
        max_pending_inbox_bytes: 64 * 1024 * 1024,
        max_pending_package_count: 32,
        max_generations: 1,
        max_global_material_bytes: 512 * 1024 * 1024,
    };
    let (manager, _node) = mgr_with_limits(&signing, true, limits);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 1, 2);
    let err = manager.stage_verify(&d2.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_GENERATIONS_EXCEEDED"), "{err}");
}

#[test]
fn resource_limits_inbox_count_enforced() {
    let signing = SigningKey::generate(&mut OsRng);
    let limits = MaterialResourceLimits {
        max_pending_inbox_bytes: 64 * 1024 * 1024,
        max_pending_package_count: 1,
        max_generations: 64,
        max_global_material_bytes: 512 * 1024 * 1024,
    };
    let (manager, node) = mgr_with_limits(&signing, true, limits);
    let inbox = node.0.join("state/supervisor/material/_inbox/pkg-a");
    fs::create_dir_all(&inbox).unwrap();
    fs::write(inbox.join("x"), b"pending").unwrap();
    let (_p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    let err = manager.stage_verify(&d1.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_PENDING_COUNT_EXCEEDED"), "{err}");
}

#[test]
fn resource_limits_inbox_bytes_enforced() {
    let signing = SigningKey::generate(&mut OsRng);
    let limits = MaterialResourceLimits {
        max_pending_inbox_bytes: 8,
        max_pending_package_count: 32,
        max_generations: 64,
        max_global_material_bytes: 512 * 1024 * 1024,
    };
    let (manager, node) = mgr_with_limits(&signing, true, limits);
    let inbox = node.0.join("state/supervisor/material/_inbox");
    fs::create_dir_all(&inbox).unwrap();
    fs::write(inbox.join("blob"), b"0123456789").unwrap();
    let (_p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    let err = manager.stage_verify(&d1.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_PENDING_BYTES_EXCEEDED"), "{err}");
}

#[test]
fn resource_limits_global_bytes_enforced() {
    let signing = SigningKey::generate(&mut OsRng);
    let limits = MaterialResourceLimits {
        max_pending_inbox_bytes: 64 * 1024 * 1024,
        max_pending_package_count: 32,
        max_generations: 64,
        max_global_material_bytes: 4,
    };
    let (manager, _node) = mgr_with_limits(&signing, true, limits);
    let (_p1, d1) = sign_and_write(&signing, b"abcdef", 1, 1, 1);
    let err = manager.stage_verify(&d1.0, &scope()).unwrap_err();
    assert!(err.contains("MATERIAL_GLOBAL_BYTES_EXCEEDED"), "{err}");
}

#[test]
fn health_receipt_required_fields() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    let mut receipt = HealthReceipt::verify_only_fixture(
        &manager.get_state("fixture").unwrap().candidate.unwrap(),
        "fixture",
    );
    receipt.checker_identity.clear();
    let err = manager.promote_candidate("fixture", &receipt).unwrap_err();
    assert!(err.contains("MATERIAL_HEALTH_CHECKER_MISSING"), "{err}");
    let still = manager.get_state("fixture").unwrap();
    assert_eq!(
        still.candidate.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert!(still.active.is_none());
}

#[test]
fn filesystem_backend_is_used_for_writes() {
    let signing = SigningKey::generate(&mut OsRng);
    let node = TempRoot(std::env::temp_dir().join(format!("node-{}", Uuid::new_v4())));
    fs::create_dir_all(node.0.join("state/supervisor")).unwrap();
    let trust = MaterialTrustStore::from_entries(vec![trust_entry(&signing, true)]).unwrap();
    let mut contracts = MaterialContractRegistry::new();
    contracts.insert(MaterialContract {
        capability: "fixture".into(),
        allowed_path_prefixes: vec!["policy".into()],
        max_total_bytes: 1_000_000,
        max_file_bytes: 64_000,
        max_file_count: 16,
        activation_policy: ACTIVATION_VERIFY_ONLY.into(),
        allowed_extensions: vec![],
    });
    let fs = Arc::new(CountingFs::new());
    let manager = MaterialManager::with_backend(
        node.0.clone(),
        trust,
        contracts,
        MaterialResourceLimits::default(),
        fs.clone(),
        true,
    );
    let (_p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    assert!(fs.writes.load(Ordering::SeqCst) > 0);
}

#[test]
fn trust_store_load_rejects_agent_path_and_duplicates() {
    let signing = SigningKey::generate(&mut OsRng);
    let node = TempRoot(std::env::temp_dir().join(format!("node-{}", Uuid::new_v4())));
    let agent_path = node.0.join("state/agent/trust.json");
    fs::create_dir_all(agent_path.parent().unwrap()).unwrap();
    fs::write(&agent_path, b"{}").unwrap();
    let err = MaterialTrustStore::load(&agent_path, &StdMaterialFilesystem).unwrap_err();
    assert!(err.contains("MATERIAL_TRUST_PATH_AGENT_FORBIDDEN"), "{err}");

    let entry = trust_entry(&signing, true);
    let dup = serde_json::json!({
        "schema": 1,
        "typ": MATERIAL_TRUST_STORE_TYP,
        "entries": [entry.clone(), entry.clone()],
    });
    let path = material_trust_store_path(&node.0);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_vec_pretty(&dup).unwrap()).unwrap();
    let err = MaterialTrustStore::load(&path, &StdMaterialFilesystem).unwrap_err();
    assert!(err.contains("MATERIAL_TRUST_DUPLICATE_KEY_ID"), "{err}");
}

#[test]
fn trust_store_load_accepts_supervisor_path() {
    let signing = SigningKey::generate(&mut OsRng);
    let node = TempRoot(std::env::temp_dir().join(format!("node-{}", Uuid::new_v4())));
    let entry = trust_entry(&signing, true);
    let file = serde_json::json!({
        "schema": 1,
        "typ": MATERIAL_TRUST_STORE_TYP,
        "entries": [entry],
    });
    let path = material_trust_store_path(&node.0);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    let loaded = MaterialTrustStore::load(&path, &StdMaterialFilesystem).unwrap();
    loaded
        .resolve_and_authorize(
            &trust_entry(&signing, true).key_id,
            "urn:actium:test-issuer",
            "fixture",
            "org-1",
            "site-1",
            "dep-1",
            "00000000000000010000",
            false,
        )
        .unwrap();
}

#[cfg(unix)]
#[test]
fn trust_store_world_writable_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let signing = SigningKey::generate(&mut OsRng);
    let node = TempRoot(std::env::temp_dir().join(format!("node-{}", Uuid::new_v4())));
    let entry = trust_entry(&signing, true);
    let file = serde_json::json!({
        "schema": 1,
        "typ": MATERIAL_TRUST_STORE_TYP,
        "entries": [entry],
    });
    let path = material_trust_store_path(&node.0);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    let err = MaterialTrustStore::load(&path, &StdMaterialFilesystem).unwrap_err();
    assert!(err.contains("MATERIAL_TRUST_PERMISSIONS"), "{err}");
}

#[test]
fn m1_m2_success_sets_lkg() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"m1", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (p2, d2) = sign_and_write(&signing, b"m2", 1, 1, 2);
    manager.stage_verify(&d2.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p2.body.material_content_digest);
    let after = manager.get_state("fixture").unwrap();
    assert_eq!(
        after.active.unwrap().material_content_digest,
        p2.body.material_content_digest
    );
    assert_eq!(
        after.lkg.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
}

fn fixture_root(node: &Path) -> PathBuf {
    material_capability_root(node, "fixture")
}

#[test]
fn corrupt_mirror_journal_wins() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    fs::write(fixture_root(&node.0).join("active.json"), b"NOT-JSON").unwrap();
    let after = manager.get_state("fixture").unwrap();
    assert_eq!(
        after.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
}

#[test]
fn mirror_ahead_of_journal_fail_closed() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let mut evil = manager.get_state("fixture").unwrap();
    evil.state_revision = 999;
    fs::write(
        fixture_root(&node.0).join("material-state.json"),
        serde_json::to_vec_pretty(&evil).unwrap(),
    )
    .unwrap();
    let err = manager.get_state("fixture").unwrap_err();
    assert!(err.contains("MATERIAL_STATE_MIRROR_AHEAD"), "{err}");
}

#[test]
fn missing_journal_with_mirrors_fail_closed() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let journal = fixture_root(&node.0).join("journal");
    for entry in fs::read_dir(&journal).unwrap() {
        let path = entry.unwrap().path();
        fs::remove_file(path).unwrap();
    }
    let err = manager.get_state("fixture").unwrap_err();
    assert!(err.contains("MATERIAL_STATE_JOURNAL_MISSING"), "{err}");
}

#[test]
fn journal_chain_break_fail_closed() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let journal = fixture_root(&node.0).join("journal");
    let fake = serde_json::json!({
        "schema": 1,
        "stateRevision": 99,
        "previousRecordSha256": "deadbeef",
        "state": manager.get_state("fixture").ok(),
        "recordSha256": "cafebabe"
    });
    fs::write(
        journal.join("00000000000000000099-cafebabe.json"),
        fake.to_string(),
    )
    .unwrap();
    let err = manager.get_state("fixture").unwrap_err();
    assert!(err.contains("MATERIAL_STATE_CORRUPT"), "{err}");
}

#[test]
fn journal_record_hash_mismatch_fail_closed() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let journal = fixture_root(&node.0).join("journal");
    let path = fs::read_dir(&journal)
        .unwrap()
        .map(|e| e.unwrap().path())
        .max()
        .unwrap();
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["recordSha256"] = serde_json::Value::String("00".repeat(32));
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let err = manager.get_state("fixture").unwrap_err();
    assert!(err.contains("MATERIAL_STATE_CORRUPT"), "{err}");
}

#[test]
fn journal_duplicate_revision_fail_closed() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let journal = fixture_root(&node.0).join("journal");
    let original = fs::read_dir(&journal)
        .unwrap()
        .map(|e| e.unwrap().path())
        .min()
        .unwrap();
    let bytes = fs::read(&original).unwrap();
    fs::write(journal.join("00000000000000000001-duplicate.json"), bytes).unwrap();
    let err = manager.get_state("fixture").unwrap_err();
    assert!(err.contains("MATERIAL_STATE_CORRUPT"), "{err}");
}

#[test]
fn crash_a_incomplete_staging_rematerializes() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"complete", 1, 1, 1);
    let dir_name = generation_dir_name(
        p1.body.authority_epoch,
        p1.body.generation,
        p1.body.revision,
        &p1.body.material_content_digest,
    );
    let gen = fixture_root(&node.0).join("generations").join(&dir_name);
    fs::create_dir_all(gen.join("content/policy")).unwrap();
    fs::write(gen.join("content/policy/policy.json"), b"PARTIAL").unwrap();
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let restored = fs::read(gen.join("content/policy/policy.json")).unwrap();
    assert_eq!(restored, b"complete");
}

#[test]
fn crash_b_post_verify_retries_commit() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    let journal = fixture_root(&node.0).join("journal");
    for entry in fs::read_dir(&journal).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    for name in [
        "active.json",
        "lkg.json",
        "candidate.json",
        "material-state.json",
    ] {
        let _ = fs::remove_file(fixture_root(&node.0).join(name));
    }
    manager.stage_verify(&d1.0, &scope()).unwrap();
    let state = manager.get_state("fixture").unwrap();
    assert_eq!(
        state.candidate.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
}

#[test]
fn crash_c_missing_mirrors_rebuild_from_journal() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    for name in [
        "active.json",
        "lkg.json",
        "candidate.json",
        "material-state.json",
    ] {
        fs::remove_file(fixture_root(&node.0).join(name)).unwrap();
    }
    let after = manager.get_state("fixture").unwrap();
    assert_eq!(
        after.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert!(fixture_root(&node.0).join("active.json").is_file());
}

#[test]
fn crash_d_post_health_pre_commit_keeps_previous_active() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (p2, d2) = sign_and_write(&signing, b"b", 1, 1, 2);
    manager.stage_verify(&d2.0, &scope()).unwrap();
    let mid = manager.get_state("fixture").unwrap();
    assert_eq!(
        mid.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert_eq!(
        mid.candidate.unwrap().material_content_digest,
        p2.body.material_content_digest
    );
}

#[test]
fn crash_e_restart_during_recovery_is_deterministic() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, _node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 1, 2);
    manager.stage_verify(&d2.0, &scope()).unwrap();
    let first = manager.rollback_internal("fixture").unwrap();
    let second = manager.rollback_internal("fixture").unwrap();
    assert_eq!(
        first.active.as_ref().unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert_eq!(
        second.active.as_ref().unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    assert!(second.candidate.is_none());
}

#[test]
fn a1_master_security_agent_cannot_replace_active() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"M1", 1, 1, 1);
    manager.stage_verify(&d1.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p1.body.material_content_digest);

    let agent = node.0.join("state/agent");
    fs::create_dir_all(agent.join("policy")).unwrap();
    fs::write(agent.join("policy/policy.json"), b"EVIL-POLICY").unwrap();
    fs::write(agent.join("artifact.bin"), b"EVIL-ARTIFACT").unwrap();
    fs::write(agent.join("authority.pub"), b"EVIL-KEY").unwrap();
    fs::write(agent.join("metadata.json"), b"{\"generation\":99}").unwrap();
    let cap = fixture_root(&node.0);
    fs::write(cap.join("active.json"), b"{\"materialContentDigest\":\"agent\"}").unwrap();
    fs::write(
        cap.join("material-state.json"),
        b"{\"schema\":1,\"stateRevision\":1,\"status\":\"active\"}",
    )
    .unwrap();

    let after_tamper = manager.get_state("fixture").unwrap();
    assert_eq!(
        after_tamper.active.unwrap().material_content_digest,
        p1.body.material_content_digest,
        "ACTIVE must remain M1 without a Supervisor operation"
    );

    let (p2, d2) = sign_and_write(&signing, b"M2", 1, 1, 2);
    manager.stage_verify(&d2.0, &scope()).unwrap();
    promote_ok(&manager, "fixture", &p2.body.material_content_digest);
    let after_m2 = manager.get_state("fixture").unwrap();
    assert_eq!(
        after_m2.active.unwrap().material_content_digest,
        p2.body.material_content_digest
    );
    assert_eq!(
        after_m2.lkg.unwrap().material_content_digest,
        p1.body.material_content_digest
    );

    let signing2 = SigningKey::generate(&mut OsRng);
    let (manager2, _node2) = mgr(&signing2, true);
    let (q1, e1) = sign_and_write(&signing2, b"M1b", 1, 1, 1);
    manager2.stage_verify(&e1.0, &scope()).unwrap();
    promote_ok(&manager2, "fixture", &q1.body.material_content_digest);
    let (q2, e2) = sign_and_write(&signing2, b"M2fail", 1, 1, 2);
    manager2.stage_verify(&e2.0, &scope()).unwrap();
    let mut fail = HealthReceipt::verify_only_fixture(
        &manager2.get_state("fixture").unwrap().candidate.unwrap(),
        "fixture",
    );
    fail.result = "fail".into();
    assert!(manager2.promote_candidate("fixture", &fail).is_err());
    let failed = manager2.get_state("fixture").unwrap();
    assert_eq!(
        failed.active.as_ref().unwrap().material_content_digest,
        q1.body.material_content_digest
    );
    assert_eq!(
        failed.lkg.as_ref().unwrap().material_content_digest,
        q1.body.material_content_digest
    );
    assert_eq!(
        failed.candidate.as_ref().unwrap().material_content_digest,
        q2.body.material_content_digest
    );
}
