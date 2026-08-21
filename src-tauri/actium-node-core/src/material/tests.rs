use super::*;
use crate::material_fs::normalize_relative_path;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::fs;
use uuid::Uuid;

fn scope() -> NodeScope {
    NodeScope {
        organization_id: "org-1".into(),
        site_id: "site-1".into(),
        deployment_id: "dep-1".into(),
        node_id: Some("node-1".into()),
        active_payload_digest: None,
        active_runtime_release: None,
        supervisor_features: vec!["material_plane_v1".into()],
    }
}

fn sign_and_write(
    signing: &SigningKey,
    content: &[u8],
    epoch: u64,
    gen: u64,
    rev: u64,
) -> (MaterialPackageV1, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("mat-{}", Uuid::new_v4()));
    fs::create_dir_all(root.join("content/policy")).unwrap();
    fs::write(root.join("content/policy/policy.json"), content).unwrap();
    let file_digest = hex_sha256(content);
    let entries = vec![MaterialContentEntry {
        path: "policy/policy.json".into(),
        size: content.len() as u64,
        sha256: file_digest,
    }];
    let manifest_digest = compute_manifest_digest(&entries).unwrap();
    let content_digest = compute_content_digest_from_disk(
        &crate::material_fs::StdMaterialFilesystem,
        &root.join("content"),
        &entries,
    )
    .unwrap();
    let key_bytes = signing.verifying_key().to_bytes();
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
        valid_from: None,
        valid_until: Some("99999999999999999999".into()),
        feature_requirements: vec!["material_plane_v1".into()],
        content_manifest: entries,
        extensions: Default::default(),
        anti_rollback: MaterialAntiRollback {
            min_authority_epoch: epoch,
            min_generation: gen,
            previous_material_digest: None,
        },
    };
    let digest = hex_sha256(&serde_json::to_vec(&body).unwrap());
    let sig = signing.sign(digest.as_bytes());
    let package = MaterialPackageV1 {
        body,
        signature: MaterialSignature {
            alg: "Ed25519".into(),
            key_id: key_id_for_public_key(&key_bytes),
            signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            public_key: Some(base64::engine::general_purpose::STANDARD.encode(key_bytes)),
        },
    };
    fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&package).unwrap(),
    )
    .unwrap();
    (package, root)
}

fn mgr(signing: &SigningKey, allow_gen: bool) -> (MaterialManager, std::path::PathBuf) {
    let node = std::env::temp_dir().join(format!("node-{}", Uuid::new_v4()));
    fs::create_dir_all(node.join("state")).unwrap();
    let key_bytes = signing.verifying_key().to_bytes();
    let trust = MaterialTrustStore::from_entries(vec![MaterialTrustEntry {
        key_id: key_id_for_public_key(&key_bytes),
        public_key_spki_b64: base64::engine::general_purpose::STANDARD.encode(key_bytes),
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
    }]);
    let mut contracts = MaterialContractRegistry::new();
    contracts.insert(MaterialContract {
        capability: "fixture".into(),
        allowed_path_prefixes: vec!["policy".into()],
        max_total_bytes: 1_000_000,
        max_file_bytes: 64_000,
        max_file_count: 16,
        activation_policy: "verify_only".into(),
        allowed_extensions: vec![],
    });
    (
        MaterialManager::new(node.clone(), trust, contracts, MaterialResourceLimits::default()),
        node,
    )
}

#[test]
fn agent_tamper_does_not_alter_active() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"{\"v\":1}", 1, 1, 1);
    manager.stage_verify_to_candidate(&d1, &scope(), true).unwrap();
    manager
        .complete_health_and_commit("fixture", &p1.body.material_content_digest)
        .unwrap();
    fs::create_dir_all(node.join("state/agent")).unwrap();
    fs::write(node.join("state/agent/policy.json"), b"EVIL").unwrap();
    let after = manager.get_state("fixture").unwrap();
    assert_eq!(
        after.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    let _ = fs::remove_dir_all(node);
    let _ = fs::remove_dir_all(d1);
}

#[test]
fn epoch_regression_rejected() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 2, 1, 1);
    manager.stage_verify_to_candidate(&d1, &scope(), true).unwrap();
    manager
        .complete_health_and_commit("fixture", &p1.body.material_content_digest)
        .unwrap();
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 9, 9);
    let err = manager.stage_verify_to_candidate(&d2, &scope(), true).unwrap_err();
    assert!(err.contains("MATERIAL_AUTHORITY_EPOCH_REGRESSION"), "{err}");
    let _ = fs::remove_dir_all(node);
    let _ = fs::remove_dir_all(d1);
    let _ = fs::remove_dir_all(d2);
}

#[test]
fn generation_advance_requires_trust_flag() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, false);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify_to_candidate(&d1, &scope(), true).unwrap();
    manager
        .complete_health_and_commit("fixture", &p1.body.material_content_digest)
        .unwrap();
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 2, 1);
    let err = manager.stage_verify_to_candidate(&d2, &scope(), true).unwrap_err();
    assert!(err.contains("MATERIAL_GENERATION_ADVANCE_UNAUTHORIZED"), "{err}");
    let _ = fs::remove_dir_all(node);
    let _ = fs::remove_dir_all(d1);
    let _ = fs::remove_dir_all(d2);
}

#[test]
fn health_fail_recovery_keeps_lkg() {
    let signing = SigningKey::generate(&mut OsRng);
    let (manager, node) = mgr(&signing, true);
    let (p1, d1) = sign_and_write(&signing, b"a", 1, 1, 1);
    manager.stage_verify_to_candidate(&d1, &scope(), true).unwrap();
    manager
        .complete_health_and_commit("fixture", &p1.body.material_content_digest)
        .unwrap();
    let (_p2, d2) = sign_and_write(&signing, b"b", 1, 1, 2);
    manager.stage_verify_to_candidate(&d2, &scope(), true).unwrap();
    let recovered = manager.recover_to_lkg_internal("fixture").unwrap();
    assert_eq!(
        recovered.active.unwrap().material_content_digest,
        p1.body.material_content_digest
    );
    let _ = fs::remove_dir_all(node);
    let _ = fs::remove_dir_all(d1);
    let _ = fs::remove_dir_all(d2);
}

#[test]
fn path_traversal_rejected() {
    assert!(normalize_relative_path("../x").is_err());
}
