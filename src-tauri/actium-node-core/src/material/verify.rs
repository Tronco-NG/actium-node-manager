use super::types::{
    MaterialContentEntry, MaterialPackageV1, MaterialTrustEntry, MATERIAL_CONTENT_DIGEST_ALG,
};
use crate::material_fs::{
    normalize_relative_path, MaterialFilesystemBackend, StdMaterialFilesystem,
};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn compute_manifest_digest(entries: &[MaterialContentEntry]) -> Result<String, String> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let canonical =
        serde_json::to_vec(&sorted).map_err(|e| format!("MATERIAL_MANIFEST_CANONICALIZE: {e}"))?;
    Ok(hex_sha256(&canonical))
}

pub fn compute_content_digest_from_disk(
    fs: &StdMaterialFilesystem,
    content_root: &Path,
    entries: &[MaterialContentEntry],
) -> Result<String, String> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut hasher = Sha256::new();
    hasher.update(MATERIAL_CONTENT_DIGEST_ALG.as_bytes());
    hasher.update(&[0u8]);
    for entry in sorted {
        let rel = normalize_relative_path(&entry.path)?;
        let bytes =
            fs.read_regular_file_bounded(&content_root.join(&rel), entry.size as usize + 1)?;
        if bytes.len() as u64 != entry.size {
            return Err(format!("MATERIAL_SIZE_MISMATCH:{rel}"));
        }
        let file_digest = hex_sha256(&bytes);
        if file_digest != entry.sha256 {
            return Err(format!("MATERIAL_FILE_DIGEST_MISMATCH:{rel}"));
        }
        hasher.update(rel.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(&entry.size.to_le_bytes());
        hasher.update(file_digest.as_bytes());
        hasher.update(&[0u8]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn signed_envelope_digest(package: &MaterialPackageV1) -> Result<String, String> {
    let bytes = serde_json::to_vec(&package.body)
        .map_err(|e| format!("MATERIAL_ENVELOPE_CANONICALIZE: {e}"))?;
    Ok(hex_sha256(&bytes))
}

pub fn verify_ed25519_signature(
    package: &MaterialPackageV1,
    trusted: &MaterialTrustEntry,
) -> Result<(), String> {
    if package.signature.alg != "Ed25519" {
        return Err("MATERIAL_SIGNATURE_ALG".into());
    }
    let digest = signed_envelope_digest(package)?;
    let spki = decode_b64(&trusted.public_key_spki_b64)?;
    let key_bytes: [u8; 32] = if spki.len() == 32 {
        spki.as_slice().try_into().unwrap()
    } else if spki.len() > 32 {
        spki[spki.len() - 32..]
            .try_into()
            .map_err(|_| "MATERIAL_TRUST_KEY_LENGTH".to_string())?
    } else {
        return Err("MATERIAL_TRUST_KEY_LENGTH".into());
    };
    let verifying =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| "MATERIAL_TRUST_KEY_INVALID".to_string())?;
    let sig_bytes = decode_b64(&package.signature.signature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| "MATERIAL_SIGNATURE_INVALID".to_string())?;
    verifying
        .verify(digest.as_bytes(), &signature)
        .map_err(|_| "MATERIAL_SIGNATURE_VERIFY_FAILED".to_string())?;
    Ok(())
}

pub fn key_id_for_public_key(raw32: &[u8]) -> String {
    format!("sha256:{}", hex_sha256(raw32))
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode_b64(value: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value.trim()))
        .map_err(|_| "MATERIAL_B64_INVALID".to_string())
}
