use super::trust::MaterialTrustEntry;
use super::types::{
    MaterialContentEntry, MaterialPackageBodyV1, MaterialPackageV1, MATERIAL_CONTENT_DIGEST_ALG,
    SIGNED_ENVELOPE_V1,
};
use crate::attestation::canonical_json;
use crate::material_fs::{normalize_relative_path, MaterialFilesystemBackend};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

/// RFC 8410 id-Ed25519 OBJECT IDENTIFIER { 1 3 101 112 } DER contents (without tag/len).
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];

pub fn compute_manifest_digest(entries: &[MaterialContentEntry]) -> Result<String, String> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let canonical =
        serde_json::to_vec(&sorted).map_err(|e| format!("MATERIAL_MANIFEST_CANONICALIZE: {e}"))?;
    Ok(hex_sha256(&canonical))
}

pub fn compute_content_digest_from_disk(
    fs: &dyn MaterialFilesystemBackend,
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

/// Canonical signed-envelope-v1 bytes.
///
/// Protocol: Ed25519 signs these bytes directly.
/// `signed_envelope_digest` is a SHA-256 fingerprint of the same bytes and MUST
/// NOT be the signed payload.
pub fn canonical_signed_envelope_v1(body: &MaterialPackageBodyV1) -> Result<Vec<u8>, String> {
    let value =
        serde_json::to_value(body).map_err(|e| format!("MATERIAL_ENVELOPE_SERIALIZE: {e}"))?;
    let json = canonical_json(&value)?;
    let mut out = Vec::with_capacity(SIGNED_ENVELOPE_V1.len() + 1 + json.len());
    out.extend_from_slice(SIGNED_ENVELOPE_V1.as_bytes());
    out.push(0);
    out.extend_from_slice(json.as_bytes());
    Ok(out)
}

pub fn signed_envelope_digest(package: &MaterialPackageV1) -> Result<String, String> {
    Ok(hex_sha256(&canonical_signed_envelope_v1(&package.body)?))
}

pub fn verify_ed25519_signature(
    package: &MaterialPackageV1,
    trusted: &MaterialTrustEntry,
) -> Result<(), String> {
    if package.signature.alg != "Ed25519" {
        return Err("MATERIAL_SIGNATURE_ALG".into());
    }
    // package.signature.public_key is never consulted. Trust anchor is the store.
    let envelope = canonical_signed_envelope_v1(&package.body)?;
    let spki = decode_b64(&trusted.public_key_spki_der_b64)?;
    let key_bytes = parse_ed25519_spki_der(&spki)?;
    let expected_key_id = key_id_for_spki_der(&spki);
    if package.signature.key_id != expected_key_id || trusted.key_id != expected_key_id {
        return Err("MATERIAL_TRUST_KEY_ID_MISMATCH".into());
    }
    let verifying = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| "MATERIAL_TRUST_KEY_INVALID".to_string())?;
    let sig_bytes = decode_b64(&package.signature.signature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| "MATERIAL_SIGNATURE_INVALID".to_string())?;
    verifying
        .verify(&envelope, &signature)
        .map_err(|_| "MATERIAL_SIGNATURE_VERIFY_FAILED".to_string())?;
    Ok(())
}

/// Parse RFC 8410 Ed25519 SubjectPublicKeyInfo DER and return the raw 32-byte key.
/// This is a real DER TLV parse — not "take the last 32 bytes".
pub fn parse_ed25519_spki_der(der: &[u8]) -> Result<[u8; 32], String> {
    let mut i = 0usize;
    let outer = take_tlv(der, &mut i, 0x30)?;
    if i != der.len() {
        return Err("MATERIAL_SPKI_TRAILING".into());
    }
    let mut j = 0usize;
    let alg = take_tlv(outer, &mut j, 0x30)?;
    let mut k = 0usize;
    let oid = take_tlv(alg, &mut k, 0x06)?;
    if k != alg.len() {
        return Err("MATERIAL_SPKI_ALG_PARAMS".into());
    }
    if oid != ED25519_OID {
        return Err("MATERIAL_SPKI_OID".into());
    }
    let bit = take_tlv(outer, &mut j, 0x03)?;
    if j != outer.len() {
        return Err("MATERIAL_SPKI_TRAILING".into());
    }
    if bit.is_empty() || bit[0] != 0x00 {
        return Err("MATERIAL_SPKI_BITSTRING".into());
    }
    if bit.len() != 33 {
        return Err("MATERIAL_SPKI_KEY_LENGTH".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bit[1..]);
    VerifyingKey::from_bytes(&key).map_err(|_| "MATERIAL_SPKI_KEY_INVALID".to_string())?;
    Ok(key)
}

pub fn encode_ed25519_spki_der(raw32: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(raw32);
    der
}

pub fn key_id_for_spki_der(spki_der: &[u8]) -> String {
    format!("sha256:{}", hex_sha256(spki_der))
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn decode_b64(value: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value.trim()))
        .map_err(|_| "MATERIAL_B64_INVALID".to_string())
}

fn take_tlv<'a>(data: &'a [u8], i: &mut usize, expected_tag: u8) -> Result<&'a [u8], String> {
    if *i >= data.len() || data[*i] != expected_tag {
        return Err("MATERIAL_SPKI_DER".into());
    }
    *i += 1;
    if *i >= data.len() {
        return Err("MATERIAL_SPKI_DER".into());
    }
    let len_byte = data[*i];
    if len_byte > 0x7f {
        return Err("MATERIAL_SPKI_DER_LONG_FORM".into());
    }
    let len = len_byte as usize;
    *i += 1;
    if *i + len > data.len() {
        return Err("MATERIAL_SPKI_DER".into());
    }
    let content = &data[*i..*i + len];
    *i += len;
    Ok(content)
}
