use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const MATERIAL_ATTESTATION_SCHEMA: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialAttestationEnvelope {
    pub schema: u8,
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub statement: MaterialAttestationStatement,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MaterialAttestationStatement {
    pub host_id: String,
    pub deployment_id: String,
    pub generation: u64,
    pub runtime_release: Option<String>,
    pub payload_digest: Option<String>,
    pub material_digest: String,
    pub observed_at: String,
    pub runtime_units: Vec<AttestedRuntimeUnit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestedRuntimeUnit {
    pub runtime_unit_id: String,
    pub capability: String,
    pub dependency_scope: String,
    pub compose_project: String,
    pub effective_config_digest: String,
    pub health: String,
    pub lifecycle_state: String,
    pub started_at: Option<String>,
    pub containers: Vec<AttestedContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttestedContainer {
    pub workload_code: Option<String>,
    pub compose_service: String,
    pub container_id: String,
    pub image_reference: String,
    pub image_id: String,
    pub repo_digest: Option<String>,
    pub effective_config_digest: String,
    pub health: String,
    pub lifecycle_state: String,
    pub started_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttestationSigner {
    key_path: PathBuf,
    signing_key: SigningKey,
}

impl AttestationSigner {
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, String> {
        let key_path = path.into();
        let signing_key = if key_path.is_file() {
            let raw = fs::read_to_string(&key_path)
                .map_err(|error| format!("No se pudo leer la identidad de atestacion: {error}"))?;
            let bytes = decode_hex(raw.trim())?;
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "La identidad de atestacion debe contener 32 bytes.".to_string())?;
            SigningKey::from_bytes(&secret)
        } else {
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!("No se pudo crear el directorio de atestacion: {error}")
                })?;
            }
            let key = SigningKey::generate(&mut OsRng);
            persist_secret(&key_path, &hex(key.as_bytes()))?;
            key
        };
        Ok(Self {
            key_path,
            signing_key,
        })
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn key_id(&self) -> String {
        format!(
            "sha256:{}",
            hex(&Sha256::digest(self.signing_key.verifying_key().as_bytes()))
        )
    }

    pub fn sign(
        &self,
        statement: MaterialAttestationStatement,
    ) -> Result<MaterialAttestationEnvelope, String> {
        let value = serde_json::to_value(&statement)
            .map_err(|error| format!("No se pudo serializar la atestacion: {error}"))?;
        let canonical = canonical_json(&value)?;
        let signature = self.signing_key.sign(canonical.as_bytes());
        Ok(MaterialAttestationEnvelope {
            schema: MATERIAL_ATTESTATION_SCHEMA,
            algorithm: "Ed25519".to_string(),
            key_id: self.key_id(),
            public_key: URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes()),
            statement,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

pub fn canonical_json(value: &Value) -> Result<String, String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value)
            .map_err(|error| format!("No se pudo canonicalizar string JSON: {error}")),
        Value::Array(values) => Ok(format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        )),
        Value::Object(values) => {
            let ordered = values.iter().collect::<BTreeMap<_, _>>();
            let fields = ordered
                .into_iter()
                .map(|(key, value)| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(key).map_err(|error| {
                            format!("No se pudo canonicalizar clave JSON: {error}")
                        })?,
                        canonical_json(value)?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

fn persist_secret(path: &Path, value: &str) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("No se pudo crear la identidad de atestacion: {error}"))?;
    file.write_all(format!("{value}\n").as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo persistir la identidad de atestacion: {error}"))?;
    set_secret_mode(&temporary)?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo promover la identidad de atestacion: {error}"))
}

#[cfg(unix)]
fn set_secret_mode(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("No se pudo restringir la identidad de atestacion: {error}"))
}

#[cfg(not(unix))]
fn set_secret_mode(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("La identidad de atestacion no contiene hexadecimal valido.".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|_| {
                "La identidad de atestacion no contiene hexadecimal valido.".to_string()
            })
        })
        .collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{canonical_json, AttestationSigner, MaterialAttestationStatement};
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn canonicaliza_objetos_sin_depender_del_orden() {
        assert_eq!(
            canonical_json(&json!({"z": 1, "a": {"b": true, "a": false}})).unwrap(),
            r#"{"a":{"a":false,"b":true},"z":1}"#
        );
    }

    #[test]
    fn firma_ed25519_es_verificable() {
        let root = std::env::temp_dir().join(format!("actium-attestation-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let envelope = signer
            .sign(MaterialAttestationStatement {
                host_id: Uuid::new_v4().to_string(),
                deployment_id: Uuid::new_v4().to_string(),
                generation: 7,
                runtime_release: Some("0.8.0-lab.2".to_string()),
                payload_digest: Some("a".repeat(64)),
                material_digest: "b".repeat(64),
                observed_at: "2026-08-13T00:00:00Z".to_string(),
                runtime_units: Vec::new(),
            })
            .unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(envelope.public_key)
            .unwrap();
        let key = VerifyingKey::from_bytes(&bytes.try_into().unwrap()).unwrap();
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(envelope.signature)
            .unwrap();
        let canonical = canonical_json(&serde_json::to_value(envelope.statement).unwrap()).unwrap();
        key.verify(
            canonical.as_bytes(),
            &Signature::from_bytes(&signature.try_into().unwrap()),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(root);
    }
}
