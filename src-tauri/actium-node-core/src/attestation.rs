use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
    pub sequence: u64,
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

#[derive(Debug, Clone)]
pub struct AttestationJournal {
    supervisor_state: PathBuf,
    persistence_faults: Arc<Mutex<VecDeque<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationRecordBody {
    schema: u8,
    sequence: u64,
    previous_record_sha256: Option<String>,
    envelope: MaterialAttestationEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct AttestationRecord {
    #[serde(flatten)]
    body: AttestationRecordBody,
    record_sha256: String,
}

impl AttestationSigner {
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, String> {
        let key_path = path.into();
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!("No se pudo crear el directorio de atestacion: {error}")
            })?;
        }
        let identity_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(key_path.with_extension("identity.lock"))
            .map_err(|error| format!("No se pudo abrir lock de identidad: {error}"))?;
        identity_lock
            .lock_exclusive()
            .map_err(|error| format!("No se pudo adquirir lock de identidad: {error}"))?;
        if !key_path.is_file() {
            let candidate = SigningKey::generate(&mut OsRng);
            match persist_secret_create_new(&key_path, &hex(candidate.as_bytes())) {
                Ok(()) => {}
                Err(error) if key_path.is_file() => {
                    let _ = error;
                }
                Err(error) => return Err(error),
            }
        }
        let signing_key = {
            let raw = fs::read_to_string(&key_path)
                .map_err(|error| format!("No se pudo leer la identidad de atestacion: {error}"))?;
            let bytes = decode_hex(raw.trim())?;
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "La identidad de atestacion debe contener 32 bytes.".to_string())?;
            SigningKey::from_bytes(&secret)
        };
        let _ = FileExt::unlock(&identity_lock);
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

pub fn verify_material_attestation(envelope: &MaterialAttestationEnvelope) -> Result<(), String> {
    if envelope.schema != MATERIAL_ATTESTATION_SCHEMA || envelope.algorithm != "Ed25519" {
        return Err("Atestacion material usa schema o algoritmo incompatible.".to_string());
    }
    let public = URL_SAFE_NO_PAD
        .decode(&envelope.public_key)
        .map_err(|_| "Public key de atestacion invalida.".to_string())?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| "Public key de atestacion no posee 32 bytes.".to_string())?;
    let key = VerifyingKey::from_bytes(&public)
        .map_err(|_| "Public key Ed25519 de atestacion invalida.".to_string())?;
    let expected_key_id = format!("sha256:{}", hex(&Sha256::digest(public)));
    if envelope.key_id != expected_key_id {
        return Err("keyId de atestacion no coincide con su public key.".to_string());
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&envelope.signature)
        .map_err(|_| "Firma de atestacion invalida.".to_string())?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| "Firma de atestacion no posee 64 bytes.".to_string())?;
    let value = serde_json::to_value(&envelope.statement)
        .map_err(|error| format!("No se pudo serializar atestacion: {error}"))?;
    key.verify(
        canonical_json(&value)?.as_bytes(),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| "Firma material Ed25519 no verificable.".to_string())
}

impl AttestationJournal {
    pub fn new(supervisor_state: impl Into<PathBuf>) -> Self {
        Self {
            supervisor_state: supervisor_state.into(),
            persistence_faults: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    #[cfg(any(test, feature = "fault-injection"))]
    pub fn with_persistence_faults(
        supervisor_state: impl Into<PathBuf>,
        faults: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            supervisor_state: supervisor_state.into(),
            persistence_faults: Arc::new(Mutex::new(faults.into_iter().map(Into::into).collect())),
        }
    }

    pub fn sign_and_publish<F>(
        &self,
        signer: &AttestationSigner,
        build_statement: F,
    ) -> Result<MaterialAttestationEnvelope, String>
    where
        F: FnOnce(u64) -> Result<MaterialAttestationStatement, String>,
    {
        fs::create_dir_all(&self.supervisor_state)
            .map_err(|error| format!("No se pudo crear estado autoritativo: {error}"))?;
        let lock_path = self.supervisor_state.join("attestation-mutation.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| format!("No se pudo abrir lock de atestacion: {error}"))?;
        lock.lock_exclusive()
            .map_err(|error| format!("No se pudo adquirir lock de atestacion: {error}"))?;

        let latest = self.load_latest_record()?;
        let legacy = if latest.is_none() {
            self.load_legacy_envelope()?
        } else {
            None
        };
        let previous_sequence = latest
            .as_ref()
            .map(|record| record.body.sequence)
            .or_else(|| legacy.as_ref().map(|envelope| envelope.statement.sequence))
            .unwrap_or(0);
        let sequence = previous_sequence
            .checked_add(1)
            .ok_or_else(|| "Secuencia de atestacion agotada.".to_string())?;
        let statement = build_statement(sequence)?;
        if statement.sequence != sequence {
            return Err("Builder de atestacion altero la secuencia asignada.".to_string());
        }
        let envelope = signer.sign(statement)?;
        let body = AttestationRecordBody {
            schema: 1,
            sequence,
            previous_record_sha256: latest.map(|record| record.record_sha256),
            envelope: envelope.clone(),
        };
        let record = AttestationRecord {
            record_sha256: sha256_json(&body)?,
            body,
        };
        let persisted = self.persist_record(&record);
        if let Err(error) = persisted {
            let recovered = self
                .load_latest_record()
                .ok()
                .flatten()
                .is_some_and(|value| value == record);
            if !recovered {
                return Err(error);
            }
        }
        let _ = self.sync_derived_views(&envelope);
        let _ = FileExt::unlock(&lock);
        Ok(envelope)
    }

    pub fn latest(&self) -> Result<Option<MaterialAttestationEnvelope>, String> {
        fs::create_dir_all(&self.supervisor_state)
            .map_err(|error| format!("No se pudo crear estado autoritativo: {error}"))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.supervisor_state.join("attestation-mutation.lock"))
            .map_err(|error| format!("No se pudo abrir lock de atestacion: {error}"))?;
        lock.lock_exclusive()
            .map_err(|error| format!("No se pudo adquirir lock de atestacion: {error}"))?;
        if let Some(record) = self.load_latest_record()? {
            let _ = self.sync_derived_views(&record.body.envelope);
            return Ok(Some(record.body.envelope));
        }
        self.load_legacy_envelope()
    }

    fn records_path(&self) -> PathBuf {
        self.supervisor_state.join("material-attestations-v1")
    }

    fn persist_record(&self, record: &AttestationRecord) -> Result<(), String> {
        let directory = self.records_path();
        fs::create_dir_all(&directory)
            .map_err(|error| format!("No se pudo crear journal de atestacion: {error}"))?;
        self.persistence_fault("attestation.before_temp_write")?;
        let final_path = directory.join(format!(
            "{:020}-{}.json",
            record.body.sequence, record.record_sha256
        ));
        let temporary = directory.join(format!(
            ".{:020}-{}.tmp-{}",
            record.body.sequence,
            record.record_sha256,
            Uuid::new_v4()
        ));
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|error| format!("No se pudo serializar record de atestacion: {error}"))?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("No se pudo crear atestacion temporal: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("No se pudo escribir atestacion temporal: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("No se pudo sincronizar atestacion temporal: {error}"))?;
        self.persistence_fault("attestation.after_temp_sync")?;
        fs::rename(&temporary, &final_path)
            .map_err(|error| format!("No se pudo publicar atestacion inmutable: {error}"))?;
        sync_directory(&directory)?;
        self.persistence_fault("attestation.after_rename")?;
        Ok(())
    }

    fn load_latest_record(&self) -> Result<Option<AttestationRecord>, String> {
        let directory = self.records_path();
        if !directory.is_dir() {
            return Ok(None);
        }
        let mut paths = fs::read_dir(&directory)
            .map_err(|error| format!("No se pudo leer journal de atestacion: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("Entrada de atestacion invalida: {error}"))?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect::<Vec<_>>();
        paths.sort();
        let mut previous_hash = None;
        let mut previous_sequence = 0_u64;
        let mut latest = None;
        for path in paths {
            let record = read_attestation_record(&path)?;
            let expected_sequence = if previous_sequence == 0 {
                record.body.sequence
            } else {
                previous_sequence.saturating_add(1)
            };
            if record.body.schema != 1
                || record.body.sequence != expected_sequence
                || record.body.previous_record_sha256 != previous_hash
            {
                return Err(format!(
                    "ATTESTATION_STATE_CORRUPT: cadena invalida en {}.",
                    path.display()
                ));
            }
            previous_sequence = record.body.sequence;
            previous_hash = Some(record.record_sha256.clone());
            latest = Some(record);
        }
        if let Some(record) = latest.as_ref() {
            let evidence_path = self.supervisor_state.join("material-attestation.json");
            if let Ok(bytes) = fs::read(&evidence_path) {
                if let Ok(witness) = serde_json::from_slice::<MaterialAttestationEnvelope>(&bytes) {
                    if verify_material_attestation(&witness).is_ok()
                        && (witness.statement.sequence > record.body.sequence
                            || (witness.statement.sequence == record.body.sequence
                                && witness != record.body.envelope))
                    {
                        return Err(
                            "ATTESTATION_STATE_TRUNCATED: evidencia firmada conoce un checkpoint ausente o divergente."
                                .to_string(),
                        );
                    }
                }
            }
            if let Ok(raw) = fs::read_to_string(self.supervisor_state.join("attestation-sequence"))
            {
                if raw
                    .trim()
                    .parse::<u64>()
                    .is_ok_and(|sequence| sequence > record.body.sequence)
                {
                    return Err(
                        "ATTESTATION_STATE_TRUNCATED: contador conoce un checkpoint ausente."
                            .to_string(),
                    );
                }
            }
        }
        Ok(latest)
    }

    fn load_legacy_envelope(&self) -> Result<Option<MaterialAttestationEnvelope>, String> {
        let evidence_path = self.supervisor_state.join("material-attestation.json");
        let sequence_path = self.supervisor_state.join("attestation-sequence");
        if !evidence_path.is_file() {
            if sequence_path.exists() {
                return Err(
                    "ATTESTATION_STATE_CORRUPT: contador existe sin evidencia firmada.".to_string(),
                );
            }
            return Ok(None);
        }
        let bytes = fs::read(&evidence_path)
            .map_err(|error| format!("No se pudo leer atestacion legacy: {error}"))?;
        let envelope = serde_json::from_slice::<MaterialAttestationEnvelope>(&bytes)
            .map_err(|error| format!("ATTESTATION_STATE_CORRUPT: evidencia legacy: {error}"))?;
        verify_material_attestation(&envelope)?;
        if sequence_path.is_file() {
            let sequence = fs::read_to_string(&sequence_path)
                .map_err(|error| format!("No se pudo leer secuencia legacy: {error}"))?
                .trim()
                .parse::<u64>()
                .map_err(|_| {
                    "ATTESTATION_STATE_CORRUPT: secuencia legacy no es u64.".to_string()
                })?;
            if sequence != envelope.statement.sequence {
                return Err(
                    "ATTESTATION_STATE_CORRUPT: contador y evidencia legacy divergen.".to_string(),
                );
            }
        }
        Ok(Some(envelope))
    }

    fn sync_derived_views(&self, envelope: &MaterialAttestationEnvelope) -> Result<(), String> {
        self.persistence_fault("attestation.before_mirrors")?;
        write_json_derived(
            &self.supervisor_state.join("material-attestation.json"),
            envelope,
        )?;
        self.persistence_fault("attestation.mirror.sequence")?;
        write_text_derived(
            &self.supervisor_state.join("attestation-sequence"),
            &format!("{}\n", envelope.statement.sequence),
        )
    }

    fn persistence_fault(&self, stage: &str) -> Result<(), String> {
        let mut faults = self
            .persistence_faults
            .lock()
            .map_err(|_| "Fault injector de atestacion envenenado.".to_string())?;
        if faults.front().is_some_and(|value| value == stage) {
            faults.pop_front();
            return Err(format!("PERSISTENCE_FAULT_INJECTED:{stage}"));
        }
        Ok(())
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

fn persist_secret_create_new(path: &Path, value: &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("No se pudo crear la identidad de atestacion: {error}"))?;
    file.write_all(format!("{value}\n").as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo persistir la identidad de atestacion: {error}"))?;
    set_secret_mode(path)
}

fn read_attestation_record(path: &Path) -> Result<AttestationRecord, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    let record = serde_json::from_slice::<AttestationRecord>(&bytes)
        .map_err(|error| format!("ATTESTATION_STATE_CORRUPT en {}: {error}", path.display()))?;
    if sha256_json(&record.body)? != record.record_sha256
        || record.body.envelope.statement.sequence != record.body.sequence
    {
        return Err(format!(
            "ATTESTATION_STATE_CORRUPT: digest o secuencia invalida en {}.",
            path.display()
        ));
    }
    verify_material_attestation(&record.body.envelope)?;
    let expected_name = format!("{:020}-{}.json", record.body.sequence, record.record_sha256);
    if path.file_name().and_then(|value| value.to_str()) != Some(expected_name.as_str()) {
        return Err(format!(
            "ATTESTATION_STATE_CORRUPT: nombre no coincide en {}.",
            path.display()
        ));
    }
    Ok(record)
}

fn sha256_json(value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("No se pudo canonicalizar record: {error}"))?;
    Ok(hex(&Sha256::digest(bytes)))
}

fn write_json_derived(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("No se pudo serializar vista de atestacion: {error}"))?;
    write_bytes_derived(path, &bytes)
}

fn write_text_derived(path: &Path, value: &str) -> Result<(), String> {
    write_bytes_derived(path, value.as_bytes())
}

fn write_bytes_derived(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let mut file = File::create(&temporary)
        .map_err(|error| format!("No se pudo crear vista temporal: {error}"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("No se pudo persistir vista temporal: {error}"))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("No se pudo retirar vista {}: {error}", path.display()))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo publicar vista {}: {error}", path.display()))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("No se pudo sincronizar {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
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
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
    use super::{
        canonical_json, AttestationJournal, AttestationSigner, MaterialAttestationStatement,
    };
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde_json::json;
    use std::{fs, sync::Arc, thread};
    use uuid::Uuid;

    fn statement(sequence: u64) -> MaterialAttestationStatement {
        MaterialAttestationStatement {
            host_id: Uuid::new_v4().to_string(),
            deployment_id: Uuid::new_v4().to_string(),
            sequence,
            generation: 7,
            runtime_release: Some("0.8.0-lab.test".to_string()),
            payload_digest: Some("a".repeat(64)),
            material_digest: "b".repeat(64),
            observed_at: "2026-08-15T00:00:00Z".to_string(),
            runtime_units: Vec::new(),
        }
    }

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
                sequence: 9,
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

    #[test]
    fn journal_reabre_y_continua_secuencia_sin_reset() {
        let root = std::env::temp_dir().join(format!("actium-att-journal-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let journal = AttestationJournal::new(root.join("state"));
        let first = journal
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap();
        assert_eq!(first.statement.sequence, 1);
        let reopened = AttestationJournal::new(root.join("state"));
        let second = reopened
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap();
        assert_eq!(second.statement.sequence, 2);
        assert_eq!(
            reopened.latest().unwrap().unwrap().statement.sequence,
            second.statement.sequence
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refreshes_concurrentes_serializan_secuencias_unicas() {
        let root = std::env::temp_dir().join(format!("actium-att-concurrent-{}", Uuid::new_v4()));
        let signer =
            Arc::new(AttestationSigner::load_or_create(root.join("identity.key")).unwrap());
        let journal = Arc::new(AttestationJournal::new(root.join("state")));
        let threads = (0..8)
            .map(|_| {
                let signer = signer.clone();
                let journal = journal.clone();
                thread::spawn(move || {
                    journal
                        .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
                        .unwrap()
                        .statement
                        .sequence
                })
            })
            .collect::<Vec<_>>();
        let mut sequences = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=8).collect::<Vec<_>>());
        assert_eq!(journal.latest().unwrap().unwrap().statement.sequence, 8);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn fallo_post_rename_y_mirror_no_duplican_secuencia() {
        let root = std::env::temp_dir().join(format!("actium-att-fault-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let journal = AttestationJournal::with_persistence_faults(
            root.join("state"),
            ["attestation.after_rename", "attestation.mirror.sequence"],
        );
        let first = journal
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap();
        assert_eq!(first.statement.sequence, 1);
        let second = journal
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap();
        assert_eq!(second.statement.sequence, 2);
        assert_eq!(journal.latest().unwrap().unwrap().statement.sequence, 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn checkpoint_corrupto_falla_cerrado() {
        let root = std::env::temp_dir().join(format!("actium-att-corrupt-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let journal = AttestationJournal::new(root.join("state"));
        journal
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap();
        let record = fs::read_dir(root.join("state/material-attestations-v1"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::write(&record, b"{}").unwrap();
        assert!(journal
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap_err()
            .contains("ATTESTATION_STATE_CORRUPT"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn truncado_de_checkpoint_no_resetea_secuencia() {
        let root = std::env::temp_dir().join(format!("actium-att-truncate-{}", Uuid::new_v4()));
        let signer = AttestationSigner::load_or_create(root.join("identity.key")).unwrap();
        let journal = AttestationJournal::new(root.join("state"));
        journal
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap();
        journal
            .sign_and_publish(&signer, |sequence| Ok(statement(sequence)))
            .unwrap();
        let mut records = fs::read_dir(root.join("state/material-attestations-v1"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        records.sort();
        fs::remove_file(records.last().unwrap()).unwrap();
        assert!(journal
            .latest()
            .unwrap_err()
            .contains("ATTESTATION_STATE_TRUNCATED"));
        let _ = fs::remove_dir_all(root);
    }
}
