use crate::{
    storage_access_profile::StorageAccessProfile,
    storage_grant::{policy_hash, validate_filesystem_uuid, StorageGrant},
    storage_pool::{StorageClass, StoragePool},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::Instant,
};
use uuid::Uuid;

/// Resultado de la prueba activa de escritura y fsync en un pool o directorio de storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageProbeResult {
    pub success: bool,
    pub writable: bool,
    pub fsync_supported: bool,
    pub latency_microseconds: u64,
    pub error_message: Option<String>,
}

/// Declaración previa al enrolamiento donde el operador define en qué pool
/// y con qué clase de almacenamiento correrá cada capability de un nodo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageIntent {
    pub intent_id: String,
    pub deployment_id: Option<String>,
    pub capability: String,
    pub pool_id: String,
    pub pool_mountpoint: String,
    pub subpath: String,
    pub effective_path: String,
    pub storage_class: StorageClass,
    pub access_profile: StorageAccessProfile,
    pub probe_result: Option<StorageProbeResult>,
}

impl StorageIntent {
    pub fn new(
        capability: &str,
        pool: &StoragePool,
        subpath: &str,
        access_profile: StorageAccessProfile,
    ) -> Self {
        let clean_subpath = subpath.trim_matches('/').replace('\\', "/");
        let pool_path = Path::new(&pool.mountpoint);
        let effective_path = pool_path.join(&clean_subpath).to_string_lossy().into_owned();

        Self {
            intent_id: Uuid::new_v4().to_string(),
            deployment_id: None,
            capability: capability.to_string(),
            pool_id: pool.id.clone(),
            pool_mountpoint: pool.mountpoint.clone(),
            subpath: clean_subpath,
            effective_path,
            storage_class: pool.storage_class,
            access_profile,
            probe_result: None,
        }
    }

    /// Ejecuta una prueba activa de escritura (write-probe) en la ruta efectiva.
    pub fn execute_probe(&mut self) -> &StorageProbeResult {
        let target = Path::new(&self.effective_path);
        let result = execute_storage_probe(target, self.access_profile.requires_fsync);
        self.probe_result = Some(result);
        self.probe_result.as_ref().unwrap()
    }

    /// Promueve la intención validada a un StorageGrant formal una vez que el nodo
    /// posee identidad criptográfica y enrolamiento.
    pub fn promote_to_grant(
        &self,
        deployment_id: &str,
        filesystem_uuid: &str,
        filesystem: &str,
        now_seconds: u64,
    ) -> Result<StorageGrant, String> {
        validate_filesystem_uuid(filesystem_uuid)?;
        let pol_hash = policy_hash(
            &self.capability,
            &self.pool_mountpoint,
            &self.subpath,
            filesystem_uuid,
        );

        Ok(StorageGrant {
            grant_id: Uuid::new_v4().to_string(),
            capability: self.capability.clone(),
            canonical_mountpoint: self.pool_mountpoint.clone(),
            canonical_path: self.effective_path.clone(),
            subpath: self.subpath.clone(),
            filesystem: filesystem.to_string(),
            filesystem_uuid: filesystem_uuid.to_string(),
            binding_epoch: now_seconds,
            state: "applied".to_string(),
            degraded_reason: None,
            client_id: None,
            organization_id: None,
            site_id: None,
            host_id: None,
            host_installation_id: None,
            deployment_id: Some(deployment_id.to_string()),
            intent_id: Some(self.intent_id.clone()),
            idempotency_key: Some(format!("storage-intent-grant:{}", self.intent_id)),
            transaction_id: None,
            policy_hash: Some(pol_hash),
            report_generation: now_seconds,
            snapshot_hash: String::new(),
            applied_at_unix_seconds: Some(now_seconds),
            confirmed_at_unix_seconds: Some(now_seconds),
            approval_signer_key_id: None,
            approval_signer_fingerprint: None,
            approval_verified_at_unix_seconds: None,
        })
    }
}

/// Realiza una sonda de escritura real para verificar permisos, latencia y soporte fsync
/// sin dejar residuos en disco.
pub fn execute_storage_probe(dir_path: &Path, require_fsync: bool) -> StorageProbeResult {
    if !dir_path.exists() {
        if let Err(e) = fs::create_dir_all(dir_path) {
            return StorageProbeResult {
                success: false,
                writable: false,
                fsync_supported: false,
                latency_microseconds: 0,
                error_message: Some(format!("No se pudo crear directorio de prueba: {e}")),
            };
        }
    }

    let probe_filename = format!(".__actium_probe_{}.tmp", Uuid::new_v4());
    let probe_file_path = dir_path.join(&probe_filename);
    let start = Instant::now();

    let test_bytes = b"ACTIUM_STORAGE_PROBE_INTEGRITY_CHECK_VALIDATION_STRING\n";

    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .read(true)
            .open(&probe_file_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!("EACCES / Permiso denegado (os error 13): el operador no tiene permisos de escritura en {}", dir_path.display())
                } else {
                    format!("EACCES / No se pudo abrir archivo de prueba: {e}")
                }
            })?;

        file.write_all(test_bytes)
            .map_err(|e| format!("No se pudo escribir en el archivo: {e}"))?;

        if require_fsync {
            file.sync_all()
                .map_err(|e| format!("Fsync no soportado por el filesystem: {e}"))?;
        }

        // Rebobinar el puntero al inicio antes de validar la lectura
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("Error en seek de prueba: {e}"))?;

        let mut read_buf = Vec::new();
        file.read_to_end(&mut read_buf)
            .map_err(|e| format!("Error al leer buffer de prueba: {e}"))?;

        if read_buf != test_bytes {
            return Err("Lectura no coincidente tras fsync: posible corrupción o lectura diferida".into());
        }

        Ok(())
    })();

    let latency = start.elapsed().as_micros() as u64;
    let _ = fs::remove_file(&probe_file_path);

    match write_result {
        Ok(()) => StorageProbeResult {
            success: true,
            writable: true,
            fsync_supported: true,
            latency_microseconds: latency,
            error_message: None,
        },
        Err(err) => StorageProbeResult {
            success: false,
            writable: false,
            fsync_supported: false,
            latency_microseconds: latency,
            error_message: Some(err),
        },
    }
}
