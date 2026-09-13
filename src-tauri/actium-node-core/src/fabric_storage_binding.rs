use crate::{
    storage_access_profile::{provision_storage_directory, StorageAccessProfile},
    storage_pool::{StorageClass, StoragePool},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
};

/// Vinculación física de almacenamiento del Fabric.
/// Separa de manera estricta el Control State (alojado en el disco de sistema soberano)
/// del Data State (alojado en la bahía o storage pool seleccionado para datos masivos).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FabricStorageBinding {
    pub fabric_id: String,
    pub pool_id: String,
    pub pool_mountpoint: String,
    pub control_root: String,
    pub data_root: String,
    pub postgres_data_dir: String,
    pub nats_data_dir: String,
    pub storage_class: StorageClass,
    pub created_at_unix_seconds: u64,
}

impl FabricStorageBinding {
    /// Construye el binding para un Fabric. Si `pool` es el disco del sistema,
    /// `data_root` coincide con `control_root/persistent`. Si se provee una bahía secundaria,
    /// `data_root` se crea dentro del pool en `<pool>/actium/fabrics/<fabric-id>/data`.
    pub fn new(
        fabric_id: &str,
        control_root: &Path,
        pool: &StoragePool,
        now_seconds: u64,
    ) -> Self {
        let control_root_clean = control_root.to_path_buf();
        let (data_root, postgres_dir, nats_dir) = if pool.is_system {
            let persistent = control_root_clean.join("persistent");
            let pg = persistent.join("postgres");
            let nats = persistent.join("nats");
            (persistent, pg, nats)
        } else {
            let bay_root = Path::new(&pool.mountpoint)
                .join("actium")
                .join("fabrics")
                .join(fabric_id)
                .join("data");
            let pg = bay_root.join("postgres");
            let nats = bay_root.join("nats");
            (bay_root, pg, nats)
        };

        Self {
            fabric_id: fabric_id.to_string(),
            pool_id: pool.id.clone(),
            pool_mountpoint: pool.mountpoint.clone(),
            control_root: control_root_clean.to_string_lossy().into_owned(),
            data_root: data_root.to_string_lossy().into_owned(),
            postgres_data_dir: postgres_dir.to_string_lossy().into_owned(),
            nats_data_dir: nats_dir.to_string_lossy().into_owned(),
            storage_class: pool.storage_class,
            created_at_unix_seconds: now_seconds,
        }
    }

    /// Prepara de forma segura el layout de directorios:
    /// - Control State en disco de sistema con permisos 0700.
    /// - Data State aprovisionado con los StorageAccessProfile adecuados para PostgreSQL y NATS.
    pub fn ensure_layout(&self) -> Result<(), String> {
        let control = Path::new(&self.control_root);
        for dir in ["state", "releases", "manifests", "locks", "identities", "secrets"] {
            let p = control.join(dir);
            if !p.exists() {
                fs::create_dir_all(&p)
                    .map_err(|e| format!("No se pudo preparar Control State {}: {e}", p.display()))?;
            }
        }

        // Aprovisionar Data State con StorageAccessProfile correspondiente
        let pg_path = Path::new(&self.postgres_data_dir);
        provision_storage_directory(pg_path, &StorageAccessProfile::fabric_postgres())?;

        let nats_path = Path::new(&self.nats_data_dir);
        provision_storage_directory(nats_path, &StorageAccessProfile::fabric_nats())?;

        // Guardar el binding en state/fabric-storage-binding.json
        let binding_file = control.join("state/fabric-storage-binding.json");
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("No se pudo serializar binding: {e}"))?;
        fs::write(&binding_file, bytes)
            .map_err(|e| format!("No se pudo guardar binding en {}: {e}", binding_file.display()))?;

        Ok(())
    }

    /// Exporta las variables de entorno necesarias para que Docker Compose monte los volúmenes en las rutas efectivas.
    pub fn compose_env(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert(
            "ACTIUM_FABRIC_POSTGRES_DATA_PATH".to_string(),
            self.postgres_data_dir.clone(),
        );
        env.insert(
            "ACTIUM_FABRIC_NATS_DATA_PATH".to_string(),
            self.nats_data_dir.clone(),
        );
        env.insert(
            "ACTIUM_FABRIC_DATA_ROOT".to_string(),
            self.data_root.clone(),
        );
        env.insert(
            "ACTIUM_FABRIC_STORAGE_POOL_ID".to_string(),
            self.pool_id.clone(),
        );
        env
    }

    /// Carga el binding si ya existe en disco.
    pub fn load_from_control_root(control_root: &Path) -> Option<Self> {
        let binding_file = control_root.join("state/fabric-storage-binding.json");
        if binding_file.exists() {
            if let Ok(bytes) = fs::read(binding_file) {
                return serde_json::from_slice(&bytes).ok();
            }
        }
        None
    }

    /// Carga el binding existente o crea uno por defecto apuntando a la raíz del sistema.
    pub fn load_or_default(fabric_id: &str, control_root: &Path) -> Self {
        if let Some(binding) = Self::load_from_control_root(control_root) {
            return binding;
        }
        let system_pool = StoragePool {
            id: "system-pool".to_string(),
            name: "System Root".to_string(),
            device: "/dev/root".to_string(),
            mountpoint: "/".to_string(),
            filesystem: "ext4".to_string(),
            filesystem_uuid: None,
            label: Some("SYSTEM".to_string()),
            storage_class: StorageClass::System,
            total_bytes: 0,
            available_bytes: 0,
            readonly: false,
            is_system: true,
            removable: false,
            model: None,
        };
        Self::new(fabric_id, control_root, &system_pool, 0)
    }
}
