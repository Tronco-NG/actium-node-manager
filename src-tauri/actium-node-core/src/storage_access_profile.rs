use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Perfil de acceso a almacenamiento por workload industrial.
/// Define las identidades de usuario/grupo de runtime en contenedor,
/// máscaras de permisos, requerimientos de consistencia y concurrencia.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageAccessProfile {
    pub workload: String,
    pub runtime_uid: u32,
    pub runtime_gid: u32,
    #[serde(default)]
    pub supplemental_gids: Vec<u32>,
    pub required_mode: u32,
    pub requires_posix_acl: bool,
    pub requires_fsync: bool,
    pub requires_locking: bool,
    pub supports_network_fs: bool,
}

impl StorageAccessProfile {
    pub fn fabric_postgres() -> Self {
        Self {
            workload: "fabric-postgres".to_string(),
            // Las imágenes de PostgreSQL en Alpine (actium/data-plane-postgres) usan UID:GID 70:70.
            runtime_uid: 70,
            runtime_gid: 70,
            supplemental_gids: vec![1000, 999],
            required_mode: 0o700,
            requires_posix_acl: true,
            requires_fsync: true,
            requires_locking: true,
            supports_network_fs: false,
        }
    }

    pub fn fabric_nats() -> Self {
        Self {
            workload: "fabric-nats".to_string(),
            // NATS container corre como usuario actium (UID:GID 10001:10001)
            runtime_uid: 10001,
            runtime_gid: 10001,
            supplemental_gids: vec![1000],
            required_mode: 0o770,
            requires_posix_acl: true,
            requires_fsync: true,
            requires_locking: false,
            supports_network_fs: true,
        }
    }

    pub fn telemetry_history() -> Self {
        Self {
            workload: "telemetry-history".to_string(),
            runtime_uid: 1000,
            runtime_gid: 1000,
            supplemental_gids: vec![],
            required_mode: 0o750,
            requires_posix_acl: true,
            requires_fsync: true,
            requires_locking: false,
            supports_network_fs: true,
        }
    }

    pub fn radio_saf() -> Self {
        Self {
            workload: "radio-saf-minio".to_string(),
            runtime_uid: 1000,
            runtime_gid: 1000,
            supplemental_gids: vec![],
            required_mode: 0o750,
            requires_posix_acl: true,
            requires_fsync: false,
            requires_locking: false,
            supports_network_fs: true,
        }
    }

    pub fn observability_prometheus() -> Self {
        Self {
            workload: "observability-prometheus".to_string(),
            runtime_uid: 65534,
            runtime_gid: 65534,
            supplemental_gids: vec![1000],
            required_mode: 0o750,
            requires_posix_acl: true,
            requires_fsync: true,
            requires_locking: true,
            supports_network_fs: false,
        }
    }

    pub fn site_core() -> Self {
        Self {
            workload: "site-core".to_string(),
            runtime_uid: 1000,
            runtime_gid: 1000,
            supplemental_gids: vec![],
            required_mode: 0o750,
            requires_posix_acl: true,
            requires_fsync: true,
            requires_locking: false,
            supports_network_fs: false,
        }
    }

    pub fn custom(workload: &str, uid: u32, gid: u32) -> Self {
        Self {
            workload: workload.to_string(),
            runtime_uid: uid,
            runtime_gid: gid,
            supplemental_gids: vec![],
            required_mode: 0o750,
            requires_posix_acl: true,
            requires_fsync: true,
            requires_locking: false,
            supports_network_fs: true,
        }
    }

    pub fn for_capability(cap: &str) -> Self {
        match cap {
            "telemetry" | "telemetry-history" | "gps" => Self::telemetry_history(),
            "radio-saf" | "radio-archive" => Self::radio_saf(),
            "observability" | "metrics" => Self::observability_prometheus(),
            "site-core" => Self::site_core(),
            "postgres" | "fabric-postgres" => Self::fabric_postgres(),
            "nats" | "fabric-nats" => Self::fabric_nats(),
            _ => Self::site_core(),
        }
    }
}

/// Aprovisiona un directorio físico garantizando que el workload posea permisos de lectura/escritura.
#[allow(unused_variables)]
pub fn provision_storage_directory(
    target_path: &Path,
    profile: &StorageAccessProfile,
) -> Result<PathBuf, String> {


    if !target_path.exists() {
        fs::create_dir_all(target_path).map_err(|error| {
            format!(
                "No se pudo crear el directorio de storage {}: {error}",
                target_path.display()
            )
        })?;
    }

    #[cfg(unix)]
    {
        // 1. Asignar modo base
        let permissions = fs::Permissions::from_mode(profile.required_mode);
        let _ = fs::set_permissions(target_path, permissions);

        // 2. Chown recursivo al UID:GID de runtime si tenemos privilegios de root
        let path_str = target_path.to_str().unwrap_or("");
        let uid = nix::unistd::Uid::from_raw(profile.runtime_uid);
        let gid = nix::unistd::Gid::from_raw(profile.runtime_gid);
        fn recursive_chown_path(dir: &Path, uid: nix::unistd::Uid, gid: nix::unistd::Gid) {
            let _ = nix::unistd::chown(dir, Some(uid), Some(gid));
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        recursive_chown_path(&path, uid, gid);
                    } else {
                        let _ = nix::unistd::chown(&path, Some(uid), Some(gid));
                    }
                }
            }
        }
        recursive_chown_path(target_path, uid, gid);

        // 3. Si requiere POSIX ACLs y estamos en Linux, configurar default ACLs para herencia
        #[cfg(target_os = "linux")]
        if profile.requires_posix_acl {
            let acl_spec = format!(
                "u::rwx,g::rwx,o::rx,d:u::rwx,d:g::rwx,d:o::rx,d:u:{}:rwx",
                profile.runtime_uid
            );
            let _ = std::process::Command::new("setfacl")
                .args(["-m", &acl_spec, path_str])
                .output();
        }
    }

    Ok(target_path.to_path_buf())
}
