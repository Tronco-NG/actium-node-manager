use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    System,
    Hot,
    Warm,
    Bulk,
    Archive,
}

impl Default for StorageClass {
    fn default() -> Self {
        StorageClass::Bulk
    }
}

/// Representa un Storage Pool físico o lógico normalizado por el Supervisor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoragePool {
    pub id: String,
    pub name: String,
    pub device: String,
    pub mountpoint: String,
    pub filesystem: String,
    pub filesystem_uuid: Option<String>,
    pub label: Option<String>,
    pub storage_class: StorageClass,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub readonly: bool,
    pub is_system: bool,
    pub removable: bool,
    pub model: Option<String>,
}

const PSEUDO_FILESYSTEMS: &[&str] = &[
    "tmpfs", "overlay", "nsfs", "sysfs", "proc", "procfs", "cgroup", "cgroup2",
    "devpts", "devtmpfs", "squashfs", "ramfs", "pstore", "debugfs", "tracefs", "bpf",
    "binfmt_misc", "fuse.portal", "fusectl", "rpc_pipefs", "configfs", "efivarfs", "securityfs",
    "hugetlbfs", "mqueue", "autofs", "swap",
];

const RESERVED_SYSTEM_PREFIXES: &[&str] = &[
    "/etc", "/var", "/run", "/sys", "/proc", "/boot", "/dev",
];

/// Comprueba si una ruta es un directorio reservado del sistema operativo
/// o un bind mount interno que nunca debe presentarse como pool de almacenamiento.
pub fn is_internal_system_mount(mountpoint: &str) -> bool {
    let clean = mountpoint.trim();
    if clean.is_empty() || (clean.starts_with('[') && clean.ends_with(']')) {
        return true;
    }
    if clean == "/" {
        return false;
    }
    for prefix in RESERVED_SYSTEM_PREFIXES {
        if clean == *prefix || clean.starts_with(&format!("{prefix}/")) {
            return true;
        }
    }
    // Subcarpetas de autoridades o recovery generadas por bind mounts
    if clean.contains("/authority-recovery") || clean.contains("/authority-offline-root") {
        return true;
    }
    false
}

#[cfg(target_os = "linux")]
pub fn discover_storage_pools() -> Result<Vec<StoragePool>, String> {
    // 1. Intentar descubrir mediante lsblk con información de bloque rica
    let lsblk_output = std::process::Command::new("lsblk")
        .args([
            "--json",
            "--bytes",
            "-o",
            "NAME,MOUNTPOINTS,LABEL,FSTYPE,UUID,SIZE,FSAVAIL,RO,RM,HOTPLUG,TYPE,MODEL",
        ])
        .output();

    if let Ok(output) = lsblk_output {
        if output.status.success() {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                let pools = parse_lsblk_tree(&value);
                if !pools.is_empty() {
                    return Ok(normalize_and_deduplicate_pools(pools));
                }
            }
        }
    }

    // 2. Fallback a findmnt normalizado con filtrado estricto
    let findmnt_output = std::process::Command::new("findmnt")
        .args([
            "--json",
            "--bytes",
            "-o",
            "TARGET,SOURCE,FSTYPE,OPTIONS,UUID,LABEL,SIZE,AVAIL",
        ])
        .output()
        .map_err(|e| format!("STORAGE_POOL_DISCOVERY_FAILED: {e}"))?;

    if !findmnt_output.status.success() {
        return Err("STORAGE_POOL_DISCOVERY_FAILED: findmnt no exitoso".into());
    }

    let value: serde_json::Value =
        serde_json::from_slice(&findmnt_output.stdout).map_err(|_| "STORAGE_POOL_DISCOVERY_FAILED")?;

    let pools = parse_findmnt_filtered(&value);
    Ok(normalize_and_deduplicate_pools(pools))
}

#[cfg(not(target_os = "linux"))]
pub fn discover_storage_pools() -> Result<Vec<StoragePool>, String> {
    // Emulación o soporte genérico en Windows
    let mut pools = Vec::new();
    #[cfg(windows)]
    {
        for drive in ['C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'] {
            let root = format!("{}:\\", drive);
            let path = std::path::Path::new(&root);
            if path.exists() {

                let is_system = drive == 'C';
                pools.push(StoragePool {
                    id: format!("drive-{}", drive.to_ascii_lowercase()),
                    name: if is_system { format!("Disco del Sistema ({root})") } else { format!("Bahía / Unidad {drive} ({root})") },
                    device: root.clone(),
                    mountpoint: root,
                    filesystem: "NTFS".to_string(),
                    filesystem_uuid: None,
                    label: None,
                    storage_class: if is_system { StorageClass::System } else { StorageClass::Bulk },
                    total_bytes: 500_000_000_000,
                    available_bytes: 250_000_000_000,
                    readonly: false,
                    is_system,
                    removable: false,
                    model: None,
                });
            }
        }
    }
    Ok(normalize_and_deduplicate_pools(pools))
}

#[cfg(target_os = "linux")]
fn parse_lsblk_tree(value: &serde_json::Value) -> Vec<StoragePool> {
    let mut pools = Vec::new();
    if let Some(devices) = value.get("blockdevices").and_then(|v| v.as_array()) {
        for dev in devices {
            collect_lsblk_node(dev, None, &mut pools);
        }
    }
    pools
}

#[cfg(target_os = "linux")]
fn collect_lsblk_node(node: &serde_json::Value, parent_model: Option<&str>, pools: &mut Vec<StoragePool>) {
    let model = node.get("model").and_then(|v| v.as_str()).or(parent_model);
    let fstype = node.get("fstype").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();

    if !fstype.is_empty() && !PSEUDO_FILESYSTEMS.contains(&fstype.as_str()) {
        let mountpoints: Vec<&str> = if let Some(arr) = node.get("mountpoints").and_then(|v| v.as_array()) {
            arr.iter().filter_map(|v| v.as_str()).collect()
        } else if let Some(single) = node.get("mountpoint").and_then(|v| v.as_str()) {
            vec![single]
        } else {
            vec![]
        };

        for mp in mountpoints {
            if mp.is_empty() || is_internal_system_mount(mp) {
                continue;
            }
            let name = node.get("name").and_then(|v| v.as_str()).unwrap_or("disk");
            let device = format!("/dev/{name}");
            let uuid = node.get("uuid").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
            let label = node.get("label").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
            let total = node.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let avail = node.get("fsavail").and_then(|v| v.as_u64()).unwrap_or(0);
            let ro = node.get("ro").and_then(|v| v.as_bool()).unwrap_or(false);
            let rm = node.get("rm").and_then(|v| v.as_bool()).unwrap_or(false);
            let is_system = mp == "/";

            let storage_class = if is_system {
                StorageClass::System
            } else if mp.starts_with("/srv") || mp.starts_with("/mnt") || mp.starts_with("/data") {
                StorageClass::Bulk
            } else {
                StorageClass::Warm
            };

            let id = if is_system {
                "system-ssd".to_string()
            } else {
                format!("pool-{}", sanitize_identifier(mp))
            };

            let display_name = if is_system {
                "Disco Principal del Sistema (SSD/NVMe)".to_string()
            } else if let Some(lbl) = &label {
                format!("Bahía: {lbl} ({mp})")
            } else {
                format!("Bahía Almacenamiento ({mp})")
            };

            pools.push(StoragePool {
                id,
                name: display_name,
                device,
                mountpoint: mp.to_string(),
                filesystem: fstype.clone(),
                filesystem_uuid: uuid,
                label,
                storage_class,
                total_bytes: total,
                available_bytes: avail,
                readonly: ro,
                is_system,
                removable: rm,
                model: model.map(|s| s.trim().to_string()),
            });
        }
    }

    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            collect_lsblk_node(child, model, pools);
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_findmnt_filtered(value: &serde_json::Value) -> Vec<StoragePool> {
    let mut pools = Vec::new();

    fn walk_findmnt(node: &serde_json::Value, pools: &mut Vec<StoragePool>) {
        let target = node.get("target").and_then(|v| v.as_str()).unwrap_or("");
        let fstype = node.get("fstype").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();

        if !target.is_empty() && !is_internal_system_mount(target) && !fstype.is_empty() && !PSEUDO_FILESYSTEMS.contains(&fstype.as_str()) {
            let source = node.get("source").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let uuid = node.get("uuid").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
            let label = node.get("label").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
            let options = node.get("options").and_then(|v| v.as_str()).unwrap_or("");
            let readonly = options.split(',').any(|o| o.trim() == "ro");
            let total = node.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let avail = node.get("avail").and_then(|v| v.as_u64()).unwrap_or(0);
            let is_system = target == "/";

            let storage_class = if is_system {
                StorageClass::System
            } else if target.starts_with("/srv") || target.starts_with("/mnt") || target.starts_with("/data") {
                StorageClass::Bulk
            } else {
                StorageClass::Warm
            };

            let id = if is_system {
                "system-ssd".to_string()
            } else {
                format!("pool-{}", sanitize_identifier(target))
            };

            let display_name = if is_system {
                "Disco Principal del Sistema (SSD/NVMe)".to_string()
            } else if let Some(lbl) = &label {
                format!("Bahía: {lbl} ({target})")
            } else {
                format!("Bahía Almacenamiento ({target})")
            };

            pools.push(StoragePool {
                id,
                name: display_name,
                device: source,
                mountpoint: target.to_string(),
                filesystem: fstype,
                filesystem_uuid: uuid,
                label,
                storage_class,
                total_bytes: total,
                available_bytes: avail,
                readonly,
                is_system,
                removable: false,
                model: None,
            });
        }

        if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
            for child in children {
                walk_findmnt(child, pools);
            }
        }
    }

    if let Some(filesystems) = value.get("filesystems").and_then(|v| v.as_array()) {
        for fs_node in filesystems {
            walk_findmnt(fs_node, &mut pools);
        }
    }

    pools
}

fn normalize_and_deduplicate_pools(pools: Vec<StoragePool>) -> Vec<StoragePool> {
    let mut by_mount: BTreeMap<String, StoragePool> = BTreeMap::new();

    for pool in pools {
        // Normalizar la ruta canónica del punto de montaje
        let key = pool.mountpoint.clone();
        if let Some(existing) = by_mount.get_mut(&key) {
            // Priorizar si el nuevo tiene modelo o UUID
            if existing.filesystem_uuid.is_none() && pool.filesystem_uuid.is_some() {
                *existing = pool;
            }
        } else {
            by_mount.insert(key, pool);
        }
    }

    let mut result: Vec<StoragePool> = by_mount.into_values().collect();
    // Ordenar de modo que el sistema quede primero, luego por orden alfabético
    result.sort_by(|a, b| {
        b.is_system.cmp(&a.is_system).then_with(|| a.mountpoint.cmp(&b.mountpoint))
    });
    result
}

fn sanitize_identifier(path: &str) -> String {
    path.trim_matches('/')
        .replace('/', "-")
        .replace([' ', '_', '.', ':'], "-")
        .to_ascii_lowercase()
}
