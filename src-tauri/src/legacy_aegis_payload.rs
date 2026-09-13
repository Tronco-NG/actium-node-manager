//! Explicit compatibility boundary for the legacy Aegis payload.
//!
//! The base runtime never calls this module during startup. Capability
//! installation and legacy release operations opt into it explicitly and fail
//! closed when the external bundle is absent.

use std::{
    env,
    path::PathBuf,
};
use tauri::{path::BaseDirectory, AppHandle, Manager};

pub const ADAPTER_NAME: &str = "LegacyAegisPayloadAdapter";
pub const REMOVAL_CONDITION: &str =
    "Aegis Product Extension Bundle v1 + acceptance equivalente + migracion NAS completa";

pub fn optional_bundle(app: &AppHandle) -> Option<PathBuf> {
    if let Some(env_path) = env::var_os("ACTIUM_PAYLOAD_PATH").map(PathBuf::from) {
        if env_path.join("PAYLOAD.json").is_file() {
            return Some(env_path);
        }
        if env_path.is_file() && env_path.file_name().is_some_and(|name| name == "PAYLOAD.json") {
            if let Some(parent) = env_path.parent() {
                return Some(parent.to_path_buf());
            }
        }
    }

    if let Ok(resource_path) = app.path().resolve("node", BaseDirectory::Resource) {
        if resource_path.join("PAYLOAD.json").is_file() {
            return Some(resource_path);
        }
    }

    #[cfg(unix)]
    {
        let system_candidates = [
            "/usr/lib/actium/node-manager/payload",
            "/usr/lib/actium/node-manager-lab/payload",
            "/usr/lib/actium-node-manager/payload",
            "/var/lib/actium/node-manager/payload",
            "/var/lib/actium/node-manager-lab/payload",
            "/usr/lib/Actium Node Manager/node",
        ];
        for candidate in system_candidates {
            let path = PathBuf::from(candidate);
            if path.join("PAYLOAD.json").is_file() {
                return Some(path);
            }
        }

        let node_roots = ["/actium/nodes", "/actium-lab/nodes"];
        for root in node_roots {
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let releases_dir = entry.path().join("releases");
                    if let Ok(rel_entries) = std::fs::read_dir(&releases_dir) {
                        for rel_entry in rel_entries.flatten() {
                            let rel_path = rel_entry.path();
                            if rel_path.join("PAYLOAD.json").is_file() {
                                return Some(rel_path);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(windows)]
    {
        let program_data = env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let system_candidates = [
            program_data.join("Actium").join("NodeManager").join("payload"),
            program_data.join("Actium").join("NodeManagerLab").join("payload"),
            PathBuf::from(r"C:\ProgramData\Actium\NodeManager\payload"),
            PathBuf::from(r"C:\ProgramData\Actium\NodeManagerLab\payload"),
        ];
        for candidate in system_candidates {
            if candidate.join("PAYLOAD.json").is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

pub fn required_bundle(app: &AppHandle) -> Result<PathBuf, String> {
    optional_bundle(app).ok_or_else(|| {
        format!(
            "PRODUCT_EXTENSION_BUNDLE_REQUIRED: {ADAPTER_NAME} necesita un bundle externo firmado; el Base Runtime no incluye PAYLOAD.json. Retiro: {REMOVAL_CONDITION}."
        )
    })
}
