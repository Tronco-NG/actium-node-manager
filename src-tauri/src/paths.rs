use crate::product;
use std::{env, path::PathBuf};

pub fn data_root() -> PathBuf {
    data_root_for(product::PRODUCT_CHANNEL)
}

pub fn data_root_for(channel: &str) -> PathBuf {
    if cfg!(target_os = "windows") {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        if channel == "lab" {
            base.join("Actium").join("NodeManagerLab")
        } else {
            base.join("Actium").join("NodeManager")
        }
    } else {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
            .unwrap_or_else(env::temp_dir);
        if channel == "lab" {
            base.join("actium").join("node-manager-lab")
        } else {
            base.join("actium").join("node-manager")
        }
    }
}

/// Host-level configuration shared by Stable and Lab. It contains no secrets.
pub fn host_control_plane_config_path() -> PathBuf {
    data_root_for("stable").join("Host").join("control-plane.json")
}

/// System-wide fallback for the host-level configuration. Bootstrap may still
/// persist the legacy per-user document, but package deployments can provide a
/// single explicit host binding for every desktop user without copying a
/// deployment into an arbitrary home directory.
pub fn shared_host_control_plane_config_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Actium")
            .join("NodeManager")
            .join("Host")
            .join("control-plane.json")
    } else {
        PathBuf::from("/etc/actium/node-manager/Host/control-plane.json")
    }
}

fn supervisor_data_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Actium")
            .join(if product::is_lab() {
                "NodeManagerLab"
            } else {
                "NodeManager"
            })
    } else if product::is_lab() {
        PathBuf::from("/var/lib/actium/node-manager-lab")
    } else {
        PathBuf::from("/var/lib/actium/node-manager")
    }
}

pub fn authorized_nodes_root() -> PathBuf {
    authorized_nodes_root_for(product::PRODUCT_CHANNEL)
}

pub fn default_install_dir() -> PathBuf {
    authorized_nodes_root()
}

pub fn managed_nodes_dir() -> PathBuf {
    authorized_nodes_root()
}

pub fn recovery_root_dir() -> PathBuf {
    authorized_nodes_root().join(".recovery")
}

pub fn registry_path() -> PathBuf {
    data_root().join("Registry").join("nodes.json")
}

pub fn diagnostics_dir() -> PathBuf {
    data_root().join("Diagnostics")
}

/// Product Extension Bundle registry for this Manager channel. The registry
/// is optional and may be empty; the base runtime must remain usable without
/// any extension directory or manifest.
pub fn extensions_root() -> PathBuf {
    data_root().join("extensions")
}

pub fn supervisor_data_root_for(channel: &str) -> PathBuf {
    let is_lab = channel == "lab";
    if cfg!(target_os = "windows") {
        env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Actium")
            .join(if is_lab {
                "NodeManagerLab"
            } else {
                "NodeManager"
            })
    } else if is_lab {
        PathBuf::from("/var/lib/actium/node-manager-lab")
    } else {
        PathBuf::from("/var/lib/actium/node-manager")
    }
}

pub fn authorized_nodes_root_for(channel: &str) -> PathBuf {
    let is_lab = channel == "lab";
    if cfg!(target_os = "windows") {
        if is_lab {
            PathBuf::from(r"C:\ActiumLab\nodes")
        } else {
            PathBuf::from(r"C:\Actium\nodes")
        }
    } else {
        env::var_os("ACTIUM_NODE_MANAGER_NODES_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let config_file = if is_lab {
                    std::path::Path::new("/etc/actium/node-manager-lab/supervisor.toml")
                } else {
                    std::path::Path::new("/etc/actium/node-manager/supervisor.toml")
                };
                if let Ok(content) = std::fs::read_to_string(config_file) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("authorized_nodes_root") {
                            if let Some(val) = trimmed.split('=').nth(1) {
                                let cleaned = val.trim().trim_matches('"').trim_matches('\'');
                                if !cleaned.is_empty() {
                                    return PathBuf::from(cleaned);
                                }
                            }
                        }
                    }
                }
                if is_lab {
                    PathBuf::from("/actium-lab/nodes")
                } else {
                    PathBuf::from("/actium/nodes")
                }
            })
    }
}

pub fn supervisor_socket_path_for(channel: &str) -> PathBuf {
    let is_lab = channel == "lab";
    env::var_os("ACTIUM_NODE_SUPERVISOR_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(target_os = "windows") {
                PathBuf::from(if is_lab {
                    "ActiumNodeSupervisorLab"
                } else {
                    "ActiumNodeSupervisor"
                })
            } else {
                PathBuf::from(if is_lab {
                    "/run/actium/node-manager-lab.sock"
                } else {
                    "/run/actium/node-manager.sock"
                })
            }
        })
}

pub fn supervisor_key_path_for(channel: &str) -> PathBuf {
    let is_lab = channel == "lab";
    env::var_os("ACTIUM_NODE_SUPERVISOR_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(target_os = "windows") {
                supervisor_data_root_for(channel).join("config").join("ipc.key")
            } else {
                PathBuf::from(if is_lab {
                    "/etc/actium/node-manager-lab/ipc.key"
                } else {
                    "/etc/actium/node-manager/ipc.key"
                })
            }
        })
}

pub fn supervisor_socket_path() -> PathBuf {
    supervisor_socket_path_for(product::PRODUCT_CHANNEL)
}

pub fn supervisor_key_path() -> PathBuf {
    supervisor_key_path_for(product::PRODUCT_CHANNEL)
}
