use crate::product;
use std::{env, path::PathBuf};

pub fn data_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        if product::is_lab() {
            base.join("Actium").join("NodeManagerLab")
        } else {
            base.join("Actium").join("NodeManager")
        }
    } else {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
            .unwrap_or_else(env::temp_dir);
        if product::is_lab() {
            base.join("actium").join("node-manager-lab")
        } else {
            base.join("actium").join("node-manager")
        }
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
    if cfg!(target_os = "windows") {
        supervisor_data_root().join("nodes")
    } else {
        env::var_os("ACTIUM_NODE_MANAGER_NODES_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                if product::is_lab() {
                    PathBuf::from("/srv/actium-lab/nodes")
                } else {
                    PathBuf::from("/srv/actium-data/nodes")
                }
            })
    }
}

pub fn default_install_dir() -> PathBuf {
    authorized_nodes_root().join(if product::is_lab() {
        "actium-lab-node-01"
    } else {
        "actium-node-01"
    })
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

pub fn supervisor_socket_path() -> PathBuf {
    env::var_os("ACTIUM_NODE_SUPERVISOR_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(target_os = "windows") {
                PathBuf::from(if product::is_lab() {
                    "ActiumNodeSupervisorLab"
                } else {
                    "ActiumNodeSupervisor"
                })
            } else {
                PathBuf::from(if product::is_lab() {
                    "/run/actium/node-manager-lab.sock"
                } else {
                    "/run/actium/node-manager.sock"
                })
            }
        })
}

pub fn supervisor_key_path() -> PathBuf {
    env::var_os("ACTIUM_NODE_SUPERVISOR_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(target_os = "windows") {
                supervisor_data_root().join("config").join("ipc.key")
            } else {
                PathBuf::from(if product::is_lab() {
                    "/etc/actium/node-manager-lab/ipc.key"
                } else {
                    "/etc/actium/node-manager/ipc.key"
                })
            }
        })
}
