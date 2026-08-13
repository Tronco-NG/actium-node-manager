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
            base.join("Actium")
        }
    } else {
        let base = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
            .unwrap_or_else(env::temp_dir);
        if product::is_lab() {
            base.join("actium").join("node-manager-lab")
        } else {
            base.join("actium")
        }
    }
}

pub fn authorized_nodes_root() -> PathBuf {
    if !product::is_lab() {
        return managed_nodes_dir();
    }
    if cfg!(target_os = "windows") {
        data_root().join("Nodes")
    } else {
        env::var_os("ACTIUM_NODE_MANAGER_NODES_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/srv/actium-data/nodes"))
    }
}

pub fn default_install_dir() -> PathBuf {
    if product::is_lab() {
        authorized_nodes_root().join("actium-lab-node-01")
    } else {
        data_root().join(if cfg!(target_os = "windows") {
            "TelemetryNode"
        } else {
            "telemetry-node"
        })
    }
}

pub fn managed_nodes_dir() -> PathBuf {
    if product::is_lab() {
        authorized_nodes_root()
    } else {
        data_root().join(if cfg!(target_os = "windows") {
            "TelemetryNodes"
        } else {
            "telemetry-nodes"
        })
    }
}

pub fn recovery_root_dir() -> PathBuf {
    if product::is_lab() {
        authorized_nodes_root().join(".recovery")
    } else {
        data_root().join("ActiumTelemetryNode-Recovery")
    }
}

pub fn registry_path() -> PathBuf {
    if product::is_lab() {
        data_root().join("Registry").join("nodes.json")
    } else {
        data_root().join("TelemetryNodeManager").join("nodes.json")
    }
}

pub fn diagnostics_dir() -> PathBuf {
    if product::is_lab() {
        data_root().join("Diagnostics")
    } else {
        data_root().join("TelemetryNodeManager").join("Diagnostics")
    }
}

pub fn operations_db_path() -> PathBuf {
    data_root().join("State").join("operations.sqlite3")
}

pub fn supervisor_socket_path() -> PathBuf {
    env::var_os("ACTIUM_NODE_SUPERVISOR_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/actium/node-manager.sock"))
}

pub fn supervisor_key_path() -> PathBuf {
    env::var_os("ACTIUM_NODE_SUPERVISOR_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/actium/node-manager/ipc.key"))
}
