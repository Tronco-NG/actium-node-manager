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
        env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join("ActiumLab").join("Nodes"))
            .unwrap_or_else(|| data_root().join("Nodes"))
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
