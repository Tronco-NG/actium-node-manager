pub const DATA_PLANE_RELEASE_VERSION: &str = if cfg!(actium_channel_lab) {
    "0.8.0-lab.15"
} else {
    "0.8.0-rc.1"
};
pub const PAYLOAD_SCHEMA_VERSION: u8 = 3;
pub const SITE_RUNTIME_SCHEMA_VERSION: &str = "1.1";
pub const NODE_SUPERVISOR_VERSION: &str = "0.5.4";
pub const LEGACY_PRODUCT_ALIASES: [&str; 4] = [
    "Actium Telemetry Node Manager",
    "Actium Telemetry Node Installer",
    "actium-telemetry-node-installer",
    "Actium Telemetry Data Plane",
];

pub const TELEMETRY_PORT: u16 = if cfg!(actium_channel_lab) {
    18_090
} else {
    8_090
};
pub const RADIO_CONTROL_PORT: u16 = if cfg!(actium_channel_lab) {
    18_100
} else {
    8_100
};
pub const RADIO_SAF_PORT: u16 = if cfg!(actium_channel_lab) {
    18_101
} else {
    8_101
};
pub const SITE_CORE_PORT: u16 = if cfg!(actium_channel_lab) {
    18_088
} else {
    8_088
};
pub const PROMETHEUS_PORT: u16 = if cfg!(actium_channel_lab) {
    19_090
} else {
    9_090
};
pub const GRAFANA_PORT: u16 = if cfg!(actium_channel_lab) {
    13_001
} else {
    3_001
};
pub const TURN_PORT: u16 = if cfg!(actium_channel_lab) {
    13_478
} else {
    3_478
};
pub const TURN_TLS_PORT: u16 = if cfg!(actium_channel_lab) {
    15_349
} else {
    5_349
};
pub const TURN_MIN_PORT: u16 = if cfg!(actium_channel_lab) {
    59_160
} else {
    49_160
};
pub const TURN_MAX_PORT: u16 = if cfg!(actium_channel_lab) {
    59_200
} else {
    49_200
};
pub const LIVEKIT_HTTP_PORT: u16 = if cfg!(actium_channel_lab) {
    17_880
} else {
    7_880
};
pub const LIVEKIT_RTC_TCP_PORT: u16 = if cfg!(actium_channel_lab) {
    17_881
} else {
    7_881
};
pub const LIVEKIT_UDP_MIN_PORT: u16 = if cfg!(actium_channel_lab) {
    60_000
} else {
    50_000
};
pub const LIVEKIT_UDP_MAX_PORT: u16 = if cfg!(actium_channel_lab) {
    60_100
} else {
    50_100
};

pub const PRODUCT_CHANNEL: &str = if cfg!(actium_channel_lab) {
    "lab"
} else {
    "stable"
};

pub const fn is_lab() -> bool {
    cfg!(actium_channel_lab)
}

pub const fn display_name() -> &'static str {
    if is_lab() {
        "Actium Node Manager Lab"
    } else {
        "Actium Node Manager"
    }
}

pub const fn manager_version() -> &'static str {
    if is_lab() {
        "0.7.0-lab.15"
    } else {
        "0.7.0-rc.2"
    }
}

pub fn compose_project_name(deployment_code: &str) -> String {
    let deployment_code = deployment_code.trim();
    let prefix = if is_lab() {
        "actium-lab-"
    } else {
        "actium-node-"
    };
    if deployment_code.starts_with(prefix) {
        deployment_code.to_string()
    } else {
        format!("{prefix}{deployment_code}")
    }
}

pub fn project_name_allowed(project_name: &str) -> bool {
    let project_name = project_name.trim();
    if is_lab() {
        project_name.starts_with("actium-lab-")
    } else {
        project_name.starts_with("actium-node-")
    }
}

#[cfg(test)]
mod tests {
    use super::{compose_project_name, project_name_allowed, PRODUCT_CHANNEL, TELEMETRY_PORT};

    #[test]
    fn namespace_compose_respeta_el_canal_compilado() {
        let project = compose_project_name("node-01");
        if PRODUCT_CHANNEL == "lab" {
            assert_eq!(project, "actium-lab-node-01");
            assert_eq!(TELEMETRY_PORT, 18_090);
            assert!(project_name_allowed(&project));
            assert!(!project_name_allowed("actium-center-01"));
        } else {
            assert_eq!(project, "actium-node-node-01");
            assert_eq!(TELEMETRY_PORT, 8_090);
            assert!(project_name_allowed(&project));
            assert!(!project_name_allowed("actium-lab-node-01"));
            assert!(!project_name_allowed("actium-center-01"));
        }
    }
}
