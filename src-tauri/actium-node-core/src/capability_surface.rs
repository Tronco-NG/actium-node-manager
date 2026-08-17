use std::collections::{BTreeMap, BTreeSet};

pub const KNOWN_PROFILES: [&str; 8] = [
    "site-core",
    "telemetry",
    "radio-control",
    "radio-saf",
    "radio-turn",
    "radio-livekit",
    "observability",
    "connectivity",
];

pub const COMMON_ENV_KEYS: [&str; 11] = [
    "DATA_PLANE_NETWORK_MODE",
    "DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED",
    "ACTIUM_NETWORK_RECONCILIATION_POLICY",
    "ACTIUM_NETWORK_INTERFACE",
    "ACTIUM_NETWORK_ADDRESS",
    "ACTIUM_NETWORK_PLANE",
    "ACTIUM_NETWORK_PRIORITY",
    "DATA_PLANE_BIND_ADDRESS",
    "DATA_PLANE_PUBLIC_BASE_URL",
    "DATA_PLANE_CORS_ORIGINS",
    "ACTIUM_USE_PUBLISHED_IMAGES",
];

pub const IDENTITY_ENV_KEYS: [&str; 11] = [
    "ACTIUM_HOST_INSTALLATION_ID",
    "ACTIUM_DEPLOYMENT_ID",
    "ACTIUM_DEPLOYMENT_CODE",
    "ACTIUM_PROJECT_NAME",
    "ACTIUM_DATA_PLANE_PROJECT",
    "ACTIUM_HOST_CODE",
    "ACTIUM_CLIENT_ID",
    "ACTIUM_ORGANIZATION_ID",
    "ACTIUM_SITE_ID",
    "ACTIUM_SITE_CODE",
    "ACTIUM_HOST_DISPLAY_NAME",
];

pub const RESUME_IMMUTABLE_ENV_KEYS: [&str; 10] = [
    "ACTIUM_HOST_INSTALLATION_ID",
    "ACTIUM_DEPLOYMENT_ID",
    "ACTIUM_DEPLOYMENT_CODE",
    "ACTIUM_PROJECT_NAME",
    "ACTIUM_DATA_PLANE_PROJECT",
    "ACTIUM_HOST_CODE",
    "ACTIUM_CLIENT_ID",
    "ACTIUM_ORGANIZATION_ID",
    "ACTIUM_SITE_ID",
    "ACTIUM_SITE_CODE",
];

/// Historical issuer policy. Do not invent versions beyond documented defaults.
/// Generic packages use 0.3.0; Connectivity required 0.4.0 when that profile was introduced.
pub fn installer_min_version_for_profiles(profiles: &[String]) -> &'static str {
    if profiles.iter().any(|profile| profile == "connectivity") {
        "0.4.0"
    } else {
        "0.3.0"
    }
}

pub fn is_known_profile(profile: &str) -> bool {
    KNOWN_PROFILES.contains(&profile)
}

pub fn profile_dependencies(profile: &str) -> &'static [&'static str] {
    match profile {
        "connectivity" => &["telemetry"],
        _ => &[],
    }
}

pub fn effective_profiles(selected: &[String]) -> BTreeSet<String> {
    let mut effective = BTreeSet::new();
    for profile in selected {
        if !is_known_profile(profile) {
            continue;
        }
        effective.insert(profile.clone());
        for dependency in profile_dependencies(profile) {
            effective.insert((*dependency).to_string());
        }
    }
    effective
}

pub fn profile_env_keys(profile: &str) -> &'static [&'static str] {
    match profile {
        "site-core" => &["SITE_CORE_PORT", "SITE_CORE_PUBLIC_URL"],
        "telemetry" => &[
            "TELEMETRY_PORT",
            "TELEMETRY_INGRESS_PUBLIC_URL",
            "TELEMETRY_READ_PUBLIC_URL",
        ],
        "radio-control" => &["RADIO_CONTROL_PORT", "RADIO_CONTROL_PUBLIC_URL"],
        "radio-saf" => &["RADIO_SAF_PORT", "RADIO_ARCHIVE_HOST_PATH", "RADIO_SAF_ENABLED"],
        "observability" => &["PROMETHEUS_PORT", "GRAFANA_PORT", "METRICS_PUBLIC_URL"],
        "radio-turn" => &[
            "TURN_REALM",
            "TURN_EXTERNAL_IP",
            "TURN_URLS",
            "TURN_PORT",
            "TURN_TLS_PORT",
            "TURN_MIN_PORT",
            "TURN_MAX_PORT",
        ],
        "radio-livekit" => &[
            "LIVEKIT_NODE_IP",
            "LIVEKIT_PUBLIC_URL",
            "LIVEKIT_HTTP_PORT",
            "LIVEKIT_RTC_TCP_PORT",
            "LIVEKIT_UDP_MIN_PORT",
            "LIVEKIT_UDP_MAX_PORT",
            "RADIO_LIVEKIT_ENABLED",
        ],
        "connectivity" => &[
            "CONNECTIVITY_EDGE_CONTROL_URL",
            "CONNECTIVITY_NODE_ROLE",
            "CONNECTIVITY_NODE_PRIORITY",
            "CONNECTIVITY_PULL_LIMIT",
            "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED",
            "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED",
            "CONNECTIVITY_FALLBACK_ORDER",
        ],
        _ => &[],
    }
}

pub fn profile_port_keys(profile: &str) -> &'static [&'static str] {
    match profile {
        "site-core" => &["SITE_CORE_PORT"],
        "telemetry" => &["TELEMETRY_PORT"],
        "radio-control" => &["RADIO_CONTROL_PORT"],
        "radio-saf" => &["RADIO_SAF_PORT"],
        "observability" => &["PROMETHEUS_PORT", "GRAFANA_PORT"],
        "radio-turn" => &["TURN_PORT", "TURN_TLS_PORT", "TURN_MIN_PORT", "TURN_MAX_PORT"],
        "radio-livekit" => &[
            "LIVEKIT_HTTP_PORT",
            "LIVEKIT_RTC_TCP_PORT",
            "LIVEKIT_UDP_MIN_PORT",
            "LIVEKIT_UDP_MAX_PORT",
        ],
        _ => &[],
    }
}

pub fn active_env_keys(profiles: &[String]) -> BTreeSet<&'static str> {
    let effective = effective_profiles(profiles);
    let mut keys = BTreeSet::from(COMMON_ENV_KEYS);
    for profile in effective {
        for key in profile_env_keys(&profile) {
            keys.insert(*key);
        }
    }
    keys
}

pub fn active_port_keys(profiles: &[String]) -> BTreeSet<&'static str> {
    let effective = effective_profiles(profiles);
    let mut keys = BTreeSet::new();
    for profile in effective {
        for key in profile_port_keys(&profile) {
            keys.insert(*key);
        }
    }
    keys
}

pub fn key_is_authoritative(profiles: &[String], key: &str) -> bool {
    COMMON_ENV_KEYS.contains(&key) || active_env_keys(profiles).contains(key)
}

pub fn assert_resume_profiles(
    leftover_profiles: &[String],
    requested_profiles: &[String],
    authorized_profiles: &[String],
) -> Result<BTreeSet<String>, String> {
    let leftover = effective_profiles(leftover_profiles);
    let requested = effective_profiles(requested_profiles);
    let authorized = effective_profiles(authorized_profiles);
    for profile in &leftover {
        if !requested.contains(profile) {
            return Err(format!(
                "RESUME_PROFILE_DRIFT: el leftover exige {profile} y el retry no puede quitarlo."
            ));
        }
    }
    for profile in &requested {
        if leftover.contains(profile) {
            continue;
        }
        if !authorized.contains(profile) {
            return Err(format!(
                "RESUME_PROFILE_UNAUTHORIZED: {profile} no esta en el leftover ni autorizado por el .adpe."
            ));
        }
    }
    Ok(requested)
}

pub fn assert_resume_identity(
    leftover: &BTreeMap<String, String>,
    requested: &BTreeMap<String, String>,
) -> Result<(), String> {
    for key in RESUME_IMMUTABLE_ENV_KEYS {
        let left = leftover.get(key).map(String::as_str).unwrap_or("").trim();
        let right = requested.get(key).map(String::as_str).unwrap_or("").trim();
        if left.is_empty() {
            continue;
        }
        if right != left {
            return Err(format!(
                "RESUME_IDENTITY_MISMATCH: {key} leftover={left} request={right}."
            ));
        }
    }
    Ok(())
}

pub fn preserve_leftover_network(
    leftover: &BTreeMap<String, String>,
    requested: &mut BTreeMap<String, String>,
) {
    for key in COMMON_ENV_KEYS {
        if let Some(value) = leftover.get(key) {
            if !value.trim().is_empty() {
                requested.insert((*key).to_string(), value.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_core_puro_no_expone_turn_ni_telemetry() {
        let keys = active_env_keys(&["site-core".into()]);
        assert!(keys.contains("SITE_CORE_PORT"));
        assert!(!keys.contains("TURN_PORT"));
        assert!(!keys.contains("TELEMETRY_PORT"));
        assert!(!keys.contains("LIVEKIT_HTTP_PORT"));
        assert!(!keys.contains("CONNECTIVITY_EDGE_CONTROL_URL"));
        assert!(!keys.contains("PROMETHEUS_PORT"));
        let ports = active_port_keys(&["site-core".into()]);
        assert_eq!(ports, BTreeSet::from(["SITE_CORE_PORT"]));
    }

    #[test]
    fn connectivity_cierra_sobre_telemetry() {
        let effective = effective_profiles(&["connectivity".into()]);
        assert!(effective.contains("connectivity"));
        assert!(effective.contains("telemetry"));
        let ports = active_port_keys(&["connectivity".into()]);
        assert!(ports.contains("TELEMETRY_PORT"));
        assert!(!ports.contains("SITE_CORE_PORT"));
    }

    #[test]
    fn livekit_incluye_su_cierre_de_puertos() {
        let ports = active_port_keys(&["radio-livekit".into()]);
        assert!(ports.contains("LIVEKIT_HTTP_PORT"));
        assert!(ports.contains("LIVEKIT_UDP_MAX_PORT"));
        assert!(!ports.contains("TURN_PORT"));
    }

    #[test]
    fn resume_no_puede_quitar_perfiles() {
        let error = assert_resume_profiles(
            &["site-core".into(), "telemetry".into()],
            &["site-core".into()],
            &["site-core".into(), "telemetry".into()],
        )
        .unwrap_err();
        assert!(error.contains("RESUME_PROFILE_DRIFT"));
    }

    #[test]
    fn resume_permite_ampliacion_autorizada() {
        let profiles = assert_resume_profiles(
            &["site-core".into()],
            &["site-core".into(), "observability".into()],
            &["site-core".into(), "observability".into()],
        )
        .unwrap();
        assert!(profiles.contains("observability"));
    }

    #[test]
    fn resume_identidad_falla_cerrado() {
        let leftover = BTreeMap::from([
            ("ACTIUM_HOST_INSTALLATION_ID".into(), "e0864698-6978-4481-bfb2-76df5d9032bf".into()),
            ("ACTIUM_DEPLOYMENT_ID".into(), "7e207490-88fd-4e31-9684-d247475215ab".into()),
            ("ACTIUM_PROJECT_NAME".into(), "actium-lab-node-01".into()),
        ]);
        let mut requested = leftover.clone();
        requested.insert(
            "ACTIUM_HOST_INSTALLATION_ID".into(),
            "00000000-0000-0000-0000-000000000000".into(),
        );
        let error = assert_resume_identity(&leftover, &requested).unwrap_err();
        assert!(error.contains("RESUME_IDENTITY_MISMATCH"));
    }

    #[test]
    fn installer_min_version_historica() {
        assert_eq!(
            installer_min_version_for_profiles(&["site-core".into()]),
            "0.3.0"
        );
        assert_eq!(
            installer_min_version_for_profiles(&["connectivity".into()]),
            "0.4.0"
        );
    }
}
