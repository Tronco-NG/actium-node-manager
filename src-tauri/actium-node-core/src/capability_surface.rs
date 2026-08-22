use std::collections::{BTreeMap, BTreeSet};

pub const KNOWN_PROFILES: [&str; 10] = [
    "site-core",
    "telemetry",
    "people",
    "control",
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

pub const IDENTITY_ENV_KEYS: [&str; 10] = [
    "ACTIUM_NODE_INSTALLATION_ID",
    "ACTIUM_DEPLOYMENT_ID",
    "ACTIUM_DEPLOYMENT_CODE",
    "ACTIUM_PROJECT_NAME",
    "ACTIUM_DATA_PLANE_PROJECT",
    "ACTIUM_CLIENT_ID",
    "ACTIUM_ORGANIZATION_ID",
    "ACTIUM_SITE_ID",
    "ACTIUM_SITE_CODE",
    "ACTIUM_MANAGER_CHANNEL",
];

pub const RESUME_IMMUTABLE_ENV_KEYS: [&str; 9] = [
    "ACTIUM_NODE_INSTALLATION_ID",
    "ACTIUM_DEPLOYMENT_ID",
    "ACTIUM_DEPLOYMENT_CODE",
    "ACTIUM_PROJECT_NAME",
    "ACTIUM_DATA_PLANE_PROJECT",
    "ACTIUM_CLIENT_ID",
    "ACTIUM_ORGANIZATION_ID",
    "ACTIUM_SITE_ID",
    "ACTIUM_SITE_CODE",
];

/// Keys that first-install/resume must (re)materialize even if they are not
/// profile-scoped configuration. HostIdentity is injected by Supervisor.
pub const SYSTEM_INSTALL_ENV_KEYS: [&str; 14] = [
    "ACTIUM_CONTROL_ENDPOINT",
    "ACTIUM_ENROLLMENT_TOKEN",
    "ACTIUM_INSTALLER_VERSION",
    "ACTIUM_SITE_CORE_DEPLOYMENT_ID",
    "ACTIUM_SITE_CORE_ENDPOINT",
    "ACTIUM_TERMINAL_PUBLIC_KEY_PATH",
    "ACTIUM_OPERATOR_PUBLIC_KEY_PATH",
    "SITE_RUNTIME_BUNDLE_PUBLIC_KEY_PATH",
    "ACTIUM_TERMINAL_ISSUER",
    "ACTIUM_OPERATOR_ISSUER",
    "SITE_RUNTIME_EXPECTED_ISSUER",
    "SITE_RUNTIME_SCHEMA_VERSION",
    "ACTIUM_PROFILES",
    "ACTIUM_REQUIRED_RUNTIME_FEATURES",
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
        "people" => &["PEOPLE_PORT", "PEOPLE_RESOLVE_PUBLIC_URL"],
        "control" => &[
            "CONTROL_RUNTIME_PORT",
            "CONTROL_RUNTIME_PUBLIC_URL",
            "CONTROL_OBJECT_STORAGE_PORT",
            "CONTROL_OBJECT_STORAGE_PUBLIC_URL",
        ],
        "radio-control" => &["RADIO_CONTROL_PORT", "RADIO_CONTROL_PUBLIC_URL"],
        "radio-saf" => &[
            "RADIO_SAF_PORT",
            "RADIO_ARCHIVE_HOST_PATH",
            "RADIO_SAF_ENABLED",
        ],
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
            "CONNECTIVITY_SYNC_ENABLED",
            "CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED",
            "CONNECTIVITY_SUPABASE_FALLBACK_ENABLED",
            "CONNECTIVITY_FALLBACK_ORDER",
            "CONNECTIVITY_PREFERRED_TRANSPORT",
            "CONNECTIVITY_ALLOWED_TRANSPORTS",
            "CONNECTIVITY_GATEWAY_STRATEGY",
            "CONNECTIVITY_ROAMING_ALLOWED",
        ],
        _ => &[],
    }
}

pub fn profile_port_keys(profile: &str) -> &'static [&'static str] {
    match profile {
        "site-core" => &["SITE_CORE_PORT"],
        "telemetry" => &["TELEMETRY_PORT"],
        "people" => &["PEOPLE_PORT"],
        "control" => &["CONTROL_RUNTIME_PORT", "CONTROL_OBJECT_STORAGE_PORT"],
        "radio-control" => &["RADIO_CONTROL_PORT"],
        "radio-saf" => &["RADIO_SAF_PORT"],
        "observability" => &["PROMETHEUS_PORT", "GRAFANA_PORT"],
        "radio-turn" => &[
            "TURN_PORT",
            "TURN_TLS_PORT",
            "TURN_MIN_PORT",
            "TURN_MAX_PORT",
        ],
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

pub fn key_is_install_material(profiles: &[String], key: &str) -> bool {
    IDENTITY_ENV_KEYS.contains(&key)
        || SYSTEM_INSTALL_ENV_KEYS.contains(&key)
        || key_is_authoritative(profiles, key)
}

pub fn merge_resume_env(
    leftover: &BTreeMap<String, String>,
    generated: &BTreeMap<String, String>,
    profiles: &[String],
    preserve_network: bool,
) -> Result<BTreeMap<String, String>, String> {
    assert_resume_identity(leftover, generated)?;
    let mut values = leftover.clone();
    for (key, value) in generated {
        if crate::HOST_IDENTITY_ENV_KEYS.contains(&key.as_str()) {
            continue;
        }
        if key_is_install_material(profiles, key) {
            values.insert(key.clone(), value.clone());
        }
    }
    if preserve_network {
        preserve_leftover_network(leftover, &mut values);
    }
    Ok(values)
}

pub fn parse_profile_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn sanitize_inactive_env(
    profiles: &[String],
    values: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let active = active_env_keys(profiles);
    values
        .iter()
        .filter(|(key, _)| {
            crate::HOST_IDENTITY_ENV_KEYS.contains(&key.as_str())
                || IDENTITY_ENV_KEYS.contains(&key.as_str())
                || SYSTEM_INSTALL_ENV_KEYS.contains(&key.as_str())
                || active.contains(key.as_str())
                || key.starts_with("ACTIUM_FABRIC_")
                || key.starts_with("ACTIUM_DEPLOYMENT_NETWORK")
                || key.starts_with("ACTIUM_RUNTIME_")
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

pub fn validate_active_configuration(
    profiles: &[String],
    values: &BTreeMap<String, String>,
) -> Result<(), String> {
    let effective = effective_profiles(profiles);
    let get = |key: &str| values.get(key).map(String::as_str).unwrap_or("").trim();
    if effective.iter().any(|profile| profile == "radio-turn") {
        if get("TURN_REALM").is_empty() {
            return Err("TURN requiere un realm o dominio publico.".to_string());
        }
        if get("TURN_URLS")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .any(|value| {
                !(value.starts_with("turn:") || value.starts_with("turns:"))
                    || value.chars().any(char::is_whitespace)
            })
        {
            return Err("Cada URL TURN debe usar turn: o turns:.".to_string());
        }
    }
    if effective.iter().any(|profile| profile == "radio-livekit") {
        if get("LIVEKIT_NODE_IP").is_empty() {
            return Err("LiveKit requiere la IP anunciada del nodo.".to_string());
        }
        if !get("LIVEKIT_PUBLIC_URL").starts_with("wss://") {
            return Err("La URL publica de LiveKit debe usar wss://.".to_string());
        }
    }
    if effective.iter().any(|profile| profile == "connectivity") {
        if !get("CONNECTIVITY_EDGE_CONTROL_URL").starts_with("https://") {
            return Err("Connectivity Edge requiere una URL de control https://.".to_string());
        }
    }
    Ok(())
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
    fn people_es_independiente_de_site_core_y_connectivity() {
        let effective = effective_profiles(&["people".into()]);
        assert_eq!(effective, BTreeSet::from(["people".to_string()]));
        assert_eq!(active_port_keys(&["people".into()]), BTreeSet::from(["PEOPLE_PORT"]));
        let keys = active_env_keys(&["people".into()]);
        assert!(keys.contains("PEOPLE_RESOLVE_PUBLIC_URL"));
        assert!(!keys.contains("SITE_CORE_PORT"));
        assert!(!keys.contains("CONNECTIVITY_EDGE_CONTROL_URL"));
    }

    #[test]
    fn control_es_independiente_de_site_core_y_nats() {
        let effective = effective_profiles(&["control".into()]);
        assert_eq!(effective, BTreeSet::from(["control".to_string()]));
        assert_eq!(
            active_port_keys(&["control".into()]),
            BTreeSet::from([
                "CONTROL_OBJECT_STORAGE_PORT",
                "CONTROL_RUNTIME_PORT",
            ])
        );
        let keys = active_env_keys(&["control".into()]);
        assert!(keys.contains("CONTROL_RUNTIME_PUBLIC_URL"));
        assert!(keys.contains("CONTROL_OBJECT_STORAGE_PUBLIC_URL"));
        assert!(!keys.contains("SITE_CORE_PORT"));
        assert!(!keys.contains("CONNECTIVITY_EDGE_CONTROL_URL"));
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
            (
                "ACTIUM_NODE_INSTALLATION_ID".into(),
                "e0864698-6978-4481-bfb2-76df5d9032bf".into(),
            ),
            (
                "ACTIUM_DEPLOYMENT_ID".into(),
                "7e207490-88fd-4e31-9684-d247475215ab".into(),
            ),
            ("ACTIUM_PROJECT_NAME".into(), "actium-lab-node-01".into()),
        ]);
        let mut requested = leftover.clone();
        requested.insert(
            "ACTIUM_NODE_INSTALLATION_ID".into(),
            "00000000-0000-0000-0000-000000000000".into(),
        );
        let error = assert_resume_identity(&leftover, &requested).unwrap_err();
        assert!(error.contains("RESUME_IDENTITY_MISMATCH"));
    }

    #[test]
    fn site_core_ignora_turn_legado_invalido() {
        let env = BTreeMap::from([
            ("ACTIUM_PROFILES".into(), "site-core".into()),
            ("SITE_CORE_PORT".into(), "18088".into()),
            ("TURN_URLS".into(), "not-a-turn-url".into()),
            ("LIVEKIT_PUBLIC_URL".into(), "http://invalid".into()),
        ]);
        validate_active_configuration(&["site-core".into()], &env).unwrap();
        let error = validate_active_configuration(&["radio-turn".into()], &env).unwrap_err();
        assert!(error.contains("TURN"), "{error}");
    }

    #[test]
    fn merge_resume_no_pisa_host_identity_del_supervisor() {
        let leftover = BTreeMap::from([
            ("ACTIUM_NODE_INSTALLATION_ID".into(), "node-1".into()),
            ("ACTIUM_HOST_INSTALLATION_ID".into(), "host-1".into()),
            ("ACTIUM_HOST_CODE".into(), "actium-host-aabbccdd".into()),
            ("ACTIUM_DEPLOYMENT_ID".into(), "deploy-1".into()),
            ("ACTIUM_PROJECT_NAME".into(), "actium-lab-node-01".into()),
            ("SITE_CORE_PORT".into(), "18088".into()),
        ]);
        let generated = BTreeMap::from([
            ("ACTIUM_NODE_INSTALLATION_ID".into(), "node-1".into()),
            ("ACTIUM_HOST_INSTALLATION_ID".into(), "node-1".into()),
            ("ACTIUM_HOST_CODE".into(), "actium-lab-node-01".into()),
            ("ACTIUM_DEPLOYMENT_ID".into(), "deploy-1".into()),
            ("ACTIUM_PROJECT_NAME".into(), "actium-lab-node-01".into()),
            ("SITE_CORE_PORT".into(), "18088".into()),
        ]);
        let merged = merge_resume_env(&leftover, &generated, &["site-core".into()], true).unwrap();
        assert_eq!(merged.get("ACTIUM_HOST_INSTALLATION_ID").unwrap(), "host-1");
        assert_eq!(
            merged.get("ACTIUM_HOST_CODE").unwrap(),
            "actium-host-aabbccdd"
        );
        assert_eq!(merged.get("ACTIUM_NODE_INSTALLATION_ID").unwrap(), "node-1");
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

    #[test]
    fn capability_matrix_no_expone_claves_ajenas() {
        let cases: &[(&[&str], &[&str], &[&str])] = &[
            (
                &["site-core"],
                &["SITE_CORE_PORT"],
                &[
                    "TURN_PORT",
                    "TELEMETRY_PORT",
                    "LIVEKIT_HTTP_PORT",
                    "PROMETHEUS_PORT",
                    "CONNECTIVITY_EDGE_CONTROL_URL",
                ],
            ),
            (
                &["telemetry"],
                &["TELEMETRY_PORT"],
                &["TURN_PORT", "SITE_CORE_PORT", "LIVEKIT_HTTP_PORT"],
            ),
            (
                &["people"],
                &["PEOPLE_PORT", "PEOPLE_RESOLVE_PUBLIC_URL"],
                &["SITE_CORE_PORT", "TELEMETRY_PORT", "CONNECTIVITY_EDGE_CONTROL_URL"],
            ),
            (
                &["control"],
                &[
                    "CONTROL_OBJECT_STORAGE_PORT",
                    "CONTROL_OBJECT_STORAGE_PUBLIC_URL",
                    "CONTROL_RUNTIME_PORT",
                    "CONTROL_RUNTIME_PUBLIC_URL",
                ],
                &["SITE_CORE_PORT", "TELEMETRY_PORT", "PEOPLE_PORT"],
            ),
            (
                &["radio-control"],
                &["RADIO_CONTROL_PORT"],
                &["TURN_PORT", "TELEMETRY_PORT"],
            ),
            (
                &["radio-saf"],
                &["RADIO_SAF_PORT", "RADIO_ARCHIVE_HOST_PATH"],
                &["TURN_PORT", "LIVEKIT_HTTP_PORT"],
            ),
            (
                &["radio-turn"],
                &["TURN_PORT", "TURN_URLS"],
                &["LIVEKIT_HTTP_PORT", "TELEMETRY_PORT"],
            ),
            (
                &["radio-livekit"],
                &["LIVEKIT_HTTP_PORT", "LIVEKIT_UDP_MAX_PORT"],
                &["TURN_PORT"],
            ),
            (
                &["observability"],
                &["PROMETHEUS_PORT", "GRAFANA_PORT"],
                &["TURN_PORT", "TELEMETRY_PORT"],
            ),
            (
                &["connectivity"],
                &["CONNECTIVITY_EDGE_CONTROL_URL", "TELEMETRY_PORT"],
                &["TURN_PORT", "SITE_CORE_PORT"],
            ),
            (
                &["site-core", "telemetry"],
                &["SITE_CORE_PORT", "TELEMETRY_PORT"],
                &["TURN_PORT", "LIVEKIT_HTTP_PORT"],
            ),
        ];
        for (selected, present, absent) in cases {
            let profiles = selected
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>();
            let keys = active_env_keys(&profiles);
            for key in *present {
                assert!(keys.contains(key), "{selected:?} debe exponer {key}");
            }
            for key in *absent {
                assert!(!keys.contains(key), "{selected:?} no debe exponer {key}");
            }
        }
    }

    #[test]
    fn resume_conserva_claves_inactivas_del_leftover() {
        let leftover = BTreeMap::from([
            (
                "ACTIUM_HOST_INSTALLATION_ID".into(),
                "e0864698-6978-4481-bfb2-76df5d9032bf".into(),
            ),
            (
                "ACTIUM_DEPLOYMENT_ID".into(),
                "7e207490-88fd-4e31-9684-d247475215ab".into(),
            ),
            ("ACTIUM_PROFILES".into(), "site-core".into()),
            ("SITE_CORE_PORT".into(), "18088".into()),
            ("TURN_PORT".into(), "13478".into()),
            ("DATA_PLANE_BIND_ADDRESS".into(), "10.0.0.8".into()),
        ]);
        let generated = BTreeMap::from([
            (
                "ACTIUM_HOST_INSTALLATION_ID".into(),
                "e0864698-6978-4481-bfb2-76df5d9032bf".into(),
            ),
            (
                "ACTIUM_DEPLOYMENT_ID".into(),
                "7e207490-88fd-4e31-9684-d247475215ab".into(),
            ),
            ("ACTIUM_PROFILES".into(), "site-core".into()),
            ("SITE_CORE_PORT".into(), "18099".into()),
            ("TURN_PORT".into(), "19999".into()),
            ("DATA_PLANE_BIND_ADDRESS".into(), "127.0.0.1".into()),
        ]);
        let merged = merge_resume_env(&leftover, &generated, &["site-core".into()], true).unwrap();
        assert_eq!(
            merged.get("SITE_CORE_PORT").map(String::as_str),
            Some("18099")
        );
        assert_eq!(merged.get("TURN_PORT").map(String::as_str), Some("13478"));
        assert_eq!(
            merged.get("DATA_PLANE_BIND_ADDRESS").map(String::as_str),
            Some("10.0.0.8")
        );
    }
}
