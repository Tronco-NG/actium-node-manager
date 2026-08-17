#[cfg(not(unix))]
fn main() {
    eprintln!("Este gate requiere un host Unix.");
    std::process::exit(2);
}

#[cfg(unix)]
fn main() {
    if let Err(error) = run() {
        eprintln!("PACKAGED_COMMISSIONING_REJECTED: {error}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    use actium_node_core::{CommissionNodeRequest, FabricIdentity, RuntimeOperator};
    use serde_json::json;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
    use uuid::Uuid;

    let payload_root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| "Uso: verify-packaged-commissioning <payload-empaquetado>".to_string())?;
    let manifest = actium_node_core::verify_payload(&payload_root)?;
    let release_version = manifest.version().to_string();
    let test_root =
        std::env::temp_dir().join(format!("actium-packaged-commissioning-{}", Uuid::new_v4()));
    let nodes_root = test_root.join("nodes");
    let fabrics_root = test_root.join("fabrics");
    fs::create_dir_all(&nodes_root).map_err(|error| error.to_string())?;
    fs::create_dir_all(&fabrics_root).map_err(|error| error.to_string())?;

    let operator = RuntimeOperator::new_with_fabric(
        &nodes_root,
        &fabrics_root,
        &payload_root,
        FabricIdentity {
            fabric_id: "11111111-1111-4111-8111-111111111111".to_string(),
            compose_project: "actium-lab-p0-gate-fabric".to_string(),
            network_name: "actium-lab-p0-gate-fabric".to_string(),
            host_id: None,
        },
        test_root.join("state/fabric-identity.json"),
    );

    let result = (|| {
        let telemetry = commission(
            &operator,
            &nodes_root,
            &release_version,
            "telemetry",
            "telemetry",
        )?;
        assert_profile_contract(&telemetry, "telemetry")?;
        assert_release_modes(&telemetry)?;
        compose_config(&telemetry)?;

        let all_profiles = "site-core,telemetry,radio-control,radio-saf,radio-turn,radio-livekit,connectivity,observability";
        let all = commission(
            &operator,
            &nodes_root,
            &release_version,
            "all-units",
            all_profiles,
        )?;
        assert_profile_contract(&all, all_profiles)?;
        assert_release_modes(&all)?;
        compose_config(&all)?;

        let output = json!({
            "status": "verified",
            "releaseVersion": release_version,
            "telemetryProfiles": "telemetry",
            "allRuntimeUnits": true,
            "installFlow": "/bin/sh install-node.sh --prepare-only",
            "composeGate": "manage-node.sh config --quiet",
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
        );
        Ok(())
    })();

    restore_test_owned_storage(&nodes_root, &fabrics_root)?;
    fs::remove_dir_all(&test_root).map_err(|error| {
        format!(
            "No se pudo limpiar el directorio temporal {}: {error}",
            test_root.display()
        )
    })?;
    fn restore_test_owned_storage(
        nodes_root: &std::path::Path,
        fabrics_root: &std::path::Path,
    ) -> Result<(), String> {
        use nix::unistd::{chown, Gid, Uid};
        let recover = |path: &std::path::Path| {
            if !path.exists() {
                return Ok(());
            }
            // El gate se ejecuta con CAP_CHOWN y debe recuperar los roots
            // cedidos antes del cleanup, igual que un retry productivo, sin
            // capacidades DAC.
            chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
                .map_err(|error| format!("No se pudo recuperar root temporal: {error}"))
        };
        for node in fs::read_dir(nodes_root).map_err(|error| error.to_string())? {
            let node = node.map_err(|error| error.to_string())?.path();
            for relative in ["persistent/agent", "state/agent"] {
                recover(&node.join(relative))?;
            }
            let units = node.join("persistent/runtime-units");
            if !units.is_dir() {
                continue;
            }
            for unit in fs::read_dir(&units).map_err(|error| error.to_string())? {
                let root = unit.map_err(|error| error.to_string())?.path();
                recover(&root)?;
                for child in fs::read_dir(&root).map_err(|error| error.to_string())? {
                    recover(&child.map_err(|error| error.to_string())?.path())?;
                }
            }
        }
        for fabric in fs::read_dir(fabrics_root).map_err(|error| error.to_string())? {
            let root = fabric
                .map_err(|error| error.to_string())?
                .path()
                .join("persistent/nats");
            recover(&root)?;
        }
        Ok(())
    }
    fn commission(
        operator: &RuntimeOperator,
        nodes_root: &std::path::Path,
        release_version: &str,
        suffix: &str,
        profiles: &str,
    ) -> Result<PathBuf, String> {
        let node_root = nodes_root.join(format!("actium-lab-p0-{suffix}"));
        let deployment_id = Uuid::new_v4().to_string();
        let site_id = Uuid::new_v4().to_string();
        let path = |relative: &str| {
            node_root
                .join(relative)
                .to_string_lossy()
                .replace('\\', "/")
        };
        let node_env = format!(
            "ACTIUM_CONTROL_ENDPOINT=https://control.invalid\n\
ACTIUM_ENROLLMENT_TOKEN=\n\
ACTIUM_HOST_INSTALLATION_ID={}\n\
ACTIUM_HOST_CODE=actium-lab-p0\n\
ACTIUM_HOST_DISPLAY_NAME=Actium Lab P0\n\
ACTIUM_HOST_PLATFORM=linux\n\
ACTIUM_HOST_ARCHITECTURE=x86_64\n\
ACTIUM_INSTALLER_VERSION={}\n\
ACTIUM_DEPLOYMENT_ID={}\n\
ACTIUM_DEPLOYMENT_CODE=p0-{}\n\
ACTIUM_SITE_ID={}\n\
ACTIUM_TERMINAL_PUBLIC_KEY_PATH={}\n\
ACTIUM_OPERATOR_PUBLIC_KEY_PATH={}\n\
SITE_RUNTIME_BUNDLE_PUBLIC_KEY_PATH={}\n\
ACTIUM_TERMINAL_ISSUER=https://terminal.invalid\n\
ACTIUM_OPERATOR_ISSUER=https://operator.invalid\n\
SITE_RUNTIME_EXPECTED_ISSUER=https://site-runtime.invalid\n\
ACTIUM_PROFILES={}\n\
ACTIUM_PROJECT_NAME=actium-lab-p0-{}\n\
ACTIUM_DATA_PLANE_PROJECT=actium-lab-p0-{}\n\
ACTIUM_USE_PUBLISHED_IMAGES=true\n\
DATA_PLANE_NETWORK_MODE=local_only\n\
DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED=false\n\
DATA_PLANE_BIND_ADDRESS=127.0.0.1\n\
DATA_PLANE_PUBLIC_BASE_URL=http://127.0.0.1\n\
DATA_PLANE_CORS_ORIGINS=https://localhost\n\
TELEMETRY_PORT=28090\n\
RADIO_CONTROL_PORT=28100\n\
SITE_CORE_PORT=28088\n\
RADIO_ARCHIVE_HOST_PATH={}\n\
PROMETHEUS_PORT=29090\n\
GRAFANA_PORT=23001\n\
TURN_REALM=turn.invalid\n\
TURN_EXTERNAL_IP=127.0.0.1\n\
TURN_PORT=23478\n\
TURN_TLS_PORT=25349\n\
TURN_MIN_PORT=29160\n\
TURN_MAX_PORT=29200\n\
LIVEKIT_NODE_IP=127.0.0.1\n\
LIVEKIT_PUBLIC_URL=wss://livekit.invalid\n\
LIVEKIT_HTTP_PORT=27880\n\
LIVEKIT_RTC_TCP_PORT=27881\n\
LIVEKIT_UDP_MIN_PORT=30000\n\
LIVEKIT_UDP_MAX_PORT=30100\n\
CONNECTIVITY_EDGE_CONTROL_URL=https://connectivity.invalid\n\
CONNECTIVITY_NODE_ROLE=replica\n\
CONNECTIVITY_NODE_PRIORITY=100\n\
CONNECTIVITY_PULL_LIMIT=25\n\
CONNECTIVITY_DIRECT_DATA_PLANE_FALLBACK_ENABLED=true\n\
CONNECTIVITY_SUPABASE_FALLBACK_ENABLED=false\n\
CONNECTIVITY_FALLBACK_ORDER=direct_data_plane\n",
            Uuid::new_v4(),
            release_version,
            deployment_id,
            suffix,
            site_id,
            path("keys/actium-terminal-public.pem"),
            path("keys/actium-operator-public.pem"),
            path("keys/actium-site-runtime-bundle-public.pem"),
            profiles,
            suffix,
            suffix,
            path("persistent/radio-archive"),
        );
        let marker = json!({
            "managerChannel": "lab",
            "status": "installing",
            "releaseVersion": release_version,
        })
        .to_string();
        let public_key = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END PUBLIC KEY-----\n";
        operator.commission_node(&CommissionNodeRequest {
            install_dir: node_root.to_string_lossy().into_owned(),
            expected_release: release_version.to_string(),
            node_env,
            marker,
            terminal_public_key: public_key.to_string(),
            operator_public_key: public_key.to_string(),
            site_runtime_public_key: Some(public_key.to_string()),
            control_plane_ca_pem: None,
            connectivity_edge_enrollment_token: Some(format!("acen_{}", "a".repeat(48))),
            connectivity_internal_relay_token: Some(format!("acer_{}", "b".repeat(48))),
            enrollment_token: format!("adpe_{}", "c".repeat(64)),
            radio_archive_host_path: Some(path("persistent/radio-archive")),
            prepare_only: true,
            resume_incomplete: false,
        })?;
        Ok(node_root)
    }

    fn env_value(contents: &str, key: &str) -> Option<String> {
        contents.lines().find_map(|line| {
            line.strip_prefix(&format!("{key}="))
                .map(ToString::to_string)
        })
    }

    fn assert_profile_contract(node_root: &std::path::Path, expected: &str) -> Result<(), String> {
        let path = node_root.join("secrets/data-plane.env");
        let contents = fs::read_to_string(&path)
            .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
        let profiles = env_value(&contents, "ACTIUM_PROFILES");
        let active = env_value(&contents, "ACTIUM_ACTIVE_PROFILES");
        if profiles.as_deref() != Some(expected) || active.as_deref() != Some(expected) {
            return Err(format!(
                "Contrato de perfiles divergente: ACTIUM_PROFILES={profiles:?}, ACTIUM_ACTIVE_PROFILES={active:?}, esperado={expected}"
            ));
        }
        Ok(())
    }

    fn assert_release_modes(node_root: &std::path::Path) -> Result<(), String> {
        let state: serde_json::Value = serde_json::from_slice(
            &fs::read(node_root.join("state/active-release.json"))
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let relative = state
            .get("relativePath")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "active-release.json no contiene relativePath".to_string())?;
        for script in [
            "install-node.sh",
            "bootstrap.sh",
            "manage-node.sh",
            "verify-node.sh",
        ] {
            let path = node_root.join(relative).join(script);
            let mode = fs::metadata(&path)
                .map_err(|error| format!("No se pudo inspeccionar {}: {error}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o111 == 0 {
                return Err(format!(
                    "{} perdio su bit ejecutable durante staging",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn compose_config(node_root: &std::path::Path) -> Result<(), String> {
        let state: serde_json::Value = serde_json::from_slice(
            &fs::read(node_root.join("state/active-release.json"))
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let relative = state
            .get("relativePath")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "active-release.json no contiene relativePath".to_string())?;
        let output = Command::new("/bin/sh")
            .arg(node_root.join(relative).join("manage-node.sh"))
            .arg("config")
            .env(
                "ACTIUM_DATA_PLANE_ENV_FILE",
                node_root.join("secrets/data-plane.env"),
            )
            .current_dir(node_root.join(relative))
            .output()
            .map_err(|error| format!("No se pudo ejecutar manage-node.sh config: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "docker compose config fallo con los env reales de commissioning:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    result
}
