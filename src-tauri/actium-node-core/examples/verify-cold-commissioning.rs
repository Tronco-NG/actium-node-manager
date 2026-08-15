#[cfg(not(unix))]
fn main() {
    eprintln!("Este gate requiere Linux/WSL con Docker.");
    std::process::exit(2);
}

#[cfg(unix)]
fn main() {
    if let Err(error) = run() {
        eprintln!("COLD_COMMISSIONING_REJECTED: {error}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    use actium_node_core::{CommissionNodeRequest, FabricIdentity, RuntimeOperator};
    use serde_json::{json, Value};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::Duration,
    };
    use uuid::Uuid;

    let payload_root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            "Uso: verify-cold-commissioning <payload> <minimal|full|invalid-package>".to_string()
        })?;
    let mode = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "minimal".to_string());
    let profiles = match mode.as_str() {
        "minimal" | "invalid-package" => "site-core",
        "full" => "site-core,telemetry,radio-control",
        _ => return Err("El modo debe ser minimal, full o invalid-package.".to_string()),
    };
    let release_version = actium_node_core::verify_payload(&payload_root)?
        .version()
        .to_string();
    let test_id = Uuid::new_v4();
    let token = test_id.simple().to_string();
    let short = &token[..8];
    let test_root = std::env::temp_dir().join(format!("actium-cold-{short}"));
    let nodes_root = test_root.join("nodes");
    let fabrics_root = test_root.join("fabrics");
    let node_root = nodes_root.join(format!("actium-lab-cold-{mode}-{short}"));
    fs::create_dir_all(&nodes_root).map_err(|error| error.to_string())?;
    fs::create_dir_all(&fabrics_root).map_err(|error| error.to_string())?;
    if node_root.exists() {
        return Err("El gate exige un root de nodo inexistente.".to_string());
    }

    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/site-runtime/v1/fixtures/valid-package.json")
        .canonicalize()
        .map_err(|error| format!("Fixture Site Runtime ausente: {error}"))?;
    let fixture: Value =
        serde_json::from_slice(&fs::read(&fixture_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let expected_issuer = fixture
        .get("expected_issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| "Fixture sin expected_issuer.".to_string())?;

    let cert_path = test_root.join("control-plane.crt");
    let key_path = test_root.join("control-plane.key");
    create_test_certificate(&cert_path, &key_path)?;
    let runtime_root_private_path = test_root.join("site-runtime-root-private.pem");
    let runtime_root_public_path = test_root.join("site-runtime-root-public.pem");
    create_site_runtime_root(&runtime_root_private_path, &runtime_root_public_path)?;
    let root_public_key =
        fs::read_to_string(&runtime_root_public_path).map_err(|error| error.to_string())?;
    let deployment_id = Uuid::new_v4().to_string();
    let host_id = Uuid::new_v4().to_string();
    let port =
        20_000 + (u16::from_be_bytes([test_id.as_bytes()[0], test_id.as_bytes()[1]]) % 20_000);
    let events_path = test_root.join("control-events.jsonl");
    let ready_path = test_root.join("control-ready");
    let server_config = test_root.join("control-config.json");
    fs::write(
        &server_config,
        serde_json::to_vec_pretty(&json!({
            "deploymentId": deployment_id,
            "hostId": host_id,
            "port": port,
            "fixturePath": fixture_path,
            "certPath": cert_path,
            "keyPath": key_path,
            "rootPrivateKeyPath": runtime_root_private_path,
            "expectedIssuer": expected_issuer,
            "eventsPath": events_path,
            "readyPath": ready_path,
            "invalidPackage": mode == "invalid-package",
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let control_script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/cold-control-plane.mjs")
        .canonicalize()
        .map_err(|error| format!("Test double ausente: {error}"))?;
    let mut control = Command::new("node")
        .arg(control_script)
        .arg(&server_config)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("No se pudo iniciar Control Plane de prueba: {error}"))?;
    wait_for_file(&ready_path, Duration::from_secs(15), &mut control)?;

    let fabric_id = Uuid::new_v4().to_string();
    let fabric_project = format!("actium-lab-cold-{short}-fabric");
    let operator = RuntimeOperator::new_with_fabric(
        &nodes_root,
        &fabrics_root,
        &payload_root,
        FabricIdentity {
            fabric_id: fabric_id.clone(),
            compose_project: fabric_project.clone(),
            network_name: fabric_project.clone(),
            host_id: None,
        },
        test_root.join("state/fabric-identity.json"),
    );
    let path = |relative: &str| {
        node_root
            .join(relative)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let node_env = format!(
        "ACTIUM_CONTROL_ENDPOINT=https://host.docker.internal:{port}\n\
ACTIUM_HOST_INSTALLATION_ID={}\n\
ACTIUM_HOST_CODE=actium-lab-cold-{short}\n\
ACTIUM_HOST_DISPLAY_NAME=Actium Cold {mode}\n\
ACTIUM_HOST_PLATFORM=linux\n\
ACTIUM_HOST_ARCHITECTURE=x86_64\n\
ACTIUM_INSTALLER_VERSION={release_version}\n\
ACTIUM_DEPLOYMENT_ID={deployment_id}\n\
ACTIUM_DEPLOYMENT_CODE=cold-{mode}-{short}\n\
ACTIUM_SITE_ID=33333333-3333-4333-8333-333333333333\n\
ACTIUM_TERMINAL_PUBLIC_KEY_PATH={}\n\
ACTIUM_OPERATOR_PUBLIC_KEY_PATH={}\n\
SITE_RUNTIME_BUNDLE_PUBLIC_KEY_PATH={}\n\
ACTIUM_TERMINAL_ISSUER=https://terminal.fixture.invalid\n\
ACTIUM_OPERATOR_ISSUER=https://operator.fixture.invalid\n\
SITE_RUNTIME_EXPECTED_ISSUER={expected_issuer}\n\
ACTIUM_PROFILES={profiles}\n\
ACTIUM_PROJECT_NAME=actium-lab-cold-{mode}-{short}\n\
ACTIUM_DATA_PLANE_PROJECT=actium-lab-cold-{mode}-{short}\n\
ACTIUM_USE_PUBLISHED_IMAGES=false\n\
DATA_PLANE_NETWORK_MODE=local_only\n\
DATA_PLANE_NETWORK_CONFIGURATION_DEFERRED=false\n\
DATA_PLANE_BIND_ADDRESS=127.0.0.1\n\
DATA_PLANE_PUBLIC_BASE_URL=http://127.0.0.1\n\
DATA_PLANE_CORS_ORIGINS=https://localhost\n\
GPS_STREAM_MAX_BYTES=16777216\n\
HEARTBEAT_STREAM_MAX_BYTES=8388608\n\
TELEMETRY_PORT={}\n\
RADIO_CONTROL_PORT={}\n\
SITE_CORE_PORT={}\n\
RADIO_ARCHIVE_HOST_PATH={}\n\
RADIO_SAF_ENABLED={}\n",
        Uuid::new_v4(),
        path("keys/actium-terminal-public.pem"),
        path("keys/actium-operator-public.pem"),
        path("keys/actium-site-runtime-bundle-public.pem"),
        port + 1,
        port + 2,
        port + 3,
        path("persistent/radio-archive"),
        mode == "full",
    );
    let request = CommissionNodeRequest {
        install_dir: node_root.to_string_lossy().into_owned(),
        expected_release: release_version.clone(),
        node_env,
        marker: json!({
            "managerChannel": "lab",
            "status": "installing",
            "releaseVersion": release_version,
        })
        .to_string(),
        terminal_public_key: format!("{root_public_key}\n"),
        operator_public_key: format!("{root_public_key}\n"),
        site_runtime_public_key: Some(format!("{root_public_key}\n")),
        control_plane_ca_pem: Some(
            fs::read_to_string(&cert_path).map_err(|error| error.to_string())?,
        ),
        connectivity_edge_enrollment_token: None,
        connectivity_internal_relay_token: None,
        enrollment_token: format!("adpe_{}", "c".repeat(64)),
        radio_archive_host_path: (mode == "full").then(|| path("persistent/radio-archive")),
        prepare_only: false,
    };

    let result = operator.commission_node(&request);
    let evidence = match result {
        Ok(result) if mode != "invalid-package" => {
            let inventory = operator.runtime_unit_inventory(&node_root)?;
            if inventory.units.iter().any(|unit| unit.state != "ready") {
                return finish_with_error(
                    &mut control,
                    &operator,
                    &node_root,
                    &fabric_project,
                    &fabric_id,
                    &test_root,
                    format!("Health global incompleto: {:?}", inventory.units),
                );
            }
            let lifecycle: Value = serde_json::from_slice(
                &fs::read(node_root.join("state/node-runtime/agent-lifecycle.json"))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            assert_ordered_lifecycle(&lifecycle)?;
            assert_output_order(&result.output)?;
            let release_state: Value = serde_json::from_slice(
                &fs::read(node_root.join("state/release-state.json"))
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            if release_state.get("promotionStatus").and_then(Value::as_str) != Some("active") {
                return Err("El commissioning exitoso no dejo una release active.".to_string());
            }
            json!({
                "status": "pass",
                "mode": mode,
                "coldRoot": true,
                "fabric": "ready",
                "profiles": profiles,
                "sequence": result.output.lines().filter(|line| line.contains("agent_") || line.contains("site_core_") || line.contains("site_runtime_") || line.contains("runtime_ready:")).collect::<Vec<_>>(),
                "globalHealth": inventory.units.iter().map(|unit| json!({ "capability": unit.capability, "state": unit.state })).collect::<Vec<_>>(),
                "lifecycle": lifecycle,
                "controlEvents": fs::read_to_string(&events_path).unwrap_or_default().lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()).collect::<Vec<_>>(),
            })
        }
        Ok(_) => {
            return finish_with_error(
                &mut control,
                &operator,
                &node_root,
                &fabric_project,
                &fabric_id,
                &test_root,
                "El package invalido fue aceptado durante commissioning.".to_string(),
            )
        }
        Err(error) if mode == "invalid-package" => {
            let release_state: Value = serde_json::from_slice(
                &fs::read(node_root.join("state/release-state.json"))
                    .map_err(|read_error| read_error.to_string())?,
            )
            .map_err(|parse_error| parse_error.to_string())?;
            let marker: Value = serde_json::from_slice(
                &fs::read(node_root.join(".actium-node-installation.json"))
                    .map_err(|read_error| read_error.to_string())?,
            )
            .map_err(|parse_error| parse_error.to_string())?;
            if !release_state
                .get("activeRelease")
                .is_none_or(Value::is_null)
                || release_state
                    .get("lastFailedRelease")
                    .is_none_or(Value::is_null)
                || release_state.get("promotionStatus").and_then(Value::as_str) != Some("failed")
                || marker.get("status").and_then(Value::as_str) != Some("failed")
                || !node_root.join("persistent").is_dir()
            {
                return finish_with_error(
                    &mut control,
                    &operator,
                    &node_root,
                    &fabric_project,
                    &fabric_id,
                    &test_root,
                    format!("Rollback inicial inconsistente: {release_state}"),
                );
            }
            let evidence = json!({
                "status": "pass",
                "mode": mode,
                "failure": error,
                "activeRelease": null,
                "lastFailedReleasePreserved": true,
                "persistentRootPreserved": true,
                "commissioningCompleted": false,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&evidence)
                    .map_err(|serialize_error| serialize_error.to_string())?
            );
            cleanup(
                &mut control,
                &operator,
                &node_root,
                &fabric_project,
                &fabric_id,
                &test_root,
            );
            return Ok(());
        }
        Err(error) => {
            return finish_with_error(
                &mut control,
                &operator,
                &node_root,
                &fabric_project,
                &fabric_id,
                &test_root,
                error,
            )
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&evidence).map_err(|error| error.to_string())?
    );
    cleanup(
        &mut control,
        &operator,
        &node_root,
        &fabric_project,
        &fabric_id,
        &test_root,
    );
    Ok(())
}

#[cfg(unix)]
fn create_test_certificate(cert: &std::path::Path, key: &std::path::Path) -> Result<(), String> {
    let status = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=host.docker.internal",
            "-addext",
            "subjectAltName=DNS:host.docker.internal",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-keyout",
        ])
        .arg(key)
        .arg("-out")
        .arg(cert)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("OpenSSL no disponible: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("OpenSSL no pudo crear el certificado efimero.".to_string())
    }
}

#[cfg(unix)]
fn create_site_runtime_root(
    private_key: &std::path::Path,
    public_key: &std::path::Path,
) -> Result<(), String> {
    let private_status = std::process::Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(private_key)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("OpenSSL no disponible: {error}"))?;
    let public_status = std::process::Command::new("openssl")
        .args(["pkey", "-pubout", "-in"])
        .arg(private_key)
        .arg("-out")
        .arg(public_key)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| format!("OpenSSL no disponible: {error}"))?;
    if private_status.success() && public_status.success() {
        Ok(())
    } else {
        Err("OpenSSL no pudo crear la autoridad Site Runtime efimera.".to_string())
    }
}

#[cfg(unix)]
fn wait_for_file(
    path: &std::path::Path,
    timeout: std::time::Duration,
    child: &mut std::process::Child,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    while started.elapsed() < timeout {
        if path.is_file() {
            return Ok(());
        }
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("Control Plane de prueba termino antes de escuchar.".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("Control Plane de prueba no inicio a tiempo.".to_string())
}

#[cfg(unix)]
fn assert_ordered_lifecycle(value: &serde_json::Value) -> Result<(), String> {
    let events = value
        .get("events")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Lifecycle sin events.".to_string())?;
    let states = events
        .iter()
        .filter_map(|event| event.get("state").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();
    let expected = [
        "starting",
        "enrolled",
        "host_reconciled",
        "runtime_sync_pending",
        "runtime_synced",
        "site_core_ready",
        "reporting",
    ];
    let mut cursor = 0;
    for state in &states {
        if cursor < expected.len() && *state == expected[cursor] {
            cursor += 1;
        }
    }
    if cursor == expected.len() {
        Ok(())
    } else {
        Err(format!("Lifecycle fuera de orden: {states:?}"))
    }
}

#[cfg(unix)]
fn assert_output_order(output: &str) -> Result<(), String> {
    let expected = [
        "site_core_alive",
        "agent_started",
        "agent_enrolled",
        "agent_host_reconciled",
        "site_runtime_synced",
        "site_core_ready",
        "agent_reporting",
    ];
    let mut offset = 0;
    for event in expected {
        let index = output[offset..]
            .find(event)
            .ok_or_else(|| format!("Falta evento bootstrap {event}."))?
            + offset;
        offset = index + event.len();
    }
    Ok(())
}

#[cfg(unix)]
fn finish_with_error<T>(
    control: &mut std::process::Child,
    operator: &actium_node_core::RuntimeOperator,
    node_root: &std::path::Path,
    fabric_project: &str,
    fabric_id: &str,
    test_root: &std::path::Path,
    error: String,
) -> Result<T, String> {
    cleanup(
        control,
        operator,
        node_root,
        fabric_project,
        fabric_id,
        test_root,
    );
    Err(error)
}

#[cfg(unix)]
fn cleanup(
    control: &mut std::process::Child,
    operator: &actium_node_core::RuntimeOperator,
    node_root: &std::path::Path,
    fabric_project: &str,
    fabric_id: &str,
    test_root: &std::path::Path,
) {
    if std::env::var("ACTIUM_E2E_KEEP_FAILED").ok().as_deref() == Some("true") {
        eprintln!("E2E_PRESERVED_ROOT={}", test_root.display());
        let _ = control.kill();
        let _ = control.wait();
        return;
    }
    let deployment_network = std::fs::read(node_root.join("state/runtime-topology.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|topology| {
            topology
                .get("deploymentNetworkName")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
    let _ = operator.execute(node_root, "stop", None);
    if let Ok(ids) = std::process::Command::new("docker")
        .args([
            "ps",
            "-aq",
            "--filter",
            &format!("label=com.docker.compose.project={fabric_project}"),
        ])
        .output()
    {
        for id in String::from_utf8_lossy(&ids.stdout).split_whitespace() {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", id])
                .status();
        }
    }
    let _ = std::process::Command::new("docker")
        .args(["network", "rm", fabric_project])
        .status();
    if let Some(network) = deployment_network {
        let _ = std::process::Command::new("docker")
            .args(["network", "rm", &network])
            .status();
    }
    if let Ok(networks) = std::process::Command::new("docker")
        .args([
            "network",
            "ls",
            "-q",
            "--filter",
            &format!("label=com.actium.fabric-id={fabric_id}"),
        ])
        .output()
    {
        for network in String::from_utf8_lossy(&networks.stdout).split_whitespace() {
            let _ = std::process::Command::new("docker")
                .args(["network", "rm", network])
                .status();
        }
    }
    let _ = control.kill();
    let _ = control.wait();
    let _ = std::fs::remove_dir_all(test_root);
}
