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

    let payload_arg = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| {
            "Uso: verify-cold-commissioning <payload> <minimal|full|config-all|invalid-package|selective-recovery|radio-saf|fault-first|fault-upgrade|fault-fabric-upgrade|incomplete-resume|two-nodes-same-host|ipc-resume> [stage]".to_string()
        })?;
    let payload_root = fs::canonicalize(&payload_arg).map_err(|error| {
        format!(
            "No se pudo canonicalizar el payload {}: {error}",
            payload_arg.display()
        )
    })?;
    let mode = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "minimal".to_string());
    let profiles = match mode.as_str() {
        "minimal"
        | "invalid-package"
        | "selective-recovery"
        | "fault-first"
        | "fault-upgrade"
        | "fault-fabric-upgrade"
        | "incomplete-resume"
        | "two-nodes-same-host"
        | "ipc-resume" => "site-core",
        "full" => "site-core,telemetry,radio-control",
        "radio-saf" => "site-core,radio-saf",
        "config-all" => "site-core,telemetry,radio-control,radio-saf,radio-turn,radio-livekit,observability,connectivity",
        _ => return Err("Modo de cold commissioning desconocido.".to_string()),
    };
    let fault_stage = std::env::args().nth(3);
    if matches!(
        mode.as_str(),
        "fault-first" | "fault-upgrade" | "fault-fabric-upgrade"
    ) {
        let stage = fault_stage
            .as_deref()
            .ok_or_else(|| format!("{mode} requiere stage."))?;
        if mode == "fault-first" {
            std::env::set_var("ACTIUM_FAULT_INJECTION_STAGE", stage);
        }
    }
    let release_version = actium_node_core::verify_payload(&payload_root)?
        .version()
        .to_string();
    let test_id = Uuid::new_v4();
    let token = test_id.simple().to_string();
    let short = &token[..8];
    let test_root = std::env::var_os("ACTIUM_COLD_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("actium-cold-{short}")));
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
    let container_fixture = test_root.join("site-runtime-fixture.json");
    fs::copy(&fixture_path, &container_fixture).map_err(|error| error.to_string())?;
    let control_script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/cold-control-plane.mjs")
        .canonicalize()
        .map_err(|error| format!("Test double ausente: {error}"))?;
    fs::copy(&control_script, test_root.join("cold-control-plane.mjs"))
        .map_err(|error| error.to_string())?;
    fs::write(
        &server_config,
        serde_json::to_vec_pretty(&json!({
            "deploymentId": deployment_id,
            "hostId": host_id,
            "port": port,
            "fixturePath": "/work/site-runtime-fixture.json",
            "certPath": "/work/control-plane.crt",
            "keyPath": "/work/control-plane.key",
            "rootPrivateKeyPath": "/work/site-runtime-root-private.pem",
            "expectedIssuer": expected_issuer,
            "eventsPath": "/work/control-events.jsonl",
            "readyPath": "/work/control-ready",
            "invalidPackage": mode == "invalid-package",
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let control_container = format!("actium-cold-control-{short}");
    fs::write(test_root.join("control-container"), &control_container)
        .map_err(|error| error.to_string())?;
    let mut control = Command::new("docker")
        .args(["run", "--rm", "--name", &control_container, "--publish"])
        .arg(format!("{port}:{port}"))
        .args(["--volume"])
        .arg(format!("{}:/work:rw", test_root.display()))
        .args([
            "node:22-alpine",
            "node",
            "/work/cold-control-plane.mjs",
            "/work/control-config.json",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("No se pudo iniciar Control Plane de prueba: {error}"))?;
    if let Err(error) = wait_for_file(&ready_path, Duration::from_secs(60), &mut control) {
        stop_control_plane(&mut control, &test_root);
        let _ = fs::remove_dir_all(&test_root);
        return Err(error);
    }

    let fabric_id = Uuid::new_v4().to_string();
    let fabric_project = format!("actium-lab-cold-{short}-fabric");
    let fabric_identity = FabricIdentity {
        fabric_id: fabric_id.clone(),
        compose_project: fabric_project.clone(),
        network_name: fabric_project.clone(),
        host_id: None,
    };
    let operator = RuntimeOperator::new_with_fabric(
        &nodes_root,
        &fabrics_root,
        &payload_root,
        fabric_identity.clone(),
        test_root.join("state/fabric-identity.json"),
    );
    let path = |relative: &str| {
        node_root
            .join(relative)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let radio_saf_enabled = mode == "radio-saf";
    let installation_id = Uuid::new_v4().to_string();
    let node_env = format!(
        "ACTIUM_CONTROL_ENDPOINT=https://host.docker.internal:{port}\n\
ACTIUM_NODE_INSTALLATION_ID={installation_id}\n\
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
RADIO_SAF_PORT={}\n\
SITE_CORE_PORT={}\n\
RADIO_ARCHIVE_HOST_PATH={}\n\
RADIO_SAF_ENABLED={}\n\
TURN_REALM=cold.invalid\n\
TURN_EXTERNAL_IP=127.0.0.1\n\
TURN_URLS=turn:127.0.0.1:3478\n\
LIVEKIT_NODE_IP=127.0.0.1\n\
LIVEKIT_PUBLIC_URL=wss://livekit.cold.invalid\n\
CONNECTIVITY_EDGE_CONTROL_URL=https://connectivity.cold.invalid\n",
        path("keys/actium-terminal-public.pem"),
        path("keys/actium-operator-public.pem"),
        path("keys/actium-site-runtime-bundle-public.pem"),
        port + 1,
        port + 2,
        port + 3,
        port + 4,
        path("persistent/radio-archive"),
        radio_saf_enabled,
    );
    let request = CommissionNodeRequest {
        install_dir: node_root.to_string_lossy().into_owned(),
        expected_release: release_version.clone(),
        node_env,
        marker: json!({
            "managerChannel": "lab",
            "status": "installing",
            "releaseVersion": release_version,
            "installationId": installation_id,
            "deploymentId": deployment_id,
        })
        .to_string(),
        terminal_public_key: format!("{root_public_key}\n"),
        operator_public_key: format!("{root_public_key}\n"),
        site_runtime_public_key: Some(format!("{root_public_key}\n")),
        control_plane_ca_pem: Some(
            fs::read_to_string(&cert_path).map_err(|error| error.to_string())?,
        ),
        connectivity_edge_enrollment_token: (mode == "config-all")
            .then(|| format!("acen_{}", "e".repeat(48))),
        connectivity_internal_relay_token: (mode == "config-all")
            .then(|| format!("acer_{}", "r".repeat(48))),
        enrollment_token: format!("adpe_{}", "c".repeat(64)),
        radio_archive_host_path: radio_saf_enabled.then(|| path("persistent/radio-archive")),
        prepare_only: mode == "config-all",
        resume_incomplete: false,
    };

    if mode == "two-nodes-same-host" {
        return run_two_nodes_same_host(
            &mut control,
            &operator,
            &request,
            &node_root,
            &nodes_root,
            &fabric_project,
            &fabric_id,
            &test_root,
            &installation_id,
            release_version.as_str(),
            short,
        );
    }
    if mode == "ipc-resume" {
        return run_ipc_resume(
            &mut control,
            &request,
            &node_root,
            &nodes_root,
            &fabrics_root,
            &payload_root,
            &fabric_project,
            &fabric_id,
            &test_root,
            &installation_id,
        );
    }
    if mode == "incomplete-resume" && !cfg!(feature = "fault-injection") {
        return finish_with_error(
            &mut control,
            &operator,
            &node_root,
            &fabric_project,
            &fabric_id,
            &test_root,
            "incomplete-resume requiere --features fault-injection.".to_string(),
        );
    }

    let result = if mode == "incomplete-resume" {
        run_incomplete_resume_e2e(
            &operator,
            &request,
            &node_root,
            &nodes_root,
            &fabrics_root,
            &payload_root,
            fabric_identity.clone(),
            test_root.join("state/fabric-identity.json"),
            &installation_id,
        )
    } else {
        operator.commission_node(&request)
    };
    let evidence = match result {
        Ok(result) if mode != "invalid-package" => {
            if mode == "config-all" {
                let runtime =
                    actium_node_core::ReleaseManager::new(&node_root).active_runtime_dir()?;
                let config = Command::new("/bin/sh")
                    .arg(runtime.join("manage-node.sh"))
                    .arg("config")
                    .env(
                        "ACTIUM_DATA_PLANE_ENV_FILE",
                        node_root.join("secrets/data-plane.env"),
                    )
                    .output()
                    .map_err(|error| format!("No se pudo ejecutar manage-node config: {error}"))?;
                if !config.status.success() {
                    return finish_with_error(
                        &mut control,
                        &operator,
                        &node_root,
                        &fabric_project,
                        &fabric_id,
                        &test_root,
                        format!(
                            "manage-node config rechazo la topologia: {}",
                            String::from_utf8_lossy(&config.stderr)
                        ),
                    );
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "pass",
                        "mode": mode,
                        "profiles": profiles,
                        "prepareOnly": true,
                        "manageNodeConfig": String::from_utf8_lossy(&config.stdout).trim(),
                    }))
                    .map_err(|error| error.to_string())?
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
            if matches!(mode.as_str(), "fault-upgrade" | "fault-fabric-upgrade") {
                let candidate_payload =
                    match build_fault_candidate_payload(&payload_root, &test_root) {
                        Ok(payload) => payload,
                        Err(error) => {
                            return finish_with_error(
                                &mut control,
                                &operator,
                                &node_root,
                                &fabric_project,
                                &fabric_id,
                                &test_root,
                                format!("No se pudo construir fault candidate: {error}"),
                            )
                        }
                    };
                let candidate_operator = RuntimeOperator::new_with_fabric(
                    &nodes_root,
                    &fabrics_root,
                    &candidate_payload,
                    fabric_identity.clone(),
                    test_root.join("state/fabric-identity.json"),
                );
                let stage = fault_stage.as_deref().unwrap_or_default();
                std::env::set_var("ACTIUM_FAULT_INJECTION_STAGE", stage);
                let action = if mode == "fault-upgrade" {
                    "update"
                } else {
                    "start"
                };
                let failure = candidate_operator
                    .execute(&node_root, action, None)
                    .expect_err("fault upgrade debio fallar");
                std::env::remove_var("ACTIUM_FAULT_INJECTION_STAGE");
                if !failure.contains("[ROLLED_BACK]") {
                    return finish_with_error(
                        &mut control,
                        &operator,
                        &node_root,
                        &fabric_project,
                        &fabric_id,
                        &test_root,
                        format!("Upgrade no restauro LKG: {failure}"),
                    );
                }
                let node_release: Value = serde_json::from_slice(
                    &fs::read(node_root.join("state/release-state.json"))
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                let fabric_release: Value = serde_json::from_slice(
                    &fs::read(
                        fabrics_root
                            .join(&fabric_id)
                            .join("state/release-state.json"),
                    )
                    .map_err(|error| error.to_string())?,
                )
                .map_err(|error| error.to_string())?;
                let restored = if mode == "fault-upgrade" {
                    node_release.get("promotionStatus").and_then(Value::as_str)
                        == Some("rolled_back")
                        && fabric_release
                            .get("promotionStatus")
                            .and_then(Value::as_str)
                            == Some("active")
                } else {
                    node_release.get("promotionStatus").and_then(Value::as_str) == Some("active")
                        && fabric_release
                            .get("promotionStatus")
                            .and_then(Value::as_str)
                            == Some("rolled_back")
                };
                if !restored {
                    return finish_with_error(
                        &mut control,
                        &operator,
                        &node_root,
                        &fabric_project,
                        &fabric_id,
                        &test_root,
                        format!(
                            "Estado de upgrade inseguro: node={node_release}, fabric={fabric_release}"
                        ),
                    );
                }
                let inventory = operator.runtime_unit_inventory(&node_root)?;
                if inventory.units.iter().any(|unit| unit.state != "ready") {
                    return finish_with_error(
                        &mut control,
                        &operator,
                        &node_root,
                        &fabric_project,
                        &fabric_id,
                        &test_root,
                        format!("LKG restaurado sin health: {:?}", inventory.units),
                    );
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "pass",
                        "mode": mode,
                        "stage": stage,
                        "candidateMaterialDistinct": true,
                        "failure": failure,
                        "nodeRelease": node_release,
                        "fabricRelease": fabric_release,
                        "lkgHealth": "pass",
                    }))
                    .map_err(|error| error.to_string())?
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
            let mut recovery_evidence = Value::Null;
            if mode == "selective-recovery" {
                recovery_evidence = match verify_selective_site_core_recovery(
                    &operator,
                    &node_root,
                    &events_path,
                ) {
                    Ok(value) => value,
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
            }
            if mode == "radio-saf" {
                recovery_evidence = match verify_radio_saf_storage(&operator, &node_root) {
                    Ok(value) => value,
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
            }
            let attestation_refresh = match operator.refresh_material_attestations() {
                Ok(messages) => messages,
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
            if attestation_refresh
                .iter()
                .any(|message| message.contains("atestacion no disponible"))
            {
                return finish_with_error(
                    &mut control,
                    &operator,
                    &node_root,
                    &fabric_project,
                    &fabric_id,
                    &test_root,
                    format!(
                        "Refresh material fallo: {}",
                        attestation_refresh.join(" | ")
                    ),
                );
            }
            let attestation_boundary = match verify_attestation_boundary(&node_root) {
                Ok(value) => value,
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
            let site_core_secret_boundary = match verify_site_core_secret_boundary(&node_root) {
                Ok(value) => value,
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
            let lifecycle: Value = serde_json::from_slice(
                &fs::read(node_root.join("state/agent/agent-lifecycle.json"))
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
                "nodeInstallationId": installation_id,
                "hostInstallationId": fs::read_to_string(node_root.join("node.env")).ok().and_then(|contents| contents.lines().find_map(|line| line.strip_prefix("ACTIUM_HOST_INSTALLATION_ID=")).map(str::to_string)),
                "identitiesDistinct": fs::read_to_string(node_root.join("node.env")).ok().and_then(|contents| {
                    let host = contents.lines().find_map(|line| line.strip_prefix("ACTIUM_HOST_INSTALLATION_ID="))?;
                    Some(host != installation_id)
                }),
                "fabric": "ready",
                "profiles": profiles,
                "sequence": result.output.lines().filter(|line| line.contains("agent_") || line.contains("site_core_") || line.contains("site_runtime_") || line.contains("runtime_ready:")).collect::<Vec<_>>(),
                "globalHealth": inventory.units.iter().map(|unit| json!({ "capability": unit.capability, "state": unit.state })).collect::<Vec<_>>(),
                "lifecycle": lifecycle,
                "controlEvents": fs::read_to_string(&events_path).unwrap_or_default().lines().filter_map(|line| serde_json::from_str::<Value>(line).ok()).collect::<Vec<_>>(),
                "recoveryEvidence": recovery_evidence,
                "attestationBoundary": attestation_boundary,
                "siteCoreSecretBoundary": site_core_secret_boundary,
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
        Err(error) if mode == "fault-first" => {
            std::env::remove_var("ACTIUM_FAULT_INJECTION_STAGE");
            let release_state: Value = serde_json::from_slice(
                &fs::read(node_root.join("state/release-state.json"))
                    .map_err(|read_error| read_error.to_string())?,
            )
            .map_err(|parse_error| parse_error.to_string())?;
            if !release_state
                .get("activeRelease")
                .is_none_or(Value::is_null)
                || release_state.get("promotionStatus").and_then(Value::as_str) != Some("failed")
                || release_state
                    .get("lastFailedRelease")
                    .is_none_or(Value::is_null)
            {
                return finish_with_error(
                    &mut control,
                    &operator,
                    &node_root,
                    &fabric_project,
                    &fabric_id,
                    &test_root,
                    format!("Fault injection dejo release insegura: {release_state}"),
                );
            }
            let fabric_state_path = fabrics_root
                .join(&fabric_id)
                .join("state/release-state.json");
            let fabric_state = fs::read(&fabric_state_path)
                .ok()
                .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
            if fabric_state.as_ref().is_some_and(|state| {
                state.get("promotionStatus").and_then(Value::as_str) == Some("promoting")
                    || state
                        .get("activeRelease")
                        .is_some_and(|value| !value.is_null())
                        && state.get("promotionStatus").and_then(Value::as_str) == Some("failed")
            }) {
                return finish_with_error(
                    &mut control,
                    &operator,
                    &node_root,
                    &fabric_project,
                    &fabric_id,
                    &test_root,
                    format!("Fault injection dejo Fabric inseguro: {fabric_state:?}"),
                );
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "pass",
                    "mode": mode,
                    "stage": fault_stage,
                    "failure": error,
                    "nodeRelease": release_state,
                    "fabricRelease": fabric_state,
                }))
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
fn run_incomplete_resume_e2e(
    operator: &actium_node_core::RuntimeOperator,
    request: &actium_node_core::CommissionNodeRequest,
    node_root: &std::path::Path,
    nodes_root: &std::path::Path,
    fabrics_root: &std::path::Path,
    payload_root: &std::path::Path,
    fabric_identity: actium_node_core::FabricIdentity,
    fabric_identity_path: std::path::PathBuf,
    installation_id: &str,
) -> Result<actium_node_core::RuntimeActionResult, String> {
    use serde_json::Value;
    use std::fs;

    std::env::set_var("ACTIUM_FAULT_INJECTION_STAGE", "commission.topology");
    let first = operator
        .commission_node(request)
        .expect_err("el first install debe fallar antes de topologia");
    std::env::remove_var("ACTIUM_FAULT_INJECTION_STAGE");
    if !first.contains("FAULT_INJECTED:commission.topology") {
        return Err(format!(
            "El first install debe abortar en commission.topology, no en otro punto: {first}"
        ));
    }
    if !node_root.join("node.env").is_file() {
        return Err("El leftover no conservo node.env.".to_string());
    }
    if node_root.join("compose.yml").is_file() {
        return Err("El leftover no debe tener Compose operativo.".to_string());
    }
    if node_root.join("state/runtime-topology.json").is_file() {
        return Err("El leftover no debe tener topologia materializada.".to_string());
    }
    let marker: Value = serde_json::from_slice(
        &fs::read(node_root.join(".actium-node-installation.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if marker.get("status").and_then(Value::as_str) != Some("failed") {
        return Err(format!("El leftover no dejo marker failed: {marker}"));
    }
    if marker.get("installationId").and_then(Value::as_str) != Some(installation_id) {
        return Err(format!(
            "El leftover no conservo installationId {installation_id}: {marker}"
        ));
    }
    let leftover_env =
        fs::read_to_string(node_root.join("node.env")).map_err(|error| error.to_string())?;
    let env_value = |contents: &str, key: &str| {
        contents
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_string()
    };
    let leftover_profiles = env_value(&leftover_env, "ACTIUM_PROFILES");
    let leftover_project = env_value(&leftover_env, "ACTIUM_PROJECT_NAME");
    let leftover_deployment = env_value(&leftover_env, "ACTIUM_DEPLOYMENT_ID");
    let leftover_host = env_value(&leftover_env, "ACTIUM_HOST_INSTALLATION_ID");
    let leftover_node = env_value(&leftover_env, "ACTIUM_NODE_INSTALLATION_ID");
    let leftover_host_code = env_value(&leftover_env, "ACTIUM_HOST_CODE");
    if leftover_profiles.is_empty() || leftover_project.is_empty() || leftover_deployment.is_empty()
    {
        return Err("El leftover no conservo perfiles o identidad tecnica.".to_string());
    }
    if leftover_node != installation_id {
        return Err(format!(
            "El leftover no conservo ACTIUM_NODE_INSTALLATION_ID={installation_id}: {leftover_node}"
        ));
    }
    if leftover_host.is_empty() || leftover_host == installation_id {
        return Err(format!(
            "El leftover debe inyectar HostIdentity distinta del nodo: host={leftover_host} node={installation_id}"
        ));
    }
    if leftover_host_code == leftover_project || leftover_host_code.starts_with("actium-lab-cold-")
    {
        return Err(format!(
            "HOST_CODE no debe derivarse del proyecto del nodo: {leftover_host_code}"
        ));
    }
    let release_state: Value = serde_json::from_slice(
        &fs::read(node_root.join("state/release-state.json")).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if !release_state
        .get("activeRelease")
        .is_none_or(Value::is_null)
    {
        return Err(format!(
            "El leftover no debe conservar activeRelease: {release_state}"
        ));
    }

    let restarted = actium_node_core::RuntimeOperator::new_with_fabric(
        nodes_root,
        fabrics_root,
        payload_root,
        fabric_identity,
        fabric_identity_path,
    );
    let mut retry = request.clone();
    retry.resume_incomplete = true;
    let result = restarted.commission_node(&retry)?;
    let marker_after: Value = serde_json::from_slice(
        &fs::read(node_root.join(".actium-node-installation.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if marker_after.get("installationId").and_then(Value::as_str) != Some(installation_id) {
        return Err(format!(
            "El retry no conservo installationId {installation_id}: {marker_after}"
        ));
    }
    if marker_after.get("managerChannel").and_then(Value::as_str) != Some("lab") {
        return Err(format!(
            "El retry no conservo managerChannel=lab: {marker_after}"
        ));
    }
    let env_after =
        fs::read_to_string(node_root.join("node.env")).map_err(|error| error.to_string())?;
    let profile_after = env_value(&env_after, "ACTIUM_PROFILES");
    let project_after = env_value(&env_after, "ACTIUM_PROJECT_NAME");
    let host_after = env_value(&env_after, "ACTIUM_HOST_INSTALLATION_ID");
    let node_after = env_value(&env_after, "ACTIUM_NODE_INSTALLATION_ID");
    let host_code_after = env_value(&env_after, "ACTIUM_HOST_CODE");
    let deployment_after = env_value(&env_after, "ACTIUM_DEPLOYMENT_ID");
    if deployment_after != leftover_deployment {
        return Err(format!(
            "El retry derivo deploymentId leftover={leftover_deployment} retry={deployment_after}."
        ));
    }
    if profile_after != leftover_profiles {
        return Err(format!(
            "El retry derivo perfiles leftover={leftover_profiles} retry={profile_after}."
        ));
    }
    if project_after != leftover_project {
        return Err(format!(
            "El retry derivo proyecto leftover={leftover_project} retry={project_after}."
        ));
    }
    if node_after != installation_id {
        return Err(format!(
            "El retry derivo node installationId leftover={installation_id} retry={node_after}."
        ));
    }
    if host_after != leftover_host {
        return Err(format!(
            "El retry derivo host installationId leftover={leftover_host} retry={host_after}."
        ));
    }
    if host_after == node_after {
        return Err("Resume mezclo HostIdentity con NodeInstallationIdentity.".to_string());
    }
    if host_code_after == project_after {
        return Err(format!(
            "Resume derivo HOST_CODE desde projectName: {host_code_after}"
        ));
    }
    let leftover_ports = env_value(&leftover_env, "SITE_CORE_PORT");
    let ports_after = env_value(&env_after, "SITE_CORE_PORT");
    if leftover_ports != ports_after {
        return Err(format!(
            "Resume autoasigno puertos leftover={leftover_ports} retry={ports_after}."
        ));
    }
    Ok(result)
}

#[cfg(unix)]
fn verify_selective_site_core_recovery(
    operator: &actium_node_core::RuntimeOperator,
    node_root: &std::path::Path,
    events_path: &std::path::Path,
) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    use std::fs;

    let topology: Value = serde_json::from_slice(
        &fs::read(node_root.join("state/runtime-topology.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let site_core = topology
        .get("units")
        .and_then(Value::as_array)
        .and_then(|units| {
            units
                .iter()
                .find(|unit| unit.get("capability").and_then(Value::as_str) == Some("site-core"))
        })
        .ok_or_else(|| "Topologia sin Site Core para recovery selectivo.".to_string())?;
    let runtime_unit_id = site_core
        .get("runtimeUnitId")
        .and_then(Value::as_str)
        .ok_or_else(|| "Site Core sin runtimeUnitId.".to_string())?;
    let agent_state = node_root.join("persistent/agent/agent.json");
    let agent_before = fs::read(&agent_state).map_err(|error| error.to_string())?;
    let package_requests_before = count_control_event(events_path, "site-runtime-package")?;
    let package_sha_before = last_control_package_sha(events_path)?;

    operator.execute(node_root, "stop", None)?;
    let site_core_state = node_root
        .join("persistent/runtime-units")
        .join(runtime_unit_id)
        .join("site-core");
    let site_runtime_state = site_core_state.join("runtime");
    let canonical_node = node_root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let canonical_parent = site_runtime_state
        .parent()
        .ok_or_else(|| "Site Core state sin parent.".to_string())?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if !canonical_parent.starts_with(&canonical_node) {
        return Err("Recovery selectivo intento salir del root temporal.".to_string());
    }
    fs::remove_dir_all(&site_runtime_state).map_err(|error| error.to_string())?;
    let restarted = operator.execute(node_root, "start", None)?;
    let inventory = operator.runtime_unit_inventory(node_root)?;
    if inventory.units.iter().any(|unit| unit.state != "ready") {
        return Err(format!(
            "Recovery selectivo no convergio: {:?}",
            inventory.units
        ));
    }
    let package_requests_after = count_control_event(events_path, "site-runtime-package")?;
    if package_requests_after <= package_requests_before {
        return Err("Agent no volvio a consultar el mismo Site Runtime package.".to_string());
    }
    let package_sha_after = last_control_package_sha(events_path)?;
    if package_sha_before != package_sha_after {
        return Err(format!(
            "Recovery selectivo recibio otro package: {package_sha_before} != {package_sha_after}."
        ));
    }
    if fs::read(&agent_state)
        .map_err(|error| error.to_string())?
        .is_empty()
        || agent_before.is_empty()
    {
        return Err("Estado durable del Agent no fue preservado.".to_string());
    }
    let lifecycle: Value = serde_json::from_slice(
        &fs::read(node_root.join("state/agent/agent-lifecycle.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if lifecycle.get("state").and_then(Value::as_str) != Some("reporting") {
        return Err(format!("Agent no recupero reporting: {lifecycle}"));
    }
    Ok(serde_json::json!({
        "siteCoreRuntimeStateRecreated": site_runtime_state.is_dir(),
        "agentStatePreserved": true,
        "sameSignedPackageReinstalled": true,
        "packageSha256": package_sha_after,
        "packageRequestsBefore": package_requests_before,
        "packageRequestsAfter": package_requests_after,
        "siteCoreReady": true,
        "agentReporting": true,
        "globalHealth": "pass",
        "orchestration": restarted.message,
    }))
}

#[cfg(unix)]
fn count_control_event(path: &std::path::Path, expected: &str) -> Result<usize, String> {
    let raw = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    Ok(raw
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event.get("event").and_then(serde_json::Value::as_str) == Some(expected))
        .count())
}

#[cfg(unix)]
fn last_control_package_sha(path: &std::path::Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    raw.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| {
            event.get("event").and_then(serde_json::Value::as_str) == Some("site-runtime-package")
        })
        .filter_map(|event| {
            event
                .get("package_sha256")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .last()
        .ok_or_else(|| "Control Plane no registro package SHA-256.".to_string())
}

#[cfg(unix)]
fn build_fault_candidate_payload(
    payload_root: &std::path::Path,
    test_root: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    use actium_node_core::{tree_sha256, verify_payload, PayloadManifestV3};
    use sha2::{Digest, Sha256};
    use std::{fs, io::Write, os::unix::fs::PermissionsExt, path::Path};

    fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
        fs::create_dir_all(target).map_err(|error| error.to_string())?;
        fs::set_permissions(
            target,
            fs::Permissions::from_mode(
                fs::metadata(source)
                    .map_err(|error| error.to_string())?
                    .permissions()
                    .mode(),
            ),
        )
        .map_err(|error| error.to_string())?;
        for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            let metadata = fs::symlink_metadata(&source_path).map_err(|error| error.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "Fixture candidato rechazo symlink: {}",
                    source_path.display()
                ));
            }
            if metadata.is_dir() {
                copy_tree(&source_path, &target_path)?;
            } else if metadata.is_file() {
                fs::copy(&source_path, &target_path).map_err(|error| error.to_string())?;
                fs::set_permissions(
                    &target_path,
                    fs::Permissions::from_mode(metadata.permissions().mode()),
                )
                .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    let candidate = test_root.join("fault-candidate-payload");
    copy_tree(payload_root, &candidate)?;
    let marker_path = candidate.join("README.md");
    fs::OpenOptions::new()
        .append(true)
        .open(&marker_path)
        .and_then(|mut file| file.write_all(b"\nFault candidate material.\n"))
        .map_err(|error| error.to_string())?;
    let manifest_path = candidate.join("PAYLOAD.json");
    let mut manifest: PayloadManifestV3 =
        serde_json::from_slice(&fs::read(&manifest_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let candidate_version = format!("{}-fault-candidate", manifest.release_version);
    fs::write(candidate.join("VERSION"), format!("{candidate_version}\n"))
        .map_err(|error| error.to_string())?;
    for relative in ["README.md", "VERSION"] {
        let bytes = fs::read(candidate.join(relative)).map_err(|error| error.to_string())?;
        let entry = manifest
            .files
            .iter_mut()
            .find(|entry| entry.path == relative)
            .ok_or_else(|| format!("Payload sin {relative} para fault candidate."))?;
        entry.size = bytes.len() as u64;
        entry.sha256 = format!("{:x}", Sha256::digest(&bytes));
    }
    manifest.release_version = candidate_version;
    manifest.tree_sha256 = tree_sha256(&manifest.files);
    manifest.source_dirty = true;
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    verify_payload(&candidate)?;
    Ok(candidate)
}

#[cfg(unix)]
fn verify_radio_saf_storage(
    operator: &actium_node_core::RuntimeOperator,
    node_root: &std::path::Path,
) -> Result<serde_json::Value, String> {
    use actium_node_core::RuntimeUnitActionRequest;
    use serde_json::Value;
    use std::{fs, os::unix::fs::MetadataExt, process::Command};

    let topology: Value = serde_json::from_slice(
        &fs::read(node_root.join("state/runtime-topology.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let unit = topology
        .get("units")
        .and_then(Value::as_array)
        .and_then(|units| {
            units
                .iter()
                .find(|unit| unit.get("capability").and_then(Value::as_str) == Some("radio-saf"))
        })
        .ok_or_else(|| "Topologia sin Radio S&F.".to_string())?;
    let runtime_unit_id = unit
        .get("runtimeUnitId")
        .and_then(Value::as_str)
        .ok_or_else(|| "Radio S&F sin runtimeUnitId.".to_string())?;
    let compose_project = unit
        .get("composeProject")
        .and_then(Value::as_str)
        .ok_or_else(|| "Radio S&F sin composeProject.".to_string())?;
    let objects = node_root
        .join("persistent/runtime-units")
        .join(runtime_unit_id)
        .join("objects");
    let metadata = fs::metadata(&objects).map_err(|error| error.to_string())?;
    if metadata.uid() != 1000 || metadata.gid() != 1000 {
        return Err(format!(
            "Radio S&F objects posee owner {}:{}, esperado 1000:1000.",
            metadata.uid(),
            metadata.gid()
        ));
    }
    let minio = format!("{compose_project}-minio");
    let write = Command::new("docker")
        .args([
            "exec",
            &minio,
            "sh",
            "-c",
            "printf hardening > /data/.actium-storage-probe && rm /data/.actium-storage-probe",
        ])
        .status()
        .map_err(|error| error.to_string())?;
    if !write.success() {
        return Err("MinIO no pudo escribir storage persistente como uid 1000.".to_string());
    }
    if fs::read_dir(&objects)
        .map_err(|error| error.to_string())?
        .next()
        .is_none()
    {
        return Err("MinIO no materializo metadata/bucket sobre storage vacio.".to_string());
    }
    operator.execute_runtime_unit(&RuntimeUnitActionRequest {
        install_dir: node_root.to_string_lossy().into_owned(),
        runtime_unit_id: runtime_unit_id.to_string(),
        action: "restart".to_string(),
    })?;
    let inventory = operator.runtime_unit_inventory(node_root)?;
    let ready = inventory
        .units
        .iter()
        .find(|candidate| candidate.runtime_unit_id == runtime_unit_id)
        .is_some_and(|candidate| candidate.state == "ready");
    if !ready {
        return Err("Radio S&F no recupero readiness despues de restart.".to_string());
    }
    Ok(serde_json::json!({
        "objectsPath": objects,
        "owner": "1000:1000",
        "minioWrite": "pass",
        "bucketInitialized": true,
        "restartReady": true,
    }))
}

#[cfg(unix)]
fn verify_attestation_boundary(node_root: &std::path::Path) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    use std::{fs, os::unix::fs::MetadataExt, process::Command};

    let topology: Value = serde_json::from_slice(
        &fs::read(node_root.join("state/runtime-topology.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let agent_project = topology
        .get("units")
        .and_then(Value::as_array)
        .and_then(|units| {
            units
                .iter()
                .find(|unit| unit.get("capability").and_then(Value::as_str) == Some("agent"))
        })
        .and_then(|unit| unit.get("composeProject"))
        .and_then(Value::as_str)
        .ok_or_else(|| "Topologia sin proyecto Agent.".to_string())?;
    let path = node_root.join("state/supervisor/material-attestation.json");
    let envelope: Value =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if envelope
        .pointer("/statement/sequence")
        .and_then(Value::as_u64)
        .is_none_or(|sequence| sequence < 1)
    {
        return Err("Atestacion sin secuencia anti-replay.".to_string());
    }
    let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
    if metadata.mode() & 0o222 != 0 {
        return Err(format!(
            "Atestacion host writable: {:o}.",
            metadata.mode() & 0o777
        ));
    }
    let container = format!("{agent_project}-agent");
    let boundary = Command::new("docker")
        .args([
            "exec",
            "--user",
            "1000:1000",
            &container,
            "sh",
            "-c",
            "test -r /var/lib/actium-supervisor-evidence/material-attestation.json && test ! -w /var/lib/actium-supervisor-evidence && test ! -w /var/lib/actium-supervisor-evidence/material-attestation.json",
        ])
        .status()
        .map_err(|error| error.to_string())?;
    if !boundary.success() {
        return Err("Agent puede mutar o no puede leer evidencia Supervisor.".to_string());
    }
    Ok(serde_json::json!({
        "agentState": "rw",
        "supervisorEvidence": "ro",
        "hostMode": format!("{:o}", metadata.mode() & 0o777),
        "sequence": envelope.pointer("/statement/sequence"),
    }))
}

#[cfg(unix)]
fn verify_site_core_secret_boundary(
    node_root: &std::path::Path,
) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    use std::{fs, process::Command};

    let topology: Value = serde_json::from_slice(
        &fs::read(node_root.join("state/runtime-topology.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let site_core = topology
        .get("units")
        .and_then(Value::as_array)
        .and_then(|units| {
            units
                .iter()
                .find(|unit| unit.get("capability").and_then(Value::as_str) == Some("site-core"))
        })
        .ok_or_else(|| "Topologia sin Site Core.".to_string())?;
    let project = site_core
        .get("composeProject")
        .and_then(Value::as_str)
        .ok_or_else(|| "Site Core sin composeProject.".to_string())?;
    let runtime_unit_id = site_core
        .get("runtimeUnitId")
        .and_then(Value::as_str)
        .ok_or_else(|| "Site Core sin runtimeUnitId.".to_string())?;
    let container = format!("{project}-site-core");
    let check = Command::new("docker")
        .args([
            "exec",
            &container,
            "sh",
            "-c",
            "test -r /run/actium-site-core-secrets/postgres-password && test \"$(stat -c %a /run/actium-site-core-secrets/postgres-password)\" = 400 && test ! -e /var/lib/actium-site-core/.secrets",
        ])
        .status()
        .map_err(|error| error.to_string())?;
    if !check.success() {
        return Err("Site Core no preservo secrets efimeros 0400.".to_string());
    }
    let durable = node_root
        .join("persistent/runtime-units")
        .join(runtime_unit_id)
        .join("site-core");
    if durable.join(".secrets").exists() {
        return Err("Site Core persistio secrets dentro de su volumen durable.".to_string());
    }
    Ok(serde_json::json!({
        "runtimeSecrets": "/run/actium-site-core-secrets",
        "mode": "0400",
        "persistentSecretsAbsent": true,
        "process": "non-root",
    }))
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
fn run_two_nodes_same_host(
    control: &mut std::process::Child,
    operator: &actium_node_core::RuntimeOperator,
    first_request: &actium_node_core::CommissionNodeRequest,
    first_root: &std::path::Path,
    nodes_root: &std::path::Path,
    fabric_project: &str,
    fabric_id: &str,
    test_root: &std::path::Path,
    first_installation_id: &str,
    release_version: &str,
    short: &str,
) -> Result<(), String> {
    use serde_json::json;
    use std::fs;
    use uuid::Uuid;

    let mut first = first_request.clone();
    first.prepare_only = true;
    operator.commission_node(&first).map_err(|error| {
        let _ = finish_with_error::<()>(
            control,
            operator,
            first_root,
            fabric_project,
            fabric_id,
            test_root,
            error.clone(),
        );
        error
    })?;
    let second_id = Uuid::new_v4().to_string();
    let second_deployment = Uuid::new_v4().to_string();
    let second_root = nodes_root.join(format!("actium-lab-cold-b-{short}"));
    fs::create_dir_all(&second_root).map_err(|error| error.to_string())?;
    let mut second = first.clone();
    second.install_dir = second_root.to_string_lossy().into_owned();
    let first_project = first
        .node_env
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_PROJECT_NAME="))
        .unwrap_or_default()
        .to_string();
    let second_project = format!("actium-lab-cold-b-{short}");
    second.node_env = first
        .node_env
        .replace(first_installation_id, &second_id)
        .replace(
            &first_request_deployment_id(&first.node_env),
            &second_deployment,
        )
        .replace(&first_project, &second_project);
    second.marker = first
        .marker
        .replace(first_installation_id, &second_id)
        .replace(
            &first_request_deployment_id(&first.node_env),
            &second_deployment,
        );
    second.prepare_only = true;
    let _ = release_version;
    operator.commission_node(&second).map_err(|error| {
        let _ = finish_with_error::<()>(
            control,
            operator,
            first_root,
            fabric_project,
            fabric_id,
            test_root,
            error.clone(),
        );
        error
    })?;
    let env_value = |root: &std::path::Path, key: &str| {
        fs::read_to_string(root.join("node.env"))
            .ok()
            .and_then(|contents| {
                contents
                    .lines()
                    .find_map(|line| line.strip_prefix(&format!("{key}=")))
                    .map(str::to_string)
            })
            .unwrap_or_default()
    };
    let host_a = env_value(first_root, "ACTIUM_HOST_INSTALLATION_ID");
    let host_b = env_value(&second_root, "ACTIUM_HOST_INSTALLATION_ID");
    let node_a = env_value(first_root, "ACTIUM_NODE_INSTALLATION_ID");
    let node_b = env_value(&second_root, "ACTIUM_NODE_INSTALLATION_ID");
    if host_a.is_empty() || host_a != host_b {
        return finish_with_error(
            control,
            operator,
            first_root,
            fabric_project,
            fabric_id,
            test_root,
            format!("Los nodos no comparten HostIdentity: {host_a} vs {host_b}"),
        );
    }
    if node_a == node_b || node_a == host_a || node_b == host_b {
        return finish_with_error(
            control,
            operator,
            first_root,
            fabric_project,
            fabric_id,
            test_root,
            format!("Identidades de nodo no quedaron separadas: nodeA={node_a} nodeB={node_b} host={host_a}"),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "pass",
            "mode": "two-nodes-same-host",
            "hostInstallationId": host_a,
            "nodeInstallationIds": [node_a, node_b],
            "sharedHostIdentity": true,
        }))
        .map_err(|error| error.to_string())?
    );
    cleanup(
        control,
        operator,
        first_root,
        fabric_project,
        fabric_id,
        test_root,
    );
    let _ = operator.execute(&second_root, "stop", None);
    Ok(())
}

#[cfg(unix)]
fn first_request_deployment_id(node_env: &str) -> String {
    node_env
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_DEPLOYMENT_ID="))
        .unwrap_or_default()
        .to_string()
}

#[cfg(unix)]
const NODE_SCOPED_PATH_KEYS: &[(&str, &str)] = &[
    (
        "ACTIUM_TERMINAL_PUBLIC_KEY_PATH",
        "keys/actium-terminal-public.pem",
    ),
    (
        "ACTIUM_OPERATOR_PUBLIC_KEY_PATH",
        "keys/actium-operator-public.pem",
    ),
    (
        "SITE_RUNTIME_BUNDLE_PUBLIC_KEY_PATH",
        "keys/actium-site-runtime-bundle-public.pem",
    ),
    ("RADIO_ARCHIVE_HOST_PATH", "persistent/radio-archive"),
];

#[cfg(unix)]
fn fixture_unix_path(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(unix)]
fn relocate_path_value(value: &str, from_root: &str, target_node: &std::path::Path) -> String {
    let from = from_root.trim_end_matches('/');
    let trimmed = value.trim();
    if let Some(relative) = trimmed
        .strip_prefix(from)
        .map(|item| item.trim_start_matches('/'))
    {
        return fixture_unix_path(&target_node.join(relative));
    }
    trimmed.to_string()
}

#[cfg(unix)]
fn relocate_node_env(document: &str, from_root: &str, target_node: &std::path::Path) -> String {
    let relocated = document
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return line.to_string();
            }
            let Some((key, value)) = trimmed.split_once('=') else {
                return line.to_string();
            };
            if let Some((_, relative)) = NODE_SCOPED_PATH_KEYS
                .iter()
                .find(|(candidate, _)| *candidate == key)
            {
                if !value.trim().is_empty() {
                    return format!("{key}={}", fixture_unix_path(&target_node.join(relative)));
                }
            }
            if !from_root.is_empty() && value.trim().starts_with(from_root.trim_end_matches('/')) {
                return format!(
                    "{key}={}",
                    relocate_path_value(value, from_root, target_node)
                );
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    if document.ends_with('\n') {
        format!("{relocated}\n")
    } else {
        relocated
    }
}

#[cfg(unix)]
fn relocate_commission_request(
    request: &actium_node_core::CommissionNodeRequest,
    target_node: &std::path::Path,
) -> Result<actium_node_core::CommissionNodeRequest, String> {
    let from_root = fixture_unix_path(std::path::Path::new(&request.install_dir));
    let target = fixture_unix_path(target_node);
    let mut relocated = request.clone();
    relocated.install_dir = target.clone();
    relocated.node_env = relocate_node_env(&request.node_env, &from_root, target_node);
    relocated.radio_archive_host_path = request.radio_archive_host_path.as_ref().map(|value| {
        if value.trim().is_empty() {
            value.clone()
        } else {
            fixture_unix_path(&target_node.join("persistent/radio-archive"))
        }
    });
    let target_prefix = target.trim_end_matches('/');
    for (key, _) in NODE_SCOPED_PATH_KEYS {
        let Some(value) = relocated.node_env.lines().find_map(|line| {
            line.strip_prefix(&format!("{key}="))
                .map(str::trim)
                .filter(|item| !item.is_empty())
        }) else {
            continue;
        };
        if !value.starts_with(target_prefix) {
            return Err(format!(
                "El request reubicado conserva {key} fuera de {target}: {value}"
            ));
        }
        if !from_root.is_empty() && value.starts_with(from_root.trim_end_matches('/')) {
            return Err(format!(
                "El request reubicado conserva {key} en el root original: {value}"
            ));
        }
    }
    Ok(relocated)
}

#[cfg(unix)]
fn run_ipc_resume(
    control: &mut std::process::Child,
    request: &actium_node_core::CommissionNodeRequest,
    node_root: &std::path::Path,
    nodes_root: &std::path::Path,
    fabrics_root: &std::path::Path,
    payload_root: &std::path::Path,
    fabric_project: &str,
    fabric_id: &str,
    test_root: &std::path::Path,
    installation_id: &str,
) -> Result<(), String> {
    use actium_node_core::{SupervisorClient, SupervisorCommand, SupervisorReply};
    use serde_json::{json, Value};
    use std::{
        fs,
        process::{Command, Stdio},
        thread,
        time::Duration,
    };

    if !cfg!(feature = "fault-injection") {
        return Err("ipc-resume requiere --features fault-injection.".to_string());
    }
    let supervisor_bin = supervisor_binary()?;
    let ipc_root = test_root.join("supervisor-ipc");
    fs::create_dir_all(&ipc_root).map_err(|error| error.to_string())?;
    let nodes = ipc_root.join("nodes");
    let fabrics = ipc_root.join("fabrics");
    fs::create_dir_all(&nodes).map_err(|error| error.to_string())?;
    fs::create_dir_all(&fabrics).map_err(|error| error.to_string())?;
    let ipc_key = ipc_root.join("ipc.key");
    fs::write(&ipc_key, b"actium-lab22-ipc-key-32bytes-minimum!!")
        .map_err(|error| error.to_string())?;
    let ownership = json!({
        "schema": 1,
        "owner": "actium-node-supervisor",
        "productChannel": "lab",
        "rootId": uuid::Uuid::new_v4().to_string(),
        "authorizedNodesRoot": nodes.to_string_lossy(),
        "authorizedFabricsRoot": fabrics.to_string_lossy(),
    });
    fs::write(
        ipc_root.join("root-ownership.json"),
        serde_json::to_vec_pretty(&ownership).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let config_path = ipc_root.join("supervisor.toml");
    let socket = ipc_root.join("supervisor.sock");
    let config = format!(
        "product_channel = \"lab\"\n\
socket_path = \"{}\"\n\
pipe_name = \"ActiumNodeSupervisorLabIpc\"\n\
service_name = \"ActiumNodeSupervisorLabIpc\"\n\
ipc_key_path = \"{}\"\n\
journal_path = \"{}\"\n\
authorized_nodes_root = \"{}\"\n\
authorized_fabrics_root = \"{}\"\n\
payload_root = \"{}\"\n\
log_dir = \"{}\"\n\
fabric_identity_path = \"{}\"\n\
fabric_id = \"auto\"\n\
fabric_project = \"actium-lab-fabric-ipc\"\n\
fabric_network = \"actium-lab-fabric-ipc\"\n\
operator_group = \"root\"\n\
network_reconcile_interval_seconds = 15\n\
root_ownership_marker = \"{}\"\n",
        socket.display(),
        ipc_key.display(),
        ipc_root.join("operations.sqlite3").display(),
        nodes.display(),
        fabrics.display(),
        payload_root.display(),
        ipc_root.join("logs").display(),
        ipc_root.join("fabric-identity.json").display(),
        ipc_root.join("root-ownership.json").display(),
    );
    fs::write(&config_path, config).map_err(|error| error.to_string())?;
    let target_node = nodes.join("actium-lab-ipc-01");
    fs::create_dir_all(&target_node).map_err(|error| error.to_string())?;
    let commission = relocate_commission_request(request, &target_node)?;
    let spawn = |fault: Option<&str>| -> Result<std::process::Child, String> {
        let mut command = Command::new(&supervisor_bin);
        let log_path = ipc_root.join("supervisor-spawn.log");
        let log = fs::File::create(&log_path).map_err(|error| error.to_string())?;
        command
            .arg("--config")
            .arg(&config_path)
            .current_dir(&ipc_root)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                log.try_clone().map_err(|error| error.to_string())?,
            ))
            .stderr(Stdio::from(log));
        if let Some(stage) = fault {
            command.env("ACTIUM_FAULT_INJECTION_STAGE", stage);
        } else {
            command.env_remove("ACTIUM_FAULT_INJECTION_STAGE");
        }
        command
            .spawn()
            .map_err(|error| format!("No se pudo arrancar Supervisor: {error}"))
    };
    let wait_ready = |child: &mut std::process::Child| -> Result<SupervisorClient, String> {
        let client = SupervisorClient::new(&socket, &ipc_key);
        for _ in 0..80 {
            if let Some(status) = child.try_wait().ok().flatten() {
                let log =
                    fs::read_to_string(ipc_root.join("supervisor-spawn.log")).unwrap_or_default();
                return Err(format!("Supervisor salio antes del ping ({status}): {log}"));
            }
            if let Ok(SupervisorReply::Pong { features, .. }) =
                client.request(SupervisorCommand::Ping)
            {
                if !features.iter().any(|value| value == "host_identity_v1") {
                    return Err(format!(
                        "Supervisor listo sin host_identity_v1: {features:?}"
                    ));
                }
                return Ok(client);
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err("Supervisor IPC no respondio al ping.".to_string())
    };
    let mut child = spawn(Some("commission.topology"))?;
    let client = wait_ready(&mut child).map_err(|error| {
        let _ = child.kill();
        error
    })?;
    let first = client.request(SupervisorCommand::CommissionNode(commission.clone()));
    let _ = child.kill();
    let _ = child.wait();
    let first_error = first.expect_err("el first install IPC debe fallar antes de topologia");
    if !first_error.contains("FAULT_INJECTED:commission.topology")
        && !first_error.contains("FIRST_INSTALL_ABORTED")
    {
        return Err(format!("Fallo IPC inesperado: {first_error}"));
    }
    let leftover_env = fs::read_to_string(target_node.join("node.env"))
        .map_err(|error| format!("leftover IPC sin node.env: {error}"))?;
    let leftover_host = leftover_env
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_HOST_INSTALLATION_ID="))
        .unwrap_or_default()
        .to_string();
    let leftover_node = leftover_env
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_NODE_INSTALLATION_ID="))
        .unwrap_or_default()
        .to_string();
    if leftover_node != installation_id
        || leftover_host == leftover_node
        || leftover_host.is_empty()
    {
        return Err(format!(
            "Leftover IPC mezclo identidades node={leftover_node} host={leftover_host}"
        ));
    }
    let leftover_terminal = leftover_env
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_TERMINAL_PUBLIC_KEY_PATH="))
        .unwrap_or_default();
    let target_prefix = fixture_unix_path(&target_node);
    if !leftover_terminal.starts_with(target_prefix.trim_end_matches('/')) {
        return Err(format!(
            "Leftover IPC conservo una ruta de clave fuera de {target_prefix}: {leftover_terminal}"
        ));
    }
    let mut restarted = spawn(None)?;
    let client = wait_ready(&mut restarted).map_err(|error| {
        let _ = restarted.kill();
        error
    })?;
    let mut retry = commission.clone();
    retry.resume_incomplete = true;
    let resumed = client.request(SupervisorCommand::CommissionNode(retry));
    let _ = restarted.kill();
    let _ = restarted.wait();
    let resumed = resumed?;
    let env_after =
        fs::read_to_string(target_node.join("node.env")).map_err(|error| error.to_string())?;
    let host_after = env_after
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_HOST_INSTALLATION_ID="))
        .unwrap_or_default();
    let node_after = env_after
        .lines()
        .find_map(|line| line.strip_prefix("ACTIUM_NODE_INSTALLATION_ID="))
        .unwrap_or_default();
    if host_after != leftover_host || node_after != leftover_node {
        return Err(format!(
            "Resume IPC derivo identidades leftover host={leftover_host} node={leftover_node} after host={host_after} node={node_after}"
        ));
    }
    let env_line = |contents: &str, key: &str| {
        contents
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
    };
    if env_line(&env_after, "ACTIUM_DEPLOYMENT_ID")
        != env_line(&leftover_env, "ACTIUM_DEPLOYMENT_ID")
        || env_line(&env_after, "ACTIUM_PROFILES") != env_line(&leftover_env, "ACTIUM_PROFILES")
        || env_line(&env_after, "SITE_CORE_PORT") != env_line(&leftover_env, "SITE_CORE_PORT")
    {
        return Err("Resume IPC derivo deployment, perfiles o puertos.".to_string());
    }
    if !env_line(&env_after, "ACTIUM_TERMINAL_PUBLIC_KEY_PATH")
        .starts_with(target_prefix.trim_end_matches('/'))
    {
        return Err("Resume IPC no conservo las rutas node-scoped en target_node.".to_string());
    }
    let topology: Value = serde_json::from_slice(
        &fs::read(target_node.join("state/runtime-topology.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if topology.get("hostInstallationId").and_then(Value::as_str) != Some(leftover_host.as_str()) {
        return Err(format!(
            "topology.hostInstallationId no coincide con HostIdentity: {topology}"
        ));
    }
    let _ = nodes_root;
    let _ = fabrics_root;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "pass",
            "mode": "ipc-resume",
            "nodeInstallationId": leftover_node,
            "hostInstallationId": leftover_host,
            "identitiesDistinct": leftover_host != leftover_node,
            "supervisorRestarted": true,
            "resume": match resumed {
                SupervisorReply::RuntimeAction(result) => result.message,
                _ => "ok".into(),
            },
        }))
        .map_err(|error| error.to_string())?
    );
    let operator = actium_node_core::RuntimeOperator::new_with_fabric(
        nodes_root,
        fabrics_root,
        payload_root,
        actium_node_core::FabricIdentity {
            fabric_id: fabric_id.to_string(),
            compose_project: fabric_project.to_string(),
            network_name: fabric_project.to_string(),
            host_id: None,
        },
        test_root.join("state/fabric-identity.json"),
    );
    cleanup(
        control,
        &operator,
        node_root,
        fabric_project,
        fabric_id,
        test_root,
    );
    let _ = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "docker compose -p actium-lab-fabric-ipc down --remove-orphans >/dev/null 2>&1 || true"
        ))
        .status();
    Ok(())
}

#[cfg(unix)]
fn supervisor_binary() -> Result<std::path::PathBuf, String> {
    use std::path::PathBuf;
    if let Ok(path) = std::env::var("ACTIUM_SUPERVISOR_BIN") {
        return Ok(PathBuf::from(path));
    }
    let candidate =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/debug/actium-node-supervisor");
    if candidate.is_file() {
        return Ok(candidate);
    }
    Err(format!(
        "No se encontro actium-node-supervisor en {}",
        candidate.display()
    ))
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
        stop_control_plane(control, test_root);
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
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    let _ = std::process::Command::new("docker")
        .args(["network", "rm", fabric_project])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if let Some(network) = deployment_network {
        let _ = std::process::Command::new("docker")
            .args(["network", "rm", &network])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
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
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    stop_control_plane(control, test_root);
    let _ = std::fs::remove_dir_all(test_root);
}

#[cfg(unix)]
fn stop_control_plane(control: &mut std::process::Child, test_root: &std::path::Path) {
    if let Ok(name) = std::fs::read_to_string(test_root.join("control-container")) {
        let name = name.trim();
        if name.starts_with("actium-cold-control-") {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", name])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
    let _ = control.kill();
    let _ = control.wait();
}
