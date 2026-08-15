use actium_node_core::{
    AttestationJournal, AttestationSigner, MaterialAttestationStatement, ReleaseManager,
    RuntimeOperator,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().collect::<Vec<_>>();
    match arguments.get(1).map(String::as_str) {
        Some("--hold-release-lock") => {
            let root = required_path(&arguments, 2)?;
            let ready = required_path(&arguments, 3)?;
            let release = required_path(&arguments, 4)?;
            let manager = ReleaseManager::new(root);
            let _guard = manager.lock_mutation()?;
            fs::write(ready, b"ready\n").map_err(|error| error.to_string())?;
            wait_file(&release, Duration::from_secs(10))?;
            Ok(())
        }
        Some("--hold-node-and-fabric") => {
            let node = required_path(&arguments, 2)?;
            let fabric = required_path(&arguments, 3)?;
            let node_ready = required_path(&arguments, 4)?;
            let acquire_fabric = required_path(&arguments, 5)?;
            let fabric_ready = required_path(&arguments, 6)?;
            let release = required_path(&arguments, 7)?;
            let _node = ReleaseManager::new(node).lock_mutation()?;
            fs::write(node_ready, b"ready\n").map_err(|error| error.to_string())?;
            wait_file(&acquire_fabric, Duration::from_secs(10))?;
            let _fabric = ReleaseManager::new(fabric).lock_mutation()?;
            fs::write(fabric_ready, b"ready\n").map_err(|error| error.to_string())?;
            wait_file(&release, Duration::from_secs(10))?;
            Ok(())
        }
        Some("--try-node-and-fabric") => {
            let node = required_path(&arguments, 2)?;
            let fabric = required_path(&arguments, 3)?;
            let node_ready = required_path(&arguments, 4)?;
            let acquire_fabric = required_path(&arguments, 5)?;
            let result = required_path(&arguments, 6)?;
            let _node = ReleaseManager::new(node).lock_mutation()?;
            fs::write(node_ready, b"ready\n").map_err(|error| error.to_string())?;
            wait_file(&acquire_fabric, Duration::from_secs(10))?;
            let outcome = ReleaseManager::new(fabric)
                .lock_mutation()
                .map(|_| "acquired".to_string())
                .unwrap_or_else(|error| error);
            fs::write(result, outcome).map_err(|error| error.to_string())?;
            Ok(())
        }
        Some("--publish-attestation") => {
            let root = required_path(&arguments, 2)?;
            publish_attestation(&root).map(|_| ())
        }
        Some(other) => Err(format!("Modo desconocido: {other}")),
        None => parent_gate(),
    }
}

fn parent_gate() -> Result<(), String> {
    let root = env::temp_dir().join(format!("actium-durable-state-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let executable = env::current_exe().map_err(|error| error.to_string())?;

    let nodes_root = root.join("nodes");
    let release_root = nodes_root.join("node-a");
    fs::create_dir_all(release_root.join("state")).map_err(|error| error.to_string())?;
    fs::write(release_root.join("state/runtime-topology.json"), b"{}\n")
        .map_err(|error| error.to_string())?;
    let ready = root.join("release-lock.ready");
    let release = root.join("release-lock.release");
    let mut holder = Command::new(&executable)
        .args([
            "--hold-release-lock",
            &release_root.to_string_lossy(),
            &ready.to_string_lossy(),
            &release.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("No se pudo iniciar holder: {error}"))?;
    wait_file(&ready, Duration::from_secs(10))?;
    let conflict = ReleaseManager::new(&release_root)
        .lock_mutation()
        .expect_err("el segundo proceso debe ser rechazado");
    if !conflict.contains("MUTATION_BUSY") {
        return Err(format!("Conflicto inesperado: {conflict}"));
    }
    let skipped =
        RuntimeOperator::new(&nodes_root, root.join("payload")).refresh_material_attestations()?;
    if skipped.len() != 1 || !skipped[0].contains("atestacion omitida") {
        return Err(format!("Reconciler no omitio mutacion activa: {skipped:?}"));
    }
    fs::write(&release, b"release\n").map_err(|error| error.to_string())?;
    let status = holder.wait().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("Holder termino con {status}."));
    }
    ReleaseManager::new(&release_root).lock_mutation()?;

    let fabric_root = root.join("fabrics/shared");
    let node_b = nodes_root.join("node-b");
    let node_a_ready = root.join("node-a.ready");
    let node_b_ready = root.join("node-b.ready");
    let acquire_a = root.join("node-a.acquire-fabric");
    let acquire_b = root.join("node-b.acquire-fabric");
    let fabric_ready = root.join("fabric.ready");
    let fabric_release = root.join("fabric.release");
    let fabric_result = root.join("fabric.result");
    let mut fabric_holder = Command::new(&executable)
        .args([
            "--hold-node-and-fabric",
            &release_root.to_string_lossy(),
            &fabric_root.to_string_lossy(),
            &node_a_ready.to_string_lossy(),
            &acquire_a.to_string_lossy(),
            &fabric_ready.to_string_lossy(),
            &fabric_release.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    wait_file(&node_a_ready, Duration::from_secs(10))?;
    fs::write(&acquire_a, b"go\n").map_err(|error| error.to_string())?;
    wait_file(&fabric_ready, Duration::from_secs(10))?;
    let mut fabric_contender = Command::new(&executable)
        .args([
            "--try-node-and-fabric",
            &node_b.to_string_lossy(),
            &fabric_root.to_string_lossy(),
            &node_b_ready.to_string_lossy(),
            &acquire_b.to_string_lossy(),
            &fabric_result.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    wait_file(&node_b_ready, Duration::from_secs(10))?;
    fs::write(&acquire_b, b"go\n").map_err(|error| error.to_string())?;
    wait_file(&fabric_result, Duration::from_secs(10))?;
    let contention = fs::read_to_string(&fabric_result).map_err(|error| error.to_string())?;
    if !contention.contains("MUTATION_BUSY") {
        return Err(format!("Contencion Fabric inesperada: {contention}"));
    }
    fs::write(&fabric_release, b"release\n").map_err(|error| error.to_string())?;
    for child in [&mut fabric_holder, &mut fabric_contender] {
        let status = child.wait().map_err(|error| error.to_string())?;
        if !status.success() {
            return Err(format!("Proceso Node/Fabric termino con {status}."));
        }
    }

    let attestation_root = root.join("attestation");
    let children = (0..8)
        .map(|_| {
            Command::new(&executable)
                .args(["--publish-attestation", &attestation_root.to_string_lossy()])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    for child in children {
        let output = child
            .wait_with_output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "Publisher fallo: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    let latest = AttestationJournal::new(attestation_root.join("state"))
        .latest()?
        .ok_or_else(|| "No existe atestacion final.".to_string())?;
    if latest.statement.sequence != 8 {
        return Err(format!(
            "Secuencia concurrente final {}, se esperaba 8.",
            latest.statement.sequence
        ));
    }

    println!("release_cross_process_lock=PASS");
    println!("attestation_reconciler_under_node_mutation=PASS skipped=true");
    println!("node_fabric_lock_order=PASS contender=MUTATION_BUSY deadlock=false");
    println!("attestation_cross_process_sequence=PASS highest=8 unique=8");
    let _ = fs::remove_dir_all(root);
    Ok(())
}

fn publish_attestation(root: &Path) -> Result<u64, String> {
    fs::create_dir_all(root).map_err(|error| error.to_string())?;
    let signer = AttestationSigner::load_or_create(root.join("identity.key"))?;
    let journal = AttestationJournal::new(root.join("state"));
    let envelope = journal.sign_and_publish(&signer, |sequence| {
        Ok(MaterialAttestationStatement {
            host_id: Uuid::nil().to_string(),
            deployment_id: Uuid::nil().to_string(),
            sequence,
            generation: u64::from(std::process::id()),
            runtime_release: Some("0.8.0-lab.test".to_string()),
            payload_digest: Some("a".repeat(64)),
            material_digest: "b".repeat(64),
            observed_at: "2026-08-15T00:00:00Z".to_string(),
            runtime_units: Vec::new(),
            fabric: None,
            journal_id: String::new(),
            attestation_identity_id: String::new(),
            identity_epoch: 0,
            release_revision: 1,
            topology_digest: "c".repeat(64),
            configuration_digest: "d".repeat(64),
            observation_started_at: "2026-08-15T00:00:00Z".to_string(),
            observation_completed_at: "2026-08-15T00:00:01Z".to_string(),
            journal_chain: Default::default(),
        })
    })?;
    Ok(envelope.statement.sequence)
}

fn wait_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if path.is_file() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("Timeout esperando {}.", path.display()))
}

fn required_path(arguments: &[String], index: usize) -> Result<PathBuf, String> {
    arguments
        .get(index)
        .map(PathBuf::from)
        .ok_or_else(|| format!("Falta argumento {index}."))
}
