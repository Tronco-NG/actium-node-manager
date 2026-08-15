use actium_node_core::{
    AttestationJournal, AttestationSigner, MaterialAttestationStatement, ReleaseManager,
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
            let manager = ReleaseManager::new(root);
            let _guard = manager.lock_mutation()?;
            fs::write(ready, b"ready\n").map_err(|error| error.to_string())?;
            thread::sleep(Duration::from_secs(2));
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

    let release_root = root.join("release-root");
    let ready = root.join("release-lock.ready");
    let mut holder = Command::new(&executable)
        .args([
            "--hold-release-lock",
            &release_root.to_string_lossy(),
            &ready.to_string_lossy(),
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
    let status = holder.wait().map_err(|error| error.to_string())?;
    if !status.success() {
        return Err(format!("Holder termino con {status}."));
    }
    ReleaseManager::new(&release_root).lock_mutation()?;

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
            generation: 1,
            runtime_release: Some("0.8.0-lab.test".to_string()),
            payload_digest: Some("a".repeat(64)),
            material_digest: "b".repeat(64),
            observed_at: "2026-08-15T00:00:00Z".to_string(),
            runtime_units: Vec::new(),
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
