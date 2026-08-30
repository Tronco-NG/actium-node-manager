//! Headless Manager process client. It is built from the core workspace so
//! tests do not need to link the desktop Tauri runtime, while the desktop
//! commands use the same `StorageBackend` implementation.
use actium_node_core::{EnrollmentApplyRequest, SignedEnvelope, StorageBackend, StorageGrantApprovalRequest, StoragePreflightRequest};
use std::{env, fs, path::PathBuf, time::Duration};
fn value(flag: &str, args: &[String]) -> Option<String> { args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone()) }
fn required(flag: &str, args: &[String]) -> Result<String, String> { value(flag, args).ok_or_else(|| format!("{flag} requerido")) }
fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> { println!("{}", serde_json::to_string(value).map_err(|e| e.to_string())?); Ok(()) }
fn main() { if let Err(error) = run() { eprintln!("{error}"); std::process::exit(1); } }
fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let backend = StorageBackend::new(required("--socket", &args)?, required("--key", &args)?);
    match args.get(1).map(String::as_str).unwrap_or("status") {
        "discover" => print_json(&backend.discover()?),
        "status" => print_json(&backend.enrollment_status()?),
        "enroll" => { let center_bundle: SignedEnvelope = serde_json::from_slice(&fs::read(PathBuf::from(required("--bundle", &args)?)).map_err(|e| e.to_string())?).map_err(|e| format!("bundle invalido: {e}"))?; let enrollment_package: SignedEnvelope = serde_json::from_slice(&fs::read(PathBuf::from(required("--package", &args)?)).map_err(|e| e.to_string())?).map_err(|e| format!("package invalido: {e}"))?; print_json(&backend.apply_enrollment(EnrollmentApplyRequest { center_bundle, enrollment_package, enrollment_nonce: required("--nonce", &args)?, node_public_key: required("--node-key", &args)? })?) },
        "preflight" => print_json(&backend.preflight(StoragePreflightRequest { mountpoint: required("--mount", &args)?, subpath: value("--subpath", &args).unwrap_or_default(), capability: value("--capability", &args).unwrap_or_else(|| "telemetry".into()), deployment_id: value("--deployment", &args).unwrap_or_default() })?),
        "apply" => { let preflight: actium_node_core::StorageGrantPreflight = serde_json::from_slice(&fs::read(PathBuf::from(required("--preflight", &args)?)).map_err(|e| e.to_string())?).map_err(|e| format!("preflight invalido: {e}"))?; let approval: SignedEnvelope = serde_json::from_slice(&fs::read(PathBuf::from(required("--approval", &args)?)).map_err(|e| e.to_string())?).map_err(|e| format!("approval invalida: {e}"))?; print_json(&backend.apply_approval(StorageGrantApprovalRequest { preflight, approval })?) },
        "list" => print_json(&backend.list()?),
        "watch" => { let timeout = value("--timeout", &args).and_then(|v| v.parse().ok()).unwrap_or(30); print_json(&backend.wait_for_reconnect(Duration::from_secs(timeout))?) },
        _ => return Err("comando: discover|status|enroll|preflight|apply|list|watch".into()),
    }?;
    Ok(())
}
