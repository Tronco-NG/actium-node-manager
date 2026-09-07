//! Minimal HTTP boundary for the sovereign Authority Service.
//!
//! The default mode is deliberately UNINITIALIZED: starting this process does
//! not generate keys, create a trust hierarchy, or promote test material. The
//! fixture mode exists only for contract tests and is opt-in through an
//! explicit test-only environment variable.

use actium_node_core::{
    authority_capability, AuthorityKind, AuthorityService, AuthorityStatus,
    DurableAuthorityState, KeyProvider, SignedTrustBundle, SoftwareSealedKeyProvider,
    TestEphemeralKeyProvider, verify_signed_trust_bundle,
    TRUST_FABRIC_ALGORITHM,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const CONTRACT: &str = "actium-authority-service@1.0.0";
const MAX_BODY_BYTES: usize = 192 * 1024;

enum ServiceMode {
    Uninitialized,
    TestFixture(AuthorityService<TestEphemeralKeyProvider>),
    Durable {
        service: AuthorityService<SoftwareSealedKeyProvider>,
        trust_bundle: Option<SignedTrustBundle>,
    },
    Unavailable(String),
}

struct ServiceState {
    mode: ServiceMode,
    state_path: PathBuf,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs()).unwrap_or(0)
}

fn main() -> Result<(), String> {
    let listen = env::var("ACTIUM_AUTHORITY_LISTEN").unwrap_or_else(|_| "127.0.0.1:9443".to_string());
    let address: SocketAddr = listen.parse().map_err(|_| "AUTHORITY_SERVICE_LISTEN_INVALID".to_string())?;
    let token_file = env::var("ACTIUM_AUTHORITY_SERVICE_TOKEN_FILE").ok().filter(|value| !value.trim().is_empty());
    let expected_client_id = env::var("ACTIUM_AUTHORITY_SERVICE_EXPECTED_CLIENT_ID").ok().filter(|value| !value.trim().is_empty());
    if !address.ip().is_loopback() && token_file.is_none() {
        return Err("AUTHORITY_SERVICE_REMOTE_BIND_REQUIRES_SERVICE_AUTH".into());
    }
    if !address.ip().is_loopback() && env::var("ACTIUM_AUTHORITY_TLS_TERMINATED").as_deref() != Ok("true") {
        return Err("AUTHORITY_SERVICE_REMOTE_BIND_REQUIRES_TLS_TERMINATOR".into());
    }

    let fixture = env::var("ACTIUM_AUTHORITY_TEST_FIXTURE").as_deref() == Ok("1");
    if fixture && env::var("ACTIUM_ENVIRONMENT").as_deref() == Ok("production") {
        return Err("AUTHORITY_TEST_FIXTURE_FORBIDDEN_IN_PRODUCTION".into());
    }
    let state_path = authority_data_dir()?.join("authority-state.json");
    let mode = if fixture {
        ServiceMode::TestFixture(build_test_fixture()?)
    } else {
        load_durable_mode(&state_path)
    };
    let mode_name = match &mode {
        ServiceMode::TestFixture(_) => "test_fixture",
        ServiceMode::Durable { .. } => "durable",
        ServiceMode::Unavailable(_) => "unavailable",
        ServiceMode::Uninitialized => "uninitialized",
    };
    let state = Arc::new(Mutex::new(ServiceState { mode, state_path }));
    let listener = TcpListener::bind(address).map_err(|_| "AUTHORITY_SERVICE_BIND_FAILED".to_string())?;
    eprintln!("actium-authority-service listening on {} mode={mode_name}", address);
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let result = handle_connection(&mut stream, &state, token_file.as_deref(), expected_client_id.as_deref());
                if let Err(code) = result {
                    let status = authority_error_status(&code);
                    let _ = write_json(&mut stream, status, json!({ "ok": false, "code": code }));
                }
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

fn authority_data_dir() -> Result<PathBuf, String> {
    if let Some(value) = env::var_os("ACTIUM_AUTHORITY_DATA_DIR").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(value));
    }
    #[cfg(windows)]
    {
        let root = env::var_os("ProgramData").ok_or_else(|| "AUTHORITY_DATA_DIR_UNCONFIGURED".to_string())?;
        return Ok(PathBuf::from(root).join("Actium").join("authority"));
    }
    #[cfg(not(windows))]
    { Ok(PathBuf::from("/var/lib/actium/authority")) }
}

fn load_durable_mode(state_path: &Path) -> ServiceMode {
    if !state_path.is_file() { return ServiceMode::Uninitialized; }
    let sealing_key_file = match env::var_os("ACTIUM_AUTHORITY_SEALING_KEY_FILE") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => return ServiceMode::Unavailable("AUTHORITY_SEALING_KEY_FILE_UNCONFIGURED".into()),
    };
    let key_root = env::var_os("ACTIUM_AUTHORITY_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_path.parent().unwrap_or_else(|| Path::new(".")).join("keys"));
    let provider = match SoftwareSealedKeyProvider::from_sealing_key_file(key_root, sealing_key_file) {
        Ok(value) => value,
        Err(error) => return ServiceMode::Unavailable(error),
    };
    let bytes = match fs::read(state_path) {
        Ok(value) => value,
        Err(_) => return ServiceMode::Unavailable("AUTHORITY_STATE_READ_FAILED".into()),
    };
    let durable: DurableAuthorityState = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return ServiceMode::Unavailable("AUTHORITY_STATE_INVALID".into()),
    };
    match AuthorityService::from_durable_state(provider, durable) {
        Ok(value) => {
            let trust_bundle = match env::var_os("ACTIUM_AUTHORITY_TRUST_BUNDLE_FILE").filter(|value| !value.is_empty()) {
                Some(path) => {
                    let bytes = match fs::read(PathBuf::from(path)) {
                        Ok(bytes) => bytes,
                        Err(_) => return ServiceMode::Unavailable("AUTHORITY_TRUST_BUNDLE_UNAVAILABLE".into()),
                    };
                    let bundle: SignedTrustBundle = match serde_json::from_slice(&bytes) {
                        Ok(bundle) => bundle,
                        Err(_) => return ServiceMode::Unavailable("AUTHORITY_TRUST_BUNDLE_INVALID".into()),
                    };
                    if verify_signed_trust_bundle(&bundle, now(), value.trust_epoch()).is_err() {
                        return ServiceMode::Unavailable("AUTHORITY_TRUST_BUNDLE_INVALID".into());
                    }
                    Some(bundle)
                }
                None => None,
            };
            ServiceMode::Durable { service: value, trust_bundle }
        }
        Err(_) => ServiceMode::Unavailable("AUTHORITY_STATE_INVALID".into()),
    }
}

fn persist_durable_state(service: &AuthorityService<SoftwareSealedKeyProvider>, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|_| "AUTHORITY_STATE_DIRECTORY_FAILED")?; }
    let bytes = serde_json::to_vec_pretty(&service.durable_state()).map_err(|_| "AUTHORITY_STATE_SERIALIZE_FAILED")?;
    let temporary = path.with_extension("tmp");
    // The temporary name is owned by this service. Removing only this
    // derived file makes an interrupted write retryable without touching the
    // committed state or unrelated recovery artifacts.
    if temporary.exists() { let _ = fs::remove_file(&temporary); }
    let mut file = fs::OpenOptions::new().create_new(true).write(true).open(&temporary).map_err(|_| "AUTHORITY_STATE_TEMP_CREATE_FAILED")?;
    file.write_all(&bytes).map_err(|_| "AUTHORITY_STATE_WRITE_FAILED")?;
    file.sync_all().map_err(|_| "AUTHORITY_STATE_SYNC_FAILED")?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) { let _ = fs::remove_file(&temporary); return Err(format!("AUTHORITY_STATE_COMMIT_FAILED: {error}")); }
    Ok(())
}

fn build_test_fixture() -> Result<AuthorityService<TestEphemeralKeyProvider>, String> {
    let mut service = AuthorityService::new(TestEphemeralKeyProvider::default(), "actium-product-v1-test");
    let timestamp = now().saturating_sub(60);
    service.initialize_root("product-root", timestamp)?;
    service.issue_subordinate(
        "product-root",
        "deployment-authority",
        AuthorityKind::DeploymentAuthority,
        vec![authority_capability(AuthorityKind::DeploymentAuthority).into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "deployment-authority",
        "deployment-root",
        AuthorityKind::DeploymentRoot,
        vec![authority_capability(AuthorityKind::DeploymentRoot).into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "deployment-root",
        "center-authority",
        AuthorityKind::CenterAuthority,
        vec![
            authority_capability(AuthorityKind::CenterAuthority).into(),
            "center_bundle_signing".into(),
            "site_runtime_authority".into(),
        ],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "center-authority",
        "enrollment-authority",
        AuthorityKind::EnrollmentAuthority,
        vec!["host_enrollment".into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "product-root",
        "release-authority",
        AuthorityKind::ReleaseAuthority,
        vec![authority_capability(AuthorityKind::ReleaseAuthority).into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "release-authority",
        "product-signing-authority",
        AuthorityKind::ProductSigningAuthority,
        vec!["product_signing".into()],
        timestamp,
        None,
    )?;
    Ok(service)
}

fn handle_connection(stream: &mut TcpStream, state: &Arc<Mutex<ServiceState>>, token_file: Option<&str>, expected_client_id: Option<&str>) -> Result<(), String> {
    let request = read_request(stream)?;
    if request.path == "/health" && request.method == "GET" {
        let guard = state.lock().map_err(|_| "AUTHORITY_SERVICE_STATE_UNAVAILABLE".to_string())?;
        return write_json(stream, 200, health_payload(&guard.mode));
    }
    if request.method != "POST" || !request.path.starts_with("/v1/") {
        return write_json(stream, 405, json!({ "ok": false, "code": "AUTHORITY_METHOD_NOT_ALLOWED" }));
    }
    if request.headers.get("x-actium-authority-contract").map(String::as_str) != Some(CONTRACT) {
        return write_json(stream, 400, json!({ "ok": false, "code": "AUTHORITY_CONTRACT_REQUIRED" }));
    }
    if !authorized(&request.headers, token_file, expected_client_id)? {
        return write_json(stream, 401, json!({ "ok": false, "code": "AUTHORITY_SERVICE_AUTH_REQUIRED" }));
    }
    let body: Value = serde_json::from_slice(&request.body).map_err(|_| "AUTHORITY_REQUEST_INVALID".to_string())?;
    if body.get("contract").and_then(Value::as_str) != Some(CONTRACT) {
        return write_json(stream, 400, json!({ "ok": false, "code": "AUTHORITY_CONTRACT_INVALID" }));
    }
    require_request_context(&request.path, &body, expected_client_id, &request.headers)?;
    let response = {
        let mut guard = state.lock().map_err(|_| "AUTHORITY_SERVICE_STATE_UNAVAILABLE".to_string())?;
        let idempotency_key = body.get("idempotencyKey").and_then(Value::as_str).filter(|value| !value.is_empty());
        let request_digest = request_digest(&body)?;
        let cached = if let (ServiceMode::Durable { service, .. }, Some(key)) = (&guard.mode, idempotency_key) {
            service.idempotency_result(key, &request_digest)?
        } else { None };
        let response = if let Some(cached) = cached {
            cached
        } else {
            let response = dispatch(&mut guard.mode, &request.path, &body)?;
            if let (ServiceMode::Durable { service, .. }, Some(key)) = (&mut guard.mode, idempotency_key) {
                service.record_idempotency_result(key.to_string(), request_digest, response.clone());
            }
            response
        };
        if let ServiceMode::Durable { service, .. } = &guard.mode {
            persist_durable_state(service, &guard.state_path)?;
        }
        Ok::<Value, String>(response)
    }?;
    write_json(stream, 200, response)
}

fn request_digest(body: &Value) -> Result<String, String> {
    let canonical = actium_node_core::canonical_json(body)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn health_payload(mode: &ServiceMode) -> Value {
    match mode {
        ServiceMode::Durable { service, trust_bundle } => json!({ "ok": true, "status": "alive", "authorityState": if service.authorities().next().is_some() { "INITIALIZED" } else { "UNINITIALIZED" }, "trustBundleState": if trust_bundle.is_some() { "READY" } else { "UNCONFIGURED" }, "contract": CONTRACT }),
        ServiceMode::TestFixture(_) => json!({ "ok": true, "status": "alive", "authorityState": "TEST_FIXTURE", "contract": CONTRACT }),
        ServiceMode::Unavailable(code) => json!({ "ok": true, "status": "degraded", "authorityState": "UNAVAILABLE", "code": code, "contract": CONTRACT }),
        ServiceMode::Uninitialized => json!({ "ok": true, "status": "alive", "authorityState": "UNINITIALIZED", "contract": CONTRACT }),
    }
}

fn require_request_context(path: &str, body: &Value, expected_client_id: Option<&str>, headers: &HashMap<String, String>) -> Result<(), String> {
    if !matches!(path, "/v1/readiness" | "/v1/sign" | "/v1/verify" | "/v1/trust-bundle") { return Ok(()); }
    let expected_operation = match path {
        "/v1/readiness" => "readiness",
        "/v1/sign" => "sign",
        "/v1/verify" => "verify",
        "/v1/trust-bundle" => "trust_bundle",
        _ => unreachable!(),
    };
    if body.get("operation").and_then(Value::as_str) != Some(expected_operation) { return Err("AUTHORITY_OPERATION_MISMATCH".into()); }
    let request_id = body.get("requestId").and_then(Value::as_str).unwrap_or("");
    if request_id.is_empty() || request_id.len() > 128 { return Err("AUTHORITY_REQUEST_ID_REQUIRED".into()); }
    if let Some(header_request_id) = headers.get("x-actium-request-id") {
        if !constant_time_equal(request_id.as_bytes(), header_request_id.as_bytes()) { return Err("AUTHORITY_REQUEST_CONTEXT_MISMATCH".into()); }
    }
    if matches!(path, "/v1/sign" | "/v1/verify") {
        let idempotency = body.get("idempotencyKey").and_then(Value::as_str).unwrap_or("");
        if idempotency.is_empty() || idempotency.len() > 256 { return Err("AUTHORITY_IDEMPOTENCY_KEY_REQUIRED".into()); }
        if let Some(header_idempotency) = headers.get("x-actium-idempotency-key") {
            if !constant_time_equal(idempotency.as_bytes(), header_idempotency.as_bytes()) { return Err("AUTHORITY_REQUEST_CONTEXT_MISMATCH".into()); }
        }
    }
    let caller = body.get("caller").and_then(Value::as_str).unwrap_or("");
    let header_caller = headers.get("x-actium-service-id").map(String::as_str).unwrap_or("");
    if caller.is_empty() || caller.len() > 128 || header_caller.is_empty() || !constant_time_equal(caller.as_bytes(), header_caller.as_bytes()) {
        return Err("AUTHORITY_CALLER_MISMATCH".into());
    }
    if let Some(expected) = expected_client_id {
        if !constant_time_equal(caller.as_bytes(), expected.as_bytes()) { return Err("AUTHORITY_CALLER_MISMATCH".into()); }
    }
    Ok(())
}

fn authority_error_status(code: &str) -> u16 {
    if code == "TRUST_IDEMPOTENCY_KEY_REUSED" { return 409; }
    if matches!(code,
        "AUTHORITY_SERVICE_AUTH_REQUIRED" |
        "AUTHORITY_SERVICE_CREDENTIAL_UNAVAILABLE" |
        "AUTHORITY_CALLER_MISMATCH" |
        "AUTHORITY_CALLER_REQUIRED"
    ) { return 401; }
    if code.starts_with("AUTHORITY_REQUEST") || code.starts_with("AUTHORITY_IDEMPOTENCY") || code.contains("CONTEXT_MISMATCH") || code.contains("CONTRACT") || code.contains("OPERATION_MISMATCH") { return 400; }
    if code.contains("BOOTSTRAP") || code.contains("UNAVAILABLE") || code.contains("UNCONFIGURED") { return 503; }
    500
}

fn dispatch(mode: &mut ServiceMode, path: &str, body: &Value) -> Result<Value, String> {
    match mode {
        ServiceMode::Uninitialized => match path {
            "/v1/readiness" => {
                let capability = body.get("capability").and_then(Value::as_str).unwrap_or("");
                if capability.is_empty() { return Err("AUTHORITY_CAPABILITY_REQUIRED".into()); }
                Ok(json!({
                    "status": "unavailable",
                    "capability": capability,
                    "authorityId": Value::Null,
                    "keyId": Value::Null,
                    "fingerprint": Value::Null,
                    "code": "AUTHORITY_BOOTSTRAP_PENDING",
                    "reason": "OWNER_CEREMONY_REQUIRED"
                }))
            }
            "/v1/trust-bundle" | "/v1/sign" | "/v1/verify" => Err("AUTHORITY_BOOTSTRAP_PENDING".into()),
            _ => Err("AUTHORITY_OPERATION_NOT_FOUND".into()),
        },
        ServiceMode::TestFixture(service) => dispatch_fixture(service, path, body),
        ServiceMode::Durable { service, trust_bundle } => dispatch_durable(service, trust_bundle.as_ref(), path, body),
        ServiceMode::Unavailable(code) => Err(code.clone()),
    }
}

fn dispatch_durable(service: &mut AuthorityService<SoftwareSealedKeyProvider>, trust_bundle: Option<&SignedTrustBundle>, path: &str, body: &Value) -> Result<Value, String> {
    if path == "/v1/trust-bundle" {
        let bundle = trust_bundle.ok_or_else(|| "AUTHORITY_TRUST_BUNDLE_UNAVAILABLE".to_string())?;
        return serde_json::to_value(bundle).map_err(|_| "AUTHORITY_RESPONSE_INVALID".into());
    }
    dispatch_fixture(service, path, body)
}

fn dispatch_fixture<P: KeyProvider>(service: &mut AuthorityService<P>, path: &str, body: &Value) -> Result<Value, String> {
    let timestamp = now();
    match path {
        "/v1/readiness" => {
            let capability = body.get("capability").and_then(Value::as_str).ok_or_else(|| "AUTHORITY_CAPABILITY_REQUIRED".to_string())?;
            serde_json::to_value(service.readiness(capability, timestamp).map_err(|_| "AUTHORITY_CAPABILITY_UNAVAILABLE")?).map_err(|_| "AUTHORITY_RESPONSE_INVALID".into())
        }
        "/v1/trust-bundle" => {
            let root = service.authorities().find(|authority| authority.kind == AuthorityKind::ProductTrustRoot && authority.status == AuthorityStatus::Active).ok_or_else(|| "AUTHORITY_BOOTSTRAP_PENDING".to_string())?;
            serde_json::to_value(service.trust_bundle(&root.authority_id, timestamp, None)?).map_err(|_| "AUTHORITY_RESPONSE_INVALID".into())
        }
        "/v1/sign" => {
            let capability = body.get("capability").and_then(Value::as_str).ok_or_else(|| "AUTHORITY_CAPABILITY_REQUIRED".to_string())?;
            let payload = decode_field(body, "payload")?;
            let (readiness, signature) = service.sign_for_capability(capability, &payload, timestamp).map_err(|_| "AUTHORITY_CAPABILITY_UNAVAILABLE".to_string())?;
            Ok(json!({ "keyId": readiness.key_id, "signature": URL_SAFE_NO_PAD.encode(signature), "algorithm": TRUST_FABRIC_ALGORITHM }))
        }
        "/v1/verify" => {
            let capability = body.get("capability").and_then(Value::as_str).ok_or_else(|| "AUTHORITY_CAPABILITY_REQUIRED".to_string())?;
            let key_id = body.get("keyId").and_then(Value::as_str).ok_or_else(|| "AUTHORITY_KEY_ID_REQUIRED".to_string())?;
            let payload = decode_field(body, "payload")?;
            let signature = decode_field(body, "signature")?;
            service.verify_for_capability(capability, key_id, &payload, &signature, timestamp)?;
            Ok(json!({ "ok": true }))
        }
        _ => Err("AUTHORITY_OPERATION_NOT_FOUND".into()),
    }
}

fn decode_field(body: &Value, field: &str) -> Result<Vec<u8>, String> {
    let raw = body.get(field).and_then(Value::as_str).ok_or_else(|| "AUTHORITY_REQUEST_INVALID".to_string())?;
    URL_SAFE_NO_PAD.decode(raw).map_err(|_| "AUTHORITY_REQUEST_INVALID".into())
}

fn authorized(headers: &HashMap<String, String>, token_file: Option<&str>, expected_client_id: Option<&str>) -> Result<bool, String> {
    if let Some(expected_client_id) = expected_client_id {
        let actual = headers.get("x-actium-service-id").map(String::as_str).unwrap_or("");
        if !constant_time_equal(actual.as_bytes(), expected_client_id.as_bytes()) { return Ok(false); }
    }
    let Some(path) = token_file else { return Ok(expected_client_id.is_none() || headers.contains_key("x-actium-service-id")); };
    let expected = std::fs::read_to_string(path).map_err(|_| "AUTHORITY_SERVICE_CREDENTIAL_UNAVAILABLE".to_string())?;
    let expected = expected.trim();
    let actual = headers.get("authorization").map(String::as_str).unwrap_or("");
    let expected_header = format!("Bearer {expected}");
    Ok(constant_time_equal(actual.as_bytes(), expected_header.as_bytes()))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut bytes = Vec::with_capacity(8192);
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).map_err(|_| "AUTHORITY_REQUEST_READ_FAILED")?;
        if read == 0 { return Err("AUTHORITY_REQUEST_EOF".into()); }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_BODY_BYTES + 16 * 1024 { return Err("AUTHORITY_REQUEST_TOO_LARGE".into()); }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") { break index + 4; }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).map_err(|_| "AUTHORITY_REQUEST_INVALID")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| "AUTHORITY_REQUEST_INVALID".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or("").to_string();
    let path = request_parts.next().unwrap_or("").to_string();
    let version = request_parts.next().unwrap_or("");
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") { return Err("AUTHORITY_REQUEST_INVALID".into()); }
    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        if let Some((name, value)) = line.split_once(':') { headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string()); }
    }
    let content_length = headers.get("content-length").map(|value| value.parse::<usize>().ok()).flatten().unwrap_or(0);
    if content_length > MAX_BODY_BYTES { return Err("AUTHORITY_REQUEST_TOO_LARGE".into()); }
    while bytes.len() < header_end + content_length {
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).map_err(|_| "AUTHORITY_REQUEST_READ_FAILED")?;
        if read == 0 { return Err("AUTHORITY_REQUEST_EOF".into()); }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpRequest { method, path, headers, body: bytes[header_end..header_end + content_length].to_vec() })
}

fn write_json(stream: &mut TcpStream, status: u16, value: Value) -> Result<(), String> {
    let body = serde_json::to_vec(&value).map_err(|_| "AUTHORITY_RESPONSE_INVALID".to_string())?;
    let reason = match status { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 405 => "Method Not Allowed", 409 => "Conflict", _ => "Service Unavailable" };
    let header = format!("HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
    stream.write_all(header.as_bytes()).map_err(|_| "AUTHORITY_RESPONSE_WRITE_FAILED".to_string())?;
    stream.write_all(&body).map_err(|_| "AUTHORITY_RESPONSE_WRITE_FAILED".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_context_binds_body_to_headers_and_expected_caller() {
        let mut headers = HashMap::new();
        headers.insert("x-actium-request-id".into(), "request-1".into());
        headers.insert("x-actium-idempotency-key".into(), "sign-1".into());
        headers.insert("x-actium-service-id".into(), "center".into());
        let body = json!({ "operation": "sign", "requestId": "request-1", "idempotencyKey": "sign-1", "caller": "center" });
        require_request_context("/v1/sign", &body, Some("center"), &headers).unwrap();
    }

    #[test]
    fn machine_context_rejects_caller_substitution() {
        let mut headers = HashMap::new();
        headers.insert("x-actium-request-id".into(), "request-1".into());
        headers.insert("x-actium-idempotency-key".into(), "sign-1".into());
        headers.insert("x-actium-service-id".into(), "center".into());
        let body = json!({ "operation": "sign", "requestId": "request-1", "idempotencyKey": "sign-1", "caller": "other-service" });
        assert_eq!(require_request_context("/v1/sign", &body, Some("center"), &headers).unwrap_err(), "AUTHORITY_CALLER_MISMATCH");
    }
}
