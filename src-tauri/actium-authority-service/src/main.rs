//! Minimal HTTP boundary for the sovereign Authority Service.
//!
//! The default mode is deliberately UNINITIALIZED: starting this process does
//! not generate keys, create a trust hierarchy, or promote test material. The
//! fixture mode exists only for contract tests and is opt-in through an
//! explicit test-only environment variable.

use actium_node_core::{
    authority_capability, AuthorityKind, AuthorityService, AuthorityStatus,
    TestEphemeralKeyProvider, TRUST_FABRIC_ALGORITHM,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const CONTRACT: &str = "actium-authority-service@1.0.0";
const MAX_BODY_BYTES: usize = 192 * 1024;

enum ServiceMode {
    Uninitialized,
    TestFixture(AuthorityService<TestEphemeralKeyProvider>),
}

struct ServiceState {
    mode: ServiceMode,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs()).unwrap_or(0)
}

fn main() -> Result<(), String> {
    let listen = env::var("ACTIUM_AUTHORITY_LISTEN").unwrap_or_else(|_| "127.0.0.1:9443".to_string());
    let address: SocketAddr = listen.parse().map_err(|_| "AUTHORITY_SERVICE_LISTEN_INVALID".to_string())?;
    let token_file = env::var("ACTIUM_AUTHORITY_SERVICE_TOKEN_FILE").ok().filter(|value| !value.trim().is_empty());
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
    let state = Arc::new(Mutex::new(ServiceState {
        mode: if fixture { ServiceMode::TestFixture(build_test_fixture()?) } else { ServiceMode::Uninitialized },
    }));
    let listener = TcpListener::bind(address).map_err(|_| "AUTHORITY_SERVICE_BIND_FAILED".to_string())?;
    eprintln!("actium-authority-service listening on {} mode={}", address, if fixture { "test_fixture" } else { "uninitialized" });
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let result = handle_connection(&mut stream, &state, token_file.as_deref());
                if let Err(code) = result {
                    let status = if code.contains("BOOTSTRAP") || code.contains("UNAVAILABLE") { 503 } else { 500 };
                    let _ = write_json(&mut stream, status, json!({ "ok": false, "code": code }));
                }
            }
            Err(_) => continue,
        }
    }
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

fn handle_connection(stream: &mut TcpStream, state: &Arc<Mutex<ServiceState>>, token_file: Option<&str>) -> Result<(), String> {
    let request = read_request(stream)?;
    if request.path == "/health" && request.method == "GET" {
        return write_json(stream, 200, json!({ "ok": true, "status": "ready", "contract": CONTRACT }));
    }
    if request.method != "POST" || !request.path.starts_with("/v1/") {
        return write_json(stream, 405, json!({ "ok": false, "code": "AUTHORITY_METHOD_NOT_ALLOWED" }));
    }
    if request.headers.get("x-actium-authority-contract").map(String::as_str) != Some(CONTRACT) {
        return write_json(stream, 400, json!({ "ok": false, "code": "AUTHORITY_CONTRACT_REQUIRED" }));
    }
    if !authorized(&request.headers, token_file)? {
        return write_json(stream, 401, json!({ "ok": false, "code": "AUTHORITY_SERVICE_AUTH_REQUIRED" }));
    }
    let body: Value = serde_json::from_slice(&request.body).map_err(|_| "AUTHORITY_REQUEST_INVALID".to_string())?;
    if body.get("contract").and_then(Value::as_str) != Some(CONTRACT) {
        return write_json(stream, 400, json!({ "ok": false, "code": "AUTHORITY_CONTRACT_INVALID" }));
    }
    let response = {
        let mut guard = state.lock().map_err(|_| "AUTHORITY_SERVICE_STATE_UNAVAILABLE".to_string())?;
        dispatch(&mut guard.mode, &request.path, &body)
    }?;
    write_json(stream, 200, response)
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
    }
}

fn dispatch_fixture(service: &mut AuthorityService<TestEphemeralKeyProvider>, path: &str, body: &Value) -> Result<Value, String> {
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

fn authorized(headers: &HashMap<String, String>, token_file: Option<&str>) -> Result<bool, String> {
    let Some(path) = token_file else { return Ok(true); };
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
    let reason = match status { 200 => "OK", 400 => "Bad Request", 401 => "Unauthorized", 405 => "Method Not Allowed", _ => "Service Unavailable" };
    let header = format!("HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
    stream.write_all(header.as_bytes()).map_err(|_| "AUTHORITY_RESPONSE_WRITE_FAILED".to_string())?;
    stream.write_all(&body).map_err(|_| "AUTHORITY_RESPONSE_WRITE_FAILED".to_string())
}
