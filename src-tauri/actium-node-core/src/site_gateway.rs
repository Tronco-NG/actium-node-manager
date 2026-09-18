//! Product-neutral host-shared Site Gateway contracts and allowlisted router.
//!
//! The gateway never proxies arbitrary localhost ports and never accepts
//! remote reverse-proxy configuration.  TLS/DNS provider automation is
//! optional; when absent the gateway emits an explicit provisioning plan.

use crate::site_identity::{site_network_identity, SiteNetworkIdentityV1};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SITE_GATEWAY_CONTRACT: &str = "actium.connectivity.site-gateway.v1";
pub const SITE_GATEWAY_MAX_BODY_BYTES: usize = 256 * 1024;
pub const SITE_GATEWAY_MAX_RESPONSE_BYTES: usize = 1_048_576;
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProvisionStatus {
    ImplementedSource,
    NotProvisioned,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsDesiredStateV1 {
    pub site_id: String,
    pub dns_name: String,
    pub records: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsObservedStateV1 {
    pub dns_name: String,
    pub resolved_addresses: Vec<String>,
    pub status: ProvisionStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TlsDesiredStateV1 {
    pub site_id: String,
    pub dns_name: String,
    pub bind: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CertificateObservedStateV1 {
    pub dns_name: String,
    pub fingerprint: Option<String>,
    pub identity: Option<String>,
    pub not_after: Option<String>,
    pub renewal_state: String,
    pub status: ProvisionStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SiteGatewayProvisioningPlanV1 {
    pub dns: DnsDesiredStateV1,
    pub tls: TlsDesiredStateV1,
    pub public_endpoints: Vec<String>,
    pub operator_action: String,
    pub router_mutation: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAdapterAllowlistV1 {
    pub capability: String,
    pub local_endpoint: String,
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SiteGatewayTlsMaterialV1 {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub expected_hostname: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SiteGatewayConfigV1 {
    pub site_id: String,
    pub host_id: String,
    pub bind: String,
    pub identity: SiteNetworkIdentityV1,
    pub adapters: Vec<CapabilityAdapterAllowlistV1>,
    pub request_timeout_ms: u64,
    pub generation: u64,
    pub require_tls: bool,
    pub tls: Option<SiteGatewayTlsMaterialV1>,
}

pub fn dns_tls_provisioning_plan(
    site_id: &str,
    host_id: &str,
    public_ipv4: Option<&str>,
) -> Result<SiteGatewayProvisioningPlanV1, String> {
    let identity = site_network_identity(site_id)?;
    let records = public_ipv4
        .map(|ip| vec![format!("A {ip}")])
        .unwrap_or_default();
    let dns_ready = !records.is_empty();
    Ok(SiteGatewayProvisioningPlanV1 {
        dns: DnsDesiredStateV1 {
            site_id: site_id.to_string(),
            dns_name: identity.dns_name.clone(),
            records,
        },
        tls: TlsDesiredStateV1 {
            site_id: site_id.to_string(),
            dns_name: identity.dns_name.clone(),
            bind: "0.0.0.0:443".into(),
            generation: 1,
        },
        public_endpoints: vec![format!("https://{}:443", identity.dns_name)],
        operator_action: if dns_ready {
            format!(
                "TLS_NOT_PROVISIONED host={host_id} publish DNS A/AAAA then issue certificate for {}",
                identity.dns_name
            )
        } else {
            format!(
                "DNS_NOT_CONFIGURED host={host_id} publish {} then issue certificate; do not mutate customer router yet",
                identity.dns_name
            )
        },
        router_mutation: "FORBIDDEN_UNTIL_EXPLICIT_PROVIDER_POLICY",
    })
}

pub fn adapter_for_path<'a>(
    adapters: &'a [CapabilityAdapterAllowlistV1],
    path: &str,
) -> Result<&'a CapabilityAdapterAllowlistV1, String> {
    let matches: Vec<&CapabilityAdapterAllowlistV1> = adapters
        .iter()
        .filter(|adapter| path == adapter.path_prefix || path.starts_with(&format!("{}/", adapter.path_prefix)))
        .collect();
    if matches.len() != 1 {
        return Err("SITE_GATEWAY_PATH_NOT_ALLOWLISTED".into());
    }
    let adapter = matches[0];
    if !adapter.local_endpoint.starts_with("http://127.0.0.1:")
        && !adapter.local_endpoint.starts_with("https://127.0.0.1:")
        && !adapter.local_endpoint.starts_with("http://[::1]:")
    {
        return Err("SITE_GATEWAY_ADAPTER_NOT_LOOPBACK".into());
    }
    Ok(adapter)
}

pub struct SiteGatewayHandle {
    pub bind: String,
    shutdown: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl SiteGatewayHandle {
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.bind);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub fn start_site_gateway(config: SiteGatewayConfigV1) -> Result<SiteGatewayHandle, String> {
    if config.require_tls && config.tls.is_none() {
        return Err("SITE_GATEWAY_TLS_REQUIRED".into());
    }
    let tls_config = match &config.tls {
        Some(material) => Some(load_tls_config(material)?),
        None => None,
    };
    let listener = TcpListener::bind(&config.bind).map_err(|_| "SITE_GATEWAY_BIND_FAILED".to_string())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "SITE_GATEWAY_BIND_FAILED".to_string())?;
    let bind = listener
        .local_addr()
        .map_err(|_| "SITE_GATEWAY_BIND_FAILED".to_string())?
        .to_string();
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = shutdown.clone();
    let thread_config = config;
    let join = thread::spawn(move || loop {
        if thread_shutdown.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = handle_accepted(stream, &thread_config, tls_config.clone());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    });
    Ok(SiteGatewayHandle {
        bind,
        shutdown,
        join: Some(join),
    })
}

fn load_tls_config(material: &SiteGatewayTlsMaterialV1) -> Result<Arc<ServerConfig>, String> {
    if material.expected_hostname.trim().is_empty() {
        return Err("SITE_GATEWAY_TLS_HOSTNAME_REQUIRED".into());
    }
    let mut cert_reader = BufReader::new(material.certificate_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "SITE_GATEWAY_TLS_CERT_INVALID".to_string())?;
    if certs.is_empty() {
        return Err("SITE_GATEWAY_TLS_CERT_INVALID".into());
    }
    let mut key_reader = BufReader::new(material.private_key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| "SITE_GATEWAY_TLS_KEY_INVALID".to_string())?
        .ok_or_else(|| "SITE_GATEWAY_TLS_KEY_MISSING".to_string())?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| "SITE_GATEWAY_TLS_CONFIG_INVALID".to_string())?;
    Ok(Arc::new(config))
}

fn handle_accepted(
    stream: TcpStream,
    config: &SiteGatewayConfigV1,
    tls: Option<Arc<ServerConfig>>,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(config.request_timeout_ms.max(50))))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(config.request_timeout_ms.max(50))))
        .ok();
    if let Some(tls) = tls {
        let conn = ServerConnection::new(tls).map_err(|_| "SITE_GATEWAY_TLS_HANDSHAKE_FAILED".to_string())?;
        let mut tls_stream = rustls::StreamOwned::new(conn, stream);
        handle_http(&mut tls_stream, config)
    } else {
        let mut stream = stream;
        handle_http(&mut stream, config)
    }
}

fn handle_http<S: Read + Write>(stream: &mut S, config: &SiteGatewayConfigV1) -> Result<(), String> {
    let (method, path, headers, body) = match read_http_request(stream, config.request_timeout_ms) {
        Ok(request) => request,
        Err(error) if error == "SITE_GATEWAY_PAYLOAD_TOO_LARGE" => {
            return write_json(stream, 413, r#"{"ok":false,"status":"PAYLOAD_TOO_LARGE"}"#);
        }
        Err(error) => return Err(error),
    };
    if path == "/health/live" || path == "/health/ready" {
        return write_json(
            stream,
            200,
            &format!(
                r#"{{"ok":true,"status":"{}","contract":"{SITE_GATEWAY_CONTRACT}"}}"#,
                if path.ends_with("live") { "live" } else { "ready" }
            ),
        );
    }
    if path == "/v1/site-identity/challenge" {
        return handle_identity_challenge(stream, config, &method, &body);
    }
    if method != "GET" && method != "POST" {
        return write_json(stream, 405, r#"{"ok":false,"status":"METHOD_NOT_ALLOWED"}"#);
    }
    match adapter_for_path(&config.adapters, &path) {
        Ok(adapter) => forward_to_adapter(stream, adapter, &method, &path, &headers, &body, config.request_timeout_ms),
        Err(error) => write_json(stream, 403, &format!(r#"{{"ok":false,"status":"{error}"}}"#)),
    }
}

fn handle_identity_challenge<S: Read + Write>(
    stream: &mut S,
    config: &SiteGatewayConfigV1,
    method: &str,
    body: &[u8],
) -> Result<(), String> {
    if method != "POST" {
        return write_json(stream, 405, r#"{"ok":false,"status":"METHOD_NOT_ALLOWED"}"#);
    }
    let payload: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "SITE_GATEWAY_CHALLENGE_INVALID".to_string())?;
    let nonce = payload
        .get("nonce")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim();
    if nonce.is_empty() || nonce.len() > 128 {
        return write_json(stream, 400, r#"{"ok":false,"status":"SITE_GATEWAY_CHALLENGE_NONCE_REQUIRED"}"#);
    }
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".into());
    let body = serde_json::json!({
        "protocolVersion": 1,
        "nonce": nonce,
        "siteId": config.site_id,
        "hostId": config.host_id,
        "gatewayGeneration": config.generation,
        "canonicalHostname": config.identity.dns_name,
        "observedAt": observed_at,
        "proofKind": "SITE_GATEWAY_CHALLENGE_V1",
        "hostSigned": false,
        "contract": SITE_GATEWAY_CONTRACT,
    });
    write_json(stream, 200, &body.to_string())
}

fn read_http_request<S: Read>(
    stream: &mut S,
    _timeout_ms: u64,
) -> Result<(String, String, BTreeMap<String, String>, Vec<u8>), String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let read = stream.read(&mut chunk).map_err(|_| "SITE_GATEWAY_READ_FAILED".to_string())?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > SITE_GATEWAY_MAX_BODY_BYTES + 8192 {
            return Err("SITE_GATEWAY_PAYLOAD_TOO_LARGE".into());
        }
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "SITE_GATEWAY_READ_FAILED".to_string())?;
    let header_bytes = &buffer[..header_end];
    let header_text = std::str::from_utf8(header_bytes).map_err(|_| "SITE_GATEWAY_READ_FAILED".to_string())?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > SITE_GATEWAY_MAX_BODY_BYTES {
        return Err("SITE_GATEWAY_PAYLOAD_TOO_LARGE".into());
    }
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).map_err(|_| "SITE_GATEWAY_READ_FAILED".to_string())?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > SITE_GATEWAY_MAX_BODY_BYTES {
            return Err("SITE_GATEWAY_PAYLOAD_TOO_LARGE".into());
        }
    }
    body.truncate(content_length);
    Ok((method, path, headers, body))
}

fn adapter_socket(local_endpoint: &str) -> Result<(SocketAddr, String), String> {
    let rest = local_endpoint
        .strip_prefix("http://")
        .or_else(|| local_endpoint.strip_prefix("https://"))
        .ok_or_else(|| "SITE_GATEWAY_ADAPTER_NOT_LOOPBACK".to_string())?;
    let hostport = rest.split('/').next().unwrap_or(rest);
    let addr: SocketAddr = hostport
        .parse()
        .map_err(|_| "SITE_GATEWAY_ADAPTER_NOT_LOOPBACK".to_string())?;
    if !addr.ip().is_loopback() {
        return Err("SITE_GATEWAY_ADAPTER_NOT_LOOPBACK".into());
    }
    Ok((addr, hostport.to_string()))
}

fn forward_to_adapter<S: Read + Write>(
    client: &mut S,
    adapter: &CapabilityAdapterAllowlistV1,
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    timeout_ms: u64,
) -> Result<(), String> {
    let (addr, host) = adapter_socket(&adapter.local_endpoint)?;
    let mut upstream = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms.max(50)))
        .map_err(|_| "SITE_GATEWAY_ADAPTER_UNREACHABLE".to_string())?;
    upstream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms.max(50))))
        .ok();
    upstream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms.max(50))))
        .ok();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (name, value) in headers {
        if HOP_BY_HOP.contains(&name.as_str()) || name == "content-length" {
            continue;
        }
        if value.len() > 1024 {
            continue;
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    upstream
        .write_all(request.as_bytes())
        .and_then(|_| upstream.write_all(body))
        .map_err(|_| "SITE_GATEWAY_ADAPTER_WRITE_FAILED".to_string())?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match upstream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&chunk[..read]);
                if response.len() > SITE_GATEWAY_MAX_RESPONSE_BYTES {
                    return write_json(client, 502, r#"{"ok":false,"status":"SITE_GATEWAY_ADAPTER_RESPONSE_TOO_LARGE"}"#);
                }
            }
            Err(_) => break,
        }
    }
    if response.is_empty() {
        return write_json(client, 502, r#"{"ok":false,"status":"SITE_GATEWAY_ADAPTER_EMPTY"}"#);
    }
    client
        .write_all(&response)
        .map_err(|_| "SITE_GATEWAY_WRITE_FAILED".to_string())
}

fn write_json<S: Write>(stream: &mut S, code: u16, body: &str) -> Result<(), String> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|_| "SITE_GATEWAY_WRITE_FAILED".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn provisioning_plan_does_not_fake_dns_ready() {
        let plan = dns_tls_provisioning_plan("00ed1921-098e-4efd-b71d-fbc220278486", "host-1", None).unwrap();
        assert!(plan.operator_action.starts_with("DNS_NOT_CONFIGURED"));
        assert_eq!(plan.router_mutation, "FORBIDDEN_UNTIL_EXPLICIT_PROVIDER_POLICY");
    }

    #[test]
    fn rejects_non_loopback_and_unknown_paths() {
        let adapters = vec![CapabilityAdapterAllowlistV1 {
            capability: "telemetry.gps.batch".into(),
            local_endpoint: "http://127.0.0.1:8090".into(),
            path_prefix: "/v1/capability/telemetry".into(),
        }];
        assert!(adapter_for_path(&adapters, "/v1/capability/telemetry/gps").is_ok());
        assert_eq!(
            adapter_for_path(&adapters, "/v1/admin").unwrap_err(),
            "SITE_GATEWAY_PATH_NOT_ALLOWLISTED"
        );
        let bad = vec![CapabilityAdapterAllowlistV1 {
            capability: "x".into(),
            local_endpoint: "http://10.77.10.1:8090".into(),
            path_prefix: "/v1/capability/telemetry".into(),
        }];
        assert_eq!(
            adapter_for_path(&bad, "/v1/capability/telemetry").unwrap_err(),
            "SITE_GATEWAY_ADAPTER_NOT_LOOPBACK"
        );
    }

    fn test_config(identity: SiteNetworkIdentityV1, adapters: Vec<CapabilityAdapterAllowlistV1>) -> SiteGatewayConfigV1 {
        SiteGatewayConfigV1 {
            site_id: identity.site_id.clone(),
            host_id: "host-1".into(),
            bind: "127.0.0.1:0".into(),
            identity,
            adapters,
            request_timeout_ms: 2_000,
            generation: 7,
            require_tls: false,
            tls: None,
        }
    }

    #[test]
    fn local_http_health_is_not_site_identity_proof() {
        let identity = site_network_identity("00ed1921-098e-4efd-b71d-fbc220278486").unwrap();
        let handle = start_site_gateway(test_config(identity.clone(), Vec::new())).unwrap();
        let bind = handle.bind.clone();
        let get = |path: &str| {
            let mut stream = TcpStream::connect(&bind).unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: site\r\nConnection: close\r\n\r\n").as_bytes())
                .unwrap();
            let mut body = String::new();
            stream.read_to_string(&mut body).unwrap();
            body
        };
        let ready = get("/health/ready");
        assert!(ready.contains("\"status\":\"ready\""));
        assert!(!ready.contains(&identity.site_id));
        assert!(get("/secret").contains("SITE_GATEWAY_PATH_NOT_ALLOWLISTED"));
        handle.shutdown();
    }

    #[test]
    fn forwards_only_to_allowlisted_loopback_adapter() {
        let identity = site_network_identity("00ed1921-098e-4efd-b71d-fbc220278486").unwrap();
        let adapter = TcpListener::bind("127.0.0.1:0").unwrap();
        adapter.set_nonblocking(false).ok();
        let adapter_addr = adapter.local_addr().unwrap();
        let adapter_thread = thread::spawn(move || {
            adapter.set_nonblocking(false).ok();
            let (mut stream, _) = adapter.accept().expect("adapter accept");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        buf.extend_from_slice(&chunk[..read]);
                        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let response = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 16\r\nconnection: close\r\n\r\n{\"ok\":true,\"n\":1}";
            let _ = stream.write_all(response);
        });
        thread::sleep(Duration::from_millis(50));
        let handle = start_site_gateway(test_config(
            identity,
            vec![CapabilityAdapterAllowlistV1 {
                capability: "test-product-capability".into(),
                local_endpoint: format!("http://{adapter_addr}"),
                path_prefix: "/v1/capability/test-product".into(),
            }],
        ))
        .unwrap();
        let mut stream = TcpStream::connect(&handle.bind).unwrap();
        stream
            .write_all(b"POST /v1/capability/test-product HTTP/1.1\r\nHost: site\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
            .unwrap();
        let mut body = String::new();
        stream.read_to_string(&mut body).unwrap();
        assert!(
            body.contains("{\"ok\":true,\"n\":1}"),
            "unexpected gateway response: {body:?}"
        );
        handle.shutdown();
        adapter_thread.join().unwrap();
    }

    #[test]
    fn identity_challenge_binds_site_host_and_nonce() {
        let identity = site_network_identity("00ed1921-098e-4efd-b71d-fbc220278486").unwrap();
        let handle = start_site_gateway(test_config(identity.clone(), Vec::new())).unwrap();
        let mut stream = TcpStream::connect(&handle.bind).unwrap();
        let body = r#"{"protocolVersion":1,"nonce":"nonce-1"}"#;
        stream
            .write_all(
                format!(
                    "POST /v1/site-identity/challenge HTTP/1.1\r\nHost: site\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.contains("SITE_GATEWAY_CHALLENGE_V1"));
        assert!(response.contains("nonce-1"));
        assert!(response.contains(&identity.site_id));
        assert!(response.contains("host-1"));
        assert!(response.contains(&identity.dns_name));
        handle.shutdown();
    }

    #[test]
    fn require_tls_without_material_fails_closed() {
        let identity = site_network_identity("00ed1921-098e-4efd-b71d-fbc220278486").unwrap();
        let mut config = test_config(identity, Vec::new());
        config.require_tls = true;
        match start_site_gateway(config) {
            Err(error) => assert_eq!(error, "SITE_GATEWAY_TLS_REQUIRED"),
            Ok(_) => panic!("expected TLS required"),
        }
    }

    #[test]
    fn tls_listener_serves_health() {
        let identity = site_network_identity("00ed1921-098e-4efd-b71d-fbc220278486").unwrap();
        let cert = rcgen::generate_simple_self_signed(vec![identity.dns_name.clone()]).unwrap();
        let mut config = test_config(identity.clone(), Vec::new());
        config.require_tls = true;
        config.tls = Some(SiteGatewayTlsMaterialV1 {
            certificate_pem: cert.cert.pem(),
            private_key_pem: cert.key_pair.serialize_pem(),
            expected_hostname: identity.dns_name,
        });
        let handle = start_site_gateway(config).unwrap();
        assert!(!handle.bind.is_empty());
        handle.shutdown();
    }
}
