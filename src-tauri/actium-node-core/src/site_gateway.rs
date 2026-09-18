//! Product-neutral host-shared Site Gateway contracts and allowlisted router.
//!
//! The gateway never proxies arbitrary localhost ports and never accepts
//! remote reverse-proxy configuration.  TLS/DNS provider automation is
//! optional; when absent the gateway emits an explicit provisioning plan.

use crate::site_identity::{site_network_identity, SiteNetworkIdentityV1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const SITE_GATEWAY_CONTRACT: &str = "actium.connectivity.site-gateway.v1";
pub const SITE_GATEWAY_MAX_BODY_BYTES: usize = 256 * 1024;

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
pub struct SiteGatewayConfigV1 {
    pub site_id: String,
    pub host_id: String,
    pub bind: String,
    pub identity: SiteNetworkIdentityV1,
    pub adapters: Vec<CapabilityAdapterAllowlistV1>,
    pub request_timeout_ms: u64,
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
                let _ = handle_connection(stream, &thread_config);
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

fn handle_connection(mut stream: TcpStream, config: &SiteGatewayConfigV1) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(config.request_timeout_ms.max(50))))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(config.request_timeout_ms.max(50))))
        .ok();
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer).map_err(|_| "SITE_GATEWAY_READ_FAILED".to_string())?;
    let request = std::str::from_utf8(&buffer[..read]).unwrap_or("");
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let headers: BTreeMap<String, String> = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    if request.len() > SITE_GATEWAY_MAX_BODY_BYTES {
        return write_json(&mut stream, 413, r#"{"ok":false,"status":"PAYLOAD_TOO_LARGE"}"#);
    }
    if path == "/health/live" {
        return write_json(
            &mut stream,
            200,
            &format!(
                r#"{{"ok":true,"status":"live","contract":"{SITE_GATEWAY_CONTRACT}","siteId":"{}"}}"#,
                config.site_id
            ),
        );
    }
    if path == "/health/ready" {
        let identity_ok = headers
            .get("x-actium-site-id")
            .map(|value| value == &config.site_id)
            .unwrap_or(true);
        let code = if identity_ok { 200 } else { 403 };
        return write_json(
            &mut stream,
            code,
            &format!(
                r#"{{"ok":{},"status":"{}","contract":"{SITE_GATEWAY_CONTRACT}","hostId":"{}"}}"#,
                identity_ok,
                if identity_ok { "ready" } else { "SITE_IDENTITY_MISMATCH" },
                config.host_id
            ),
        );
    }
    if method != "GET" && method != "POST" {
        return write_json(&mut stream, 405, r#"{"ok":false,"status":"METHOD_NOT_ALLOWED"}"#);
    }
    match adapter_for_path(&config.adapters, path) {
        Ok(adapter) => write_json(
            &mut stream,
            200,
            &format!(
                r#"{{"ok":true,"status":"ALLOWLISTED","capability":"{}","adapter":"{}"}}"#,
                adapter.capability, adapter.local_endpoint
            ),
        ),
        Err(error) => write_json(
            &mut stream,
            403,
            &format!(r#"{{"ok":false,"status":"{error}"}}"#),
        ),
    }
}

fn write_json(stream: &mut TcpStream, code: u16, body: &str) -> Result<(), String> {
    let reason = match code {
        200 => "OK",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
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

    #[test]
    fn local_http_health_and_allowlist() {
        let identity = site_network_identity("00ed1921-098e-4efd-b71d-fbc220278486").unwrap();
        let handle = start_site_gateway(SiteGatewayConfigV1 {
            site_id: identity.site_id.clone(),
            host_id: "host-1".into(),
            bind: "127.0.0.1:0".into(),
            identity,
            adapters: vec![CapabilityAdapterAllowlistV1 {
                capability: "test-product-capability".into(),
                local_endpoint: "http://127.0.0.1:8090".into(),
                path_prefix: "/v1/capability/test-product".into(),
            }],
            request_timeout_ms: 500,
        })
        .unwrap();
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
        assert!(get("/health/live").contains("\"status\":\"live\""));
        assert!(get("/health/ready").contains("\"status\":\"ready\""));
        assert!(get("/v1/capability/test-product").contains("ALLOWLISTED"));
        assert!(get("/secret").contains("SITE_GATEWAY_PATH_NOT_ALLOWLISTED"));
        handle.shutdown();
    }
}
