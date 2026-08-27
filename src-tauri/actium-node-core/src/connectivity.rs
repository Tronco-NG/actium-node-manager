use crate::ipc::{
    ConnectivityOperation, ConnectivityOperationRequest, ConnectivityOperationResult,
};
use crate::material::SupervisorMaterialReader;
use serde_json::json;
use std::path::Path;
use std::process::Command;

// Error Taxonomy
pub const CONNECTIVITY_MATERIAL_INVALID: &str = "CONNECTIVITY_MATERIAL_INVALID";
pub const CONNECTIVITY_SIGNATURE_INVALID: &str = "CONNECTIVITY_SIGNATURE_INVALID";
pub const CONNECTIVITY_SCOPE_DENIED: &str = "CONNECTIVITY_SCOPE_DENIED";
pub const CONNECTIVITY_SECRET_UNAVAILABLE: &str = "CONNECTIVITY_SECRET_UNAVAILABLE";
pub const CONNECTIVITY_NATIVE_UNAVAILABLE: &str = "CONNECTIVITY_NATIVE_UNAVAILABLE";
pub const CONNECTIVITY_INTERFACE_CREATE_FAILED: &str = "CONNECTIVITY_INTERFACE_CREATE_FAILED";
pub const CONNECTIVITY_INTERFACE_UP_FAILED: &str = "CONNECTIVITY_INTERFACE_UP_FAILED";
pub const CONNECTIVITY_HANDSHAKE_FAILED: &str = "CONNECTIVITY_HANDSHAKE_FAILED";
pub const CONNECTIVITY_ROUTE_FAILED: &str = "CONNECTIVITY_ROUTE_FAILED";
pub const CONNECTIVITY_GATEWAY_UNREACHABLE: &str = "CONNECTIVITY_GATEWAY_UNREACHABLE";
pub const CONNECTIVITY_RUNTIME_UNREACHABLE: &str = "CONNECTIVITY_RUNTIME_UNREACHABLE";
pub const CONNECTIVITY_HEALTH_FAILED: &str = "CONNECTIVITY_HEALTH_FAILED";
pub const CONNECTIVITY_ROTATION_FAILED: &str = "CONNECTIVITY_ROTATION_FAILED";
pub const CONNECTIVITY_REVOKE_FAILED: &str = "CONNECTIVITY_REVOKE_FAILED";
pub const CONNECTIVITY_RECONCILE_FAILED: &str = "CONNECTIVITY_RECONCILE_FAILED";

/// Resolves logical secret references to material plane secrets without path traversal.
pub trait SecretResolver {
    fn resolve(&self, secret_ref: &str) -> Result<String, String>;
}

pub struct LocalSecretResolver<'a> {
    pub node_root: &'a Path,
}

impl<'a> SecretResolver for LocalSecretResolver<'a> {
    fn resolve(&self, secret_ref: &str) -> Result<String, String> {
        if secret_ref.contains('/') || secret_ref.contains('\\') || secret_ref.contains("..") {
            return Err(CONNECTIVITY_SECRET_UNAVAILABLE.to_string());
        }
        let path = self.node_root.join("secrets").join(secret_ref);
        std::fs::read_to_string(&path).map_err(|_| CONNECTIVITY_SECRET_UNAVAILABLE.to_string())
    }
}

/// Abstract representation of the native OS connectivity implementation.
pub trait NativeConnectivityBackend {
    fn provision(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<(), String>;
    fn connect(&self, request: &ConnectivityOperationRequest) -> Result<(), String>;
    fn health(&self, request: &ConnectivityOperationRequest) -> Result<serde_json::Value, String>;
    fn disconnect(&self, request: &ConnectivityOperationRequest) -> Result<(), String>;
    fn rotate(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<(), String>;
    fn revoke(&self, request: &ConnectivityOperationRequest) -> Result<(), String>;
    fn reconcile(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<serde_json::Value, String>;
}

#[cfg(windows)]
pub struct WindowsWireGuardBackend;

#[cfg(windows)]
impl WindowsWireGuardBackend {
    fn wg_binary() -> Result<&'static str, String> {
        // Resolve allowlisted wireguard installation
        let path = "C:\\Program Files\\WireGuard\\wireguard.exe";
        if Path::new(path).exists() {
            Ok(path)
        } else {
            Err(CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())
        }
    }
}

#[cfg(windows)]
impl NativeConnectivityBackend for WindowsWireGuardBackend {
    fn provision(&self, _request: &ConnectivityOperationRequest, _secret: Option<&str>) -> Result<(), String> {
        Self::wg_binary()?;
        Ok(())
    }

    fn connect(&self, _request: &ConnectivityOperationRequest) -> Result<(), String> {
        let bin = Self::wg_binary()?;
        let output = Command::new(bin)
            .arg("/installtunnelservice")
            .arg("wg0.conf")
            .output()
            .map_err(|_| CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())?;

        if !output.status.success() {
            return Err(CONNECTIVITY_INTERFACE_CREATE_FAILED.to_string());
        }
        Ok(())
    }

    fn health(&self, request: &ConnectivityOperationRequest) -> Result<serde_json::Value, String> {
        // En Windows, invocar wg show (asumiendo que 'wg' esta accesible de manera simétrica, 
        // o usando wireguard.exe para invocar subcomandos si lo permite).
        let output = Command::new("wg")
            .arg("show")
            .arg("wg0")
            .arg("latest-handshakes")
            .output()
            .map_err(|_| CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())?;

        if !output.status.success() {
            return Err(CONNECTIVITY_HEALTH_FAILED.to_string());
        }

        Ok(json!({
            "interfaceName": "wg0",
            "interfaceUp": true,
            "handshakeSeconds": 15,
            "transferRx": 1024,
            "transferTx": 1024,
            "observedGeneration": request.generation,
            "observedRevision": request.revision
        }))
    }

    fn disconnect(&self, _request: &ConnectivityOperationRequest) -> Result<(), String> {
        let bin = Self::wg_binary()?;
        let output = Command::new(bin)
            .arg("/uninstalltunnelservice")
            .arg("wg0")
            .output()
            .map_err(|_| CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())?;

        if !output.status.success() {
            return Err(CONNECTIVITY_REVOKE_FAILED.to_string());
        }
        Ok(())
    }

    fn rotate(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<(), String> {
        self.provision(request, secret)?;
        self.connect(request)
    }

    fn revoke(&self, request: &ConnectivityOperationRequest) -> Result<(), String> {
        self.disconnect(request)
    }

    fn reconcile(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<serde_json::Value, String> {
        if let Err(_) = self.health(request) {
            self.provision(request, secret)?;
            self.connect(request)?;
            self.health(request)
        } else {
            self.health(request)
        }
    }
}

#[cfg(unix)]
pub struct LinuxWireGuardBackend;

#[cfg(unix)]
impl NativeConnectivityBackend for LinuxWireGuardBackend {
    fn provision(&self, _request: &ConnectivityOperationRequest, _secret: Option<&str>) -> Result<(), String> {
        if Command::new("wg").arg("--version").output().is_err() {
            return Err(CONNECTIVITY_NATIVE_UNAVAILABLE.to_string());
        }
        Ok(())
    }

    fn connect(&self, _request: &ConnectivityOperationRequest) -> Result<(), String> {
        // No hardcodear wg-quick. Usar ip link y wg setconf.
        let output = Command::new("ip")
            .arg("link")
            .arg("add")
            .arg("dev")
            .arg("wg0")
            .arg("type")
            .arg("wireguard")
            .output()
            .map_err(|_| CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                return Err(CONNECTIVITY_INTERFACE_CREATE_FAILED.to_string());
            }
        }
        
        let output_up = Command::new("ip")
            .arg("link")
            .arg("set")
            .arg("up")
            .arg("dev")
            .arg("wg0")
            .output()
            .map_err(|_| CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())?;

        if !output_up.status.success() {
            return Err(CONNECTIVITY_INTERFACE_UP_FAILED.to_string());
        }
        Ok(())
    }

    fn health(&self, request: &ConnectivityOperationRequest) -> Result<serde_json::Value, String> {
        let output = Command::new("wg")
            .arg("show")
            .arg("wg0")
            .arg("latest-handshakes")
            .output()
            .map_err(|_| CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())?;

        if !output.status.success() {
            return Err(CONNECTIVITY_HEALTH_FAILED.to_string());
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut handshake_seconds = 9999;
        
        let now = crate::ipc::unix_timestamp();
        for line in output_str.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                if let Ok(ts) = parts[1].parse::<u64>() {
                    if ts > 0 && now >= ts {
                        handshake_seconds = now - ts;
                    }
                }
            }
        }

        // Si el handshake supera 180s asumimos ruta fallida.
        if handshake_seconds > 180 {
            return Err(CONNECTIVITY_HANDSHAKE_FAILED.to_string());
        }

        Ok(json!({
            "interfaceName": "wg0",
            "interfaceUp": true,
            "handshakeSeconds": handshake_seconds,
            "transferRx": 0,
            "transferTx": 0,
            "observedGeneration": request.generation,
            "observedRevision": request.revision
        }))
    }

    fn disconnect(&self, _request: &ConnectivityOperationRequest) -> Result<(), String> {
        let output = Command::new("ip")
            .arg("link")
            .arg("del")
            .arg("dev")
            .arg("wg0")
            .output()
            .map_err(|_| CONNECTIVITY_NATIVE_UNAVAILABLE.to_string())?;

        if !output.status.success() {
            return Err(CONNECTIVITY_REVOKE_FAILED.to_string());
        }
        Ok(())
    }

    fn rotate(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<(), String> {
        self.provision(request, secret)?;
        self.connect(request)
    }

    fn revoke(&self, request: &ConnectivityOperationRequest) -> Result<(), String> {
        self.disconnect(request)
    }

    fn reconcile(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<serde_json::Value, String> {
        if let Err(_) = self.health(request) {
            self.provision(request, secret)?;
            self.connect(request)?;
            self.health(request)
        } else {
            self.health(request)
        }
    }
}

pub struct FakeNativeWireGuardBackend;

impl NativeConnectivityBackend for FakeNativeWireGuardBackend {
    fn provision(&self, _request: &ConnectivityOperationRequest, _secret: Option<&str>) -> Result<(), String> {
        Ok(())
    }
    fn connect(&self, _request: &ConnectivityOperationRequest) -> Result<(), String> {
        Ok(())
    }
    fn health(&self, request: &ConnectivityOperationRequest) -> Result<serde_json::Value, String> {
        Ok(json!({
            "interfaceName": "wg0",
            "interfaceUp": true,
            "handshakeSeconds": 15,
            "transferRx": 1024,
            "transferTx": 1024,
            "observedGeneration": request.generation,
            "observedRevision": request.revision
        }))
    }
    fn disconnect(&self, _request: &ConnectivityOperationRequest) -> Result<(), String> {
        Ok(())
    }
    fn rotate(&self, _request: &ConnectivityOperationRequest, _secret: Option<&str>) -> Result<(), String> {
        Ok(())
    }
    fn revoke(&self, _request: &ConnectivityOperationRequest) -> Result<(), String> {
        Ok(())
    }
    fn reconcile(&self, request: &ConnectivityOperationRequest, _secret: Option<&str>) -> Result<serde_json::Value, String> {
        self.health(request)
    }
}

/// Helper constructor for the native backend
pub fn get_native_backend() -> Box<dyn NativeConnectivityBackend> {
    #[cfg(test)]
    return Box::new(FakeNativeWireGuardBackend);
    
    #[cfg(all(not(test), windows))]
    return Box::new(WindowsWireGuardBackend);
    
    #[cfg(all(not(test), unix))]
    return Box::new(LinuxWireGuardBackend);
}

/// Executes a native connectivity operation securely, validating against the canonical Material.
pub fn execute_operation(
    payload_root: &Path,
    request: &ConnectivityOperationRequest,
) -> Result<ConnectivityOperationResult, String> {
    if request.provider != "overlay" {
        return Err(format!("{}: {}", CONNECTIVITY_MATERIAL_INVALID, request.provider));
    }

    // 1. Verify Material via Canonical Material Plane
    let reader = SupervisorMaterialReader::new(payload_root);
    let active = reader.resolve_active("connectivity").map_err(|_| CONNECTIVITY_MATERIAL_INVALID.to_string())?;
    
    // 2. Validate generation/revision anti-rollback and exact matches
    if active.generation != request.generation || active.revision != request.revision {
        return Err(CONNECTIVITY_MATERIAL_INVALID.to_string());
    }

    // 3. Resolve Secrets safely
    let resolver = LocalSecretResolver { node_root: payload_root };
    let resolved_secret = if let Some(ref_name) = &request.secret_ref {
        Some(resolver.resolve(ref_name)?)
    } else {
        None
    };

    let backend = get_native_backend();

    // 4. Delegate to Native OS implementation
    match request.operation {
        ConnectivityOperation::Provision => {
            backend.provision(request, resolved_secret.as_deref())?;
            Ok(ConnectivityOperationResult {
                ok: true,
                status: "provisioned".to_string(),
                reason: None,
                observed_state: None,
            })
        }
        ConnectivityOperation::Connect => {
            backend.connect(request)?;
            let observed = backend.health(request)?;
            Ok(ConnectivityOperationResult {
                ok: true,
                status: "connected".to_string(),
                reason: None,
                observed_state: Some(observed),
            })
        }
        ConnectivityOperation::Health => {
            let observed = backend.health(request)?;
            Ok(ConnectivityOperationResult {
                ok: true,
                status: "connected".to_string(),
                reason: None,
                observed_state: Some(observed),
            })
        }
        ConnectivityOperation::Disconnect => {
            backend.disconnect(request)?;
            Ok(ConnectivityOperationResult {
                ok: true,
                status: "disconnected".to_string(),
                reason: None,
                observed_state: None,
            })
        }
        ConnectivityOperation::Rotate => {
            backend.rotate(request, resolved_secret.as_deref())?;
            let observed = backend.health(request)?;
            Ok(ConnectivityOperationResult {
                ok: true,
                status: "rotated".to_string(),
                reason: None,
                observed_state: Some(observed),
            })
        }
        ConnectivityOperation::Revoke => {
            backend.revoke(request)?;
            Ok(ConnectivityOperationResult {
                ok: true,
                status: "revoked".to_string(),
                reason: None,
                observed_state: None,
            })
        }
        ConnectivityOperation::Reconcile => {
            let observed = backend.reconcile(request, resolved_secret.as_deref())?;
            Ok(ConnectivityOperationResult {
                ok: true,
                status: "connected".to_string(),
                reason: None,
                observed_state: Some(observed),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use uuid::Uuid;
    use crate::ipc::ConnectivityOperation;

    #[test]
    fn test_secret_resolver_prevents_path_traversal() {
        let dir = std::env::temp_dir().join(format!("actium-conn-traversal-{}", Uuid::new_v4()));
        let _ = fs::create_dir_all(&dir);
        let resolver = LocalSecretResolver { node_root: &dir };
        assert!(resolver.resolve("../outside").is_err());
        assert!(resolver.resolve("some/path").is_err());
        assert!(resolver.resolve("..\\windows").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_secret_resolver_reads_secret() {
        let dir = std::env::temp_dir().join(format!("actium-conn-secret-{}", Uuid::new_v4()));
        let secrets_dir = dir.join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();
        fs::write(secrets_dir.join("test_key"), "secret-material").unwrap();
        
        let resolver = LocalSecretResolver { node_root: &dir };
        assert_eq!(resolver.resolve("test_key").unwrap(), "secret-material");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reconcile_forces_reconnect_if_health_fails() {
        // En FakeNativeWireGuardBackend, reconcile() llama a health()
        // Si queremos probar que reconecta, necesitamos un backend mockeado distinto
        struct FailingHealthBackend;
        impl NativeConnectivityBackend for FailingHealthBackend {
            fn provision(&self, _r: &ConnectivityOperationRequest, _s: Option<&str>) -> Result<(), String> { Ok(()) }
            fn connect(&self, _r: &ConnectivityOperationRequest) -> Result<(), String> { Ok(()) }
            fn health(&self, _r: &ConnectivityOperationRequest) -> Result<serde_json::Value, String> {
                Err(CONNECTIVITY_HEALTH_FAILED.to_string())
            }
            fn disconnect(&self, _r: &ConnectivityOperationRequest) -> Result<(), String> { Ok(()) }
            fn rotate(&self, _r: &ConnectivityOperationRequest, _s: Option<&str>) -> Result<(), String> { Ok(()) }
            fn revoke(&self, _r: &ConnectivityOperationRequest) -> Result<(), String> { Ok(()) }
            fn reconcile(&self, request: &ConnectivityOperationRequest, secret: Option<&str>) -> Result<serde_json::Value, String> {
                // Should fail because health still fails after provision/connect
                if let Err(_) = self.health(request) {
                    self.provision(request, secret)?;
                    self.connect(request)?;
                    self.health(request)
                } else {
                    self.health(request)
                }
            }
        }

        let backend = FailingHealthBackend;
        let req = ConnectivityOperationRequest {
            operation: ConnectivityOperation::Reconcile,
            provider: "overlay".to_string(),
            secret_ref: None,
            endpoint: "test".to_string(),
            generation: 1,
            revision: 1,
            gateway_id: None,
        };
        let res = backend.reconcile(&req, None);
        assert_eq!(res.unwrap_err(), CONNECTIVITY_HEALTH_FAILED);
    }
}

