use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};

const DEFAULT_SOURCE: &str = "host-control-plane-config";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ControlPlaneConfigDocument {
    control_plane_url: String,
    #[serde(default)]
    host_enrollment_endpoint: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActiumControlPlaneConfig {
    pub control_plane_url: Option<String>,
    pub host_enrollment_endpoint: Option<String>,
    pub environment: Option<String>,
    pub source: String,
    pub config_path: String,
    pub status: String,
    pub reason: Option<String>,
}

fn canonical_endpoint(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty()
        || !value.starts_with("https://")
        || value.chars().any(char::is_whitespace)
        || value.contains('#')
        || value.contains('?')
    {
        return None;
    }
    Some(value.to_string())
}

fn loopback_http_endpoint(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('/');
    if value.is_empty()
        || !value.starts_with("http://")
        || value.chars().any(char::is_whitespace)
        || value.contains('#')
        || value.contains('?')
    {
        return None;
    }
    let authority = value.strip_prefix("http://")?.split('/').next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let remainder = &authority[close + 1..];
        if !remainder.is_empty() {
            let port = remainder.strip_prefix(':')?;
            if port.is_empty() || port.parse::<u16>().is_err() {
                return None;
            }
        }
        &authority[1..close]
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') || port.is_empty() || port.parse::<u16>().is_err() {
            return None;
        }
        host
    } else {
        authority
    };
    if !matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return None;
    }
    Some(value.to_string())
}

fn canonical_host_enrollment_endpoint(value: &str) -> Option<String> {
    canonical_endpoint(value).or_else(|| loopback_http_endpoint(value))
}

fn unconfigured(path: &PathBuf, source: &str, reason: Option<&str>) -> ActiumControlPlaneConfig {
    ActiumControlPlaneConfig {
        control_plane_url: None,
        host_enrollment_endpoint: None,
        environment: None,
        source: source.to_string(),
        config_path: path.to_string_lossy().into_owned(),
        status: "unconfigured".to_string(),
        reason: reason.map(str::to_string),
    }
}

fn configured(
    path: &PathBuf,
    control_plane_url: String,
    host_enrollment_endpoint: Option<String>,
    environment: Option<String>,
    source: &str,
) -> ActiumControlPlaneConfig {
    let host_enrollment_endpoint =
        host_enrollment_endpoint.or_else(|| Some(control_plane_url.clone()));
    ActiumControlPlaneConfig {
        control_plane_url: Some(control_plane_url),
        host_enrollment_endpoint,
        environment,
        source: source.to_string(),
        config_path: path.to_string_lossy().into_owned(),
        status: "configured".to_string(),
        reason: None,
    }
}

fn resolve_file(path: &PathBuf) -> ActiumControlPlaneConfig {
    let Ok(contents) = fs::read_to_string(path) else {
        return unconfigured(
            path,
            DEFAULT_SOURCE,
            Some("CONTROL_PLANE_CONFIG_UNREADABLE"),
        );
    };
    let Ok(document) = serde_json::from_str::<ControlPlaneConfigDocument>(&contents) else {
        return unconfigured(path, DEFAULT_SOURCE, Some("CONTROL_PLANE_CONFIG_INVALID"));
    };
    let Some(control_plane_url) = canonical_endpoint(&document.control_plane_url) else {
        return unconfigured(path, DEFAULT_SOURCE, Some("CONTROL_PLANE_URL_INVALID"));
    };
    let host_enrollment_endpoint = match document.host_enrollment_endpoint {
        Some(value) => canonical_host_enrollment_endpoint(&value),
        None => Some(control_plane_url.clone()),
    };
    if host_enrollment_endpoint.is_none() {
        return unconfigured(
            path,
            DEFAULT_SOURCE,
            Some("HOST_ENROLLMENT_ENDPOINT_INVALID"),
        );
    }
    configured(
        path,
        control_plane_url,
        host_enrollment_endpoint,
        document
            .environment
            .filter(|value| !value.trim().is_empty()),
        document.source.as_deref().unwrap_or(DEFAULT_SOURCE),
    )
}

pub fn resolve() -> ActiumControlPlaneConfig {
    let path = crate::paths::host_control_plane_config_path();
    if path.exists() {
        return resolve_file(&path);
    }
    let shared_path = crate::paths::shared_host_control_plane_config_path();
    if shared_path.exists() {
        return resolve_file(&shared_path);
    }

    if let Ok(value) = env::var("ACTIUM_CONTROL_ENDPOINT") {
        if let Some(control_plane_url) = canonical_endpoint(&value) {
            let environment = env::var("ACTIUM_CONTROL_ENVIRONMENT")
                .ok()
                .filter(|value| !value.trim().is_empty());
            return configured(
                &path,
                control_plane_url,
                None,
                environment,
                "process-environment",
            );
        }
        return unconfigured(
            &path,
            "process-environment",
            Some("CONTROL_PLANE_URL_INVALID"),
        );
    }

    unconfigured(&path, DEFAULT_SOURCE, Some("CONTROL_PLANE_UNCONFIGURED"))
}

pub fn persist_from_bootstrap(
    control_plane_url: &str,
    environment: Option<&str>,
) -> Result<(), String> {
    let Some(control_plane_url) = canonical_endpoint(control_plane_url) else {
        return Err("CONTROL_PLANE_URL_INVALID".to_string());
    };
    let path = crate::paths::host_control_plane_config_path();
    if path.exists() {
        let current = resolve();
        if current.status != "configured"
            || current.control_plane_url.as_deref() != Some(control_plane_url.as_str())
        {
            return Err("CONTROL_PLANE_CONFIG_CONFLICT".to_string());
        }
        return Ok(());
    }
    let document = ControlPlaneConfigDocument {
        control_plane_url: control_plane_url.clone(),
        host_enrollment_endpoint: Some(control_plane_url),
        environment: environment
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        source: Some("signed-bootstrap".to_string()),
    };
    let contents = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("CONTROL_PLANE_CONFIG_SERIALIZE_FAILED: {error}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("CONTROL_PLANE_CONFIG_DIRECTORY_FAILED: {error}"))?;
    }
    fs::write(&path, format!("{contents}\n"))
        .map_err(|error| format!("CONTROL_PLANE_CONFIG_WRITE_FAILED: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("CONTROL_PLANE_CONFIG_PERMISSIONS_FAILED: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{canonical_endpoint, canonical_host_enrollment_endpoint};

    #[test]
    fn endpoint_canonico_exige_https_y_no_admite_fragmentos() {
        assert_eq!(
            canonical_endpoint("https://center.example/gateway/"),
            Some("https://center.example/gateway".to_string())
        );
        assert!(canonical_endpoint("http://center.example").is_none());
        assert!(canonical_endpoint("https://center.example/gateway?x=1").is_none());
        assert!(canonical_endpoint("https://center.example/gateway#x").is_none());
    }

    #[test]
    fn host_enrollment_endpoint_allows_only_loopback_http() {
        assert_eq!(
            canonical_host_enrollment_endpoint("http://127.0.0.1:18083/"),
            Some("http://127.0.0.1:18083".to_string())
        );
        assert_eq!(
            canonical_host_enrollment_endpoint("http://[::1]:18083/"),
            Some("http://[::1]:18083".to_string())
        );
        assert!(canonical_host_enrollment_endpoint("http://10.77.10.226:18083").is_none());
        assert!(canonical_host_enrollment_endpoint("http://127.0.0.1:not-a-port").is_none());
    }
}
