use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, net::IpAddr, path::Path, process::Command};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkReconciliationPolicy {
    #[default]
    Manual,
    ReconcileOnOperation,
    AutoOnInterfaceChange,
}

impl NetworkReconciliationPolicy {
    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or_default().trim() {
            "reconcile_on_operation" => Self::ReconcileOnOperation,
            "auto_on_interface_change" => Self::AutoOnInterfaceChange,
            _ => Self::Manual,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkAddress {
    pub interface: String,
    pub address: String,
    pub prefix_length: u8,
    pub family: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkReconciliationResult {
    pub policy: NetworkReconciliationPolicy,
    pub changed: bool,
    pub selected_interface: Option<String>,
    pub selected_address: Option<String>,
    pub message: String,
}

pub fn network_inventory() -> Result<Vec<NetworkAddress>, String> {
    if !cfg!(target_os = "linux") {
        return Ok(Vec::new());
    }
    let output = Command::new("ip")
        .args(["-j", "address", "show", "up"])
        .output()
        .map_err(|error| format!("No se pudo ejecutar iproute2: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "iproute2 no pudo inventariar interfaces: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let links = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout)
        .map_err(|error| format!("iproute2 devolvio JSON invalido: {error}"))?;
    let mut inventory = Vec::new();
    for link in links {
        let interface = link
            .get("ifname")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if interface.is_empty() || interface == "lo" {
            continue;
        }
        for address in link
            .get("addr_info")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            let family = address
                .get("family")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let local = address
                .get("local")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if !matches!(family, "inet" | "inet6") || local.parse::<IpAddr>().is_err() {
                continue;
            }
            inventory.push(NetworkAddress {
                interface: interface.to_string(),
                address: local.to_string(),
                prefix_length: address
                    .get("prefixlen")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u8::try_from(value).ok())
                    .unwrap_or_default(),
                family: family.to_string(),
                scope: address
                    .get("scope")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }
    }
    inventory.sort_by(|left, right| {
        left.interface
            .cmp(&right.interface)
            .then(left.family.cmp(&right.family))
            .then(left.address.cmp(&right.address))
    });
    Ok(inventory)
}

pub fn reconcile_node_network(
    node_root: &Path,
    operation_triggered: bool,
) -> Result<NetworkReconciliationResult, String> {
    let node_env_path = node_root.join("node.env");
    let contents = fs::read_to_string(&node_env_path)
        .map_err(|error| format!("No se pudo leer {}: {error}", node_env_path.display()))?;
    let config = parse_env(&contents);
    let policy = NetworkReconciliationPolicy::parse(
        config
            .get("ACTIUM_NETWORK_RECONCILIATION_POLICY")
            .map(String::as_str),
    );
    if config.get("DATA_PLANE_NETWORK_MODE").map(String::as_str) != Some("trusted_lan") {
        return Ok(NetworkReconciliationResult {
            policy,
            changed: false,
            selected_interface: config.get("ACTIUM_NETWORK_INTERFACE").cloned(),
            selected_address: config.get("ACTIUM_NETWORK_ADDRESS").cloned(),
            message: "La reconciliacion de interfaz solo aplica a trusted_lan.".to_string(),
        });
    }
    if policy == NetworkReconciliationPolicy::Manual
        || (policy == NetworkReconciliationPolicy::ReconcileOnOperation && !operation_triggered)
    {
        return Ok(NetworkReconciliationResult {
            policy,
            changed: false,
            selected_interface: config.get("ACTIUM_NETWORK_INTERFACE").cloned(),
            selected_address: config.get("ACTIUM_NETWORK_ADDRESS").cloned(),
            message: "La politica de red no autoriza reconciliacion en este evento.".to_string(),
        });
    }
    let requested_interface = config
        .get("ACTIUM_NETWORK_INTERFACE")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "La reconciliacion exige ACTIUM_NETWORK_INTERFACE explicita; no se usara la ruta por defecto como autoridad.".to_string()
        })?;
    let requested_address = config
        .get("ACTIUM_NETWORK_ADDRESS")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let inventory = network_inventory()?;
    let selected = if let Some(address) = requested_address {
        inventory.iter().find(|candidate| {
            candidate.interface == requested_interface && candidate.address == address
        })
    } else {
        inventory.iter().find(|candidate| {
            candidate.interface == requested_interface
                && candidate.family == "inet"
                && candidate.scope == "global"
        })
    }
    .ok_or_else(|| {
        format!(
            "La interfaz {requested_interface} no posee la direccion autorizada {}.",
            requested_address.unwrap_or("IPv4 global")
        )
    })?;
    let previous_base_url = config
        .get("DATA_PLANE_PUBLIC_BASE_URL")
        .map(String::as_str)
        .unwrap_or_default();
    if previous_base_url.trim().is_empty() {
        return Err("DATA_PLANE_PUBLIC_BASE_URL no esta configurada.".to_string());
    }
    let next_base_url = replace_url_host(previous_base_url, &selected.address)?;
    let previous_host = url_host(previous_base_url).unwrap_or_default();
    let updates = BTreeMap::from([
        ("DATA_PLANE_BIND_ADDRESS", "0.0.0.0".to_string()),
        ("DATA_PLANE_PUBLIC_BASE_URL", next_base_url.clone()),
        ("ACTIUM_NETWORK_ADDRESS", selected.address.clone()),
    ]);
    let mut changed_files = Vec::new();
    for relative in ["node.env", "secrets/data-plane.env"] {
        let path = node_root.join(relative);
        if !path.is_file() {
            continue;
        }
        let current = fs::read_to_string(&path)
            .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
        let mut updated = update_env(&current, &updates);
        updated = replace_managed_host(&updated, &previous_host, &selected.address);
        if updated != current {
            write_atomic(&path, updated.as_bytes())?;
            changed_files.push(relative);
        }
    }
    Ok(NetworkReconciliationResult {
        policy,
        changed: !changed_files.is_empty(),
        selected_interface: Some(selected.interface.clone()),
        selected_address: Some(selected.address.clone()),
        message: if changed_files.is_empty() {
            format!(
                "La publicacion ya coincide con {} en {}.",
                selected.address, selected.interface
            )
        } else {
            format!(
                "Red reconciliada en {} usando {} ({next_base_url}).",
                changed_files.join(", "),
                selected.interface
            )
        },
    })
}

fn parse_env(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn update_env(contents: &str, updates: &BTreeMap<&str, String>) -> String {
    let mut seen = std::collections::BTreeSet::new();
    let mut lines = contents
        .lines()
        .map(|line| {
            let Some((key, _)) = line.split_once('=') else {
                return line.to_string();
            };
            let key = key.trim();
            let Some(value) = updates.get(key) else {
                return line.to_string();
            };
            seen.insert(key.to_string());
            format!("{key}={value}")
        })
        .collect::<Vec<_>>();
    for (key, value) in updates {
        if !seen.contains(*key) {
            lines.push(format!("{key}={value}"));
        }
    }
    format!("{}\n", lines.join("\n"))
}

fn url_host(value: &str) -> Option<String> {
    let (_, authority_and_path) = value.split_once("://")?;
    let authority = authority_and_path.split('/').next()?;
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.starts_with('[') {
        return authority
            .strip_prefix('[')?
            .split_once(']')
            .map(|(host, _)| host.to_string())
            .or_else(|| authority.strip_suffix(']').map(str::to_string));
    }
    Some(authority.split(':').next()?.to_string())
}

fn replace_url_host(value: &str, address: &str) -> Result<String, String> {
    let host = url_host(value).ok_or_else(|| format!("URL no valida: {value}"))?;
    Ok(value.replacen(&host, address, 1))
}

fn replace_managed_host(contents: &str, previous_host: &str, next_host: &str) -> String {
    if previous_host.is_empty() || previous_host == next_host {
        contents.to_string()
    } else {
        const MANAGED_KEYS: [&str; 9] = [
            "TELEMETRY_INGRESS_PUBLIC_URL",
            "TELEMETRY_READ_PUBLIC_URL",
            "METRICS_PUBLIC_URL",
            "RADIO_CONTROL_PUBLIC_URL",
            "SITE_CORE_PUBLIC_URL",
            "ACTIUM_SITE_CORE_ENDPOINT",
            "LIVEKIT_PUBLIC_URL",
            "LIVEKIT_NODE_IP",
            "TURN_EXTERNAL_IP",
        ];
        format!(
            "{}\n",
            contents
                .lines()
                .map(|line| {
                    let Some((key, value)) = line.split_once('=') else {
                        return line.to_string();
                    };
                    if MANAGED_KEYS.contains(&key.trim()) {
                        format!("{}={}", key.trim(), value.replace(previous_host, next_host))
                    } else {
                        line.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let metadata = fs::metadata(path).ok();
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("No se pudo escribir {}: {error}", temporary.display()))?;
    preserve_unix_owner_and_mode(&temporary, metadata.as_ref())?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("No se pudo promover {}: {error}", path.display()))
}

#[cfg(unix)]
fn preserve_unix_owner_and_mode(
    path: &Path,
    metadata: Option<&fs::Metadata>,
) -> Result<(), String> {
    use nix::unistd::{chown, Gid, Uid};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Some(metadata) = metadata else {
        return Ok(());
    };
    fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode())).map_err(|error| {
        format!(
            "No se pudo preservar el modo de {}: {error}",
            path.display()
        )
    })?;
    chown(
        path,
        Some(Uid::from_raw(metadata.uid())),
        Some(Gid::from_raw(metadata.gid())),
    )
    .map_err(|error| {
        format!(
            "No se pudo preservar el owner de {}: {error}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
fn preserve_unix_owner_and_mode(
    _path: &Path,
    _metadata: Option<&fs::Metadata>,
) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{replace_managed_host, replace_url_host, update_env};
    use std::collections::BTreeMap;

    #[test]
    fn actualiza_host_sin_cambiar_esquema_o_puerto() {
        assert_eq!(
            replace_url_host("http://192.168.1.8:18090/api", "10.20.30.40").unwrap(),
            "http://10.20.30.40:18090/api"
        );
    }

    #[test]
    fn env_es_determinista_y_preserva_claves_ajenas() {
        let updates = BTreeMap::from([("A", "3".to_string()), ("C", "4".to_string())]);
        assert_eq!(update_env("A=1\nB=2\n", &updates), "A=3\nB=2\nC=4\n");
    }

    #[test]
    fn reconciliacion_no_reemplaza_secretos_ni_claves_ajenas() {
        let current = "TELEMETRY_READ_PUBLIC_URL=http://10.0.0.2:18090\nTOKEN=token-10.0.0.2\n";
        let updated = replace_managed_host(current, "10.0.0.2", "10.0.0.3");
        assert!(updated.contains("TELEMETRY_READ_PUBLIC_URL=http://10.0.0.3:18090"));
        assert!(updated.contains("TOKEN=token-10.0.0.2"));
    }
}
