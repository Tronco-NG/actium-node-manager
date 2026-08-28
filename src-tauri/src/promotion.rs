use crate::paths;
use actium_node_core::{SupervisorClient, SupervisorCommand, SupervisorReply};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMappingDiff {
    pub key: String,
    pub label: String,
    pub source_port: u16,
    pub target_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromotionPreview {
    pub source_channel: String,
    pub target_channel: String,
    pub source_dir: String,
    pub target_dir: String,
    pub source_compose_project: String,
    pub target_compose_project: String,
    pub deployment_code: String,
    pub port_diffs: Vec<PortMappingDiff>,
    pub can_promote: bool,
    pub blocking_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromotionResult {
    pub success: bool,
    pub message: String,
    pub target_deployment_code: String,
    pub target_install_dir: String,
}

fn map_port_offset(key: &str, value: u16, to_stable: bool) -> u16 {
    if to_stable {
        match key {
            "TELEMETRY_PORT" | "ACTIUM_TELEMETRY_PORT" => 8090,
            "SITE_CORE_PORT" | "ACTIUM_SITE_CORE_PORT" => 8088,
            "PEOPLE_PORT" | "ACTIUM_PEOPLE_PORT" => 8092,
            "CONTROL_RUNTIME_PORT" | "ACTIUM_CONTROL_PORT" => 8094,
            "RADIO_CONTROL_PORT" | "ACTIUM_RADIO_CONTROL_PORT" => 8100,
            "RADIO_SAF_PORT" | "ACTIUM_RADIO_SAF_PORT" => 8101,
            "PROMETHEUS_PORT" => 9090,
            "GRAFANA_PORT" => 3001,
            "TURN_PORT" => 3478,
            "LIVEKIT_HTTP_PORT" => 7880,
            _ => {
                if value >= 10000 {
                    value - 10000
                } else {
                    value
                }
            }
        }
    } else {
        match key {
            "TELEMETRY_PORT" | "ACTIUM_TELEMETRY_PORT" => 18090,
            "SITE_CORE_PORT" | "ACTIUM_SITE_CORE_PORT" => 18088,
            "PEOPLE_PORT" | "ACTIUM_PEOPLE_PORT" => 18092,
            "CONTROL_RUNTIME_PORT" | "ACTIUM_CONTROL_PORT" => 18094,
            "RADIO_CONTROL_PORT" | "ACTIUM_RADIO_CONTROL_PORT" => 18100,
            "RADIO_SAF_PORT" | "ACTIUM_RADIO_SAF_PORT" => 18101,
            "PROMETHEUS_PORT" => 19090,
            "GRAFANA_PORT" => 13001,
            "TURN_PORT" => 13478,
            "LIVEKIT_HTTP_PORT" => 17880,
            _ => {
                if value < 10000 {
                    value + 10000
                } else {
                    value
                }
            }
        }
    }
}

pub fn preview_node_promotion(
    source_channel: &str,
    target_channel: &str,
    deployment_code: &str,
) -> Result<PromotionPreview, String> {
    let source_root = paths::authorized_nodes_root_for(source_channel);
    let target_root = paths::authorized_nodes_root_for(target_channel);
    let source_node_dir = source_root.join(deployment_code);

    if !source_node_dir.is_dir() {
        return Err(format!(
            "El nodo {deployment_code} no existe en el canal origen {source_channel} (ruta: {})",
            source_node_dir.display()
        ));
    }

    let to_stable = target_channel == "stable";
    let target_deployment_code = if to_stable {
        deployment_code
            .strip_prefix("actium-lab-")
            .unwrap_or(deployment_code)
            .to_string()
    } else if !deployment_code.starts_with("actium-lab-") {
        format!("actium-lab-{deployment_code}")
    } else {
        deployment_code.to_string()
    };

    let target_node_dir = target_root.join(&target_deployment_code);
    let mut can_promote = true;
    let mut blocking_reason = None;

    if target_node_dir.exists() {
        can_promote = false;
        blocking_reason = Some(format!(
            "Ya existe un nodo con identificador '{}' en el canal destino {target_channel}",
            target_deployment_code
        ));
    }

    let source_compose_project = if source_channel == "lab" {
        format!("actium-lab-{deployment_code}")
    } else {
        format!("actium-node-{deployment_code}")
    };

    let target_compose_project = if target_channel == "lab" {
        format!("actium-lab-{target_deployment_code}")
    } else {
        format!("actium-node-{target_deployment_code}")
    };

    // Build standard port diffs
    let port_keys = [
        ("TELEMETRY_PORT", "Telemetría / GPS"),
        ("SITE_CORE_PORT", "Site Core Soberano"),
        ("PEOPLE_PORT", "People Data Plane"),
        ("CONTROL_RUNTIME_PORT", "Control Runtime"),
        ("RADIO_CONTROL_PORT", "HT Radio Control"),
        ("RADIO_SAF_PORT", "Store & Forward"),
        ("PROMETHEUS_PORT", "Prometheus TSDB"),
        ("GRAFANA_PORT", "Grafana Dashboards"),
        ("TURN_PORT", "TURN WebRTC"),
        ("LIVEKIT_HTTP_PORT", "LiveKit SFU"),
    ];

    let mut port_diffs = Vec::new();
    for (key, label) in port_keys {
        let src_port = map_port_offset(key, 0, source_channel == "stable");
        let dst_port = map_port_offset(key, 0, to_stable);
        port_diffs.push(PortMappingDiff {
            key: key.to_string(),
            label: label.to_string(),
            source_port: src_port,
            target_port: dst_port,
        });
    }

    Ok(PromotionPreview {
        source_channel: source_channel.to_string(),
        target_channel: target_channel.to_string(),
        source_dir: source_node_dir.to_string_lossy().into_owned(),
        target_dir: target_node_dir.to_string_lossy().into_owned(),
        source_compose_project,
        target_compose_project,
        deployment_code: target_deployment_code,
        port_diffs,
        can_promote,
        blocking_reason,
    })
}

pub fn execute_node_promotion(
    source_channel: &str,
    target_channel: &str,
    deployment_code: &str,
) -> Result<PromotionResult, String> {
    let preview = preview_node_promotion(source_channel, target_channel, deployment_code)?;
    if !preview.can_promote {
        return Err(preview.blocking_reason.unwrap_or_else(|| "Promoción no permitida".to_string()));
    }

    let source_dir = PathBuf::from(&preview.source_dir);
    let target_dir = PathBuf::from(&preview.target_dir);
    let to_stable = target_channel == "stable";

    // 1. Detener el workload en el supervisor origen si está disponible
    let src_client = SupervisorClient::new(
        paths::supervisor_socket_path_for(source_channel),
        paths::supervisor_key_path_for(source_channel),
    );
    let _ = src_client.request(SupervisorCommand::ExecuteRuntimeUnit(
        actium_node_core::RuntimeUnitActionRequest {
            install_dir: source_dir.to_string_lossy().into_owned(),
            runtime_unit_id: deployment_code.to_string(),
            action: "stop".to_string(),
        },
    ));

    // 2. Crear directorios en destino y copiar archivos preservando secretos y estado
    if let Some(parent) = target_dir.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("No se pudo crear directorio destino: {e}"))?;
    }

    copy_dir_recursive(&source_dir, &target_dir)
        .map_err(|e| format!("Error al copiar datos del nodo hacia {}: {e}", target_dir.display()))?;

    // 3. Modificar node.env en el destino para aplicar el remapeo
    let env_path = target_dir.join("node.env");
    if env_path.is_file() {
        let env_content = fs::read_to_string(&env_path).map_err(|e| format!("No se pudo leer node.env: {e}"))?;
        let mut new_lines = Vec::new();

        for line in env_content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                new_lines.push(line.to_string());
                continue;
            }

            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');

                let updated_val = match key {
                    "PRODUCT_CHANNEL" | "ACTIUM_PRODUCT_CHANNEL" => target_channel.to_string(),
                    "COMPOSE_PROJECT_NAME" => preview.target_compose_project.clone(),
                    "FABRIC_PROJECT" | "ACTIUM_FABRIC_PROJECT" => {
                        if to_stable {
                            "actium-node-fabric-01".to_string()
                        } else {
                            "actium-lab-fabric-01".to_string()
                        }
                    }
                    "FABRIC_NETWORK" | "ACTIUM_FABRIC_NETWORK" => {
                        if to_stable {
                            "actium-node-fabric-01".to_string()
                        } else {
                            "actium-lab-fabric-01".to_string()
                        }
                    }
                    port_key if port_key.ends_with("_PORT") => {
                        if let Ok(parsed_p) = val.parse::<u16>() {
                            map_port_offset(port_key, parsed_p, to_stable).to_string()
                        } else {
                            val.to_string()
                        }
                    }
                    _ => val.to_string(),
                };

                new_lines.push(format!("{key}={updated_val}"));
            } else {
                new_lines.push(line.to_string());
            }
        }

        fs::write(&env_path, new_lines.join("\n"))
            .map_err(|e| format!("No se pudo actualizar node.env en destino: {e}"))?;
    }

    // 4. Actualizar marcador .actium-node-installation.json si existe
    let marker_path = target_dir.join(".actium-node-installation.json");
    if marker_path.is_file() {
        if let Ok(content) = fs::read_to_string(&marker_path) {
            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(obj) = json.as_object_mut() {
                    obj.insert("managerChannel".to_string(), serde_json::Value::String(target_channel.to_string()));
                    obj.insert("deploymentCode".to_string(), serde_json::Value::String(preview.deployment_code.clone()));
                }
                let _ = fs::write(&marker_path, serde_json::to_string_pretty(&json).unwrap_or_default());
            }
        }
    }

    // 5. Iniciar el nodo en el supervisor destino si está activo
    let dst_client = SupervisorClient::new(
        paths::supervisor_socket_path_for(target_channel),
        paths::supervisor_key_path_for(target_channel),
    );
    let start_res = dst_client.request(SupervisorCommand::ExecuteRuntimeUnit(
        actium_node_core::RuntimeUnitActionRequest {
            install_dir: target_dir.to_string_lossy().into_owned(),
            runtime_unit_id: preview.deployment_code.clone(),
            action: "start".to_string(),
        },
    ));

    let start_msg = match start_res {
        Ok(SupervisorReply::RuntimeAction(res)) => {
            format!(" e iniciado exitosamente ({})", res.message)
        }
        Ok(_) => " y registrado en supervisor destino.".to_string(),
        Err(e) => format!(" (advertencia: supervisor destino no pudo iniciar automáticamente: {e})"),
    };

    Ok(PromotionResult {
        success: true,
        message: format!(
            "Nodo '{}' promovido exitosamente del canal {} al canal {}{}",
            preview.deployment_code, source_channel, target_channel, start_msg
        ),
        target_deployment_code: preview.deployment_code,
        target_install_dir: target_dir.to_string_lossy().into_owned(),
    })
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
