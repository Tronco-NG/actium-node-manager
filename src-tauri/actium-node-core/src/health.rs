use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthGateReport {
    pub healthy: bool,
    pub total: usize,
    pub ready: usize,
    pub failures: Vec<String>,
}

pub fn evaluate_docker_inspect(raw: &str) -> Result<HealthGateReport, String> {
    let containers = serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .map_err(|error| format!("docker inspect no devolvio JSON valido: {error}"))?;
    let mut ready = 0_usize;
    let mut failures = Vec::new();

    for container in &containers {
        let name = container
            .pointer("/Name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("contenedor")
            .trim_start_matches('/');
        let state = container
            .pointer("/State/Status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let health = container
            .pointer("/State/Health/Status")
            .and_then(serde_json::Value::as_str);
        let exit_code = container
            .pointer("/State/ExitCode")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1);
        let one_shot = name.contains("migrator") || name.contains("migration");
        let is_ready = state == "running" && matches!(health, None | Some("healthy"))
            || state == "exited" && exit_code == 0 && one_shot;
        if is_ready {
            ready += 1;
        } else {
            failures.push(format!(
                "{name}: state={state}, health={}, exit={exit_code}",
                health.unwrap_or("none")
            ));
        }
    }

    if containers.is_empty() {
        failures.push("El proyecto Compose no tiene contenedores observables.".to_string());
    }
    Ok(HealthGateReport {
        healthy: failures.is_empty(),
        total: containers.len(),
        ready,
        failures,
    })
}

#[cfg(test)]
mod tests {
    use super::evaluate_docker_inspect;

    #[test]
    fn no_confunde_running_con_healthy() {
        let raw = r#"[{"Name":"/node-api","State":{"Status":"running","Health":{"Status":"unhealthy"},"ExitCode":0}}]"#;
        let report = evaluate_docker_inspect(raw).expect("report");
        assert!(!report.healthy);
    }

    #[test]
    fn acepta_health_y_migracion_completada() {
        let raw = r#"[
          {"Name":"/node-api","State":{"Status":"running","Health":{"Status":"healthy"},"ExitCode":0}},
          {"Name":"/node-migrator","State":{"Status":"exited","ExitCode":0}}
        ]"#;
        let report = evaluate_docker_inspect(raw).expect("report");
        assert!(report.healthy);
        assert_eq!(report.ready, 2);
    }
}
