use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthGateReport {
    pub healthy: bool,
    pub total: usize,
    pub alive: usize,
    pub ready: usize,
    pub degraded: usize,
    pub failures: Vec<String>,
}

impl HealthGateReport {
    pub fn lifecycle_state(&self) -> &'static str {
        if self.healthy {
            "ready"
        } else if self.degraded > 0 {
            "degraded"
        } else if self.alive > 0 {
            "alive"
        } else {
            "commissioned"
        }
    }
}

pub fn evaluate_docker_inspect(raw: &str) -> Result<HealthGateReport, String> {
    let containers = serde_json::from_str::<Vec<serde_json::Value>>(raw)
        .map_err(|error| format!("docker inspect no devolvio JSON valido: {error}"))?;
    let mut alive = 0_usize;
    let mut ready = 0_usize;
    let mut degraded = 0_usize;
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
        let is_alive = state == "running";
        let is_ready = state == "running" && health == Some("healthy")
            || state == "exited" && exit_code == 0 && one_shot;
        let is_degraded = health == Some("unhealthy")
            || state == "exited" && !(exit_code == 0 && one_shot)
            || !matches!(state, "running" | "created") && !is_ready;
        if is_alive {
            alive += 1;
        }
        if is_ready {
            ready += 1;
        } else {
            if is_degraded {
                degraded += 1;
            }
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
        healthy: !containers.is_empty() && failures.is_empty(),
        total: containers.len(),
        alive,
        ready,
        degraded,
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
        assert_eq!(report.alive, 1);
        assert_eq!(report.degraded, 1);
        assert_eq!(report.lifecycle_state(), "degraded");
    }

    #[test]
    fn running_sin_health_es_alive_pero_no_ready() {
        let raw = r#"[{"Name":"/node-api","State":{"Status":"running","ExitCode":0}}]"#;
        let report = evaluate_docker_inspect(raw).expect("report");
        assert!(!report.healthy);
        assert_eq!(report.alive, 1);
        assert_eq!(report.ready, 0);
        assert_eq!(report.degraded, 0);
        assert_eq!(report.lifecycle_state(), "alive");
    }

    #[test]
    fn acepta_health_y_migracion_completada() {
        let raw = r#"[
          {"Name":"/node-api","State":{"Status":"running","Health":{"Status":"healthy"},"ExitCode":0}},
          {"Name":"/node-migrator","State":{"Status":"exited","ExitCode":0}}
        ]"#;
        let report = evaluate_docker_inspect(raw).expect("report");
        assert!(report.healthy);
        assert_eq!(report.alive, 1);
        assert_eq!(report.ready, 2);
        assert_eq!(report.degraded, 0);
        assert_eq!(report.lifecycle_state(), "ready");
    }
}
