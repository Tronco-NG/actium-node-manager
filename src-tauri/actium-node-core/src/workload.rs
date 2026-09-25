use serde::{Deserialize, Serialize};

pub const WORKLOAD_PROFILE_SCHEMA: &str = "actium-workload-profile@1.0.0";
pub const WORKLOAD_DEPLOYMENT_SCHEMA: &str = "actium-workload-deployment@1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeKind {
    OciContainer,
    OciCompose,
    Vm,
}

impl RuntimeKind {
    pub fn is_implemented(self) -> bool {
        matches!(self, Self::OciContainer | Self::OciCompose)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkPolicy {
    Isolated,
    SiteInternal,
    ProductInternal,
    PublicHttps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentStatus {
    Pending,
    Ready,
    Degraded,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentObservation {
    pub component_id: String,
    pub status: ComponentStatus,
}

pub fn overall_from_components(components: &[ComponentObservation]) -> ComponentStatus {
    if components.is_empty() {
        return ComponentStatus::Failed;
    }
    if components
        .iter()
        .all(|component| component.status == ComponentStatus::Ready)
    {
        return ComponentStatus::Ready;
    }
    if components
        .iter()
        .any(|component| component.status == ComponentStatus::Failed)
    {
        return ComponentStatus::Failed;
    }
    if components
        .iter()
        .all(|component| component.status == ComponentStatus::Stopped)
    {
        return ComponentStatus::Stopped;
    }
    if components
        .iter()
        .any(|component| component.status == ComponentStatus::Degraded)
    {
        return ComponentStatus::Degraded;
    }
    ComponentStatus::Pending
}

pub fn profile_json_has_inline_secret_values(json: &str) -> bool {
    let lower = json.to_ascii_lowercase();
    ["\"password\":", "\"secret\":", "\"api_key\":", "\"app_key\":"]
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_kinds_are_implemented_vm_is_reserved() {
        assert!(RuntimeKind::OciCompose.is_implemented());
        assert!(RuntimeKind::OciContainer.is_implemented());
        assert!(!RuntimeKind::Vm.is_implemented());
    }

    #[test]
    fn overall_ready_requires_every_component() {
        let components = vec![
            ComponentObservation {
                component_id: "application".into(),
                status: ComponentStatus::Ready,
            },
            ComponentObservation {
                component_id: "datastore".into(),
                status: ComponentStatus::Pending,
            },
        ];
        assert_eq!(overall_from_components(&components), ComponentStatus::Pending);
        let ready = vec![
            ComponentObservation {
                component_id: "application".into(),
                status: ComponentStatus::Ready,
            },
            ComponentObservation {
                component_id: "datastore".into(),
                status: ComponentStatus::Ready,
            },
        ];
        assert_eq!(overall_from_components(&ready), ComponentStatus::Ready);
    }

    #[test]
    fn profile_rejects_inline_secret_values() {
        assert!(profile_json_has_inline_secret_values(r#"{"password":"x"}"#));
        assert!(!profile_json_has_inline_secret_values(
            r#"{"secretRequirements":[{"secretId":"app.secret_key"}]}"#
        ));
    }
}
