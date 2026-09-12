use crate::attestation::canonical_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const FABRIC_CANONICALIZATION_VERSION: u8 = 1;
pub const FABRIC_ATTESTATION_SCHEMA_V2: u8 = 2;
pub const FABRIC_CANONICAL_STATE_SCHEMA: u8 = 1;
pub const FABRIC_CANONICAL_STATE_RELATIVE_PATH: &str = "state/fabric-canonical-state.json";



#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FabricLifecycleStatus {
    Steady,
    DriftDetected,
    Reconciling,
    AdoptRequired,
    Promoting,
    RollingBack,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FabricReconcileMode {
    AutoReconcile,
    OwnerAdopt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeclaredFabricImage {
    pub service: String,
    pub image: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PinnedFabricImage {
    pub service: String,
    pub repo_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeclaredFabricMaterial {
    pub payload_digest: Option<String>,
    pub compose_digest: String,
    pub install_mode: String,
    pub declared_images: Vec<DeclaredFabricImage>,
    #[serde(default)]
    pub pinned_repo_digests: Vec<PinnedFabricImage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FabricAdoptReceipt {
    pub receipt_id: String,
    pub mode: FabricReconcileMode,
    pub from_generation: u64,
    pub to_generation: u64,
    pub from_canonical: String,
    pub to_canonical: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FabricCanonicalState {
    pub schema: u8,
    pub fabric_id: String,
    pub attestation_schema: u8,
    pub canonicalization_version: u8,
    pub instance_generation: u64,
    pub canonical_fabric_digest: String,
    pub desired_canonical_fabric_digest: String,
    pub runtime_evidence_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lkg_canonical_fabric_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lkg_instance_generation: Option<u64>,
    pub lifecycle_status: FabricLifecycleStatus,
    pub drift_status: String,
    pub install_mode: String,
    pub compose_digest: String,
    #[serde(default)]
    pub pinned_repo_digests: Vec<PinnedFabricImage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_adopt_receipt: Option<FabricAdoptReceipt>,
}

impl FabricCanonicalState {
    pub fn state_path(fabric_root: &Path) -> PathBuf {
        fabric_root.join(FABRIC_CANONICAL_STATE_RELATIVE_PATH)
    }
}

/// Content-addressed Fabric identity. Instance fields (fabricId, paths,
/// runtimeUnitId, containerId, timestamps, observed imageId, local revision
/// counters) are excluded by construction.
pub fn canonical_fabric_digest(material: &DeclaredFabricMaterial) -> Result<String, String> {
    let mut declared_images = material.declared_images.clone();
    declared_images.sort_by(|left, right| left.service.cmp(&right.service));
    for pair in declared_images.windows(2) {
        if pair[0].service == pair[1].service {
            return Err("FABRIC_DECLARED_IMAGE_DUPLICATE".to_string());
        }
    }
    let mut pinned = material.pinned_repo_digests.clone();
    pinned.sort_by(|left, right| left.service.cmp(&right.service));
    for pin in &pinned {
        if !pin.repo_digest.starts_with("sha256:") && !valid_checksum(&pin.repo_digest) {
            return Err("FABRIC_PINNED_DIGEST_INVALID".to_string());
        }
    }
    if !valid_checksum(&material.compose_digest) {
        return Err("FABRIC_COMPOSE_DIGEST_INVALID".to_string());
    }
    if let Some(payload) = &material.payload_digest {
        if !valid_checksum(payload) {
            return Err("FABRIC_PAYLOAD_DIGEST_INVALID".to_string());
        }
    }
    let value = serde_json::json!({
        "canonicalizationVersion": FABRIC_CANONICALIZATION_VERSION,
        "composeDigest": material.compose_digest,
        "declaredImages": declared_images,
        "installMode": material.install_mode,
        "payloadDigest": material.payload_digest,
        "pinnedRepoDigests": pinned,
    });
    Ok(sha256_hex(canonical_json(&value)?.as_bytes()))
}

pub fn runtime_evidence_digest(stable_unit: &serde_json::Value) -> Result<String, String> {
    Ok(sha256_hex(canonical_json(stable_unit)?.as_bytes()))
}

pub fn compose_digest(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub fn parse_compose_declared_images(compose: &str) -> Result<Vec<DeclaredFabricImage>, String> {
    let mut images = Vec::new();
    let mut in_services = false;
    let mut current_service: Option<String> = None;
    for raw in compose.lines() {
        let line = strip_yaml_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        let indent = leading_spaces(line);
        let trimmed = line.trim();
        if indent == 0 && trimmed.ends_with(':') {
            in_services = trimmed == "services:";
            current_service = None;
            continue;
        }
        if !in_services {
            continue;
        }
        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
            current_service = Some(trimmed.trim_end_matches(':').to_string());
            continue;
        }
        if indent >= 4 && trimmed.starts_with("image:") {
            let service = current_service
                .clone()
                .ok_or_else(|| "FABRIC_COMPOSE_IMAGE_WITHOUT_SERVICE".to_string())?;
            let image = parse_yaml_scalar(trimmed.trim_start_matches("image:").trim())?;
            if image.is_empty() {
                return Err("FABRIC_COMPOSE_IMAGE_EMPTY".to_string());
            }
            images.push(DeclaredFabricImage { service, image });
        }
    }
    images.sort_by(|left, right| left.service.cmp(&right.service));
    Ok(images)
}

pub fn parse_install_mode(fabric_env: &str) -> Result<String, String> {
    let mut values = BTreeMap::new();
    for raw in fabric_env.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_string(), value.trim().to_string());
    }
    let mode = values
        .get("ACTIUM_INSTALL_MODE")
        .cloned()
        .ok_or_else(|| "FABRIC_INSTALL_MODE_MISSING".to_string())?;
    if mode != "published_images" && mode != "local_build" {
        return Err("FABRIC_INSTALL_MODE_INVALID".to_string());
    }
    Ok(mode)
}

pub fn load_declared_fabric_material(
    compose_path: &Path,
    fabric_env: &str,
    payload_digest: Option<String>,
    pinned_repo_digests: Vec<PinnedFabricImage>,
) -> Result<DeclaredFabricMaterial, String> {
    let compose_bytes = fs::read(compose_path).map_err(|error| {
        format!(
            "FABRIC_COMPOSE_UNREADABLE: {}: {error}",
            compose_path.display()
        )
    })?;
    let compose_text = String::from_utf8_lossy(&compose_bytes);
    Ok(DeclaredFabricMaterial {
        payload_digest,
        compose_digest: compose_digest(&compose_bytes),
        install_mode: parse_install_mode(fabric_env)?,
        declared_images: parse_compose_declared_images(&compose_text)?,
        pinned_repo_digests,
    })
}

pub fn observed_declared_images(
    containers: &[(String, String)],
) -> Vec<DeclaredFabricImage> {
    let mut images: Vec<DeclaredFabricImage> = containers
        .iter()
        .map(|(service, image)| DeclaredFabricImage {
            service: service.clone(),
            image: image.clone(),
        })
        .collect();
    images.sort_by(|left, right| left.service.cmp(&right.service));
    images
}

pub fn evaluate_fabric_lifecycle(
    desired: &str,
    active: &str,
    observed_canonical: &str,
    mode: FabricReconcileMode,
) -> (FabricLifecycleStatus, String) {
    if desired == active && active == observed_canonical {
        return (FabricLifecycleStatus::Steady, "none".to_string());
    }
    if desired == active && active != observed_canonical {
        return match mode {
            FabricReconcileMode::AutoReconcile => (
                FabricLifecycleStatus::DriftDetected,
                "observed_declared_mismatch".to_string(),
            ),
            FabricReconcileMode::OwnerAdopt => (
                FabricLifecycleStatus::AdoptRequired,
                "observed_declared_mismatch".to_string(),
            ),
        };
    }
    if desired != active {
        if active == observed_canonical {
            return (FabricLifecycleStatus::Promoting, "desired_pending".to_string());
        }
        return (FabricLifecycleStatus::Reconciling, "desired_active_mismatch".to_string());
    }
    (FabricLifecycleStatus::Degraded, "inconsistent".to_string())
}

pub fn adopt_observed_fabric(
    state: &FabricCanonicalState,
    observed_canonical: &str,
    observed_at: &str,
) -> Result<(FabricCanonicalState, FabricAdoptReceipt), String> {
    if !valid_checksum(observed_canonical) {
        return Err("FABRIC_OBSERVED_CANONICAL_INVALID".to_string());
    }
    if observed_canonical == state.canonical_fabric_digest {
        return Err("FABRIC_ADOPT_NO_MATERIAL_CHANGE".to_string());
    }
    if state.lifecycle_status != FabricLifecycleStatus::AdoptRequired
        && state.lifecycle_status != FabricLifecycleStatus::DriftDetected
    {
        return Err("FABRIC_ADOPT_NOT_REQUIRED".to_string());
    }
    let receipt = FabricAdoptReceipt {
        receipt_id: uuid::Uuid::new_v4().to_string(),
        mode: FabricReconcileMode::OwnerAdopt,
        from_generation: state.instance_generation,
        to_generation: state.instance_generation.saturating_add(1),
        from_canonical: state.canonical_fabric_digest.clone(),
        to_canonical: observed_canonical.to_string(),
        observed_at: observed_at.to_string(),
    };
    let mut next = state.clone();
    next.lkg_canonical_fabric_digest = Some(state.canonical_fabric_digest.clone());
    next.lkg_instance_generation = Some(state.instance_generation);
    next.instance_generation = receipt.to_generation;
    next.canonical_fabric_digest = observed_canonical.to_string();
    next.desired_canonical_fabric_digest = observed_canonical.to_string();
    next.lifecycle_status = FabricLifecycleStatus::Steady;
    next.drift_status = "adopted".to_string();
    next.last_adopt_receipt = Some(receipt.clone());
    Ok((next, receipt))
}

pub fn auto_reconcile_to_desired(state: &FabricCanonicalState) -> FabricCanonicalState {
    let mut next = state.clone();
    next.lifecycle_status = if state.canonical_fabric_digest == state.desired_canonical_fabric_digest
    {
        FabricLifecycleStatus::Reconciling
    } else {
        FabricLifecycleStatus::RollingBack
    };
    next.drift_status = "auto_reconcile".to_string();
    next
}

pub fn rollback_to_lkg(state: &FabricCanonicalState) -> Result<FabricCanonicalState, String> {
    let lkg = state
        .lkg_canonical_fabric_digest
        .clone()
        .ok_or_else(|| "FABRIC_LKG_UNAVAILABLE".to_string())?;
    let generation = state
        .lkg_instance_generation
        .ok_or_else(|| "FABRIC_LKG_UNAVAILABLE".to_string())?;
    let mut next = state.clone();
    next.desired_canonical_fabric_digest = lkg;
    next.instance_generation = generation;
    next.lifecycle_status = FabricLifecycleStatus::RollingBack;
    next.drift_status = "rollback_lkg".to_string();
    Ok(next)
}

fn valid_checksum(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| matches!(ch, 'a'..='f' | '0'..='9'))
}

fn sha256_hex(value: &[u8]) -> String {
    hex(&Sha256::digest(value))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| *ch == ' ').count()
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..index],
            _ => {}
        }
    }
    line
}

fn parse_yaml_scalar(value: &str) -> Result<String, String> {
    let value = value.trim();
    if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
        || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
    {
        return Ok(value[1..value.len() - 1].to_string());
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> DeclaredFabricMaterial {
        DeclaredFabricMaterial {
            payload_digest: Some("a".repeat(64)),
            compose_digest: "b".repeat(64),
            install_mode: "published_images".to_string(),
            declared_images: vec![
                DeclaredFabricImage {
                    service: "nats".to_string(),
                    image: "nats:2.10.22-alpine".to_string(),
                },
                DeclaredFabricImage {
                    service: "postgres".to_string(),
                    image: "postgres:17.6-alpine".to_string(),
                },
            ],
            pinned_repo_digests: Vec::new(),
        }
    }

    fn evidence(runtime_unit_id: &str, image_id: &str, repo: Option<&str>, started: &str) -> serde_json::Value {
        serde_json::json!({
            "runtimeUnitId": runtime_unit_id,
            "capability": "fabric",
            "dependencyScope": "host-shared",
            "composeProject": "actium-node-fabric-01",
            "effectiveConfigDigest": "c".repeat(64),
            "containers": [{
                "workloadCode": "postgres",
                "migrationProfile": null,
                "composeService": "postgres",
                "imageReference": "postgres:17.6-alpine",
                "imageId": image_id,
                "repoDigest": repo,
                "effectiveConfigDigest": "d".repeat(64),
                "migrationSucceeded": null,
            }],
            "startedAt": started,
        })
    }

    #[test]
    fn site_core_y_telemetry_comparten_canonical() {
        let digest = canonical_fabric_digest(&material()).unwrap();
        assert_eq!(digest, canonical_fabric_digest(&material()).unwrap());
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn runtime_unit_id_no_cambia_canonical() {
        let digest = canonical_fabric_digest(&material()).unwrap();
        let _ = evidence("unit-a", &format!("sha256:{}", "1".repeat(64)), None, "t0");
        let _ = evidence("unit-b", &format!("sha256:{}", "1".repeat(64)), None, "t0");
        assert_eq!(digest, canonical_fabric_digest(&material()).unwrap());
    }

    #[test]
    fn evidencia_distinta_no_cambia_canonical() {
        let canonical = canonical_fabric_digest(&material()).unwrap();
        let left = runtime_evidence_digest(&evidence(
            "fabric",
            &format!("sha256:{}", "1".repeat(64)),
            Some(&format!("postgres@sha256:{}", "2".repeat(64))),
            "2026-09-01T00:00:00Z",
        ))
        .unwrap();
        let right = runtime_evidence_digest(&evidence(
            "fabric",
            &format!("sha256:{}", "9".repeat(64)),
            Some(&format!("postgres@sha256:{}", "8".repeat(64))),
            "2026-09-11T04:29:00Z",
        ))
        .unwrap();
        assert_ne!(left, right);
        assert_eq!(canonical, canonical_fabric_digest(&material()).unwrap());
    }

    #[test]
    fn restart_misma_imagen_y_config_preserva_canonical() {
        let first = canonical_fabric_digest(&material()).unwrap();
        let restarted = material();
        assert_eq!(first, canonical_fabric_digest(&restarted).unwrap());
    }

    #[test]
    fn config_canonica_cambia_canonical() {
        let mut changed = material();
        changed.install_mode = "local_build".to_string();
        assert_ne!(
            canonical_fabric_digest(&material()).unwrap(),
            canonical_fabric_digest(&changed).unwrap()
        );
    }

    #[test]
    fn declared_image_cambia_canonical() {
        let mut changed = material();
        changed.declared_images[1].image = "postgres:17.7-alpine".to_string();
        assert_ne!(
            canonical_fabric_digest(&material()).unwrap(),
            canonical_fabric_digest(&changed).unwrap()
        );
    }

    #[test]
    fn compose_digest_cambia_canonical() {
        let mut changed = material();
        changed.compose_digest = "e".repeat(64);
        assert_ne!(
            canonical_fabric_digest(&material()).unwrap(),
            canonical_fabric_digest(&changed).unwrap()
        );
    }

    #[test]
    fn payload_digest_cambia_canonical() {
        let mut changed = material();
        changed.payload_digest = Some("f".repeat(64));
        assert_ne!(
            canonical_fabric_digest(&material()).unwrap(),
            canonical_fabric_digest(&changed).unwrap()
        );
    }

    #[test]
    fn pin_de_repo_digest_cambia_canonical() {
        let mut changed = material();
        changed.pinned_repo_digests = vec![PinnedFabricImage {
            service: "postgres".to_string(),
            repo_digest: format!("sha256:{}", "2".repeat(64)),
        }];
        assert_ne!(
            canonical_fabric_digest(&material()).unwrap(),
            canonical_fabric_digest(&changed).unwrap()
        );
    }

    #[test]
    fn orden_de_imagenes_no_cambia_canonical() {
        let mut reversed = material();
        reversed.declared_images.reverse();
        assert_eq!(
            canonical_fabric_digest(&material()).unwrap(),
            canonical_fabric_digest(&reversed).unwrap()
        );
    }

    #[test]
    fn parse_compose_declared_images_estable() {
        let compose = r#"
networks:
  fabric: {}
services:
  postgres:
    image: postgres:17.6-alpine
    restart: unless-stopped
  nats:
    image: "nats:2.10.22-alpine" # comment
"#;
        let images = parse_compose_declared_images(compose).unwrap();
        assert_eq!(images[0].service, "nats");
        assert_eq!(images[1].service, "postgres");
        assert_eq!(images[1].image, "postgres:17.6-alpine");
    }

    #[test]
    fn host_a_y_b_independientes_mismo_material() {
        let digest = canonical_fabric_digest(&material()).unwrap();
        let mut other = material();
        other.install_mode = "published_images".to_string();
        assert_eq!(digest, canonical_fabric_digest(&other).unwrap());
    }

    #[test]
    fn drift_exige_adopt_y_no_tofu() {
        let canonical = canonical_fabric_digest(&material()).unwrap();
        let mut observed = material();
        observed.declared_images[0].image = "nats:2.11.0-alpine".to_string();
        let observed_digest = canonical_fabric_digest(&observed).unwrap();
        let (status, drift) = evaluate_fabric_lifecycle(
            &canonical,
            &canonical,
            &observed_digest,
            FabricReconcileMode::OwnerAdopt,
        );
        assert_eq!(status, FabricLifecycleStatus::AdoptRequired);
        assert_eq!(drift, "observed_declared_mismatch");
        assert_ne!(canonical, observed_digest);
    }

    #[test]
    fn auto_reconcile_marca_drift_sin_adoptar() {
        let canonical = canonical_fabric_digest(&material()).unwrap();
        let mut observed = material();
        observed.compose_digest = "c".repeat(64);
        let observed_digest = canonical_fabric_digest(&observed).unwrap();
        let (status, _) = evaluate_fabric_lifecycle(
            &canonical,
            &canonical,
            &observed_digest,
            FabricReconcileMode::AutoReconcile,
        );
        assert_eq!(status, FabricLifecycleStatus::DriftDetected);
    }

    #[test]
    fn adopt_crea_generation_nueva_y_lkg() {
        let canonical = canonical_fabric_digest(&material()).unwrap();
        let mut observed = material();
        observed.install_mode = "local_build".to_string();
        let observed_digest = canonical_fabric_digest(&observed).unwrap();
        let state = FabricCanonicalState {
            schema: FABRIC_CANONICAL_STATE_SCHEMA,
            fabric_id: "d2bc7de4-3b87-4ae5-916f-93a5a14150b7".to_string(),
            attestation_schema: FABRIC_ATTESTATION_SCHEMA_V2,
            canonicalization_version: FABRIC_CANONICALIZATION_VERSION,
            instance_generation: 1,
            canonical_fabric_digest: canonical.clone(),
            desired_canonical_fabric_digest: canonical.clone(),
            runtime_evidence_digest: "1".repeat(64),
            lkg_canonical_fabric_digest: None,
            lkg_instance_generation: None,
            lifecycle_status: FabricLifecycleStatus::AdoptRequired,
            drift_status: "observed_declared_mismatch".to_string(),
            install_mode: "published_images".to_string(),
            compose_digest: "b".repeat(64),
            pinned_repo_digests: Vec::new(),
            last_adopt_receipt: None,
        };
        let (next, receipt) =
            adopt_observed_fabric(&state, &observed_digest, "2026-09-12T00:00:00Z").unwrap();
        assert_eq!(receipt.from_generation, 1);
        assert_eq!(receipt.to_generation, 2);
        assert_eq!(next.instance_generation, 2);
        assert_eq!(next.canonical_fabric_digest, observed_digest);
        assert_eq!(next.lkg_canonical_fabric_digest.as_deref(), Some(canonical.as_str()));
        assert_eq!(next.lifecycle_status, FabricLifecycleStatus::Steady);
        let rolled = rollback_to_lkg(&next).unwrap();
        assert_eq!(rolled.desired_canonical_fabric_digest, canonical);
        assert_eq!(rolled.lifecycle_status, FabricLifecycleStatus::RollingBack);
    }

    #[test]
    fn adopt_idempotente_sin_cambio_falla() {
        let canonical = canonical_fabric_digest(&material()).unwrap();
        let state = FabricCanonicalState {
            schema: FABRIC_CANONICAL_STATE_SCHEMA,
            fabric_id: "d2bc7de4-3b87-4ae5-916f-93a5a14150b7".to_string(),
            attestation_schema: FABRIC_ATTESTATION_SCHEMA_V2,
            canonicalization_version: FABRIC_CANONICALIZATION_VERSION,
            instance_generation: 1,
            canonical_fabric_digest: canonical.clone(),
            desired_canonical_fabric_digest: canonical.clone(),
            runtime_evidence_digest: "1".repeat(64),
            lkg_canonical_fabric_digest: None,
            lkg_instance_generation: None,
            lifecycle_status: FabricLifecycleStatus::AdoptRequired,
            drift_status: "observed_declared_mismatch".to_string(),
            install_mode: "published_images".to_string(),
            compose_digest: "b".repeat(64),
            pinned_repo_digests: Vec::new(),
            last_adopt_receipt: None,
        };
        let error = adopt_observed_fabric(&state, &canonical, "2026-09-12T00:00:00Z")
            .expect_err("adopt without change");
        assert_eq!(error, "FABRIC_ADOPT_NO_MATERIAL_CHANGE");
    }
}
