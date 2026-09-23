//! One read-only resolver for Supervisor configuration and its versioned
//! migrations.  Preflight, `--check`, staging, and runtime loading consume the
//! same resolved value; only deployment activation persists `canonical_toml`.

#[cfg(windows)]
use super::program_data_root;
use super::{default_trust_store_path, SupervisorConfig};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub const CURRENT_CONFIG_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum DeploymentEnvironment {
    Stable,
    Lab,
}

impl DeploymentEnvironment {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Lab => "lab",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "stable" => Ok(Self::Stable),
            "lab" => Ok(Self::Lab),
            _ => Err("CONFIG_EFFECTIVE_STATE_INVALID: deployment_environment is unsupported".into()),
        }
    }
}

impl std::fmt::Display for DeploymentEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub(super) struct EffectiveSupervisorConfig {
    pub config: SupervisorConfig,
    pub source_schema_version: u32,
    pub schema_version: u32,
    pub config_digest: String,
    pub canonical_toml: String,
    pub migrations: Vec<String>,
}

pub(super) fn resolve_effective_supervisor_config(
    path: &Path,
) -> Result<EffectiveSupervisorConfig, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("CONFIG_EFFECTIVE_STATE_INVALID: cannot read config: {error}"))?;
    resolve_effective_supervisor_config_text(&source)
}

fn resolve_effective_supervisor_config_text(
    source: &str,
) -> Result<EffectiveSupervisorConfig, String> {
    let mut document = source
        .parse::<toml::Value>()
        .map_err(|error| format!("CONFIG_EFFECTIVE_STATE_INVALID: invalid TOML: {error}"))?;
    if !document.is_table() {
        return Err("CONFIG_EFFECTIVE_STATE_INVALID: config root must be a table".into());
    }

    // An unversioned installation is the only legacy input and is explicitly
    // treated as schema v1. Future schema versions fail closed.
    let source_schema_version = match document.get("config_schema_version") {
        None => 1,
        Some(toml::Value::Integer(version)) if *version > 0 => u32::try_from(*version)
            .map_err(|_| "CONFIG_SCHEMA_UNSUPPORTED: version is out of range".to_string())?,
        Some(_) => return Err("CONFIG_SCHEMA_UNSUPPORTED: invalid schema version".into()),
    };
    if source_schema_version > CURRENT_CONFIG_SCHEMA_VERSION {
        return Err(format!(
            "CONFIG_SCHEMA_UNSUPPORTED: found {source_schema_version}, supported through {CURRENT_CONFIG_SCHEMA_VERSION}"
        ));
    }
    if source_schema_version == 0 {
        return Err("CONFIG_SCHEMA_UNSUPPORTED: version 0 is invalid".into());
    }

    let mut version = source_schema_version;
    let mut migrations = Vec::new();
    while version < CURRENT_CONFIG_SCHEMA_VERSION {
        match version {
            1 => {
                migrate_v1_to_v2(&mut document)?;
                migrations.push("v1->v2".into());
                version = 2;
            }
            2 => {
                migrate_v2_to_v3(&mut document)?;
                migrations.push("v2->v3".into());
                version = 3;
            }
            unsupported => {
                return Err(format!(
                    "CONFIG_SCHEMA_UNSUPPORTED: no migration path from v{unsupported}"
                ));
            }
        }
    }

    if document.get("trust_store_path").is_none() {
        return Err("TRUST_STORE_PATH_REQUIRED: schema v3 requires an explicit path".into());
    }
    if document.get("product_channel").is_some() {
        return Err(
            "CONFIG_EFFECTIVE_STATE_INVALID: schema v3 cannot contain product_channel".into(),
        );
    }
    let config: SupervisorConfig = document
        .clone()
        .try_into()
        .map_err(|error| format!("CONFIG_EFFECTIVE_STATE_INVALID: {error}"))?;
    config.validate().map_err(|error| {
        if error.starts_with("TRUST_STORE_") || error.starts_with("CONFIG_") {
            error
        } else {
            format!("CONFIG_EFFECTIVE_STATE_INVALID: {error}")
        }
    })?;

    // Serialize the typed value so defaults participate in the digest. This
    // prevents an omitted default and an explicit default from producing two
    // effective configurations with different identities.
    let mut canonical_value: toml::Value = toml::to_string(&config)
        .map_err(|error| format!("CONFIG_EFFECTIVE_STATE_INVALID: serialize: {error}"))?
        .parse()
        .map_err(|error| format!("CONFIG_EFFECTIVE_STATE_INVALID: canonical TOML: {error}"))?;
    canonical_value
        .as_table_mut()
        .ok_or_else(|| "CONFIG_EFFECTIVE_STATE_INVALID: canonical root is not a table".to_string())?
        .insert(
            "config_schema_version".into(),
            toml::Value::Integer(CURRENT_CONFIG_SCHEMA_VERSION as i64),
        );
    let canonical_toml = toml::to_string(&canonical_value)
        .map_err(|error| format!("CONFIG_EFFECTIVE_STATE_INVALID: serialize canonical: {error}"))?;
    let digest = Sha256::digest(canonical_toml.as_bytes());
    let config_digest = format!("sha256:{}", encode_hex(&digest));

    Ok(EffectiveSupervisorConfig {
        config,
        source_schema_version,
        schema_version: CURRENT_CONFIG_SCHEMA_VERSION,
        config_digest,
        canonical_toml,
        migrations,
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn migrate_v1_to_v2(document: &mut toml::Value) -> Result<(), String> {
    let table = document
        .as_table_mut()
        .ok_or_else(|| "CONFIG_MIGRATION_FAILED: v1 root must be a table".to_string())?;
    let environment = match table.get("product_channel") {
        None => DeploymentEnvironment::Stable,
        Some(toml::Value::String(value)) => DeploymentEnvironment::parse(value)
            .map_err(|_| "CONFIG_MIGRATION_FAILED: product_channel is unsupported".to_string())?,
        Some(_) => return Err("CONFIG_MIGRATION_FAILED: product_channel must be a string".into()),
    };
    table.insert(
        "product_channel".into(),
        toml::Value::String(environment.as_str().into()),
    );
    if !table.contains_key("trust_store_path") {
        table.insert(
            "trust_store_path".into(),
            toml::Value::String(
                canonical_trust_store_path(environment)
                    .to_string_lossy()
                    .into_owned(),
            ),
        );
    }
    table.insert("config_schema_version".into(), toml::Value::Integer(2));
    Ok(())
}

fn migrate_v2_to_v3(document: &mut toml::Value) -> Result<(), String> {
    let table = document
        .as_table_mut()
        .ok_or_else(|| "CONFIG_MIGRATION_FAILED: v2 root must be a table".to_string())?;
    let legacy_environment = match table.remove("product_channel") {
        None => None,
        Some(toml::Value::String(value)) => Some(DeploymentEnvironment::parse(&value)
            .map_err(|_| "CONFIG_MIGRATION_FAILED: product_channel is unsupported".to_string())?),
        Some(_) => {
            return Err("CONFIG_MIGRATION_FAILED: product_channel must be a string".into())
        }
    };
    let explicit_environment = match table.remove("deployment_environment") {
        Some(toml::Value::String(value)) => Some(DeploymentEnvironment::parse(&value)
            .map_err(|_| "CONFIG_MIGRATION_FAILED: deployment_environment is unsupported".to_string())?),
        Some(_) => {
            return Err(
                "CONFIG_MIGRATION_FAILED: deployment_environment must be a string".into(),
            )
        }
        None => None,
    };
    if legacy_environment.is_some()
        && explicit_environment.is_some()
        && legacy_environment != explicit_environment
    {
        return Err("CONFIG_MIGRATION_FAILED: conflicting legacy environment fields".into());
    }
    let environment = explicit_environment
        .or(legacy_environment)
        .unwrap_or(DeploymentEnvironment::Stable);
    if !table.contains_key("trust_store_path") {
        table.insert(
            "trust_store_path".into(),
            toml::Value::String(
                canonical_trust_store_path(environment)
                    .to_string_lossy()
                    .into_owned(),
            ),
        );
    }
    table.insert(
        "deployment_environment".into(),
        toml::Value::String(environment.as_str().into()),
    );
    table.insert("config_schema_version".into(), toml::Value::Integer(3));
    Ok(())
}

pub(super) fn canonical_trust_store_path(environment: DeploymentEnvironment) -> PathBuf {
    match environment {
        DeploymentEnvironment::Lab => {
            #[cfg(unix)]
            {
                PathBuf::from("/var/lib/actium/node-manager-lab/trust/trust-bundle.json")
            }
            #[cfg(windows)]
            {
                program_data_root()
                    .join("NodeManagerLab")
                    .join("trust")
                    .join("trust-bundle.json")
            }
        }
        DeploymentEnvironment::Stable => default_trust_store_path(),
    }
}

pub(super) fn validate_trust_store_path(
    environment: DeploymentEnvironment,
    path: &Path,
) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return Err("TRUST_STORE_PATH_REQUIRED: path must be absolute".into());
    }
    let stable_store = default_trust_store_path();
    let stable_root = stable_store
        .parent()
        .ok_or_else(|| "TRUST_STORE_PATH_REQUIRED: stable namespace is invalid".to_string())?;
    let lab_store = canonical_trust_store_path(DeploymentEnvironment::Lab);
    let lab_root = lab_store
        .parent()
        .ok_or_else(|| "TRUST_STORE_PATH_REQUIRED: lab namespace is invalid".to_string())?;
    if (environment == DeploymentEnvironment::Lab && path.starts_with(stable_root))
        || (environment == DeploymentEnvironment::Stable && path.starts_with(lab_root))
    {
        return Err(
            "TRUST_STORE_ENVIRONMENT_MISMATCH: path belongs to another deployment environment namespace".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn minimal_lab_v1() -> String {
        "product_channel = \"lab\"\nfabric_project = \"actium-lab-fabric-01\"\nfabric_network = \"actium-lab-fabric-01\"\n".into()
    }

    #[test]
    fn legacy_lab_config_migrates_in_memory_to_canonical_lab_trust_store() {
        let root = std::env::temp_dir().join(format!("supervisor-config-v1-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("supervisor.toml");
        let source = minimal_lab_v1();
        fs::write(&path, &source).unwrap();

        let resolved = resolve_effective_supervisor_config(&path).unwrap();
        assert_eq!(resolved.source_schema_version, 1);
        assert_eq!(resolved.schema_version, 3);
        assert_eq!(resolved.migrations, ["v1->v2", "v2->v3"]);
        assert_eq!(
            resolved.config.trust_store_path,
            canonical_trust_store_path(DeploymentEnvironment::Lab)
        );
        assert!(resolved
            .canonical_toml
            .contains("config_schema_version = 3"));
        assert!(resolved
            .canonical_toml
            .contains("deployment_environment = \"lab\""));
        assert!(!resolved.canonical_toml.contains("product_channel"));
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_stable_config_migrates_to_only_the_stable_trust_namespace() {
        let root =
            std::env::temp_dir().join(format!("supervisor-config-stable-v1-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("supervisor.toml");
        let source = "product_channel = \"stable\"\nfabric_project = \"actium-node-fabric-01\"\nfabric_network = \"actium-node-fabric-01\"\n";
        fs::write(&path, source).unwrap();

        let resolved = resolve_effective_supervisor_config(&path).unwrap();
        assert_eq!(resolved.source_schema_version, 1);
        assert_eq!(resolved.schema_version, 3);
        assert_eq!(resolved.migrations, ["v1->v2", "v2->v3"]);
        assert_eq!(
            resolved.config.trust_store_path,
            canonical_trust_store_path(DeploymentEnvironment::Stable)
        );
        assert!(!resolved
            .config
            .trust_store_path
            .starts_with(canonical_trust_store_path(DeploymentEnvironment::Lab)));
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn effective_digest_includes_defaults_and_is_deterministic() {
        let root =
            std::env::temp_dir().join(format!("supervisor-config-digest-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("supervisor.toml");
        fs::write(&path, minimal_lab_v1()).unwrap();
        let first = resolve_effective_supervisor_config(&path).unwrap();
        let second = resolve_effective_supervisor_config(&path).unwrap();
        assert_eq!(first.config_digest, second.config_digest);
        assert!(first
            .canonical_toml
            .contains("runtime_reconcile_interval_seconds"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn migrated_effective_config_round_trips_without_changing_digest() {
        let root =
            std::env::temp_dir().join(format!("supervisor-config-roundtrip-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let source_path = root.join("legacy.toml");
        let staged_path = root.join("staged.toml");
        fs::write(&source_path, minimal_lab_v1()).unwrap();

        let preflight = resolve_effective_supervisor_config(&source_path).unwrap();
        fs::write(&staged_path, &preflight.canonical_toml).unwrap();
        let runtime = resolve_effective_supervisor_config(&staged_path).unwrap();

        assert_eq!(runtime.source_schema_version, CURRENT_CONFIG_SCHEMA_VERSION);
        assert!(runtime.migrations.is_empty());
        assert_eq!(preflight.config_digest, runtime.config_digest);
        assert_eq!(
            preflight.config.trust_store_path,
            runtime.config.trust_store_path
        );
        assert_eq!(
            preflight.config.deployment_environment,
            runtime.config.deployment_environment
        );
        assert_eq!(fs::read_to_string(&source_path).unwrap(), minimal_lab_v1());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn channel_cross_binding_is_rejected_by_path_namespace() {
        let error = validate_trust_store_path(
            DeploymentEnvironment::Lab,
            &default_trust_store_path(),
        )
        .unwrap_err();
        assert!(error.starts_with("TRUST_STORE_ENVIRONMENT_MISMATCH"), "{error}");
        let error =
            validate_trust_store_path(
                DeploymentEnvironment::Stable,
                &canonical_trust_store_path(DeploymentEnvironment::Lab),
            )
            .unwrap_err();
        assert!(error.starts_with("TRUST_STORE_ENVIRONMENT_MISMATCH"), "{error}");
    }

    #[test]
    fn schema_v2_migrates_old_product_channel_to_deployment_environment() {
        let trust_path = toml::Value::String(
            canonical_trust_store_path(DeploymentEnvironment::Lab)
                .to_string_lossy()
                .into_owned(),
        );
        let source = format!(
            "config_schema_version = 2\nproduct_channel = \"lab\"\ntrust_store_path = {trust_path}\nfabric_project = \"actium-lab-fabric-01\"\nfabric_network = \"actium-lab-fabric-01\"\n"
        );
        let resolved = resolve_effective_supervisor_config_text(&source).unwrap();
        assert_eq!(resolved.source_schema_version, 2);
        assert_eq!(resolved.schema_version, 3);
        assert_eq!(resolved.migrations, ["v2->v3"]);
        assert_eq!(resolved.config.deployment_environment, DeploymentEnvironment::Lab);
        assert!(!resolved.canonical_toml.contains("product_channel"));
    }

    #[test]
    fn schema_v2_lab_without_trust_path_migrates_to_canonical_lab_store() {
        let source = "config_schema_version = 2\nproduct_channel = \"lab\"\nfabric_project = \"actium-lab-fabric-01\"\nfabric_network = \"actium-lab-fabric-01\"\n";
        let resolved = resolve_effective_supervisor_config_text(source).unwrap();
        assert_eq!(resolved.config.deployment_environment, DeploymentEnvironment::Lab);
        assert_eq!(
            resolved.config.trust_store_path,
            canonical_trust_store_path(DeploymentEnvironment::Lab)
        );
        assert!(resolved.migrations.contains(&"v2->v3".into()));
    }

    #[test]
    fn unsupported_schema_version_has_a_stable_error_code() {
        let error =
            resolve_effective_supervisor_config_text("config_schema_version = 99\n").unwrap_err();
        assert!(error.starts_with("CONFIG_SCHEMA_UNSUPPORTED"), "{error}");
    }
}
