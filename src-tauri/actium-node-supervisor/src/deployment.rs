//! Durable, deployment-environment-scoped Supervisor transaction state.
//!
//! The journal is the authority for an interrupted deployment.  Runtime
//! process state and the `current` reference are observations used to
//! reconcile it; neither is silently treated as a completed transaction.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) const DEPLOYMENT_PROTOCOL_VERSION: u32 = 1;
pub(super) const DEPLOYMENT_JOURNAL_SCHEMA_VERSION: u32 = 2;
pub(super) const TRUST_STORE_SCHEMA_VERSION: u32 = 3;
const REQUIRED_PROMOTION_SMOKE_CHECKS: [&str; 8] = [
    "supervisor-self-test:PASS",
    "supervisor-ipc-ping:PASS",
    "authority-served-ready:PASS",
    "trust-store-channel-epoch-bundle-authority-binding:PASS",
    "runtime-process-config-artifact-receipt-match:PASS",
    "manager-ui-functional:PASS",
    "supervisor-channel-functional:PASS",
    "authority-trust-functional:PASS",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompatibilityManifest {
    schema_version: u32,
    release_channel: ReleaseChannel,
    manager: VersionRange,
    supervisor: VersionRange,
    authority: VersionRange,
    supervisor_config_schema: SchemaRange,
    trust_store_schema: SchemaRange,
    authority_protocol: String,
    authority_lifecycle_protocol: String,
    deployment_protocol: SchemaRange,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum ReleaseChannel {
    #[serde(rename = "DEV")]
    Dev,
    #[serde(rename = "RC")]
    Rc,
    #[serde(rename = "STABLE")]
    Stable,
}

impl ReleaseChannel {
    fn matches_manager_version(self, value: &str) -> bool {
        let Ok(version) = semver::Version::parse(value) else {
            return false;
        };
        let prerelease = version.pre.as_str();
        let first_identifier = prerelease.split('.').next().unwrap_or_default();
        match self {
            Self::Dev => !prerelease.is_empty() && first_identifier != "rc",
            Self::Rc => first_identifier == "rc",
            Self::Stable => prerelease.is_empty(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionRange {
    minimum: String,
    maximum: String,
}

impl VersionRange {
    fn contains(&self, candidate: &str) -> bool {
        let Ok(version) = semver::Version::parse(candidate) else {
            return false;
        };
        let Ok(minimum) = semver::Version::parse(&self.minimum) else {
            return false;
        };
        let Ok(maximum) = semver::Version::parse(&self.maximum) else {
            return false;
        };
        minimum <= version && version <= maximum
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SchemaRange {
    minimum: u32,
    maximum: u32,
}

impl SchemaRange {
    fn contains(&self, candidate: u32) -> bool {
        self.minimum <= candidate && candidate <= self.maximum
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum DeploymentState {
    Created,
    Staging,
    Staged,
    PreflightPassed,
    ReadyToActivate,
    Activating,
    Verifying,
    Committed,
    RollingBack,
    RolledBack,
    Failed,
    Blocked,
}

impl DeploymentState {
    fn can_transition_to(self, next: Self) -> bool {
        use DeploymentState::*;
        matches!(
            (self, next),
            (Created, Staging)
                | (Created, Failed)
                | (Staging, Staged)
                | (Staging, Failed)
                | (Staged, PreflightPassed)
                | (Staged, Failed)
                | (PreflightPassed, ReadyToActivate)
                | (PreflightPassed, Failed)
                | (ReadyToActivate, Activating)
                | (ReadyToActivate, RollingBack)
                | (ReadyToActivate, Failed)
                | (ReadyToActivate, RolledBack)
                | (Activating, Verifying)
                | (Activating, RollingBack)
                | (Activating, Failed)
                | (Verifying, Committed)
                | (Verifying, RollingBack)
                | (Verifying, Failed)
                | (Committed, RollingBack)
                | (Blocked, RollingBack)
                | (RollingBack, RolledBack)
                | (RollingBack, Failed)
        ) || matches!(next, Blocked) && !matches!(self, RolledBack | Failed | Blocked)
            || self == next
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DeploymentJournal {
    pub schema_version: u32,
    pub deployment_id: String,
    #[serde(alias = "channel")]
    pub deployment_environment: super::effective_config::DeploymentEnvironment,
    #[serde(default)]
    pub release_channel: Option<ReleaseChannel>,
    pub artifact_digest: String,
    pub previous_artifact_digest: Option<String>,
    pub previous_deployment_id: Option<String>,
    pub config_digest: String,
    pub config_generation: u64,
    pub trust_store_id: Option<String>,
    #[serde(default)]
    pub trust_bundle_id: Option<String>,
    pub trust_epoch: u64,
    #[serde(default)]
    pub served_authority_id: Option<String>,
    pub authority_generation: u64,
    pub activation_generation: u64,
    #[serde(default)]
    pub supervisor_binary_digest: Option<String>,
    #[serde(default)]
    pub authority_binary_digest: Option<String>,
    #[serde(default)]
    pub previous_authority_target: Option<String>,
    #[serde(default)]
    pub previous_authority_binary_digest: Option<String>,
    #[serde(default)]
    pub previous_authority_build_info: Option<serde_json::Value>,
    #[serde(default)]
    pub trust_store_migrated: bool,
    pub state: DeploymentState,
    pub created_at: String,
    pub updated_at: String,
    pub failure_code: Option<String>,
}

impl DeploymentJournal {
    pub(super) fn new(
        deployment_id: String,
        deployment_environment: super::effective_config::DeploymentEnvironment,
        artifact_digest: String,
        previous_artifact_digest: Option<String>,
        previous_deployment_id: Option<String>,
        config_digest: String,
        config_generation: u64,
        trust_store_id: Option<String>,
        trust_epoch: u64,
        authority_generation: u64,
        activation_generation: u64,
    ) -> Self {
        let now = timestamp();
        Self {
            schema_version: DEPLOYMENT_JOURNAL_SCHEMA_VERSION,
            deployment_id,
            deployment_environment,
            release_channel: None,
            artifact_digest,
            previous_artifact_digest,
            previous_deployment_id,
            config_digest,
            config_generation,
            trust_store_id,
            trust_bundle_id: None,
            trust_epoch,
            served_authority_id: None,
            authority_generation,
            activation_generation,
            supervisor_binary_digest: None,
            authority_binary_digest: None,
            previous_authority_target: None,
            previous_authority_binary_digest: None,
            previous_authority_build_info: None,
            trust_store_migrated: false,
            state: DeploymentState::Created,
            created_at: now.clone(),
            updated_at: now,
            failure_code: None,
        }
    }

    pub(super) fn transition(&mut self, next: DeploymentState) -> Result<(), String> {
        if !self.state.can_transition_to(next) {
            return Err("DEPLOYMENT_STATE_TRANSITION_INVALID".into());
        }
        self.state = next;
        self.updated_at = timestamp();
        Ok(())
    }

    pub(super) fn fail(&mut self, code: &str) -> Result<(), String> {
        if code.is_empty()
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err("DEPLOYMENT_ERROR_CODE_INVALID".into());
        }
        self.transition(DeploymentState::Failed)?;
        self.failure_code = Some(code.into());
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ActivationReceipt {
    pub schema_version: u32,
    pub deployment_id: String,
    #[serde(alias = "channel")]
    pub deployment_environment: super::effective_config::DeploymentEnvironment,
    #[serde(default)]
    release_channel: Option<ReleaseChannel>,
    pub artifact_digest: String,
    #[serde(default)]
    pub supervisor_binary_digest: Option<String>,
    #[serde(default)]
    pub authority_binary_digest: Option<String>,
    #[serde(default)]
    pub authority_build_info: Option<serde_json::Value>,
    pub config_digest: String,
    pub trust_store_id: Option<String>,
    #[serde(default)]
    pub trust_bundle_id: Option<String>,
    pub trust_epoch: u64,
    #[serde(default)]
    pub served_authority_id: Option<String>,
    pub authority_generation: u64,
    pub activation_generation: u64,
    pub build_id: String,
    pub source_commit: String,
    pub activated_at: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RollbackReceipt {
    schema_version: u32,
    deployment_id: String,
    #[serde(alias = "channel")]
    deployment_environment: super::effective_config::DeploymentEnvironment,
    #[serde(default)]
    release_channel: Option<ReleaseChannel>,
    failed_artifact_digest: String,
    restored_deployment_id: Option<String>,
    restored_artifact_digest: Option<String>,
    restored_supervisor_digest: Option<String>,
    #[serde(default)]
    restored_authority_binary_digest: Option<String>,
    restored_config_digest: Option<String>,
    #[serde(default)]
    restored_supervisor_build_info: Option<serde_json::Value>,
    #[serde(default)]
    restored_authority_build_info: Option<serde_json::Value>,
    trust_store_id: Option<String>,
    trust_bundle_id: Option<String>,
    trust_epoch: u64,
    served_authority_id: String,
    authority_generation: u64,
    activation_generation: u64,
    verified_at: String,
    result: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum DeploymentErrorCode {
    TrustStorePathRequired,
    TrustStoreEnvironmentMismatch,
    TrustStoreSchemaUnsupported,
    TrustStorePermissionInvalid,
    TrustStoreEpochMismatch,
    TrustStoreMetadataRequired,
    DeploymentEnvironmentMismatch,
    ConfigSchemaUnsupported,
    ConfigMigrationFailed,
    ConfigEffectiveStateInvalid,
    ConfigDigestMismatch,
    AuthorityBindingMismatch,
    AuthorityGenerationMismatch,
    AuthorityTrustBundleUnavailable,
    DeploymentAuthorityBaselineRequired,
    ArtifactIncompatible,
    ArtifactDigestMismatch,
    DeploymentPreflightFailed,
    DeploymentStageFailed,
    DeploymentActivationFailed,
    DeploymentVerificationFailed,
    DeploymentRollbackFailed,
    DeploymentRollbackPointerAmbiguous,
    DeploymentReconciliationAmbiguous,
    DeploymentServiceNotActive,
    DeploymentLegacyRuntimeUnavailable,
    DeploymentCurrentRuntimeUnavailable,
    DeploymentServiceLaunchFailed,
    DeploymentBlocked,
    DeploymentPromotionSmokeRequired,
    DeploymentPromotionSmokeInvalid,
    DeploymentPromotionSmokeCopyFailed,
}

impl DeploymentErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::TrustStorePathRequired => "TRUST_STORE_PATH_REQUIRED",
            Self::TrustStoreEnvironmentMismatch => "TRUST_STORE_ENVIRONMENT_MISMATCH",
            Self::TrustStoreSchemaUnsupported => "TRUST_STORE_SCHEMA_UNSUPPORTED",
            Self::TrustStorePermissionInvalid => "TRUST_STORE_PERMISSION_INVALID",
            Self::TrustStoreEpochMismatch => "TRUST_STORE_EPOCH_MISMATCH",
            Self::TrustStoreMetadataRequired => "TRUST_STORE_METADATA_REQUIRED",
            Self::DeploymentEnvironmentMismatch => "DEPLOYMENT_ENVIRONMENT_MISMATCH",
            Self::ConfigSchemaUnsupported => "CONFIG_SCHEMA_UNSUPPORTED",
            Self::ConfigMigrationFailed => "CONFIG_MIGRATION_FAILED",
            Self::ConfigEffectiveStateInvalid => "CONFIG_EFFECTIVE_STATE_INVALID",
            Self::ConfigDigestMismatch => "CONFIG_DIGEST_MISMATCH",
            Self::AuthorityBindingMismatch => "AUTHORITY_BINDING_MISMATCH",
            Self::AuthorityGenerationMismatch => "AUTHORITY_GENERATION_MISMATCH",
            Self::AuthorityTrustBundleUnavailable => "AUTHORITY_TRUST_BUNDLE_UNAVAILABLE",
            Self::DeploymentAuthorityBaselineRequired => "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED",
            Self::ArtifactIncompatible => "ARTIFACT_INCOMPATIBLE",
            Self::ArtifactDigestMismatch => "ARTIFACT_DIGEST_MISMATCH",
            Self::DeploymentPreflightFailed => "DEPLOYMENT_PREFLIGHT_FAILED",
            Self::DeploymentStageFailed => "DEPLOYMENT_STAGE_FAILED",
            Self::DeploymentActivationFailed => "DEPLOYMENT_ACTIVATION_FAILED",
            Self::DeploymentVerificationFailed => "DEPLOYMENT_VERIFICATION_FAILED",
            Self::DeploymentRollbackFailed => "DEPLOYMENT_ROLLBACK_FAILED",
            Self::DeploymentRollbackPointerAmbiguous => "DEPLOYMENT_ROLLBACK_POINTER_AMBIGUOUS",
            Self::DeploymentReconciliationAmbiguous => "DEPLOYMENT_RECONCILIATION_AMBIGUOUS",
            Self::DeploymentServiceNotActive => "DEPLOYMENT_SERVICE_NOT_ACTIVE",
            Self::DeploymentLegacyRuntimeUnavailable => "DEPLOYMENT_LEGACY_RUNTIME_UNAVAILABLE",
            Self::DeploymentCurrentRuntimeUnavailable => "DEPLOYMENT_CURRENT_RUNTIME_UNAVAILABLE",
            Self::DeploymentServiceLaunchFailed => "DEPLOYMENT_SERVICE_LAUNCH_FAILED",
            Self::DeploymentBlocked => "DEPLOYMENT_BLOCKED",
            Self::DeploymentPromotionSmokeRequired => "DEPLOYMENT_PROMOTION_SMOKE_REQUIRED",
            Self::DeploymentPromotionSmokeInvalid => "DEPLOYMENT_PROMOTION_SMOKE_INVALID",
            Self::DeploymentPromotionSmokeCopyFailed => "DEPLOYMENT_PROMOTION_SMOKE_COPY_FAILED",
        }
    }
}

pub(super) fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "DEPLOYMENT_JOURNAL_PATH_INVALID".to_string())?;
    fs::create_dir_all(parent).map_err(|_| "DEPLOYMENT_JOURNAL_WRITE_FAILED".to_string())?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED".to_string())?;
    let file_name = path
        .file_name()
        .ok_or_else(|| "DEPLOYMENT_JOURNAL_PATH_INVALID".to_string())?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| "DEPLOYMENT_JOURNAL_WRITE_FAILED".to_string())?;
    use std::io::Write;
    file.write_all(&bytes)
        .map_err(|_| "DEPLOYMENT_JOURNAL_WRITE_FAILED".to_string())?;
    file.sync_all()
        .map_err(|_| "DEPLOYMENT_JOURNAL_SYNC_FAILED".to_string())?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("DEPLOYMENT_JOURNAL_COMMIT_FAILED: {error}"));
    }
    if let Ok(directory) = fs::File::open(parent) {
        directory
            .sync_all()
            .map_err(|_| "DEPLOYMENT_JOURNAL_SYNC_FAILED".to_string())?;
    }
    Ok(())
}

pub(super) fn load_journal(path: &Path) -> Result<DeploymentJournal, String> {
    let bytes = fs::read(path).map_err(|_| "DEPLOYMENT_JOURNAL_UNAVAILABLE".to_string())?;
    let journal: DeploymentJournal =
        serde_json::from_slice(&bytes).map_err(|_| "DEPLOYMENT_JOURNAL_INVALID".to_string())?;
    if !matches!(journal.schema_version, 1 | DEPLOYMENT_JOURNAL_SCHEMA_VERSION) {
        return Err("DEPLOYMENT_JOURNAL_SCHEMA_UNSUPPORTED".into());
    }
    Ok(journal)
}

pub(super) fn deployment_dir(root: &Path, deployment_id: &str) -> Result<PathBuf, String> {
    validate_deployment_id(deployment_id)?;
    Ok(root.join("deployments").join(deployment_id))
}

fn validate_deployment_id(value: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(value).is_ok()
        || value.strip_prefix("legacy-").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        })
    {
        return Ok(());
    }
    Err("DEPLOYMENT_ID_INVALID".into())
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    format!("unix:{seconds}")
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let command = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| "DEPLOYMENT_COMMAND_REQUIRED".to_string())?;
    let options = parse_options(&args[1..])?;
    // `--channel` is an explicitly retained CLI compatibility alias. Internally
    // this selector is the host deployment environment, never a release track.
    let environment = options
        .get("environment")
        .or_else(|| options.get("channel"))
        .map(String::as_str)
        .unwrap_or("stable");
    let environment = super::effective_config::DeploymentEnvironment::parse(environment)
        .map_err(|_| "DEPLOYMENT_ENVIRONMENT_INVALID".to_string())?;
    let environment = environment.as_str();
    let root = options
        .get("root")
        .map(PathBuf::from)
        .unwrap_or_else(|| default_root(environment));
    #[cfg(unix)]
    let _deployment_lock = if matches!(
        command,
        "capture-legacy"
            | "capture-authority-baseline"
            | "preflight"
            | "stage"
            | "deploy"
            | "promote-lab"
            | "activate"
            | "verify"
            | "rollback"
            | "reconcile"
            | "reconcile-all"
    ) {
        Some(DeploymentLock::acquire()?)
    } else {
        None
    };
    match command {
        "status" => print_status(&root, environment),
        "inspect" => {
            let id = options
                .get("id")
                .ok_or_else(|| "DEPLOYMENT_ID_REQUIRED".to_string())?;
            let directory = deployment_dir(&root, id)?;
            let journal = load_journal(&directory.join("journal.json"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&journal)
                    .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
            );
            Ok(())
        }
        "capture-legacy" => capture_legacy_baseline(
            &root,
            environment,
            options.get("config").map(PathBuf::from).as_deref(),
        ),
        "capture-authority-baseline" => capture_authority_legacy_baseline(),
        "stage" => {
            let deployment_id = stage_candidate(&options, &root, environment)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "deploymentId": deployment_id,
                    "deploymentEnvironment": environment,
                    "state": "READY_TO_ACTIVATE",
                }))
                .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
            );
            Ok(())
        }
        "deploy" => deploy_candidate(&options, &root, environment),
        "promote-lab" => {
            if environment != "lab" {
                return Err("DEPLOYMENT_ENVIRONMENT_INVALID".into());
            }
            let deployment_id = options
                .get("id")
                .ok_or_else(|| "DEPLOYMENT_ID_REQUIRED".to_string())?;
            let report = options
                .get("smoke-report")
                .map(PathBuf::from)
                .ok_or_else(|| "DEPLOYMENT_PROMOTION_SMOKE_REQUIRED".to_string())?;
            let evidence = options
                .get("smoke-evidence")
                .map(PathBuf::from)
                .ok_or_else(|| "DEPLOYMENT_PROMOTION_SMOKE_REQUIRED".to_string())?;
            promote_lab_deployment(&root, deployment_id, &report, &evidence)
        }
        "preflight" => preflight_candidate(&options, environment),
        "activate" => with_deployment_id(&options, &root, activate_deployment),
        "verify" => with_deployment_id(&options, &root, verify_deployment),
        "rollback" => with_deployment_id(&options, &root, rollback_deployment),
        "reconcile" => with_deployment_id(&options, &root, reconcile_deployment),
        "reconcile-all" => reconcile_pending_transactions(),
        _ => Err("DEPLOYMENT_COMMAND_INVALID".into()),
    }
}

pub(super) fn launch_service(args: &[String]) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = args;
        return Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let options = parse_options(args)?;
        match service_launch_target(&options)? {
            ServiceLaunchTarget::Authority => {
                let binary = select_authority_runtime(
                &authority_runtime_root(),
                Path::new("/usr/lib/Actium Node Manager/authority/actium-authority-service"),
                Path::new(
                    "/usr/lib/Actium Node Manager/authority-package/actium-authority-service",
                ),
            )?;
                let error = Command::new(binary).exec();
                Err(format!("DEPLOYMENT_SERVICE_LAUNCH_FAILED: {error}"))
            }
            ServiceLaunchTarget::Supervisor(environment) => {
                let environment = environment.as_str();
                let root = default_root(environment);
                let legacy_binary = if environment == "lab" {
                PathBuf::from("/usr/lib/actium/node-manager-lab/actium-node-supervisor")
            } else {
                PathBuf::from("/usr/lib/actium/node-manager/actium-node-supervisor")
            };
                let legacy_binary = select_preserved_supervisor_binary(&root, &legacy_binary);
                let legacy_config = default_config(environment);
                let (binary, config) =
                    select_supervisor_runtime(&root, &legacy_binary, &legacy_config)?;
                let error = Command::new(binary).arg("--config").arg(config).exec();
                Err(format!("DEPLOYMENT_SERVICE_LAUNCH_FAILED: {error}"))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceLaunchTarget {
    Authority,
    Supervisor(super::effective_config::DeploymentEnvironment),
}

fn service_launch_target(
    options: &std::collections::BTreeMap<String, String>,
) -> Result<ServiceLaunchTarget, String> {
    let role = options.get("role").map(String::as_str);
    let environment = options.get("environment").map(String::as_str);
    let legacy_channel = options.get("channel").map(String::as_str);

    if let Some(role) = role {
        return if role == "authority" && environment.is_none() && legacy_channel.is_none() {
            Ok(ServiceLaunchTarget::Authority)
        } else {
            Err("DEPLOYMENT_OPTION_INVALID".into())
        };
    }
    if environment.is_some() && legacy_channel.is_some() {
        return Err("DEPLOYMENT_OPTION_INVALID".into());
    }
    if legacy_channel == Some("authority") {
        return Ok(ServiceLaunchTarget::Authority);
    }
    let value = environment
        .or(legacy_channel)
        .ok_or_else(|| "DEPLOYMENT_ENVIRONMENT_INVALID".to_string())?;
    super::effective_config::DeploymentEnvironment::parse(value)
        .map(ServiceLaunchTarget::Supervisor)
        .map_err(|_| "DEPLOYMENT_ENVIRONMENT_INVALID".to_string())
}

fn select_supervisor_runtime(
    root: &Path,
    legacy_binary: &Path,
    legacy_config: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    if let Some(deployment_id) = current_deployment_id(root)? {
        let runtime = deployment_dir(root, &deployment_id)?.join("runtime");
        let binary = runtime.join("actium-node-supervisor");
        let config = runtime.join("supervisor.toml");
        if !binary.is_file() || !config.is_file() {
            return Err("DEPLOYMENT_CURRENT_RUNTIME_UNAVAILABLE".into());
        }
        Ok((binary, config))
    } else if legacy_binary.is_file() && legacy_config.is_file() {
        Ok((legacy_binary.to_path_buf(), legacy_config.to_path_buf()))
    } else {
        Err("DEPLOYMENT_LEGACY_RUNTIME_UNAVAILABLE".into())
    }
}

fn select_preserved_supervisor_binary(root: &Path, fallback: &Path) -> PathBuf {
    let preserved = root.join("legacy/actium-node-supervisor");
    if preserved.is_file() {
        preserved
    } else {
        fallback.to_path_buf()
    }
}

fn select_authority_runtime(
    root: &Path,
    legacy_binary: &Path,
    package_binary: &Path,
) -> Result<PathBuf, String> {
    let pointer = root.join("current");
    match fs::symlink_metadata(&pointer) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let preserved_legacy = root.join("legacy/actium-authority-service");
            if preserved_legacy.is_file() {
                Ok(preserved_legacy)
            } else if legacy_binary.is_file() {
                Ok(legacy_binary.to_path_buf())
            } else if package_binary.is_file() {
                Ok(package_binary.to_path_buf())
            } else {
                Err("DEPLOYMENT_LEGACY_RUNTIME_UNAVAILABLE".into())
            }
        }
        Err(_) => Err("DEPLOYMENT_AUTHORITY_POINTER_INVALID".into()),
        Ok(_) => {
            let target =
                fs::read_link(&pointer).map_err(|_| "DEPLOYMENT_AUTHORITY_POINTER_INVALID")?;
            let directory = resolve_authority_target(root, &target)?;
            let binary = directory.join("actium-authority-service");
            if !binary.is_file() {
                return Err("DEPLOYMENT_CURRENT_RUNTIME_UNAVAILABLE".into());
            }
            Ok(binary)
        }
    }
}

#[cfg(unix)]
struct DeploymentLock {
    _lock: nix::fcntl::Flock<fs::File>,
}

#[cfg(unix)]
impl DeploymentLock {
    fn acquire() -> Result<Self, String> {
        let lock_root = default_root("stable");
        create_private_dir(&lock_root)?;
        let path = lock_root.join("deployment.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .map_err(|_| "DEPLOYMENT_LOCK_UNAVAILABLE".to_string())?;
        set_private_file_permissions(&path)?;
        let lock = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|_| "DEPLOYMENT_LOCK_UNAVAILABLE".to_string())?;
        Ok(Self { _lock: lock })
    }
}

fn with_deployment_id<F>(
    options: &std::collections::BTreeMap<String, String>,
    root: &Path,
    operation: F,
) -> Result<(), String>
where
    F: FnOnce(&Path, &str) -> Result<(), String>,
{
    let id = options
        .get("id")
        .ok_or_else(|| "DEPLOYMENT_ID_REQUIRED".to_string())?;
    operation(root, id)
}

fn parse_options(args: &[String]) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut options = std::collections::BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let key = args[index]
            .strip_prefix("--")
            .ok_or_else(|| "DEPLOYMENT_OPTION_INVALID".to_string())?;
        let value = args
            .get(index + 1)
            .ok_or_else(|| "DEPLOYMENT_OPTION_VALUE_REQUIRED".to_string())?;
        if value.starts_with("--") || options.insert(key.into(), value.clone()).is_some() {
            return Err("DEPLOYMENT_OPTION_INVALID".into());
        }
        index += 2;
    }
    Ok(options)
}

fn default_root(channel: &str) -> PathBuf {
    #[cfg(unix)]
    {
        let suffix = if channel == "lab" {
            "node-manager-lab"
        } else {
            "node-manager"
        };
        PathBuf::from("/var/lib/actium").join(suffix)
    }
    #[cfg(windows)]
    {
        let base = super::program_data_root().join(if channel == "lab" {
            "NodeManagerLab"
        } else {
            "NodeManager"
        });
        base.join("state")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from(".").join(if channel == "lab" {
            "node-manager-lab"
        } else {
            "node-manager"
        })
    }
}

fn print_status(root: &Path, channel: &str) -> Result<(), String> {
    let deployments = root.join("deployments");
    let mut journals = Vec::new();
    if deployments.is_dir() {
        for entry in fs::read_dir(&deployments).map_err(|_| "DEPLOYMENT_STATE_READ_FAILED")? {
            let entry = entry.map_err(|_| "DEPLOYMENT_STATE_READ_FAILED")?;
            if !entry
                .file_type()
                .map_err(|_| "DEPLOYMENT_STATE_READ_FAILED")?
                .is_dir()
            {
                continue;
            }
            let journal_path = entry.path().join("journal.json");
            if journal_path.is_file() {
                let journal = load_journal(&journal_path)?;
                if journal.deployment_environment.as_str() != channel {
                    return Err("DEPLOYMENT_ENVIRONMENT_MISMATCH".into());
                }
                journals.push(journal);
            }
        }
    }
    journals.sort_by(|left, right| left.created_at.cmp(&right.created_at));
    let current = fs::read_link(root.join("current")).ok();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "deploymentEnvironment": channel,
            "current": current.map(|path| path.to_string_lossy().into_owned()),
            "deployments": journals,
        }))
        .map_err(|_| "DEPLOYMENT_STATUS_SERIALIZE_FAILED")?
    );
    Ok(())
}

fn default_config(channel: &str) -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(if channel == "lab" {
            "/etc/actium/node-manager-lab/supervisor.toml"
        } else {
            "/etc/actium/node-manager/supervisor.toml"
        })
    }
    #[cfg(windows)]
    {
        super::program_data_root()
            .join(if channel == "lab" {
                "Actium\\NodeManagerLab"
            } else {
                "Actium\\NodeManager"
            })
            .join("supervisor.toml")
    }
    #[cfg(not(any(unix, windows)))]
    {
        PathBuf::from("supervisor.toml")
    }
}

fn capture_legacy_baseline(
    root: &Path,
    channel: &str,
    config_arg: Option<&Path>,
) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (root, channel, config_arg);
        return Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into());
    }
    #[cfg(unix)]
    {
        let config_path = config_arg
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_config(channel));
        let current = root.join("current");
        if current.exists() || fs::symlink_metadata(&current).is_ok() {
            let id =
                current_deployment_id(root)?.ok_or_else(|| "DEPLOYMENT_CURRENT_POINTER_INVALID")?;
            let target = deployment_dir(root, &id)?;
            println!("legacy baseline already captured: {}", target.display());
            return Ok(());
        }

        let effective = super::effective_config::resolve_effective_supervisor_config(&config_path)?;
        let state = super::resolve_effective_supervisor_state(&effective.config)?;
        let trust_status = state.trust;
        if trust_status.state != "READY" {
            return Err(
                "DEPLOYMENT_ROLLBACK_BASELINE_NOT_READY: trust store is not SERVED_READY".into(),
            );
        }
        let authority = state
            .authority
            .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
        let service = service_name(channel);
        ensure_service_active(service)?;
        verify_config_argument(service, &config_path)?;
        let pid = service_main_pid(service)?;
        let process_exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let build_info = command_json(&process_exe, &["--build-info"])?;
        let config_effective =
            super::effective_config::resolve_effective_supervisor_config(&config_path)?;
        let ping = Command::new(&process_exe)
            .arg("--ping")
            .arg("--config")
            .arg(&config_path)
            .output()
            .map_err(|_| "DEPLOYMENT_ROLLBACK_BASELINE_NOT_READY".to_string())?;
        ensure_success(&ping, "DEPLOYMENT_ROLLBACK_BASELINE_NOT_READY")?;

        capture_authority_legacy_baseline()?;
        let artifact_digest = sha256_file(&process_exe)?;
        let deployment_id = format!(
            "legacy-{}",
            &artifact_digest.trim_start_matches("sha256:")[..16]
        );
        let directory = deployment_dir(root, &deployment_id)?;
        create_private_dir(&directory)?;
        let runtime_dir = directory.join("runtime");
        create_private_dir(&runtime_dir)?;
        let binary_path = runtime_dir.join("actium-node-supervisor");
        fs::copy(&process_exe, &binary_path).map_err(|_| "DEPLOYMENT_BASELINE_CAPTURE_FAILED")?;
        set_executable_permissions(&binary_path)?;
        fs::write(
            runtime_dir.join("supervisor.toml"),
            config_effective.canonical_toml.as_bytes(),
        )
        .map_err(|_| "DEPLOYMENT_BASELINE_CAPTURE_FAILED")?;
        write_json_atomic(&directory.join("supervisor-build-info.json"), &build_info)?;
        let (authority_target, authority_digest) = current_authority_target()?;
        let authority_build_info = running_build_info("actium-authority.service")?;
        write_json_atomic(
            &directory.join("authority-build-info.json"),
            &authority_build_info,
        )?;

        let mut journal = DeploymentJournal::new(
            deployment_id.clone(),
            super::effective_config::DeploymentEnvironment::parse(channel)?,
            artifact_digest.clone(),
            None,
            None,
            config_effective.config_digest.clone(),
            1,
            trust_status.trust_store_id.clone(),
            trust_status.current_epoch,
            authority.authority_generation,
            authority.activation_generation,
        );
        journal.trust_bundle_id = Some(authority.trust_bundle_id.clone());
        journal.served_authority_id = Some(authority.served_authority_id.clone());
        journal.supervisor_binary_digest = Some(sha256_file(&binary_path)?);
        journal.authority_binary_digest = Some(authority_digest.clone());
        journal.previous_authority_target = Some(authority_target.to_string_lossy().into_owned());
        journal.previous_authority_binary_digest = Some(authority_digest.clone());
        journal.previous_authority_build_info = Some(authority_build_info.clone());
        journal.state = DeploymentState::Committed;
        journal.updated_at = timestamp();
        write_json_atomic(&directory.join("journal.json"), &journal)?;
        let receipt = ActivationReceipt {
            schema_version: 2,
            deployment_id: deployment_id.clone(),
            deployment_environment: super::effective_config::DeploymentEnvironment::parse(channel)?,
            release_channel: None,
            artifact_digest,
            supervisor_binary_digest: Some(sha256_file(&binary_path)?),
            authority_binary_digest: Some(authority_digest),
            authority_build_info: Some(authority_build_info),
            config_digest: config_effective.config_digest,
            trust_store_id: trust_status.trust_store_id,
            trust_bundle_id: trust_status.trust_bundle_id,
            trust_epoch: trust_status.current_epoch,
            served_authority_id: Some(authority.served_authority_id),
            authority_generation: authority.authority_generation,
            activation_generation: authority.activation_generation,
            build_id: build_info
                .get("build_id")
                .or_else(|| build_info.get("buildId"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .into(),
            source_commit: build_info
                .get("source_commit")
                .or_else(|| build_info.get("sourceCommit"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .into(),
            activated_at: timestamp(),
            result: "LEGACY_BASELINE_CAPTURED".into(),
        };
        write_json_atomic(&directory.join("activation-receipt.json"), &receipt)?;
        switch_current(root, &deployment_id)?;
        println!("legacy baseline captured: {deployment_id}");
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(super) struct AuthorityStatus {
    pub(super) authority_generation: u64,
    pub(super) activation_generation: u64,
    pub(super) trust_epoch: u64,
    pub(super) trust_bundle_id: String,
    pub(super) served_authority_id: String,
}

pub(super) fn authority_status(channel: &str) -> Result<AuthorityStatus, String> {
    let (status, value) = super::authority_http_json_request(
        "POST",
        "/v1/trust-bundle/status",
        Some(&authority_status_request(channel)),
    )?;
    if status != 200
        || value.get("status").and_then(serde_json::Value::as_str) != Some("SERVED_READY")
    {
        let code = value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("AUTHORITY_BINDING_MISMATCH");
        return Err(code.into());
    }
    let receipt = value
        .get("activationReceipt")
        .filter(|value| !value.is_null())
        .ok_or_else(|| "AUTHORITY_GENERATION_MISMATCH".to_string())?;
    let authority_generation = receipt
        .get("authorityGeneration")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| "AUTHORITY_GENERATION_MISMATCH".to_string())?;
    let activation_generation = receipt
        .get("activationGeneration")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| "AUTHORITY_GENERATION_MISMATCH".to_string())?;
    Ok(AuthorityStatus {
        authority_generation,
        activation_generation,
        trust_epoch: value
            .get("trustEpoch")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        trust_bundle_id: value
            .get("trustBundleId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?
            .into(),
        served_authority_id: value
            .get("servedAuthorityId")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?
            .into(),
    })
}

fn authority_status_request(channel: &str) -> serde_json::Value {
    serde_json::json!({
        "contract": super::AUTHORITY_SERVICE_CONTRACT,
        "operation": "trust_bundle_status",
        "requestId": uuid::Uuid::new_v4().to_string(),
        "caller": super::AUTHORITY_SERVICE_CLIENT_ID,
        "channel": channel,
    })
}

fn service_name(channel: &str) -> &'static str {
    if channel == "lab" {
        "actium-node-supervisor-lab.service"
    } else {
        "actium-node-supervisor.service"
    }
}

fn systemctl(args: &[&str]) -> Result<Output, String> {
    Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|_| "DEPLOYMENT_SYSTEMD_UNAVAILABLE".into())
}

fn ensure_service_active(service: &str) -> Result<(), String> {
    let output = systemctl(&["is-active", "--quiet", service])?;
    ensure_success(&output, "DEPLOYMENT_SERVICE_NOT_ACTIVE")
}

fn service_main_pid(service: &str) -> Result<String, String> {
    let output = systemctl(&["show", "--property=MainPID", "--value", service])?;
    ensure_success(&output, "DEPLOYMENT_SERVICE_PID_UNAVAILABLE")?;
    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if pid.is_empty() || pid == "0" || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("DEPLOYMENT_SERVICE_PID_UNAVAILABLE".into());
    }
    Ok(pid)
}

fn command_json(binary: &Path, args: &[&str]) -> Result<serde_json::Value, String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|_| "ARTIFACT_INCOMPATIBLE".to_string())?;
    ensure_success(&output, "ARTIFACT_INCOMPATIBLE")?;
    serde_json::from_slice(&output.stdout).map_err(|_| "ARTIFACT_INCOMPATIBLE".into())
}

fn ensure_success(output: &Output, code: &str) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    Err(code.into())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|_| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", encode_hex(&digest.finalize())))
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

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|_| "DEPLOYMENT_STAGE_FAILED".to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "DEPLOYMENT_STAGE_FAILED".to_string())?;
    }
    Ok(())
}

fn create_authority_runtime_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|_| "DEPLOYMENT_AUTHORITY_STAGE_FAILED".to_string())?;
    #[cfg(unix)]
    {
        use nix::unistd::{chown, Gid, Group, Uid};
        use std::os::unix::fs::PermissionsExt;
        let group = Group::from_name("actium-authority")
            .map_err(|_| "DEPLOYMENT_AUTHORITY_GROUP_UNAVAILABLE")?
            .ok_or_else(|| "DEPLOYMENT_AUTHORITY_GROUP_UNAVAILABLE")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o750))
            .map_err(|_| "DEPLOYMENT_AUTHORITY_STAGE_FAILED")?;
        chown(
            path,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(group.gid.as_raw())),
        )
        .map_err(|_| "DEPLOYMENT_AUTHORITY_STAGE_FAILED")?;
    }
    Ok(())
}

fn set_authority_executable_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use nix::unistd::{chown, Gid, Group, Uid};
        use std::os::unix::fs::PermissionsExt;
        let group = Group::from_name("actium-authority")
            .map_err(|_| "DEPLOYMENT_AUTHORITY_GROUP_UNAVAILABLE")?
            .ok_or_else(|| "DEPLOYMENT_AUTHORITY_GROUP_UNAVAILABLE")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o750))
            .map_err(|_| "DEPLOYMENT_AUTHORITY_STAGE_FAILED")?;
        chown(
            path,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(group.gid.as_raw())),
        )
        .map_err(|_| "DEPLOYMENT_AUTHORITY_STAGE_FAILED")?;
    }
    let _ = path;
    Ok(())
}

fn set_executable_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|_| "DEPLOYMENT_STAGE_FAILED".to_string())?;
    }
    let _ = path;
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "DEPLOYMENT_STATE_PERMISSION_INVALID".to_string())?;
    }
    let _ = path;
    Ok(())
}

fn switch_current(root: &Path, deployment_id: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        let target = PathBuf::from("deployments").join(deployment_id);
        if !deployment_dir(root, deployment_id)?.is_dir() {
            return Err("DEPLOYMENT_POINTER_TARGET_INVALID".into());
        }
        atomic_symlink_switch(root, &target)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, deployment_id);
        Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into())
    }
}

#[cfg(unix)]
fn atomic_symlink_switch(root: &Path, target: &Path) -> Result<(), String> {
    use std::os::unix::fs::symlink;
    let current = root.join("current");
    let temporary = root.join(format!(".current-{}", uuid::Uuid::new_v4()));
    symlink(target, &temporary).map_err(|_| "DEPLOYMENT_POINTER_SWITCH_FAILED".to_string())?;
    if let Err(error) = fs::rename(&temporary, &current) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("DEPLOYMENT_POINTER_SWITCH_FAILED: {error}"));
    }
    if let Ok(directory) = fs::File::open(root) {
        directory
            .sync_all()
            .map_err(|_| "DEPLOYMENT_POINTER_SYNC_FAILED".to_string())?;
    }
    Ok(())
}

fn authority_runtime_root() -> PathBuf {
    PathBuf::from("/var/lib/actium/authority-runtime")
}

fn current_authority_target() -> Result<(PathBuf, String), String> {
    let root = authority_runtime_root();
    let pointer = root.join("current");
    let target = fs::read_link(&pointer).map_err(|_| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED")?;
    let resolved = resolve_authority_target(&root, &target)?;
    let binary = resolved.join("actium-authority-service");
    if !binary.is_file() {
        return Err("DEPLOYMENT_AUTHORITY_POINTER_INVALID".into());
    }
    Ok((target, sha256_file(&binary)?))
}

fn record_previous_authority_state(
    journal: &mut DeploymentJournal,
    target: &Path,
    binary_digest: &str,
) {
    journal.previous_authority_target = Some(target.to_string_lossy().into_owned());
    journal.previous_authority_binary_digest = Some(binary_digest.to_string());
}

fn validate_previous_authority_state(
    journal: &DeploymentJournal,
    target: &Path,
    binary_digest: &str,
) -> Result<(), String> {
    if journal.previous_authority_target.as_deref() != Some(target.to_string_lossy().as_ref())
        || journal.previous_authority_binary_digest.as_deref() != Some(binary_digest)
    {
        return Err("DEPLOYMENT_ACTIVATION_FAILED: Authority changed after stage".into());
    }
    Ok(())
}

fn validate_previous_authority_build_info(
    journal: &DeploymentJournal,
    observed: &serde_json::Value,
) -> Result<(), String> {
    if journal.previous_authority_build_info.as_ref() != Some(observed) {
        return Err("DEPLOYMENT_ACTIVATION_FAILED: Authority build changed after stage".into());
    }
    Ok(())
}

fn capture_authority_legacy_baseline() -> Result<(), String> {
    #[cfg(not(unix))]
    {
        return Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into());
    }
    #[cfg(unix)]
    {
        let root = authority_runtime_root();
        create_authority_runtime_dir(&root)?;
        create_authority_runtime_dir(&root.join("deployments"))?;
        let current = root.join("current");
        if fs::symlink_metadata(&current).is_ok() {
            current_authority_target()?;
            return Ok(());
        }
        ensure_service_active("actium-authority.service")?;
        let pid = service_main_pid("actium-authority.service")?;
        let process_exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let info = command_json(&process_exe, &["--build-info"])?;
        let digest = sha256_file(&process_exe)?;
        let id = format!("legacy-{}", &digest.trim_start_matches("sha256:")[..16]);
        let directory = root.join("deployments").join(&id);
        create_authority_runtime_dir(&directory)?;
        let binary = directory.join("actium-authority-service");
        fs::copy(&process_exe, &binary).map_err(|_| "DEPLOYMENT_BASELINE_CAPTURE_FAILED")?;
        set_authority_executable_permissions(&binary)?;
        write_json_atomic(&directory.join("build-info.json"), &info)?;
        atomic_symlink_switch(&root, &PathBuf::from("deployments").join(&id))
    }
}

fn stage_candidate(
    options: &std::collections::BTreeMap<String, String>,
    root: &Path,
    channel: &str,
) -> Result<String, String> {
    #[cfg(not(unix))]
    {
        let _ = (options, root, channel);
        return Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into());
    }
    #[cfg(unix)]
    {
        let artifact = options
            .get("artifact")
            .map(PathBuf::from)
            .ok_or_else(|| "DEPLOYMENT_ARTIFACT_REQUIRED".to_string())?;
        let expected_digest = options
            .get("expected-digest")
            .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
        let actual_digest = sha256_file(&artifact)?;
        if normalize_digest(expected_digest)? != actual_digest {
            return Err("ARTIFACT_DIGEST_MISMATCH".into());
        }
        let config_path = options
            .get("config")
            .map(PathBuf::from)
            .unwrap_or_else(|| default_config(channel));
        let host = resolve_preflight_host(channel, &config_path)?;
        let (previous_authority_target, previous_authority_binary_digest) =
            current_authority_target()?;
        let previous_authority_build_info = running_build_info("actium-authority.service")?;
        let previous_authority_target_path =
            resolve_authority_target(&authority_runtime_root(), &previous_authority_target)?;
        let stored_authority_build_info: serde_json::Value = serde_json::from_slice(
            &fs::read(previous_authority_target_path.join("build-info.json"))
                .map_err(|_| "DEPLOYMENT_BUILD_INFO_UNAVAILABLE")?,
        )
        .map_err(|_| "DEPLOYMENT_BUILD_INFO_INVALID")?;
        if stored_authority_build_info != previous_authority_build_info {
            return Err("DEPLOYMENT_AUTHORITY_BASELINE_MISMATCH".into());
        }

        let previous_id = current_deployment_id(root)?;
        let previous_journal = if let Some(previous_id) = previous_id.as_deref() {
            let previous_dir = deployment_dir(root, previous_id)?;
            let previous_journal = load_journal(&previous_dir.join("journal.json"))?;
            if previous_journal.deployment_environment.as_str() != channel
                || !matches!(previous_journal.state, DeploymentState::Committed)
            {
                return Err("DEPLOYMENT_ROLLBACK_BASELINE_INVALID".into());
            }
            verify_previous_runtime(
                root,
                &previous_dir,
                &previous_journal,
                &previous_authority_binary_digest,
                &previous_authority_build_info,
            )?;
            Some(previous_journal)
        } else {
            if ensure_service_active(service_name(channel)).is_ok() {
                return Err("DEPLOYMENT_ROLLBACK_BASELINE_REQUIRED".into());
            }
            None
        };

        if channel == "stable" {
            verify_lab_promotion(&actual_digest)?;
        }

        create_private_dir(&root.join("deployments"))?;
        let deployment_id = uuid::Uuid::new_v4().to_string();
        let directory = deployment_dir(root, &deployment_id)?;
        create_private_dir(&directory)?;
        let mut journal = DeploymentJournal::new(
            deployment_id.clone(),
            super::effective_config::DeploymentEnvironment::parse(channel)?,
            actual_digest.clone(),
            previous_journal
                .as_ref()
                .map(|previous| previous.artifact_digest.clone()),
            previous_id,
            host.effective.config_digest.clone(),
            previous_journal
                .as_ref()
                .map_or(1, |previous| previous.config_generation.saturating_add(1)),
            host.trust.trust_store_id.clone(),
            host.trust.current_epoch,
            host.authority.authority_generation,
            host.authority.activation_generation,
        );
        journal.trust_bundle_id = Some(host.authority.trust_bundle_id.clone());
        journal.served_authority_id = Some(host.authority.served_authority_id.clone());
        record_previous_authority_state(
            &mut journal,
            &previous_authority_target,
            &previous_authority_binary_digest,
        );
        journal.previous_authority_build_info = Some(previous_authority_build_info);
        journal.transition(DeploymentState::Staging)?;
        let journal_path = directory.join("journal.json");
        write_json_atomic(&journal_path, &journal)?;

        let operation = (|| -> Result<(), String> {
            let candidate =
                inspect_candidate_package(&artifact, expected_digest, channel, &host, &directory)?;
            journal.release_channel = Some(candidate.release_channel);
            write_json_atomic(&journal_path, &journal)?;
            journal.supervisor_binary_digest = Some(candidate.supervisor_binary_digest.clone());
            journal.authority_binary_digest = Some(candidate.authority_binary_digest.clone());
            let authority_deployment = authority_runtime_root()
                .join("deployments")
                .join(&deployment_id);
            create_authority_runtime_dir(&authority_deployment)?;
            let authority_candidate = authority_deployment.join("actium-authority-service");
            fs::copy(
                directory.join("runtime/actium-authority-service"),
                &authority_candidate,
            )
            .map_err(|_| "DEPLOYMENT_AUTHORITY_STAGE_FAILED")?;
            set_authority_executable_permissions(&authority_candidate)?;
            fs::copy(
                directory.join("authority-build-info.json"),
                authority_deployment.join("build-info.json"),
            )
            .map_err(|_| "DEPLOYMENT_AUTHORITY_STAGE_FAILED")?;

            journal.transition(DeploymentState::Staged)?;
            write_json_atomic(&journal_path, &journal)?;
            run_staged_config_check(&directory)?;
            journal.transition(DeploymentState::PreflightPassed)?;
            write_json_atomic(&journal_path, &journal)?;
            let preflight_result = serde_json::json!({
                "result": "PASS",
                "deploymentEnvironment": channel,
                "releaseChannel": candidate.release_channel,
                "artifactDigest": candidate.artifact_digest,
                "package": candidate.package_name,
                "packageVersion": candidate.package_version,
                "configDigest": host.effective.config_digest,
                "configSchemaVersion": host.effective.schema_version,
                "configMigrations": host.effective.migrations,
                "trustStore": host.trust,
                "authority": {
                    "authorityGeneration": host.authority.authority_generation,
                    "activationGeneration": host.authority.activation_generation,
                    "trustEpoch": host.authority.trust_epoch,
                    "trustBundleId": host.authority.trust_bundle_id,
                    "servedAuthorityId": host.authority.served_authority_id,
                },
                "supervisorBuildInfo": candidate.supervisor_info,
                "authorityBuildInfo": candidate.authority_info,
                "compatibilityManifestDigest": candidate.compatibility_manifest_digest,
            });
            write_json_atomic(&directory.join("preflight-result.json"), &preflight_result)?;
            journal.transition(DeploymentState::ReadyToActivate)?;
            write_json_atomic(&journal_path, &journal)?;
            Ok(())
        })();

        if let Err(error) = operation {
            let code = stable_error_code(&error);
            let _ = journal.fail(code);
            let _ = write_json_atomic(&journal_path, &journal);
            return Err(error);
        }
        Ok(deployment_id)
    }
}

fn deploy_candidate(
    options: &std::collections::BTreeMap<String, String>,
    root: &Path,
    channel: &str,
) -> Result<(), String> {
    preflight_candidate(options, channel)?;
    // Preflight remains read-only. Only after it has validated the exact
    // effective configuration do we snapshot the already-serving Authority
    // and, when present, a legacy channel Supervisor for rollback.
    capture_authority_legacy_baseline()?;
    if current_deployment_id(root)?.is_none() {
        let config = options
            .get("config")
            .map(PathBuf::from)
            .unwrap_or_else(|| default_config(channel));
        if ensure_service_active(service_name(channel)).is_ok() {
            capture_legacy_baseline(root, channel, Some(&config))?;
        }
    }

    let deployment_id = stage_candidate(options, root, channel)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "deploymentId": deployment_id,
            "deploymentEnvironment": channel,
            "state": "READY_TO_ACTIVATE",
        }))
        .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
    );
    activate_deployment(root, &deployment_id)?;
    verify_deployment(root, &deployment_id)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "deploymentId": deployment_id,
            "deploymentEnvironment": channel,
            "artifactDigest": normalize_digest(
                options
                    .get("expected-digest")
                    .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH")?
            )?,
            "state": "COMMITTED",
        }))
        .map_err(|_| "DEPLOYMENT_RECEIPT_SERIALIZE_FAILED")?
    );
    Ok(())
}

fn activate_deployment(root: &Path, deployment_id: &str) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (root, deployment_id);
        return Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into());
    }
    #[cfg(unix)]
    {
        let directory = deployment_dir(root, deployment_id)?;
        let journal_path = directory.join("journal.json");
        let mut journal = load_journal(&journal_path)?;
        if journal.state != DeploymentState::ReadyToActivate {
            return Err("DEPLOYMENT_ACTIVATION_FAILED: deployment is not READY_TO_ACTIVATE".into());
        }
        if current_deployment_id(root)?.as_deref() != journal.previous_deployment_id.as_deref() {
            return Err(
                "DEPLOYMENT_ACTIVATION_FAILED: current deployment changed after stage".into(),
            );
        }
        let (previous_authority_target, previous_authority_digest) = current_authority_target()?;
        validate_previous_authority_state(
            &journal,
            &previous_authority_target,
            &previous_authority_digest,
        )?;
        validate_previous_authority_build_info(
            &journal,
            &running_build_info("actium-authority.service")?,
        )?;
        validate_staged_activation_candidate(&directory, &journal)?;

        journal.transition(DeploymentState::Activating)?;
        write_json_atomic(&journal_path, &journal)?;
        let result = (|| -> Result<ActivationReceipt, String> {
            let candidate_authority = authority_runtime_root()
                .join("deployments")
                .join(deployment_id);
            let candidate_authority_binary = candidate_authority.join("actium-authority-service");
            let candidate_authority_digest = sha256_file(&candidate_authority_binary)?;
            if Some(candidate_authority_digest.as_str())
                != journal.authority_binary_digest.as_deref()
            {
                return Err("ARTIFACT_DIGEST_MISMATCH".into());
            }
            if candidate_authority_digest != previous_authority_digest {
                let root_authority = authority_runtime_root();
                let target = candidate_authority
                    .canonicalize()
                    .map_err(|_| "DEPLOYMENT_AUTHORITY_POINTER_INVALID")?;
                atomic_symlink_switch(&root_authority, &target)?;
                restart_and_wait("actium-authority.service")?;
                let current_authority = authority_status(journal.deployment_environment.as_str())?;
                if current_authority.authority_generation != journal.authority_generation
                    || current_authority.activation_generation != journal.activation_generation
                    || current_authority.trust_epoch != journal.trust_epoch
                    || current_authority.trust_bundle_id
                        != journal.trust_bundle_id.as_deref().unwrap_or_default()
                    || current_authority.served_authority_id
                        != journal.served_authority_id.as_deref().unwrap_or_default()
                {
                    return Err("AUTHORITY_GENERATION_MISMATCH".into());
                }
            } else {
                let (active_target, active_digest) = current_authority_target()?;
                let active_directory =
                    resolve_authority_target(&authority_runtime_root(), &active_target)?;
                if active_digest != candidate_authority_digest
                    || !running_binary_matches(
                        "actium-authority.service",
                        &active_directory.join("actium-authority-service"),
                        &active_digest,
                    )
                {
                    restart_and_wait("actium-authority.service")?;
                }
            }

            let config = directory.join("runtime/supervisor.toml");
            let effective = super::effective_config::resolve_effective_supervisor_config(&config)?;
            let trust_store = open_trust_store(&effective.config)?;
            let trust_before = trust_store.status();
            if trust_before.schema_version < TRUST_STORE_SCHEMA_VERSION as u8 {
                let snapshot = directory.join("trust-store-before.json");
                fs::copy(&effective.config.trust_store_path, &snapshot)
                    .map_err(|_| "DEPLOYMENT_ACTIVATION_FAILED: trust store backup failed")?;
                set_private_file_permissions(&snapshot)?;
                // Persist the recovery intent before the first durable mutation.
                journal.trust_store_migrated = true;
                write_json_atomic(&journal_path, &journal)?;
                let mut trust_store = trust_store;
                let migrated = trust_store.migrate_environment_metadata()?;
                journal.trust_store_id = migrated.trust_store_id;
                write_json_atomic(&journal_path, &journal)?;
            } else if trust_before.trust_store_id.is_none() {
                return Err("TRUST_STORE_METADATA_REQUIRED".into());
            }

            switch_current(root, deployment_id)?;
            let reload = systemctl(&["daemon-reload"])?;
            ensure_success(&reload, "DEPLOYMENT_ACTIVATION_FAILED")?;
            restart_and_wait(service_name(journal.deployment_environment.as_str()))?;
            journal.transition(DeploymentState::Verifying)?;
            write_json_atomic(&journal_path, &journal)?;
            verify_active_deployment(root, &directory, &mut journal)
        })();

        let result = match result {
            Ok(receipt) => {
                commit_verified_activation(&directory, &mut journal, &receipt).map(|()| receipt)
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(receipt) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&receipt)
                        .map_err(|_| "DEPLOYMENT_RECEIPT_SERIALIZE_FAILED")?
                );
                Ok(())
            }
            Err(error) => {
                journal.failure_code = Some(stable_error_code(&error).into());
                let _ = write_json_atomic(&journal_path, &journal);
                let rollback = perform_rollback(root, &directory, &mut journal);
                match rollback {
                    Ok(()) => Err(format!("{error}; rollback verified")),
                    Err(rollback_error) => {
                        if journal.state != DeploymentState::Blocked {
                            let _ = journal.transition(DeploymentState::Blocked);
                        }
                        journal.failure_code = Some("DEPLOYMENT_ROLLBACK_FAILED".into());
                        let _ = write_json_atomic(&journal_path, &journal);
                        Err(format!("DEPLOYMENT_BLOCKED: {error}; {rollback_error}"))
                    }
                }
            }
        }
    }
}

fn validate_staged_activation_candidate(
    directory: &Path,
    journal: &DeploymentJournal,
) -> Result<(), String> {
    let artifact = directory.join("artifact.deb");
    let supervisor = directory.join("runtime/actium-node-supervisor");
    let authority = directory.join("runtime/actium-authority-service");
    let config = directory.join("runtime/supervisor.toml");
    let manifest_path = directory.join("compatibility-manifest.json");
    let expected_supervisor_digest = journal
        .supervisor_binary_digest
        .as_deref()
        .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
    let expected_authority_digest = journal
        .authority_binary_digest
        .as_deref()
        .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
    let preflight: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("preflight-result.json"))
            .map_err(|_| "DEPLOYMENT_PREFLIGHT_FAILED: staged preflight receipt unavailable")?,
    )
    .map_err(|_| "DEPLOYMENT_PREFLIGHT_FAILED: staged preflight receipt invalid")?;
    let effective = super::effective_config::resolve_effective_supervisor_config(&config)?;
    let manifest_digest = sha256_file(&manifest_path)?;
    if sha256_file(&artifact)? != journal.artifact_digest
        || sha256_file(&supervisor)? != expected_supervisor_digest
        || sha256_file(&authority)? != expected_authority_digest
        || effective.config_digest != journal.config_digest
        || preflight.get("result").and_then(serde_json::Value::as_str) != Some("PASS")
        || preflight
            .get("deploymentEnvironment")
            .and_then(serde_json::Value::as_str)
            != Some(journal.deployment_environment.as_str())
        || preflight
            .get("releaseChannel")
            .and_then(|value| serde_json::from_value::<ReleaseChannel>(value.clone()).ok())
            != journal.release_channel
        || preflight
            .get("artifactDigest")
            .and_then(serde_json::Value::as_str)
            != Some(journal.artifact_digest.as_str())
        || preflight
            .get("configDigest")
            .and_then(serde_json::Value::as_str)
            != Some(journal.config_digest.as_str())
        || preflight
            .get("compatibilityManifestDigest")
            .and_then(serde_json::Value::as_str)
            != Some(manifest_digest.as_str())
    {
        return Err("DEPLOYMENT_ACTIVATION_FAILED: staged inputs changed after preflight".into());
    }

    let state = super::resolve_effective_supervisor_state(&effective.config)?;
    let trust = &state.trust;
    let authority_state = state
        .authority
        .as_ref()
        .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
    if trust.state != "READY"
        || trust.environment != journal.deployment_environment.as_str()
        || trust.trust_store_id != journal.trust_store_id
        || trust.trust_bundle_id != journal.trust_bundle_id
        || trust.current_epoch != journal.trust_epoch
        || authority_state.authority_generation != journal.authority_generation
        || authority_state.activation_generation != journal.activation_generation
        || Some(authority_state.trust_bundle_id.as_str())
            != journal.trust_bundle_id.as_deref()
        || Some(authority_state.served_authority_id.as_str())
            != journal.served_authority_id.as_deref()
    {
        return Err("DEPLOYMENT_ACTIVATION_FAILED: effective host state changed after preflight".into());
    }

    let manifest: CompatibilityManifest = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|_| "ARTIFACT_INCOMPATIBLE")?,
    )
    .map_err(|_| "ARTIFACT_INCOMPATIBLE")?;
    let package_version = deb_field(&artifact, "Version")?;
    validate_compatibility_manifest(
        &manifest,
        journal.deployment_environment.as_str(),
        &package_version,
        &effective,
        trust,
        &supervisor,
        &authority,
    )?;
    run_candidate(&supervisor, &["--self-test"])?;
    Ok(())
}

fn commit_verified_activation(
    directory: &Path,
    journal: &mut DeploymentJournal,
    receipt: &ActivationReceipt,
) -> Result<(), String> {
    if journal.state != DeploymentState::Verifying
        || receipt.deployment_id != journal.deployment_id
        || receipt.deployment_environment.as_str() != journal.deployment_environment.as_str()
        || receipt.release_channel != journal.release_channel
        || receipt.artifact_digest != journal.artifact_digest
        || receipt.supervisor_binary_digest != journal.supervisor_binary_digest
        || receipt.authority_binary_digest != journal.authority_binary_digest
        || receipt.config_digest != journal.config_digest
        || receipt.trust_store_id != journal.trust_store_id
        || receipt.trust_bundle_id != journal.trust_bundle_id
        || receipt.trust_epoch != journal.trust_epoch
        || receipt.served_authority_id != journal.served_authority_id
        || receipt.authority_generation != journal.authority_generation
        || receipt.activation_generation != journal.activation_generation
        || receipt.result != "SERVED_READY"
    {
        return Err(
            "DEPLOYMENT_VERIFICATION_FAILED: receipt does not match verified journal".into(),
        );
    }
    write_json_atomic(&directory.join("activation-receipt.json"), receipt)?;
    journal.transition(DeploymentState::Committed)?;
    journal.failure_code = None;
    write_json_atomic(&directory.join("journal.json"), journal)
}

fn rollback_deployment(root: &Path, deployment_id: &str) -> Result<(), String> {
    let directory = deployment_dir(root, deployment_id)?;
    let mut journal = load_journal(&directory.join("journal.json"))?;
    if !matches!(
        journal.state,
        DeploymentState::ReadyToActivate
            | DeploymentState::Activating
            | DeploymentState::Verifying
            | DeploymentState::Committed
            | DeploymentState::RollingBack
            | DeploymentState::Blocked
    ) {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: deployment has no rollback-capable state".into());
    }
    if !matches!(
        journal.state,
        DeploymentState::ReadyToActivate | DeploymentState::RollingBack
    ) && current_deployment_id(root)?.as_deref() != Some(deployment_id)
    {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: deployment is not the active pointer".into());
    }
    perform_rollback_or_block(root, &directory, &mut journal)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&journal)
            .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
    );
    Ok(())
}

fn perform_rollback(
    root: &Path,
    directory: &Path,
    journal: &mut DeploymentJournal,
) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (root, directory, journal);
        return Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into());
    }
    #[cfg(unix)]
    {
        if journal.previous_deployment_id.is_none() {
            return perform_initial_install_rollback(root, directory, journal);
        }
        let journal_path = directory.join("journal.json");
        let previous_id = journal
            .previous_deployment_id
            .clone()
            .ok_or_else(|| "DEPLOYMENT_ROLLBACK_BASELINE_REQUIRED".to_string())?;
        let previous = deployment_dir(root, &previous_id)?;
        let previous_journal = load_journal(&previous.join("journal.json"))?;
        if previous_journal.deployment_environment.as_str() != journal.deployment_environment.as_str()
            || previous_journal.state != DeploymentState::Committed
        {
            return Err("DEPLOYMENT_ROLLBACK_BASELINE_INVALID".into());
        }
        let current_id = current_deployment_id(root)?;
        if current_id.as_deref() != Some(journal.deployment_id.as_str())
            && current_id.as_deref() != Some(previous_id.as_str())
        {
            return Err("DEPLOYMENT_ROLLBACK_POINTER_AMBIGUOUS".into());
        }

        let authority_root = authority_runtime_root();
        let (authority_target, _) = current_authority_target()?;
        let previous_authority_target = journal
            .previous_authority_target
            .clone()
            .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED".to_string())?;
        let previous_authority_digest = journal
            .previous_authority_binary_digest
            .clone()
            .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED".to_string())?;
        let candidate_authority = authority_root
            .join("deployments")
            .join(&journal.deployment_id);
        let current_authority_dir = resolve_authority_target(&authority_root, &authority_target)?;
        let previous_authority_dir =
            resolve_authority_target(&authority_root, Path::new(&previous_authority_target))?;
        let candidate_authority_dir = candidate_authority
            .canonicalize()
            .map_err(|_| "DEPLOYMENT_AUTHORITY_POINTER_INVALID")?;
        if current_authority_dir != previous_authority_dir
            && current_authority_dir != candidate_authority_dir
        {
            return Err("DEPLOYMENT_ROLLBACK_AUTHORITY_POINTER_AMBIGUOUS".into());
        }

        if journal.state != DeploymentState::RollingBack {
            journal.transition(DeploymentState::RollingBack)?;
            write_json_atomic(&journal_path, journal)?;
        }

        // Do not restart an untouched host when cancelling a merely staged deployment.
        let untouched = current_id.as_deref() == Some(previous_id.as_str())
            && current_authority_dir == previous_authority_dir
            && !journal.trust_store_migrated
            && running_binary_matches(
                service_name(journal.deployment_environment.as_str()),
                &previous.join("runtime/actium-node-supervisor"),
                previous_journal
                    .supervisor_binary_digest
                    .as_deref()
                    .ok_or_else(|| "DEPLOYMENT_ROLLBACK_BASELINE_INVALID")?,
            )
            && running_binary_matches(
                "actium-authority.service",
                &previous_authority_dir.join("actium-authority-service"),
                &previous_authority_digest,
            );
        if !untouched {
            let stop = systemctl(&["stop", service_name(journal.deployment_environment.as_str())])?;
            ensure_success(&stop, "DEPLOYMENT_ROLLBACK_FAILED")?;
            if journal.trust_store_migrated {
                restore_trust_store_snapshot(directory, &previous.join("runtime/supervisor.toml"))?;
                journal.trust_store_migrated = false;
                write_json_atomic(&journal_path, journal)?;
            }
            if current_authority_dir != previous_authority_dir {
                let target = PathBuf::from(&previous_authority_target);
                atomic_symlink_switch(&authority_root, &target)?;
                restart_and_wait("actium-authority.service")?;
            } else if !running_binary_matches(
                "actium-authority.service",
                &previous_authority_dir.join("actium-authority-service"),
                &previous_authority_digest,
            ) {
                restart_and_wait("actium-authority.service")?;
            }
            switch_current(root, &previous_id)?;
            let reload = systemctl(&["daemon-reload"])?;
            ensure_success(&reload, "DEPLOYMENT_ROLLBACK_FAILED")?;
            if !running_binary_matches(
                service_name(journal.deployment_environment.as_str()),
                &previous.join("runtime/actium-node-supervisor"),
                previous_journal
                    .supervisor_binary_digest
                    .as_deref()
                    .ok_or_else(|| "DEPLOYMENT_ROLLBACK_BASELINE_INVALID")?,
            ) {
                restart_and_wait(service_name(journal.deployment_environment.as_str()))?;
            }
        }

        // Recheck all previous-state evidence after any pointer changes/restarts.
        let (served_authority_target, served_authority_digest) = current_authority_target()?;
        let served_authority_dir =
            resolve_authority_target(&authority_root, &served_authority_target)?;
        if served_authority_dir != previous_authority_dir
            || served_authority_digest != previous_authority_digest
        {
            return Err(
                "DEPLOYMENT_ROLLBACK_FAILED: Authority pointer/digest was not restored".into(),
            );
        }
        let (supervisor_build_info, authority_build_info) = verify_previous_runtime(
            root,
            &previous,
            &previous_journal,
            &previous_authority_digest,
            journal
                .previous_authority_build_info
                .as_ref()
                .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED")?,
        )?;
        let effective = super::effective_config::resolve_effective_supervisor_config(
            &previous.join("runtime/supervisor.toml"),
        )?;
        let state = super::resolve_effective_supervisor_state(&effective.config)?;
        let trust = state.trust;
        let authority = state
            .authority
            .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
        let receipt = RollbackReceipt {
            schema_version: 2,
            deployment_id: journal.deployment_id.clone(),
            deployment_environment: journal.deployment_environment,
            release_channel: journal.release_channel,
            failed_artifact_digest: journal.artifact_digest.clone(),
            restored_deployment_id: Some(previous_id),
            restored_artifact_digest: Some(previous_journal.artifact_digest),
            restored_supervisor_digest: Some(
                previous_journal
                    .supervisor_binary_digest
                    .ok_or_else(|| "DEPLOYMENT_ROLLBACK_BASELINE_INVALID")?,
            ),
            restored_authority_binary_digest: Some(previous_authority_digest),
            restored_config_digest: Some(effective.config_digest),
            restored_supervisor_build_info: Some(supervisor_build_info),
            restored_authority_build_info: Some(authority_build_info),
            trust_store_id: trust.trust_store_id,
            trust_bundle_id: trust.trust_bundle_id,
            trust_epoch: trust.current_epoch,
            served_authority_id: authority.served_authority_id,
            authority_generation: authority.authority_generation,
            activation_generation: authority.activation_generation,
            verified_at: timestamp(),
            result: "ROLLED_BACK_SERVED_READY".into(),
        };
        write_json_atomic(&directory.join("rollback-receipt.json"), &receipt)?;
        if journal.state != DeploymentState::RolledBack {
            journal.transition(DeploymentState::RolledBack)?;
        }
        write_json_atomic(&journal_path, journal)?;
        Ok(())
    }
}

#[cfg(unix)]
fn perform_initial_install_rollback(
    root: &Path,
    directory: &Path,
    journal: &mut DeploymentJournal,
) -> Result<(), String> {
    let journal_path = directory.join("journal.json");
    let service = service_name(journal.deployment_environment.as_str());
    let current_id = current_deployment_id(root)?;
    if !rollback_pointer_is_known(
        current_id.as_deref(),
        &journal.deployment_id,
        journal.previous_deployment_id.as_deref(),
    ) {
        return Err("DEPLOYMENT_ROLLBACK_POINTER_AMBIGUOUS".into());
    }

    let authority_root = authority_runtime_root();
    let (active_authority_target, _) = current_authority_target()?;
    let expected_authority_target = journal
        .previous_authority_target
        .clone()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED".to_string())?;
    let expected_authority_digest = journal
        .previous_authority_binary_digest
        .clone()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED".to_string())?;
    let expected_authority_build_info = journal
        .previous_authority_build_info
        .clone()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED".to_string())?;
    let previous_authority_dir =
        resolve_authority_target(&authority_root, Path::new(&expected_authority_target))?;
    let candidate_authority_dir = authority_root
        .join("deployments")
        .join(&journal.deployment_id)
        .canonicalize()
        .map_err(|_| "DEPLOYMENT_AUTHORITY_POINTER_INVALID")?;
    let current_authority_dir =
        resolve_authority_target(&authority_root, &active_authority_target)?;
    if current_authority_dir != previous_authority_dir
        && current_authority_dir != candidate_authority_dir
    {
        return Err("DEPLOYMENT_ROLLBACK_AUTHORITY_POINTER_AMBIGUOUS".into());
    }

    if journal.state != DeploymentState::RollingBack {
        journal.transition(DeploymentState::RollingBack)?;
        write_json_atomic(&journal_path, journal)?;
    }

    let stop = systemctl(&["stop", service])?;
    ensure_success(&stop, "DEPLOYMENT_ROLLBACK_FAILED")?;
    if journal.trust_store_migrated {
        restore_trust_store_snapshot(directory, &directory.join("runtime/supervisor.toml"))?;
        journal.trust_store_migrated = false;
        write_json_atomic(&journal_path, journal)?;
    }

    if current_authority_dir != previous_authority_dir {
        atomic_symlink_switch(&authority_root, Path::new(&expected_authority_target))?;
        restart_and_wait("actium-authority.service")?;
    } else if !running_binary_matches(
        "actium-authority.service",
        &previous_authority_dir.join("actium-authority-service"),
        &expected_authority_digest,
    ) {
        restart_and_wait("actium-authority.service")?;
    }

    if current_id.as_deref() == Some(journal.deployment_id.as_str()) {
        fs::remove_file(root.join("current"))
            .map_err(|_| "DEPLOYMENT_ROLLBACK_POINTER_SWITCH_FAILED")?;
        if let Ok(directory) = fs::File::open(root) {
            directory
                .sync_all()
                .map_err(|_| "DEPLOYMENT_POINTER_SYNC_FAILED")?;
        }
    }

    if systemctl(&["is-enabled", "--quiet", service]).is_ok_and(|output| output.status.success()) {
        let disable = systemctl(&["disable", service])?;
        ensure_success(&disable, "DEPLOYMENT_ROLLBACK_FAILED")?;
    }
    let reload = systemctl(&["daemon-reload"])?;
    ensure_success(&reload, "DEPLOYMENT_ROLLBACK_FAILED")?;
    ensure_service_stopped(service)?;

    let (served_authority_target, served_authority_digest) = current_authority_target()?;
    let served_authority_dir = resolve_authority_target(&authority_root, &served_authority_target)?;
    if served_authority_dir != previous_authority_dir
        || served_authority_digest != expected_authority_digest
    {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: Authority baseline was not restored".into());
    }
    verify_running_binary(
        "actium-authority.service",
        &previous_authority_dir.join("actium-authority-service"),
        &expected_authority_digest,
    )?;
    let authority_build_info = running_build_info("actium-authority.service")?;
    if authority_build_info != expected_authority_build_info {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: Authority build-info mismatch".into());
    }

    let effective = super::effective_config::resolve_effective_supervisor_config(
        &directory.join("runtime/supervisor.toml"),
    )?;
    let state = super::resolve_effective_supervisor_state(&effective.config)?;
    let trust = state.trust;
    let authority = state
        .authority
        .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
    if trust.state != "READY"
        || trust.environment != journal.deployment_environment.as_str()
        || trust.trust_store_id != journal.trust_store_id
        || trust.current_epoch != journal.trust_epoch
        || trust.trust_bundle_id != journal.trust_bundle_id
        || authority.authority_generation != journal.authority_generation
        || authority.activation_generation != journal.activation_generation
        || Some(authority.trust_bundle_id.as_str()) != journal.trust_bundle_id.as_deref()
        || Some(authority.served_authority_id.as_str()) != journal.served_authority_id.as_deref()
    {
        return Err(
            "DEPLOYMENT_ROLLBACK_FAILED: initial host trust/Authority state drifted".into(),
        );
    }

    let receipt = RollbackReceipt {
        schema_version: 2,
        deployment_id: journal.deployment_id.clone(),
        deployment_environment: journal.deployment_environment,
        release_channel: journal.release_channel,
        failed_artifact_digest: journal.artifact_digest.clone(),
        restored_deployment_id: None,
        restored_artifact_digest: None,
        restored_supervisor_digest: None,
        restored_authority_binary_digest: Some(expected_authority_digest),
        restored_config_digest: Some(effective.config_digest),
        restored_supervisor_build_info: None,
        restored_authority_build_info: Some(authority_build_info),
        trust_store_id: trust.trust_store_id,
        trust_bundle_id: trust.trust_bundle_id,
        trust_epoch: trust.current_epoch,
        served_authority_id: authority.served_authority_id,
        authority_generation: authority.authority_generation,
        activation_generation: authority.activation_generation,
        verified_at: timestamp(),
        result: "ROLLED_BACK_NO_ACTIVE_SUPERVISOR".into(),
    };
    write_json_atomic(&directory.join("rollback-receipt.json"), &receipt)?;
    journal.transition(DeploymentState::RolledBack)?;
    write_json_atomic(&journal_path, journal)?;
    Ok(())
}

#[cfg(not(unix))]
fn perform_initial_install_rollback(
    _root: &Path,
    _directory: &Path,
    _journal: &mut DeploymentJournal,
) -> Result<(), String> {
    Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into())
}

fn ensure_service_stopped(service: &str) -> Result<(), String> {
    let output = systemctl(&["is-active", service])?;
    let state = String::from_utf8_lossy(&output.stdout);
    if output.status.success() || !matches!(state.trim(), "inactive" | "failed") {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: channel service is not stopped".into());
    }
    let pid = systemctl(&["show", "--property=MainPID", "--value", service])?;
    ensure_success(&pid, "DEPLOYMENT_ROLLBACK_FAILED")?;
    if String::from_utf8_lossy(&pid.stdout).trim() != "0" {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: channel service still has a MainPID".into());
    }
    Ok(())
}

fn perform_rollback_or_block(
    root: &Path,
    directory: &Path,
    journal: &mut DeploymentJournal,
) -> Result<(), String> {
    match perform_rollback(root, directory, journal) {
        Ok(()) => Ok(()),
        Err(error) => {
            if journal.state != DeploymentState::Blocked {
                let _ = journal.transition(DeploymentState::Blocked);
            }
            journal.failure_code = Some("DEPLOYMENT_ROLLBACK_FAILED".into());
            let _ = write_json_atomic(&directory.join("journal.json"), journal);
            Err(format!("DEPLOYMENT_BLOCKED: {error}"))
        }
    }
}

fn reconcile_deployment(root: &Path, deployment_id: &str) -> Result<(), String> {
    let directory = deployment_dir(root, deployment_id)?;
    let journal_path = directory.join("journal.json");
    let mut journal = load_journal(&journal_path)?;
    match journal.state {
        DeploymentState::Committed => {
            if verify_deployment(root, deployment_id).is_ok() {
                return Ok(());
            }
            journal.failure_code = Some("DEPLOYMENT_VERIFICATION_FAILED".into());
            write_json_atomic(&journal_path, &journal)?;
            return perform_rollback_or_block(root, &directory, &mut journal);
        }
        DeploymentState::RolledBack => {
            verify_rollback_receipt(root, &directory, &journal)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&journal)
                    .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
            );
            return Ok(());
        }
        DeploymentState::Activating
        | DeploymentState::Verifying
        | DeploymentState::RollingBack
        | DeploymentState::Blocked => {}
        DeploymentState::ReadyToActivate => {
            println!(
                "{}",
                serde_json::to_string_pretty(&journal)
                    .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
            );
            return Ok(());
        }
        _ => return Err("DEPLOYMENT_RECONCILIATION_NOT_REQUIRED".into()),
    }

    let current_id = current_deployment_id(root);
    let action = match current_id.as_ref() {
        Ok(current_id) => choose_reconcile_action(
            journal.state,
            current_id.as_deref(),
            deployment_id,
            journal.previous_deployment_id.as_deref(),
        ),
        Err(_) => ReconcileAction::Block,
    };
    if action == ReconcileAction::Block {
        journal.failure_code = Some("DEPLOYMENT_RECONCILIATION_AMBIGUOUS".into());
        if journal.state != DeploymentState::Blocked {
            journal.transition(DeploymentState::Blocked)?;
        }
        write_json_atomic(&journal_path, &journal)?;
        return Err(
            "DEPLOYMENT_BLOCKED: current pointer does not match transaction journal".into(),
        );
    }

    if action == ReconcileAction::VerifyCandidate {
        if journal.state == DeploymentState::Activating {
            journal.transition(DeploymentState::Verifying)?;
            write_json_atomic(&journal_path, &journal)?;
        }
        match verify_active_deployment(root, &directory, &mut journal) {
            Ok(receipt) => {
                write_json_atomic(&directory.join("activation-receipt.json"), &receipt)?;
                journal.transition(DeploymentState::Committed)?;
                journal.failure_code = None;
                write_json_atomic(&journal_path, &journal)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&receipt)
                        .map_err(|_| "DEPLOYMENT_RECEIPT_SERIALIZE_FAILED")?
                );
                return Ok(());
            }
            Err(error) => {
                journal.failure_code = Some(stable_error_code(&error).into());
                write_json_atomic(&journal_path, &journal)?;
            }
        }
    }
    perform_rollback_or_block(root, &directory, &mut journal)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&journal)
            .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileAction {
    VerifyCandidate,
    Rollback,
    Block,
}

fn choose_reconcile_action(
    state: DeploymentState,
    current_id: Option<&str>,
    candidate_id: &str,
    previous_id: Option<&str>,
) -> ReconcileAction {
    if !rollback_pointer_is_known(current_id, candidate_id, previous_id) {
        return ReconcileAction::Block;
    }
    if matches!(
        state,
        DeploymentState::RollingBack | DeploymentState::Blocked
    ) {
        return ReconcileAction::Rollback;
    }
    if current_id == Some(candidate_id)
        && matches!(
            state,
            DeploymentState::Activating | DeploymentState::Verifying
        )
    {
        ReconcileAction::VerifyCandidate
    } else {
        ReconcileAction::Rollback
    }
}

fn reconcile_pending_transactions() -> Result<(), String> {
    let mut pending = Vec::new();
    let mut interrupted_stages = Vec::new();
    for channel in ["lab", "stable"] {
        let root = default_root(channel);
        let deployments = root.join("deployments");
        let entries = match fs::read_dir(&deployments) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err("DEPLOYMENT_JOURNAL_UNAVAILABLE".into()),
        };
        for entry in entries {
            let entry = entry.map_err(|_| "DEPLOYMENT_JOURNAL_UNAVAILABLE")?;
            if !entry
                .file_type()
                .map_err(|_| "DEPLOYMENT_JOURNAL_UNAVAILABLE")?
                .is_dir()
            {
                continue;
            }
            let journal_path = entry.path().join("journal.json");
            if !journal_path.is_file() {
                continue;
            }
            let journal = load_journal(&journal_path)?;
            if journal.deployment_environment.as_str() != channel {
                return Err("DEPLOYMENT_ENVIRONMENT_MISMATCH".into());
            }
            match journal.state {
                DeploymentState::Created
                | DeploymentState::Staging
                | DeploymentState::Staged
                | DeploymentState::PreflightPassed => {
                    interrupted_stages.push((root.clone(), journal.deployment_id));
                }
                DeploymentState::Activating
                | DeploymentState::Verifying
                | DeploymentState::RollingBack
                | DeploymentState::Blocked => {
                    // Queue even an unreadable pointer. `reconcile_deployment`
                    // persists BLOCKED on that ambiguity instead of aborting
                    // the boot scan with an unjournaled error.
                    let not_current = current_deployment_id(&root)
                        .map(|current| current.as_deref() != Some(journal.deployment_id.as_str()))
                        .unwrap_or(true);
                    pending.push((not_current, root.clone(), journal.deployment_id));
                }
                DeploymentState::ReadyToActivate
                | DeploymentState::Committed
                | DeploymentState::RolledBack
                | DeploymentState::Failed => {}
            }
        }
    }

    // Resolve transactions that switched a live pointer before touching any
    // stale, pre-activation staging journals. The global lock prevents a new
    // channel transition while this ordered recovery runs.
    pending.sort_by_key(|(not_current, _, _)| *not_current);
    let mut results = Vec::new();
    let mut failures = Vec::new();
    for (_, root, deployment_id) in pending {
        match reconcile_deployment(&root, &deployment_id) {
            Ok(()) => results.push(serde_json::json!({
                "deploymentId": deployment_id,
                "result": "RECONCILED",
            })),
            Err(error) => failures.push(error),
        }
    }
    for (root, deployment_id) in interrupted_stages {
        let directory = deployment_dir(&root, &deployment_id)?;
        let journal_path = directory.join("journal.json");
        let mut journal = load_journal(&journal_path)?;
        journal.fail("DEPLOYMENT_STAGE_INTERRUPTED")?;
        write_json_atomic(&journal_path, &journal)?;
        results.push(serde_json::json!({
            "deploymentId": deployment_id,
            "result": "FAILED_NO_HOST_MUTATION",
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "result": if failures.is_empty() { "RECONCILED" } else { "BLOCKED" },
            "transactions": results,
            "failures": failures,
        }))
        .map_err(|_| "DEPLOYMENT_JOURNAL_SERIALIZE_FAILED")?
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err("DEPLOYMENT_BLOCKED: one or more interrupted transactions need inspection".into())
    }
}

fn verify_previous_runtime(
    root: &Path,
    directory: &Path,
    journal: &DeploymentJournal,
    authority_digest: &str,
    expected_authority_build_info: &serde_json::Value,
) -> Result<(serde_json::Value, serde_json::Value), String> {
    if current_deployment_id(root)?.as_deref() != Some(journal.deployment_id.as_str()) {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: restored deployment pointer mismatch".into());
    }
    let effective = super::effective_config::resolve_effective_supervisor_config(
        &directory.join("runtime/supervisor.toml"),
    )?;
    if effective.config_digest != journal.config_digest {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: restored config digest mismatch".into());
    }
    let binary = directory.join("runtime/actium-node-supervisor");
    let digest = journal
        .supervisor_binary_digest
        .as_deref()
        .ok_or_else(|| "DEPLOYMENT_ROLLBACK_BASELINE_INVALID")?;
    if sha256_file(&binary)? != digest {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: restored binary digest mismatch".into());
    }
    let legacy_baseline = journal.deployment_id.starts_with("legacy-");
    verify_running_binary_with_legacy_path(
        service_name(journal.deployment_environment.as_str()),
        &binary,
        digest,
        legacy_baseline,
    )?;
    let supervisor_build_info = running_build_info(service_name(journal.deployment_environment.as_str()))?;
    let expected_supervisor_build_info: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("supervisor-build-info.json"))
            .map_err(|_| "DEPLOYMENT_BUILD_INFO_UNAVAILABLE")?,
    )
    .map_err(|_| "DEPLOYMENT_BUILD_INFO_INVALID")?;
    if supervisor_build_info != expected_supervisor_build_info {
        return Err(
            "DEPLOYMENT_ROLLBACK_FAILED: Supervisor build-info differs from baseline".into(),
        );
    }
    let process_config = service_config_argument(service_name(journal.deployment_environment.as_str()))?;
    verify_effective_config_argument(
        &process_config,
        &root.join("current/runtime/supervisor.toml"),
        &effective.config_digest,
        legacy_baseline,
    )?;
    run_candidate(&binary, &["--self-test"])?;
    run_candidate(
        &binary,
        &[
            "--ping",
            "--config",
            root.join("current/runtime/supervisor.toml")
                .to_str()
                .ok_or_else(|| "DEPLOYMENT_ROLLBACK_FAILED")?,
        ],
    )?;
    let state = super::resolve_effective_supervisor_state(&effective.config)?;
    let trust = state.trust;
    if trust.state != "READY"
        || trust.environment != journal.deployment_environment.as_str()
        || trust.trust_store_id != journal.trust_store_id
        || trust.current_epoch != journal.trust_epoch
    {
        return Err(
            "DEPLOYMENT_ROLLBACK_FAILED: previous Trust Store does not match journal".into(),
        );
    }
    let authority = state
        .authority
        .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
    if authority.authority_generation != journal.authority_generation
        || authority.activation_generation != journal.activation_generation
        || authority.trust_epoch != journal.trust_epoch
        || journal.trust_bundle_id.as_deref() != Some(authority.trust_bundle_id.as_str())
        || journal.served_authority_id.as_deref() != Some(authority.served_authority_id.as_str())
    {
        return Err("DEPLOYMENT_ROLLBACK_FAILED: previous Authority generation mismatch".into());
    }
    let (authority_target, _) = current_authority_target()?;
    let authority_root = authority_runtime_root();
    let authority_dir = resolve_authority_target(&authority_root, &authority_target)?;
    verify_running_binary_with_legacy_path(
        "actium-authority.service",
        &authority_dir.join("actium-authority-service"),
        authority_digest,
        legacy_baseline,
    )?;
    let authority_build_info = running_build_info("actium-authority.service")?;
    if &authority_build_info != expected_authority_build_info {
        return Err(
            "DEPLOYMENT_ROLLBACK_FAILED: Authority build-info differs from baseline".into(),
        );
    }
    Ok((supervisor_build_info, authority_build_info))
}

fn restore_trust_store_snapshot(
    failed_deployment: &Path,
    previous_config_path: &Path,
) -> Result<(), String> {
    let previous_config =
        super::effective_config::resolve_effective_supervisor_config(previous_config_path)?;
    let path = previous_config.config.trust_store_path;
    let bytes = fs::read(failed_deployment.join("trust-store-before.json"))
        .map_err(|_| "DEPLOYMENT_ROLLBACK_FAILED: Trust Store snapshot unavailable")?;
    let parent = path.parent().ok_or_else(|| "TRUST_STORE_PATH_INVALID")?;
    let temporary = parent.join(format!(".trust-restore-{}.tmp", uuid::Uuid::new_v4()));
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|_| {
        "DEPLOYMENT_ROLLBACK_FAILED: Trust Store restore could not create temporary file"
    })?;
    file.write_all(&bytes)
        .map_err(|_| "DEPLOYMENT_ROLLBACK_FAILED: Trust Store restore write failed")?;
    file.sync_all()
        .map_err(|_| "DEPLOYMENT_ROLLBACK_FAILED: Trust Store restore sync failed")?;
    drop(file);
    set_private_file_permissions(&temporary)?;
    fs::rename(&temporary, &path)
        .map_err(|_| "DEPLOYMENT_ROLLBACK_FAILED: Trust Store restore rename failed")?;
    if let Ok(directory) = fs::File::open(parent) {
        directory
            .sync_all()
            .map_err(|_| "DEPLOYMENT_ROLLBACK_FAILED: Trust Store restore sync failed")?;
    }
    Ok(())
}

fn running_binary_matches(service: &str, expected: &Path, digest: &str) -> bool {
    verify_running_binary(service, expected, digest).is_ok()
}

fn resolve_authority_target(root: &Path, target: &Path) -> Result<PathBuf, String> {
    let resolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        root.join(target)
    };
    let canonical = resolved
        .canonicalize()
        .map_err(|_| "DEPLOYMENT_AUTHORITY_POINTER_INVALID")?;
    let deployments = root
        .join("deployments")
        .canonicalize()
        .map_err(|_| "DEPLOYMENT_AUTHORITY_POINTER_INVALID")?;
    if !canonical.starts_with(&deployments) {
        return Err("DEPLOYMENT_AUTHORITY_POINTER_INVALID".into());
    }
    Ok(canonical)
}

fn verify_rollback_receipt(
    root: &Path,
    directory: &Path,
    journal: &DeploymentJournal,
) -> Result<(), String> {
    let receipt: RollbackReceipt = serde_json::from_slice(
        &fs::read(directory.join("rollback-receipt.json"))
            .map_err(|_| "DEPLOYMENT_ROLLBACK_RECEIPT_UNAVAILABLE")?,
    )
    .map_err(|_| "DEPLOYMENT_ROLLBACK_RECEIPT_INVALID")?;
    if journal.previous_deployment_id.is_none() {
        return verify_initial_install_rollback_receipt(root, directory, journal, &receipt);
    }
    let previous_id = journal
        .previous_deployment_id
        .as_deref()
        .ok_or_else(|| "DEPLOYMENT_ROLLBACK_BASELINE_REQUIRED")?;
    let previous = deployment_dir(root, previous_id)?;
    let previous_journal = load_journal(&previous.join("journal.json"))?;
    if receipt.deployment_id != journal.deployment_id
        || receipt.deployment_environment.as_str() != journal.deployment_environment.as_str()
        || receipt.release_channel != journal.release_channel
        || receipt.failed_artifact_digest != journal.artifact_digest
        || receipt.restored_deployment_id.as_deref() != Some(previous_id)
        || receipt.restored_artifact_digest.as_deref()
            != Some(previous_journal.artifact_digest.as_str())
        || receipt.restored_supervisor_digest.as_deref()
            != previous_journal.supervisor_binary_digest.as_deref()
        || receipt.restored_authority_binary_digest != journal.previous_authority_binary_digest
        || receipt.restored_config_digest.as_deref()
            != Some(previous_journal.config_digest.as_str())
        || receipt.trust_store_id != previous_journal.trust_store_id
        || receipt.trust_bundle_id != previous_journal.trust_bundle_id
        || receipt.trust_epoch != previous_journal.trust_epoch
        || previous_journal.served_authority_id.as_deref()
            != Some(receipt.served_authority_id.as_str())
        || receipt.authority_generation != previous_journal.authority_generation
        || receipt.activation_generation != previous_journal.activation_generation
        || receipt.result != "ROLLED_BACK_SERVED_READY"
    {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }
    let previous = deployment_dir(root, previous_id)?;
    let authority_digest = journal
        .previous_authority_binary_digest
        .as_deref()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED")?;
    let expected_authority_build_info = journal
        .previous_authority_build_info
        .as_ref()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED")?;
    let (supervisor_build_info, authority_build_info) = verify_previous_runtime(
        root,
        &previous,
        &previous_journal,
        authority_digest,
        expected_authority_build_info,
    )?;
    if receipt.restored_supervisor_build_info.as_ref() != Some(&supervisor_build_info)
        || receipt.restored_authority_build_info.as_ref() != Some(&authority_build_info)
    {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }
    Ok(())
}

fn verify_initial_install_rollback_receipt(
    root: &Path,
    directory: &Path,
    journal: &DeploymentJournal,
    receipt: &RollbackReceipt,
) -> Result<(), String> {
    if receipt.deployment_id != journal.deployment_id
        || receipt.deployment_environment.as_str() != journal.deployment_environment.as_str()
        || receipt.release_channel != journal.release_channel
        || receipt.failed_artifact_digest != journal.artifact_digest
        || receipt.restored_deployment_id.is_some()
        || receipt.restored_artifact_digest.is_some()
        || receipt.restored_supervisor_digest.is_some()
        || receipt.restored_supervisor_build_info.is_some()
        || receipt.restored_authority_binary_digest != journal.previous_authority_binary_digest
        || receipt.result != "ROLLED_BACK_NO_ACTIVE_SUPERVISOR"
        || current_deployment_id(root)?.is_some()
    {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }
    let service = service_name(journal.deployment_environment.as_str());
    ensure_service_stopped(service)?;
    if systemctl(&["is-enabled", "--quiet", service])?
        .status
        .success()
    {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }

    let authority_digest = journal
        .previous_authority_binary_digest
        .as_deref()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED")?;
    let authority_build_info = journal
        .previous_authority_build_info
        .as_ref()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED")?;
    let expected_target = journal
        .previous_authority_target
        .as_deref()
        .ok_or_else(|| "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED")?;
    let (target, digest) = current_authority_target()?;
    let authority_root = authority_runtime_root();
    if target != Path::new(expected_target) || digest != authority_digest {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }
    let authority_dir = resolve_authority_target(&authority_root, &target)?;
    verify_running_binary(
        "actium-authority.service",
        &authority_dir.join("actium-authority-service"),
        authority_digest,
    )?;
    let served_build_info = running_build_info("actium-authority.service")?;
    if &served_build_info != authority_build_info
        || receipt.restored_authority_build_info.as_ref() != Some(&served_build_info)
    {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }

    let effective = super::effective_config::resolve_effective_supervisor_config(
        &directory.join("runtime/supervisor.toml"),
    )?;
    if receipt.restored_config_digest.as_deref() != Some(effective.config_digest.as_str()) {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }
    let state = super::resolve_effective_supervisor_state(&effective.config)?;
    let trust = state.trust;
    let authority = state
        .authority
        .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
    if trust.state != "READY"
        || trust.environment != journal.deployment_environment.as_str()
        || trust.trust_store_id != journal.trust_store_id
        || trust.trust_bundle_id != journal.trust_bundle_id
        || trust.current_epoch != journal.trust_epoch
        || trust.trust_store_id != receipt.trust_store_id
        || trust.trust_bundle_id != receipt.trust_bundle_id
        || trust.current_epoch != receipt.trust_epoch
        || authority.served_authority_id.as_str()
            != journal.served_authority_id.as_deref().unwrap_or_default()
        || authority.served_authority_id != receipt.served_authority_id
        || authority.authority_generation != journal.authority_generation
        || authority.authority_generation != receipt.authority_generation
        || authority.activation_generation != journal.activation_generation
        || authority.activation_generation != receipt.activation_generation
    {
        return Err("DEPLOYMENT_ROLLBACK_RECEIPT_INVALID".into());
    }
    Ok(())
}

fn verify_deployment(root: &Path, deployment_id: &str) -> Result<(), String> {
    let directory = deployment_dir(root, deployment_id)?;
    let journal_path = directory.join("journal.json");
    let mut journal = load_journal(&journal_path)?;
    if !matches!(
        journal.state,
        DeploymentState::Committed | DeploymentState::Verifying
    ) {
        return Err("DEPLOYMENT_VERIFICATION_FAILED: deployment is not active".into());
    }
    let receipt = verify_active_deployment(root, &directory, &mut journal)?;
    if journal.state == DeploymentState::Verifying {
        write_json_atomic(&directory.join("activation-receipt.json"), &receipt)?;
        journal.transition(DeploymentState::Committed)?;
        write_json_atomic(&journal_path, &journal)?;
    } else {
        let recorded: ActivationReceipt = serde_json::from_slice(
            &fs::read(directory.join("activation-receipt.json"))
                .map_err(|_| "DEPLOYMENT_RECEIPT_UNAVAILABLE")?,
        )
        .map_err(|_| "DEPLOYMENT_RECEIPT_INVALID")?;
        if !activation_receipts_match(&recorded, &receipt) || recorded.result != "SERVED_READY" {
            return Err(
                "DEPLOYMENT_VERIFICATION_FAILED: durable receipt differs from runtime".into(),
            );
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&receipt)
            .map_err(|_| "DEPLOYMENT_RECEIPT_SERIALIZE_FAILED")?
    );
    Ok(())
}

fn activation_receipts_match(recorded: &ActivationReceipt, observed: &ActivationReceipt) -> bool {
    recorded.schema_version == observed.schema_version
        && recorded.deployment_id == observed.deployment_id
        && recorded.deployment_environment.as_str() == observed.deployment_environment.as_str()
        && recorded.release_channel == observed.release_channel
        && recorded.artifact_digest == observed.artifact_digest
        && recorded.supervisor_binary_digest == observed.supervisor_binary_digest
        && recorded.authority_binary_digest == observed.authority_binary_digest
        && recorded.authority_build_info == observed.authority_build_info
        && recorded.config_digest == observed.config_digest
        && recorded.trust_store_id == observed.trust_store_id
        && recorded.trust_bundle_id == observed.trust_bundle_id
        && recorded.trust_epoch == observed.trust_epoch
        && recorded.served_authority_id == observed.served_authority_id
        && recorded.authority_generation == observed.authority_generation
        && recorded.activation_generation == observed.activation_generation
        && recorded.build_id == observed.build_id
        && recorded.source_commit == observed.source_commit
        && recorded.result == observed.result
}

fn verify_active_deployment(
    root: &Path,
    directory: &Path,
    journal: &mut DeploymentJournal,
) -> Result<ActivationReceipt, String> {
    if current_deployment_id(root)?.as_deref() != Some(journal.deployment_id.as_str()) {
        return Err("DEPLOYMENT_VERIFICATION_FAILED: current pointer does not name journal".into());
    }
    let runtime = directory.join("runtime");
    let supervisor_binary = runtime.join("actium-node-supervisor");
    let authority_binary = runtime.join("actium-authority-service");
    let artifact = directory.join("artifact.deb");
    if sha256_file(&artifact)? != journal.artifact_digest
        || Some(sha256_file(&supervisor_binary)?.as_str())
            != journal.supervisor_binary_digest.as_deref()
        || Some(sha256_file(&authority_binary)?.as_str())
            != journal.authority_binary_digest.as_deref()
    {
        return Err("ARTIFACT_DIGEST_MISMATCH".into());
    }
    verify_running_binary(
        service_name(journal.deployment_environment.as_str()),
        &supervisor_binary,
        journal
            .supervisor_binary_digest
            .as_deref()
            .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH")?,
    )?;
    let (authority_target, authority_digest) = current_authority_target()?;
    let authority_runtime = if authority_target.is_absolute() {
        authority_target.clone()
    } else {
        authority_runtime_root().join(&authority_target)
    };
    let authority_runtime_binary = authority_runtime.join("actium-authority-service");
    if authority_digest
        != journal
            .authority_binary_digest
            .as_deref()
            .unwrap_or_default()
    {
        return Err(
            "DEPLOYMENT_VERIFICATION_FAILED: served Authority differs from candidate".into(),
        );
    }
    verify_running_binary(
        "actium-authority.service",
        &authority_runtime_binary,
        &authority_digest,
    )?;
    let authority_build_info = running_build_info("actium-authority.service")?;
    let recorded_authority_build_info: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("authority-build-info.json"))
            .map_err(|_| "DEPLOYMENT_BUILD_INFO_UNAVAILABLE")?,
    )
    .map_err(|_| "DEPLOYMENT_BUILD_INFO_INVALID")?;
    if authority_build_info != recorded_authority_build_info {
        return Err(
            "DEPLOYMENT_VERIFICATION_FAILED: Authority build-info differs from staged artifact"
                .into(),
        );
    }
    verify_config_argument(
        service_name(journal.deployment_environment.as_str()),
        &root.join("current/runtime/supervisor.toml"),
    )?;
    let effective = super::effective_config::resolve_effective_supervisor_config(
        &root.join("current/runtime/supervisor.toml"),
    )?;
    if effective.config_digest != journal.config_digest {
        return Err("CONFIG_DIGEST_MISMATCH".into());
    }
    let state = super::resolve_effective_supervisor_state(&effective.config)?;
    let trust = state.trust;
    if trust.environment != journal.deployment_environment.as_str()
        || trust.trust_store_id != journal.trust_store_id
        || trust.current_epoch != journal.trust_epoch
    {
        return Err("TRUST_STORE_EPOCH_MISMATCH".into());
    }
    let authority = state
        .authority
        .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
    if authority.authority_generation != journal.authority_generation
        || authority.activation_generation != journal.activation_generation
        || journal.trust_bundle_id.as_deref() != Some(authority.trust_bundle_id.as_str())
        || journal.served_authority_id.as_deref() != Some(authority.served_authority_id.as_str())
    {
        return Err("AUTHORITY_GENERATION_MISMATCH".into());
    }
    run_candidate(&supervisor_binary, &["--self-test"])?;
    run_candidate(
        &supervisor_binary,
        &[
            "--ping",
            "--config",
            root.join("current/runtime/supervisor.toml")
                .to_str()
                .ok_or_else(|| "DEPLOYMENT_VERIFICATION_FAILED")?,
        ],
    )?;
    journal.trust_store_id = trust.trust_store_id.clone();
    journal.trust_bundle_id = trust.trust_bundle_id.clone();
    journal.authority_generation = authority.authority_generation;
    journal.activation_generation = authority.activation_generation;
    journal.served_authority_id = Some(authority.served_authority_id.clone());
    let info: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.join("supervisor-build-info.json"))
            .map_err(|_| "DEPLOYMENT_BUILD_INFO_UNAVAILABLE")?,
    )
    .map_err(|_| "DEPLOYMENT_BUILD_INFO_INVALID")?;
    if running_build_info(service_name(journal.deployment_environment.as_str()))? != info {
        return Err(
            "DEPLOYMENT_VERIFICATION_FAILED: Supervisor build-info differs from staged artifact"
                .into(),
        );
    }
    Ok(ActivationReceipt {
        schema_version: 2,
        deployment_id: journal.deployment_id.clone(),
        deployment_environment: journal.deployment_environment,
        release_channel: journal.release_channel,
        artifact_digest: journal.artifact_digest.clone(),
        supervisor_binary_digest: journal.supervisor_binary_digest.clone(),
        authority_binary_digest: journal.authority_binary_digest.clone(),
        authority_build_info: Some(authority_build_info),
        config_digest: journal.config_digest.clone(),
        trust_store_id: journal.trust_store_id.clone(),
        trust_bundle_id: journal.trust_bundle_id.clone(),
        trust_epoch: journal.trust_epoch,
        served_authority_id: journal.served_authority_id.clone(),
        authority_generation: journal.authority_generation,
        activation_generation: journal.activation_generation,
        build_id: info
            .get("build_id")
            .or_else(|| info.get("buildId"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .into(),
        source_commit: info
            .get("source_commit")
            .or_else(|| info.get("sourceCommit"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .into(),
        activated_at: timestamp(),
        result: "SERVED_READY".into(),
    })
}

fn verify_running_binary(service: &str, expected: &Path, digest: &str) -> Result<(), String> {
    verify_running_binary_with_legacy_path(service, expected, digest, false)
}

fn verify_running_binary_with_legacy_path(
    service: &str,
    expected: &Path,
    digest: &str,
    allow_legacy_path: bool,
) -> Result<(), String> {
    ensure_service_active(service)?;
    let pid = service_main_pid(service)?;
    let process = PathBuf::from(format!("/proc/{pid}/exe"));
    verify_binary_identity(&process, expected, digest, allow_legacy_path)
}

fn verify_binary_identity(
    observed: &Path,
    expected: &Path,
    digest: &str,
    allow_legacy_path: bool,
) -> Result<(), String> {
    if sha256_file(observed)? != digest {
        return Err("DEPLOYMENT_VERIFICATION_FAILED: served process digest mismatch".into());
    }
    if !allow_legacy_path && !same_canonical_path(observed, expected)? {
        return Err("DEPLOYMENT_VERIFICATION_FAILED: served executable path mismatch".into());
    }
    Ok(())
}

fn verify_config_argument(service: &str, expected: &Path) -> Result<(), String> {
    let configured = service_config_argument(service)?;
    if !same_canonical_path(&configured, expected)? {
        return Err("DEPLOYMENT_VERIFICATION_FAILED: process config path mismatch".into());
    }
    Ok(())
}

fn service_config_argument(service: &str) -> Result<PathBuf, String> {
    let pid = service_main_pid(service)?;
    let bytes = fs::read(format!("/proc/{pid}/cmdline"))
        .map_err(|_| "DEPLOYMENT_VERIFICATION_FAILED: process args unavailable")?;
    let args: Vec<_> = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .collect();
    let config_index = args
        .iter()
        .position(|arg| *arg == b"--config")
        .ok_or_else(|| "DEPLOYMENT_VERIFICATION_FAILED: process config argument missing")?;
    let configured = args
        .get(config_index + 1)
        .ok_or_else(|| "DEPLOYMENT_VERIFICATION_FAILED: process config argument invalid")?;
    Ok(PathBuf::from(
        String::from_utf8_lossy(configured).into_owned(),
    ))
}

fn verify_effective_config_argument(
    configured: &Path,
    expected: &Path,
    expected_digest: &str,
    allow_legacy_path: bool,
) -> Result<(), String> {
    if !allow_legacy_path && !same_canonical_path(configured, expected)? {
        return Err("DEPLOYMENT_VERIFICATION_FAILED: process config path mismatch".into());
    }
    let effective = super::effective_config::resolve_effective_supervisor_config(configured)?;
    if effective.config_digest != expected_digest {
        return Err("CONFIG_DIGEST_MISMATCH: served config differs from baseline".into());
    }
    Ok(())
}

fn same_canonical_path(left: &Path, right: &Path) -> Result<bool, String> {
    let left = fs::canonicalize(left).map_err(|_| "DEPLOYMENT_VERIFICATION_FAILED")?;
    let right = fs::canonicalize(right).map_err(|_| "DEPLOYMENT_VERIFICATION_FAILED")?;
    Ok(left == right)
}

fn open_trust_store(
    config: &super::SupervisorConfig,
) -> Result<super::trust_store::SupervisorTrustStore, String> {
    let mut bootstrap_roots = super::load_trust_bootstrap_roots(&config.trust_bootstrap_path)?;
    if bootstrap_roots.is_empty() && config.trust_store_path.is_file() {
        let ceremony_dir = config.authority_data_root.join("ceremonies");
        if let Some(root) = super::trust_store::owner_ceremony_bootstrap_anchor(
            &config.trust_store_path,
            &ceremony_dir,
        )? {
            bootstrap_roots.push(root);
        } else {
            return Err("TRUST_BOOTSTRAP_ANCHOR_UNAVAILABLE".into());
        }
    }
    super::trust_store::SupervisorTrustStore::open_for_environment_and_bootstrap_roots(
        &config.trust_store_path,
        config.deployment_environment,
        &bootstrap_roots,
    )
}

fn restart_and_wait(service: &str) -> Result<(), String> {
    let enable = systemctl(&["enable", service])?;
    ensure_success(&enable, "DEPLOYMENT_ACTIVATION_FAILED")?;
    let output = systemctl(&["restart", service])?;
    ensure_success(&output, "DEPLOYMENT_ACTIVATION_FAILED")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if ensure_service_active(service).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("DEPLOYMENT_ACTIVATION_FAILED: service did not become active".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn promote_lab_deployment(
    lab_root: &Path,
    deployment_id: &str,
    smoke_report_path: &Path,
    smoke_evidence_path: &Path,
) -> Result<(), String> {
    let directory = deployment_dir(lab_root, deployment_id)?;
    let journal_path = directory.join("journal.json");
    let mut journal = load_journal(&journal_path)?;
    if journal.deployment_environment.as_str() != "lab"
        || journal.state != DeploymentState::Committed
        || current_deployment_id(lab_root)?.as_deref() != Some(deployment_id)
    {
        return Err("ARTIFACT_INCOMPATIBLE: LAB deployment is not committed and served".into());
    }
    let report_bytes = fs::read(smoke_report_path)
        .map_err(|_| "DEPLOYMENT_PROMOTION_SMOKE_REQUIRED".to_string())?;
    let smoke_report: LabSmokeReport = serde_json::from_slice(&report_bytes)
        .map_err(|_| "DEPLOYMENT_PROMOTION_SMOKE_INVALID".to_string())?;
    validate_lab_smoke_report(&smoke_report, &journal)?;
    let observed_evidence_digest = sha256_file(smoke_evidence_path)?;
    if normalize_digest(&smoke_report.evidence_digest)? != observed_evidence_digest {
        return Err("DEPLOYMENT_PROMOTION_SMOKE_INVALID: evidence digest mismatch".into());
    }
    let observed_receipt = verify_active_deployment(lab_root, &directory, &mut journal)?;
    let receipt_path = directory.join("activation-receipt.json");
    let recorded_receipt: ActivationReceipt = serde_json::from_slice(
        &fs::read(&receipt_path).map_err(|_| "DEPLOYMENT_RECEIPT_UNAVAILABLE")?,
    )
    .map_err(|_| "DEPLOYMENT_RECEIPT_INVALID")?;
    if !activation_receipts_match(&recorded_receipt, &observed_receipt) {
        return Err(
            "DEPLOYMENT_VERIFICATION_FAILED: LAB receipt differs from served runtime".into(),
        );
    }
    write_json_atomic(&journal_path, &journal)?;
    write_lab_promotion_receipt(
        lab_root,
        &directory,
        &journal,
        &recorded_receipt,
        &smoke_report,
        smoke_evidence_path,
        &observed_evidence_digest,
    )
}

fn validate_lab_smoke_report(
    report: &LabSmokeReport,
    journal: &DeploymentJournal,
) -> Result<(), String> {
    let required_checks = [
        "manager-ui-functional:PASS",
        "supervisor-channel-functional:PASS",
        "authority-trust-functional:PASS",
    ];
    let checks: BTreeSet<_> = report.checks.iter().map(String::as_str).collect();
    if report.schema_version != 1
        || report.deployment_id != journal.deployment_id
        || report.artifact_digest != journal.artifact_digest
        || report.result != "PASS"
        || report.test_suite.trim().is_empty()
        || report.completed_at.trim().is_empty()
        || normalize_digest(&report.evidence_digest).is_err()
        || checks.len() != report.checks.len()
        || report.checks.len() != required_checks.len()
        || required_checks.iter().any(|check| !checks.contains(check))
    {
        return Err("DEPLOYMENT_PROMOTION_SMOKE_INVALID".into());
    }
    Ok(())
}

fn write_lab_promotion_receipt(
    _lab_root: &Path,
    directory: &Path,
    journal: &DeploymentJournal,
    receipt: &ActivationReceipt,
    smoke_report: &LabSmokeReport,
    smoke_evidence_path: &Path,
    smoke_evidence_digest: &str,
) -> Result<(), String> {
    let lab_receipt_path = directory.join("activation-receipt.json");
    let lab_receipt_digest = sha256_file(&lab_receipt_path)?;
    let build_id = receipt.build_id.clone();
        let mut promotion = LabPromotionReceipt {
        schema_version: 2,
        release_channel: journal.release_channel.ok_or("ARTIFACT_INCOMPATIBLE")?,
        promoted_release_channel: ReleaseChannel::Stable,
        artifact_digest: journal.artifact_digest.clone(),
        lab_deployment_id: journal.deployment_id.clone(),
        lab_receipt_digest,
        build_id,
        source_commit: receipt.source_commit.clone(),
        supervisor_binary_digest: receipt
            .supervisor_binary_digest
            .clone()
            .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH")?,
        authority_binary_digest: receipt
            .authority_binary_digest
            .clone()
            .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH")?,
        authority_build_info: receipt
            .authority_build_info
            .clone()
            .ok_or_else(|| "DEPLOYMENT_BUILD_INFO_UNAVAILABLE")?,
        trust_store_schema: TRUST_STORE_SCHEMA_VERSION,
        trust_store_id: journal
            .trust_store_id
            .clone()
            .ok_or_else(|| "TRUST_STORE_METADATA_REQUIRED")?,
        trust_bundle_id: journal
            .trust_bundle_id
            .clone()
            .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH")?,
        trust_epoch: journal.trust_epoch,
        served_authority_id: journal
            .served_authority_id
            .clone()
            .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH")?,
        authority_generation: journal.authority_generation,
        activation_generation: journal.activation_generation,
        authority_protocol: super::AUTHORITY_SERVICE_CONTRACT.into(),
        authority_lifecycle_protocol: super::SUCCESSOR_ACTIVATION_CONTRACT.into(),
        compatibility_manifest_digest: sha256_file(&directory.join("compatibility-manifest.json"))?,
        smoke_result: smoke_report.result.clone(),
        smoke_report_digest: String::new(),
        smoke_test_suite: smoke_report.test_suite.clone(),
        smoke_evidence_digest: normalize_digest(&smoke_report.evidence_digest)?,
        smoke_checks: [
            "supervisor-self-test:PASS".into(),
            "supervisor-ipc-ping:PASS".into(),
            "authority-served-ready:PASS".into(),
            "trust-store-channel-epoch-bundle-authority-binding:PASS".into(),
            "runtime-process-config-artifact-receipt-match:PASS".into(),
        ]
        .into_iter()
        .chain(smoke_report.checks.iter().cloned())
        .collect(),
        promoted_at: timestamp(),
        result: "PROMOTABLE".into(),
    };
    let promotions = default_root("stable").join("promotions");
    create_private_dir(&promotions)?;
    let digest_hex = journal
        .artifact_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH")?;
    let receipt_path = promotions.join(format!("{digest_hex}.json"));
    let smoke_path = promotions.join(format!("{digest_hex}.smoke-report.json"));
    let evidence_path = promotions.join(format!("{digest_hex}.smoke-evidence"));
    let smoke_bytes = serde_json::to_vec_pretty(smoke_report)
        .map_err(|_| "DEPLOYMENT_RECEIPT_SERIALIZE_FAILED")?;
    let smoke_digest = sha256_bytes(&smoke_bytes);
    if receipt_path.exists() {
        let existing: LabPromotionReceipt =
            serde_json::from_slice(&fs::read(&receipt_path).map_err(|_| "ARTIFACT_INCOMPATIBLE")?)
                .map_err(|_| "ARTIFACT_INCOMPATIBLE")?;
        if existing.smoke_report_digest != smoke_digest
            || existing.smoke_evidence_digest != smoke_evidence_digest
            || existing.artifact_digest != promotion.artifact_digest
        {
            return Err("ARTIFACT_INCOMPATIBLE: immutable LAB promotion already exists".into());
        }
        verify_lab_promotion(&journal.artifact_digest)?;
        println!(
            "{{\"result\":\"PROMOTABLE\",\"artifactDigest\":\"{}\"}}",
            journal.artifact_digest
        );
        return Ok(());
    }
    write_json_atomic(&smoke_path, smoke_report)?;
    promotion.smoke_report_digest = sha256_file(&smoke_path)?;
    promotion.smoke_evidence_digest = atomic_copy_file(smoke_evidence_path, &evidence_path)?;
    if promotion.smoke_evidence_digest != smoke_evidence_digest {
        return Err("DEPLOYMENT_PROMOTION_SMOKE_INVALID: evidence changed while copying".into());
    }
    write_json_atomic(&receipt_path, &promotion)
}

fn atomic_copy_file(source: &Path, destination: &Path) -> Result<String, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "DEPLOYMENT_JOURNAL_PATH_INVALID".to_string())?;
    create_private_dir(parent)?;
    let temporary = parent.join(format!(".smoke-evidence-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let copy_result = (|| -> Result<(), String> {
        let mut target = options
            .open(&temporary)
            .map_err(|_| "DEPLOYMENT_PROMOTION_SMOKE_COPY_FAILED")?;
        let mut source = fs::File::open(source)
            .map_err(|_| "DEPLOYMENT_PROMOTION_SMOKE_REQUIRED".to_string())?;
        std::io::copy(&mut source, &mut target)
            .map_err(|_| "DEPLOYMENT_PROMOTION_SMOKE_COPY_FAILED")?;
        target
            .sync_all()
            .map_err(|_| "DEPLOYMENT_PROMOTION_SMOKE_COPY_FAILED")?;
        Ok(())
    })();
    if let Err(error) = copy_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("DEPLOYMENT_PROMOTION_SMOKE_COPY_FAILED: {error}"));
    }
    if let Ok(directory) = fs::File::open(parent) {
        directory
            .sync_all()
            .map_err(|_| "DEPLOYMENT_PROMOTION_SMOKE_COPY_FAILED")?;
    }
    sha256_file(destination)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn normalize_digest(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ARTIFACT_DIGEST_MISMATCH".into());
    }
    Ok(format!("sha256:{hex}"))
}

fn current_deployment_id(root: &Path) -> Result<Option<String>, String> {
    let pointer = root.join("current");
    let target = match fs::read_link(&pointer) {
        Ok(target) => target,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("DEPLOYMENT_CURRENT_POINTER_INVALID".into()),
    };
    let components: Vec<_> = target.components().collect();
    if components.len() != 2 || components[0].as_os_str() != "deployments" {
        return Err("DEPLOYMENT_CURRENT_POINTER_INVALID".into());
    }
    let id = components[1].as_os_str().to_string_lossy().into_owned();
    let directory = deployment_dir(root, &id)?;
    if !directory.is_dir() {
        return Err("DEPLOYMENT_CURRENT_POINTER_INVALID".into());
    }
    Ok(Some(id))
}

fn rollback_pointer_is_known(
    current_id: Option<&str>,
    candidate_id: &str,
    previous_id: Option<&str>,
) -> bool {
    current_id == Some(candidate_id)
        || match previous_id {
            Some(previous_id) => current_id == Some(previous_id),
            None => current_id.is_none(),
        }
}

fn locate_package_prefix(unpacked: &Path) -> Result<PathBuf, String> {
    for candidate in [
        unpacked.join("usr/lib/Actium Node Manager"),
        unpacked.join("usr/lib/actium-node-manager"),
    ] {
        if candidate
            .join("supervisor/actium-node-supervisor")
            .is_file()
            && candidate
                .join("authority-package/actium-authority-service")
                .is_file()
        {
            return Ok(candidate);
        }
    }
    Err("ARTIFACT_INCOMPATIBLE".into())
}

fn run_candidate(binary: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|_| "DEPLOYMENT_PREFLIGHT_FAILED".to_string())?;
    ensure_success(&output, "DEPLOYMENT_PREFLIGHT_FAILED")
}

struct PreflightHostState {
    effective: super::effective_config::EffectiveSupervisorConfig,
    trust: super::trust_store::TrustStoreStatus,
    authority: AuthorityStatus,
}

struct CandidateInspection {
    release_channel: ReleaseChannel,
    artifact_digest: String,
    package_name: String,
    package_version: String,
    supervisor_info: serde_json::Value,
    authority_info: serde_json::Value,
    supervisor_binary_digest: String,
    authority_binary_digest: String,
    compatibility_manifest_digest: String,
}

struct TemporaryDirectory(PathBuf);

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn resolve_preflight_host(channel: &str, config_path: &Path) -> Result<PreflightHostState, String> {
    let effective = super::effective_config::resolve_effective_supervisor_config(config_path)?;
    if effective.config.deployment_environment.as_str() != channel {
        return Err("TRUST_STORE_ENVIRONMENT_MISMATCH".into());
    }
    let resolved = super::resolve_effective_supervisor_state(&effective.config)?;
    let trust = resolved.trust;
    if trust.state != "READY" {
        return Err("TRUST_STORE_METADATA_REQUIRED".into());
    }
    let authority = resolved
        .authority
        .ok_or_else(|| "AUTHORITY_BINDING_MISMATCH".to_string())?;
    Ok(PreflightHostState {
        effective,
        trust,
        authority,
    })
}

fn inspect_candidate_package(
    artifact: &Path,
    expected_digest: &str,
    channel: &str,
    host: &PreflightHostState,
    workspace: &Path,
) -> Result<CandidateInspection, String> {
    let staged_artifact = workspace.join("artifact.deb");
    fs::copy(artifact, &staged_artifact).map_err(|_| "DEPLOYMENT_STAGE_FAILED")?;
    let artifact_digest = sha256_file(&staged_artifact)?;
    if normalize_digest(expected_digest)? != artifact_digest {
        return Err("ARTIFACT_DIGEST_MISMATCH".into());
    }
    let package_name = deb_field(&staged_artifact, "Package")?;
    let package_version = deb_field(&staged_artifact, "Version")?;
    if package_name != "actium-node-manager" {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    let unpacked = workspace.join("package");
    create_private_dir(&unpacked)?;
    let extracted = Command::new("dpkg-deb")
        .args(["-x"])
        .arg(&staged_artifact)
        .arg(&unpacked)
        .output()
        .map_err(|_| "DEPLOYMENT_STAGE_FAILED".to_string())?;
    ensure_success(&extracted, "DEPLOYMENT_STAGE_FAILED")?;

    let prefix = locate_package_prefix(&unpacked)?;
    let supervisor_dir = prefix.join("supervisor");
    let authority_dir = prefix.join("authority-package");
    let compatibility_path = supervisor_dir.join("compatibility-manifest.json");
    let manifest: CompatibilityManifest = serde_json::from_slice(
        &fs::read(&compatibility_path).map_err(|_| "ARTIFACT_INCOMPATIBLE")?,
    )
    .map_err(|_| "ARTIFACT_INCOMPATIBLE")?;
    let supervisor_binary = supervisor_dir.join("actium-node-supervisor");
    let authority_binary = authority_dir.join("actium-authority-service");
    if !supervisor_binary.is_file() || !authority_binary.is_file() {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    validate_compatibility_manifest(
        &manifest,
        channel,
        &package_version,
        &host.effective,
        &host.trust,
        &supervisor_binary,
        &authority_binary,
    )?;

    let supervisor_info = command_json(&supervisor_binary, &["--build-info"])?;
    let authority_info = command_json(&authority_binary, &["--build-info"])?;
    let supervisor_binary_digest = sha256_file(&supervisor_binary)?;
    let authority_binary_digest = sha256_file(&authority_binary)?;
    for (info, digest) in [
        (&supervisor_info, &supervisor_binary_digest),
        (&authority_info, &authority_binary_digest),
    ] {
        if info
            .get("binary_sha256")
            .or_else(|| info.get("binarySha256"))
            .and_then(serde_json::Value::as_str)
            != Some(digest.as_str())
        {
            return Err("ARTIFACT_DIGEST_MISMATCH".into());
        }
        validate_build_metadata(info)?;
    }
    run_candidate(&supervisor_binary, &["--self-test"])?;

    let runtime_dir = workspace.join("runtime");
    create_private_dir(&runtime_dir)?;
    let staged_supervisor = runtime_dir.join("actium-node-supervisor");
    fs::copy(&supervisor_binary, &staged_supervisor).map_err(|_| "DEPLOYMENT_STAGE_FAILED")?;
    set_executable_permissions(&staged_supervisor)?;
    let staged_authority = runtime_dir.join("actium-authority-service");
    fs::copy(&authority_binary, &staged_authority).map_err(|_| "DEPLOYMENT_STAGE_FAILED")?;
    set_executable_permissions(&staged_authority)?;
    fs::write(
        runtime_dir.join("supervisor.toml"),
        host.effective.canonical_toml.as_bytes(),
    )
    .map_err(|_| "DEPLOYMENT_STAGE_FAILED")?;
    fs::copy(
        &compatibility_path,
        workspace.join("compatibility-manifest.json"),
    )
    .map_err(|_| "DEPLOYMENT_STAGE_FAILED")?;
    write_json_atomic(
        &workspace.join("supervisor-build-info.json"),
        &supervisor_info,
    )?;
    write_json_atomic(
        &workspace.join("authority-build-info.json"),
        &authority_info,
    )?;
    Ok(CandidateInspection {
        artifact_digest,
        package_name,
        package_version,
        supervisor_info,
        authority_info,
        supervisor_binary_digest: sha256_file(&staged_supervisor)?,
        authority_binary_digest: sha256_file(&staged_authority)?,
        compatibility_manifest_digest: sha256_file(&workspace.join("compatibility-manifest.json"))?,
        release_channel: manifest.release_channel,
    })
}

fn run_staged_config_check(workspace: &Path) -> Result<(), String> {
    let runtime = workspace.join("runtime");
    let supervisor = runtime.join("actium-node-supervisor");
    let config = runtime.join("supervisor.toml");
    run_candidate(
        &supervisor,
        &[
            "--check",
            "--config",
            config
                .to_str()
                .ok_or_else(|| "DEPLOYMENT_PREFLIGHT_FAILED")?,
        ],
    )
}

fn preflight_candidate(
    options: &std::collections::BTreeMap<String, String>,
    channel: &str,
) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (options, channel);
        return Err("DEPLOYMENT_PLATFORM_UNSUPPORTED".into());
    }
    #[cfg(unix)]
    {
        let artifact = options
            .get("artifact")
            .map(PathBuf::from)
            .ok_or_else(|| "DEPLOYMENT_ARTIFACT_REQUIRED".to_string())?;
        let expected_digest = options
            .get("expected-digest")
            .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
        let config_path = options
            .get("config")
            .map(PathBuf::from)
            .unwrap_or_else(|| default_config(channel));
        let host = resolve_preflight_host(channel, &config_path)?;
        let workspace = std::env::temp_dir().join(format!(
            "actium-deployment-preflight-{}",
            uuid::Uuid::new_v4()
        ));
        create_private_dir(&workspace)?;
        let _cleanup = TemporaryDirectory(workspace.clone());
        let candidate =
            inspect_candidate_package(&artifact, expected_digest, channel, &host, &workspace)?;
        run_staged_config_check(&workspace)?;
        if channel == "stable" {
            verify_lab_promotion(&candidate.artifact_digest)?;
        }
        let result = serde_json::json!({
            "result": "PASS",
            "deploymentEnvironment": channel,
            "releaseChannel": candidate.release_channel,
            "artifactDigest": candidate.artifact_digest,
            "package": candidate.package_name,
            "packageVersion": candidate.package_version,
            "configDigest": host.effective.config_digest,
            "configSchemaVersion": host.effective.schema_version,
            "configMigrations": host.effective.migrations,
            "trustStore": host.trust,
            "authority": {
                "authorityGeneration": host.authority.authority_generation,
                "activationGeneration": host.authority.activation_generation,
                "trustEpoch": host.authority.trust_epoch,
                "trustBundleId": host.authority.trust_bundle_id,
                "servedAuthorityId": host.authority.served_authority_id,
            },
            "supervisorBuildInfo": candidate.supervisor_info,
            "authorityBuildInfo": candidate.authority_info,
            "compatibilityManifestDigest": candidate.compatibility_manifest_digest,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&result).map_err(|_| "DEPLOYMENT_PREFLIGHT_FAILED")?
        );
        Ok(())
    }
}

fn validate_compatibility_manifest(
    manifest: &CompatibilityManifest,
    channel: &str,
    target_manager_version: &str,
    effective: &super::effective_config::EffectiveSupervisorConfig,
    trust_status: &super::trust_store::TrustStoreStatus,
    supervisor_binary: &Path,
    authority_binary: &Path,
) -> Result<(), String> {
    if manifest.schema_version != 1
        || !manifest
            .release_channel
            .matches_manager_version(target_manager_version)
        || !manifest
            .supervisor_config_schema
            .contains(effective.schema_version)
        || !manifest
            .trust_store_schema
            .contains(TRUST_STORE_SCHEMA_VERSION)
        || !manifest
            .deployment_protocol
            .contains(DEPLOYMENT_PROTOCOL_VERSION)
        || manifest.authority_protocol != super::AUTHORITY_SERVICE_CONTRACT
        || manifest.authority_lifecycle_protocol != super::SUCCESSOR_ACTIVATION_CONTRACT
    {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    let supervisor_info = command_json(supervisor_binary, &["--build-info"])?;
    let authority_info = command_json(authority_binary, &["--build-info"])?;
    let supervisor_version = info_string(&supervisor_info, &["version"])?;
    let authority_version = info_string(&authority_info, &["version"])?;
    if !manifest.supervisor.contains(supervisor_version)
        || !manifest.authority.contains(authority_version)
    {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    let manager = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "actium-node-manager"])
        .output()
        .map_err(|_| "ARTIFACT_INCOMPATIBLE".to_string())?;
    ensure_success(&manager, "ARTIFACT_INCOMPATIBLE")?;
    let manager_version = String::from_utf8_lossy(&manager.stdout).trim().to_string();
    if !manifest.manager.contains(&manager_version)
        || !manifest.manager.contains(target_manager_version)
    {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    let supervisor_service_active = ensure_service_active(service_name(channel)).is_ok();
    let has_channel_deployment = current_deployment_id(&default_root(channel))?.is_some();
    if has_channel_deployment && !supervisor_service_active {
        return Err("DEPLOYMENT_SERVICE_NOT_ACTIVE".into());
    }
    if supervisor_service_active {
        let host_supervisor = running_build_info(service_name(channel))?;
        if !manifest
            .supervisor
            .contains(info_string(&host_supervisor, &["version"])?)
        {
            return Err("ARTIFACT_INCOMPATIBLE".into());
        }
    }
    let host_authority = running_build_info("actium-authority.service")?;
    if !manifest
        .authority
        .contains(info_string(&host_authority, &["version"])?)
    {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    let host_trust_schema = if trust_status.trust_store_id.is_some() {
        trust_status.schema_version as u32
    } else {
        1
    };
    if !manifest.trust_store_schema.contains(host_trust_schema) {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    Ok(())
}

fn deb_field(artifact: &Path, field: &str) -> Result<String, String> {
    let output = Command::new("dpkg-deb")
        .args(["-f"])
        .arg(artifact)
        .arg(field)
        .output()
        .map_err(|_| "ARTIFACT_INCOMPATIBLE".to_string())?;
    ensure_success(&output, "ARTIFACT_INCOMPATIBLE")?;
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        return Err("ARTIFACT_INCOMPATIBLE".into());
    }
    Ok(value)
}

fn info_string<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Result<&'a str, String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .ok_or_else(|| "ARTIFACT_INCOMPATIBLE".into())
}

fn validate_build_metadata(info: &serde_json::Value) -> Result<(), String> {
    for keys in [
        &["build_id", "buildId"][..],
        &["source_commit", "sourceCommit"][..],
    ] {
        let value = info_string(info, keys)?;
        if value.trim().is_empty() || value == "unknown" {
            return Err("ARTIFACT_INCOMPATIBLE: build provenance is incomplete".into());
        }
    }
    Ok(())
}

fn running_build_info(service: &str) -> Result<serde_json::Value, String> {
    ensure_service_active(service)?;
    let pid = service_main_pid(service)?;
    command_json(
        &PathBuf::from(format!("/proc/{pid}/exe")),
        &["--build-info"],
    )
}

pub(super) fn validate_authority_binding(
    trust: &super::trust_store::TrustStoreStatus,
    authority: &AuthorityStatus,
) -> Result<(), String> {
    if trust.state != "READY" {
        return Err("AUTHORITY_BINDING_MISMATCH".into());
    }
    if trust.current_epoch != authority.trust_epoch {
        return Err("TRUST_STORE_EPOCH_MISMATCH".into());
    }
    if trust.trust_bundle_id.as_deref() != Some(authority.trust_bundle_id.as_str())
        || trust.authority_binding.as_deref() != Some(authority.served_authority_id.as_str())
    {
        return Err("AUTHORITY_BINDING_MISMATCH".into());
    }
    Ok(())
}

pub(super) fn format_machine_error(error: &str) -> String {
    serde_json::to_string(&serde_json::json!({
        "ok": false,
        "code": stable_error_code(error),
        "detail": error,
    }))
    .unwrap_or_else(|_| "{\"ok\":false,\"code\":\"DEPLOYMENT_STAGE_FAILED\"}".into())
}

fn stable_error_code(error: &str) -> &'static str {
    let code = error.split(':').next().unwrap_or("");
    if code.is_empty()
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return DeploymentErrorCode::DeploymentStageFailed.as_str();
    }
    match code {
        "TRUST_STORE_PATH_REQUIRED" | "TRUST_STORE_CHANNEL_PATH_REQUIRED" => {
            DeploymentErrorCode::TrustStorePathRequired.as_str()
        }
        "TRUST_STORE_CHANNEL_MISMATCH" | "TRUST_STORE_ENVIRONMENT_MISMATCH" => {
            DeploymentErrorCode::TrustStoreEnvironmentMismatch.as_str()
        }
        "TRUST_STORE_SCHEMA_UNSUPPORTED" => {
            DeploymentErrorCode::TrustStoreSchemaUnsupported.as_str()
        }
        "TRUST_STORE_PERMISSION_INVALID" => {
            DeploymentErrorCode::TrustStorePermissionInvalid.as_str()
        }
        "TRUST_STORE_EPOCH_MISMATCH" => DeploymentErrorCode::TrustStoreEpochMismatch.as_str(),
        "TRUST_STORE_METADATA_REQUIRED" => DeploymentErrorCode::TrustStoreMetadataRequired.as_str(),
        "DEPLOYMENT_ENVIRONMENT_MISMATCH" => {
            DeploymentErrorCode::DeploymentEnvironmentMismatch.as_str()
        }
        "CONFIG_SCHEMA_UNSUPPORTED" => DeploymentErrorCode::ConfigSchemaUnsupported.as_str(),
        "CONFIG_MIGRATION_FAILED" => DeploymentErrorCode::ConfigMigrationFailed.as_str(),
        "CONFIG_EFFECTIVE_STATE_INVALID" => {
            DeploymentErrorCode::ConfigEffectiveStateInvalid.as_str()
        }
        "CONFIG_DIGEST_MISMATCH" => DeploymentErrorCode::ConfigDigestMismatch.as_str(),
        "AUTHORITY_BINDING_MISMATCH" => DeploymentErrorCode::AuthorityBindingMismatch.as_str(),
        "AUTHORITY_GENERATION_MISMATCH" => {
            DeploymentErrorCode::AuthorityGenerationMismatch.as_str()
        }
        "AUTHORITY_TRUST_BUNDLE_UNAVAILABLE" => {
            DeploymentErrorCode::AuthorityTrustBundleUnavailable.as_str()
        }
        "DEPLOYMENT_AUTHORITY_BASELINE_REQUIRED" => {
            DeploymentErrorCode::DeploymentAuthorityBaselineRequired.as_str()
        }
        "ARTIFACT_INCOMPATIBLE" => DeploymentErrorCode::ArtifactIncompatible.as_str(),
        "ARTIFACT_DIGEST_MISMATCH" => DeploymentErrorCode::ArtifactDigestMismatch.as_str(),
        "DEPLOYMENT_PREFLIGHT_FAILED" => DeploymentErrorCode::DeploymentPreflightFailed.as_str(),
        "DEPLOYMENT_STAGE_FAILED" => DeploymentErrorCode::DeploymentStageFailed.as_str(),
        "DEPLOYMENT_ACTIVATION_FAILED" => DeploymentErrorCode::DeploymentActivationFailed.as_str(),
        "DEPLOYMENT_VERIFICATION_FAILED" => {
            DeploymentErrorCode::DeploymentVerificationFailed.as_str()
        }
        "DEPLOYMENT_ROLLBACK_FAILED" => DeploymentErrorCode::DeploymentRollbackFailed.as_str(),
        "DEPLOYMENT_ROLLBACK_POINTER_AMBIGUOUS" => {
            DeploymentErrorCode::DeploymentRollbackPointerAmbiguous.as_str()
        }
        "DEPLOYMENT_RECONCILIATION_AMBIGUOUS" => {
            DeploymentErrorCode::DeploymentReconciliationAmbiguous.as_str()
        }
        "DEPLOYMENT_SERVICE_NOT_ACTIVE" => DeploymentErrorCode::DeploymentServiceNotActive.as_str(),
        "DEPLOYMENT_LEGACY_RUNTIME_UNAVAILABLE" => {
            DeploymentErrorCode::DeploymentLegacyRuntimeUnavailable.as_str()
        }
        "DEPLOYMENT_CURRENT_RUNTIME_UNAVAILABLE" => {
            DeploymentErrorCode::DeploymentCurrentRuntimeUnavailable.as_str()
        }
        "DEPLOYMENT_SERVICE_LAUNCH_FAILED" => {
            DeploymentErrorCode::DeploymentServiceLaunchFailed.as_str()
        }
        "DEPLOYMENT_BLOCKED" => DeploymentErrorCode::DeploymentBlocked.as_str(),
        "DEPLOYMENT_PROMOTION_SMOKE_REQUIRED" => {
            DeploymentErrorCode::DeploymentPromotionSmokeRequired.as_str()
        }
        "DEPLOYMENT_PROMOTION_SMOKE_INVALID" => {
            DeploymentErrorCode::DeploymentPromotionSmokeInvalid.as_str()
        }
        "DEPLOYMENT_PROMOTION_SMOKE_COPY_FAILED" => {
            DeploymentErrorCode::DeploymentPromotionSmokeCopyFailed.as_str()
        }
        _ => DeploymentErrorCode::DeploymentStageFailed.as_str(),
    }
}

fn verify_lab_promotion(artifact_digest: &str) -> Result<(), String> {
    let digest_hex = artifact_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| "ARTIFACT_DIGEST_MISMATCH".to_string())?;
    let receipt_path = default_root("stable")
        .join("promotions")
        .join(format!("{digest_hex}.json"));
    let bytes = fs::read(&receipt_path)
        .map_err(|_| "ARTIFACT_INCOMPATIBLE: LAB promotion receipt required".to_string())?;
    let receipt: LabPromotionReceipt = serde_json::from_slice(&bytes)
        .map_err(|_| "ARTIFACT_INCOMPATIBLE: LAB promotion receipt invalid".to_string())?;
    if receipt.schema_version != 2
        || receipt.artifact_digest != artifact_digest
        || receipt.release_channel == ReleaseChannel::Dev
        || receipt.promoted_release_channel != ReleaseChannel::Stable
        || receipt.result != "PROMOTABLE"
        || receipt.smoke_result != "PASS"
        || !has_required_promotion_smoke_checks(&receipt.smoke_checks)
        || normalize_digest(&receipt.smoke_report_digest).is_err()
        || normalize_digest(&receipt.smoke_evidence_digest).is_err()
        || receipt.smoke_test_suite.trim().is_empty()
        || receipt.trust_store_schema == 0
        || receipt.trust_store_schema > TRUST_STORE_SCHEMA_VERSION
        || receipt.trust_store_id.is_empty()
        || receipt.source_commit.is_empty()
        || receipt.supervisor_binary_digest.is_empty()
        || receipt.authority_binary_digest.is_empty()
        || receipt.trust_bundle_id.is_empty()
        || receipt.served_authority_id.is_empty()
        || receipt.trust_epoch == 0
        || receipt.authority_generation == 0
        || receipt.activation_generation == 0
        || receipt.authority_protocol != super::AUTHORITY_SERVICE_CONTRACT
        || receipt.authority_lifecycle_protocol != super::SUCCESSOR_ACTIVATION_CONTRACT
    {
        return Err("ARTIFACT_INCOMPATIBLE: LAB promotion receipt mismatch".into());
    }
    let lab_directory = deployment_dir(&default_root("lab"), &receipt.lab_deployment_id)?;
    let lab_journal = load_journal(&lab_directory.join("journal.json"))?;
    if lab_journal.deployment_environment.as_str() != "lab"
        || lab_journal.state != DeploymentState::Committed
        || lab_journal.artifact_digest != artifact_digest
        || lab_journal.release_channel != Some(receipt.release_channel)
        || lab_journal.trust_store_id.as_deref() != Some(receipt.trust_store_id.as_str())
        || lab_journal.trust_bundle_id.as_deref() != Some(receipt.trust_bundle_id.as_str())
        || lab_journal.served_authority_id.as_deref() != Some(receipt.served_authority_id.as_str())
        || lab_journal.trust_epoch != receipt.trust_epoch
        || lab_journal.authority_generation != receipt.authority_generation
        || lab_journal.activation_generation != receipt.activation_generation
        || lab_journal.supervisor_binary_digest.as_deref()
            != Some(receipt.supervisor_binary_digest.as_str())
        || lab_journal.authority_binary_digest.as_deref()
            != Some(receipt.authority_binary_digest.as_str())
        || sha256_file(&lab_directory.join("compatibility-manifest.json"))?
            != receipt.compatibility_manifest_digest
    {
        return Err(
            "ARTIFACT_INCOMPATIBLE: LAB promotion does not match committed deployment".into(),
        );
    }
    let smoke_path = default_root("stable")
        .join("promotions")
        .join(format!("{digest_hex}.smoke-report.json"));
    let evidence_path = default_root("stable")
        .join("promotions")
        .join(format!("{digest_hex}.smoke-evidence"));
    if sha256_file(&smoke_path)? != receipt.smoke_report_digest {
        return Err("ARTIFACT_INCOMPATIBLE: LAB smoke report digest mismatch".into());
    }
    if sha256_file(&evidence_path)? != receipt.smoke_evidence_digest {
        return Err("ARTIFACT_INCOMPATIBLE: LAB smoke evidence digest mismatch".into());
    }
    let smoke_report: LabSmokeReport = serde_json::from_slice(
        &fs::read(&smoke_path)
            .map_err(|_| "ARTIFACT_INCOMPATIBLE: LAB smoke report unavailable")?,
    )
    .map_err(|_| "ARTIFACT_INCOMPATIBLE: LAB smoke report invalid")?;
    validate_lab_smoke_report(&smoke_report, &lab_journal)
        .map_err(|_| "ARTIFACT_INCOMPATIBLE: LAB smoke report mismatch")?;
    if smoke_report.test_suite != receipt.smoke_test_suite
        || normalize_digest(&smoke_report.evidence_digest)? != receipt.smoke_evidence_digest
    {
        return Err("ARTIFACT_INCOMPATIBLE: LAB smoke evidence mismatch".into());
    }
    let receipt_path = lab_directory.join("activation-receipt.json");
    if sha256_file(&receipt_path)? != receipt.lab_receipt_digest {
        return Err("ARTIFACT_INCOMPATIBLE: LAB receipt digest mismatch".into());
    }
    let bytes = fs::read(receipt_path)
        .map_err(|_| "ARTIFACT_INCOMPATIBLE: LAB receipt unavailable".to_string())?;
    let served: ActivationReceipt = serde_json::from_slice(&bytes)
        .map_err(|_| "ARTIFACT_INCOMPATIBLE: LAB receipt invalid".to_string())?;
    if served.result != "SERVED_READY"
        || served.deployment_id != receipt.lab_deployment_id
        || served.deployment_environment.as_str() != "lab"
        || served.release_channel != Some(receipt.release_channel)
        || served.artifact_digest != artifact_digest
        || served.build_id != receipt.build_id
        || served.source_commit != receipt.source_commit
        || served.supervisor_binary_digest.as_deref()
            != Some(receipt.supervisor_binary_digest.as_str())
        || served.authority_binary_digest.as_deref()
            != Some(receipt.authority_binary_digest.as_str())
        || served.authority_build_info.as_ref() != Some(&receipt.authority_build_info)
        || served.trust_store_id.as_deref() != Some(receipt.trust_store_id.as_str())
        || served.trust_bundle_id.as_deref() != Some(receipt.trust_bundle_id.as_str())
        || served.served_authority_id.as_deref() != Some(receipt.served_authority_id.as_str())
        || served.trust_epoch != receipt.trust_epoch
        || served.authority_generation != receipt.authority_generation
        || served.activation_generation != receipt.activation_generation
    {
        return Err("ARTIFACT_INCOMPATIBLE: LAB receipt not served".into());
    }
    Ok(())
}

fn has_required_promotion_smoke_checks(checks: &[String]) -> bool {
    let observed: BTreeSet<_> = checks.iter().map(String::as_str).collect();
    observed.len() == REQUIRED_PROMOTION_SMOKE_CHECKS.len()
        && REQUIRED_PROMOTION_SMOKE_CHECKS
            .iter()
            .all(|check| observed.contains(check))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LabPromotionReceipt {
    schema_version: u32,
    release_channel: ReleaseChannel,
    promoted_release_channel: ReleaseChannel,
    artifact_digest: String,
    lab_deployment_id: String,
    lab_receipt_digest: String,
    build_id: String,
    source_commit: String,
    supervisor_binary_digest: String,
    authority_binary_digest: String,
    authority_build_info: serde_json::Value,
    trust_store_schema: u32,
    trust_store_id: String,
    trust_bundle_id: String,
    trust_epoch: u64,
    served_authority_id: String,
    authority_generation: u64,
    activation_generation: u64,
    authority_protocol: String,
    authority_lifecycle_protocol: String,
    compatibility_manifest_digest: String,
    smoke_result: String,
    smoke_report_digest: String,
    smoke_test_suite: String,
    smoke_evidence_digest: String,
    smoke_checks: Vec<String>,
    promoted_at: String,
    result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LabSmokeReport {
    schema_version: u32,
    deployment_id: String,
    artifact_digest: String,
    result: String,
    test_suite: String,
    evidence_digest: String,
    checks: Vec<String>,
    completed_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample() -> DeploymentJournal {
        let mut journal = DeploymentJournal::new(
            Uuid::new_v4().to_string(),
            crate::effective_config::DeploymentEnvironment::Lab,
            "sha256:artifact".into(),
            None,
            None,
            "sha256:config".into(),
            1,
            None,
            0,
            1,
            1,
        );
        journal.release_channel = Some(ReleaseChannel::Rc);
        journal
    }

    #[test]
    fn package_prefix_requires_the_non_active_authority_package_directory() {
        let root = std::env::temp_dir().join(format!("package-prefix-{}", Uuid::new_v4()));
        let prefix = root.join("usr/lib/Actium Node Manager");
        fs::create_dir_all(prefix.join("supervisor")).unwrap();
        fs::write(
            prefix.join("supervisor/actium-node-supervisor"),
            b"supervisor",
        )
        .unwrap();
        fs::create_dir_all(prefix.join("authority")).unwrap();
        fs::write(
            prefix.join("authority/actium-authority-service"),
            b"legacy-path",
        )
        .unwrap();
        assert_eq!(
            locate_package_prefix(&root),
            Err("ARTIFACT_INCOMPATIBLE".into())
        );
        fs::create_dir_all(prefix.join("authority-package")).unwrap();
        fs::write(
            prefix.join("authority-package/actium-authority-service"),
            b"candidate-package",
        )
        .unwrap();
        assert_eq!(locate_package_prefix(&root).unwrap(), prefix);
        fs::remove_dir_all(root).unwrap();
    }

    fn receipt() -> ActivationReceipt {
        ActivationReceipt {
            schema_version: 2,
            deployment_id: Uuid::new_v4().to_string(),
            deployment_environment: crate::effective_config::DeploymentEnvironment::Lab,
            release_channel: Some(ReleaseChannel::Rc),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            supervisor_binary_digest: Some(format!("sha256:{}", "b".repeat(64))),
            authority_binary_digest: Some(format!("sha256:{}", "c".repeat(64))),
            authority_build_info: Some(serde_json::json!({ "buildId": "authority-build" })),
            config_digest: format!("sha256:{}", "d".repeat(64)),
            trust_store_id: Some(Uuid::new_v4().to_string()),
            trust_bundle_id: Some(Uuid::new_v4().to_string()),
            trust_epoch: 7,
            served_authority_id: Some("authority-7".into()),
            authority_generation: 3,
            activation_generation: 8,
            build_id: "manager-build".into(),
            source_commit: "abc123".into(),
            activated_at: timestamp(),
            result: "SERVED_READY".into(),
        }
    }

    fn smoke_report(journal: &DeploymentJournal) -> LabSmokeReport {
        LabSmokeReport {
            schema_version: 1,
            deployment_id: journal.deployment_id.clone(),
            artifact_digest: journal.artifact_digest.clone(),
            result: "PASS".into(),
            test_suite: "lab-functional-smoke-v1".into(),
            evidence_digest: format!("sha256:{}", "e".repeat(64)),
            checks: vec![
                "manager-ui-functional:PASS".into(),
                "supervisor-channel-functional:PASS".into(),
                "authority-trust-functional:PASS".into(),
            ],
            completed_at: timestamp(),
        }
    }

    #[test]
    fn service_launch_selector_separates_authority_role_from_deployment_environment() {
        let role = [("role".to_string(), "authority".to_string())]
            .into_iter()
            .collect();
        assert_eq!(
            service_launch_target(&role).unwrap(),
            ServiceLaunchTarget::Authority
        );

        let lab = [("environment".to_string(), "lab".to_string())]
            .into_iter()
            .collect();
        assert_eq!(
            service_launch_target(&lab).unwrap(),
            ServiceLaunchTarget::Supervisor(
                crate::effective_config::DeploymentEnvironment::Lab
            )
        );

        let legacy_authority = [("channel".to_string(), "authority".to_string())]
            .into_iter()
            .collect();
        assert_eq!(
            service_launch_target(&legacy_authority).unwrap(),
            ServiceLaunchTarget::Authority
        );

        let ambiguous = [
            ("role".to_string(), "authority".to_string()),
            ("environment".to_string(), "lab".to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            service_launch_target(&ambiguous).unwrap_err(),
            "DEPLOYMENT_OPTION_INVALID"
        );
    }

    #[cfg(unix)]
    #[test]
    fn service_launcher_uses_legacy_only_without_a_pointer_and_never_falls_back_from_broken_current(
    ) {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("service-launch-{}", Uuid::new_v4()));
        let legacy_binary = root.join("legacy/supervisor");
        let legacy_config = root.join("legacy/supervisor.toml");
        fs::create_dir_all(legacy_binary.parent().unwrap()).unwrap();
        fs::write(&legacy_binary, b"legacy").unwrap();
        fs::write(&legacy_config, b"product_channel='lab'").unwrap();
        let package_legacy = root.join("package/legacy-supervisor");
        fs::create_dir_all(package_legacy.parent().unwrap()).unwrap();
        fs::write(&package_legacy, b"package-legacy").unwrap();
        let preserved = root.join("legacy/actium-node-supervisor");
        fs::write(&preserved, b"preinst-preserved").unwrap();
        assert_eq!(
            select_preserved_supervisor_binary(&root, &package_legacy),
            preserved
        );
        fs::remove_file(&preserved).unwrap();
        assert_eq!(
            select_preserved_supervisor_binary(&root, &package_legacy),
            package_legacy
        );
        assert_eq!(
            select_supervisor_runtime(&root, &legacy_binary, &legacy_config).unwrap(),
            (legacy_binary.clone(), legacy_config.clone())
        );

        let deployment_id = Uuid::new_v4().to_string();
        let deployment = root.join("deployments").join(&deployment_id);
        fs::create_dir_all(&deployment).unwrap();
        symlink(
            PathBuf::from("deployments").join(&deployment_id),
            root.join("current"),
        )
        .unwrap();
        assert_eq!(
            select_supervisor_runtime(&root, &legacy_binary, &legacy_config).unwrap_err(),
            "DEPLOYMENT_CURRENT_RUNTIME_UNAVAILABLE"
        );
        fs::create_dir_all(deployment.join("runtime")).unwrap();
        let current_binary = deployment.join("runtime/actium-node-supervisor");
        let current_config = deployment.join("runtime/supervisor.toml");
        fs::write(&current_binary, b"candidate").unwrap();
        fs::write(&current_config, b"product_channel='lab'").unwrap();
        assert_eq!(
            select_supervisor_runtime(&root, &legacy_binary, &legacy_config).unwrap(),
            (current_binary, current_config)
        );

        let authority_root = root.join("authority-runtime");
        let authority_deployment = authority_root.join("deployments").join(&deployment_id);
        fs::create_dir_all(&authority_deployment).unwrap();
        let legacy_authority = root.join("legacy/authority");
        fs::write(&legacy_authority, b"legacy-authority").unwrap();
        fs::create_dir_all(authority_root.join("legacy")).unwrap();
        let preserved_authority = authority_root.join("legacy/actium-authority-service");
        fs::write(&preserved_authority, b"preserved-authority").unwrap();
        assert_eq!(
            select_authority_runtime(&authority_root, &legacy_authority, &legacy_authority)
                .unwrap(),
            preserved_authority
        );
        fs::remove_file(&preserved_authority).unwrap();
        assert_eq!(
            select_authority_runtime(&authority_root, &legacy_authority, &legacy_authority)
                .unwrap(),
            legacy_authority
        );
        symlink(
            PathBuf::from("deployments").join(&deployment_id),
            authority_root.join("current"),
        )
        .unwrap();
        let current_authority = authority_deployment.join("actium-authority-service");
        fs::write(&current_authority, b"candidate-authority").unwrap();
        assert_eq!(
            select_authority_runtime(&authority_root, &legacy_authority, &legacy_authority)
                .unwrap(),
            current_authority
        );
        fs::remove_file(authority_root.join("current")).unwrap();
        fs::remove_file(&legacy_authority).unwrap();
        let packaged_authority = root.join("package/authority-package/actium-authority-service");
        fs::create_dir_all(packaged_authority.parent().unwrap()).unwrap();
        fs::write(&packaged_authority, b"package-authority").unwrap();
        assert_eq!(
            select_authority_runtime(&authority_root, &legacy_authority, &packaged_authority)
                .unwrap(),
            packaged_authority
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_state_machine_accepts_only_declared_transitions() {
        let mut journal = sample();
        for state in [
            DeploymentState::Staging,
            DeploymentState::Staged,
            DeploymentState::PreflightPassed,
            DeploymentState::ReadyToActivate,
            DeploymentState::Activating,
            DeploymentState::Verifying,
            DeploymentState::Committed,
        ] {
            journal.transition(state).unwrap();
        }
        assert_eq!(journal.state, DeploymentState::Committed);
        assert_eq!(
            journal.transition(DeploymentState::Staging).unwrap_err(),
            "DEPLOYMENT_STATE_TRANSITION_INVALID"
        );
    }

    #[test]
    fn interrupted_activation_has_explicit_rollback_path() {
        let mut journal = sample();
        for state in [
            DeploymentState::Staging,
            DeploymentState::Staged,
            DeploymentState::PreflightPassed,
            DeploymentState::ReadyToActivate,
            DeploymentState::Activating,
            DeploymentState::Verifying,
            DeploymentState::RollingBack,
            DeploymentState::RolledBack,
        ] {
            journal.transition(state).unwrap();
        }
        assert_eq!(journal.state, DeploymentState::RolledBack);
    }

    #[test]
    fn ready_deployment_can_be_cancelled_transactionally() {
        let mut journal = sample();
        for state in [
            DeploymentState::Staging,
            DeploymentState::Staged,
            DeploymentState::PreflightPassed,
            DeploymentState::ReadyToActivate,
            DeploymentState::RollingBack,
            DeploymentState::RolledBack,
        ] {
            journal.transition(state).unwrap();
        }
        assert_eq!(journal.state, DeploymentState::RolledBack);
    }

    #[test]
    fn first_activation_recovery_accepts_only_absent_or_candidate_pointer() {
        let candidate = Uuid::new_v4().to_string();
        let unrelated = Uuid::new_v4().to_string();
        assert!(rollback_pointer_is_known(None, &candidate, None));
        assert!(rollback_pointer_is_known(
            Some(&candidate),
            &candidate,
            None
        ));
        assert!(!rollback_pointer_is_known(
            Some(&unrelated),
            &candidate,
            None
        ));
        assert!(rollback_pointer_is_known(
            Some("previous"),
            &candidate,
            Some("previous")
        ));
        assert!(!rollback_pointer_is_known(
            None,
            &candidate,
            Some("previous")
        ));
        assert!(!rollback_pointer_is_known(
            Some(&unrelated),
            &candidate,
            Some("previous")
        ));
    }

    #[test]
    fn recovery_commits_only_verified_candidate_and_rolls_back_other_known_pointers() {
        let candidate = "candidate";
        let previous = "previous";
        for state in [DeploymentState::Activating, DeploymentState::Verifying] {
            assert_eq!(
                choose_reconcile_action(state, Some(candidate), candidate, Some(previous)),
                ReconcileAction::VerifyCandidate
            );
            assert_eq!(
                choose_reconcile_action(state, Some(previous), candidate, Some(previous)),
                ReconcileAction::Rollback
            );
        }
        for current in [Some(candidate), Some(previous)] {
            assert_eq!(
                choose_reconcile_action(
                    DeploymentState::RollingBack,
                    current,
                    candidate,
                    Some(previous)
                ),
                ReconcileAction::Rollback
            );
        }
        assert_eq!(
            choose_reconcile_action(
                DeploymentState::Verifying,
                Some("unrelated"),
                candidate,
                Some(previous)
            ),
            ReconcileAction::Block
        );
        assert_eq!(
            choose_reconcile_action(DeploymentState::Blocked, None, candidate, Some(previous)),
            ReconcileAction::Block
        );
    }

    #[cfg(unix)]
    #[test]
    fn reconciliation_persists_blocked_when_current_pointer_is_unreadable() {
        let root =
            std::env::temp_dir().join(format!("reconcile-invalid-pointer-{}", Uuid::new_v4()));
        let mut journal = sample();
        for state in [
            DeploymentState::Staging,
            DeploymentState::Staged,
            DeploymentState::PreflightPassed,
            DeploymentState::ReadyToActivate,
            DeploymentState::Activating,
        ] {
            journal.transition(state).unwrap();
        }
        let directory = deployment_dir(&root, &journal.deployment_id).unwrap();
        fs::create_dir_all(&directory).unwrap();
        write_json_atomic(&directory.join("journal.json"), &journal).unwrap();
        fs::write(root.join("current"), b"not-an-atomic-symlink").unwrap();

        let error = reconcile_deployment(&root, &journal.deployment_id).unwrap_err();
        let persisted = load_journal(&directory.join("journal.json")).unwrap();
        assert!(error.starts_with("DEPLOYMENT_BLOCKED:"));
        assert_eq!(persisted.state, DeploymentState::Blocked);
        assert_eq!(
            persisted.failure_code.as_deref(),
            Some("DEPLOYMENT_RECONCILIATION_AMBIGUOUS")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn served_receipt_comparison_binds_authority_build_info_and_all_digests() {
        let recorded = receipt();
        assert!(activation_receipts_match(&recorded, &recorded));

        let mut changed_authority = recorded.clone();
        changed_authority.authority_build_info =
            Some(serde_json::json!({ "buildId": "different" }));
        assert!(!activation_receipts_match(&recorded, &changed_authority));

        let mut changed_config = recorded.clone();
        changed_config.config_digest = format!("sha256:{}", "e".repeat(64));
        assert!(!activation_receipts_match(&recorded, &changed_config));
    }

    #[test]
    fn activation_is_committed_only_after_a_matching_receipt_is_durable() {
        let root = std::env::temp_dir().join(format!("activation-commit-{}", Uuid::new_v4()));
        let mut journal = sample();
        for state in [
            DeploymentState::Staging,
            DeploymentState::Staged,
            DeploymentState::PreflightPassed,
            DeploymentState::ReadyToActivate,
            DeploymentState::Activating,
            DeploymentState::Verifying,
        ] {
            journal.transition(state).unwrap();
        }
        let directory = deployment_dir(&root, &journal.deployment_id).unwrap();
        fs::create_dir_all(&directory).unwrap();
        write_json_atomic(&directory.join("journal.json"), &journal).unwrap();
        let mut served = receipt();
        served.deployment_id = journal.deployment_id.clone();
        served.deployment_environment = journal.deployment_environment;
        served.artifact_digest = journal.artifact_digest.clone();
        served.supervisor_binary_digest = journal.supervisor_binary_digest.clone();
        served.authority_binary_digest = journal.authority_binary_digest.clone();
        served.config_digest = journal.config_digest.clone();
        served.trust_store_id = journal.trust_store_id.clone();
        served.trust_bundle_id = journal.trust_bundle_id.clone();
        served.trust_epoch = journal.trust_epoch;
        served.served_authority_id = journal.served_authority_id.clone();
        served.authority_generation = journal.authority_generation;
        served.activation_generation = journal.activation_generation;

        fs::create_dir(directory.join("activation-receipt.json")).unwrap();
        assert!(commit_verified_activation(&directory, &mut journal, &served).is_err());
        assert_eq!(journal.state, DeploymentState::Verifying);
        assert_eq!(
            load_journal(&directory.join("journal.json")).unwrap().state,
            DeploymentState::Verifying
        );

        fs::remove_dir(directory.join("activation-receipt.json")).unwrap();
        commit_verified_activation(&directory, &mut journal, &served).unwrap();
        assert_eq!(journal.state, DeploymentState::Committed);
        assert_eq!(
            load_journal(&directory.join("journal.json")).unwrap().state,
            DeploymentState::Committed
        );
        let persisted: ActivationReceipt =
            serde_json::from_slice(&fs::read(directory.join("activation-receipt.json")).unwrap())
                .unwrap();
        assert_eq!(persisted.deployment_id, journal.deployment_id);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_authority_binding_is_durable_and_rejects_host_drift() {
        let mut journal = sample();
        let target = Path::new("deployments/legacy-authority");
        let digest = format!("sha256:{}", "a".repeat(64));
        record_previous_authority_state(&mut journal, target, &digest);
        assert_eq!(
            journal.previous_authority_target.as_deref(),
            Some("deployments/legacy-authority")
        );
        assert_eq!(
            journal.previous_authority_binary_digest.as_deref(),
            Some(digest.as_str())
        );
        assert!(validate_previous_authority_state(&journal, target, &digest).is_ok());
        assert_eq!(
            validate_previous_authority_state(&journal, Path::new("deployments/other"), &digest)
                .unwrap_err(),
            "DEPLOYMENT_ACTIVATION_FAILED: Authority changed after stage"
        );
        assert!(validate_previous_authority_state(
            &journal,
            target,
            &format!("sha256:{}", "b".repeat(64))
        )
        .is_err());
    }

    #[test]
    fn stage_binds_the_shared_authority_build_that_lab_already_serves() {
        let mut journal = sample();
        let authority_after_lab = serde_json::json!({
            "version": "0.1.0",
            "buildId": "lab-promoted-authority",
            "binarySha256": format!("sha256:{}", "a".repeat(64)),
        });
        journal.previous_authority_build_info = Some(authority_after_lab.clone());
        assert!(validate_previous_authority_build_info(&journal, &authority_after_lab).is_ok());

        let old_stable_authority = serde_json::json!({
            "version": "0.1.0",
            "buildId": "pre-lab-authority",
        });
        assert!(validate_previous_authority_build_info(&journal, &old_stable_authority).is_err());
    }

    #[test]
    fn legacy_baseline_accepts_same_served_binary_at_old_path_but_keeps_digest_binding() {
        let root = std::env::temp_dir().join(format!("legacy-runtime-{}", Uuid::new_v4()));
        let old = root.join("usr/lib/actium/actium-node-supervisor");
        let snapshot = root
            .join("var/lib/actium/node-manager/deployments/legacy/runtime/actium-node-supervisor");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        fs::write(&old, b"same legacy executable").unwrap();
        fs::copy(&old, &snapshot).unwrap();
        let digest = sha256_file(&snapshot).unwrap();

        assert!(verify_binary_identity(&old, &snapshot, &digest, true).is_ok());
        assert_eq!(
            verify_binary_identity(&old, &snapshot, &digest, false).unwrap_err(),
            "DEPLOYMENT_VERIFICATION_FAILED: served executable path mismatch"
        );
        fs::write(&old, b"different executable").unwrap();
        assert_eq!(
            verify_binary_identity(&old, &snapshot, &digest, true).unwrap_err(),
            "DEPLOYMENT_VERIFICATION_FAILED: served process digest mismatch"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_baseline_accepts_old_config_path_only_when_effective_digest_matches() {
        let root = std::env::temp_dir().join(format!("legacy-config-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let old = root.join("etc/actium/node-manager/supervisor.toml");
        let snapshot =
            root.join("var/lib/actium/node-manager/deployments/legacy/runtime/supervisor.toml");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        fs::create_dir_all(snapshot.parent().unwrap()).unwrap();
        let config = "product_channel = \"lab\"\nfabric_project = \"actium-lab-fabric-01\"\nfabric_network = \"actium-lab-fabric-01\"\n";
        fs::write(&old, config).unwrap();
        let effective =
            super::super::effective_config::resolve_effective_supervisor_config(&old).unwrap();
        fs::write(&snapshot, &effective.canonical_toml).unwrap();

        assert!(
            verify_effective_config_argument(&old, &snapshot, &effective.config_digest, true)
                .is_ok()
        );
        assert!(
            verify_effective_config_argument(&old, &snapshot, &effective.config_digest, false)
                .is_err()
        );
        fs::write(&old, "product_channel = \"lab\"\n").unwrap();
        assert_eq!(
            verify_effective_config_argument(&old, &snapshot, &effective.config_digest, true)
                .unwrap_err()
                .split(':')
                .next(),
            Some("CONFIG_EFFECTIVE_STATE_INVALID")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn journal_round_trip_is_atomic_and_schema_checked() {
        let root = std::env::temp_dir().join(format!("deployment-journal-{}", Uuid::new_v4()));
        let path = root.join("deployment.json");
        let journal = sample();
        write_json_atomic(&path, &journal).unwrap();
        assert_eq!(load_journal(&path).unwrap(), journal);
        let persisted = serde_json::to_value(&journal).unwrap();
        assert_eq!(persisted["deploymentEnvironment"], "lab");
        assert_eq!(persisted["releaseChannel"], "RC");
        assert!(persisted.get("channel").is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn journal_v1_channel_alias_migrates_as_environment_without_inventing_release_channel() {
        let root = std::env::temp_dir().join(format!("deployment-journal-v1-{}", Uuid::new_v4()));
        let path = root.join("deployment.json");
        let journal = sample();
        let mut legacy = serde_json::to_value(journal).unwrap();
        let object = legacy.as_object_mut().unwrap();
        object.insert("schemaVersion".into(), serde_json::json!(1));
        let environment = object.remove("deploymentEnvironment").unwrap();
        object.insert("channel".into(), environment);
        object.remove("releaseChannel");
        write_json_atomic(&path, &legacy).unwrap();

        let loaded = load_journal(&path).unwrap();
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.deployment_environment, crate::effective_config::DeploymentEnvironment::Lab);
        assert_eq!(loaded.release_channel, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn release_channel_contract_does_not_accept_lab_as_a_distribution_track() {
        assert_eq!(serde_json::from_str::<ReleaseChannel>("\"DEV\"").unwrap(), ReleaseChannel::Dev);
        assert_eq!(serde_json::from_str::<ReleaseChannel>("\"RC\"").unwrap(), ReleaseChannel::Rc);
        assert_eq!(serde_json::from_str::<ReleaseChannel>("\"STABLE\"").unwrap(), ReleaseChannel::Stable);
        assert!(serde_json::from_str::<ReleaseChannel>("\"LAB\"").is_err());
        assert!(ReleaseChannel::Rc.matches_manager_version("0.7.0-rc.4"));
        assert!(ReleaseChannel::Dev.matches_manager_version("0.7.0-dev.2"));
        assert!(ReleaseChannel::Stable.matches_manager_version("0.7.0"));
        assert!(!ReleaseChannel::Stable.matches_manager_version("0.7.0-rc.4"));
        assert!(!ReleaseChannel::Rc.matches_manager_version("0.7.0"));
    }

    #[test]
    fn deployment_paths_reject_traversal() {
        assert_eq!(
            deployment_dir(Path::new("/tmp/root"), "../stable").unwrap_err(),
            "DEPLOYMENT_ID_INVALID"
        );
    }

    #[test]
    fn deployment_errors_are_machine_readable_and_preserve_legacy_incident_code() {
        assert_eq!(
            stable_error_code("TRUST_STORE_CHANNEL_PATH_REQUIRED: no se configuró el path"),
            "TRUST_STORE_PATH_REQUIRED"
        );
        assert_eq!(
            stable_error_code("falló algo antes de AUTHORITY_BINDING_MISMATCH"),
            "DEPLOYMENT_STAGE_FAILED"
        );
        let error = format_machine_error("CONFIG_DIGEST_MISMATCH: digest distinto");
        let value: serde_json::Value = serde_json::from_str(&error).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["code"], "CONFIG_DIGEST_MISMATCH");
        assert_eq!(
            stable_error_code("AUTHORITY_TRUST_BUNDLE_UNAVAILABLE"),
            "AUTHORITY_TRUST_BUNDLE_UNAVAILABLE"
        );
        assert_eq!(
            stable_error_code("TRUST_STORE_METADATA_REQUIRED: metadata ausente"),
            "TRUST_STORE_METADATA_REQUIRED"
        );
        assert_eq!(
            stable_error_code("DEPLOYMENT_ENVIRONMENT_MISMATCH: journal fuera de su root"),
            "DEPLOYMENT_ENVIRONMENT_MISMATCH"
        );
        assert_eq!(
            stable_error_code("DEPLOYMENT_SERVICE_NOT_ACTIVE"),
            "DEPLOYMENT_SERVICE_NOT_ACTIVE"
        );
    }

    #[test]
    fn trust_epoch_drift_has_its_own_stable_failure_code() {
        let trust = super::super::trust_store::TrustStoreStatus {
            state: "READY".into(),
            schema_version: 3,
            trust_store_id: Some(Uuid::new_v4().to_string()),
            trust_bundle_id: Some("bundle-2".into()),
            environment: "stable".into(),
            channel: "stable".into(),
            authority_binding: Some("authority-2".into()),
            current_epoch: 1,
            bundle_digest: Some("sha256:bundle".into()),
            lkg_digest: None,
            bootstrap_anchor_count: 1,
            path: "/tmp/stable/trust.json".into(),
        };
        let authority = AuthorityStatus {
            authority_generation: 2,
            activation_generation: 3,
            trust_epoch: 2,
            trust_bundle_id: "bundle-2".into(),
            served_authority_id: "authority-2".into(),
        };
        assert_eq!(
            validate_authority_binding(&trust, &authority).unwrap_err(),
            "TRUST_STORE_EPOCH_MISMATCH"
        );
    }

    #[test]
    fn lab_promotion_requires_digest_bound_functional_smoke_evidence() {
        let journal = sample();
        let report = smoke_report(&journal);
        assert!(validate_lab_smoke_report(&report, &journal).is_ok());

        let mut missing_check = report.clone();
        missing_check.checks.pop();
        assert_eq!(
            validate_lab_smoke_report(&missing_check, &journal).unwrap_err(),
            "DEPLOYMENT_PROMOTION_SMOKE_INVALID"
        );

        let mut wrong_artifact = report;
        wrong_artifact.artifact_digest = format!("sha256:{}", "f".repeat(64));
        assert_eq!(
            validate_lab_smoke_report(&wrong_artifact, &journal).unwrap_err(),
            "DEPLOYMENT_PROMOTION_SMOKE_INVALID"
        );
    }

    #[test]
    fn stable_promotion_requires_the_exact_eight_verified_smoke_checks() {
        let mut checks: Vec<String> = REQUIRED_PROMOTION_SMOKE_CHECKS
            .iter()
            .map(|check| (*check).to_string())
            .collect();
        assert!(has_required_promotion_smoke_checks(&checks));

        checks[0] = "invented-check:PASS".into();
        assert!(!has_required_promotion_smoke_checks(&checks));

        checks[0] = REQUIRED_PROMOTION_SMOKE_CHECKS[0].into();
        checks.push("extra-check:PASS".into());
        assert!(!has_required_promotion_smoke_checks(&checks));

        checks.pop();
        checks[1] = checks[0].clone();
        assert!(!has_required_promotion_smoke_checks(&checks));
    }

    #[cfg(unix)]
    #[test]
    fn promotion_evidence_is_copied_atomically_with_private_mode() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("promotion-evidence-{}", Uuid::new_v4()));
        let source = root.join("source.log");
        let destination = root.join("promotions/evidence.log");
        fs::create_dir_all(&root).unwrap();
        fs::write(&source, b"functional smoke passed\n").unwrap();
        let digest = atomic_copy_file(&source, &destination).unwrap();
        assert_eq!(digest, sha256_file(&source).unwrap());
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"functional smoke passed\n"
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn authority_status_query_uses_the_read_only_service_contract() {
        let request = authority_status_request("lab");
        assert_eq!(request["contract"], crate::AUTHORITY_SERVICE_CONTRACT);
        assert_eq!(request["operation"], "trust_bundle_status");
        assert_eq!(request["caller"], crate::AUTHORITY_SERVICE_CLIENT_ID);
        assert_eq!(request["channel"], "lab");
        assert!(request["requestId"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }
}
