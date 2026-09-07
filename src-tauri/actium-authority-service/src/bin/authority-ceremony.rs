//! Explicit offline Product Trust Root ceremony.
//!
//! This command is never called by the Authority Service at startup.  It
//! creates a new hierarchy only when the Owner supplies separate offline and
//! online storage locations and an explicit confirmation string.  The root
//! remains in the offline provider; only subordinate keys are re-wrapped into
//! the online provider.  No private key is printed or serialized.

use actium_node_core::{
    authority_capability, unix_now, AuthorityKind, AuthorityService, DurableAuthorityState,
    SealedKeyProvider,
};
use serde_json::to_vec_pretty;
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const TRUST_ROOT_SET: &str = "actium-product-v1";
const CONFIRMATION: &str = "OFFLINE_ROOT_OWNER_APPROVED";

fn main() {
    if let Err(error) = run() {
        eprintln!("authority ceremony failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    if args.confirm != CONFIRMATION {
        return Err("AUTHORITY_CEREMONY_CONFIRMATION_REQUIRED".into());
    }
    if args.root_authority_id.trim().is_empty()
        || args.root_authority_id.contains(['/', '\\', ':'])
    {
        return Err("AUTHORITY_ROOT_ID_INVALID".into());
    }

    fs::create_dir_all(&args.offline_key_dir).map_err(|_| "AUTHORITY_OFFLINE_DIR_FAILED")?;
    if fs::read_dir(&args.offline_key_dir)
        .map_err(|_| "AUTHORITY_OFFLINE_DIR_FAILED")?
        .next()
        .is_some()
    {
        return Err("AUTHORITY_OFFLINE_DIR_NOT_EMPTY".into());
    }
    if args.online_key_dir.exists() {
        return Err("AUTHORITY_ONLINE_KEY_DIR_ALREADY_EXISTS".into());
    }
    if args.state_out.exists() || args.trust_bundle_out.exists() {
        return Err("AUTHORITY_CEREMONY_OUTPUT_ALREADY_EXISTS".into());
    }
    if same_path(&args.offline_sealing_key_file, &args.online_sealing_key_file)? {
        return Err("AUTHORITY_SEALING_KEYS_MUST_BE_SEPARATE".into());
    }

    let online_parent = args
        .online_key_dir
        .parent()
        .ok_or_else(|| "AUTHORITY_ONLINE_DIR_INVALID".to_string())?;
    fs::create_dir_all(online_parent).map_err(|_| "AUTHORITY_ONLINE_PARENT_FAILED")?;
    let staging = online_parent.join(format!(
        ".actium-authority-staging-{}-{}",
        std::process::id(),
        unix_now()
    ));
    if staging.exists() {
        return Err("AUTHORITY_CEREMONY_STAGING_EXISTS".into());
    }

    let offline = SealedKeyProvider::from_sealing_key_file(
        &args.offline_key_dir,
        &args.offline_sealing_key_file,
    )?;
    let mut service = AuthorityService::new(offline, TRUST_ROOT_SET);
    let timestamp = unix_now();
    let root = service.initialize_root(&args.root_authority_id, timestamp)?;
    service.issue_subordinate(
        &root.authority.authority_id,
        "deployment-authority",
        AuthorityKind::DeploymentAuthority,
        vec![authority_capability(AuthorityKind::DeploymentAuthority).into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "deployment-authority",
        "deployment-root",
        AuthorityKind::DeploymentRoot,
        vec![authority_capability(AuthorityKind::DeploymentRoot).into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "deployment-root",
        "center-authority",
        AuthorityKind::CenterAuthority,
        vec![
            authority_capability(AuthorityKind::CenterAuthority).into(),
            "center_bundle_signing".into(),
            "site_runtime_authority".into(),
        ],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "center-authority",
        "enrollment-authority",
        AuthorityKind::EnrollmentAuthority,
        vec!["host_enrollment".into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        &root.authority.authority_id,
        "release-authority",
        AuthorityKind::ReleaseAuthority,
        vec![authority_capability(AuthorityKind::ReleaseAuthority).into()],
        timestamp,
        None,
    )?;
    service.issue_subordinate(
        "release-authority",
        "product-signing-authority",
        AuthorityKind::ProductSigningAuthority,
        vec!["product_signing".into()],
        timestamp,
        None,
    )?;

    let trust_bundle = service.trust_bundle(&root.authority.authority_id, timestamp, None)?;
    service.verify_trust_bundle(&trust_bundle, timestamp, 1)?;
    let mut durable: DurableAuthorityState = service.durable_state();
    durable.public_only_key_ids = vec![root.authority.key_id.clone()];

    let offline_key_ids: Vec<String> = durable
        .authorities
        .iter()
        .filter(|authority| authority.key_id != root.authority.key_id)
        .map(|authority| authority.key_id.clone())
        .collect();

    let mut online = SealedKeyProvider::from_sealing_key_file(&staging, &args.online_sealing_key_file)?;
    for key_id in &offline_key_ids {
        online.copy_key_from(service.provider(), key_id)?;
    }
    // Rehydrate against the staged provider before any public artifact is
    // activated.  This catches missing subordinate references early.
    let _validated = AuthorityService::from_durable_state(online, durable.clone())?;

    let mut created_outputs = Vec::new();
    if let Err(error) = write_new_json(&args.state_out, &durable) {
        cleanup_staging(&staging);
        return Err(error);
    }
    created_outputs.push(args.state_out.clone());
    if let Err(error) = write_new_json(&args.trust_bundle_out, &trust_bundle) {
        for output in &created_outputs {
            let _ = fs::remove_file(output);
        }
        cleanup_staging(&staging);
        return Err(error);
    }
    created_outputs.push(args.trust_bundle_out.clone());

    if let Err(error) = fs::rename(&staging, &args.online_key_dir) {
        for output in &created_outputs {
            let _ = fs::remove_file(output);
        }
        cleanup_staging(&staging);
        return Err(format!("AUTHORITY_ONLINE_KEY_DIR_COMMIT_FAILED: {error}"));
    }

    println!(
        "Authority ceremony prepared: root_key_id={} trust_bundle={} subordinate_keys={} online_root_private_key=absent",
        root.authority.key_id,
        args.trust_bundle_out.display(),
        offline_key_ids.len()
    );
    Ok(())
}

fn write_new_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "AUTHORITY_OUTPUT_PATH_INVALID".to_string())?;
    fs::create_dir_all(parent).map_err(|_| "AUTHORITY_OUTPUT_DIR_FAILED")?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("authority"),
        std::process::id()
    ));
    if temporary.exists() || path.exists() {
        return Err("AUTHORITY_CEREMONY_OUTPUT_ALREADY_EXISTS".into());
    }
    let bytes = to_vec_pretty(value).map_err(|_| "AUTHORITY_OUTPUT_SERIALIZE_FAILED")?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| "AUTHORITY_OUTPUT_TEMP_FAILED")?;
    if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("AUTHORITY_OUTPUT_WRITE_FAILED: {error}"));
    }
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(format!("AUTHORITY_OUTPUT_COMMIT_FAILED: {error}"));
    }
    Ok(())
}

fn cleanup_staging(path: &Path) {
    if path.is_dir() {
        let _ = fs::remove_dir_all(path);
    }
}

fn same_path(left: &Path, right: &Path) -> Result<bool, String> {
    let left = left
        .canonicalize()
        .map_err(|_| "AUTHORITY_SEALING_KEY_UNAVAILABLE".to_string())?;
    let right = right
        .canonicalize()
        .map_err(|_| "AUTHORITY_SEALING_KEY_UNAVAILABLE".to_string())?;
    Ok(left == right)
}

struct Args {
    offline_key_dir: PathBuf,
    online_key_dir: PathBuf,
    offline_sealing_key_file: PathBuf,
    online_sealing_key_file: PathBuf,
    state_out: PathBuf,
    trust_bundle_out: PathBuf,
    root_authority_id: String,
    confirm: String,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut values = std::collections::BTreeMap::new();
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if !flag.starts_with("--") {
                return Err("AUTHORITY_CEREMONY_ARGUMENT_INVALID".into());
            }
            let value = args
                .next()
                .ok_or_else(|| "AUTHORITY_CEREMONY_ARGUMENT_VALUE_REQUIRED".to_string())?;
            if values.insert(flag, value).is_some() {
                return Err("AUTHORITY_CEREMONY_ARGUMENT_DUPLICATE".into());
            }
        }
        let required = |name: &str| {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| format!("AUTHORITY_CEREMONY_ARGUMENT_REQUIRED: {name}"))
        };
        Ok(Self {
            offline_key_dir: PathBuf::from(required("--offline-key-dir")?),
            online_key_dir: PathBuf::from(required("--online-key-dir")?),
            offline_sealing_key_file: PathBuf::from(required("--offline-sealing-key-file")?),
            online_sealing_key_file: PathBuf::from(required("--online-sealing-key-file")?),
            state_out: PathBuf::from(required("--state-out")?),
            trust_bundle_out: PathBuf::from(required("--trust-bundle-out")?),
            root_authority_id: required("--root-authority-id")?,
            confirm: required("--confirm")?,
        })
    }
}
