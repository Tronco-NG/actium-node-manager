//! One-shot Root-brief Trust Bundle rebuild.
//!
//! After Center Authority reissue, durable AS may serve a stale file while
//! Product Root remains `public_only` offline. This tool briefly combines
//! online subordinate keys with the offline Product Root inside a wiped
//! work directory, signs a successor Trust Bundle, and writes only the
//! public artifact. Private key material is never printed.

use actium_node_core::{
    unix_now, AuthorityKind, AuthorityService, DurableAuthorityState, SealedKeyProvider,
    SignedTrustBundle,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, to_vec_pretty};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const CONFIRMATION: &str = "BRIEF_ROOT_REBUILD_APPROVED";
const EXPECTED_CENTER_AUTHORITY_ID: &str = "center-authority-v2";

fn main() {
    if let Err(error) = run() {
        eprintln!("authority rebuild trust bundle failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse()?;
    if args.confirm != CONFIRMATION {
        return Err("AUTHORITY_ROOT_BRIEF_CONFIRMATION_REQUIRED".into());
    }
    if args.root_key_id.trim().is_empty() || args.root_key_id.contains(['/', '\\', ':']) {
        return Err("AUTHORITY_ROOT_KEY_ID_INVALID".into());
    }
    if args.trust_bundle_out.exists() {
        return Err("AUTHORITY_TRUST_BUNDLE_OUTPUT_ALREADY_EXISTS".into());
    }
    if same_path(&args.offline_sealing_key_file, &args.online_sealing_key_file)? {
        return Err("AUTHORITY_SEALING_KEYS_MUST_BE_SEPARATE".into());
    }

    let state_bytes =
        fs::read(&args.state_in).map_err(|_| "AUTHORITY_STATE_IN_UNAVAILABLE".to_string())?;
    let mut state: DurableAuthorityState = serde_json::from_slice(&state_bytes)
        .map_err(|_| "AUTHORITY_STATE_IN_INVALID".to_string())?;
    if !state
        .authorities
        .iter()
        .any(|authority| authority.authority_id == EXPECTED_CENTER_AUTHORITY_ID)
    {
        return Err("AUTHORITY_STATE_MISSING_CENTER_AUTHORITY_V2".into());
    }
    if !state
        .public_only_key_ids
        .iter()
        .any(|key_id| key_id == &args.root_key_id)
    {
        return Err("AUTHORITY_ROOT_KEY_NOT_PUBLIC_ONLY".into());
    }
    let root_authority = state
        .authorities
        .iter()
        .find(|authority| {
            authority.key_id == args.root_key_id && authority.kind == AuthorityKind::ProductTrustRoot
        })
        .ok_or_else(|| "AUTHORITY_ROOT_KEY_ID_UNKNOWN".to_string())?
        .clone();

    let work_dir = std::env::temp_dir().join(format!(
        "actium-root-brief-rebuild-{}-{}",
        std::process::id(),
        unix_now()
    ));
    if work_dir.exists() {
        return Err("AUTHORITY_ROOT_BRIEF_WORK_DIR_EXISTS".into());
    }
    fs::create_dir_all(&work_dir).map_err(|_| "AUTHORITY_ROOT_BRIEF_WORK_DIR_FAILED")?;
    let _cleanup = WorkDirGuard {
        path: work_dir.clone(),
    };

    let mut sealing_key = [0u8; 32];
    OsRng.fill_bytes(&mut sealing_key);
    let online = SealedKeyProvider::from_sealing_key_file(
        &args.online_key_dir,
        &args.online_sealing_key_file,
    )?;
    let offline = SealedKeyProvider::from_sealing_key_file(
        &args.offline_key_dir,
        &args.offline_sealing_key_file,
    )?;
    let mut work = SealedKeyProvider::new(&work_dir, sealing_key)?;

    for authority in &state.authorities {
        if authority.key_id == args.root_key_id {
            continue;
        }
        work.copy_key_from(&online, &authority.key_id)?;
    }
    work.copy_key_from(&offline, &args.root_key_id)?;

    // Temporary signing workspace may hold the Root private key; clear
    // public_only so from_durable_state accepts the brief presence.
    state.public_only_key_ids.clear();
    let service = AuthorityService::from_durable_state(work, state)?;
    let timestamp = unix_now();
    let trust_bundle = service.trust_bundle(&root_authority.authority_id, timestamp, None)?;
    service.verify_trust_bundle(&trust_bundle, timestamp, service.trust_epoch())?;
    let center_authority_id = trust_bundle
        .bundle
        .center_authority
        .as_ref()
        .map(|authority| authority.authority_id.as_str())
        .ok_or_else(|| "AUTHORITY_TRUST_BUNDLE_CENTER_MISSING".to_string())?;
    if center_authority_id != EXPECTED_CENTER_AUTHORITY_ID {
        return Err(format!(
            "AUTHORITY_TRUST_BUNDLE_CENTER_MISMATCH:expected={EXPECTED_CENTER_AUTHORITY_ID}:observed={center_authority_id}"
        ));
    }

    write_new_json(&args.trust_bundle_out, &trust_bundle)?;

    let result = json!({
        "ok": true,
        "centerAuthorityId": center_authority_id,
        "trustBundleId": trust_bundle.bundle.trust_bundle_id,
        "trustEpoch": trust_bundle.bundle.trust_epoch,
        "signingKeyId": trust_bundle.signing_key_id,
        "stateIn": path_string(&args.state_in),
        "trustBundleOut": path_string(&args.trust_bundle_out),
        "onlineKeyDir": path_string(&args.online_key_dir),
        "offlineKeyDir": path_string(&args.offline_key_dir),
        "rootPrivateMaterial": "absent_from_output",
    });
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|_| "AUTHORITY_RESULT_SERIALIZE_FAILED")?
    );
    Ok(())
}

struct WorkDirGuard {
    path: PathBuf,
}

impl Drop for WorkDirGuard {
    fn drop(&mut self) {
        if self.path.is_dir() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn write_new_json(path: &Path, value: &SignedTrustBundle) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "AUTHORITY_OUTPUT_PATH_INVALID".to_string())?;
    fs::create_dir_all(parent).map_err(|_| "AUTHORITY_OUTPUT_DIR_FAILED")?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("trust-bundle"),
        std::process::id()
    ));
    if temporary.exists() || path.exists() {
        return Err("AUTHORITY_TRUST_BUNDLE_OUTPUT_ALREADY_EXISTS".into());
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

fn same_path(left: &Path, right: &Path) -> Result<bool, String> {
    let left = left
        .canonicalize()
        .map_err(|_| "AUTHORITY_SEALING_KEY_UNAVAILABLE".to_string())?;
    let right = right
        .canonicalize()
        .map_err(|_| "AUTHORITY_SEALING_KEY_UNAVAILABLE".to_string())?;
    Ok(left == right)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

struct Args {
    online_key_dir: PathBuf,
    online_sealing_key_file: PathBuf,
    offline_key_dir: PathBuf,
    offline_sealing_key_file: PathBuf,
    state_in: PathBuf,
    trust_bundle_out: PathBuf,
    root_key_id: String,
    confirm: String,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut values = std::collections::BTreeMap::new();
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if !flag.starts_with("--") {
                return Err("AUTHORITY_ROOT_BRIEF_ARGUMENT_INVALID".into());
            }
            let value = args
                .next()
                .ok_or_else(|| "AUTHORITY_ROOT_BRIEF_ARGUMENT_VALUE_REQUIRED".to_string())?;
            if values.insert(flag, value).is_some() {
                return Err("AUTHORITY_ROOT_BRIEF_ARGUMENT_DUPLICATE".into());
            }
        }
        let required = |name: &str| {
            values
                .get(name)
                .cloned()
                .ok_or_else(|| format!("AUTHORITY_ROOT_BRIEF_ARGUMENT_REQUIRED: {name}"))
        };
        Ok(Self {
            online_key_dir: PathBuf::from(required("--online-key-dir")?),
            online_sealing_key_file: PathBuf::from(required("--online-sealing-key-file")?),
            offline_key_dir: PathBuf::from(required("--offline-key-dir")?),
            offline_sealing_key_file: PathBuf::from(required("--offline-sealing-key-file")?),
            state_in: PathBuf::from(required("--state-in")?),
            trust_bundle_out: PathBuf::from(required("--trust-bundle-out")?),
            root_key_id: required("--root-key-id")?,
            confirm: required("--confirm")?,
        })
    }
}
