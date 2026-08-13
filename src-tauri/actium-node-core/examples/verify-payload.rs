use actium_node_core::{verify_payload, VerifiedPayload};
use serde_json::json;
use std::path::PathBuf;

fn main() {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("Uso: cargo run -p actium-node-core --example verify-payload -- <payload>");
            std::process::exit(2);
        });
    let verified = verify_payload(&root).unwrap_or_else(|error| {
        eprintln!("PAYLOAD_REJECTED: {error}");
        std::process::exit(1);
    });
    let result = match verified {
        VerifiedPayload::Schema3(manifest) => json!({
            "status": "verified",
            "schema": 3,
            "releaseVersion": manifest.release_version,
            "treeSha256": manifest.tree_sha256,
            "files": manifest.files.len(),
            "sourceCommit": manifest.source_commit,
            "sourceDirty": manifest.source_dirty,
        }),
        VerifiedPayload::LegacyUnverified {
            version,
            declared_digest,
            ..
        } => json!({
            "status": "legacy-unverified",
            "schema": 2,
            "releaseVersion": version,
            "declaredDigest": declared_digest,
        }),
    };
    println!("{}", serde_json::to_string_pretty(&result).expect("JSON"));
}
