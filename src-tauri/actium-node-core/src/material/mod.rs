//! Supervisor-authoritative material plane (A1).
//! Journal is source of truth; active/lkg/candidate are derived views only.

mod manager;
mod state;
mod trust;
mod types;
mod verify;

pub use manager::{MaterialManager, MaterialMutationGuard};
pub use state::MaterialStateStore;
pub use trust::{MaterialTrustEntry, MaterialTrustStore};
pub use types::*;
pub use verify::{
    compute_content_digest_from_disk, compute_manifest_digest, hex_sha256, key_id_for_public_key,
    signed_envelope_digest,
};

#[cfg(test)]
mod tests;
