//! Supervisor-authoritative material plane (A1).
//! Journal is source of truth; active/lkg/candidate are derived views only.

mod manager;
mod reader;
mod scope;
mod state;
mod trust;
mod types;
mod verify;

pub use manager::{MaterialManager, MaterialMutationGuard};
pub use reader::{ActiveMaterial, SupervisorMaterialReader};
pub use scope::{
    load_contract_registry, load_trust_store, resolve_package_dir, trusted_scope_from_node_root,
};
pub use state::MaterialStateStore;
pub use trust::{MaterialTrustEntry, MaterialTrustStore};
pub use types::*;
pub use verify::{
    canonical_signed_envelope_v1, compute_content_digest_from_disk, compute_manifest_digest,
    encode_ed25519_spki_der, hex_sha256, key_id_for_spki_der, parse_ed25519_spki_der,
    signed_envelope_digest,
};

#[cfg(test)]
mod tests;
