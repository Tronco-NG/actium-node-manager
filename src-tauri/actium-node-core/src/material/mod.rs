//! Supervisor-authoritative material plane (A1).
//! Journal is source of truth; active/lkg/candidate are derived views only.

mod connectivity;
mod manager;
mod reader;
mod scope;
mod state;
mod trust;
mod types;
mod verify;

pub use connectivity::{
    apply_network_transition, connectivity_material_contract, materialize_provider,
    parse_gateway_strategy, parse_transport_kind, reject_agent_material_path,
    validate_access_transport_policy, AccessConnectivityPolicy, ConnectivityStatus,
    TransportKind, CONNECTIVITY_MATERIAL_CAPABILITY, CONNECTIVITY_MATERIAL_RELATIVE,
};
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
