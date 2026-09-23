//! Authority lifecycle plan derived from durable Authority Service state.
//!
//! Replaces migration-specific hardcoding (`center-authority-v2`, specific
//! transition UUIDs) with discovery from `DurableAuthorityState` plus the
//! currently served Trust Bundle.  This is not a generic PKI framework.

use crate::trust_fabric::{
    AuthorityDescriptor, AuthorityKind, AuthorityStatus, CenterAuthorityTransitionStatus,
    CenterAuthorityTransitionV1, DurableAuthorityState, REMOTE_OPERATIONS_SIGNING_CAPABILITY,
    SignedTrustBundle,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AUTHORITY_LIFECYCLE_CONTRACT: &str = "actium.authority.lifecycle.plan.v1";
pub const AUTHORITY_LIFECYCLE_CUSTODY_OFFLINE_PRODUCT_ROOT: &str = "offline_product_root_public_only";
pub const AUTHORITY_LIFECYCLE_CUSTODY_ONLINE_SUBORDINATE: &str = "online_subordinate";
pub const SUCCESSOR_ACTIVATION_CONTRACT: &str = "actium.authority.successor-activation.v1";
pub const HOST_TRUST_CONVERGENCE_CONTRACT: &str = "actium.authority.host-trust-convergence.v1";

/// A trust lifecycle is scoped to an explicit product channel.  The channel
/// is part of the public job/receipt contract so LAB and STABLE can never be
/// confused by an otherwise valid transition, while older durable files that
/// predate channel support remain readable as STABLE.
pub fn normalize_lifecycle_channel(value: Option<&str>) -> Result<String, String> {
    let channel = value.unwrap_or("stable").trim().to_ascii_lowercase();
    match channel.as_str() {
        "lab" | "stable" => Ok(channel),
        _ => Err("AUTHORITY_LIFECYCLE_CHANNEL_INVALID".into()),
    }
}

pub fn default_lifecycle_channel() -> String {
    "stable".into()
}

/// Runtime phases are deliberately separate from the durable Center
/// transition status.  The former describes what this Host is serving; the
/// latter describes governance/publication and host convergence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityLifecyclePhase {
    Generated,
    Prepared,
    Validated,
    Activating,
    ServedReady,
    Published,
    Converging,
    Converged,
    Retired,
    Failed,
    Rollback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuccessorActivationReceiptV1 {
    pub contract: String,
    pub phase: AuthorityLifecyclePhase,
    pub transition_id: String,
    pub predecessor_authority_id: String,
    pub successor_authority_id: String,
    pub previous_digest: String,
    pub served_digest: String,
    pub trust_epoch: u64,
    /// Authority generation is distinct from software/build/install identity.
    pub authority_generation: u64,
    pub activation_generation: u64,
    pub started_at: u64,
    pub completed_at: u64,
    pub result: String,
    pub lkg_path: String,
    /// Product lifecycle channel.  Defaults to STABLE for pre-channel
    /// receipts, but all new activation receipts write it explicitly.
    #[serde(default = "default_lifecycle_channel")]
    pub channel: String,
}

/// Public, signed successor material carried by a Center-issued Host job.
/// The bundle and transition contain public evidence only; no private key is
/// transported to the Host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTrustBundleRefreshRequestV1 {
    pub contract: String,
    pub transition: CenterAuthorityTransitionV1,
    pub bundle: SignedTrustBundle,
    pub expected_digest: String,
    pub authority_generation: u64,
    /// Per-job activation generation; intentionally distinct from trust epoch.
    #[serde(default)]
    pub activation_generation: u64,
    #[serde(default = "default_lifecycle_channel")]
    pub channel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostTrustActivationReceiptV1 {
    pub contract: String,
    pub phase: AuthorityLifecyclePhase,
    pub transition_id: String,
    pub predecessor_authority_id: String,
    pub successor_authority_id: String,
    pub previous_digest: String,
    pub served_digest: String,
    pub previous_trust_epoch: u64,
    pub trust_epoch: u64,
    pub authority_generation: u64,
    pub activation_generation: u64,
    pub started_at: u64,
    pub completed_at: u64,
    pub result: String,
    pub lkg_path: String,
    /// SHA-256 over the canonical public receipt without this field.  It is
    /// the durable replay key correlated by Center; it is not a signature.
    #[serde(default)]
    pub receipt_digest: String,
    #[serde(default = "default_lifecycle_channel")]
    pub channel: String,
}

impl HostTrustActivationReceiptV1 {
    pub fn with_receipt_digest(mut self) -> Result<Self, String> {
        let mut value = serde_json::to_value(&self)
            .map_err(|error| format!("HOST_TRUST_RECEIPT_SERIALIZE_FAILED: {error}"))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| "HOST_TRUST_RECEIPT_OBJECT_REQUIRED".to_string())?;
        object.remove("receiptDigest");
        let canonical = crate::canonical_json(&value)?;
        let digest = Sha256::digest(canonical.as_bytes());
        self.receipt_digest = format!("sha256:{digest:x}");
        Ok(self)
    }
}

/// Validate the currently served bundle before promoting a successor for an
/// open Center-authority transition.
///
/// The first activation starts from the transition predecessor. A retry or a
/// later epoch of the same transition starts from the already served
/// successor, which is a valid intermediate state and must be treated as the
/// current LKG rather than as a split-brain condition. The latter case is
/// accepted only when the prior bundle is the same successor, has a strictly
/// lower trust epoch, and still retains the original predecessor publicly.
/// Signatures and the transition proof remain the responsibility of the
/// existing bundle/transition verifiers.
pub fn validate_successor_activation_lineage(
    transition: &CenterAuthorityTransitionV1,
    previous: &SignedTrustBundle,
    candidate: &SignedTrustBundle,
) -> Result<(), String> {
    let previous_center = previous
        .bundle
        .center_authority
        .as_ref()
        .ok_or_else(|| "AUTHORITY_SUCCESSOR_PREDECESSOR_NOT_SERVED".to_string())?;
    let candidate_center = candidate
        .bundle
        .center_authority
        .as_ref()
        .ok_or_else(|| "AUTHORITY_SUCCESSOR_CENTER_MISSING".to_string())?;

    if candidate_center.authority_id != transition.successor_authority_id
        || candidate_center.key_id != transition.successor_key_id
    {
        return Err("AUTHORITY_SUCCESSOR_TRANSITION_SCOPE_INVALID".into());
    }
    if candidate.bundle.trust_epoch < transition.activation_epoch
        || candidate.bundle.trust_epoch <= previous.bundle.trust_epoch
    {
        return Err("TRUST_EPOCH_NOT_MONOTONIC".into());
    }

    let serves_original_predecessor = previous_center.authority_id
        == transition.predecessor_authority_id
        && previous_center.key_id == transition.predecessor_key_id;
    if serves_original_predecessor {
        return Ok(());
    }

    let serves_prior_successor = previous_center.authority_id
        == transition.successor_authority_id
        && previous_center.key_id == transition.successor_key_id;
    if !serves_prior_successor {
        return Err("AUTHORITY_SUCCESSOR_PREDECESSOR_NOT_SERVED".into());
    }

    let predecessor_retained = previous
        .bundle
        .predecessor_center_authorities
        .iter()
        .any(|authority| {
            authority.authority_id == transition.predecessor_authority_id
                && authority.key_id == transition.predecessor_key_id
        });
    if !predecessor_retained {
        return Err("AUTHORITY_SUCCESSOR_LINEAGE_INVALID".into());
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityLifecycleRuntimeV1 {
    pub contract: String,
    pub phase: AuthorityLifecyclePhase,
    pub served_digest: Option<String>,
    pub expected_digest: Option<String>,
    pub authority_generation: u64,
    pub trust_epoch: u64,
    pub transition_id: Option<String>,
    pub updated_at: u64,
    pub last_activation: Option<SuccessorActivationReceiptV1>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityLifecycleState {
    Healthy,
    SuccessorPrepared,
    OwnerApprovalRequired,
    RootRequired,
    TrustBundleRebuildRequired,
    ReadyToPromote,
    Promoting,
    HostConvergence,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityLifecyclePlanV1 {
    pub contract: String,
    pub current_authority_id: String,
    pub target_authority_id: String,
    pub predecessor_authority_id: String,
    pub transition_id: Option<String>,
    pub required_capabilities: Vec<String>,
    pub current_trust_epoch: u64,
    pub target_trust_epoch: u64,
    pub root_authority_id: String,
    pub custody_profile: String,
    pub state: AuthorityLifecycleState,
    pub predecessor_overlap_required: bool,
    pub owner_root_action_required: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServedTrustBundleView<'a> {
    pub center_authority_id: &'a str,
    pub trust_epoch: u64,
}

pub fn resolve_authority_lifecycle_plan(
    state: &DurableAuthorityState,
    served: Option<ServedTrustBundleView<'_>>,
) -> Result<AuthorityLifecyclePlanV1, String> {
    let root = product_root(state)?;
    let custody_profile = if state
        .public_only_key_ids
        .iter()
        .any(|key_id| key_id == &root.key_id)
    {
        AUTHORITY_LIFECYCLE_CUSTODY_OFFLINE_PRODUCT_ROOT
    } else {
        AUTHORITY_LIFECYCLE_CUSTODY_ONLINE_SUBORDINATE
    };

    let centers: Vec<&AuthorityDescriptor> = state
        .authorities
        .iter()
        .filter(|authority| authority.kind == AuthorityKind::CenterAuthority)
        .collect();
    if centers.is_empty() {
        return Err("AUTHORITY_LIFECYCLE_CENTER_MISSING".into());
    }

    let served_center_id = served
        .map(|view| view.center_authority_id.to_string())
        .or_else(|| {
            centers
                .iter()
                .find(|authority| {
                    authority.status == AuthorityStatus::Active
                        && !authority
                            .capabilities
                            .iter()
                            .any(|cap| cap == REMOTE_OPERATIONS_SIGNING_CAPABILITY)
                })
                .or_else(|| centers.first())
                .map(|authority| authority.authority_id.clone())
        })
        .ok_or_else(|| "AUTHORITY_LIFECYCLE_CURRENT_CENTER_UNKNOWN".to_string())?;

    let transition = open_transition(state)?;
    let current_epoch = served.map(|view| view.trust_epoch).unwrap_or(state.trust_epoch);

    if let Some(transition) = transition {
        return plan_from_transition(state, root, custody_profile, &served_center_id, current_epoch, transition);
    }

    let current = centers
        .iter()
        .find(|authority| authority.authority_id == served_center_id)
        .copied()
        .ok_or_else(|| "AUTHORITY_LIFECYCLE_SERVED_CENTER_UNKNOWN".to_string())?;
    let has_remote_ops = current
        .capabilities
        .iter()
        .any(|cap| cap == REMOTE_OPERATIONS_SIGNING_CAPABILITY);
    let state_value = if has_remote_ops {
        AuthorityLifecycleState::Healthy
    } else {
        AuthorityLifecycleState::Blocked
    };
    Ok(AuthorityLifecyclePlanV1 {
        contract: AUTHORITY_LIFECYCLE_CONTRACT.to_string(),
        current_authority_id: current.authority_id.clone(),
        target_authority_id: current.authority_id.clone(),
        predecessor_authority_id: current.authority_id.clone(),
        transition_id: None,
        required_capabilities: current.capabilities.clone(),
        current_trust_epoch: current_epoch,
        target_trust_epoch: current_epoch,
        root_authority_id: root.authority_id.clone(),
        custody_profile: custody_profile.to_string(),
        state: state_value,
        predecessor_overlap_required: false,
        owner_root_action_required: false,
        reason: if has_remote_ops {
            "current_center_healthy".into()
        } else {
            "current_center_missing_remote_operations_signing".into()
        },
    })
}

/// Successor identity for Root Brief rebuild.  Fail-closed if durable state
/// does not identify exactly one in-flight successor.
pub fn host_trust_refresh_required(plan: &AuthorityLifecyclePlanV1) -> bool {
    matches!(
        plan.state,
        AuthorityLifecycleState::ReadyToPromote
            | AuthorityLifecycleState::Promoting
            | AuthorityLifecycleState::HostConvergence
    )
}

pub fn resolve_root_brief_successor_authority_id(
    state: &DurableAuthorityState,
    served: Option<ServedTrustBundleView<'_>>,
) -> Result<String, String> {
    let plan = resolve_authority_lifecycle_plan(state, served)?;
    match plan.state {
        AuthorityLifecycleState::RootRequired
        | AuthorityLifecycleState::TrustBundleRebuildRequired
        | AuthorityLifecycleState::ReadyToPromote
        | AuthorityLifecycleState::Promoting
        | AuthorityLifecycleState::HostConvergence => {
            if plan.target_authority_id.is_empty()
                || plan.target_authority_id == plan.current_authority_id
            {
                return Err("AUTHORITY_LIFECYCLE_SUCCESSOR_UNRESOLVED".into());
            }
            if !state
                .authorities
                .iter()
                .any(|authority| {
                    authority.authority_id == plan.target_authority_id
                        && authority.kind == AuthorityKind::CenterAuthority
                })
            {
                return Err("AUTHORITY_LIFECYCLE_SUCCESSOR_NOT_IN_STATE".into());
            }
            Ok(plan.target_authority_id)
        }
        AuthorityLifecycleState::Healthy => Err("AUTHORITY_LIFECYCLE_NO_SUCCESSOR_PENDING".into()),
        AuthorityLifecycleState::SuccessorPrepared
        | AuthorityLifecycleState::OwnerApprovalRequired => {
            Err("AUTHORITY_LIFECYCLE_OWNER_APPROVAL_REQUIRED".into())
        }
        AuthorityLifecycleState::Failed | AuthorityLifecycleState::Blocked => {
            Err(format!("AUTHORITY_LIFECYCLE_{:?}", plan.state).to_ascii_uppercase())
        }
    }
}

fn product_root(state: &DurableAuthorityState) -> Result<&AuthorityDescriptor, String> {
    let mut roots: Vec<&AuthorityDescriptor> = state
        .authorities
        .iter()
        .filter(|authority| {
            authority.kind == AuthorityKind::ProductTrustRoot
                && authority.status == AuthorityStatus::Active
        })
        .collect();
    if roots.len() != 1 {
        return Err("AUTHORITY_LIFECYCLE_PRODUCT_ROOT_AMBIGUOUS".into());
    }
    Ok(roots.remove(0))
}

fn open_transition(
    state: &DurableAuthorityState,
) -> Result<Option<&CenterAuthorityTransitionV1>, String> {
    let open: Vec<&CenterAuthorityTransitionV1> = state
        .center_authority_transitions
        .iter()
        .filter(|transition| {
            !matches!(
                transition.status,
                CenterAuthorityTransitionStatus::Completed
                    | CenterAuthorityTransitionStatus::Failed
            )
        })
        .collect();
    match open.len() {
        0 => Ok(None),
        1 => Ok(Some(open[0])),
        _ => Err("AUTHORITY_LIFECYCLE_AMBIGUOUS_OPEN_TRANSITIONS".into()),
    }
}

fn plan_from_transition(
    state: &DurableAuthorityState,
    root: &AuthorityDescriptor,
    custody_profile: &str,
    served_center_id: &str,
    current_epoch: u64,
    transition: &CenterAuthorityTransitionV1,
) -> Result<AuthorityLifecyclePlanV1, String> {
    let successor = state
        .authorities
        .iter()
        .find(|authority| authority.authority_id == transition.successor_authority_id)
        .ok_or_else(|| "AUTHORITY_LIFECYCLE_SUCCESSOR_NOT_IN_STATE".to_string())?;
    let public_only_root = custody_profile == AUTHORITY_LIFECYCLE_CUSTODY_OFFLINE_PRODUCT_ROOT;
    let bundle_has_successor = served_center_id == transition.successor_authority_id;
    let publication = transition
        .proof
        .get("publication")
        .and_then(|value| value.as_str())
        .unwrap_or("");

    let (lifecycle_state, reason, owner_root_action_required) = match transition.status {
        CenterAuthorityTransitionStatus::Prepared => (
            AuthorityLifecycleState::OwnerApprovalRequired,
            "successor_prepared_owner_approval_required",
            false,
        ),
        CenterAuthorityTransitionStatus::Issued if bundle_has_successor => (
            AuthorityLifecycleState::ReadyToPromote,
            "successor_present_in_served_bundle",
            false,
        ),
        CenterAuthorityTransitionStatus::Issued if public_only_root => (
            AuthorityLifecycleState::RootRequired,
            "issued_successor_requires_offline_product_root_brief",
            true,
        ),
        CenterAuthorityTransitionStatus::Issued
            if publication == "EXPLICIT_TRUST_BUNDLE_PUBLICATION_REQUIRED" =>
        {
            (
                AuthorityLifecycleState::TrustBundleRebuildRequired,
                "issued_successor_requires_trust_bundle_rebuild",
                false,
            )
        }
        CenterAuthorityTransitionStatus::Issued => (
            AuthorityLifecycleState::TrustBundleRebuildRequired,
            "issued_successor_not_in_served_bundle",
            false,
        ),
        CenterAuthorityTransitionStatus::Published => (
            AuthorityLifecycleState::Promoting,
            "successor_bundle_published",
            false,
        ),
        CenterAuthorityTransitionStatus::HostsConverging => (
            AuthorityLifecycleState::HostConvergence,
            "hosts_must_refresh_trust_without_reenroll",
            false,
        ),
        CenterAuthorityTransitionStatus::Active => (
            AuthorityLifecycleState::Healthy,
            "successor_active",
            false,
        ),
        CenterAuthorityTransitionStatus::PredecessorRetiring => (
            AuthorityLifecycleState::HostConvergence,
            "predecessor_overlap_until_scoped_host_convergence",
            false,
        ),
        CenterAuthorityTransitionStatus::Completed => (
            AuthorityLifecycleState::Healthy,
            "transition_completed",
            false,
        ),
        CenterAuthorityTransitionStatus::Failed => {
            (AuthorityLifecycleState::Failed, "transition_failed", false)
        }
    };

    Ok(AuthorityLifecyclePlanV1 {
        contract: AUTHORITY_LIFECYCLE_CONTRACT.to_string(),
        current_authority_id: served_center_id.to_string(),
        target_authority_id: successor.authority_id.clone(),
        predecessor_authority_id: transition.predecessor_authority_id.clone(),
        transition_id: Some(transition.transition_id.clone()),
        required_capabilities: if transition.required_capabilities.is_empty() {
            successor.capabilities.clone()
        } else {
            transition.required_capabilities.clone()
        },
        current_trust_epoch: current_epoch,
        target_trust_epoch: transition.activation_epoch.max(current_epoch),
        root_authority_id: root.authority_id.clone(),
        custody_profile: custody_profile.to_string(),
        state: lifecycle_state,
        predecessor_overlap_required: !matches!(
            transition.status,
            CenterAuthorityTransitionStatus::Completed
                | CenterAuthorityTransitionStatus::Failed
                | CenterAuthorityTransitionStatus::PredecessorRetiring
        ),
        owner_root_action_required,
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_fabric::{
        AuthorityCertificate, AuthorityDescriptor, AuthorityKind, AuthorityStatus,
        CenterAuthorityTransitionSignatureV1, CenterAuthorityTransitionV1, DurableAuthorityState,
        Revocation, RootTransition, SignedTrustBundle, TrustBundle,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    fn descriptor(id: &str, kind: AuthorityKind, key: &str, caps: &[&str]) -> AuthorityDescriptor {
        AuthorityDescriptor {
            authority_id: id.into(),
            kind,
            key_id: key.into(),
            public_key: "pub".into(),
            fingerprint: key.into(),
            algorithm: "Ed25519".into(),
            status: AuthorityStatus::Active,
            valid_from: 1,
            valid_until: None,
            issuer_authority_id: None,
            issuer_key_id: None,
            serial: id.into(),
            version: 1,
            capabilities: caps.iter().map(|cap| cap.to_string()).collect(),
            certificate: None,
            created_at: 1,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    fn state(
        authorities: Vec<AuthorityDescriptor>,
        transitions: Vec<CenterAuthorityTransitionV1>,
        public_only: &[&str],
    ) -> DurableAuthorityState {
        DurableAuthorityState {
            schema: 1,
            trust_root_set: "actium-product-v1".into(),
            trust_epoch: 1,
            authorities,
            revocations: Vec::<Revocation>::new(),
            root_transitions: Vec::<RootTransition>::new(),
            center_authority_transitions: transitions,
            audit_events: Vec::new(),
            idempotency_results: BTreeMap::new(),
            public_only_key_ids: public_only.iter().map(|id| id.to_string()).collect(),
        }
    }

    fn issued_transition(id: &str, predecessor: &str, successor: &str) -> CenterAuthorityTransitionV1 {
        CenterAuthorityTransitionV1 {
            contract: "actium-center-authority-reissue@1.0.0".into(),
            transition_id: id.into(),
            trust_root_set: "actium-product-v1".into(),
            predecessor_authority_id: predecessor.into(),
            predecessor_key_id: "pred-key".into(),
            successor_authority_id: successor.into(),
            successor_key_id: "succ-key".into(),
            successor_certificate_version: 2,
            required_capabilities: vec![
                "authority:issue-enrollment".into(),
                "center_bundle_signing".into(),
                REMOTE_OPERATIONS_SIGNING_CAPABILITY.into(),
                "site_runtime_authority".into(),
            ],
            issued_at: 10,
            activation_epoch: 2,
            status: CenterAuthorityTransitionStatus::Issued,
            issuer_authority_id: "deployment-root".into(),
            issuer_key_id: "dr-key".into(),
            signatures: vec![CenterAuthorityTransitionSignatureV1 {
                authority_id: "deployment-root".into(),
                key_id: "dr-key".into(),
                algorithm: "Ed25519".into(),
                signature: "sig".into(),
            }],
            proof: json!({
                "publication": "EXPLICIT_TRUST_BUNDLE_PUBLICATION_REQUIRED",
                "predecessorPreserved": true,
                "productRootChanged": false,
            }),
            request_digest: "digest".into(),
        }
    }

    fn lab_authorities() -> Vec<AuthorityDescriptor> {
        vec![
            descriptor(
                "actium-product-root-v1",
                AuthorityKind::ProductTrustRoot,
                "root-key",
                &["authority:issue-deployment-authority"],
            ),
            descriptor(
                "center-authority",
                AuthorityKind::CenterAuthority,
                "pred-key",
                &[
                    "authority:issue-enrollment",
                    "center_bundle_signing",
                    "site_runtime_authority",
                ],
            ),
            descriptor(
                "center-authority-v2",
                AuthorityKind::CenterAuthority,
                "succ-key",
                &[
                    "authority:issue-enrollment",
                    "center_bundle_signing",
                    REMOTE_OPERATIONS_SIGNING_CAPABILITY,
                    "site_runtime_authority",
                ],
            ),
        ]
    }

    fn unsigned_bundle(
        center: AuthorityDescriptor,
        retained_predecessor: Option<AuthorityDescriptor>,
        trust_epoch: u64,
    ) -> SignedTrustBundle {
        SignedTrustBundle {
            bundle: TrustBundle {
                trust_bundle_id: format!("bundle-{trust_epoch}"),
                contract: "actium-trust-bundle@1.0.0".into(),
                version: 1,
                product_roots: Vec::new(),
                root_transitions: Vec::new(),
                deployment_authority: None,
                deployment_root: None,
                center_authority: Some(center),
                predecessor_center_authorities: retained_predecessor.into_iter().collect(),
                enrollment_authorities: Vec::new(),
                release_authorities: Vec::new(),
                product_signing_authorities: Vec::new(),
                revocations: Vec::new(),
                issued_at: 1,
                expires_at: None,
                trust_epoch,
                issuer: "actium-product-root-v1".into(),
            },
            signature: "signature".into(),
            signing_key_id: "root-key".into(),
            algorithm: "Ed25519".into(),
        }
    }

    #[test]
    fn successor_activation_accepts_a_prior_successor_of_the_same_transition() {
        let authorities = lab_authorities();
        let predecessor = authorities[1].clone();
        let successor = authorities[2].clone();
        let transition = issued_transition("transition-1", "center-authority", "center-authority-v2");
        let previous = unsigned_bundle(successor.clone(), Some(predecessor.clone()), 1);
        let candidate = unsigned_bundle(successor, Some(predecessor), 2);

        validate_successor_activation_lineage(&transition, &previous, &candidate).unwrap();
    }

    #[test]
    fn successor_activation_rejects_unrelated_live_authority() {
        let authorities = lab_authorities();
        let predecessor = authorities[1].clone();
        let successor = authorities[2].clone();
        let transition = issued_transition("transition-1", "center-authority", "center-authority-v2");
        let unrelated = descriptor(
            "other-center-authority",
            AuthorityKind::CenterAuthority,
            "other-key",
            &["center_bundle_signing"],
        );
        let previous = unsigned_bundle(unrelated, None, 1);
        let candidate = unsigned_bundle(successor, Some(predecessor), 2);

        assert_eq!(
            validate_successor_activation_lineage(&transition, &previous, &candidate).unwrap_err(),
            "AUTHORITY_SUCCESSOR_PREDECESSOR_NOT_SERVED"
        );
    }

    #[test]
    fn successor_activation_requires_a_strictly_new_target_epoch() {
        let authorities = lab_authorities();
        let predecessor = authorities[1].clone();
        let successor = authorities[2].clone();
        let transition = issued_transition("transition-1", "center-authority", "center-authority-v2");
        let previous = unsigned_bundle(successor.clone(), Some(predecessor.clone()), 2);
        let candidate = unsigned_bundle(successor, Some(predecessor), 2);

        assert_eq!(
            validate_successor_activation_lineage(&transition, &previous, &candidate).unwrap_err(),
            "TRUST_EPOCH_NOT_MONOTONIC"
        );
    }

    #[test]
    fn issued_successor_with_public_only_root_requires_owner_root_brief() {
        let state = state(
            lab_authorities(),
            vec![issued_transition(
                "209beb0d-6607-4e5b-9c5c-9a3a65117e9a",
                "center-authority",
                "center-authority-v2",
            )],
            &["root-key"],
        );
        let plan = resolve_authority_lifecycle_plan(
            &state,
            Some(ServedTrustBundleView {
                center_authority_id: "center-authority",
                trust_epoch: 1,
            }),
        )
        .unwrap();
        assert_eq!(plan.state, AuthorityLifecycleState::RootRequired);
        assert_eq!(plan.target_authority_id, "center-authority-v2");
        assert_eq!(
            plan.transition_id.as_deref(),
            Some("209beb0d-6607-4e5b-9c5c-9a3a65117e9a")
        );
        assert!(plan.owner_root_action_required);
        assert!(plan.predecessor_overlap_required);
        assert_eq!(
            resolve_root_brief_successor_authority_id(
                &state,
                Some(ServedTrustBundleView {
                    center_authority_id: "center-authority",
                    trust_epoch: 1,
                })
            )
            .unwrap(),
            "center-authority-v2"
        );
    }

    #[test]
    fn host_activation_receipt_digest_is_deterministic_and_excludes_itself() {
        let receipt = HostTrustActivationReceiptV1 {
            contract: HOST_TRUST_CONVERGENCE_CONTRACT.into(),
            phase: AuthorityLifecyclePhase::ServedReady,
            transition_id: "transition-1".into(),
            predecessor_authority_id: "authority-before".into(),
            successor_authority_id: "authority-after".into(),
            previous_digest: "sha256:before".into(),
            served_digest: "sha256:after".into(),
            previous_trust_epoch: 1,
            trust_epoch: 2,
            authority_generation: 3,
            activation_generation: 4,
            started_at: 10,
            completed_at: 11,
            result: "ACTIVATED".into(),
            lkg_path: "/var/lib/actium/authority/trust-bundle.lkg.json".into(),
            receipt_digest: String::new(),
            channel: "stable".into(),
        };
        let first = receipt.clone().with_receipt_digest().unwrap();
        let second = first.clone().with_receipt_digest().unwrap();
        assert_eq!(first.receipt_digest, second.receipt_digest);
        assert!(first.receipt_digest.starts_with("sha256:"));
        assert_eq!(first.receipt_digest.len(), 71);
    }

    #[test]
    fn does_not_hardcode_future_authority_slugs() {
        let mut authorities = lab_authorities();
        authorities[2].authority_id = "center-authority-lab-successor".into();
        let state = state(
            authorities,
            vec![issued_transition(
                "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "center-authority",
                "center-authority-lab-successor",
            )],
            &["root-key"],
        );
        let target = resolve_root_brief_successor_authority_id(
            &state,
            Some(ServedTrustBundleView {
                center_authority_id: "center-authority",
                trust_epoch: 1,
            }),
        )
        .unwrap();
        assert_eq!(target, "center-authority-lab-successor");
        assert_ne!(target, "center-authority-v3");
        assert_ne!(target, "center-authority-v4");
    }

    #[test]
    fn healthy_when_served_center_already_has_remote_ops_and_no_open_transition() {
        let authorities = vec![
            descriptor(
                "actium-product-root-v1",
                AuthorityKind::ProductTrustRoot,
                "root-key",
                &["authority:issue-deployment-authority"],
            ),
            descriptor(
                "center-authority",
                AuthorityKind::CenterAuthority,
                "pred-key",
                &[
                    "authority:issue-enrollment",
                    REMOTE_OPERATIONS_SIGNING_CAPABILITY,
                ],
            ),
        ];
        let state = state(authorities, Vec::new(), &["root-key"]);
        let plan = resolve_authority_lifecycle_plan(
            &state,
            Some(ServedTrustBundleView {
                center_authority_id: "center-authority",
                trust_epoch: 4,
            }),
        )
        .unwrap();
        assert_eq!(plan.state, AuthorityLifecycleState::Healthy);
        assert!(resolve_root_brief_successor_authority_id(&state, None).is_err());
    }

    #[test]
    fn prepared_transition_is_owner_approval_not_root_brief() {
        let mut transition = issued_transition("t1", "center-authority", "center-authority-v2");
        transition.status = CenterAuthorityTransitionStatus::Prepared;
        let state = state(lab_authorities(), vec![transition], &["root-key"]);
        let plan = resolve_authority_lifecycle_plan(&state, None).unwrap();
        assert_eq!(plan.state, AuthorityLifecycleState::OwnerApprovalRequired);
        assert_eq!(
            resolve_root_brief_successor_authority_id(&state, None).unwrap_err(),
            "AUTHORITY_LIFECYCLE_OWNER_APPROVAL_REQUIRED"
        );
    }

    #[test]
    fn zero_open_transitions_is_healthy_without_successor() {
        let plan = resolve_authority_lifecycle_plan(
            &state(lab_authorities(), Vec::new(), &["root-key"]),
            Some(ServedTrustBundleView {
                center_authority_id: "center-authority",
                trust_epoch: 1,
            }),
        )
        .unwrap();
        assert_eq!(plan.state, AuthorityLifecycleState::Blocked);
        assert!(plan.transition_id.is_none());
    }

    #[test]
    fn one_published_or_hosts_converging_transition_resolves() {
        for status in [
            CenterAuthorityTransitionStatus::Published,
            CenterAuthorityTransitionStatus::HostsConverging,
        ] {
            let mut transition = issued_transition("only-one", "center-authority", "center-authority-v2");
            transition.status = status;
            let plan = resolve_authority_lifecycle_plan(
                &state(lab_authorities(), vec![transition], &["root-key"]),
                Some(ServedTrustBundleView {
                    center_authority_id: "center-authority",
                    trust_epoch: 1,
                }),
            )
            .unwrap();
            assert_eq!(plan.transition_id.as_deref(), Some("only-one"));
        }
    }

    #[test]
    fn two_issued_transitions_fail_closed() {
        let state = state(
            lab_authorities(),
            vec![
                issued_transition("t-a", "center-authority", "center-authority-v2"),
                issued_transition("t-b", "center-authority", "center-authority-v2"),
            ],
            &["root-key"],
        );
        assert_eq!(
            resolve_authority_lifecycle_plan(&state, None).unwrap_err(),
            "AUTHORITY_LIFECYCLE_AMBIGUOUS_OPEN_TRANSITIONS"
        );
        assert_eq!(
            resolve_root_brief_successor_authority_id(&state, None).unwrap_err(),
            "AUTHORITY_LIFECYCLE_AMBIGUOUS_OPEN_TRANSITIONS"
        );
    }

    #[test]
    fn prepared_plus_issued_fail_closed() {
        let mut prepared = issued_transition("t-prep", "center-authority", "center-authority-v2");
        prepared.status = CenterAuthorityTransitionStatus::Prepared;
        let state = state(
            lab_authorities(),
            vec![
                prepared,
                issued_transition("t-iss", "center-authority", "center-authority-v2"),
            ],
            &["root-key"],
        );
        assert_eq!(
            resolve_authority_lifecycle_plan(&state, None).unwrap_err(),
            "AUTHORITY_LIFECYCLE_AMBIGUOUS_OPEN_TRANSITIONS"
        );
    }

    #[allow(dead_code)]
    fn _certificate_shape_not_required() -> Option<AuthorityCertificate> {
        None
    }
}
