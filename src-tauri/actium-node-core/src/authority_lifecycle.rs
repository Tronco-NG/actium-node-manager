//! Authority lifecycle plan derived from durable Authority Service state.
//!
//! Replaces migration-specific hardcoding (`center-authority-v2`, specific
//! transition UUIDs) with discovery from `DurableAuthorityState` plus the
//! currently served Trust Bundle.  This is not a generic PKI framework.

use crate::trust_fabric::{
    AuthorityDescriptor, AuthorityKind, AuthorityStatus, CenterAuthorityTransitionStatus,
    CenterAuthorityTransitionV1, DurableAuthorityState, REMOTE_OPERATIONS_SIGNING_CAPABILITY,
};
use serde::{Deserialize, Serialize};

pub const AUTHORITY_LIFECYCLE_CONTRACT: &str = "actium.authority.lifecycle.plan.v1";
pub const AUTHORITY_LIFECYCLE_CUSTODY_OFFLINE_PRODUCT_ROOT: &str = "offline_product_root_public_only";
pub const AUTHORITY_LIFECYCLE_CUSTODY_ONLINE_SUBORDINATE: &str = "online_subordinate";

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

    let transition = latest_open_transition(state)?;
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

fn latest_open_transition(
    state: &DurableAuthorityState,
) -> Result<Option<&CenterAuthorityTransitionV1>, String> {
    let mut open: Vec<&CenterAuthorityTransitionV1> = state
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
    if open.is_empty() {
        return Ok(None);
    }
    open.sort_by_key(|transition| transition.issued_at);
    Ok(open.pop())
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
        Revocation, RootTransition,
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

    #[allow(dead_code)]
    fn _certificate_shape_not_required() -> Option<AuthorityCertificate> {
        None
    }
}
