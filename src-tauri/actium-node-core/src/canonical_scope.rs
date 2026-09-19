//! Canonical connectivity scope. Callers never self-assert tenant membership.
//!
//! Scope is derived from authenticated enrollment/binding evidence plus
//! policy generation. Missing, ambiguous, or mismatched identifiers fail closed.

use crate::HostBindingProjection;
use serde::{Deserialize, Serialize};

pub const CANONICAL_SCOPE_CONTRACT: &str = "actium.connectivity.canonical-scope.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalConnectivityScopeV1 {
    pub contract: String,
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub binding_epoch: u64,
    pub policy_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedConnectivityScope {
    pub client_id: String,
    pub organization_id: String,
    pub site_id: String,
    pub host_id: String,
    pub binding_epoch: Option<u64>,
    pub policy_generation: Option<u64>,
}

fn required_id(value: Option<&str>, code: &str) -> Result<String, String> {
    let trimmed = value.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Err(code.to_string());
    }
    Ok(trimmed.to_string())
}

impl CanonicalConnectivityScopeV1 {
    pub fn from_binding(
        binding: &HostBindingProjection,
        policy_generation: u64,
    ) -> Result<Self, String> {
        if !binding.verified {
            return Err("SCOPE_UNRESOLVED".to_string());
        }
        let client_id = required_id(binding.client_id.as_deref(), "SCOPE_UNRESOLVED")?;
        let organization_id = required_id(Some(&binding.organization_id), "SCOPE_UNRESOLVED")?;
        let site_id = required_id(binding.site_id.as_deref(), "SCOPE_UNRESOLVED")?;
        let host_id = required_id(binding.host_id.as_deref(), "SCOPE_UNRESOLVED")?;
        Ok(Self {
            contract: CANONICAL_SCOPE_CONTRACT.to_string(),
            client_id,
            organization_id,
            site_id,
            host_id,
            binding_epoch: binding.binding_epoch,
            policy_generation,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.contract != CANONICAL_SCOPE_CONTRACT {
            return Err("SCOPE_UNRESOLVED".to_string());
        }
        required_id(Some(&self.client_id), "SCOPE_UNRESOLVED")?;
        required_id(Some(&self.organization_id), "SCOPE_UNRESOLVED")?;
        required_id(Some(&self.site_id), "SCOPE_UNRESOLVED")?;
        required_id(Some(&self.host_id), "SCOPE_UNRESOLVED")?;
        Ok(())
    }

    pub fn matches_request(&self, requested: &RequestedConnectivityScope) -> Result<(), String> {
        self.validate()?;
        if requested.client_id.trim() != self.client_id
            || requested.organization_id.trim() != self.organization_id
            || requested.site_id.trim() != self.site_id
            || requested.host_id.trim() != self.host_id
        {
            return Err("SCOPE_MISMATCH".to_string());
        }
        if requested
            .binding_epoch
            .is_some_and(|epoch| epoch != self.binding_epoch)
        {
            return Err("BINDING_EPOCH_MISMATCH".to_string());
        }
        if requested
            .policy_generation
            .is_some_and(|generation| generation != self.policy_generation)
        {
            return Err("CONFIGURATION_STALE".to_string());
        }
        Ok(())
    }

    pub fn isolates(&self, other: &Self) -> Result<(), String> {
        self.validate()?;
        other.validate()?;
        if self.client_id != other.client_id
            || self.organization_id != other.organization_id
            || self.site_id != other.site_id
            || self.host_id != other.host_id
        {
            return Err("SCOPE_MISMATCH".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> HostBindingProjection {
        HostBindingProjection {
            source: "enrollment_signed".into(),
            verified: true,
            client_id: Some("client-a".into()),
            organization_id: "org-a".into(),
            site_id: Some("site-a".into()),
            host_id: Some("host-a".into()),
            host_installation_id: "install-a".into(),
            deployment_id: Some("deploy-a".into()),
            binding_epoch: 7,
            center_key_id: "kid".into(),
            center_public_key_fingerprint: "sha256:abc".into(),
        }
    }

    #[test]
    fn enrollment_binding_is_the_only_scope_source() {
        let scope = CanonicalConnectivityScopeV1::from_binding(&binding(), 3).unwrap();
        assert_eq!(scope.organization_id, "org-a");
        assert_eq!(scope.client_id, "client-a");
        assert_eq!(scope.site_id, "site-a");
        assert_eq!(scope.host_id, "host-a");
        assert_eq!(scope.binding_epoch, 7);
        assert_eq!(scope.policy_generation, 3);
    }

    #[test]
    fn unverified_or_incomplete_binding_fails_closed() {
        let mut missing_site = binding();
        missing_site.site_id = None;
        assert_eq!(
            CanonicalConnectivityScopeV1::from_binding(&missing_site, 1).unwrap_err(),
            "SCOPE_UNRESOLVED"
        );
        let mut unverified = binding();
        unverified.verified = false;
        assert_eq!(
            CanonicalConnectivityScopeV1::from_binding(&unverified, 1).unwrap_err(),
            "SCOPE_UNRESOLVED"
        );
    }

    #[test]
    fn caller_cannot_self_assert_client_or_cross_tenant() {
        let scope = CanonicalConnectivityScopeV1::from_binding(&binding(), 3).unwrap();
        let mut requested = RequestedConnectivityScope {
            organization_id: "org-a".into(),
            client_id: "client-b".into(),
            site_id: "site-a".into(),
            host_id: "host-a".into(),
            binding_epoch: Some(7),
            policy_generation: Some(3),
        };
        assert_eq!(scope.matches_request(&requested).unwrap_err(), "SCOPE_MISMATCH");
        requested.client_id = "client-a".into();
        requested.organization_id = "org-b".into();
        assert_eq!(scope.matches_request(&requested).unwrap_err(), "SCOPE_MISMATCH");
        requested.organization_id = "org-a".into();
        requested.site_id = "site-b".into();
        assert_eq!(scope.matches_request(&requested).unwrap_err(), "SCOPE_MISMATCH");
        requested.site_id = "site-a".into();
        requested.host_id = "host-b".into();
        assert_eq!(scope.matches_request(&requested).unwrap_err(), "SCOPE_MISMATCH");
    }

    #[test]
    fn missing_client_fails_closed_without_global_fallback() {
        let mut unbound = binding();
        unbound.client_id = None;
        assert_eq!(
            CanonicalConnectivityScopeV1::from_binding(&unbound, 1).unwrap_err(),
            "SCOPE_UNRESOLVED"
        );
    }
}
