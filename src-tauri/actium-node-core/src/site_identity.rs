//! Stable Site network identity.
//!
//! Display names, slugs, organizationId and deploymentId are not Site
//! network identity.  The canonical V1 identity is the Site UUID encoded as
//! a DNS-safe label under `sites.actiumsecurity.com`.

use serde::{Deserialize, Serialize};

pub const SITE_IDENTITY_DNS_ZONE: &str = "sites.actiumsecurity.com";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SiteNetworkIdentityV1 {
    pub site_id: String,
    pub dns_label: String,
    pub dns_name: String,
}

pub fn dns_safe_site_label(site_id: &str) -> Result<String, String> {
    let trimmed = site_id.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err("SITE_IDENTITY_INVALID".into());
    }
    if trimmed == "host-shared"
        || trimmed.contains("deployment")
        || trimmed.contains("organization")
    {
        return Err("SITE_IDENTITY_NOT_STABLE".into());
    }
    let compact: String = trimmed.chars().filter(|ch| *ch != '-').collect();
    if compact.is_empty()
        || !compact
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() || ch.is_ascii_lowercase() && ch.is_ascii_alphanumeric())
    {
        if !compact.chars().all(|ch| ch.is_ascii_alphanumeric()) {
            return Err("SITE_IDENTITY_NOT_DNS_SAFE".into());
        }
    }
    if compact.len() > 63 {
        return Err("SITE_IDENTITY_LABEL_TOO_LONG".into());
    }
    Ok(compact)
}

pub fn site_network_identity(site_id: &str) -> Result<SiteNetworkIdentityV1, String> {
    let dns_label = dns_safe_site_label(site_id)?;
    Ok(SiteNetworkIdentityV1 {
        site_id: site_id.trim().to_ascii_lowercase(),
        dns_name: format!("{dns_label}.{SITE_IDENTITY_DNS_ZONE}"),
        dns_label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lab_site_uuid_as_dns_label() {
        let identity = site_network_identity("00ed1921-098e-4efd-b71d-fbc220278486").unwrap();
        assert_eq!(identity.dns_label, "00ed1921098e4efdb71dfbc220278486");
        assert_eq!(
            identity.dns_name,
            "00ed1921098e4efdb71dfbc220278486.sites.actiumsecurity.com"
        );
    }

    #[test]
    fn rejects_deployment_and_host_shared_aliases() {
        assert_eq!(
            site_network_identity("host-shared").unwrap_err(),
            "SITE_IDENTITY_NOT_STABLE"
        );
        assert_eq!(
            site_network_identity("deployment-abc").unwrap_err(),
            "SITE_IDENTITY_NOT_STABLE"
        );
    }
}
