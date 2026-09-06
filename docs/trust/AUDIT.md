# Trust Fabric audit

Sensitive Trust Fabric operations emit metadata-only audit events:

| Action | Required metadata |
| --- | --- |
| `AUTHORITY_CREATED` | authority id, key id, timestamp, result |
| `AUTHORITY_ROTATED` | authority/key involved, transition reason, timestamp, result |
| `AUTHORITY_REVOKED` | authority id, key id, reason, timestamp, result |
| `TRUST_BUNDLE_ISSUED` | issuer, signing key, bundle digest, timestamp, result |
| `SIGN_OPERATION` | authority, key, capability/context, payload digest, timestamp, result |
| `SELF_TEST` | authority, key, capability, timestamp, result |

Audit records never contain private keys, PEM material, bearer tokens or the
full sensitive payload. The local `AuthorityService` keeps the same event
shape for ceremony tests; Center persists the public metadata and audit rows
in `actium_authority_audit`, while private material remains in the Authority
Service/KeyProvider boundary.
