# Authority hierarchy

`authority_id` identifies the authority record; `key_id` and its SHA-256
fingerprint identify the Ed25519 public key. A subordinate certificate is
signed by its issuer and is checked recursively before it is trusted.

The Product Trust Root issues Deployment Authority and Release Authority. The
Deployment Authority issues Deployment Root. A Deployment Root issues Center
Authority. Center Authority issues Enrollment Authority. Release Authority
issues Product Signing Authority. Host Identity is generated locally by the
Supervisor and never exports its private key.

The `Deployment Root` is a cryptographic boundary and is intentionally not
derived from or equated to `client_id`.
