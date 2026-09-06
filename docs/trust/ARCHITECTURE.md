# Actium Trust Fabric v1

The Trust Fabric is the single cryptographic boundary for enrollment,
deployment state, extension bundles, releases and revocation. Version 1 uses
Ed25519 and the canonical JSON serializer already used by Node Core, with a
domain prefix (`actium-*-v1`) on every signed payload.

The product root is an offline/sealed trust anchor. The operational chain is:

```text
Product Trust Root
  -> Deployment Authority
     -> Deployment Root
     -> Center Authority
        -> Enrollment Authority -> Host Identity
  -> Release Authority
     -> Product Signing Authority
```

Deployment/enrollment authority cannot sign software, and product signing
authority cannot enroll hosts. Each signed descriptor carries key identity,
fingerprint, validity, status, issuer and capability metadata. Private keys
are outside the Node Manager UI, Supervisor trust store and PostgreSQL.

`AuthorityService<P>` is the local/test service boundary. `P` is a
`KeyProvider`; the current backends are `TestEphemeralKeyProvider` and the
AES-256-GCM sealed `SoftwareSealedKeyProvider`. PKCS#11/HSM/TPM can replace
the provider without changing protocol code.

An absent Supervisor trust bundle is `UNINITIALIZED` and is valid during
first-trust bootstrap. First trust still requires the separately provisioned
public Product Trust bootstrap set; a bundle cannot introduce a new root by
self-signing. A present bundle is verified before installation and cannot roll
back its trust epoch.
