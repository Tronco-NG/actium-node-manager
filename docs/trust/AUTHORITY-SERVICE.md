# Authority Service boundary

`AuthorityService` is the only signing boundary used by production
orchestration. It owns provider access, capability checks, chain validation,
revocation, rotation and the public Trust Bundle. Node Manager and Center
receive key IDs, fingerprints, signatures and public descriptors only.

The cross-product contract is `actium-authority-service@1.0.0`:

```text
readiness(capability)
sign(capability, canonical payload)
verify(capability, canonical payload, signature, key_id)
trust_bundle()
```

The Center machine gateway uses `ACTIUM_AUTHORITY_SERVICE_URL` only as a
non-secret service location. A missing, malformed, non-TLS (except loopback
test), unreachable or invalid service response fails closed with
`HOST_ENROLLMENT_AUTHORITY_UNAVAILABLE`. The legacy
`ACTIUM_HOST_ENROLLMENT_*` PEM path is explicit compatibility code and is not
selected by the machine ceremony.

The service must be deployed behind an authenticated service channel (mTLS or
an equivalent host/service identity policy). This repository does not create
or provision production authority material in M4.
