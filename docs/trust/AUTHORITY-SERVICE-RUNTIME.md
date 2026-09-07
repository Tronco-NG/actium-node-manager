# Authority Service runtime boundary

`actium-authority-service` is the only HTTP boundary for Trust Fabric signing
operations. It is part of the Actium Node Manager repository, but it is a
separate service process from Manager and Supervisor.

The default process state is `UNINITIALIZED`. Startup never generates keys,
creates a hierarchy, or promotes a fixture. Until the Owner ceremony supplies
an approved provider/state, readiness returns `AUTHORITY_BOOTSTRAP_PENDING` and
sign, verify and Trust Bundle operations fail closed.

The service accepts the versioned contract
`actium-authority-service@1.0.0` and returns only public descriptors, key IDs,
fingerprints, signatures and safe status codes. A loopback listener is the
default. Non-loopback binding requires an explicitly configured service
credential and an external TLS terminator; an unauthenticated remote HTTP
listener is rejected.

`ACTIUM_AUTHORITY_TEST_FIXTURE=1` exists only for local contract tests and is
forbidden when `ACTIUM_ENVIRONMENT=production`. It is not a bootstrap path and
does not persist authority material.

The core `SoftwareSealedKeyProvider` remains the replaceable durable backend.
Its sealing key is supplied by the service boundary (OS credential, HSM, TPM or
equivalent) and is never stored in Center, PostgreSQL, Manager UI or logs.
Persistence of the authority hierarchy itself remains part of the explicit
Owner bootstrap ceremony; no implicit migration is performed by this service.

## M6.1D durable mode

When `authority-state.json` exists, the daemon loads `DurableAuthorityState`
through `SoftwareSealedKeyProvider` and cross-checks every public descriptor
against its opaque sealed-key reference before serving operations. A
`publicOnlyKeyIds` entry is allowed only for the Product Trust Root and is
required to be absent from the online provider. The durable daemon never
creates a root or signs a Trust Bundle with it: it serves the pre-signed public
bundle configured by `ACTIUM_AUTHORITY_TRUST_BUNDLE_FILE`. State and
idempotency responses are committed with a temporary file, `fsync` and atomic
rename; a stale temporary file is recoverable on the next write.

The sealing-key file is an explicitly provisioned two-line file:
`ACTIUM-SEALING-KEY-V1` followed by a base64url encoding of 32 bytes. On Unix
it must belong to the service UID and have no group/world permissions. This is
an unlock reference, not a Product Root private key, and it is never returned
by the HTTP contract. Key filenames are portable on Windows while legacy
colon-named files remain readable during migration.

Machine requests must bind `operation`, `caller`, request ID and
idempotency key to their headers and configured service identity. `health`
means process alive only; `readiness` is the capability-scoped sign→verify
self-test. A durable state is loaded but never created automatically: the
offline Owner root ceremony remains a separate, irreversible transition.

The explicit `actium-authority-ceremony` binary prepares that transition only
when invoked with separate offline/online sealing stores and the confirmation
`OFFLINE_ROOT_OWNER_APPROVED`. It writes public state and a root-signed Trust
Bundle, then re-wraps subordinate keys into a staging directory and atomically
renames that directory into the online key location. It refuses existing
outputs and never copies the Product Root key into the online location. The
binary is an operator ceremony tool, not a service startup hook.
