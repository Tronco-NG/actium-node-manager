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
