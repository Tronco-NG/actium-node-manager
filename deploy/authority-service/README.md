# Lab deployment

This unit intentionally binds the Authority Service to loopback only. It is
useful for verifying the process contract and bootstrap-pending readiness on
the lab host; it is not a remote Center endpoint and does not create authority
material.

In durable mode the unit expects the Owner ceremony to have provisioned
`/etc/actium/authority/sealing.key`, subordinate sealed keys under
`/var/lib/actium/authority/keys`, public `authority-state.json` and a
root-signed `trust-bundle.json`. The Product Root must not be present in the
online key directory. The service only serves that pre-signed bundle and uses
subordinate keys for capability-scoped signatures.

A remote binding requires a separately operated TLS terminator and service
credential. Do not set `ACTIUM_AUTHORITY_TEST_FIXTURE=1` on the lab service.
The Owner ceremony must later provision the sealed provider and verified Trust
Bundle through the approved custody procedure.
