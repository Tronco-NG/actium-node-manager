# Lab deployment

This unit intentionally binds the uninitialized Authority Service to loopback
only. It is useful for verifying the process contract and bootstrap-pending
readiness on the lab host; it is not a remote Center endpoint and does not
create production authority material.

A remote binding requires a separately operated TLS terminator and service
credential. Do not set `ACTIUM_AUTHORITY_TEST_FIXTURE=1` on the lab service.
The Owner ceremony must later provision the sealed provider and verified Trust
Bundle through the approved custody procedure.
