# Extension lifecycle

The registry states are `DISCOVERED`, `STAGED`, `VERIFIED`, `INSTALLED`,
`ACTIVE`, `DEGRADED`, `DISABLED`, `FAILED`, `ROLLED_BACK` and `REVOKED`.

An import is accepted only after parsing, schema and compatibility validation,
signature verification, artifact digest verification, dependency preflight and
health preflight. Files are copied to a unique staging directory and renamed
atomically into the installed version. Registry and active marker writes are
atomic. The previous known-good version is retained under `rollback/` when it
is replaced.

Health failure never leaves the new version active. Disable/enable,
rollback and remove are explicit Supervisor-authorized actions. A future
Center update must submit its bundle to this same engine and receive a signed
host ACK; it must not create a second installation path.
