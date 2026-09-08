# Actium Connectivity Fabric

## Ownership

Actium Node Manager owns the Host-side Connectivity Fabric and its
Supervisor-backed transport boundary. It resolves routes and reports health;
it does not grant authority, issue signatures, or replace the Control Plane.
Center owns route policy and canonical assignments. Aegis consumes the
versioned contract through its adapter.

## Contract

`actium-connectivity-service-resolution@1.0.0` is the neutral JSON/Rust
contract at `contracts/connectivity/v1/service-resolution.schema.json`.
Routes carry public metadata only: service/capability, endpoint, expected
identity, transport, authority scope, binding epoch, configuration version and
observed state. Credentials and private key material are out of contract.

Selection is deterministic: reachable before configured, then local, private,
remote, then priority. A reachable endpoint is not capability readiness and
does not authorize a request.

## Local vertical slice

The Manager reads the canonical persisted Host Control Plane configuration,
exposes a read-only Connectivity page, probes the configured Control Plane,
and requests `/service-resolution` from the configured Center gateway. Center
returns its own HTTPS origin and the bootstrap route for
`host_enrollment`; the existing machine flow remains:

`hen_* → challenge → PoP → complete → pending_apply → package → apply → ACK → confirm`

Center's existing `host-enrollment-readiness` handler continues to resolve
Authority Service and distinguish reachability from Authority readiness.

## Boundaries and future transports

The current local route uses the existing HTTPS gateway and Supervisor IPC
boundary. Direct LAN, private outbound and relay transports remain contract
variants, not implicit fallbacks. A route change cannot change authority or
permit a write against a different deployment. Future outbound/mTLS adapters
must verify the Actium trust chain, scope, epoch, replay and revocation before
the consumer executes an operation.
