# Actium Connectivity Fabric

`actium-connectivity-service-resolution@1.0.0` is public discovery metadata,
not an authority decision. The resolver keeps all candidates for diagnostics,
but only a `reachable` candidate with a complete identity/scope binding may
be preferred. Selection order among eligible candidates is `local`, `private`,
then `remote`, followed by priority.

The execution boundary is
`actium-connectivity-authenticated-session@1.0.0`. A transport adapter must
verify the peer through TLS/mTLS, signed bootstrap, or the existing Supervisor
proof and then present an exact service, capability, identity, scope,
transport, request ID and non-regressing binding epoch. Supervisor IPC is a
local control channel and is never evidence that Center is authenticated.

Before Host Enrollment, the only bootstrap operation is the existing
ticket/PoP ceremony. The Manager resolves the configured Center route, sends
the explicit bootstrap context, and the Center validates that context before
the existing `hen_*` state machine validates the ticket and proof. No new
authority, Owner JWT or public relay is introduced.
