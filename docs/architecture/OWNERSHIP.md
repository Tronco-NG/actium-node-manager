# Actium Node Manager — Ownership Freeze M2

This document freezes the product boundary after the M2 canonical switch.
The repository `Tronco-NG/actium-node-manager` is the only editable source of
the universal host lifecycle platform. Consumers integrate through versioned
neutral contracts and explicit adapters; they do not import this repository's
internal source layout.

## Actium Node Manager owns

- Node Manager UI and Tauri runtime/orchestration.
- Supervisor, Supervisor PoP, IPC and service lifecycle.
- Node Core, Host Identity, binding, epoch and recovery.
- The machine Host Enrollment protocol and its fail-closed state machine.
- Trust store, signed enrollment ACK verification and host trust transitions.
- Host-side signed discovery and infrastructure discovery.
- Host storage primitives and storage boundaries.
- Diagnostics, build identity and release/update runtime.
- Versioned platform contracts and Manager/Supervisor build tooling.

The enrollment invariant is:

```text
hen_* → challenge → Supervisor PoP → Center complete → pending_apply
→ EnrollmentPackage → Supervisor apply → signed ACK → Center confirm
→ enrolled/trusted → signed discovery
```

The Manager receives only `hen_*` from a human operator. It never receives an
Owner JWT and it never asks the operator to enter product, organization, site,
host, installation or epoch identifiers.

## Ecosistema Aegis owns

- `control-runtime` and `site-runtime`.
- People, Radio, Telemetry and Site Core.
- Aegis-specific capability logic and tactical/business behavior.
- Aegis Product/Site configuration and capability bundles.
- The legacy `PAYLOAD.json` as a frozen/generated compatibility artifact until
  a signed extension-bundle registry replaces it.

Aegis may provide capability manifests and consume Node Manager contracts, but
it cannot promote a Host to `enrolled` or `trusted` and it cannot edit the
Node Manager implementation.

## Shared contracts

Only versioned neutral contracts are shared. They carry explicit
`contract_name`, `contract_version` and compatibility policy. URLs, IDs,
tokens and authority material remain runtime state and are not embedded in a
universal build. Cross-repository integration tests may use explicitly
configured checkout paths, but production architecture must not depend on
neighboring repository layout or relative imports.

## Freeze rule

From M2 onward, new Node Manager functionality is implemented in
`Tronco-NG/actium-node-manager` only. Aegis changes must be adapters,
capability integrations, frozen/generated compatibility handling or
documentation of the consumer boundary. Any remaining legacy artifact must
declare its owner, replacement, deprecation condition and removal gate in
`docs/migration/COMPATIBILITY-BRIDGES.md`.
