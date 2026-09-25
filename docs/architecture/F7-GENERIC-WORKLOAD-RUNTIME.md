# F7 Generic Workload Runtime

Status: SOURCE_PREPARED. Native Actium capabilities (site-core, telemetry, connectivity, …) stay on the closed capability surface. F7 adds a parallel generic OCI substrate.

## Boundary

```text
Center  → DesiredWorkloadStateV1
Node Manager / Supervisor → converge profile + deployment
OCI runtime → containers / compose application
```

F7 does not install a named third-party product. An adapter in F8 may emit a `WorkloadProfileV1` that this runtime executes without knowing the product name.

Native capabilities remain `KNOWN_PROFILES` in `src/capability-surface.ts`. Generic workloads do not join that list.

## Implemented runtime kinds

- `OCI_CONTAINER`
- `OCI_COMPOSE`

Reserved, not implemented: `VM`.

## Artifacts

| Contract | Role |
|---|---|
| `actium-workload-profile@1.0.0` | Immutable what-can-be-deployed |
| `actium-workload-deployment@1.0.0` | Instance on a host, bound to client/org/assignment/site/host |
| `actium-desired-workload-state@1.0.0` | Center desired state |
| `actium-workload-deployment-receipt@1.0.0` | Observed convergence |

Profile vs deployment: one profile, many deployments. `OWNERSHIP != ALLOCATION != DEPLOYMENT`.

Secrets: profiles declare `secretRequirements`; deployments carry `secretRefs`. Inline secret values are invalid.

Volumes: `PersistentVolumeClaimV1` (purpose/size/class). Node Manager materializes local disk, NAS, ZFS, or cloud later.

Networks: `ISOLATED | SITE_INTERNAL | PRODUCT_INTERNAL | PUBLIC_HTTPS`. No arbitrary compose networks.

Health: overall READY only when every component is READY. `compose up` exit 0 is not sufficient.

Upgrade/rollback: declared on the profile. Runtime rollback is separate from database rollback.

## Convergence

```text
DESIRED → PLAN → PREPARE → INSTALL → START → HEALTH → READY
```

Failure path: `ROLLBACK` to previous profile/generation/snapshot as declared.

## Example tree (commercial, not encoded in F7)

Client → Organization → Product assignment → Site → Host → Workload deployment (profile + modules). Expanding modules later does not create a new Actium product.

## F8

A product adapter maps Actium Logistics modules onto generic `WorkloadModuleV1` ids. License (AGPL vs commercial) is an F8/F9 commercial gate, not an F7 runtime concern.
