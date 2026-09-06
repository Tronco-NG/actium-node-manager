# Gate M2 — Canonical switch

Fecha de cierre local: 2026-09-06.

## Commits de la transición

| Repo | Commit M2 | Resultado |
|---|---|---|
| `Tronco-NG/actium-node-manager` | `fe17d23` | ownership, base runtime y contratos versionados |
| `Tronco-NG/ecosistema-aegis` | `36f3ece` | eliminación del source legacy y adapters Aegis |
| `Tronco-NG/actium-center` | `9a15d25` | registro mínimo del producto |

No se hizo push. Los worktrees de Aegis y Center mantienen su WIP no
relacionado fuera de estos commits.

## Ownership resultante

`actium-node-manager` es la única fuente editable de Manager, Tauri,
Supervisor, Node Core, Host Identity, lifecycle, enrollment machine protocol,
Supervisor PoP, signed ACK, trust, signed discovery, storage host primitives,
diagnostics y tooling de release. Aegis conserva `control-runtime`,
`site-runtime`, People, Radio, Telemetry, Site Core, capabilities y behavior
de negocio.

El source trackeado de `infrastructure/data-plane/installer/**` fue retirado
de Aegis. Se mantuvieron sin limpiar los artefactos generados y el WIP local
no trackeado para no descartar material del worktree; no son parte del índice,
del workflow ni de la fuente canónica. El WIP relevante quedó además
respaldado en `C:\Users\Tronco\AppData\Local\Temp\actium-node-manager-m2-legacy-backup-20260906`.

## Frontera contractual

El catálogo del target publica:

- `actium-control-plane-config@1.0.0`;
- `actium-node-manager-host@1.0.0` para el base runtime universal;
- `actium-host-enrollment-ceremony@1.0.0`;
- `actium-product-extension-bundle@1.0.0`.

Agent y Connector consumen `@actium/aegis-actium-node-manager-adapter` y no
importan código del target ni dependen del layout de checkouts hermanos. El
E2E de storage admite rutas externas sólo mediante `ACTIUM_NODE_MANAGER_ROOT`
y `ACTIUM_CENTER_ROOT`, como tooling local explícito.

## Enrollment invariant

La única secuencia reconocida sigue siendo:

```text
hen_* → challenge → Supervisor PoP → Center complete → pending_apply
→ EnrollmentPackage → Supervisor apply → signed ACK → Center confirm
→ enrolled/trusted → signed discovery
```

No se añadió UUID manual, Owner JWT en Manager, autoridad embebida ni segunda
FSM de enrollment. El ACK exige `enrollmentNonce`.

## Validación M2

- Frontend: `npm run build` PASS.
- Contracts M2: 5 PASS.
- Host Enrollment 1.6.2: 4 PASS.
- Node Core: 202 PASS.
- Manager Rust: 51 PASS.
- Supervisor: 3 PASS.
- Aegis Agent: 56 PASS.
- Aegis Connector: 9 PASS.
- Aegis People: 20 PASS.
- Center product contract: 1 PASS.
- Build canónico: `npm run compile -- --os windows --no-terminal` PASS; no
  ejecutó `prepare:payload` y omitió el bundle Tauri por falta deliberada del
  payload externo.
- Identidad Supervisor generada desde este repo: `0.5.21`,
  `source_commit=092d936d2615cb113cb819257d7413d63cfabbfe`,
  `build_id=m2-canonical-20260906-092d936`,
  `binary_sha256=9141CDDE50D2454243D31FD99103C5CB5725A7021CA86C2073E747C6D9193596`.
- `git diff --check`: PASS en cambios versionados.
- La migración Center sólo fue creada y validada localmente; no fue aplicada
  remotamente durante M2.

## Payload y autoridad

El target no contiene `resources/node/**` ni `PAYLOAD.json`. El artefacto
legacy permanece en Aegis, sin regeneración ni copia al target; su SHA local
antes/después es `147A6EE7E9377BA9C8F209D86075A899D6E2E539A46F52001A0228214DFEC42`.
El SHA productivo de referencia continúa siendo
`BF43DE8AB7BE74026A33A30F6BE6E496034EEB9E6A9E791A0CA8F3856ACCE420`.

No se ejecutó `prepare:payload`, no hubo enrollment real, deploy NAS ni
generación/rotación de material criptográfico.

## Bridges pendientes

- Payload/capabilities Aegis: congelado hasta que exista packaging externo
  firmado y registry de bundles.
- Agent/Connector: permanecen Aegis-owned y consumen el adapter versionado.
- Center: mantiene la autoridad server-side; la migración de producto quedó
  local y pendiente de la política de aplicación de migraciones.
- Obsidian/Graphify: M3; no se movieron notas ni se alteró el grafo en M2.

M2 queda listo para revisión de cierre y M3; M4 aún requiere regresión
cross-repo/remota y aceptación explícita antes de cualquier operación NAS.
