# Actium Node Manager — Migration Manifest M1

Status: `M1 / PASS — core extraction complete; M2 READY condicionado al canonical switch`

Fecha de corte: `2026-09-06` · entorno: `personal-legion5pro`

Este manifiesto describe la extracción segura desde el working tree actual. El histórico fue importado en un checkout aislado y el overlay WIP se aplicó sólo al candidato nuevo. No se borró código de los repositorios fuente. M1 no ejecutó `prepare:payload`, no regeneró `PAYLOAD.json`, no generó material criptográfico, no ejecutó enrollment real y no modificó los repositorios fuente.

## Evidencia de baseline

| Fuente | Branch | HEAD | Estado observado |
|---|---|---|---|
| `ecosistema-aegis-control-local-backend` | `refactor/aegis-control-local-backend` | `a71d58bdb4b8bbe4893498668cb38b3a30f38ebc` | 51 entradas WIP: 29 modificadas, 22 no trackeadas |
| `actium-center-control-local-backend` | `refactor/aegis-control-local-backend` | `1126a34bfd660d0bb3f138a0c5e15386ecdbe3c1` | 10 entradas WIP: 7 modificadas, 3 no trackeadas |
| `actium-node-manager` local | `refactor/extract-from-aegis-m1` | `8fbb7228a2106681b5c8b9842b4aaa91abe151e0` | checkout history-preserving; extracción y overlay M1 comprometidos |
| `Tronco-NG/actium-node-manager` remoto | sin refs visibles | sin HEAD | repositorio remoto accesible pero vacío; no se hizo push |

Remotes auditados: Aegis `origin=https://github.com/Tronco-NG/ecosistema-aegis.git`, Center `origin=https://github.com/Tronco-NG/actium-center.git`, target `origin=https://github.com/Tronco-NG/actium-node-manager.git`. El target recibió el histórico mediante el espejo local; no se hizo fetch desde GitHub, reset ni push.

## Identidad y payload

- Manager observado: `0.7.0-rc.3`.
- Supervisor observado: `0.5.21`.
- Última identidad Manager desplegada desde el worktree Aegis: `source_commit=a71d58bdb4b8bbe4893498668cb38b3a30f38ebc`, `build_id=gate-1.6.2-control-endpoint-csp-20260906-rc3`.
- Identidad Supervisor observada en NAS: `source_commit=a71d58bdb4b8bbe4893498668cb38b3a30f38ebc`, `build_id=gate-1.6.2-20260905-rc3`.
- Payload productivo NAS verificado: SHA-256 `BF43DE8AB7BE74026A33A30F6BE6E496034EEB9E6A9E791A0CA8F3856ACCE420`.
- Payload fuente local ignorado por Git: SHA-256 `147A6EE7E9377BA9C8F209D86075A899D6E2E539A46F52001A0228214DFEC42A`; contiene `sourceDirty=true` y no debe promoverse automáticamente.
- `installer/src-tauri/resources/node/` está ignorado y se genera/sincroniza; no es una segunda fuente editable.

## Grafo observado

```text
Actium Center
  ├─ Host UI / release registry / bootstrap
  └─ actium-host-enrollment + actium-data-plane-gateway
       │  contrato HTTP, challenge, complete, confirm, ACK
       ▼
Ecosistema Aegis: Node Manager Tauri
  ├─ src/main.ts
  ├─ Tauri commands / persistent Host Control Plane config
  └─ Node Core IPC
       ▼
Actium Node Supervisor
  ├─ privileged lifecycle, host identity, storage/discovery
  ├─ Supervisor PoP y signed ACK
  └─ durable journal / trust / update gates
       ▼
Runtime payload y capability services
  ├─ platform/runtime primitives
  └─ capacidades Aegis: site-core, telemetry, people, radio, control-runtime
```

Dependencias actuales que deben desaparecer en M2: `installer` leyendo `../services/*` del monorepo, `sync-node-resources.ps1` copiando fuentes Aegis dentro de `resources/node`, y el workflow Aegis construyendo simultáneamente plataforma y capacidades sin un adapter explícito.

## Clasificación de ownership

`MOVE` indica owner canónico esperado en Node Manager. `STAY` permanece en el producto propietario. `SHARED` sólo para contratos versionados. `ADAPTER` requiere una frontera explícita durante M1/M2. `DEPRECATED` es una copia o mecanismo que no debe continuar como fuente editable.

| Clasificación | Path actual | Owner actual | Owner deseado | Dependientes / runtime | Riesgo y estrategia |
|---|---|---|---|---|---|
| MOVE | `ecosistema-aegis::infrastructure/data-plane/installer/src/main.ts` y `src/styles.css` | Aegis monorepo | Node Manager UI | Tauri WebView, Supervisor IPC, Center gateway | Extraer conservando rutas, UX hen-only y diagnóstico; mantener redirects/compatibilidad hasta M2. |
| MOVE | `ecosistema-aegis::infrastructure/data-plane/installer/src-tauri/src/{lib.rs,paths.rs,product.rs,control_plane.rs}` | Aegis monorepo | Node Manager native orchestrator | Tauri commands, filesystem Host, Control Plane config | Es frontera privilegiada; extraer con tests de path, provenance y fail-closed. |
| MOVE | `ecosistema-aegis::infrastructure/data-plane/installer/src-tauri/actium-node-core/**` | Aegis monorepo | Node Manager `crates/node-core` | IPC, identity, storage, discovery, trust, journal, lifecycle | 151 commits de installer y WIP reciente; importar historial antes de normalizar estructura. |
| MOVE | `ecosistema-aegis::infrastructure/data-plane/installer/src-tauri/actium-node-supervisor/**` | Aegis monorepo | Node Manager `crates/node-supervisor` | systemd/Windows service, PoP, apply, ACK | Preservar `0.5.21`, `enrollmentNonce`, host binding y dos canales. |
| MOVE | `ecosistema-aegis::infrastructure/data-plane/installer/src-tauri/supervisor/**` | Aegis monorepo | Node Manager release templates | instalación y service units | Son templates de producto; copiar sólo tras provenance y separar outputs generados. |
| MOVE | `ecosistema-aegis::infrastructure/data-plane/installer/scripts/{build-master.mjs,build-supervisor-*,verify-*,*contract.test.mjs}` | Aegis monorepo | Node Manager release/test tooling | builds, gates, payload identity, cold commissioning | Excluir `target`, caches y archives; mantener build identity y no ejecutar `prepare:payload` en M0. |
| ADAPTER | `ecosistema-aegis::infrastructure/data-plane/{bootstrap.*,install-node.*,manage-node.*,verify-node.*,build-release.*}` | Aegis data-plane | Node Manager lifecycle adapter | operadores y despliegues existentes | Mantener nombres/flags legacy; retirar lógica Aegis específica sólo después de consumers medidos. |
| SHARED | `ecosistema-aegis::infrastructure/data-plane/contracts/control-runtime/v1/**` | Aegis data-plane | contrato Node Manager/Aegis versionado | Node Core, runtime control y Aegis | Extraer schemas sin duplicarlos; Center consume contrato/API, no fuentes internas. |
| SHARED | `ecosistema-aegis::infrastructure/data-plane/contracts/site-runtime/v1/**` | Aegis data-plane | contrato runtime/capability | Site Runtime, Supervisor y Center | Revisar qué parte es universal y qué parte es Site Core antes de M1. |
| ADAPTER | `ecosistema-aegis::infrastructure/data-plane/services/agent/**` | Aegis data-plane | pendiente: Node Runtime o adapter Aegis | payload, lifecycle, attestation, observed state | Tiene primitives de Node y naming Aegis; ownership crítico no resuelto, no mover automáticamente. |
| ADAPTER | `ecosistema-aegis::infrastructure/data-plane/services/connector/**` | Aegis data-plane | adapter de conectividad Node | runtime network/sync | Separar transporte universal de policy Aegis; conservar contrato de red y fallback. |
| STAY | `ecosistema-aegis::infrastructure/data-plane/services/control-runtime/**` | Aegis Control local | Ecosistema Aegis | backend local, PostgreSQL, sync y policy | Contiene lógica de negocio Aegis; Node Manager sólo debe consumir API/contratos explícitos. |
| STAY | `ecosistema-aegis::infrastructure/data-plane/services/{people,radio,site-core,telemetry}/**` | Aegis capability planes | Ecosistema Aegis | payload actual, PostgreSQL/NATS/S3/LiveKit | No son plataforma universal; publicar artefactos/versiones mediante adapter, sin segunda copia editable. |
| DEPRECATED | `ecosistema-aegis::infrastructure/data-plane/installer/src-tauri/resources/node/**` | generado por sync/build | ningún owner editable | bundle Tauri y `PAYLOAD.json` | Es snapshot generado e ignorado; no importar como fuente ni regenerar payload durante M0/M1. |
| DEPRECATED | `ecosistema-aegis::infrastructure/data-plane/installer/src-tauri/resources/supervisor/**` | staging generado por build | ningún owner editable | bundle Tauri | El candidato conserva `src-tauri/supervisor/**` como fuente y genera este staging sólo durante packaging; se excluyó del histórico canónico para evitar una segunda implementación. |
| MOVE | `ecosistema-aegis::infrastructure/data-plane/compose.fabric.yml`, `compose.yml`, `node.env.example`, `VERSION` | Aegis data-plane | Node Manager host runtime | PostgreSQL/NATS y lifecycle Host | Extraer sólo primitives Host; los compose de capabilities quedan en adapters. |
| ADAPTER | `ecosistema-aegis::infrastructure/data-plane/compose.{people,radio,site-core,telemetry,control}.yml` | Aegis | Aegis adapters | capability services | No promover a plataforma universal; declarar inputs/outputs y versión de payload. |
| MOVE/ADAPTER | `ecosistema-aegis::infrastructure/data-plane/docs/**` | Aegis data-plane | dividido | operación, recovery, gates y capabilities | Separar documentos de plataforma de los de Aegis; preservar links y estado epistémico. |
| ADAPTER | `ecosistema-aegis::.github/workflows/actium-telemetry-node-installer.yml` | Aegis CI | workflow Node Manager + workflow Aegis capability | build/test/release | Extraer jobs de Node Manager; dejar en Aegis sólo integración y consumo de artefactos. |
| STAY/ADAPTER | `ecosistema-aegis::infrastructure/data-plane/{keys,secrets,postgres,nats,livekit,coturn,observability}` | Aegis deployment | según componente | infra de capabilities y host | No mover secretos ni asumir ownership por estar bajo data-plane; separar README/contrato de material. |
| EXCLUDE | `ecosistema-aegis::infrastructure/data-plane/{*.tar,*.gz,installer/target/**,installer/.cargo-target*/**,dist/**,temp/**,archivos extraños no trackeados}` | local artifact/WIP | ninguno | ninguno | No copiar, no borrar y no usar como provenance; conservar en el worktree del usuario. |
| STAY | `actium-center::supabase/functions/actium-host-enrollment/**` | Actium Center | Actium Center | ticket, challenge, complete, confirm | Es autoridad de Center; Node Manager sólo cliente machine-facing. |
| STAY | `actium-center::supabase/functions/actium-data-plane-gateway/**` | Actium Center | Actium Center | gateway HTTP, PoP, package, ACK | Mantener API estable/versionada; no importar implementación al nuevo repo. |
| STAY | `actium-center::supabase/functions/actium-data-plane-bootstrap/**` | Actium Center | Actium Center | signed bootstrap y release manifest | Owner de bootstrap y registry; exponer producto `actium-node-manager` en fase posterior. |
| STAY | `actium-center::supabase/migrations/{20260905120000,20260905123000,20260905235251}_*.sql` | Actium Center | Actium Center | estado durable de enrollment | No mover migraciones; sólo documentar contrato y versionado cross-repo. |
| STAY | `actium-center::src/features/aegis-nodes/runtime/ActiumSiteHierarchy.tsx` | Actium Center | Actium Center | Host/Site/Node UI y ticket Owner+AAL2 | Mantener separación Site/Host/Node; reemplazar imports internos por API oficial en M2. |
| STAY | `actium-center::src/features/aegis-telemetry/runtime/DataPlaneDeploymentManager.tsx` | Actium Center | Actium Center | release, payload digest y deployment | Consumir manifests firmados; no convertirse en owner de Node Manager. |
| SHARED | `actium-center::scripts/test-host-enrollment-gate-1-6.mjs` y `scripts/predeploy-release-contract.mjs` | Actium Center | contratos de integración | Center ↔ Node Manager | Mantener como tests de consumidor y acordar suite compartida sin duplicar implementación. |

## Gate 1.6.2: invariante de extracción

La extracción sólo es válida si conserva literalmente esta secuencia:

```text
hen_* → challenge → Supervisor PoP → Center complete → pending_apply
→ EnrollmentPackage → Supervisor apply → signed ACK → Center confirm
→ enrolled/trusted → signed discovery
```

No se permite introducir UUID prompts, Owner JWT en Manager, endpoint hardcodeado por cliente, autoridad compilada por Site ni una segunda FSM de enrollment.

## Obsidian audit M0

Dominio actual auditado: `vault::20 - Ecosistema Aegis/35 - Actium Node Manager/`.

- 16 notas Markdown canónicas inventariadas; no se encontraron basenames duplicados en la bóveda.
- 2 reportes contienen rutas explícitas al dominio viejo.
- El índice tiene 22 referencias entrantes Markdown observables; otros documentos enlazan las notas por basename.
- La bóveda contiene además índices/claims/cache de Demiurge con paths; no deben editarse a mano como si fueran notas canónicas.
- M0 no mueve ni renombra notas. M3 creará `15 - Actium Node Manager/00 - Índice Actium Node Manager.md`, reparará links y dejará en la ubicación vieja sólo un bridge/index mínimo si es necesario.

## Riesgos Graphify y links

- Las rutas explícitas `20 - Ecosistema Aegis/35 - Actium Node Manager` son frágiles ante el cambio de dominio; deben actualizarse en M3 con una búsqueda global y revisión de cada destino.
- Los wikilinks por basename no son ambiguos hoy, pero pueden volverse ambiguos si el nuevo índice o notas se crean con nombres repetidos; M3 debe validar resolución única antes de retirar cualquier bridge.
- Los índices, claims, manifests y caches generados por Demiurge/Graphify pueden usar path como identidad. No se editarán manualmente ni se borrarán; se reproyectarán sólo mediante el mecanismo autorizado y después de que exista una ubicación canónica.
- El dominio viejo no se eliminará en M3 si existen referencias externas no reparables. El bridge será mínimo, explícito y no contendrá copias completas de conocimiento.
- La convergencia de Graphify es una condición de M4: una sola ubicación canónica, sin claims duplicados y con los unknowns/temporalidad conservados.

## Plan de gates M1–M4

| Gate | Alcance autorizado | Criterios de salida | Riesgo/control |
|---|---|---|---|
| M1 — Repository extraction | Crear checkout Git del nuevo repo desde un espejo aislado; importar historia filtrada; extraer sólo código con ownership resuelto; mantener bridge Aegis | Nuevo repo compila y prueba Node Manager/Supervisor; provenance verificable; payload sin cambios; Aegis aún puede consumir el bridge | No iniciar hasta resolver repositorio remoto vacío, `agent/connector` y snapshot generado `resources/node` |
| M2 — Canonical switch | Construir desde el nuevo repo; publicar contratos oficiales; cambiar Aegis a APIs/adapters; retirar ownership editable duplicado | Un único productor de Manager/Supervisor/Core; builds universales; Gate 1.6.2, IPC, storage, discovery y diagnostics verdes | Cambios incrementales, rollback por artefacto y sin mover secretos/authority |
| M3 — Knowledge switch | Crear `15 - Actium Node Manager`; migrar las 16 notas canónicas; reparar path-links, MOCs y manifest/proyección Graphify; dejar bridge mínimo | Links y backlinks resueltos; no duplicación de notas/claims; mapa de repositorios actualizado | No borrar el dominio antiguo ni reproyectar caches hasta validar identidad path-based |
| M4 — Regression | Comparar builds, Node Core, IPC, enrollment 1.6.2, resolver, storage, signed ACK/`enrollmentNonce`, diagnostics, Center/Aegis integration y payload | Evidencia reproducible de extracción completa; sin enrollment real sobre NAS durante M0/M1; aprobación explícita antes de operaciones productivas | Separar pruebas locales/remotas y mantener unknowns no verificados |

## Bloqueos resueltos de M1

1. El directorio nuevo y el remoto no tienen historia Git ni refs; no existe todavía un checkout canónico sobre el cual hacer un import preservando provenance.
2. `services/agent` y `services/connector` mezclan primitives de plataforma con naming/policies Aegis; su ownership es crítico y requiere partición contractual antes de moverlos.
3. `resources/node` contiene una copia generada de servicios, documentación y compose; tratarla como fuente rompería el principio de no duplicación y podría cambiar el payload.

En M1 se resolvió el primer bloqueo con provenance importada. `agent/connector` y el snapshot generado siguen fuera del núcleo; quedan como bridges pendientes de M2 y no bloquean esta extracción.

## Resultado de importación M1

- Histórico filtrado desde `a71d58bdb4b8bbe4893498668cb38b3a30f38ebc` a `c9935525b6515488712eaa45046ee1497f834520` mediante mirror temporal y `git-filter-repo 2.47.0`.
- Overlay verificado contra el source WIP: 31 archivos con hash normalizado coincidente (28 modificados no-binarios y 3 archivos nuevos); el binario generado de Supervisor fue excluido.
- Se retiraron del candidato nuevo los tests/scripts que dependían de Compose, Telemetry, Site Core, payload o workflows internos de Aegis, además de los ejemplos de commissioning acoplados a esos contratos. El source Aegis original permanece intacto.
- El build master ya no resuelve rutas hardcodeadas de `ecosistema-aegis`, no invoca `prepare:payload` y omite el bundle Tauri cuando falta el payload externo; el Supervisor/Core sí pueden validarse como fuente independiente.
## Validación y cierre M1

- `npm ci --ignore-scripts`: PASS; lockfile sólo refleja `0.7.0-rc.3`.
- `npm run build`: PASS; TypeScript/Vite compila desde el checkout nuevo.
- Contratos Node Manager: `22 pass, 0 fail`, incluyendo control-plane resolver, Host Enrollment 1.6.2, IPC, storage, trust y diagnostics.
- Node Core/Tauri: `cargo check --workspace --all-targets --no-default-features` PASS; `cargo test --workspace --lib --no-default-features`: Node Core `202 pass`, Manager `51 pass`.
- Supervisor: `cargo test -p actium-node-supervisor --all-targets --no-default-features`: `3 pass`; release compilado desde el repo nuevo.
- `npm run compile -- --os windows --no-terminal`: PASS. No ejecutó `prepare:payload`; omitió el bundle Tauri porque el payload es un artefacto externo.
- Identidad del artefacto Supervisor: `version=0.5.21`, `source_commit=8fbb7228a2106681b5c8b9842b4aaa91abe151e0`, `build_id=m1-extract-20260906-8fbb722`, `binary_sha256=911C747F6DE9CD67A32E3905D8390FAB64865F9F04E6B170CDD33A8C9ECA5059`.
- `git diff --check` y `git fsck --full --no-reflogs`: PASS.
- Firewall final: no `resources/node/**`, `PAYLOAD.json` ni `services/agent`, `services/connector`, `people`, `radio`, `site-core`, `telemetry` o `control-runtime` fueron importados como fuente. `resources/supervisor/**` queda sólo como staging ignorado generado desde `src-tauri/supervisor/**`.
- Los worktrees Aegis y Center conservaron sus HEAD y WIP; no se hizo canonical switch, deploy NAS, enrollment real ni generación de authority material.

M1 queda `PASS` para el núcleo extraído. M2 queda `READY` para publicar el contrato oficial, cambiar Aegis a adapters y retirar el ownership editable legacy; el payload/capability bundle continúa siendo una dependencia externa deliberada y no fue convertido en fuente del repositorio nuevo.

## Cierre M2 — switch canónico

M2 implementó el switch incremental sin filtrar ni reescribir los worktrees
fuente. El source trackeado de `ecosistema-aegis::infrastructure/data-plane/installer/**`
fue retirado en `36f3ece`; Aegis conserva sólo sus capabilities, adapters y
artefactos legacy no trackeados. `actium-node-manager` publicó los contratos
neutrales y el ownership freeze en `fe17d23`. Center registró el producto
`actium-node-manager` mediante una migración local no aplicada en `9a15d25`.

Los resultados reproducibles y bridges pendientes están en
`docs/migration/M2-CANONICAL-SWITCH.md`. A partir de este punto no se aceptan
nuevos cambios de Manager/Supervisor/Core en Aegis; cualquier compatibilidad
debe pasar por el adapter o por un artefacto generado/congelado declarado.
