# Actium Node Manager — Git Provenance M1

## Estado actual

El worktree fuente auditado es `ecosistema-aegis-control-local-backend@a71d58bdb4b8bbe4893498668cb38b3a30f38ebc` sobre la rama `refactor/aegis-control-local-backend`. Está sucio y contiene WIP de Gate 1.6.2. El worktree `actium-center-control-local-backend@1126a34bfd660d0bb3f138a0c5e15386ecdbe3c1` también está sucio con cambios de integración Center.

`C:\Dev\Workspace\actium-node-manager` es ahora un checkout Git local en la rama `refactor/extract-from-aegis-m1`, con origin configurado a `https://github.com/Tronco-NG/actium-node-manager.git`. No se hizo push. El remoto sigue sin `HEAD`, ramas ni tags.

## Historia localizada

La historia de los paths no está concentrada en un único subárbol:

| Superficie | Commits observados | Primeras señales útiles |
|---|---:|---|
| `installer/` | 151 | `3105cbbae72c` instalador gráfico, `494543f225cc` enrollment firmado, `3ae17e3bf422` manager persistente |
| `installer/src-tauri/actium-node-core/` | 37 | `687f44030e92` journal/lifecycle, `152cdf80ffe9` Supervisor Linux/IPC, `4a8514e93322` attestation |
| `installer/src-tauri/actium-node-supervisor/` | 33 | `152cdf80ffe9`, `fbc6f87d217`, `d651bba49e2d` Supervisor Windows/Stable |
| `services/` | 46 | `67257bf669d2` runtime portable, `d620f9aa1769`/`c2312552e358` backend local Aegis |
| `services/agent/` | 1 sobre `src/main.ts` | `67257bf669d2` |
| `services/control-runtime/` | 3 | `d620f9aa1769`, `c2312552e358`, `805fa4ffedf7` |
| `infrastructure/data-plane/docs/` | 34 | documentación de runtime, commissioning y gates |

Los commits finales relevantes para Host Enrollment/identity en el working tree son `e9508d6fd093`, `73caf62dcab1`, `e6a35926b862` y `a71d58bdb4b8`. Estos commits pertenecen al repositorio Aegis y no deben reinterpretarse como commits del repositorio nuevo.

## Extracción ejecutada

1. Se creó el espejo aislado `C:\Users\Tronco\AppData\Local\Temp\actium-node-manager-m1-provenance-20260906\aegis-mirror.git` desde el directorio Git común de Aegis, sin usar ni modificar el worktree WIP.
2. Se verificó que `a71d58bdb4b8bbe4893498668cb38b3a30f38ebc` existía en el espejo y que el remoto nuevo estaba vacío.
3. Se creó un bundle de resguardo del espejo original: `aegis-installer-history-before-filter.bundle`.
4. Se ejecutó `git-filter-repo 2.47.0` sólo sobre `refs/heads/refactor/aegis-control-local-backend`, filtrando `infrastructure/data-plane/installer/**`, renombrando ese prefijo al root del nuevo repo y excluyendo los binarios generados de Supervisor.
5. El histórico filtrado resultó en `c9935525b6515488712eaa45046ee1497f834520`; autores, fechas, mensajes y ancestry razonable fueron conservados, aunque los hashes cambiaron por el path filtering.
6. Se importó esa ref mediante fetch local al checkout nuevo y se creó `refactor/extract-from-aegis-m1`.
7. Se aplicó después el overlay WIP limitado al path MOVE: 28 archivos modificados no-binarios y tres fuentes/tests no trackeados (`build.rs`, `control_plane.rs`, contrato Gate 1.6.2). El binario generado modificado no se promovió.

El mirror original y su bundle quedan fuera del repositorio nuevo como evidencia temporal de recuperación. No se ejecutó `git filter-branch`, `fast-export`, `fast-import`, reset, checkout destructivo ni filtrado sobre los worktrees fuente.

## Mapeo inicial de paths

```text
infrastructure/data-plane/installer/src/main.ts
  → src/main.ts
infrastructure/data-plane/installer/src-tauri/actium-node-core
  → src-tauri/actium-node-core
infrastructure/data-plane/installer/src-tauri/actium-node-supervisor
  → src-tauri/actium-node-supervisor
infrastructure/data-plane/installer/src-tauri/src
  → src-tauri/src
infrastructure/data-plane/installer/scripts
  → scripts (sólo scripts de producto y contracts locales)
```

Los paths Aegis capability (`services/people`, `radio`, `site-core`, `telemetry`, `control-runtime`) no tienen aún destino Node Manager. Su incorporación como snapshot sería provenance falsa y duplicación editable.

## Reglas de provenance

- Nunca usar el HEAD de los worktrees históricos documentales como sustituto del HEAD solicitado.
- Registrar siempre `repository_id`, branch, commit, path original, path nuevo y estado `HEAD/index/working-tree`.
- Los untracked archives, targets, caches, `PAYLOAD.json` ignorado y binarios desplegados quedan fuera de la historia fuente.
- El SHA productivo de payload `BF43DE...ACCE420` se verifica como artefacto NAS, pero no se inventa un commit fuente si el manifest local es dirty.
- No generar ni versionar secretos, tokens, JWT o material de autoridad.

## Commit mapping M1

El archivo completo generado por `git-filter-repo` queda en el espejo aislado `filter-repo/commit-map`. Los mappings relevantes para provenance de producto son:

| Commit Aegis | Commit filtrado Node Manager | Superficie |
|---|---|---|
| `3105cbbae72c36a754bca66057e0abef421485f8` | `5bd40debc6237514b873c5ab811709b4184c5012` | instalador gráfico |
| `494543f225cc92fe0f71f1559ede141eebb6abeb` | `205c0ea2a65d78c38e339feb4f853d3700585cb4` | enrollment firmado |
| `3ae17e3bf4224b95febfdba3128bed7f4558248e` | `db329c59ebba85f209058bb7ccff7d3cde061b32` | Manager persistente |
| `687f44030e92ef4fa1f53557b21fac8cae6be824` | `d557cc7fcc69f7bbe60951ca26a3fdde06dc18ba` | Core journal/lifecycle |
| `152cdf80ffe9f86c74d76f551e65fba8643b5dd5` | `d9d5915ae86ad03b98147d98ba3b204e8b45cdd8` | Supervisor Linux/IPC |
| `4a8514e93322965ee7810e1ad823fd8ec485d326` | `0eaf0edfe0df091e614e89a1de95abe4e545ca26` | attestation |
| `e9508d6fd0939d2ec8df9863569d6c5e41dc8b37` | `7530159205dcf4fe7a404ff3ce032346d25e81a4` | enrollment Gate 1.6.2 |
| `73caf62dcab17c4f62e84caa452739eaf2e940a5` | `2e91e3bb00cfe38025d670df9deabb9402606085` | Gate 1.6.2 |
| `e6a35926b862c0011f6b701926347d4a19e42c05` | `ac23947771139c7eb8f3b2799d7ed1e216a3fb1d` | Gate 1.6.2 |
| `a71d58bdb4b8bbe4893498668cb38b3a30f38ebc` | `c9935525b6515488712eaa45046ee1497f834520` | baseline importado |

`services/agent` (`67257bf...`) y `services/control-runtime` no fueron filtrados porque pertenecen a adapters/capabilities fuera de M1; no se inventó mapping de commits para ellos.

## Estado de payload

El checkout nuevo no contiene `resources/node/**` ni `PAYLOAD.json`. El snapshot Aegis local permaneció fuera del target y conserva SHA `147A6EE7E9377BA9C8F209D86075A899D6E2E539A46F52001A0228214DFEC42`; el SHA productivo de referencia continúa siendo `BF43DE8AB7BE74026A33A30F6BE6E496034EEB9E6A9E791A0CA8F3856ACCE420`. No se ejecutó `prepare:payload`.

## Identidad del candidato M1

El commit de código extraído y overlayado es `8fbb7228a2106681b5c8b9842b4aaa91abe151e0`. Desde ese commit, `npm run compile -- --os windows --no-terminal` produjo Supervisor `0.5.21` con `build_id=m1-extract-20260906-8fbb722`, `source_commit=8fbb7228a2106681b5c8b9842b4aaa91abe151e0` y `binary_sha256=911C747F6DE9CD67A32E3905D8390FAB64865F9F04E6B170CDD33A8C9ECA5059`. El bundle Tauri quedó omitido porque el payload externo no está en el repositorio canónico; eso no modifica ni regenera el snapshot.

## Overlay y canonical switch M2

El WIP MOVE fue respaldado antes del retiro del source legacy y quedó aplicado
en el checkout canónico M1. En M2 no se volvió a copiar ese WIP desde Aegis:
se agregaron únicamente contratos/docs al target y Aegis pasó a un adapter
explícito. El commit Aegis `36f3ece` elimina del índice la implementación
editable de `infrastructure/data-plane/installer/**`; el commit target
`fe17d23` fija ownership y el contrato de base runtime. El commit Center
`9a15d25` sólo registra el producto y no contiene autoridad ni secretos.

El backup local de seguridad es
`C:\Users\Tronco\AppData\Local\Temp\actium-node-manager-m2-legacy-backup-20260906`.
El histórico filtrado M1, su bundle y el commit-map permanecen en el mirror
temporal documentado arriba. Ningún artefacto generado o `PAYLOAD.json` fue
usado como provenance ni agregado al repo nuevo.
