# Actium Node Manager — Compatibility Bridges M0

Los bridges son temporales, explícitos y medibles. Ninguno autoriza una segunda implementación permanente.

| Bridge | Owner | Motivo | Contrato a conservar | Eliminación |
|---|---|---|---|---|
| Generated runtime snapshot `resources/node/**` (Aegis) → external payload input | Ecosistema Aegis produce; Node Manager legacy adapter consume | El snapshot productivo incluye capabilities Aegis y no es fuente canónica | SHA `BF43DE...ACCE420`, `PAYLOAD.json`, `runtime_release`, `payload_digest`, `source_commit` y `productChannel` | Aegis Extension Bundle v1 + acceptance equivalente + migración NAS completa; el snapshot queda congelado en Aegis y fuera de este repo. `generated snapshot != canonical source`. |
| `src-tauri/actium-node-core/assets/telemetry-audit.sql` | Aegis schema owner + Node Manager diagnostic owner | Preserva el diagnóstico existente sin importar `services/telemetry` | consulta read-only y redacción de respuesta | Cuando Aegis publique un contrato de diagnóstico versionado/firmado; no agregar aquí más lógica de Telemetry. |
| Legacy package/audience `actium-telemetry-node-installer` ↔ `actium-node-manager` | Node Manager + Center | Releases y bootstrap existentes todavía nombran la identidad legacy | audience, installer version, `PAYLOAD.json`, markers y rutas | Cuando producer/consumer nuevo esté desplegado y la métrica legacy sea cero durante la ventana acordada. |
| Aegis capability payload adapter → Node Manager release builder | Ecosistema Aegis produce; Node Manager legacy adapter consume | El payload actual contiene servicios Aegis y no debe duplicarse como fuente editable | manifest firmado, `runtime_release`, `payload_digest`, capabilities, profiles y source identity | Aegis Extension Bundle v1 + acceptance equivalente + migración NAS completa. Explicit-only; no nuevos deployments. |
| Center enrollment API → Node Manager machine client | Actium Center owner de autoridad; Node Manager owner del cliente | La autoridad de ticket/challenge/complete/confirm no debe copiarse | `hen_*`, scope challenge, PoP, `EnrollmentPackage`, `pending_apply`, signed ACK, `enrollmentNonce` | No se elimina; se versiona como API estable cross-product. |
| Supervisor IPC compatibility | Node Manager | Hosts instalados usan sockets/pipes, markers, service names y estructuras existentes | IPC typed commands, `EnrollmentApplySignedPackage`, diagnostics y error codes | Sólo después de migración idempotente con rollback en Windows/Debian. |
| Host filesystem compatibility | Node Manager | Instalaciones legacy usan `TelemetryNode*`, `ActiumTelemetryNode-Recovery` y variantes de casing | discovery, ownership, backup, recovery y no-delete | Cuando discovery dry-run y telemetría de uso legacy hayan convergido. |
| Stable/Lab channel compatibility | Node Manager | El Host comparte identity/config pero mantiene canales operativos | service units, `control-plane.json`, payload pin, Supervisor identity y channel binding | No eliminar; normalizar como channels universales. |
| Center release/deployment adapter | Actium Center | Center administra desired/observed runtime y manifests | `runtime_release`, `payload_digest`, `source_commit`, generations y signed discovery | Cuando Center consuma el contrato publicado por el repo nuevo, sin imports internos. |
| Obsidian old-domain bridge | Vault / Actium Security | Enlaces externos apuntan a `20 - Ecosistema Aegis/35 - Actium Node Manager` | un índice mínimo con wikilink al dominio top-level nuevo | Después de reparar backlinks, Graphify y referencias externas verificadas en M3/M4. |

## Prohibiciones del bridge

- No agregar prompts de `client_id`, `organization_id`, `site_id`, `host_id`, `installation_id` o `epoch`.
- No entregar Owner JWT al Manager.
- No resolver Control Plane desde Storage ni desde una URL compilada por cliente.
- No copiar una implementación Center/Aegis al nuevo repo para “facilitar” la transición.
- No modificar `PAYLOAD.json` para acomodar el layout nuevo.
- No reintroducir `sync-node-resources.ps1` ni ningún mecanismo que copie `services/*` de Aegis al árbol fuente de Node Manager.
- Los templates de Supervisor bajo `src-tauri/supervisor/**` son fuente; `src-tauri/resources/supervisor/**` es staging generado y no debe convertirse en una segunda implementación editable.

## Estado M2 — canonical switch

El source trackeado de `infrastructure/data-plane/installer/**` fue retirado
del checkout Aegis después de crear un resguardo local del WIP. El nuevo repo
es ahora el único owner editable de Manager, Supervisor, Node Core, Host
Enrollment, Control Plane client, trust, discovery, storage host primitives y
diagnostics. Aegis conserva únicamente sus capacidades y los artefactos
generados/frozen necesarios para compatibilidad de releases existentes; no se
copian al target ni se usan como fuente.

El adapter explícito vive en
`infrastructure/data-plane/adapters/actium-node-manager/` y fija
`actium-node-manager-host@1.0.0`. `services/agent` y `services/connector`
siguen siendo Aegis-owned y consumen ese descriptor neutral. El workflow Aegis
de integración prueba esos adapters sin compilar ni regenerar Node Manager.

El bridge se elimina cuando el packaging externo firmado sustituya el payload
legacy, los consumidores hayan convergido al contrato publicado y la ventana
de rollback de Aegis esté cerrada. Hasta entonces, el payload permanece fuera
del repo Node Manager y no recibe desarrollo funcional.
## M4 Trust Fabric legacy authority bridge

The legacy `ACTIUM_HOST_ENROLLMENT_*` variables and
`ACTIUM_ROOT_AUTHORITY_PUBLIC_KEY` remain only for compatibility with the
existing Center/Supervisor release. They are not the canonical trust source.
The canonical source is the Authority Service plus the Supervisor durable
Trust Store. Removal condition: Trust Fabric M4, NAS acceptance M5 and one
successful real enrollment. No new deployment may require manual key
variables.
