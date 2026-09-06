# Actium Node Manager — Compatibility Bridges M0

Los bridges son temporales, explícitos y medibles. Ninguno autoriza una segunda implementación permanente.

| Bridge | Owner | Motivo | Contrato a conservar | Eliminación |
|---|---|---|---|---|
| Generated runtime snapshot `resources/node/**` (Aegis) → external payload input | Ecosistema Aegis produce; Node Manager consume | El snapshot productivo incluye capabilities Aegis y no es fuente canónica | SHA `BF43DE...ACCE420`, `PAYLOAD.json`, `runtime_release`, `payload_digest`, `source_commit` y `productChannel` | Cuando exista un registry de artefactos firmado; mientras tanto el snapshot queda congelado en Aegis y fuera de este repo. `generated snapshot != canonical source`. |
| `src-tauri/actium-node-core/assets/telemetry-audit.sql` | Aegis schema owner + Node Manager diagnostic owner | Preserva el diagnóstico existente sin importar `services/telemetry` | consulta read-only y redacción de respuesta | Cuando Aegis publique un contrato de diagnóstico versionado/firmado; no agregar aquí más lógica de Telemetry. |
| Legacy package/audience `actium-telemetry-node-installer` ↔ `actium-node-manager` | Node Manager + Center | Releases y bootstrap existentes todavía nombran la identidad legacy | audience, installer version, `PAYLOAD.json`, markers y rutas | Cuando producer/consumer nuevo esté desplegado y la métrica legacy sea cero durante la ventana acordada. |
| Aegis capability payload adapter → Node Manager release builder | Ecosistema Aegis produce; Node Manager empaqueta | El payload actual contiene servicios Aegis y no debe duplicarse como fuente editable | manifest firmado, `runtime_release`, `payload_digest`, capabilities, profiles y source identity | Cuando capabilities publiquen artefactos versionados independientes del monorepo. |
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
