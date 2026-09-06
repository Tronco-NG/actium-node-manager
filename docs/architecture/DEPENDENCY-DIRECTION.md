# Actium Node Manager — Dependency Direction

## Dirección objetivo

```text
Actium Center
  ↓ contracts / control-plane API
Actium Node Manager
  ├─ apps/node-manager
  ├─ crates/node-core
  ├─ crates/node-supervisor
  ├─ packages/contracts
  └─ release + diagnostics
       ↑ adapters / signed capability artifacts
Ecosistema Aegis, AirShield, Sentinel, Demiurge
```

La flecha representa consumo de contratos y APIs, no import de fuentes internas. Node Manager no puede depender de internals de Aegis.

## Dependencias actuales a encapsular

| Dependencia observada | Problema | Frontera M1/M2 |
|---|---|---|
| Los tests/scripts históricos de `installer` usaban `../services/*` | El candidato nuevo no debe conocer el layout interno de Aegis | Se retiraron del candidato; los contratos de capabilities permanecen en Aegis y se consumirán vía adapter |
| `sync-node-resources.ps1` copiaba servicios al bundle | Creaba una segunda copia editable | Se retiró del candidato; Aegis conserva temporalmente su snapshot congelado |
| Aegis workflow compila Manager, Supervisor y capabilities | No hay owner único de release | workflow Node Manager separado + integration workflow Aegis |
| Center mantiene bootstrap/gateway/enrollment | Correcto en ownership, pero el contrato debe ser público/versionado | SDK/contract client, sin importar Edge Function |
| `actium-telemetry-node-installer` aparece en audience/paths | Compatibilidad legacy necesaria | alias/bridge con deprecation plan |
| payload runtime incluye Aegis capability services | No todo `data-plane` es Node Manager | decidir agent/connector y publicar capabilities como adapters |

En M1, `services/agent`, `services/connector`, `control-runtime`, `site-runtime` y las capabilities no se importaron. `src-tauri/resources/node/**` y el staging duplicado `src-tauri/resources/supervisor/**` tampoco son fuente canónica.

## Reglas de dependencia

1. `packages/contracts` contiene schemas, tipos y códigos de error; no contiene acceso directo a la base de Center.
2. `control-plane/` en Node Manager contiene cliente/protocolo, no implementación de Center.
3. `Node Core` no importa React, Supabase SDK ni módulos Aegis.
4. `Supervisor` sólo acepta comandos IPC y artefactos firmados; no recibe Owner JWT.
5. Capabilities no pueden promover Host a `enrolled/trusted`.
6. El build identity se inyecta al artefacto en build y se expone en diagnostics; no se usa semver como única evidencia.
7. Todos los adapters deben ser reemplazables, observables y tener rollback.

## Validación posterior

M4 debe comprobar que el grafo no contiene imports del nuevo Node Manager hacia `ecosistema-aegis` internals, que Center consume sólo API/contratos, y que el payload productivo no cambió sin una operación de release explícita.

El contrato de base runtime `actium-node-manager-host@1.0.0` y el catálogo de
contratos son la frontera M2. Aegis puede depender de esa superficie mediante
su adapter, pero Node Manager no depende del layout de Aegis ni de sus
implementaciones de capabilities.

`actium-product-extension-bundle@1.0.0` is the runtime capability boundary.
The same Node Core engine handles local import and future Center Desired State
delivery. The UI requests privileged lifecycle actions from Supervisor over
`extension_bundle_v1` and `extension_lifecycle_v1` IPC.
