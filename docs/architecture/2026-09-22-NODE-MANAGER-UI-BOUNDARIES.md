# Node Manager UI Boundaries — 2026-09-22

## Objetivo

Separar en ventanas navegables las responsabilidades que estaban mezcladas en Node Manager. La UI debe mostrar estado observado y ofrecer únicamente la acción que pertenece al boundary de la página actual.

La navegación nueva conserva las rutas antiguas como aliases:

| Boundary | Ventana | Ruta |
| --- | --- | --- |
| Authority | Status | `#/authority-fabric/status` |
| Authority | Root Brief | `#/authority-fabric/root-brief` |
| Authority | Ceremonia Owner/AAL2 | `#/authority-fabric/ceremony` |
| Authority | Lifecycle | `#/authority-fabric/lifecycle` |
| Connectivity | Overview | `#/connectivity` |
| Connectivity | Routes | `#/connectivity/routes` |
| Connectivity | Remote Ops | `#/connectivity/remote-ops` |
| Connectivity | WAN | `#/connectivity/wan` |
| Operations | Cola | `#/operations` |

## Separación de responsabilidades

### Authority Fabric / Status

Sólo diagnóstico read-only: Authority Service, Trust Store, epoch, digest, build identity y capabilities. `AUTHORITY_CAPABILITY_UNAVAILABLE` se muestra como `BLOCKED`; nunca como readiness operativa aunque el payload incluya un booleano legacy `ready`.

### Authority Fabric / Root Brief

Sólo resolución de rutas canónicas, preflight de custodia y reconstrucción pública one-shot. No publica en Center ni ejecuta Host Enrollment.

### Authority Fabric / Ceremonia

Sólo el flujo Owner/AAL2 y su preflight. La UI transporta rutas; no recibe PEM, private keys, sealing keys ni Owner JWT.

### Authority Fabric / Lifecycle

Sólo CURRENT/SUCCESSOR/LKG, `SERVED_READY` y activación local verificada. La ventana deja explícito que activación local no equivale a publicación en Center, receipt del Host ni `CONVERGED`.

### Connectivity

- Overview: agente, control plane y boundary.
- Routes: selección local/privada/remota y scopes.
- Remote Ops: jobs tipados, polling, receipts y estado de replay.
- WAN: CGNAT, Direct WAN, Relay y HA.

Connectivity no concede autoridad criptográfica ni sustituye la verificación del Supervisor.

### Host Enrollment

Continúa como página separada. El botón de enrollment queda bloqueado si la capability, el Trust Bundle o el código de readiness no son operativos. El ticket `hen_*` sólo se consume después del preflight efectivo.

## Qué puede hacer el operador

- Actualizar diagnósticos read-only.
- Revisar y validar rutas de custodia mediante Supervisor, sin introducir material privado.
- Ejecutar un preflight Owner/AAL2 cuando exista autorización explícita.
- Ejecutar Root Brief o activación únicamente cuando la ventana correspondiente muestre todos los gates verdes y exista autorización del Owner.
- Introducir un ticket `hen_*` válido desde Host Enrollment, sólo después de un preflight operativo.
- Revisar jobs y receipts; no repetir una operación ante un error de replay sin corregir antes el ledger de Center.
- Configurar WAN/router únicamente como tarea de infraestructura aprobada; no es requisito para la ruta local de enrollment.

## Qué requiere corrección de source

- Esta navegación y el aislamiento visual de cada boundary.
- Derivar la semántica de estado desde `state + code`, evitando verde contradictorio.
- Mantener la resolución de rutas y protocolos alineada con el endpoint observado; un gateway HTTP 200 no prueba que Authority Service esté listo.
- Corregir en Center el error `HOST_MANAGEMENT_REPLAY_LEDGER_WRITE_FAILED` antes de reintentar Remote Ops.
- Alinear la identidad de build entre el Manager empaquetado y el Authority Service observado.
- Exponer convergencia Authority como evidencia durable y no como un botón mezclado con custodia.
- Investigar el loop de reinicio de `demiurge-control-plane.service` en la capa de runtime, no desde esta UI.

## No realizado

Esta corrección es source-only. No aplica migrations, no modifica Supabase, no actualiza NAS, no ejecuta Root Brief, no activa Authority, no publica Trust Bundle y no inicia Host Enrollment real.
