# Runtime Control Plane V1

**Estado:** implementado en source, probado localmente y desplegado en el NAS de laboratorio; R1 y Connectivity siguen abiertos.
**Scope:** Node Manager / Node Supervisor / runtime workloads.
**Fuera de scope:** Root custody, Owner/AAL2, Trust Bundle publication, migrations, production, R2, ACF y Enterprises F0–F11.

## Decisión estructural

El workload ejecuta, pero no decide su propia supervivencia. El Supervisor conserva la autoridad semántica mediante `RuntimeControlPlaneV1`; Docker, systemd o un proceso nativo son adapters de ejecución y sus estados son evidencia, no lifecycle authority.

La primera implementación vive en `actium-node-core/src/runtime_control_plane.rs` y se integra en `RuntimeOperator` y el IPC del Supervisor. Center no cambia: sigue gobernando desired state y los gates Owner/AAL2/publication de autoridad.

## Contratos y estado

- Contract: `actium.runtime.control-plane.v1`.
- Estado durable por nodo: `state/runtime-control-plane.json`.
- Event log durable: `state/runtime-events.jsonl`.
- Estados de runtime: `DISCOVERED`, `PREFLIGHT`, `ADMITTED`, `STARTING`, `RUNNING`, `READY`, `DEGRADED`, `BLOCKED`, `QUARANTINED`, `RECOVERING`, `STOPPED`, `FAILED`.
- Rollout: `LEGACY`, `OBSERVED`, `MANAGED`.
- Circuit breaker: `CLOSED`, `OPEN`, `HALF_OPEN`.
- Authority/lease: `VALID`, `RENEWAL_AVAILABLE`, `RENEWAL_REQUIRED`, `CRITICAL`, `EXPIRED`, `UNKNOWN`.
- Host pressure: `HEALTHY`, `PRESSURE`, `CRITICAL`, `EMERGENCY`, `UNKNOWN`.

El snapshot IPC `runtime_control_plane_status` expone a la UI el estado semántico, liveness, readiness, authority/dependency/resource signals, circuit, lease y eventos recientes. La vista de Runtime Units lo muestra separado del inventario Docker.

## Admisión y fallos

`RuntimeAdmissionV1` valida identidad, autoridad, firma/key id/generación, temporalidad, configuración, secretos, mounts, ports, dependencias, recursos y presión del host. Evidencia de autoridad incompleta, revocada, inválida, vencida o con rollback se bloquea fail-closed.

`RuntimeFailureClassifierV1` separa:

- deterministas: `JWT_EXPIRED`, `SIGNATURE_INVALID`, `AUTHORITY_REVOKED`, `GENERATION_ROLLBACK`, `CONFIG_INVALID`, `MISSING_SECRET`, `INCOMPATIBLE_RUNTIME`, `PERMISSION_DENIED`; no reinicio, cuarentena;
- transitorios: DNS, dependencia remota, base de datos o relay; backoff bounded;
- desconocidos: máximo de intentos definido por `CircuitBreakerPolicyV1`, luego `OPEN`/cuarentena.

El backoff actual está acotado a `5s, 15s, 30s, 60s, 120s, 300s` más jitter determinista. La reconciliación `desired=RUNNING + admission denied` produce `BLOCKED/QUARANTINED`, nunca un bucle infinito de starts.

## Resource Guard y soberanía del host

`ResourceGuardV1` separa la prioridad del Sovereign Plane de la Workload Plane. `HostPressureControllerV1` bloquea nuevos workloads bajo presión crítica/emergencia y conserva Supervisor/Authority/recovery. La recolección Linux captura memoria disponible, swap, load, PSI CPU/IO, espacio de disco e inodos cuando el host los expone.

Los límites declarativos existentes (`memory`, CPU, PIDs y logs) siguen en `RuntimeUnitResourceBudget`; el nuevo guard decide admisión antes de actuar. No se reescriben payloads ni compose artifacts en esta fase.

## RuntimeAdapter y Docker

El contrato `RuntimeAdapter` define `start`, `stop`, `restart`, `inspect` y `backend` para Docker, systemd, native, containerd y VM. La ruta actual Docker permanece detrás de `RuntimeOperator`; el control plane no contiene comandos Docker.

En `MANAGED`, antes de arrancar una unit el Supervisor fija `restart=no` en los containers observados y, al entrar en cuarentena, detiene sólo los containers en ejecución con `docker stop`; no ejecuta `compose down`, no elimina metadata ni volúmenes y conserva la base para recovery. En `LEGACY` no se altera la política existente. Esto permite migrar capability por capability sin Big Bang.

## Receipts y reconciliación

Las transiciones se guardan como `RuntimeEventV1`. La recuperación de `BLOCKED/QUARANTINED/RECOVERING` a `READY` emite `RecoveryReceiptV1` con runtime, estado previo, causa, intento, timestamps y resultado. El estado durable conserva `desired_running`, observed state, circuit, lease, último evento y bounded history.

El Supervisor también mantiene heartbeat durable (`lastHeartbeatAt`) y `SupervisorWatchdogV1` para que una capa externa pueda detectar ausencia de heartbeat. La activación del watchdog systemd queda como instalación operacional posterior, no como bypass de la política.

## Rollout seguro

1. `LEGACY`: no cambia behavior; registra snapshot cuando el reconciler observa el nodo.
2. `OBSERVED`: calcula admission, clasificación, presión y acción hipotética sin intervenir.
3. `MANAGED`: controla start/restart/quarantine, deshabilita restart autónomo y aplica circuit breaker.

No se cambia automáticamente un deployment existente a `MANAGED`. La promoción requiere una manifest/configuración explícita y validación del runtime adapter. Un capability nuevo debe registrarse con `CapabilityManifestV1`, dependencias y adapter, sin lógica especial por nombre.

## Invariantes verificadas por tests

- fallo determinista no genera reinicios infinitos;
- admisión fallida impide start en `MANAGED`;
- circuit breaker limita errores desconocidos;
- estado Docker `running` no equivale a `READY`;
- desired `RUNNING` no implica restart infinito;
- eventos y estado se persisten con escritura sincronizada y promoción atómica;
- authority lease vencida se clasifica como cuarentena;
- `LEGACY` conserva los tests existentes del reconciler.

## Evidencia de esta implementación

- `cargo test -p actium-node-core runtime_control_plane --lib`: 9/9 PASS.
- `cargo test -p actium-node-core --lib runtime::tests`: 52/52 PASS.
- `cargo check -p actium-node-core -p actium-node-supervisor`: PASS.
- `cargo check -p actium-node-manager`: PASS.
- `node_modules/.bin/tsc.cmd --noEmit`: PASS.

La instalación del NAS se ejecutó sólo después de construir el Supervisor con provenance explícita, correlacionar source/artifact/runtime y pasar el preflight del instalador. La activación de `MANAGED` fue explícita y acotada a la capability afectada; no se debe publicar un Trust Bundle sucesor como sustituto de este gate.

## Evidencia de integración NAS (2026-09-21)

- Commits Node Manager: `3c176b07b66ca5bd17b76ce860ea9f5413399112` (control plane) y `5aea102a304d386b622ebed4d4ca35c55d3e6d60` (cuarentena no destructiva).
- Artifact Supervisor Linux: `sourceCommit=5aea102a304d386b622ebed4d4ca35c55d3e6d60`, `buildId=r1-runtime-control-5aea102-20260921-fix`, `binarySha256=f94080e214b9a83f8a083b8552460b7520f98184f2c0d8930c9b8d3f3dc22311`.
- Instalación: `actium-node-supervisor.service` generación `16`; `actium-node-supervisor-lab.service` generación `15`; ambos reportan el mismo source/artifact y permanecen `active`.
- El nodo `actium-home-01-site-core` quedó `hostPressure=EMERGENCY`, `site-core=BLOCKED`, `rolloutMode=MANAGED` por capability y `circuit=OPEN`; `agent` permanece `READY` en `LEGACY`.
- La reconciliación posterior no recreó el contenedor de Site Core ni volvió a emitir el loop de health probes. La primera ejecución del artifact anterior había usado el `stop` heredado de `compose down`; el commit `5aea102` corrige eso a `docker stop` no destructivo para futuras cuarentenas. El backup durable previo quedó en `runtime-control-plane.json.pre-managed-20260921T070300Z` con SHA-256 `059365cbbdd11b1c1a6a0d2111fb983df02b3c7c4890ff82bc1adef679da7234`.
- No se ejecutó Root custody, Owner/AAL2, Trust Bundle publication, migration, production deploy ni cambio de PAYLOAD.

El estado `MANAGED` fue activado sólo para la capability afectada mediante el estado durable respaldado; no se cambió el modo global ni se habilitaron otras capabilities. La recuperación requiere resolver la causa de autoridad/recursos y una acción explícita de reanudación; el control plane no convierte `desiredRunning=true` en un restart infinito.
