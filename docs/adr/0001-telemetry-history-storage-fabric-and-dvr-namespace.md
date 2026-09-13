# ADR 0001: Telemetry History, Storage Fabric y Reserva Semántica del Dominio DVR

- **Estado:** DECIDED / CANONICAL
- **Fecha:** 2026-09-10
- **Decisores:** Actium Core Team, Aegis Architecture Council, Demiurge Cortex
- **Sistemas afectados:** Actium Node Manager, Actium Fabric, Aegis Telemetry Data Plane, Aegis Control, Demiurge Cortex
- **Hito de Roadmap:** F8 (Dependencia arquitectónica transversal)

---

## 1. Contexto del Problema

Durante la auditoría del Paso 5 (Almacenamiento) de Actium Node Manager y las pruebas de despliegue en entornos de laboratorio (NAS con bahías de discos físicos), se detectaron divergencias arquitectónicas críticas:

1. **Colisión de Concurrencia (`MUTATION_BUSY`):** El mecanismo de mutación exclusiva en `ReleaseManager` operaba mediante un intento no bloqueante (`try_lock_exclusive()`) de 0 ms. Los reconciliadores de fondo (`start_runtime_reconciler` cada 5s y `start_attestation_reconciler` cada 30s) adquirían el lock del Fabric compartido, provocando abortos inmediatos (`FIRST_INSTALL_ABORTED`) en instalaciones interactivas.
2. **Descubrimiento Caótico de Mounts:** El descubrimiento de almacenamiento delegaba en un `findmnt` sin filtrar que exponía namespaces internos y bind mounts creados por systemd (`/etc/systemd/...`, `/var/lib/...`, `/srv/.../authority-recovery`), mientras que omitía las rutas base de almacenamiento masivo como `/srv/actium-data`.
3. **Incoherencia del Ciclo de Vida en el Asistente:** El panel de *Storage Grants* exigía que el nodo estuviese enrolado previamente (`enrollment_required`), creando un bloqueo de "huevo o gallina" en un wizard diseñado para crear dicho nodo.
4. **Desconexión entre Parámetros UI y Workloads Reales:** La UI solicitaba una ruta para `GPS + Telemetría`, pero los contenedores de `compose.telemetry.yml` persistían sus datos a través de PostgreSQL y NATS JetStream en el **Fabric**, el cual permanecía rígidamente fijado al disco del sistema operativo (`/actium/fabrics/<fabric-id>`).
5. **Permisos y Ownership Incompatibles:** Se forzaba un ownership estático `1000:1000 (0750)`, lo que provocaba errores `EACCES: Permission Denied` en procesos de contenedores que corren con otros UIDs (ej. PostgreSQL UID 999 o Prometheus UID 65534).
6. **Ambigüedad Semántica de "DVR":** El histórico de tracks GPS y telemetría se denominaba "DVR" en contratos y UI, creando una futura colisión semántica con el dominio de grabación y retención de video para Video Wall / VMS.

---

## 2. Decisiones Arquitectónicas Canónicas

### 2.1. Taxonomía Canónica: Telemetry History vs. Video DVR

Queda formalmente establecido el siguiente modelo de dominio:

```text
TELEMETRY DOMAIN
│
├── Telemetry Live
│   ├── GPS / Live Coordinates
│   ├── terminal_location_current
│   ├── terminal_presence_current
│   └── HybridMap / Radar / C2 Ingestion
│
└── Telemetry History
    ├── Historical points & telemetry batches
    ├── Track sessions & forensic events
    ├── Stream durability & gap detection
    └── Telemetry Replay (Capacidad de reproducción)

VIDEO DOMAIN (Reservado)
│
├── Video Wall / Live Streams (WebRTC / RTSP / ONVIF)
│
└── Video Archive / DVR
    ├── Video Recorder
    ├── Video Segments & Storage Tiers
    ├── Retention Policies
    └── Video Replay
```

- **Regla:** El término `DVR` (o `Video DVR`) queda **estrictamente reservado** para la grabación, retención y reproducción de flujos de video (Video Wall / VMS).
- **Regla:** El histórico de telemetría y GPS se denomina canónicamente **`Telemetry History`**. La reproducción o análisis retrospectivo de tracks se denomina **`Telemetry Replay`**.
- **Compatibilidad Histórica (Legacy Layer):** Los contratos existentes en Supabase y Aegis que contengan prefijos `dvr_*` (`dvr_sessions`, `get_dvr_sessions`, `get_dvr_track`, `log_dvr_track_point`, `DvrSession`, `DvrTrackPoint`) se mantienen intactos como **Legacy DVR Compatibility Layer**. No se permite renombrado destructivo de migraciones previas ni propagación de la nomenclatura `dvr` a nuevas APIs o interfaces.

### 2.2. Coordinador de Mutaciones (Host/Fabric Mutation Coordinator)

Se sustituye la adquisición fail-fast de locks por un coordinador cooperativo:
- **Prioridad estricta:**
  $$\text{Interactive Operations (Commission / Install / Storage Migration)} > \text{Scheduled Reconciliation} > \text{Background Attestation}$$
- **Mecanismo:** Las operaciones interactivas encolan una solicitud de mutación con timeout configurable (30s) y backoff exponencial con jitter. Los reconciliadores de fondo detectan la intención interactiva y **ceden inmediatamente el lock**.
- **Checks de solo lectura:** Las verificaciones de salud (`health_gate`, readiness) se desacoplan totalmente del lock exclusivo de mutación.
- `MUTATION_BUSY` queda reservado únicamente para timeouts reales, operaciones trabadas o bloqueos externos.

### 2.3. Descubrimiento Normalizado de Storage Pools

Se introduce la jerarquía física de almacenamiento:
$$\text{Physical Device} \longrightarrow \text{Partition / LVM} \longrightarrow \text{Filesystem} \longrightarrow \text{Storage Pool} \longrightarrow \text{Actium Storage Binding}$$
- Se combinan `lsblk --json`, `blkid`, `/sys/block` y `statvfs`.
- Se filtran de forma determinista pseudo-filesystems (`tmpfs`, `overlay`, `cgroup`), bind mounts de systemd y rutas del sistema operativo (`/etc`, `/var`, `/run`, `/sys`, `/proc`).
- Se identifican Storage Pools físicos con clasificación de clases: `system`, `hot`, `warm`, `bulk`, `archive`.

### 2.4. Pre-enrollment StorageIntent vs. Post-enrollment StorageGrant

- **Antes del Enrolamiento (Wizard de Instalación):** La UI y el Supervisor operan con `StorageIntent`. Se evalúa el pool, la subruta, la clase de almacenamiento y se ejecuta un **Write-Probe activo** en vivo (`touch`, `write`, `fsync`, `unlink`).
- **Después del Enrolamiento:** Tras comisionar el nodo e intercambiar la identidad criptográfica soberana, el `StorageIntent` es promovido a un `StorageGrant` formalmente firmado y persistido en `grants.json`.

### 2.5. Aprovisionamiento Granular por Workload (`StorageAccessProfile`)

Se descarta el modelo de permisos planos `1000:1000 (0750)`. En su lugar:
- Cada capability/workload declara un contrato `StorageAccessProfile` con: `workload`, `runtime_uid`, `runtime_gid`, `supplemental_gids`, `required_mode`, `requires_posix_acl`, `requires_fsync`, `requires_locking`.
- El Supervisor aprovisiona los directorios asignando el UID/GID específico de cada servicio (PostgreSQL `999:999`, MinIO `1000:1000`, Prometheus `65534:65534`).
- Se aplican **POSIX Default ACLs** (`setfacl -d -m ...`) y herencia de grupo para garantizar que no existan errores `EACCES` en ningún disco de bahía montado.

### 2.6. Fabric Reubicable: Separación de Control State y Data State

Para evitar la saturación del disco de sistema operativo en despliegues con datos masivos:
- **Control State (Soberano en SSD / Sistema):** `/actium/fabrics/<fabric-id>/` almacena `state/`, `releases/`, `manifests/`, `locks/`, `identities/`, `metadata/`.
- **Data State (Reubicable en Storage Pool):** `<storage-pool>/actium/fabrics/<fabric-id>/data/` aloja los volúmenes pesados de PostgreSQL y NATS JetStream mediante un `FabricStorageBinding` auditable.

---

## 3. Consecuencias y Mapeo de Workstreams

1. **Actium Node Core:** Implementación de `MutationCoordinator`, `StoragePool`, `StorageIntent`, `StorageAccessProfile`, y `FabricStorageBinding`.
2. **Actium Node Supervisor:** Exposición de endpoints IPC para pools e intents, con integración de prioridad interactiva en los reconciliadores.
3. **Actium Node Manager (UI):** Rediseño del Paso 5 (Storage) en 2 modos claros (Monodisco y Desacoplado Industrial Split-Tier), con feedback de write-probe y adopción de `Telemetry History`.
4. **Data Plane Workloads (Docker Compose):** Actualización de `compose.fabric.yml`, `compose.telemetry.yml`, etc., para consumir variables de volumen efectivas y grupos suplementarios.
5. **Gate de Aceptación:** El comisionamiento exige validar `desired path == effective container volume == observed filesystem` con fsync y recovery exitoso.
