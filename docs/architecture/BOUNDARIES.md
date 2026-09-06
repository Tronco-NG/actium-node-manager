# Actium Node Manager — Bounded Context

## Propósito

`Tronco-NG/actium-node-manager` será la plataforma universal de lifecycle, identidad operacional, storage/discovery local, Supervisor, IPC, trust/enrollment, release/update y diagnostics de un Host Actium.

No es `Aegis Node Manager`. Ecosistema Aegis es un consumidor y proveedor de capabilities mediante contratos/adapters. Actium Center es el control plane soberano y owner de sus funciones server-side.

## Dentro de Node Manager

- UI/runtime Tauri del Manager.
- `Node Core` transaccional y durable.
- Supervisor privilegiado y sus service units.
- Host identity, binding, epoch, journal y recovery.
- Storage discovery, grants y filesystem boundaries.
- IPC typed y lifecycle/update/rollback.
- Host Enrollment machine orchestration:
  `hen_* → challenge → Supervisor PoP → Center complete → pending_apply → EnrollmentPackage → apply → signed ACK → confirm`.
- Trust store, verification y build identity (`source_commit`, `build_id`, `binary_sha256`).
- Contratos propios de runtime/platform y release tooling.

## Fuera de Node Manager

- Owner/AAL2 ticket issuance y políticas humanas de Center.
- Center Edge Functions, migrations, RLS, release registry y Site/Organization authority.
- Aegis Control local backend y lógica de negocio de People, Radio, Site Core o Telemetry.
- Secret material de Center/Supervisor.

## Estado de transición

Durante M1/M2 se aceptan adapters de compatibilidad, pero cada uno debe declarar owner, contrato, observabilidad y condición de retiro. Un snapshot generado dentro de `resources/node` no tiene autoridad sobre la fuente que lo produjo.

Desde M2, el switch canónico está fijado: el source de Node Manager no se
mantiene en Aegis. Aegis consume contratos y adapters, mientras sus bundles de
capabilities permanecen externos al base runtime universal.

## Trust boundary

```text
Human Owner + AAL2
  → Actium Center ticket issuance
  → hen_* en memoria del Manager
  → Center challenge con scope autenticado
  → Supervisor PoP
  → Center authority signs bundle/package
  → Supervisor applies fail-closed
  → signed ACK
  → Center confirms and promotes enrolled/trusted
```

El Manager nunca decide por sí solo `enrolled/trusted`; UI guards no sustituyen las verificaciones de Center, Supervisor o RLS.

## Universal release

Un release es un artefacto universal. No se compila por cliente, Organization,
Site u Host. El Base Runtime no requiere `PAYLOAD.json`; la configuración y los
bundles de capacidades son runtime state/artefactos externos firmados. Las
capacidades Aegis se integran por manifest/adapters, no por forks de Node
Manager. Un digest de payload sólo se expone cuando existe un bundle externo
compatible.
