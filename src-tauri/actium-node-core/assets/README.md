# Core diagnostic adapters

`telemetry-audit.sql` es un adapter de diagnóstico de compatibilidad para el flujo Aegis existente. No es la implementación de `services/telemetry`, no define el runtime de Telemetry y no forma parte del payload canónico de Node Manager.

- Owner transitorio: Ecosistema Aegis (query/schema) y Actium Node Manager (ejecución privilegiada/redacción).
- Contrato: sólo consulta read-only sobre el schema runtime validado por el deployment.
- Motivo: preservar el comando IPC/UI de auditoría durante la extracción sin importar `services/telemetry`.
- Eliminación: cuando Aegis publique un contrato de diagnóstico versionado/firmado y el consumidor deje de requerir este adapter.

No agregar aquí servicios, migraciones de capability, secretos ni lógica de negocio Aegis.
