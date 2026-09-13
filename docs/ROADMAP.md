# Roadmap Canónico de Actium Node Manager

Este documento define el mapa de ruta canónico de evolución e integración de **Actium Node Manager** en el ecosistema soberano Actium/Aegis.

---

## Hito F8: Arquitectura de Almacenamiento, Resiliencia y Control de Mutaciones

### Dependencias arquitectónicas cross-system de F8

- [OPEN] Reconciliar el contrato de almacenamiento físico entre Actium Node Manager, Fabric y los workloads del Data Plane.
- [OPEN] Implementar StoragePool / StorageIntent / FabricStorageBinding para evitar que paths declarados difieran de la persistencia efectiva.
- [OPEN] Sustituir la contención fail-fast `MUTATION_BUSY` entre reconciliadores y operaciones interactivas por coordinación de mutaciones.
- [DECIDED] `Telemetry History` es el nombre canónico del histórico GPS/telemetría. `Replay` es un consumidor de ese histórico.
- [DECIDED] Los contratos `dvr_*` existentes quedan como compatibilidad legacy y no deben propagarse a nuevos contratos del Data Plane.
- [DECIDED] `DVR` queda reservado para el futuro subsistema de grabación de Video Wall / VMS.
- [OPEN] El deployment debe soportar storage bindings reubicables por capability y storage class sin mover la identidad soberana del Fabric.

---

## Referencias Documentales
- [ADR 0001: Telemetry History, Storage Fabric y Reserva Semántica del Dominio DVR](adr/0001-telemetry-history-storage-fabric-and-dvr-namespace.md)
