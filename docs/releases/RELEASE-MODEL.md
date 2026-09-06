# Release model

Una release es una referencia inmutable a un build existente. El comando de promoción no recompila:

```text
build candidate
  -> validar provenance, árbol limpio, pruebas y SHA
  -> emitir release-manifest@1.0.0
```

El manifiesto contiene `releaseId`, producto, versión, `buildId`, repositorio y commit fuente, plataforma, arquitectura, todos los artefactos con digest, compatibilidad y la firma externa de Product Signing Authority.

La clave/firma se entrega al comando como un envelope ya emitido por el Authority Service. Node Manager no genera Product Authority ni convierte un signer de prueba en signer productivo.

La identidad `(productId, version, platform, architecture)` es inmutable: si ya existe con los mismos artefactos, la operación es idempotente; si cambia cualquier artefacto o provenance, se rechaza.

Manager (`0.7.0-rc.3`), Supervisor (`0.5.21`) y Node Core conservan sus identidades de componente. M5.1 no los unifica artificialmente.
