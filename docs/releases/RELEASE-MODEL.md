# Release model

Una release es una referencia inmutable a un build existente. El comando de promoción no recompila:

```text
build candidate
  -> validar provenance, árbol limpio, pruebas y SHA
  -> preparar payload canónico de firma
  -> Authority Service Product Signing Authority firma
  -> emitir release-manifest@1.0.0
```

El manifiesto contiene `releaseId`, producto, versión, `buildId`, repositorio y commit fuente, plataforma, arquitectura, todos los artefactos con digest, compatibilidad y la firma externa de Product Signing Authority.

La clave/firma se entrega al comando como un envelope ya emitido por el Authority Service. Node Manager no genera Product Authority ni convierte un signer de prueba en signer productivo.

`release:prepare-signing` fija el manifiesto unsigned y el payload
domain-separated que Authority Service debe firmar. `release:promote` consume
la respuesta firmada, revalida el build y genera el manifiesto final. No se
acepta firma suelta por argumento de shell; el Supervisor vuelve a verificar
firma, cadena, revocación, capability, vigencia y binding del paquete al hacer
preflight/stage.

La identidad `(productId, version, platform, architecture)` es inmutable: sólo se considera idempotente cuando coinciden exactamente el manifiesto y su envelope firmado; si cambia cualquier contenido, provenance o firma, se rechaza.

Manager (`0.7.0-rc.3`), Supervisor (`0.5.21`) y Node Core conservan sus identidades de componente. M5.1 no los unifica artificialmente.
