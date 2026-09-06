# Artifact immutability

Los artefactos se copian desde el output del build a un directorio identificado por digest. El `build-manifest.json` y `SHA256SUMS` registran nombre, URI, tamaño y SHA-256.

La promoción sólo referencia esos archivos; nunca recompila ni sobrescribe un build existente. Si una release ya existe, la combinación de versión, plataforma, arquitectura y artefactos debe ser idéntica para aceptar idempotencia. Cualquier cambio produce rechazo.

La extensión o bundle de Aegis sigue su propio contrato universal y no se incorpora silenciosamente desde `PAYLOAD.json`. El payload de Aegis permanece como artefacto legacy externo y congelado durante la transición.

No se persisten claves privadas en manifests, artefactos, logs o argumentos de build. Las firmas de producción son responsabilidad del Authority Service; los signers efímeros sólo aparecen en fixtures/tests.
