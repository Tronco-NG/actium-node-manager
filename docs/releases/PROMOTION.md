# Promotion procedure

La promoción es deliberada y separada del build:

```powershell
npm run release:prepare-signing -- --build-id <candidate-build-id> --version 0.7.0-rc.3
npm run release:promote -- --signing-request <request.json> --signing-response <authority-response.json>
npm run release:channel -- --release-channel RC --release <release-id-or-manifest-path>
```

`release:prepare-signing` valida el build candidate y escribe una solicitud
inmutable en `dist/release-signing-requests/`. La solicitud contiene el
manifiesto sin firma, la capability `product_signing`, el payload exacto en
Base64URL y su SHA-256. El payload firmado es
`actium-release-manifest-v1`, un byte NUL y el JSON canónico del manifiesto,
igual al contrato que verifica Trust Fabric.

El operador entrega `payload` al `/v1/sign` de Authority Service con
`capability=product_signing`, usando la identidad autenticada y el contexto de
request/idempotency exigido por ese servicio. Guarda su respuesta JSON
(`keyId`, `signature`, `algorithm`) sin reformatear y pásala a
`release:promote`. El comando revalida el build, comprueba que la solicitud
corresponda exactamente a ese build y que la respuesta sea un envelope Ed25519
bien formado antes de escribir el manifiesto final. No recibe ni guarda claves
privadas. La verificación criptográfica y de cadena sigue siendo obligatoria
en preflight/stage del Supervisor contra el Trust Store del canal.

`DEV`, `RC` y `STABLE` son release tracks. `LAB`/`STABLE` son deployment environments y no se asignan con este comando. El paso LAB → STABLE requiere el deployment engine, smoke funcional y promotion receipt del mismo digest; el asignador de release track no sustituye esa evidencia.

La preparación verifica:

- manifest de build válido, `buildKind=candidate` y `status=BUILT`;
- repositorio `Tronco-NG/actium-node-manager` y remote canónico;
- árbol limpio y `sourceCommit` igual al `HEAD` actual;
- todos los artefactos presentes y con SHA-256 coincidente;
- evidencia de tests sin fallos;
- versión sin codificar un canal;
- unicidad y seguridad de los componentes de la identidad de release.

El finalize es inmutable: si ya existe la identidad, sólo es idempotente cuando
coinciden el manifiesto y el envelope; cualquier contenido distinto se rechaza.

No se ejecuta `npm run compile`, no se altera `target`, no se regenera PAYLOAD y no se inicia ningún despliegue remoto. La verificación criptográfica final del envelope firmado y su cadena corresponde a Trust Fabric durante preflight/stage del Supervisor.
