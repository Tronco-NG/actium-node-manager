# Promotion procedure

La promoción es deliberada y separada del build:

```powershell
npm run release:promote -- --build-id <candidate-build-id> --version 0.7.0-rc.3 --signing-key-id <key-id> --signature <signed-envelope>
npm run release:channel -- --channel lab --release <release-id-or-manifest-path>
```

El comando de promoción verifica:

- manifest de build válido, `buildKind=candidate` y `status=BUILT`;
- repositorio `Tronco-NG/actium-node-manager` y remote canónico;
- árbol limpio y `sourceCommit` igual al `HEAD` actual;
- todos los artefactos presentes y con SHA-256 coincidente;
- evidencia de tests sin fallos;
- versión sin codificar un canal;
- unicidad de la identidad de release.

No se ejecuta `npm run compile`, no se altera `target`, no se regenera PAYLOAD y no se inicia ningún despliegue remoto. La verificación criptográfica final del envelope firmado corresponde a Trust Fabric/Authority Service.
