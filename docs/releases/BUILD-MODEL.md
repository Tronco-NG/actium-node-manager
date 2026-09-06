# Build model

Actium Node Manager distingue cuatro identidades que no deben mezclarse:

1. **Build**: una ejecución concreta del builder, identificada por `build_id`.
2. **Artifact**: un archivo inmutable identificado por su SHA-256.
3. **Release**: la promoción explícita de un build candidate a una versión de producto.
4. **Channel**: una asignación independiente (`lab` o `stable`) de una release existente.

`npm run compile` sólo ejecuta BUILD. No incrementa versiones, no firma, no crea releases, no asigna canales y no modifica el payload legacy.

Cada build escribe, bajo `dist/builds/<build-id>/`:

- `build-manifest.json` (`actium-build-manifest@1.0.0`);
- `SHA256SUMS`;
- copias de los artefactos generados.

También conserva una copia content-addressed bajo `dist/artifacts/sha256/<digest>/`.

Un build `development` puede partir de un árbol sucio y nunca es promocionable. Un build `candidate` exige árbol limpio, `HEAD` real del repositorio canónico y evidencia de pruebas exitosa. `ACTIUM_SOURCE_COMMIT` sólo se acepta si coincide exactamente con `git rev-parse HEAD`; un override stale se rechaza.

El build no contiene identidad de Client, Organization, Site, Host ni un canal compilado. Stable y Lab usan la misma versión de producto; el canal pertenece al despliegue o a la asignación de release.
