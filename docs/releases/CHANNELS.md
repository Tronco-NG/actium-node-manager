# Release channels

Los canales son estado de distribución, no versiones SemVer:

- `lab`
- `stable`

Una misma release puede asignarse a `lab` y posteriormente a `stable`. El builder nunca recibe `--channel` y no produce versiones `*-lab.*` o `*-stable.*`. El identificador de producto continúa siendo `0.7.0-rc.3` mientras esa sea la versión vigente.

La asignación se persiste separadamente en `dist/channels/<channel>.json` mediante `actium-release-channel@1.0.0`. Un canal ya asignado a una release diferente falla cerrado.

En el runtime, `deploy_channel` describe dónde está instalado el artefacto. `release_version`, `build_id`, `source_commit` y `artifact_sha256` describen qué artefacto está instalado. `runtime_release` y metadata de PAYLOAD son campos legacy de compatibilidad, no la fuente de identidad de la release.
