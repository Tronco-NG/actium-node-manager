# Release channels

Los canales de release son estado de distribución, no versiones SemVer:

- `DEV`
- `RC`
- `STABLE`

`LAB` no es un canal de release: es un entorno de despliegue/validación independiente. Una misma identidad de artefacto puede validarse en el entorno LAB y luego converger a STABLE, sin rebuild. El builder no recibe `--release-channel` y no produce versiones `*-dev.*`, `*-rc.*` o `*-stable.*`; el track va en la asignación de release.

La asignación se persiste separadamente en `dist/channels/<release-channel>.json` mediante `actium-release-channel@2.0.0`. Un canal ya asignado a una release diferente falla cerrado.

En el runtime, `deployment_environment` describe dónde está instalado el artefacto (`LAB` o `STABLE`). `release_channel`, `release_version`, `build_id`, `source_commit` y `artifact_sha256` describen qué artefacto está instalado. `runtime_release` y metadata de PAYLOAD son campos legacy de compatibilidad, no la fuente de identidad de la release.
