# M5.2 — First install del Base Runtime

Este contrato demuestra la instalación inicial de Actium Node Manager sobre
Debian o Ubuntu limpios usando únicamente el `.deb` generado por el build
oficial. El operador no ejecuta scripts internos ni prepara el Host a mano:

```bash
sudo apt install ./actium-node-manager_<version>_amd64.deb
```

El paquete resuelve sus dependencias declaradas, instala el Manager y el
Supervisor embebido de la misma build, crea usuarios, directorios, IPC y las
unidades systemd, y ejecuta el self-test/health antes de aceptar la
instalación.

El estado inicial válido es:

- `BASE_RUNTIME_READY`
- `NO_EXTENSIONS`
- `UNCLAIMED`
- `TRUST_NOT_INITIALIZED`
- `CONTROL_PLANE_UNCONFIGURED` o `DISCOVERY_PENDING`

Ninguno de esos estados es un fallo del Base Runtime. La instalación no
incluye Aegis ni el snapshot legacy `PAYLOAD.json`.

## Identidad

La build candidate registra `build_id`, `source_commit`, `source_dirty=false`,
`build_kind=candidate` y SHA-256 de cada artefacto. El Supervisor persiste su
identidad instalada en `/var/lib/actium/node-manager/build-identity.json`; la
UI obtiene la identidad del Manager y del Supervisor mediante sus contratos
de diagnóstico.

## Precondiciones del entorno

M5.2 soporta únicamente Debian y Ubuntu con `systemd`, arquitectura `amd64` y
acceso a los repositorios APT configurados. Docker Engine y Compose v2 son
dependencias del paquete y deben quedar activos para el Supervisor.
