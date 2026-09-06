# Dependencias Debian/Ubuntu

La resolución normal ocurre dentro de `apt install ./<paquete>.deb` mediante
el campo Debian `Depends`; el operador no ejecuta
`install-dependencies-debian.sh`. El `postinst` sólo verifica y habilita lo
que APT ya resolvió.

Dependencias de first install:

- `systemd`, `curl`, `ca-certificates`, `openssl`, `iproute2`;
- Docker Engine: `docker.io` o `docker-ce`;
- Compose v2: `docker-compose`, `docker-compose-plugin` o
  `docker-compose-v2`;
- runtime gráfico Debian/Ubuntu declarado por Tauri.

El `postinst` falla cerrado si no puede detectar Debian/Ubuntu mediante el
paquete soportado, si no existe systemd, si Docker no puede iniciar o si
`docker compose version` no responde. No usa `curl | sh` ni agrega un
repositorio opaco durante la instalación.

La matriz de soporte debe registrar distribución, codename y arquitectura en
la evidencia de cada aceptación. No se afirma soporte genérico para otras
distribuciones.
