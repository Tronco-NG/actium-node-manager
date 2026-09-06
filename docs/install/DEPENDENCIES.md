# Dependencias Debian/Ubuntu

La resolución normal ocurre dentro de `apt install ./<paquete>.deb` mediante
el campo Debian `Depends`; el operador no ejecuta
`install-dependencies-debian.sh`. El `postinst` sólo verifica y habilita lo
que APT ya resolvió.

Dependencias de first install desde los repositorios APT de la distribución:

- `systemd`, `curl`, `ca-certificates`, `openssl`, `iproute2`;
- Docker Engine: `docker.io`;
- Compose v2: `docker-compose`;
- GTK: `libgtk-3-0` en Debian 12/Ubuntu compatibles o
  `libgtk-3-0t64` en Debian 13;
- runtime gráfico Debian/Ubuntu declarado por Tauri.

El builder normaliza el control generado del `.deb` después de Tauri para
expresar la transición GTK de Debian 12/13 como una alternativa APT:
`libgtk-3-0 | libgtk-3-0t64`. El artefacto se vuelve a inspeccionar con
`dpkg-deb` antes de copiarse al candidato; no se modifica el fuente de Aegis
ni se instala ningún paquete durante el build.

El `postinst` falla cerrado si no puede detectar Debian/Ubuntu mediante el
paquete soportado, si no existe systemd, si Docker no puede iniciar o si
`docker compose version` no responde. No usa `curl | sh` ni agrega un
repositorio Docker externo durante la instalación.

`install-dependencies-debian.sh` es únicamente un helper de recuperación
compatible. También usa exclusivamente los paquetes de la distribución; no
agrega keyrings, repositorios Docker ni instala `docker-ce`.

La matriz de soporte registra distribución, codename y arquitectura en la
evidencia de cada aceptación. Debian 12 y Ubuntu resuelven `libgtk-3-0`;
Debian 13 resuelve `libgtk-3-0t64`. No se afirma soporte genérico para otras
distribuciones ni se declaran `docker-ce`, `docker-compose-plugin` o
`docker-compose-v2` como requisitos.
