# Plataformas soportadas por M5.2

| Distribución | Arquitectura | Init requerido | Estado |
|---|---|---|---|
| Debian 13 (trixie) | amd64 | systemd | soportada para clean install |
| Ubuntu LTS con paquetes Docker/Compose v2 disponibles | amd64 | systemd | soportada, validar codename en acceptance |

Una instalación sin systemd, sin arquitectura amd64, sin repositorios APT
compatibles o sin Docker/Compose funcional falla cerrado. Windows mantiene su
acceptance NSIS separado; M5.2 no amplía esa matriz.
