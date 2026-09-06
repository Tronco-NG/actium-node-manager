# Plataformas soportadas por M5.2

| Distribución | Arquitectura | Init requerido | Estado |
|---|---|---|---|
| Debian 12 (bookworm) | amd64 | systemd | soportada para clean install |
| Debian 13 (trixie) | amd64 | systemd | soportada para clean install |
| Ubuntu LTS soportada por el runtime gráfico | amd64 | systemd | soportada, validar codename en acceptance |

Una instalación sin systemd, sin arquitectura amd64, sin repositorios APT
compatibles o sin Docker/Compose funcional falla cerrado. El primer install
usa exclusivamente `docker.io` + `docker-compose` y selecciona la variante
GTK disponible en la distribución. Windows mantiene su acceptance NSIS
separado; M5.2 no amplía esa matriz.
