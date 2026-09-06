# Estado persistente y reinstalación

El programa instalado y el estado del Host tienen ownership separado.

## Estado persistente

- `/var/lib/actium/node-manager/identity/`: Host Identity física;
- `/var/lib/actium/node-manager/extensions/`: registry y lifecycle de
  extensiones;
- `/var/lib/actium/node-manager/trust/`: Trust Store público;
- `/var/lib/actium/node-manager/operations.sqlite3`: journal operacional;
- `/etc/actium/node-manager/`: configuración e IPC;
- `/var/log/actium/node-manager/`: logs.

La primera instalación crea Host Identity local, registry vacío, directorios
de extensión y Trust Store estructuralmente vacío. No crea Product Root,
Deployment Root ni Enrollment Authority.

Las reinstalaciones del mismo paquete conservan identidad, IPC, configuración,
grants y trust state. El Supervisor conserva una copia anterior del binario y
restaura unidad, configuración y binary si falla `check`, socket o health.
