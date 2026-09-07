# M5.3 — Upgrade compatibility

M5.3 trata la instalación histórica como un fixture de actualización. El
instalador Debian no asume que el Supervisor previo pertenece a `dpkg`: puede
encontrarlo en `/usr/lib/actium/node-manager` y
`/usr/lib/actium/node-manager-lab`, conservando las unidades, configuración y
estado existentes.

## Contrato

Antes de cualquier modificación, el instalador ejecuta `--preflight` por canal
y verifica el Supervisor candidato (`--self-test` y `--build-info`), el layout
histórico, los servicios, las rutas de configuración, los directorios de
estado/datos, los symlinks no permitidos y el almacenamiento disponible.

La instalación crea un backup root-owned en
`/var/lib/actium/node-manager{,-lab}/upgrade-backups/<timestamp>-<pid>/` con:

- binario previo, unidad, configuración y drop-ins;
- identidad de Host, installation ID, trust/identity, journal y markers de
  estado;
- inventario SHA-256 de registry, Site/Host/Node metadata e intents, sin leer
  ni copiar `PAYLOAD.json`.

El estado bajo `/actium` y `/actium-lab` no se reinterpreta ni se reconstruye.
El instalador sólo actualiza el runtime y deja una evidencia hashable para
demostrar que registry, relaciones y estado durable no fueron alterados.

## Rollback e idempotencia

`--rollback <backup-dir>` sólo acepta backups bajo los directorios
`upgrade-backups` conocidos y restaura el canal, binario, unidad,
configuración, drop-ins y estado de control respaldados. Valida el binario
restaurado con `--check` y recupera el servicio si estaba activo.

La ruta de instalación normal conserva los backups y es repetible: reintentar
el mismo candidato no genera una nueva Host Identity, no cambia el
installation ID, no duplica nodos/grants ni modifica los artefactos legacy.

## Compatibilidad legacy

`PAYLOAD.json` sólo permanece como evidencia histórica del fixture. No se copia,
regenera ni usa como fuente durante el upgrade. La ausencia o presencia del
payload no define la identidad del Base Runtime.

El test `npm run test:m5-3-upgrade-compatibility` ejecuta el instalador contra
un fixture sintético con rutas espaciadas y un `.deb` real, cubriendo preflight
read-only, actualización, backup, rollback, reintento idempotente y
preservación de identidad/registry/Node metadata.
