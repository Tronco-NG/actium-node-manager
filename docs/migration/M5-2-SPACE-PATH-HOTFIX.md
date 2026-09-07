# M5.2 — Hotfix de rutas Debian con espacios

## Causa

El postinst encuentra correctamente los recursos Tauri bajo:

    /usr/lib/Actium Node Manager/supervisor/

pero la sustitución de comandos de install-supervisor-debian.sh ejecutaba el
binario como:

    build_identity="$($binary --build-info)"

Cuando binary contenía espacios, POSIX separaba el valor y el proceso
intentaba ejecutar /usr/lib/Actium. La forma corregida conserva el binario
como un único argumento:

    build_identity="$("$binary" --build-info)"

## Alcance

- Todas las rutas de instalación, staging, backup, rollback y health del
  instalador Debian se construyen y pasan entre comandos con comillas.
- DESTDIR sólo se utiliza como prefijo estándar de staging para pruebas
  aisladas; sin esa variable el comportamiento productivo continúa usando /.
- No se usa eval ni se serializan comandos para ejecutarlos como strings.
- postinst-debian.sh mantiene el path Tauri con espacios como un único
  argumento y no recibe datos de identidad del operador.
- No se tocó PAYLOAD.json, Aegis, Center, NAS ni el proceso de aceptación.

## Cobertura

El comando npm run test:m5-2-space-paths extrae un .deb real en WSL a una
ruta con espacios, ejecuta --build-info y --self-test del Supervisor
empaquetado, ejecuta el instalador con el binario bajo el path Tauri real, y
prueba:

- staging y unidad systemd;
- framing IPC mediante --self-test;
- rollback de validación desde una instalación half-configured;
- rollback ante fallo de restart/health;
- reinstalación idempotente de la misma versión.

La aceptación real con apt install queda fuera de este hotfix y debe ser
ejecutada por el operador sobre el candidato nuevo.
