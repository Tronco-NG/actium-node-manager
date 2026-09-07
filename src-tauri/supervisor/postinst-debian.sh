#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "postinst: la instalación debe ejecutarse como root." >&2
  exit 1
fi

if [ ! -d /run/systemd/system ]; then
  echo "postinst: systemd no está disponible; se requiere una instalación Debian/Ubuntu con systemd." >&2
  exit 1
fi

if [ ! -r /etc/os-release ]; then
  echo "postinst: no se pudo identificar la distribución." >&2
  exit 1
fi
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ;;
  *)
    echo "postinst: sólo Debian y Ubuntu están soportados (detectado: ${ID:-desconocido})." >&2
    exit 1
    ;;
esac
if [ "$(dpkg --print-architecture 2>/dev/null || true)" != "amd64" ]; then
  echo "postinst: este artefacto sólo soporta arquitectura amd64." >&2
  exit 1
fi

command -v systemctl >/dev/null 2>&1 || {
  echo "postinst: falta systemctl; distribución no soportada." >&2
  exit 1
}
command -v docker >/dev/null 2>&1 || {
  echo "postinst: falta Docker Engine; apt debe resolver docker.io antes de configurar este paquete." >&2
  exit 1
}

systemctl enable --now docker.service || {
  echo "postinst: no se pudo habilitar/iniciar Docker Engine." >&2
  exit 1
}

docker info >/dev/null 2>&1 || {
  echo "postinst: Docker Engine no responde; se aborta sin registrar el Supervisor." >&2
  exit 1
}
docker compose version >/dev/null 2>&1 || {
  echo "postinst: falta Docker Compose v2; apt debe resolver docker-compose antes de configurar este paquete." >&2
  exit 1
}

first_existing() {
  for candidate in "$@"; do
    if [ -e "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

PREFIX=$(first_existing \
  "/usr/lib/Actium Node Manager" \
  "/usr/lib/actium-node-manager") || {
  echo "postinst: no se encontro el prefijo instalado de Actium Node Manager." >&2
  exit 1
}

SUPERVISOR_DIR=$(first_existing \
  "$PREFIX/supervisor" \
  "$PREFIX/resources/supervisor") || {
  echo "postinst: no se encontro el Supervisor embebido en $PREFIX." >&2
  exit 1
}

SCRIPT="$SUPERVISOR_DIR/install-supervisor-debian.sh"
BINARY="$SUPERVISOR_DIR/actium-node-supervisor"
if [ ! -f "$SCRIPT" ] || [ ! -f "$BINARY" ]; then
  echo "postinst: faltan install-supervisor-debian.sh o actium-node-supervisor en $SUPERVISOR_DIR." >&2
  exit 1
fi

chmod 0755 "$SCRIPT" "$BINARY"

CHANNEL=stable
if [ -f "$SUPERVISOR_DIR/actium-node-supervisor-lab.service" ] && {
  [ -f /etc/systemd/system/actium-node-supervisor-lab.service ] ||
    [ -x /usr/lib/actium/node-manager-lab/actium-node-supervisor ]
}; then
  CHANNEL=both
fi

if [ ! -d /run/systemd/system ]; then
  echo "postinst: systemd no esta disponible; no se puede registrar Actium Node Supervisor." >&2
  exit 1
fi

echo "Actualizando Actium Node Supervisor ($CHANNEL) desde $BINARY"
"$SCRIPT" --channel "$CHANNEL" --preflight --binary "$BINARY"
"$SCRIPT" --channel "$CHANNEL" --install --binary "$BINARY"
