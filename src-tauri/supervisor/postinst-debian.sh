#!/bin/sh
set -eu

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
"$SCRIPT" --channel "$CHANNEL" --install --binary "$BINARY"
