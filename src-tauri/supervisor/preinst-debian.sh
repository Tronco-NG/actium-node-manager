#!/bin/sh
set -eu

# Preserve the currently installed Authority executable before dpkg unpacks
# the new package into authority-package/ and removes the legacy resource path.
# This is a file-level recovery baseline only: it does not activate, stop, or
# restart Authority or either Supervisor channel.
ROOT_PREFIX=${DESTDIR:-}
case "$ROOT_PREFIX" in
  ""|/*) ;;
  *) echo "preinst: DESTDIR debe ser una ruta absoluta." >&2; exit 1 ;;
esac
rooted() {
  case "$1" in /*) printf '%s%s\n' "$ROOT_PREFIX" "$1" ;; *) return 1 ;; esac
}

if [ "$(id -u)" -ne 0 ]; then
  echo "preinst: la instalación debe ejecutarse como root." >&2
  exit 1
fi

preserve_supervisor_baseline() {
  channel=$1
  unit=$2
  state_path=$3
  packaged_binary=$4
  legacy_binary=$5
  state=$(rooted "$state_path")
  current=$state/current
  if [ -e "$current" ] || [ -L "$current" ]; then return 0; fi

  legacy_dir=$state/legacy
  target=$legacy_dir/actium-node-supervisor
  for directory in "$state" "$legacy_dir"; do
    if [ -L "$directory" ] || { [ -e "$directory" ] && [ ! -d "$directory" ]; }; then
      echo "preinst: ruta legacy de Supervisor inválida: $directory" >&2
      return 1
    fi
  done
  if [ -e "$target" ] || [ -L "$target" ]; then
    if [ -L "$target" ] || [ ! -f "$target" ]; then
      echo "preinst: baseline Supervisor $channel existente inválido." >&2
      return 1
    fi
    return 0
  fi

  active=0
  process_binary=
  if [ -z "$ROOT_PREFIX" ] && command -v systemctl >/dev/null 2>&1; then
    main_pid=$(systemctl show --property=MainPID --value "$unit" 2>/dev/null || true)
    case "$main_pid" in
      ''|*[!0-9]*) ;;
      *)
        if [ "$main_pid" -gt 1 ] 2>/dev/null && [ -f "/proc/$main_pid/exe" ]; then
          process_binary=/proc/$main_pid/exe
          active=1
        fi
        ;;
    esac
    if systemctl is-active --quiet "$unit"; then active=1; fi
  fi

  packaged=$(rooted "$packaged_binary")
  legacy=$(rooted "$legacy_binary")
  temporary=$legacy_dir/.actium-node-supervisor.$$.next
  if [ ! -d "$state" ]; then install -d -m 0700 -o root -g root "$state"; fi
  if [ ! -d "$legacy_dir" ]; then install -d -m 0700 -o root -g root "$legacy_dir"; fi
  copied=0
  for source in "$process_binary" "$packaged" "$legacy"; do
    [ -n "$source" ] && [ -f "$source" ] || continue
    if install -m 0750 -o root -g root "$source" "$temporary"; then
      mv -- "$temporary" "$target"
      copied=1
      break
    fi
    rm -f -- "$temporary"
  done
  if [ "$copied" -eq 0 ]; then
    if [ "$active" -eq 1 ]; then
      echo "preinst: Supervisor $channel activo sin baseline recuperable; se cancela antes de desempaquetar." >&2
      return 1
    fi
    return 0
  fi
  echo "preinst: se preservó Supervisor $channel sin activar el candidato."
}

preserve_supervisor_baseline stable actium-node-supervisor.service \
  /var/lib/actium/node-manager \
  "/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor" \
  /usr/lib/actium/node-manager/actium-node-supervisor
preserve_supervisor_baseline lab actium-node-supervisor-lab.service \
  /var/lib/actium/node-manager-lab \
  "/usr/lib/Actium Node Manager/supervisor/actium-node-supervisor" \
  /usr/lib/actium/node-manager-lab/actium-node-supervisor

OLD_AUTHORITY=$(rooted "/usr/lib/Actium Node Manager/authority/actium-authority-service")
if [ ! -e "$OLD_AUTHORITY" ]; then exit 0; fi
if [ -L "$OLD_AUTHORITY" ] || [ ! -f "$OLD_AUTHORITY" ]; then
  echo "preinst: la ruta legacy de Authority no es un archivo regular; se rechaza." >&2
  exit 1
fi

RUNTIME=$(rooted /var/lib/actium/authority-runtime)
LEGACY=$(rooted /var/lib/actium/authority-runtime/legacy)
TARGET=$LEGACY/actium-authority-service
for directory in "$RUNTIME" "$LEGACY"; do
  if [ -L "$directory" ] || { [ -e "$directory" ] && [ ! -d "$directory" ]; }; then
    echo "preinst: ruta de baseline Authority inválida: $directory" >&2
    exit 1
  fi
done
if [ -e "$TARGET" ]; then
  if [ -L "$TARGET" ] || [ ! -f "$TARGET" ]; then
    echo "preinst: baseline Authority existente inválido." >&2
    exit 1
  fi
  exit 0
fi

if getent group actium-authority >/dev/null 2>&1; then
  runtime_group=actium-authority
  runtime_mode=0750
else
  # A legacy executable without the service group cannot be running under the
  # packaged unit; keep the public executable readable without granting writes.
  runtime_group=root
  runtime_mode=0755
fi
if [ ! -d "$RUNTIME" ]; then install -d -m "$runtime_mode" -o root -g "$runtime_group" "$RUNTIME"; fi
if [ ! -d "$LEGACY" ]; then install -d -m "$runtime_mode" -o root -g "$runtime_group" "$LEGACY"; fi

temporary=$LEGACY/.actium-authority-service.$$.next
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
install -m "$runtime_mode" -o root -g "$runtime_group" "$OLD_AUTHORITY" "$temporary"
mv -- "$temporary" "$TARGET"
trap - EXIT HUP INT TERM
echo "preinst: se preservó el runtime Authority legacy sin activarlo."
