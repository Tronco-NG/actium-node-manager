#!/bin/sh
set -eu

# dpkg owns package files and systemd unit registration only.  Channel config,
# Trust Store validation, activation, health checks and rollback are owned by
# `actium-node-supervisor deployment`; a channel failure must never leave dpkg
# half-configured.

# DESTDIR is used by the packaging integration test to exercise postinst in an
# isolated filesystem tree. dpkg normally invokes postinst with it unset.
ROOT_PREFIX=${DESTDIR:-}
case "$ROOT_PREFIX" in
  ""|/*) ;;
  *) echo "postinst: DESTDIR debe ser una ruta absoluta." >&2; exit 1 ;;
esac
rooted() {
  case "$1" in /*) printf '%s%s\n' "$ROOT_PREFIX" "$1" ;; *) return 1 ;; esac
}

if [ "$(id -u)" -ne 0 ]; then
  echo "postinst: la instalación debe ejecutarse como root." >&2
  exit 1
fi
OS_RELEASE=$(rooted /etc/os-release)
if [ ! -r "$OS_RELEASE" ]; then
  echo "postinst: no se pudo identificar la distribución." >&2
  exit 1
fi
. "$OS_RELEASE"
case "${ID:-}" in
  debian|ubuntu) ;;
  *) echo "postinst: sólo Debian y Ubuntu están soportados." >&2; exit 1 ;;
esac
if [ "$(dpkg --print-architecture 2>/dev/null || true)" != "amd64" ]; then
  echo "postinst: este artefacto sólo soporta arquitectura amd64." >&2
  exit 1
fi
command -v systemctl >/dev/null 2>&1 || {
  echo "postinst: falta systemctl; distribución no soportada." >&2
  exit 1
}

first_existing() {
  for candidate in "$@"; do
    if [ -d "$candidate" ]; then printf '%s\n' "$candidate"; return 0; fi
  done
  return 1
}
ensure_owned_dir_if_missing() {
  path=$1 mode=$2 owner=$3 group=$4
  if [ -L "$path" ]; then
    echo "postinst: se rechaza una ruta de estado que es symlink: $path" >&2
    exit 1
  fi
  if [ ! -d "$path" ]; then install -d -m "$mode" -o "$owner" -g "$group" "$path"; fi
}
ensure_authority_runtime_dir() {
  path=$1
  if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
    echo "postinst: se rechaza una ruta de runtime Authority inválida: $path" >&2
    exit 1
  fi
  if [ ! -d "$path" ]; then install -d -m 0750 -o root -g actium-authority "$path"; fi
  chown root:actium-authority "$path"
  chmod 0750 "$path"
}

PREFIX=$(first_existing "$(rooted "/usr/lib/Actium Node Manager")" "$(rooted /usr/lib/actium-node-manager)") || {
  echo "postinst: no se encontró el prefijo instalado de Actium Node Manager." >&2
  exit 1
}
SUPERVISOR_DIR=$(first_existing "$PREFIX/supervisor" "$PREFIX/resources/supervisor") || {
  echo "postinst: no se encontró el runtime Supervisor del paquete." >&2
  exit 1
}
AUTHORITY_DIR=$(first_existing "$PREFIX/authority-package" "$PREFIX/resources/authority") || {
  echo "postinst: no se encontró el runtime Authority del paquete." >&2
  exit 1
}

for asset in \
  "$SUPERVISOR_DIR/actium-node-supervisor" \
  "$SUPERVISOR_DIR/actium-node-supervisor.service" \
  "$SUPERVISOR_DIR/actium-node-supervisor-lab.service" \
  "$SUPERVISOR_DIR/actium-node-deployment-reconcile.service" \
  "$SUPERVISOR_DIR/zz-actium-node-supervisor-deployment.conf" \
  "$SUPERVISOR_DIR/zz-actium-node-supervisor-lab-deployment.conf" \
  "$SUPERVISOR_DIR/zz-actium-authority-deployment.conf" \
  "$SUPERVISOR_DIR/supervisor.toml" \
  "$SUPERVISOR_DIR/supervisor.lab.toml" \
  "$SUPERVISOR_DIR/compatibility-manifest.json" \
  "$AUTHORITY_DIR/actium-authority-service" \
  "$AUTHORITY_DIR/actium-authority-ceremony" \
  "$AUTHORITY_DIR/actium-authority-rebuild-trust-bundle" \
  "$AUTHORITY_DIR/actium-authority.service"; do
  if [ ! -f "$asset" ]; then echo "postinst: falta un asset del paquete: $asset" >&2; exit 1; fi
done

AUTHORITY_STATE=$(rooted /var/lib/actium/authority)
AUTHORITY_CONFIG=$(rooted /etc/actium/authority)
OFFLINE_ROOT=$(rooted /srv/actium-data/authority-offline-root)
RECOVERY_ROOT=$(rooted /srv/actium-data/authority-recovery)
STABLE_STATE=$(rooted /var/lib/actium/node-manager)
LAB_STATE=$(rooted /var/lib/actium/node-manager-lab)
STABLE_CONFIG=$(rooted /etc/actium/node-manager)
LAB_CONFIG=$(rooted /etc/actium/node-manager-lab)
STABLE_TRUST=$(rooted /var/lib/actium/node-manager/trust)
LAB_TRUST=$(rooted /var/lib/actium/node-manager-lab/trust)
AUTHORITY_RUNTIME=$(rooted /var/lib/actium/authority-runtime)
SYSTEMD_ROOT=$(rooted /lib/systemd/system)

if ! getent group actium-authority >/dev/null 2>&1; then groupadd --system actium-authority; fi
if ! getent passwd actium-authority >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir "$AUTHORITY_STATE" \
    --shell /usr/sbin/nologin --gid actium-authority actium-authority
fi

# Create absent support directories only. Existing Authority custody, trust,
# lifecycle and sealing files are deliberately not read, replaced or re-owned.
ensure_owned_dir_if_missing "$AUTHORITY_STATE" 0770 actium-authority actium-authority
ensure_owned_dir_if_missing "$AUTHORITY_CONFIG" 0770 actium-authority actium-authority
ensure_owned_dir_if_missing "$OFFLINE_ROOT" 0700 root root
ensure_owned_dir_if_missing "$RECOVERY_ROOT" 0700 root root
ensure_owned_dir_if_missing "$STABLE_STATE" 0700 root root
ensure_owned_dir_if_missing "$STABLE_STATE/deployments" 0700 root root
ensure_owned_dir_if_missing "$LAB_STATE" 0700 root root
ensure_owned_dir_if_missing "$LAB_STATE/deployments" 0700 root root
ensure_authority_runtime_dir "$AUTHORITY_RUNTIME"
ensure_authority_runtime_dir "$AUTHORITY_RUNTIME/deployments"
if [ -e "$AUTHORITY_RUNTIME/legacy" ] || [ -L "$AUTHORITY_RUNTIME/legacy" ]; then
  ensure_authority_runtime_dir "$AUTHORITY_RUNTIME/legacy"
  legacy_authority="$AUTHORITY_RUNTIME/legacy/actium-authority-service"
  if [ -e "$legacy_authority" ] || [ -L "$legacy_authority" ]; then
    if [ -L "$legacy_authority" ] || [ ! -f "$legacy_authority" ]; then
      echo "postinst: baseline Authority legacy inválido." >&2
      exit 1
    fi
    chown root:actium-authority "$legacy_authority"
    chmod 0750 "$legacy_authority"
  fi
fi
ensure_owned_dir_if_missing "$STABLE_CONFIG" 0700 root root
ensure_owned_dir_if_missing "$LAB_CONFIG" 0700 root root
ensure_owned_dir_if_missing "$STABLE_TRUST" 0700 root root
ensure_owned_dir_if_missing "$LAB_TRUST" 0700 root root

# Seed only absent configs; an upgrade never overwrites operator configuration.
if [ ! -e "$STABLE_CONFIG/supervisor.toml" ]; then
  install -m 0600 "$SUPERVISOR_DIR/supervisor.toml" "$STABLE_CONFIG/supervisor.toml"
elif [ -L "$STABLE_CONFIG/supervisor.toml" ]; then
  echo "postinst: no se acepta una config Supervisor symlink." >&2
  exit 1
fi
if [ ! -e "$LAB_CONFIG/supervisor.toml" ]; then
  install -m 0600 "$SUPERVISOR_DIR/supervisor.lab.toml" "$LAB_CONFIG/supervisor.toml"
elif [ -L "$LAB_CONFIG/supervisor.toml" ]; then
  echo "postinst: no se acepta una config Supervisor Lab symlink." >&2
  exit 1
fi

chmod 0755 \
  "$SUPERVISOR_DIR/actium-node-supervisor" \
  "$AUTHORITY_DIR/actium-authority-service" \
  "$AUTHORITY_DIR/actium-authority-ceremony" \
  "$AUTHORITY_DIR/actium-authority-rebuild-trust-bundle"
install -d -m 0755 "$SYSTEMD_ROOT"
install -m 0644 "$SUPERVISOR_DIR/actium-node-supervisor.service" \
  "$SYSTEMD_ROOT/actium-node-supervisor.service"
install -m 0644 "$SUPERVISOR_DIR/actium-node-supervisor-lab.service" \
  "$SYSTEMD_ROOT/actium-node-supervisor-lab.service"
install -m 0644 "$SUPERVISOR_DIR/actium-node-deployment-reconcile.service" \
  "$SYSTEMD_ROOT/actium-node-deployment-reconcile.service"
install -m 0644 "$AUTHORITY_DIR/actium-authority.service" \
  "$SYSTEMD_ROOT/actium-authority.service"
install -d -m 0755 \
  "$SYSTEMD_ROOT/actium-node-supervisor.service.d" \
  "$SYSTEMD_ROOT/actium-node-supervisor-lab.service.d" \
  "$SYSTEMD_ROOT/actium-authority.service.d"
install -m 0644 "$SUPERVISOR_DIR/zz-actium-node-supervisor-deployment.conf" \
  "$SYSTEMD_ROOT/actium-node-supervisor.service.d/zz-actium-deployment-runtime.conf"
install -m 0644 "$SUPERVISOR_DIR/zz-actium-node-supervisor-lab-deployment.conf" \
  "$SYSTEMD_ROOT/actium-node-supervisor-lab.service.d/zz-actium-deployment-runtime.conf"
install -m 0644 "$SUPERVISOR_DIR/zz-actium-authority-deployment.conf" \
  "$SYSTEMD_ROOT/actium-authority.service.d/zz-actium-deployment-runtime.conf"
systemctl daemon-reload
systemctl enable actium-authority.service
systemctl enable actium-node-deployment-reconcile.service

echo "Actium Node Manager package configured; channel deployment is an explicit transaction."
