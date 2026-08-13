#!/bin/sh
set -eu

binary=""
payload=""
start_service="true"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --payload)
      payload="${2:-}"
      shift 2
      ;;
    --no-start)
      start_service="false"
      shift
      ;;
    *)
      echo "Argumento no reconocido: $1" >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecute este instalador con sudo." >&2
  exit 1
fi
if [ -z "$binary" ] || [ ! -f "$binary" ]; then
  echo "Use --binary con el ejecutable Linux de actium-node-supervisor." >&2
  exit 1
fi
if [ -z "$payload" ] || [ ! -f "$payload/PAYLOAD.json" ]; then
  echo "Use --payload con un bundle schema 3 verificado." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI no esta instalado." >&2
  exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL no esta instalado." >&2
  exit 1
fi

"$binary" --self-test
"$binary" --verify-payload "$payload"

groupadd --system --force actium-node-operators
install -d -m 0755 /etc/actium/node-manager
install -d -m 0750 /var/lib/actium/node-manager /var/log/actium/node-manager
install -d -m 0770 -o root -g actium-node-operators /srv/actium-data/nodes /srv/actium-data/fabrics
install -d -m 0755 /usr/lib/actium/node-manager /usr/share/doc/actium-node-supervisor
install -m 0755 "$binary" /usr/lib/actium/node-manager/actium-node-supervisor.next
install -m 0644 "$script_dir/supervisor.toml" /etc/actium/node-manager/supervisor.toml.dist
if [ ! -f /etc/actium/node-manager/supervisor.toml ]; then
  install -m 0644 "$script_dir/supervisor.toml" /etc/actium/node-manager/supervisor.toml
fi
install -m 0644 "$script_dir/actium-node-supervisor.service" /etc/systemd/system/actium-node-supervisor.service

if [ ! -f /etc/actium/node-manager/ipc.key ]; then
  umask 0077
  openssl rand -base64 48 > /etc/actium/node-manager/ipc.key
fi
chown root:actium-node-operators /etc/actium/node-manager/ipc.key
chmod 0640 /etc/actium/node-manager/ipc.key

payload_target="/usr/lib/actium/node-manager/payload"
staging_target="/usr/lib/actium/node-manager/payload.next"
rm -rf -- "$staging_target"
install -d -m 0755 "$staging_target"
cp -a "$payload/." "$staging_target/"
service_was_active="false"
if systemctl is-active --quiet actium-node-supervisor.service; then
  service_was_active="true"
  systemctl stop actium-node-supervisor.service
fi
if [ -d "$payload_target" ]; then
  rm -rf -- "/usr/lib/actium/node-manager/payload.previous"
  mv "$payload_target" "/usr/lib/actium/node-manager/payload.previous"
fi
mv "$staging_target" "$payload_target"
if [ -f /usr/lib/actium/node-manager/actium-node-supervisor ]; then
  rm -f -- /usr/lib/actium/node-manager/actium-node-supervisor.previous
  mv /usr/lib/actium/node-manager/actium-node-supervisor /usr/lib/actium/node-manager/actium-node-supervisor.previous
fi
mv /usr/lib/actium/node-manager/actium-node-supervisor.next /usr/lib/actium/node-manager/actium-node-supervisor

systemctl daemon-reload
if ! /usr/lib/actium/node-manager/actium-node-supervisor --config /etc/actium/node-manager/supervisor.toml --check; then
  if [ -f /usr/lib/actium/node-manager/actium-node-supervisor.previous ]; then
    mv /usr/lib/actium/node-manager/actium-node-supervisor.previous /usr/lib/actium/node-manager/actium-node-supervisor
  fi
  if [ -d /usr/lib/actium/node-manager/payload.previous ]; then
    rm -rf -- /usr/lib/actium/node-manager/payload
    mv /usr/lib/actium/node-manager/payload.previous /usr/lib/actium/node-manager/payload
  fi
  systemctl daemon-reload
  if [ "$service_was_active" = "true" ]; then
    systemctl restart actium-node-supervisor.service
  fi
  echo "La validacion final fallo; se restauro el binario/payload anterior." >&2
  exit 1
fi
if [ "$start_service" = "true" ]; then
  systemctl enable actium-node-supervisor.service
  systemctl restart actium-node-supervisor.service
fi

echo "Actium Node Supervisor 0.2.0 instalado."
echo "Agregue operadores con: sudo usermod -aG actium-node-operators USUARIO"
