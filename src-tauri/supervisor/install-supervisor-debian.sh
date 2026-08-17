#!/bin/sh
set -eu

binary=""
payload=""
channel="lab"
start_service="true"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) binary="${2:-}"; shift 2 ;;
    --payload) payload="${2:-}"; shift 2 ;;
    --channel) channel="${2:-}"; shift 2 ;;
    --no-start) start_service="false"; shift ;;
    *) echo "Argumento no reconocido: $1" >&2; exit 2 ;;
  esac
done

if [ "$channel" != "lab" ] && [ "$channel" != "stable" ]; then
  echo "--channel debe ser lab o stable." >&2
  exit 2
fi
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
command -v docker >/dev/null 2>&1 || { echo "Docker CLI no esta instalado." >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL no esta instalado." >&2; exit 1; }

if [ "$channel" = "lab" ]; then
  config_dir=/etc/actium/node-manager-lab
  state_dir=/var/lib/actium/node-manager-lab
  log_dir=/var/log/actium/node-manager-lab
  data_root=/srv/actium-lab
  lib_dir=/usr/lib/actium/node-manager-lab
  config_template=supervisor.lab.toml
  unit_template=actium-node-supervisor-lab.service
  service=actium-node-supervisor-lab.service
else
  config_dir=/etc/actium/node-manager
  state_dir=/var/lib/actium/node-manager
  log_dir=/var/log/actium/node-manager
  data_root=/srv/actium-data
  lib_dir=/usr/lib/actium/node-manager
  config_template=supervisor.toml
  unit_template=actium-node-supervisor.service
  service=actium-node-supervisor.service
fi
nodes_root="$data_root/nodes"
fabrics_root="$data_root/fabrics"
config_path="$config_dir/supervisor.toml"
key_path="$config_dir/ipc.key"
marker_path="$state_dir/root-ownership.json"
payload_target="$lib_dir/payload"
payload_next="$lib_dir/payload.next"
payload_previous="$lib_dir/payload.previous"
binary_target="$lib_dir/actium-node-supervisor"
binary_next="$lib_dir/actium-node-supervisor.next"
binary_previous="$lib_dir/actium-node-supervisor.previous"

"$binary" --self-test
"$binary" --verify-payload "$payload"

groupadd --system --force actium-node-operators
install -d -m 0755 "$config_dir" "$lib_dir" /usr/share/doc/actium-node-supervisor
install -d -m 0750 "$state_dir" "$log_dir"
install -d -m 0750 -o root -g actium-node-operators "$nodes_root" "$fabrics_root"
install -m 0755 "$binary" "$binary_next"
install -m 0644 "$script_dir/$config_template" "$config_path.dist"
if [ ! -f "$config_path" ]; then
  install -m 0644 "$script_dir/$config_template" "$config_path"
fi
install -m 0644 "$script_dir/$unit_template" "/etc/systemd/system/$service"

if [ ! -f "$key_path" ]; then
  umask 0077
  openssl rand -base64 48 > "$key_path"
fi
chown root:actium-node-operators "$key_path"
chmod 0640 "$key_path"

if [ ! -f "$marker_path" ]; then
  root_id=$(cat /proc/sys/kernel/random/uuid)
  umask 0077
  printf '{\n  "schema": 1,\n  "owner": "actium-node-supervisor",\n  "productChannel": "%s",\n  "rootId": "%s",\n  "authorizedNodesRoot": "%s",\n  "authorizedFabricsRoot": "%s"\n}\n' \
    "$channel" "$root_id" "$nodes_root" "$fabrics_root" > "$marker_path"
fi

rm -rf -- "$payload_next"
install -d -m 0755 "$payload_next"
cp -a "$payload/." "$payload_next/"
service_was_active="false"
if systemctl is-active --quiet "$service"; then
  service_was_active="true"
  systemctl stop "$service"
fi
rm -rf -- "$payload_previous"
if [ -d "$payload_target" ]; then mv "$payload_target" "$payload_previous"; fi
mv "$payload_next" "$payload_target"
rm -f -- "$binary_previous"
if [ -f "$binary_target" ]; then mv "$binary_target" "$binary_previous"; fi
mv "$binary_next" "$binary_target"

systemctl daemon-reload
if ! "$binary_target" --config "$config_path" --check; then
  if [ -f "$binary_previous" ]; then mv "$binary_previous" "$binary_target"; fi
  if [ -d "$payload_previous" ]; then
    rm -rf -- "$payload_target"
    mv "$payload_previous" "$payload_target"
  fi
  systemctl daemon-reload
  if [ "$service_was_active" = "true" ]; then systemctl restart "$service"; fi
  echo "La validacion final fallo; se restauro binario y payload anteriores." >&2
  exit 1
fi
if [ "$start_service" = "true" ]; then
  systemctl enable "$service"
  systemctl restart "$service"
fi

echo "Actium Node Supervisor 0.5.8 ($channel) instalado."
echo "Agregue operadores con: sudo usermod -aG actium-node-operators USUARIO"
