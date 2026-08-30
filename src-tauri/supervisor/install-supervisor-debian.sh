#!/bin/sh
set -eu

binary=""
payload=""
channel="interactive"
action="install"
start_service="true"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) binary="${2:-}"; shift 2 ;;
    --payload) payload="${2:-}"; shift 2 ;;
    --channel) channel="${2:-}"; shift 2 ;;
    --install) action="install"; shift ;;
    --uninstall) action="uninstall"; shift ;;
    --interactive) channel="interactive"; shift ;;
    --no-start) start_service="false"; shift ;;
    *) echo "Argumento no reconocido: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecute este instalador con sudo / root." >&2
  exit 1
fi

if [ -z "$binary" ] || [ ! -f "$binary" ]; then
  if [ -f "$script_dir/actium-node-supervisor" ]; then
    binary="$script_dir/actium-node-supervisor"
  fi
fi

if [ -z "$payload" ] || [ ! -f "$payload/PAYLOAD.json" ]; then
  for candidate in \
    "$payload" \
    "$script_dir/payload" \
    "$script_dir/../node" \
    "$script_dir/node" \
    "/usr/lib/Actium Node Manager/node" \
    "/usr/lib/Actium Node Manager/resources/node" \
    "/usr/lib/actium-node-manager/node" \
    "/usr/lib/actium-node-manager/resources/node"
  do
    if [ -n "$candidate" ] && [ -f "$candidate/PAYLOAD.json" ]; then
      payload=$(CDPATH= cd -- "$candidate" && pwd)
      break
    fi
  done
fi
if [ -z "$payload" ] || [ ! -f "$payload/PAYLOAD.json" ]; then
  echo "No se encontro PAYLOAD.json. Pase --payload al bundle node/ del Manager o coloque payload/ junto al Supervisor." >&2
  exit 1
fi

# Modo interactivo
if [ "$channel" = "interactive" ]; then
  echo "=========================================================="
  echo "  Actium Node Supervisor - Asistente de Instalacion Linux"
  echo "=========================================================="
  echo "Seleccione la accion a realizar en este host:"
  echo "  [1] Produccion (Stable) -> Servicio actium-node-supervisor (/actium, puertos 8xxx)"
  echo "  [2] Laboratorio (Lab)   -> Servicio actium-node-supervisor-lab (/actium-lab, puertos 18xxx)"
  echo "  [3] Ambos en Paralelo   -> Dual-Channel (Coexistencia en el mismo host fisico)"
  echo "  [4] Desinstalar Servicio(s)"
  echo "  [5] Salir"
  printf "Opcion [1-5]: "
  read -r choice < /dev/tty || choice="3"
  case "$choice" in
    1) channel="stable"; action="install" ;;
    2) channel="lab"; action="install" ;;
    3) channel="both"; action="install" ;;
    4) action="uninstall" ;;
    *) echo "Operacion cancelada."; exit 0 ;;
  esac
fi

install_single_channel() {
  target_channel="$1"
  if [ "$target_channel" = "lab" ]; then
    config_dir=/etc/actium/node-manager-lab
    state_dir=/var/lib/actium/node-manager-lab
    log_dir=/var/log/actium/node-manager-lab
    data_root=/actium-lab
    lib_dir=/usr/lib/actium/node-manager-lab
    config_template=supervisor.lab.toml
    unit_template=actium-node-supervisor-lab.service
    service=actium-node-supervisor-lab.service
  else
    config_dir=/etc/actium/node-manager
    state_dir=/var/lib/actium/node-manager
    log_dir=/var/log/actium/node-manager
    data_root=/actium
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
docker_cli_dir="$state_dir/docker-cli"
docker_cli_config="$docker_cli_dir/config.json"
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

install -d -m 0700 -o root -g root "$docker_cli_dir"
if [ ! -f "$docker_cli_config" ]; then
  ( umask 0077; printf '{}\n' > "$docker_cli_config" )
fi
chown root:root "$docker_cli_config"
chmod 0600 "$docker_cli_config"

DOCKER_CONFIG="$docker_cli_dir" docker compose version >/dev/null 2>&1 || {
  echo "Docker Compose no esta disponible para el boundary endurecido del Supervisor." >&2
  exit 1
}

install -d -m 0775 -o root -g actium-node-operators "$data_root" "$nodes_root" "$fabrics_root"
chmod 2775 "$nodes_root" "$fabrics_root" 2>/dev/null || true
install -m 0755 "$binary" "$binary_next"
install -m 0644 "$script_dir/$config_template" "$config_path.dist"
install -m 0644 "$script_dir/$config_template" "$config_path"
install -m 0644 "$script_dir/$unit_template" "/etc/systemd/system/$service"
systemctl daemon-reload 2>/dev/null || true

if [ ! -f "$key_path" ]; then
  umask 0077
  openssl rand -base64 48 > "$key_path"
fi
chown root:actium-node-operators "$key_path"
chmod 0640 "$key_path"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  usermod -aG actium-node-operators "$SUDO_USER" 2>/dev/null || true
fi

root_id=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || od -x /dev/urandom 2>/dev/null | head -1 | awk '{print $2$3$4$5}')
if [ -f "$marker_path" ]; then
  existing_id=$(grep -o '"rootId": *"[^"]*"' "$marker_path" 2>/dev/null | cut -d'"' -f4 || true)
  if [ -n "$existing_id" ]; then root_id="$existing_id"; fi
fi
umask 0077
printf '{\n  "schema": 1,\n  "owner": "actium-node-supervisor",\n  "productChannel": "%s",\n  "rootId": "%s",\n  "authorizedNodesRoot": "%s",\n  "authorizedFabricsRoot": "%s"\n}\n' \
  "$target_channel" "$root_id" "$nodes_root" "$fabrics_root" > "$marker_path"

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

  echo "Actium Node Supervisor 0.5.20 ($target_channel) instalado."
  echo "Agregue operadores con: sudo usermod -aG actium-node-operators USUARIO"
}

uninstall_single_channel() {
  target_channel="$1"
  if [ "$target_channel" = "lab" ]; then
    service=actium-node-supervisor-lab.service
    lib_dir=/usr/lib/actium/node-manager-lab
  else
    service=actium-node-supervisor.service
    lib_dir=/usr/lib/actium/node-manager
  fi
  echo "Deteniendo y deshabilitando $service..."
  systemctl stop "$service" 2>/dev/null || true
  systemctl disable "$service" 2>/dev/null || true
  rm -f "/etc/systemd/system/$service"
  systemctl daemon-reload
  rm -rf "$lib_dir"
  echo "Canal $target_channel desinstalado correctamente (datos preservados en /srv/)."
}

if [ "$action" = "uninstall" ]; then
  if [ "$channel" = "both" ] || [ "$channel" = "all" ] || [ "$channel" = "interactive" ]; then
    uninstall_single_channel "stable"
    uninstall_single_channel "lab"
  else
    uninstall_single_channel "$channel"
  fi
else
  if [ "$channel" = "both" ]; then
    echo "Aprovisionando entorno Dual-Channel (Stable + Lab)..."
    install_single_channel "stable"
    install_single_channel "lab"
    echo "=========================================================="
    echo "Instalacion Dual-Channel completada con exito."
    echo "=========================================================="
  else
    install_single_channel "$channel"
  fi
fi
