#!/bin/sh
set -eu

binary=""
channel="interactive"
action="install"
start_service="true"
rollback_dir=""
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
root_prefix="${DESTDIR:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary) binary="${2:-}"; shift 2 ;;
    --channel) channel="${2:-}"; shift 2 ;;
    --install) action="install"; shift ;;
    --preflight) action="preflight"; shift ;;
    --rollback) action="rollback"; rollback_dir="${2:-}"; shift 2 ;;
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

# Modo interactivo
if [ "$channel" = "interactive" ] && [ "$action" != "rollback" ]; then
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

configure_channel_paths() {
  target_channel="$1"
  if [ "$target_channel" = "lab" ]; then
    config_dir="$root_prefix/etc/actium/node-manager-lab"
    state_dir="$root_prefix/var/lib/actium/node-manager-lab"
    log_dir="$root_prefix/var/log/actium/node-manager-lab"
    data_root="$root_prefix/actium-lab"
    lib_dir="$root_prefix/usr/lib/actium/node-manager-lab"
    config_template="supervisor.lab.toml"
    unit_template="actium-node-supervisor-lab.service"
    service="actium-node-supervisor-lab.service"
  else
    config_dir="$root_prefix/etc/actium/node-manager"
    state_dir="$root_prefix/var/lib/actium/node-manager"
    log_dir="$root_prefix/var/log/actium/node-manager"
    data_root="$root_prefix/actium"
    lib_dir="$root_prefix/usr/lib/actium/node-manager"
    config_template="supervisor.toml"
    unit_template="actium-node-supervisor.service"
    service="actium-node-supervisor.service"
  fi
nodes_root="$data_root/nodes"
fabrics_root="$data_root/fabrics"
host_identity_root="$root_prefix/var/lib/actium/node-manager/identity"
config_path="$config_dir/supervisor.toml"
key_path="$config_dir/ipc.key"
marker_path="$state_dir/root-ownership.json"
docker_cli_dir="$state_dir/docker-cli"
docker_cli_config="$docker_cli_dir/config.json"
binary_target="$lib_dir/actium-node-supervisor"
binary_next="$lib_dir/actium-node-supervisor.next"
binary_previous="$lib_dir/actium-node-supervisor.previous"
  backup_dir="$state_dir/install-backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
upgrade_backup_dir="$state_dir/upgrade-backups/$(date -u +%Y%m%dT%H%M%SZ)-$$"
unit_path="$root_prefix/etc/systemd/system/$service"
dropin_dir="$root_prefix/etc/systemd/system/$service.d"
doc_dir="$root_prefix/usr/share/doc/actium-node-supervisor"
}

snapshot_upgrade_inventory() {
  inventory_path="$upgrade_backup_dir/data-inventory.sha256"
  : > "$inventory_path"
  if [ -d "$data_root" ]; then
    find "$data_root" -type f \
      \( -name 'registry.json' -o -name '.actium-node-installation.json' \
      -o -name 'release-state.json' -o -name 'runtime-intent.json' \
      -o -name 'active-release.json' -o -name 'previous-release.json' \) \
      ! -name '*.key' -exec sha256sum -- {} \; | sort > "$inventory_path"
  fi
}

backup_state_files() {
  state_backup_dir="$upgrade_backup_dir/state-files"
  install -d -m 0700 -o root -g root "$state_backup_dir"
  : > "$upgrade_backup_dir/state-presence"
  for state_name in \
    host-identity.json host-installation-id attestation-identity.json \
    attestation-identity.key root-ownership.json build-identity.json \
    ipc.key operations.sqlite3; do
    if [ -f "$state_dir/$state_name" ]; then
      cp -a -- "$state_dir/$state_name" "$state_backup_dir/$state_name"
      printf 'present=%s\n' "$state_name" >> "$upgrade_backup_dir/state-presence"
    else
      printf 'absent=%s\n' "$state_name" >> "$upgrade_backup_dir/state-presence"
    fi
  done
  for state_name in identity trust; do
    if [ -d "$state_dir/$state_name" ]; then
      cp -a -- "$state_dir/$state_name" "$state_backup_dir/$state_name"
      printf 'present_dir=%s\n' "$state_name" >> "$upgrade_backup_dir/state-presence"
    else
      printf 'absent_dir=%s\n' "$state_name" >> "$upgrade_backup_dir/state-presence"
    fi
  done
}

create_upgrade_backup() {
  install -d -m 0750 "$state_dir"
  install -d -m 0700 -o root -g root "$upgrade_backup_dir"
  {
    printf 'schema=1\n'
    printf 'channel=%s\n' "$target_channel"
    printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if systemctl is-active --quiet "$service"; then
      printf 'service_was_active=true\n'
    else
      printf 'service_was_active=false\n'
    fi
    if [ -f "$binary_target" ]; then
      printf 'binary_present=true\n'
      sha256sum -- "$binary_target"
    else
      printf 'binary_present=false\n'
    fi
  } > "$upgrade_backup_dir/manifest"
  if [ -f "$binary_target" ]; then cp -a -- "$binary_target" "$upgrade_backup_dir/binary"; fi
  if [ -f "$config_path" ]; then cp -a -- "$config_path" "$upgrade_backup_dir/supervisor.toml"; fi
  if [ -f "$unit_path" ]; then cp -a -- "$unit_path" "$upgrade_backup_dir/service.unit"; fi
  if [ -d "$dropin_dir" ]; then cp -a -- "$dropin_dir" "$upgrade_backup_dir/dropins"; fi
  backup_state_files
  snapshot_upgrade_inventory
}

preflight_single_channel() {
  target_channel="$1"
  configure_channel_paths "$target_channel"
  printf 'Upgrade preflight (%s): verificando estado historico y candidato.\n' "$target_channel"
  for required_path in "$config_dir" "$state_dir" "$data_root" "$lib_dir"; do
    if [ -L "$required_path" ]; then
      echo "Upgrade preflight: no se aceptan symlinks en $required_path." >&2
      return 1
    fi
  done
  if [ -n "$binary" ]; then
    if [ ! -f "$binary" ]; then
      echo "Upgrade preflight: falta el Supervisor candidato en $binary." >&2
      return 1
    fi
    "$binary" --self-test >/dev/null
    candidate_build_info="$("$binary" --build-info)" || {
      echo "Upgrade preflight: no se pudo leer build-info del candidato." >&2
      return 1
    }
    printf '%s\n' "$candidate_build_info" | grep -q 'actium-node-supervisor' || {
      echo "Upgrade preflight: build-info no identifica actium-node-supervisor." >&2
      return 1
    }
  fi
  if [ -f "$binary_target" ]; then
    if [ ! -f "$config_path" ]; then
      echo "Upgrade preflight: existe Supervisor historico sin configuracion en $config_path." >&2
      return 1
    fi
    if systemctl is-active --quiet "$service"; then
      "$binary_target" --config "$config_path" --ping >/dev/null
    fi
  fi
  if [ -f "$config_path" ] && [ ! -r "$config_path" ]; then
    echo "Upgrade preflight: configuracion no legible en $config_path." >&2
    return 1
  fi
  if [ -d "$state_dir" ] && [ ! -w "$state_dir" ]; then
    echo "Upgrade preflight: state dir no escribible en $state_dir." >&2
    return 1
  fi
  if [ -e "$data_root" ] && [ ! -d "$data_root" ]; then
    echo "Upgrade preflight: data root no es un directorio en $data_root." >&2
    return 1
  fi
  if [ -d "$state_dir" ]; then
    df -Pk "$state_dir" >/dev/null
  fi
  if [ -d "$data_root" ]; then
    df -Pk "$data_root" >/dev/null
  fi
  if [ -f "$unit_path" ] && ! grep -q 'actium-node-supervisor' "$unit_path"; then
    echo "Upgrade preflight: unidad incompatible en $unit_path." >&2
    return 1
  fi
  printf 'Upgrade preflight (%s): PASS.\n' "$target_channel"
}

restore_upgrade_state() {
  state_backup_dir="$backup_dir/state-files"
  for state_name in \
    host-identity.json host-installation-id attestation-identity.json \
    attestation-identity.key root-ownership.json build-identity.json \
    ipc.key operations.sqlite3; do
    if grep -q "^present=$state_name$" "$backup_dir/state-presence"; then
      cp -a -- "$state_backup_dir/$state_name" "$state_dir/$state_name"
    elif grep -q "^absent=$state_name$" "$backup_dir/state-presence"; then
      rm -f -- "$state_dir/$state_name"
    fi
  done
  for state_name in identity trust; do
    if grep -q "^present_dir=$state_name$" "$backup_dir/state-presence"; then
      rm -rf -- "$state_dir/$state_name"
      cp -a -- "$state_backup_dir/$state_name" "$state_dir/$state_name"
    fi
  done
}

restore_install_backup() {
  if [ -f "$backup_dir/supervisor.toml" ]; then
    cp -a -- "$backup_dir/supervisor.toml" "$config_path"
  else
    rm -f -- "$config_path"
  fi
  if [ -f "$backup_dir/service.unit" ]; then
    cp -a -- "$backup_dir/service.unit" "$unit_path"
  else
    rm -f -- "$unit_path"
  fi
  rm -rf -- "$dropin_dir"
  if [ -d "$backup_dir/dropins" ]; then cp -a -- "$backup_dir/dropins" "$dropin_dir"; fi
  systemctl daemon-reload
}

wait_for_supervisor_health() {
  attempts=10
  socket_path=/run/actium/node-manager.sock
  if [ "$target_channel" = "lab" ]; then socket_path=/run/actium/node-manager-lab.sock; fi
  while [ "$attempts" -gt 0 ]; do
    if systemctl is-active --quiet "$service" \
      && test -S "$socket_path" \
      && "$binary_target" --config "$config_path" --ping; then
      return 0
    fi
    attempts=$((attempts - 1))
    sleep 1
  done
  return 1
}

rollback_upgrade_backup() {
  selected_backup_dir="$rollback_dir"
  case "$selected_backup_dir" in
    "$root_prefix/var/lib/actium/node-manager/upgrade-backups/"*|"$root_prefix/var/lib/actium/node-manager-lab/upgrade-backups/"*) ;;
    *) echo "Rollback rechazado: backup fuera del directorio upgrade-backups." >&2; return 1 ;;
  esac
  if [ ! -f "$selected_backup_dir/manifest" ] || [ ! -f "$selected_backup_dir/state-presence" ]; then
    echo "Rollback rechazado: backup de upgrade incompleto en $selected_backup_dir." >&2
    return 1
  fi
  target_channel="$(sed -n 's/^channel=//p' "$selected_backup_dir/manifest" | head -n 1)"
  case "$target_channel" in stable|lab) ;; *) echo "Rollback rechazado: canal invalido." >&2; return 1 ;; esac
  configure_channel_paths "$target_channel"
  service_was_active="$(sed -n 's/^service_was_active=//p' "$selected_backup_dir/manifest" | head -n 1)"
  if systemctl is-active --quiet "$service"; then systemctl stop "$service"; fi
  install -d -m 0755 "$config_dir" "$lib_dir" "$doc_dir"
  install -d -m 0750 "$state_dir" "$log_dir"
  if [ -f "$selected_backup_dir/binary" ]; then
    install -m 0755 "$selected_backup_dir/binary" "$binary_target"
  else
    rm -f -- "$binary_target"
  fi
  backup_dir="$selected_backup_dir"
  restore_install_backup
  restore_upgrade_state
  systemctl daemon-reload
  if [ -f "$binary_target" ] && ! "$binary_target" --config "$config_path" --check; then
    echo "Rollback rechazado: el Supervisor restaurado no supera --check." >&2
    return 1
  fi
  if [ "$service_was_active" = "true" ]; then
    systemctl enable "$service"
    if ! systemctl restart "$service" || ! wait_for_supervisor_health; then
      echo "Rollback incompleto: el Supervisor restaurado no recupero salud/socket." >&2
      return 1
    fi
  fi
  echo "Rollback de upgrade restaurado desde $rollback_dir ($target_channel)."
}

install_single_channel() {
  target_channel="$1"
  configure_channel_paths "$target_channel"

  preflight_single_channel "$target_channel"
  create_upgrade_backup

# El Supervisor reconcilia grants al iniciar y escribe su drop-in administrado.
# Crear sólo su directorio permite esa operación bajo ProtectSystem=strict sin
# abrir escritura sobre el resto de la configuración de systemd.
install -d -m 0755 "$dropin_dir"

# Nunca sobrescribimos la configuración local ni los grants administrados sin
# conservar un rollback root-owned. La identidad del Host, el trust store y la
# configuración de storage no se regeneran desde el paquete.
 install -d -m 0700 -o root -g root "$backup_dir"
if [ -f "$config_path" ]; then cp -a -- "$config_path" "$backup_dir/supervisor.toml"; fi
if [ -f "$unit_path" ]; then cp -a -- "$unit_path" "$backup_dir/service.unit"; fi
if [ -d "$dropin_dir" ]; then cp -a -- "$dropin_dir" "$backup_dir/dropins"; fi

"$binary" --self-test

groupadd --system --force actium-node-operators
install -d -m 0755 "$config_dir" "$lib_dir" "$doc_dir"
install -d -m 0750 "$state_dir" "$log_dir"
install -d -m 0750 -o root -g root "$host_identity_root"

install -d -m 0700 -o root -g root "$docker_cli_dir"
if [ ! -f "$docker_cli_config" ]; then
  ( umask 0077; printf '{}\n' > "$docker_cli_config" )
fi
chown root:root "$docker_cli_config"
chmod 0600 "$docker_cli_config"

build_identity_path="$state_dir/build-identity.json"
build_identity="$("$binary" --build-info)" || {
  echo "No se pudo obtener la identidad de build del Supervisor embebido." >&2
  exit 1
}
printf '%s\n' "$build_identity" > "$build_identity_path"
chown root:root "$build_identity_path"
chmod 0600 "$build_identity_path"

DOCKER_CONFIG="$docker_cli_dir" docker compose version >/dev/null 2>&1 || {
  echo "Docker Compose no esta disponible para el boundary endurecido del Supervisor." >&2
  exit 1
}

install -d -m 0775 -o root -g actium-node-operators "$data_root" "$nodes_root" "$fabrics_root"
chmod 2775 "$nodes_root" "$fabrics_root" 2>/dev/null || true
install -m 0755 "$binary" "$binary_next"
install -m 0644 "$script_dir/$config_template" "$config_path.dist"
# Una actualización nunca reemplaza la configuración ni drop-ins existentes:
# éstos contienen identidad local y grants aprobados por owner.
if [ ! -f "$config_path" ]; then install -m 0644 "$script_dir/$config_template" "$config_path"; fi
install -m 0644 "$script_dir/$unit_template" "$unit_path"
# Este drop-in pertenecía al modelo de allowlist universal. No es un grant y
# reabre rutas inexistentes; se elimina sólo después de haberlo respaldado.
rm -f -- "$dropin_dir/mass-storage.conf"

# Las primeras versiones guardaban el nombre de servicio Windows en la
# configuración Linux. Migramos únicamente ese campo legado para que el
# Supervisor pueda reconciliar grants y systemd pueda resolver la unidad real;
# el resto de la configuración local permanece intacto.
legacy_service_name="ActiumNodeSupervisor"
if [ "$target_channel" = "lab" ]; then legacy_service_name="ActiumNodeSupervisorLab"; fi
if [ -f "$config_path" ]; then
  current_service_name=$(sed -n 's/^[[:space:]]*service_name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$config_path" | head -n 1)
  if [ "$current_service_name" = "$legacy_service_name" ]; then
    normalized_config="$config_path.next"
    sed "s/^[[:space:]]*service_name[[:space:]]*=.*/service_name = \"${service%.service}\"/" "$config_path" > "$normalized_config"
    chown --reference="$config_path" "$normalized_config" 2>/dev/null || true
    chmod --reference="$config_path" "$normalized_config" 2>/dev/null || true
    mv -f -- "$normalized_config" "$config_path"
  fi
fi
systemctl daemon-reload

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

service_was_active="false"
if systemctl is-active --quiet "$service"; then
  service_was_active="true"
  systemctl stop "$service"
fi
rm -f -- "$binary_previous"
if [ -f "$binary_target" ]; then mv -- "$binary_target" "$binary_previous"; fi
mv -- "$binary_next" "$binary_target"

systemctl daemon-reload
if ! "$binary_target" --config "$config_path" --check; then
  if [ -f "$binary_previous" ]; then mv -- "$binary_previous" "$binary_target"; fi
  restore_install_backup
  if [ "$service_was_active" = "true" ]; then systemctl restart "$service"; fi
  echo "La validacion final fallo; se restauro el binario anterior." >&2
  exit 1
fi
if [ "$start_service" = "true" ]; then
  systemctl enable "$service"
  if ! systemctl restart "$service" || ! wait_for_supervisor_health; then
    if [ -f "$binary_previous" ]; then mv -- "$binary_previous" "$binary_target"; fi
    restore_install_backup
    if [ "$service_was_active" = "true" ]; then systemctl restart "$service" || true; fi
    echo "La instalación no superó health/socket/IPC; se restauró unidad, drop-ins, configuración y binario previos. Backup: $backup_dir" >&2
    exit 1
  fi
fi

  echo "Actium Node Supervisor 0.5.21 ($target_channel) instalado."
  echo "Agregue operadores con: sudo usermod -aG actium-node-operators USUARIO"
}

uninstall_single_channel() {
  target_channel="$1"
  if [ "$target_channel" = "lab" ]; then
    service="actium-node-supervisor-lab.service"
    lib_dir="$root_prefix/usr/lib/actium/node-manager-lab"
  else
    service="actium-node-supervisor.service"
    lib_dir="$root_prefix/usr/lib/actium/node-manager"
  fi
  echo "Deteniendo y deshabilitando $service..."
  systemctl stop "$service" 2>/dev/null || true
  systemctl disable "$service" 2>/dev/null || true
  rm -f -- "$root_prefix/etc/systemd/system/$service"
  systemctl daemon-reload
  rm -rf -- "$lib_dir"
  echo "Canal $target_channel desinstalado correctamente (datos preservados en /srv/)."
}

if [ "$action" = "rollback" ]; then
  rollback_upgrade_backup
elif [ "$action" = "preflight" ]; then
  if [ "$channel" = "both" ]; then
    preflight_single_channel "stable"
    preflight_single_channel "lab"
  else
    preflight_single_channel "$channel"
  fi
elif [ "$action" = "uninstall" ]; then
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
