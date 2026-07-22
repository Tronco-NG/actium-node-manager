#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo 'Este instalador de dependencias debe ejecutarse como root.' >&2
  exit 2
fi

[ -r /etc/os-release ] || { echo 'No se pudo identificar la distribucion.' >&2; exit 2; }
. /etc/os-release

case "${ID:-}" in
  debian|ubuntu) ;;
  *)
    echo "Instalacion automatica soportada solamente en Debian y Ubuntu (detectado: ${ID:-desconocido})." >&2
    exit 2
    ;;
esac

CODENAME=${VERSION_CODENAME:-}
[ -n "$CODENAME" ] || { echo 'La distribucion no informa VERSION_CODENAME.' >&2; exit 2; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

ARCH=$(dpkg --print-architecture)
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' "$ARCH" "$ID" "$CODENAME" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now docker
fi

NODE_USER=${ACTIUM_NODE_USER:-}
if [ -n "$NODE_USER" ] && id "$NODE_USER" >/dev/null 2>&1; then
  getent group docker >/dev/null 2>&1 || groupadd docker
  usermod -aG docker "$NODE_USER"
  echo "El usuario $NODE_USER fue agregado al grupo docker. Debe cerrar sesion y volver a entrar antes de operar Docker sin privilegios."
fi

docker --version
docker compose version
echo 'Dependencias del Actium Telemetry Node instaladas correctamente.'
