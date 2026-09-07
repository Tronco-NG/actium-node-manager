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
[ "$(dpkg --print-architecture 2>/dev/null || true)" = "amd64" ] || {
  echo 'Este helper solo soporta arquitectura amd64.' >&2
  exit 2
}

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl openssl iproute2

# No reemplazar un Docker oficial ya instalado. En un host limpio se usan los
# paquetes de la distribución; en un host existente se conserva el proveedor
# que ya satisface el boundary Docker/Compose.
if ! command -v docker >/dev/null 2>&1; then
  apt-get install -y docker.io
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y docker-compose
fi

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
echo 'Dependencias del Actium Node Manager Base Runtime instaladas correctamente.'
