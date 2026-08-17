#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
installer_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
payload_root=${1:-}

[ -n "$payload_root" ] || { echo "Uso: $0 <payload-empaquetado>" >&2; exit 2; }
[ -f "$payload_root/PAYLOAD.json" ] || { echo "Falta PAYLOAD.json en $payload_root" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "Docker es obligatorio para validar todos los contratos Compose." >&2; exit 1; }
docker compose version >/dev/null
if [ "$(id -u)" -eq 0 ]; then
  command -v cargo >/dev/null 2>&1 || { echo "Cargo es obligatorio para ejecutar el gate de commissioning como root." >&2; exit 1; }
fi

while IFS= read -r executable; do
  [ -z "$executable" ] || [ -x "$payload_root/$executable" ] || {
    echo "Script Unix sin bit ejecutable en el payload empaquetado: $executable" >&2
    exit 1
  }
done < "$script_dir/payload-unix-executables.txt"
echo "Modos Unix del payload empaquetado verificados en $payload_root"

verify_packaged_commissioning() {
  cargo run --quiet \
    --manifest-path "$installer_root/src-tauri/Cargo.toml" \
    -p actium-node-core \
    --example verify-packaged-commissioning \
    -- "$payload_root"
}

if [ "$(id -u)" -eq 0 ]; then
  verify_packaged_commissioning
else
  # El commissioning empaquetado materializa storage con el mismo boundary
  # que el Supervisor: root + CAP_CHOWN, sin capacidades DAC. Un usuario de
  # build no puede simular ese contrato con chmods locales, por lo que el gate
  # se ejecuta en un contenedor efimero limitado.
  docker_binary=$(readlink -f "$(command -v docker)")
  compose_plugin=$(command -v docker-compose || true)
  [ -n "$compose_plugin" ] || {
    echo "El fallback CAP_CHOWN requiere el plugin docker-compose del host." >&2
    exit 1
  }
  compose_plugin=$(readlink -f "$compose_plugin")
  [ -S /var/run/docker.sock ] || {
    echo "El fallback CAP_CHOWN requiere /var/run/docker.sock para docker compose config." >&2
    exit 1
  }
  docker run --rm \
    --cap-drop=ALL \
    --cap-add=CHOWN \
    -e CARGO_TARGET_DIR=/tmp/actium-target \
    -v "$docker_binary:/usr/local/bin/docker:ro" \
    -v "$compose_plugin:/usr/local/lib/docker/cli-plugins/docker-compose:ro" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$installer_root:/workspace:ro" \
    -v "$payload_root:/payload:ro" \
    -w /workspace \
    rust:latest \
    cargo run --quiet \
      --manifest-path src-tauri/Cargo.toml \
      -p actium-node-core \
      --example verify-packaged-commissioning \
      -- /payload
fi
