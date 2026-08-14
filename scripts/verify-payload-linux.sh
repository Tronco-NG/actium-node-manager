#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
installer_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
payload_root=${1:-}

[ -n "$payload_root" ] || { echo "Uso: $0 <payload-empaquetado>" >&2; exit 2; }
[ -f "$payload_root/PAYLOAD.json" ] || { echo "Falta PAYLOAD.json en $payload_root" >&2; exit 2; }
command -v cargo >/dev/null 2>&1 || { echo "Cargo es obligatorio para ejecutar el gate de commissioning." >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker es obligatorio para validar todos los contratos Compose." >&2; exit 1; }
docker compose version >/dev/null

while IFS= read -r executable; do
  [ -z "$executable" ] || [ -x "$payload_root/$executable" ] || {
    echo "Script Unix sin bit ejecutable en el payload empaquetado: $executable" >&2
    exit 1
  }
done < "$script_dir/payload-unix-executables.txt"
echo "Modos Unix del payload empaquetado verificados en $payload_root"
cargo run --quiet \
  --manifest-path "$installer_root/src-tauri/Cargo.toml" \
  -p actium-node-core \
  --example verify-packaged-commissioning \
  -- "$payload_root"
