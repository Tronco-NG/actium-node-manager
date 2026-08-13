#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
installer_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
tauri_root="$installer_root/src-tauri"
artifact_dir="$installer_root/dist/supervisor"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT INT TERM

if [ ! -f "$tauri_root/resources/node/PAYLOAD.json" ]; then
  echo "Falta resources/node/PAYLOAD.json. Ejecute npm run prepare:payload antes del build Linux." >&2
  exit 1
fi

cargo build --release --manifest-path "$tauri_root/Cargo.toml" -p actium-node-supervisor
mkdir -p "$artifact_dir" "$stage/actium-node-supervisor-0.1.0/payload"
install -m 0755 "$tauri_root/target/release/actium-node-supervisor" "$stage/actium-node-supervisor-0.1.0/actium-node-supervisor"
install -m 0755 "$tauri_root/supervisor/install-supervisor-debian.sh" "$stage/actium-node-supervisor-0.1.0/install-supervisor-debian.sh"
install -m 0644 "$tauri_root/supervisor/actium-node-supervisor.service" "$stage/actium-node-supervisor-0.1.0/actium-node-supervisor.service"
install -m 0644 "$tauri_root/supervisor/supervisor.toml" "$stage/actium-node-supervisor-0.1.0/supervisor.toml"
install -m 0644 "$tauri_root/supervisor/README.md" "$stage/actium-node-supervisor-0.1.0/README.md"
cp -a "$tauri_root/resources/node/." "$stage/actium-node-supervisor-0.1.0/payload/"
tar -C "$stage" -czf "$artifact_dir/actium-node-supervisor-0.1.0-linux-x86_64.tar.gz" actium-node-supervisor-0.1.0
(cd "$artifact_dir" && sha256sum actium-node-supervisor-0.1.0-linux-x86_64.tar.gz > actium-node-supervisor-0.1.0-linux-x86_64.tar.gz.sha256)
echo "$artifact_dir/actium-node-supervisor-0.1.0-linux-x86_64.tar.gz"
