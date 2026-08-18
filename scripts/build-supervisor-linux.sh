#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
installer_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
tauri_root="$installer_root/src-tauri"
artifact_dir="$tauri_root/target/release/bundle/supervisor"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT INT TERM

if [ ! -f "$tauri_root/resources/node/PAYLOAD.json" ]; then
  echo "Falta resources/node/PAYLOAD.json. Ejecute npm run prepare:payload antes del build Linux." >&2
  exit 1
fi

cargo build --release --manifest-path "$tauri_root/Cargo.toml" -p actium-node-supervisor
version=0.5.16
package="actium-node-supervisor-$version"
mkdir -p "$artifact_dir" "$stage/$package/payload"
install -m 0755 "$tauri_root/target/release/actium-node-supervisor" "$stage/$package/actium-node-supervisor"
install -m 0755 "$tauri_root/supervisor/install-supervisor-debian.sh" "$stage/$package/install-supervisor-debian.sh"
install -m 0644 "$tauri_root/supervisor/actium-node-supervisor.service" "$stage/$package/actium-node-supervisor.service"
install -m 0644 "$tauri_root/supervisor/actium-node-supervisor-lab.service" "$stage/$package/actium-node-supervisor-lab.service"
install -m 0644 "$tauri_root/supervisor/supervisor.toml" "$stage/$package/supervisor.toml"
install -m 0644 "$tauri_root/supervisor/supervisor.lab.toml" "$stage/$package/supervisor.lab.toml"
install -m 0644 "$tauri_root/supervisor/README.md" "$stage/$package/README.md"
cp -a "$tauri_root/resources/node/." "$stage/$package/payload/"
while IFS= read -r executable; do
  if [ -n "$executable" ]; then
    sed -i 's/\r$//' "$stage/$package/payload/$executable"
    chmod 0755 "$stage/$package/payload/$executable"
  fi
done < "$script_dir/payload-unix-executables.txt"
source_date_epoch=$(git -C "$installer_root" show -s --format=%ct HEAD)
case "$source_date_epoch" in ''|*[!0-9]*) echo "Git no devolvio SOURCE_DATE_EPOCH valido." >&2; exit 1;; esac
raw_tar="$stage/$package.tar"
LC_ALL=C tar \
  --format=gnu \
  --sort=name \
  --mtime="@$source_date_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$stage" \
  -cf "$raw_tar" \
  "$package"
gzip -n -c "$raw_tar" > "$artifact_dir/$package-linux-x86_64.tar.gz"
mkdir -p "$stage/extracted"
tar -C "$stage/extracted" -xzf "$artifact_dir/$package-linux-x86_64.tar.gz"
node "$script_dir/verify-payload-identity.mjs" "$stage/extracted/$package/payload"
while IFS= read -r executable; do
  [ -z "$executable" ] || [ -x "$stage/extracted/$package/payload/$executable" ] || {
    echo "Script Unix sin bit ejecutable en el payload del Supervisor: $executable" >&2
    exit 1
  }
done < "$script_dir/payload-unix-executables.txt"
(cd "$artifact_dir" && sha256sum "$package-linux-x86_64.tar.gz" > "$package-linux-x86_64.tar.gz.sha256")
echo "$artifact_dir/$package-linux-x86_64.tar.gz"
