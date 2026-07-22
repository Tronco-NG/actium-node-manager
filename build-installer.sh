#!/usr/bin/env sh
set -eu

INSTALLER_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_PLANE_ROOT=$(CDPATH= cd -- "$INSTALLER_ROOT/.." && pwd)
OUTPUT_ROOT="$DATA_PLANE_ROOT/dist/installers/linux"

cd "$INSTALLER_ROOT"
npm ci
npm run tauri:build -- --bundles deb,appimage
mkdir -p "$OUTPUT_ROOT"
cp src-tauri/target/release/bundle/deb/*.deb "$OUTPUT_ROOT/"
cp src-tauri/target/release/bundle/appimage/*.AppImage "$OUTPUT_ROOT/"
(cd "$OUTPUT_ROOT" && sha256sum ./*.deb ./*.AppImage > SHA256SUMS)
echo "Instaladores Linux disponibles en $OUTPUT_ROOT"
