#!/usr/bin/env sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUTPUT_ROOT="$PROJECT_ROOT/dist/installers/linux"

cd "$PROJECT_ROOT"
npm ci
npm run tauri:build -- --bundles deb,appimage
mkdir -p "$OUTPUT_ROOT"
cp src-tauri/target/release/bundle/deb/*.deb "$OUTPUT_ROOT/"
cp src-tauri/target/release/bundle/appimage/*.AppImage "$OUTPUT_ROOT/"
(cd "$OUTPUT_ROOT" && sha256sum ./*.deb ./*.AppImage > SHA256SUMS)
echo "Instaladores Linux disponibles en $OUTPUT_ROOT"
