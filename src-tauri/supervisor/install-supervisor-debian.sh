#!/bin/sh
set -eu

# Compatibility entrypoint only: all configuration, Trust Store and deployment
# invariants live in the typed Rust engine.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=${ACTIUM_NODE_SUPERVISOR_BINARY:-"$script_dir/actium-node-supervisor"}
if [ ! -x "$binary" ]; then
  echo "deployment engine no encontrado o no ejecutable: $binary" >&2
  exit 127
fi
exec "$binary" deployment "$@"
