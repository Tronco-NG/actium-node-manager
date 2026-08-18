#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
installer_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
deps="$installer_root/src-tauri/target/debug/deps"
test_bin=""
for candidate in "$deps"/actium_node_core-*; do
  [ -f "$candidate" ] || continue
  case "$candidate" in
    *.d|*.rlib|*.rmeta|*.so) continue ;;
  esac
  if [ -z "$test_bin" ] || [ "$candidate" -nt "$test_bin" ]; then
    test_bin=$candidate
  fi
done
if [ -z "$test_bin" ] || [ ! -f "$test_bin" ]; then
  echo "Falta el binario de test actium_node_core. Ejecute cargo test -p actium-node-core --lib antes." >&2
  exit 1
fi
# Reusa el binario ya compilado en /tmp. capsh sin CAP_DAC_* no puede
# ejecutar ~/.cargo/bin/cargo porque el HOME del runner es 0750.
copied=/tmp/actium-node-core-capchown-test
cp -f "$test_bin" "$copied"
chmod a+rx "$copied"
# Boundary equivalente a cap-drop ALL + cap-add CHOWN: sin FOWNER ni DAC.
capsh_cmd="ACTIUM_ASSERT_CHOWN_ONLY=1 $copied"
exec sudo capsh --drop=cap_dac_override,cap_dac_read_search,cap_fowner -- -c "$capsh_cmd storage_site_core_recupera_retry_parcial_sin_dac_adicional --exact && $capsh_cmd storage_agent_recupera_retry_parcial_sin_dac_ni_fowner --exact"
