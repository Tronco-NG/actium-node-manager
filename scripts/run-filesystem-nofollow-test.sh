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
copied=/tmp/actium-node-core-nofollow-test
cp -f "$test_bin" "$copied"
chmod a+rx "$copied"

# Reproduce el boundary productivo del servicio:
# CapEff/CapPrm/CapBnd = CAP_CHOWN únicamente,
# CapAmb = 0 y NoNewPrivs = 1.
bounding=$(sudo capsh --print | sed -n 's/^Bounding set =//p')
drop_caps=$(
  printf '%s\n' "$bounding" |
  tr ',' '\n' |
  grep -v '^cap_chown$' |
  paste -sd, -
)

if [ -z "$drop_caps" ]; then
  echo "ERROR: no se pudo derivar capability drop-set product-equivalent." >&2
  exit 1
fi
# Boundary equivalente a cap-drop ALL + cap-add CHOWN: sin FOWNER ni DAC.
run_restricted_test() {
  test_name="$1"
  echo "=================================================="
  echo "==> Ejecutando test restricted: $test_name"
  echo "=================================================="
  output=$(sudo capsh --drop="$drop_caps" --no-new-privs -- -c "ACTIUM_ASSERT_CHOWN_ONLY=1 $copied $test_name --exact" 2>&1) || {
    echo "ERROR: Fallo la ejecucion del test $test_name" >&2
    echo "$output" >&2
    exit 1
  }
  echo "$output"
  if ! echo "$output" | grep -q "running 1 test"; then
    echo "ERROR: El test $test_name no ejecuto exactamente 1 test (salida no contiene 'running 1 test')." >&2
    exit 1
  fi
  if ! echo "$output" | grep -q "test result: ok. 1 passed; 0 failed"; then
    echo "ERROR: El test $test_name no paso exitosamente (salida no contiene '1 passed; 0 failed')." >&2
    exit 1
  fi
  echo "✓ Test $test_name: 1 passed / 0 failed"
}

run_restricted_test "runtime::tests::storage_agent_rechaza_symlink_y_no_sigue_al_objetivo"
run_restricted_test "runtime::tests::storage_agent_rechaza_fifo_y_no_lo_promueve"
run_restricted_test "runtime::tests::storage_agent_rechaza_socket_y_no_lo_promueve"
run_restricted_test "runtime::tests::storage_runtime_unit_rechaza_symlink_en_hijo"
run_restricted_test "runtime::tests::storage_agent_recupera_retry_parcial_sin_dac_ni_fowner"
run_restricted_test "runtime::tests::storage_agent_no_confunde_runtime_json_0600_con_ausente"
run_restricted_test "runtime::tests::storage_agent_copy_legacy_migra_archivo_faltante"
run_restricted_test "runtime::tests::storage_agent_restricted_supervisor_falla_lectura_host_directo"
run_restricted_test "runtime::tests::storage_agent_restricted_supervisor_e2e_reader_container"
run_restricted_test "runtime::tests::storage_agent_reader_large_payload_no_pipe_deadlock"
run_restricted_test "runtime::tests::storage_radio_saf_recupera_retry_parcial_sin_dac"
run_restricted_test "runtime::tests::storage_fabric_nats_recupera_sin_dac"
run_restricted_test "runtime::tests::storage_site_core_recupera_retry_parcial_sin_dac_adicional"
run_restricted_test "runtime::tests::storage_agent_toctou_cerrado_tras_recuperar_root"
run_restricted_test "runtime::tests::storage_ensure_node_storage_path_rechaza_symlink_y_no_escapa"
run_restricted_test "privileged_fs::tests::rechaza_symlink_sin_seguir_el_objetivo"
run_restricted_test "privileged_fs::tests::rechaza_hardlink_adicional_st_nlink"
run_restricted_test "privileged_fs::tests::read_regular_file_nofollow_bounded_rechaza_exceso"

echo "=================================================="
echo "TODOS LOS TESTS NOFOLLOW RESTRICTED PASARON (18/18)"
echo "=================================================="


