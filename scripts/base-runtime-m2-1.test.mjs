import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

function between(source, start, end) {
  const startAt = source.indexOf(start);
  assert.notEqual(startAt, -1, `No se encontró ${start}`);
  const endAt = source.indexOf(end, startAt + start.length);
  assert.notEqual(endAt, -1, `No se encontró ${end}`);
  return source.slice(startAt, endAt);
}

test("startup base no depende de PAYLOAD ni resources/node", () => {
  const lib = read("src-tauri/src/lib.rs");
  const startup = between(lib, "fn get_system_info(", "fn inspect_installation(");
  assert.match(startup, /extension_registry_for_backend/);
  assert.match(lib, /SupervisorCommand::ExtensionStatus/);
  assert.match(lib, /load_extension_registry/);
  assert.doesNotMatch(startup, /payload_dir|verify_payload|PAYLOAD\.json|BaseDirectory::Resource/);

  const tauriConfig = read("src-tauri/tauri.conf.json");
  assert.doesNotMatch(tauriConfig, /resources[\\/]node|PAYLOAD\.json/);
});

test("legacy payload sólo queda detrás de un adapter explícito", () => {
  const adapter = read("src-tauri/src/legacy_aegis_payload.rs");
  assert.match(adapter, /LegacyAegisPayloadAdapter/);
  assert.match(adapter, /Product Extension Bundle v1/);
  assert.match(adapter, /required_bundle/);
  assert.match(read("src-tauri/src/lib.rs"), /legacy_aegis_payload::required_bundle/);
});

test("registry declara el contrato y los estados de ausencia/degradación", () => {
  const registry = read("src-tauri/actium-node-core/src/extensions.rs");
  assert.match(registry, /actium-product-extension-bundle@1\.0\.0/);
  assert.match(registry, /BASE_RUNTIME_READY/);
  assert.match(registry, /EXTENSION_DEGRADED/);
  assert.match(registry, /extension_registry_state/);
});

test("Supervisor acepta payload ausente en check y conserva verificación explícita", () => {
  const supervisor = read("src-tauri/actium-node-supervisor/src/main.rs");
  const check = between(supervisor, "if check_only {", "run_daemon(config");
  assert.match(check, /NO_EXTENSIONS/);
  assert.match(check, /load_extension_registry/);
  assert.doesNotMatch(check, /verify_schema3_payload\(&config\.payload_root\)/);
  assert.match(supervisor, /if let Some\(path\) = verify_payload_path/);

  const windowsBuild = read("scripts/build-supervisor-windows.ps1");
  assert.match(windowsBuild, /PayloadPath/);
  assert.match(windowsBuild, /Product Extension Bundle: NO_EXTENSIONS/);
  const linuxBuild = read("scripts/build-supervisor-linux.sh");
  assert.match(linuxBuild, /payload=\"\$\{1:-\}\"/);
  assert.match(linuxBuild, /Product Extension Bundle: NO_EXTENSIONS/);
});

test("build master compila Tauri base sin exigir paquete terminal legacy", () => {
  const build = read("scripts/build-master.mjs");
  assert.match(build, /includeTerminal && payloadAvailable/);
  assert.match(build, /Compilando Actium Node Manager Base Runtime/);
  assert.match(build, /npx tauri build --bundles deb/);
});
