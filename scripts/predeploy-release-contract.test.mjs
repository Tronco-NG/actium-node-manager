import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const centerRoot = process.env.ACTIUM_CENTER_ROOT
  ? resolve(process.env.ACTIUM_CENTER_ROOT)
  : resolve(installerRoot, "../../../../actium-center-control-local-backend");

const read = (absPath) => readFileSync(absPath, "utf8");

function extractPresets(source) {
  const presets = [];
  const pattern = /release:\s*'([^']+)',\s*payloadDigest:\s*'([a-f0-9]{64})'/gi;
  for (const match of source.matchAll(pattern)) {
    presets.push({ release: match[1], payloadDigest: match[2].toLowerCase() });
  }
  return presets;
}

test("Node Manager expone la release copiable para Center", () => {
  const main = read(resolve(installerRoot, "src/main.ts"));
  const lib = read(resolve(installerRoot, "src-tauri/src/lib.rs"));
  const build = read(resolve(installerRoot, "scripts/build-master.mjs"));
  assert.match(main, /copy-center-release/);
  assert.match(main, /function centerReleaseBlock/);
  assert.match(main, /payload_digest=/);
  assert.match(main, /function nodeDeployChannel/);
  assert.match(main, /Canal de despliegue/);
  assert.match(main, /independiente del nombre del payload/);
  assert.match(lib, /payload_digest: Option<String>/);
  assert.match(lib, /deploy_channel:/);
  assert.match(lib, /infer_deploy_channel/);
  assert.match(build, /predeploy-release-contract/);
  assert.match(build, /printCenterReleasePin/);
  assert.match(build, /--keep-payload/);
  assert.match(build, /--refresh-payload/);
  assert.match(build, /ACTIUM_KEEP_PAYLOAD/);
  assert.match(build, /conservar digest pinned/);
});

test("PAYLOAD.json tiene identidad de release exacta", () => {
  const payload = JSON.parse(read(resolve(installerRoot, "src-tauri/resources/node/PAYLOAD.json")));
  assert.equal(typeof payload.releaseVersion, "string");
  assert.ok(payload.releaseVersion.length > 0, "releaseVersion no puede estar vacío");
  assert.match(payload.treeSha256, /^[a-f0-9]{64}$/);
  const version = read(resolve(installerRoot, "src-tauri/resources/node/VERSION")).trim();
  assert.equal(version, payload.releaseVersion, "VERSION y PAYLOAD.releaseVersion deben coincidir");
});

test("Center no mezcla digest de rc.1 con lab.32 y tiene ceremonia de journal", () => {
  assert.ok(existsSync(centerRoot), `Actium Center no está en ${centerRoot}`);
  const panel = read(resolve(centerRoot, "src/features/aegis-nodes/runtime/NodeRuntimeEditorPanels.tsx"));
  const manager = read(resolve(centerRoot, "src/features/aegis-telemetry/runtime/DataPlaneDeploymentManager.tsx"));
  const sql = read(resolve(centerRoot, "supabase/migrations/20260830120000_supersede_attestation_ledger_v1.sql"));
  const presets = extractPresets(panel);

  assert.ok(presets.length >= 2, "Center debe declarar presets de release");
  const rc1 = presets.find((preset) => preset.release === "0.8.0-rc.1");
  const lab32 = presets.filter((preset) => preset.release === "0.8.0-lab.32");
  assert.ok(rc1, "falta el preset 0.8.0-rc.1");
  assert.equal(rc1.payloadDigest, "dc6b55a613bf0874cf5faca42107e5c4a765ba6c767e4873fd384a53807c4512");
  assert.ok(lab32.length > 0, "falta el preset 0.8.0-lab.32");
  for (const preset of lab32) {
    assert.notEqual(
      preset.payloadDigest,
      rc1.payloadDigest,
      "lab.32 no puede reutilizar el digest de rc.1",
    );
  }

  assert.match(panel, /assertAssignableRuntimeRelease/);
  assert.match(panel, /Fijar desired = observada/);
  assert.match(manager, /supersede_actium_data_plane_attestation_ledger_v1/);
  assert.doesNotMatch(manager, /desired_payload_digest \|\| 'dc6b55a6/);
  assert.match(sql, /p_reason not in \('disk_wipe', 'key_compromise', 'host_rebuild', 'reinstall'\)/);
  assert.match(sql, /grant execute on function public.supersede_actium_data_plane_attestation_ledger_v1/);
});

test("Center declara el payload que se va a compilar", () => {
  assert.ok(existsSync(centerRoot), `Actium Center no está en ${centerRoot}`);
  const panel = read(resolve(centerRoot, "src/features/aegis-nodes/runtime/NodeRuntimeEditorPanels.tsx"));
  const payload = JSON.parse(read(resolve(installerRoot, "src-tauri/resources/node/PAYLOAD.json")));
  const presets = extractPresets(panel);
  const compiled = presets.some(
    (preset) => preset.release === payload.releaseVersion && preset.payloadDigest === payload.treeSha256,
  );
  assert.ok(
    compiled,
    `Center no declara el payload compilado ${payload.releaseVersion} / ${payload.treeSha256}. Actualizá defaultRuntimeReleasePresets o bump de VERSION; no compiles este payload.`,
  );
});
