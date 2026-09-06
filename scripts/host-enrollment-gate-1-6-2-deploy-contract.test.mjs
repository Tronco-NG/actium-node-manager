import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const manager = fs.readFileSync(path.join(root, "src/main.ts"), "utf8");
const coreIpc = fs.readFileSync(path.join(root, "src-tauri/actium-node-core/src/ipc.rs"), "utf8");
const supervisor = fs.readFileSync(path.join(root, "src-tauri/actium-node-supervisor/src/main.rs"), "utf8");
const tauriLib = fs.readFileSync(path.join(root, "src-tauri/src/lib.rs"), "utf8");
const controlPlane = fs.readFileSync(path.join(root, "src-tauri/src/control_plane.rs"), "utf8");
const tauriConfig = fs.readFileSync(path.join(root, "src-tauri/tauri.conf.json"), "utf8");

test("Manager pide únicamente hen_* y usa el endpoint canónico configurado", () => {
  assert.doesNotMatch(manager, /window\.prompt/);
  assert.match(manager, /Host Enrollment/);
  assert.match(manager, /Ticket hen_\*/);
  assert.match(manager, /id="enrollment-ticket"/);
  assert.match(manager, /id="enrollment-proof"/);
  assert.match(manager, /control_plane_config/);
  assert.match(manager, /effectiveControlPlaneConfig\(\)\.hostEnrollmentEndpoint/);
  assert.match(manager, /CONTROL_PLANE_UNCONFIGURED/);
  assert.match(tauriConfig, /connect-src[^\n]*https:/);
  assert.doesNotMatch(tauriConfig, /supabase\.co/);
  assert.doesNotMatch(manager, /bootstrapValidation\?\.controlEndpoint \|\| installation\.config\?\.ACTIUM_CONTROL_ENDPOINT/);
  for (const field of ["client_id", "organization_id", "site_id", "host_id"]) {
    assert.doesNotMatch(manager, new RegExp(`window\\.prompt[^\\n]*${field}`));
  }
});

test("Control Plane se resuelve desde un contrato persistente de Host", () => {
  assert.match(tauriLib, /fn control_plane_config\(\)/);
  assert.match(tauriLib, /control_plane_config,/);
  assert.match(controlPlane, /host_control_plane_config_path/);
  assert.match(controlPlane, /signed-bootstrap/);
  assert.match(manager, /<strong>Control Plane<\/strong>/);
  assert.match(manager, /<dt>Environment<\/dt>/);
  assert.match(manager, /<dt>Enrollment gateway<\/dt>/);
  assert.match(manager, /<dt>Reachability<\/dt>/);
});

test("la ceremonia ordena challenge, complete, apply y confirm", () => {
  const order = [
    "host-enrollment-challenge",
    "host-enrollment-complete",
    "enrollment_apply_signed_package",
    "host-enrollment-confirm",
  ].map((value) => manager.indexOf(value));
  assert.ok(order.every((index) => index >= 0));
  assert.ok(order.every((index, position) => position === 0 || index > order[position - 1]));
  assert.match(coreIpc, /enrollment_nonce/);
  assert.match(supervisor, /enrollment_nonce/);
});

test("diagnóstico expone identidad material del binario", () => {
  assert.match(manager, /sourceCommit: string/);
  assert.match(manager, /buildId: string/);
  assert.match(manager, /binarySha256\?: string \| null/);
  assert.match(coreIpc, /binary_sha256/);
  assert.match(supervisor, /current_binary_sha256/);
});

console.log("host-enrollment-gate-1.6.2: Manager/Supervisor contract verified");
