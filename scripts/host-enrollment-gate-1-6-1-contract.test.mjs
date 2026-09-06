import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const supervisorRoot = path.join(root, "src-tauri");
const source = fs.readFileSync(
  path.join(supervisorRoot, "actium-node-supervisor/src/main.rs"),
  "utf8",
);
const runtime = fs.readFileSync(
  path.join(supervisorRoot, "actium-node-core/src/runtime.rs"),
  "utf8",
);

function read(relative) {
  return fs.readFileSync(path.join(supervisorRoot, relative), "utf8");
}

test("Stable y Lab comparten la raiz soberana de HostIdentity", () => {
  const stable = read("supervisor/supervisor.toml");
  const lab = read("supervisor/supervisor.lab.toml");
  const expected = 'host_identity_root = "/var/lib/actium/node-manager/identity"';
  assert.match(stable, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(lab, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(source, /host_identity_root: PathBuf/);
  assert.match(source, /load_host_identity\(&state\.config\.host_identity_root\)/);
  assert.match(source, /new_with_fabric_and_channel_and_host_identity/);
  assert.match(source, /migrate_legacy_host_identity/);
  assert.match(source, /HOST_IDENTITY_CONFLICT/);
  assert.match(runtime, /host_identity_state_dir: PathBuf/);
  assert.match(runtime, /fn host_identity_state_dir\(&self\).*Ok\(self\.host_identity_state_dir\.clone\(\)\)/s);
  assert.doesNotMatch(source, /load_host_identity\(state\.config\.journal_path\.parent\(\)/);
});

test("instalador Windows materializa la misma identidad fuera del root de canal", () => {
  for (const relative of [
    "supervisor/supervisor.windows.toml.template",
  ]) {
    assert.match(read(relative), /host_identity_root = "__HOST_IDENTITY_ROOT__"/);
  }
  for (const relative of [
    "supervisor/install-supervisor-windows.ps1",
  ]) {
    const installer = read(relative);
    assert.match(installer, /hostIdentityRoot = Join-Path \$env:ProgramData 'Actium\\NodeManager\\identity'/);
    assert.match(installer, /Replace\('__HOST_IDENTITY_ROOT__'/);
  }
  for (const relative of [
    "supervisor/actium-node-supervisor-lab.service",
  ]) {
    assert.match(read(relative), /ReadWritePaths=.*\/var\/lib\/actium\/node-manager\/identity/);
  }
  for (const relative of [
    "supervisor/install-supervisor-debian.sh",
  ]) {
    assert.match(read(relative), /host_identity_root=\/var\/lib\/actium\/node-manager\/identity/);
    assert.match(read(relative), /install -d -m 0750 -o root -g root "\$host_identity_root"/);
  }
});

console.log("host-enrollment-gate-1.6.1: HostIdentity root shared by stable/lab");
