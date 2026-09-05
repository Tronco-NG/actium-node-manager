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
  assert.doesNotMatch(source, /load_host_identity\(state\.config\.journal_path\.parent\(\)/);
});

test("instalador Windows materializa la misma identidad fuera del root de canal", () => {
  for (const relative of [
    "supervisor/supervisor.windows.toml.template",
    "resources/supervisor/supervisor.windows.toml.template",
  ]) {
    assert.match(read(relative), /host_identity_root = "__HOST_IDENTITY_ROOT__"/);
  }
  for (const relative of [
    "supervisor/install-supervisor-windows.ps1",
    "resources/supervisor/install-supervisor-windows.ps1",
  ]) {
    const installer = read(relative);
    assert.match(installer, /hostIdentityRoot = Join-Path \$env:ProgramData 'Actium\\NodeManager\\identity'/);
    assert.match(installer, /Replace\('__HOST_IDENTITY_ROOT__'/);
  }
});

console.log("host-enrollment-gate-1.6.1: HostIdentity root shared by stable/lab");
