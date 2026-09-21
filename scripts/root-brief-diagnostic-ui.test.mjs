import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8").replaceAll("\r\n", "\n");

test("Root Brief path resolution exposes the Supervisor diagnostic reason and field details", () => {
  const manager = read("src/main.ts");

  assert.match(manager, /function authorityRootBriefFailedChecks\(resolution: AuthorityRootBriefPathResolution\)/);
  assert.match(manager, /function authorityRootBriefDiagnosticDetails\(resolution: AuthorityRootBriefPathResolution\)/);
  assert.match(manager, /result\.reasonCode \|\| failedChecks\.join\(\", \"\)/);
  assert.match(manager, /rootBriefResolution\.reasonCode/);
  assert.match(manager, /rootBriefDiagnosticDetails/);
  assert.match(manager, /field\.detail/);
  assert.match(manager, /title="\$\{escapeHtml\(detail\)\}"/);
});

test("Supervisor packaging reports the version from build identity", () => {
  const installer = read("src-tauri/supervisor/install-supervisor-debian.sh");

  assert.match(installer, /installed_version=.*build_identity/);
  assert.match(installer, /Actium Node Supervisor \$\{installed_version:-unknown\}/);
  assert.doesNotMatch(installer, /Actium Node Supervisor 0\.5\.22/);
});
