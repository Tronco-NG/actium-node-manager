import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const installerRoot = resolve(import.meta.dirname, "..");
const workflow = resolve(installerRoot, "..", "..", "..", ".github", "workflows", "actium-telemetry-node-installer.yml");

test("los jobs publicables construyen y verifican explicitamente el canal Lab", async () => {
  const contents = await readFile(workflow, "utf8");
  assert.match(contents, /npm run tauri:build:lab -- --bundles nsis,msi/u);
  assert.match(contents, /npm run verify:lab-artifact -- --platform windows/u);
  assert.match(contents, /npm run tauri:build:lab -- --bundles deb,appimage/u);
  assert.match(contents, /npm run verify:lab-artifact -- --platform linux/u);
  assert.doesNotMatch(contents, /npm run tauri:build -- --bundles nsis,msi/u);
  assert.doesNotMatch(contents, /npm run tauri:build -- --bundles deb,appimage/u);
});
