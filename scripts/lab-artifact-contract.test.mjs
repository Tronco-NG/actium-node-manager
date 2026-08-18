import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { escapeRegExp } from "./escape-regexp.mjs";

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
  assert.match(contents, /fail-fast:\s*false/u);
  assert.match(contents, /scenario: incomplete-resume/u);
  assert.match(contents, /scenario: two-nodes-same-host/u);
  assert.match(contents, /scenario: ipc-resume/u);
  assert.match(contents, /scenario: physical-lab22-leftover-resume/u);
  assert.match(contents, /scenario: filesystem-nofollow-boundary/u);
});

test("escapeRegExp es canonico en Node 22", () => {
  assert.equal(escapeRegExp("0.7.0-lab.21"), "0\\.7\\.0-lab\\.21");
  assert.equal(escapeRegExp("a+b(c)"), "a\\+b\\(c\\)");
  assert.ok(new RegExp(escapeRegExp("0.7.0-lab.21"), "u").test("0.7.0-lab.21"));
  assert.ok(!new RegExp(escapeRegExp("0.7.0-lab.21"), "u").test("0x7x0-labx21"));
});
