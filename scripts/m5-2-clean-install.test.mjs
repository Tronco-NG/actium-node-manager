import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const tauri = JSON.parse(fs.readFileSync(path.join(root, "src-tauri/tauri.conf.json"), "utf8"));
const releaseTauri = JSON.parse(fs.readFileSync(path.join(root, "src-tauri/tauri.release.conf.json"), "utf8"));
const viteConfig = fs.readFileSync(path.join(root, "vite.config.ts"), "utf8");
const dependencyHelper = fs.readFileSync(path.join(root, "src-tauri/resources/install-dependencies-debian.sh"), "utf8");
const postinst = fs.readFileSync(path.join(root, "src-tauri/supervisor/postinst-debian.sh"), "utf8");
const supervisorInstaller = fs.readFileSync(path.join(root, "src-tauri/supervisor/install-supervisor-debian.sh"), "utf8");
const service = fs.readFileSync(path.join(root, "src-tauri/supervisor/actium-node-supervisor.service"), "utf8");
const supervisorMain = fs.readFileSync(path.join(root, "src-tauri/actium-node-supervisor/src/main.rs"), "utf8");
const buildMaster = fs.readFileSync(path.join(root, "scripts/build-master.mjs"), "utf8");

test("Linux package declares first-install dependencies and systemd integration", () => {
  const depends = tauri.bundle?.linux?.deb?.depends ?? [];
  assert.ok(depends.includes("systemd"));
  assert.ok(depends.includes("openssl"));
  assert.ok(depends.some((value) => value.includes("docker.io") && value.includes("docker-ce")));
  assert.ok(depends.some((value) => value.includes("docker-compose") && value.includes("docker-compose-plugin")));
  assert.doesNotMatch(depends.join(","), /docker-compose-v2/);
  assert.match(dependencyHelper, /if ! command -v docker/);
  assert.match(dependencyHelper, /if ! docker compose version/);
  assert.doesNotMatch(dependencyHelper, /apt-get install -y .*docker\.io docker-compose/);
  assert.doesNotMatch(dependencyHelper, /download\.docker\.com|docker-compose-v2/);
  assert.match(postinst, /systemctl enable --now docker\.service/);
  assert.match(postinst, /docker info/);
  assert.match(postinst, /docker compose version/);
  assert.match(service, /Requires=docker\.service/);
});

test("first install initializes only Base Runtime state", () => {
  assert.match(supervisorMain, /load_or_create_host_identity/);
  assert.match(supervisorMain, /ensure_extension_registry/);
  assert.match(supervisorMain, /--build-info/);
  assert.match(supervisorInstaller, /build-identity\.json/);
  assert.doesNotMatch(supervisorInstaller, /PAYLOAD\.json/);
  assert.doesNotMatch(supervisorInstaller, /--payload/);
  assert.doesNotMatch(postinst, /PAYLOAD\.json/);
});

test("Linux build stages only target-specific Supervisor resources", () => {
  assert.match(viteConfig, /outDir:\s*["']dist\/frontend["']/);
  assert.match(fs.readFileSync(path.join(root, "src-tauri/tauri.conf.json"), "utf8"), /frontendDist.*dist\/frontend/);
  assert.match(buildMaster, /rmSync\(supervisorResDir, \{ recursive: true, force: true \}\)/);
  assert.match(buildMaster, /rm -rf src-tauri\/resources\/supervisor/);
  assert.match(buildMaster, /rm -rf ~\/\.actium-tauri-target\/release\/bundle\/deb/);
  assert.match(buildMaster, /rm -rf src-tauri\/target\/release\/bundle\/deb/);
  assert.match(buildMaster, /normalize-debian-package\.sh/);
  assert.match(buildMaster, /normalizeLocalDebianPackages/);
  assert.doesNotMatch(tauri.bundle?.resources ? JSON.stringify(tauri.bundle.resources) : "", /resources\/node/);
});

test("Linux release build never selects the Vite dev server", () => {
  assert.equal(releaseTauri.build?.devUrl, null);
  assert.equal(releaseTauri.build?.frontendDist, "../dist/frontend");
  assert.match(buildMaster, /tauri:build:linux/);
  assert.match(buildMaster, /verify-tauri-release-assets\.mjs/);
});

test("CSP remains universal and does not embed a customer endpoint", () => {
  const csp = tauri.app?.security?.csp ?? "";
  assert.match(csp, /connect-src[^;]*https:/);
  assert.doesNotMatch(csp, /supabase\.co/);
});

console.log("m5-2-clean-install: package, identity and Base Runtime contract verified");
