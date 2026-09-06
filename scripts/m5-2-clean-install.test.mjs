import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const tauri = JSON.parse(fs.readFileSync(path.join(root, "src-tauri/tauri.conf.json"), "utf8"));
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
  assert.ok(depends.includes("docker.io"));
  assert.ok(depends.includes("docker-compose"));
  assert.doesNotMatch(depends.join(","), /docker-ce|docker-compose-plugin|docker-compose-v2/);
  assert.match(dependencyHelper, /apt-get install -y .*docker\.io docker-compose/);
  assert.doesNotMatch(dependencyHelper, /download\.docker\.com|docker-ce|docker-compose-plugin|docker-compose-v2/);
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
  assert.match(viteConfig, /emptyOutDir:\s*false/);
  assert.match(buildMaster, /rmSync\(supervisorResDir, \{ recursive: true, force: true \}\)/);
  assert.match(buildMaster, /rm -rf src-tauri\/resources\/supervisor/);
  assert.match(buildMaster, /rm -rf ~\/\.actium-tauri-target\/release\/bundle\/deb/);
  assert.match(buildMaster, /rm -rf src-tauri\/target\/release\/bundle\/deb/);
  assert.match(buildMaster, /normalize-debian-package\.sh/);
  assert.match(buildMaster, /normalizeLocalDebianPackages/);
  assert.doesNotMatch(tauri.bundle?.resources ? JSON.stringify(tauri.bundle.resources) : "", /resources\/node/);
});

test("CSP remains universal and does not embed a customer endpoint", () => {
  const csp = tauri.app?.security?.csp ?? "";
  assert.match(csp, /connect-src[^;]*https:/);
  assert.doesNotMatch(csp, /supabase\.co/);
});

console.log("m5-2-clean-install: package, identity and Base Runtime contract verified");
