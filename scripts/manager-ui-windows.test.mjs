import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8").replaceAll("\r\n", "\n");
const manager = read("src/main.ts");
const styles = read("src/styles.css");

test("Node Manager expone ventanas separadas por boundary", () => {
  for (const route of [
    "#/authority-fabric/status",
    "#/authority-fabric/root-brief",
    "#/authority-fabric/ceremony",
    "#/authority-fabric/lifecycle",
    "#/connectivity/routes",
    "#/connectivity/remote-ops",
    "#/connectivity/relay",
    "#/connectivity/wan",
  ]) {
    assert.match(manager, new RegExp(route.replaceAll("/", "\\/")));
  }
  assert.match(manager, /function managerWindowFor\(area: ManagerArea\)/);
  assert.match(manager, /function managerWindowForRoute\(area: ManagerArea, rawRoute: string\)/);
  assert.match(manager, /manager-section-nav/);
  assert.match(manager, /data-authority-window=/);
  assert.match(manager, /data-connectivity-window=/);
});

test("Authority y Connectivity esconden las ventanas fuera de scope", () => {
  for (const id of [
    "authority-status-window",
    "authority-root-brief-rebuild",
    "authority-ceremony-window",
    "authority-lifecycle-window",
    "authority-enrollment-window",
    "connectivity-agent-window",
    "connectivity-routes-window",
    "connectivity-remote-ops-window",
    "connectivity-wan-window",
  ]) {
    assert.match(manager, new RegExp(`id=\\"${id}\\"`));
  }
  assert.match(styles, /authority-shell\[data-authority-window=/);
  assert.match(styles, /connectivity-shell\[data-connectivity-window=/);
  assert.match(manager, /authorityWindow !== "root-brief" \? "hidden"/);
  assert.match(manager, /authorityWindow !== "ceremony" \? "hidden"/);
  assert.match(manager, /authorityWindow !== "lifecycle" \? "hidden"/);
  assert.match(manager, /id=\"authority-enrollment-window\" class=\"infrastructure-grid\" style=\"display:none\" hidden/);
  assert.match(manager, /id=\"authority-ceremony-window\" class=\"infrastructure-section\" style=\"display:\$\{authorityWindow === \"ceremony\" \? \"block\" : \"none\"\}/);
  assert.match(manager, /id=\"authority-lifecycle-window\" class=\"infrastructure-section\" style=\"display:\$\{authorityWindow === \"lifecycle\" \? \"block\" : \"none\"\}/);
  assert.match(manager, /id=\"connectivity-relay-window\" class=\"infrastructure-section\" style=\"display:\$\{connectivityWindow === \"relay\" \? \"block\" : \"none\"\}/);
});

test("La navegación de ventanas no puede capturar la altura del workspace", () => {
  assert.match(styles, /\.manager-app\s*\{[\s\S]*height:\s*100vh[\s\S]*grid-template-rows:\s*minmax\(0,\s*1fr\)/);
  assert.match(styles, /\.manager-workspace\s*\{[\s\S]*height:\s*100%[\s\S]*grid-template-rows:\s*72px\s+max-content\s+minmax\(0,\s*1fr\)/);
  assert.match(styles, /\.manager-section-nav\s*\{[\s\S]*align-self:\s*start[\s\S]*align-items:\s*flex-start[\s\S]*align-content:\s*start/);
  assert.match(styles, /\.manager-section-nav button\s*\{[\s\S]*height:\s*auto[\s\S]*align-self:\s*flex-start[\s\S]*flex:\s*0\s+0\s+auto/);
});

test("Capability unavailable no se presenta como readiness operativa", () => {
  assert.match(manager, /function authorityEnrollmentOperational/);
  assert.match(manager, /function authorityCapabilityDisplayState/);
  assert.match(manager, /authorityCapabilityDisplayState\(row\)/);
  assert.match(manager, /const localReady = enrollmentAuthorityReadiness\.authorityConfigured/);
  assert.match(manager, /authorityEnrollmentOperational\(enrollmentAuthorityReadiness\)/);
});

test("La fila de Trust bundle cierra el atributo de clase antes de seguir con el HTML", () => {
  assert.match(manager, /readiness\.trustBundle\.code\.toUpperCase\(\)\) \? "ok" : "bad"\}"><i><\/i>/);
});

console.log("manager-ui-windows: ok");
