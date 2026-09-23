import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { dashboardLayout, dashboardPage } from "../src/dashboard-layout.ts";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const manager = fs.readFileSync(path.join(root, "src/main.ts"), "utf8").replaceAll("\r\n", "\n");
const styles = fs.readFileSync(path.join(root, "src/styles.css"), "utf8").replaceAll("\r\n", "\n");

test("el Dashboard adapta columnas y páginas al tamaño real de una VM", () => {
  assert.deepEqual(dashboardLayout(918, 716, true), { columns: 2, rows: 1, pageSize: 2 });
  assert.deepEqual(dashboardLayout(640, 600, false), { columns: 1, rows: 1, pageSize: 1 });
  assert.deepEqual(dashboardLayout(1366, 900, false), { columns: 3, rows: 2, pageSize: 6 });
  assert.deepEqual(dashboardLayout(2560, 1494, false), { columns: 3, rows: 3, pageSize: 9 });
});

test("la página de nodos recorta y limita índices cuando cambia el inventario o el viewport", () => {
  const nodes = Array.from({ length: 23 }, (_, index) => `node-${index + 1}`);
  assert.deepEqual(dashboardPage(nodes, 0, 6), {
    page: 0, pageCount: 4, start: 0, end: 6, items: nodes.slice(0, 6),
  });
  assert.deepEqual(dashboardPage(nodes, 3, 6), {
    page: 3, pageCount: 4, start: 18, end: 23, items: nodes.slice(18),
  });
  assert.deepEqual(dashboardPage(nodes, 99, 9), {
    page: 2, pageCount: 3, start: 18, end: 23, items: nodes.slice(18),
  });
  assert.deepEqual(dashboardPage([], 99, 0), {
    page: 0, pageCount: 1, start: 0, end: 0, items: [],
  });
});

test("Dashboard fija controles, deja Configuración en sidebar y mantiene una sola actualización", () => {
  assert.match(manager, /active === "dashboard" \? "" : `<header class="manager-pagebar/);
  assert.match(manager, /data-route="#\/settings"/);
  assert.match(manager, /if \(area === "settings"\)/);
  assert.match(manager, /aria-label="Actualizar estado"/);
  assert.equal([...manager.matchAll(/id="refresh-nodes"/g)].length, 1);
  const sidebarFooter = manager.match(/<footer class="sidebar-footer">([\s\S]*?)<\/footer>/)?.[1] ?? "";
  assert.doesNotMatch(sidebarFooter, /install-supervisor-btn|sidebar-channels-strip/);
  assert.doesNotMatch(manager, /manager-product-context/);
  assert.match(manager, /connectivityFallbackOrder/);
  assert.match(manager, /function renderManagerSettings\(\)/);
  assert.match(manager, /const supervisorCard = \(channel: "stable" \| "lab"/);
  assert.match(manager, /class="install-supervisor-btn primary compact" data-channel="\$\{channel\}"/);
  assert.match(manager, /const needsRepair = Boolean\(status\?\.installed && !status\.available\)/);
  assert.match(manager, /Reinstalar \/ activar/);
  assert.match(manager, /querySelectorAll<HTMLButtonElement>\("#install-channel-supervisor-btn, \.install-supervisor-btn"\)[\s\S]*handleInstallSupervisor\(channel\)/);
  assert.match(manager, /system\.payloadDigest/);
  assert.match(manager, /system\.payloadSchemaVersion/);
  assert.match(manager, /id="previous-node-page"[\s\S]*id="next-node-page"/);
  assert.match(manager, /const page = dashboardPage\(managedNodes, managerPage, layout\.pageSize\)/);
  assert.match(manager, /document\.querySelector\("#previous-node-page"\)\?\.addEventListener\("click"[\s\S]*managerPage = Math\.max\(0, managerPage - 1\)/);
  assert.match(manager, /document\.querySelector\("#next-node-page"\)\?\.addEventListener\("click"[\s\S]*managerPage \+= 1/);
  assert.match(styles, /\.dashboard-footer\s*\{[\s\S]*position:\s*fixed[\s\S]*left:\s*var\(--manager-sidebar-width\)[\s\S]*bottom:\s*0/);
  assert.match(styles, /\.dashboard-footer\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\) auto/);
  assert.match(styles, /\.dashboard-footer \.operation-chat\s*\{[\s\S]*justify-self:\s*end/);
  assert.match(styles, /\.dashboard-footer \.operation-chat-panel\s*\{[\s\S]*right:\s*0[\s\S]*left:\s*auto[\s\S]*max-width:\s*calc\(100vw - var\(--manager-sidebar-width\) - 32px\)[\s\S]*transform:\s*none/);
  assert.match(styles, /@media \(max-width: 760px\)\s*\{[\s\S]*\.dashboard-footer\s*\{[\s\S]*grid-template-columns:\s*minmax\(0, 1fr\)[\s\S]*grid-template-rows:\s*auto auto/);
  assert.match(styles, /\.supervisor-setting-action\s*\{/);
  assert.match(manager, /dashboard-node-grid \$\{managedNodes\.length === 0 \? "is-empty" : ""\}/);
  assert.match(styles, /\.node-list\.dashboard-node-grid\.is-empty\s*\{\s*grid-template-rows:\s*minmax\(0, 1fr\)/);
  assert.match(styles, /\.node-card-details\s*\{/);
  assert.match(manager, /<details class="node-card-details">/);
});

test("la flecha del sidebar apunta según la acción disponible", () => {
  assert.match(manager, /sidebarToggle\.textContent = collapsed \? "›" : "‹"/);
  assert.doesNotMatch(styles, /\.manager-app\.sidebar-collapsed\s+\.sidebar-toggle\s*\{[^}]*transform\s*:/);
});
