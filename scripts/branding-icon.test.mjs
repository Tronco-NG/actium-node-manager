import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8").replaceAll("\r\n", "\n");
const manager = read("src/main.ts");
const styles = read("src/styles.css");
const buildScript = read("src-tauri/build.rs");
const config = JSON.parse(read("src-tauri/tauri.conf.json"));
const sidebarBrand = manager.match(/<header class="sidebar-brand"[^>]*>([\s\S]*?)<\/header>/)?.[1] ?? "";

test("el lockup del sidebar es vectorial, conserva el icono y comparte su paleta", () => {
  const svg = read("src/assets/icons/actium-node-manager.svg");
  const lockup = read("src/assets/icons/actium-node-manager-lockup.svg");
  assert.match(svg, /<svg\b[^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /viewBox="0 0 320 320"/);
  assert.doesNotMatch(svg, /<\s*(script|foreignObject)\b/i);
  assert.doesNotMatch(svg, /\b(?:href|xlink:href)\s*=\s*["'](?:https?:|\/\/)/i);
  assert.match(manager, /new URL\("\.\/assets\/icons\/actium-node-manager\.svg", import\.meta\.url\)\.href/);
  assert.match(manager, /new URL\("\.\/assets\/icons\/actium-node-manager-lockup\.svg", import\.meta\.url\)\.href/);
  assert.match(sidebarBrand, /<img\b[^>]*class="sidebar-brand-lockup"[^>]*src="\$\{nodeManagerBrandLockup\}"/);
  assert.match(sidebarBrand, /<img\b[^>]*class="sidebar-brand-logo"[^>]*src="\$\{nodeManagerBrandIcon\}"/);
  assert.match(manager, /<header class="sidebar-brand" role="group" aria-label="Actium Node Manager">/);
  assert.match(lockup, /<svg\b[^>]*width="184" height="71" viewBox="0 0 184 71"/);
  assert.match(lockup, /<svg x="0" y="13\.5" width="44" height="44" viewBox="0 0 320 320"/);
  const iconContents = svg.slice(svg.indexOf(">") + 1, svg.lastIndexOf("</svg>")).trim();
  assert.ok(lockup.includes(iconContents), "el lockup reutiliza literalmente el arte del icono de sidebar");
  assert.match(lockup, /<text class="wordmark-title" x="38\.5" y="49">ctium<\/text>/);
  assert.match(lockup, /<text class="wordmark-product" x="90" y="49">Node Manager<\/text>/);
  assert.match(lockup, /class="wordmark-title" x="38\.5" y="49">ctium<\/text>[\s\S]*class="wordmark-product" x="90" y="49">Node Manager<\/text>/);
  assert.match(lockup, /\.wordmark-title\s*\{[^}]*font-family:\s*Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;[^}]*font-size:\s*18px;[^}]*font-weight:\s*700;[^}]*fill:\s*url\(#wordmark-metal\);/);
  assert.match(lockup, /\.wordmark-product\s*\{[^}]*font-family:\s*Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;[^}]*font-size:\s*11\.5px;[^}]*font-weight:\s*600;[^}]*fill:\s*#AAB6A8;/);
  assert.match(lockup, /<linearGradient id="wordmark-metal"[^>]*>[\s\S]*?<stop offset="0%" stop-color="#556959"\/>[\s\S]*?<stop offset="100%" stop-color="#344337"\/>[\s\S]*?<\/linearGradient>/);
  assert.doesNotMatch(lockup, /#81927F|#5B6F5D|wordmark-title[^}]*fill:\s*#[\da-f]{6}/i);
  assert.doesNotMatch(lockup, /<\s*(script|foreignObject)\b/i);
  assert.doesNotMatch(lockup, /\b(?:href|xlink:href)\s*=\s*["'](?:https?:|\/\/)/i);
  assert.doesNotMatch(sidebarBrand, /sidebar-brand-copy/);
  assert.match(styles, /\.sidebar-brand-logo\s*\{[^}]*width:\s*44px;[^}]*height:\s*44px;[^}]*object-fit:\s*contain;/);
  assert.match(styles, /\.sidebar-brand-lockup\s*\{[^}]*width:\s*184px;[^}]*max-width:\s*100%;[^}]*height:\s*71px;[^}]*object-position:\s*left center;/);
  assert.match(styles, /\.sidebar-brand\s*\{[^}]*justify-content:\s*flex-start;[^}]*padding:\s*0 10px;/);
  assert.match(styles, /\.manager-app\.sidebar-collapsed \.sidebar-brand\s*\{[^}]*justify-content:\s*flex-start;[^}]*padding-inline:\s*10px;/);
  assert.match(styles, /\.manager-app\.sidebar-collapsed \.sidebar-brand-lockup\s*\{\s*display:\s*none;/);
  assert.match(styles, /\.manager-app\.sidebar-collapsed \.sidebar-brand-logo\s*\{\s*display:\s*block;/);
  assert.match(styles, /\.manager-app\.sidebar-collapsed \.sidebar-channel-switcher,[\s\S]*?\.manager-app\.sidebar-collapsed \.sidebar-section-label,[\s\S]*?\{\s*display:\s*none !important;/);
});

test("Tauri conserva la lista de iconos de bundle para regenerar desde el mismo SVG", () => {
  assert.deepEqual(config.bundle.icon, [
    "icons/32x32.png",
    "icons/128x128.png",
    "icons/128x128@2x.png",
    "icons/icon.ico",
  ]);
  for (const icon of config.bundle.icon) {
    assert.ok(fs.statSync(path.join(root, "src-tauri", icon)).size > 0, `${icon} debe existir`);
  }
});

test("Cargo invalida el ejecutable cuando cambia cualquiera de los iconos Tauri", () => {
  assert.match(buildScript, /println!\("cargo:rerun-if-changed=\{icon\}"\)/);
  for (const icon of config.bundle.icon) {
    assert.ok(buildScript.includes(`"${icon}"`), `build.rs debe observar ${icon}`);
  }
});
