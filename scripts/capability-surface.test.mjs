import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("la superficie TS coincide con el catalogo Rust", async () => {
  const rust = await readFile(resolve(installerRoot, "src-tauri/actium-node-core/src/capability_surface.rs"), "utf8");
  const ts = await readFile(resolve(installerRoot, "src/capability-surface.ts"), "utf8");
  for (const profile of [
    "site-core",
    "telemetry",
    "radio-control",
    "radio-saf",
    "radio-turn",
    "radio-livekit",
    "observability",
    "connectivity",
  ]) {
    assert.match(rust, new RegExp(`"${profile}"`));
    assert.match(ts, new RegExp(`"${profile}"`));
  }
  assert.match(rust, /connectivity" => &\["telemetry"\]/);
  assert.match(ts, /connectivity: \["telemetry"\]/);
  assert.match(rust, /SITE_CORE_PORT/);
  assert.match(ts, /site-core-port/);
});

test("site-core puro no exige TURN ni Telemetry en wizard o config", async () => {
  const main = await readFile(resolve(installerRoot, "src/main.ts"), "utf8");
  assert.match(main, /data-surface="site-core"/);
  assert.match(main, /data-surface="radio-turn"/);
  assert.match(main, /refreshCapabilitySurface/);
  assert.match(main, /visiblePortFieldIds\(selectedProfiles\(\)\)/);
  assert.doesNotMatch(
    main.split("const required =")[1]?.split(";")[0] ?? "",
    /telemetry-port", "radio-control-port", "radio-saf-port", "site-core-port", "prometheus-port", "grafana-port/,
  );
});

test("installer_min_version historica no se inventa", async () => {
  const rust = await readFile(resolve(installerRoot, "src-tauri/actium-node-core/src/capability_surface.rs"), "utf8");
  assert.match(rust, /profile == "connectivity"/);
  assert.match(rust, /"0\.4\.0"/);
  assert.match(rust, /"0\.3\.0"/);
  assert.doesNotMatch(rust, /0\.5\.0/);
});
