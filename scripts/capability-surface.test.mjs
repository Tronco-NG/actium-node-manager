import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  effectiveProfiles,
  installerMinVersionForProfiles,
  selectAllProfiles,
  visibleFieldIds,
  visiblePortFieldIds,
} from "../src/capability-surface.ts";

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const MATRIX = [
  {
    name: "site-core only",
    profiles: ["site-core"],
    present: ["site-core-port", "site-core-public-url"],
    absent: [
      "telemetry-port",
      "turn-port",
      "livekit-http-port",
      "prometheus-port",
      "connectivity-edge-control-url",
      "radio-control-port",
    ],
    ports: ["site-core-port"],
  },
  {
    name: "telemetry only",
    profiles: ["telemetry"],
    present: ["telemetry-port", "telemetry-ingress-public-url"],
    absent: ["site-core-port", "turn-port", "connectivity-edge-control-url"],
    ports: ["telemetry-port"],
  },
  {
    name: "radio-control only",
    profiles: ["radio-control"],
    present: ["radio-control-port", "radio-control-public-url"],
    absent: ["turn-port", "telemetry-port"],
    ports: ["radio-control-port"],
  },
  {
    name: "radio-saf",
    profiles: ["radio-saf"],
    present: ["radio-saf-port", "radio-archive-host-path"],
    absent: ["turn-port", "livekit-http-port"],
    ports: ["radio-saf-port"],
  },
  {
    name: "radio-turn",
    profiles: ["radio-turn"],
    present: ["turn-realm", "turn-port", "turn-urls"],
    absent: ["livekit-http-port", "telemetry-port"],
    ports: ["turn-port", "turn-tls-port", "turn-min-port", "turn-max-port"],
  },
  {
    name: "radio-livekit + closure",
    profiles: ["radio-livekit"],
    present: ["livekit-node-ip", "livekit-http-port", "livekit-udp-max-port"],
    absent: ["turn-port"],
    ports: ["livekit-http-port", "livekit-rtc-tcp-port", "livekit-udp-min-port", "livekit-udp-max-port"],
  },
  {
    name: "observability",
    profiles: ["observability"],
    present: ["prometheus-port", "grafana-port", "metrics-public-url"],
    absent: ["turn-port", "telemetry-port"],
    ports: ["prometheus-port", "grafana-port"],
  },
  {
    name: "connectivity + telemetry dependency",
    profiles: ["connectivity"],
    present: ["connectivity-edge-control-url", "telemetry-port"],
    absent: ["turn-port", "site-core-port"],
    ports: ["telemetry-port"],
  },
  {
    name: "site-core + telemetry",
    profiles: ["site-core", "telemetry"],
    present: ["site-core-port", "telemetry-port"],
    absent: ["turn-port", "livekit-http-port"],
    ports: ["site-core-port", "telemetry-port"],
  },
];

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

test("matriz de capability-scoping: schema, required y ports", () => {
  for (const item of MATRIX) {
    const visible = visibleFieldIds(item.profiles);
    const ports = visiblePortFieldIds(item.profiles);
    const effective = effectiveProfiles(item.profiles);
    for (const field of item.present) {
      assert.ok(visible.has(field), `${item.name} debe mostrar ${field}`);
    }
    for (const field of item.absent) {
      assert.ok(!visible.has(field), `${item.name} no debe mostrar ${field}`);
    }
    assert.deepEqual(new Set(ports), new Set(item.ports), `${item.name} ports`);
    if (item.profiles.includes("connectivity")) {
      assert.ok(effective.includes("telemetry"), "Connectivity cierra sobre Telemetry");
    }
    if (item.profiles.length === 1 && item.profiles[0] === "site-core") {
      assert.deepEqual(effective, ["site-core"]);
    }
  }
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

test("seleccionar todo exige refresh de capability surface", async () => {
  const main = await readFile(resolve(installerRoot, "src/main.ts"), "utf8");
  const selectAllHandler = main.split('document.querySelector("#select-all")')[1] ?? "";
  assert.match(selectAllHandler, /selectAllProfiles/);
  assert.match(selectAllHandler, /refreshCapabilitySurface/);
  const documentLike = {
    boxes: [
      { value: "site-core", disabled: false, checked: false },
      { value: "telemetry", disabled: false, checked: false },
      { value: "radio-turn", disabled: true, checked: false },
    ],
    hidden: new Set(["telemetry", "radio-turn"]),
    refresh() {
      const selected = this.boxes.filter((item) => item.checked).map((item) => item.value);
      this.hidden = new Set(["site-core", "telemetry", "radio-turn"].filter((profile) => !selected.includes(profile)));
    },
    selectAll() {
      const decision = selectAllProfiles(this.boxes);
      this.boxes.forEach((box) => {
        if (!box.disabled && decision.selected.includes(box.value)) box.checked = true;
      });
      if (decision.refreshRequired) this.refresh();
    },
  };
  documentLike.selectAll();
  assert.deepEqual(
    documentLike.boxes.filter((item) => item.checked).map((item) => item.value),
    ["site-core", "telemetry"],
  );
  assert.equal(documentLike.hidden.has("telemetry"), false);
  assert.equal(documentLike.hidden.has("radio-turn"), true);
  assert.ok(selectAllProfiles(documentLike.boxes).refreshRequired);
});

test("resume no autoasigna puertos; el boton explicito si", async () => {
  const main = await readFile(resolve(installerRoot, "src/main.ts"), "utf8");
  assert.match(main, /!installation.recoverableIncompletePreparation/);
  assert.match(main, /portsExplicitlyAssigned = true/);
  assert.match(main, /assignAvailablePorts\(false\)/);
  assert.match(main, /assignAvailablePorts\(true\)/);
});

test("installer_min_version historica no se inventa", () => {
  assert.equal(installerMinVersionForProfiles(["site-core"]), "0.3.0");
  assert.equal(installerMinVersionForProfiles(["connectivity"]), "0.4.0");
  assert.equal(installerMinVersionForProfiles(["radio-turn", "radio-livekit"]), "0.3.0");
});
