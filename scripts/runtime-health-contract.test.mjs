import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataPlaneRoot = resolve(installerRoot, "..");

test("Agent consume topologia materializada y no aliases globales", async () => {
  const source = await readFile(resolve(dataPlaneRoot, "services/agent/src/main.ts"), "utf8");
  const compose = await readFile(resolve(dataPlaneRoot, "compose.agent.yml"), "utf8");

  assert.match(source, /loadRuntimeTopology\(RUNTIME_TOPOLOGY_PATH\)/);
  assert.match(compose, /state\/runtime-topology\.json:\/var\/lib\/actium-node-topology\/runtime-topology\.json:ro/);
  for (const alias of [
    "http://data-plane-nats",
    "http://data-plane-minio",
    "http://telemetry-gateway",
    "http://site-core",
    "http://connectivity-node-connector",
    "http://radio-plane",
    "http://radio-livekit",
    "http://data-plane-prometheus",
    "tcpProbe('data-plane-postgres'",
    "tcpProbe('radio-turn'",
  ]) {
    assert.equal(source.includes(alias), false, `Alias global prohibido en Agent: ${alias}`);
  }
});

test("TURN usa allocation autenticada y Site Core usa readiness", async () => {
  const turn = await readFile(resolve(dataPlaneRoot, "compose.turn.yml"), "utf8");
  const siteCore = await readFile(resolve(dataPlaneRoot, "compose.site-core.yml"), "utf8");
  const livekit = await readFile(resolve(dataPlaneRoot, "compose.livekit.yml"), "utf8");

  assert.match(turn, /turnutils_uclient -t -y -c -n 1 -m 1 -W/);
  assert.match(turn, /cat \/run\/secrets\/turn_auth_secret/);
  assert.doesNotMatch(turn, /healthcheck:[\s\S]*\/(?:dev\/)?tcp/);
  assert.match(siteCore, /http:\/\/127\.0\.0\.1:8088\/health\/ready/);
  assert.doesNotMatch(siteCore, /http:\/\/127\.0\.0\.1:8088\/health\/live/);
  assert.match(livekit, /wget -q --spider http:\/\/127\.0\.0\.1:\$\$\{LIVEKIT_HTTP_PORT:-17880\}\//);
});
