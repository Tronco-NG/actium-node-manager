import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

const dataPlaneRoot = resolve(import.meta.dirname, "../..");

async function read(relativePath) {
  return readFile(resolve(dataPlaneRoot, relativePath), "utf8");
}

function serviceBlock(compose, service, nextService) {
  const start = compose.indexOf(`  ${service}:`);
  assert.notEqual(start, -1, `Servicio ausente: ${service}`);
  const end = nextService ? compose.indexOf(`  ${nextService}:`, start + 1) : compose.indexOf("\nnetworks:", start);
  assert.notEqual(end, -1, `No se pudo delimitar ${service}`);
  return compose.slice(start, end);
}

test("Redis de LiveKit queda autenticado y confinado a su red privada", async () => {
  const [compose, bootstrapSh, bootstrapPs1, livekitConfig] = await Promise.all([
    read("compose.livekit.yml"),
    read("bootstrap.sh"),
    read("bootstrap.ps1"),
    read("livekit/livekit.yaml"),
  ]);
  const redis = serviceBlock(compose, "livekit-redis", "livekit");
  const livekit = serviceBlock(compose, "livekit");

  assert.match(redis, /requirepass \$\$\{redis_password\}/);
  assert.match(redis, /secrets: \[livekit_redis_password\]/);
  assert.match(redis, /networks: \[livekit-state\]/);
  assert.doesNotMatch(redis, /networks: \[[^\]]*fabric/);
  assert.match(livekit, /secrets: \[livekit_keys, livekit_redis_password\]/);
  assert.match(livekit, /umask 077/);
  assert.match(livekit, /password: .*\$\$\{redis_password\}/);
  assert.match(compose, /livekit-state: \{ internal: true \}/);
  assert.match(compose, /livekit_redis_password: \{ file:/);
  assert.match(bootstrapSh, /livekit_redis_password.*random_hex 32/);
  assert.match(bootstrapPs1, /livekit_redis_password.*New-SecureToken 32/);
  assert.match(livekitConfig, /password: __ACTIUM_LIVEKIT_REDIS_PASSWORD__/);
});

test("Connector local usa sólo la red del deployment y HTTP Telemetry exacto", async () => {
  const [compose, agentCompose, runtime, topology, networkContract] = await Promise.all([
    read("compose.connectivity.yml"),
    read("compose.agent.yml"),
    read("installer/src-tauri/actium-node-core/src/runtime.rs"),
    read("installer/src-tauri/actium-node-core/src/topology.rs"),
    read("services/connector/src/network-contract.ts"),
  ]);
  const connector = serviceBlock(compose, "connectivity-node-connector");

  assert.match(connector, /CONNECTIVITY_LOCAL_TELEMETRY_PROJECT: \$\{ACTIUM_TELEMETRY_COMPOSE_PROJECT:/);
  assert.match(connector, /networks: \[deployment, control-plane-egress\]/);
  assert.doesNotMatch(connector, /ACTIUM_RUNTIME_DB_|postgres_password|nats_password/);
  assert.doesNotMatch(compose, /ACTIUM_FABRIC_NETWORK/);
  assert.match(compose, /name: "\$\{ACTIUM_DEPLOYMENT_NETWORK:/);
  assert.match(runtime, /ACTIUM_TELEMETRY_COMPOSE_PROJECT/);
  assert.match(runtime, /http:\/\/\{project\}-gateway:8090/);
  assert.match(runtime, /ensure_deployment_docker_network/);
  assert.match(topology, /pub deployment_network_name: String/);
  assert.match(topology, /RUNTIME_TOPOLOGY_SCHEMA: u8 = 3/);
  assert.match(agentCompose, /topology\.schema!==3/);
  assert.match(agentCompose, /!topology\.deploymentNetworkName/);
  assert.match(networkContract, /url\.hostname !== `\$\{composeProject\}-gateway`/);
  assert.doesNotMatch(networkContract, /connectivity-telemetry-gateway|hostname === 'telemetry-gateway'/);
});

test("Telemetry local no conserva ownership SQL de Connectivity", async () => {
  const [repository, adapter, config, main, edgeCompose, telemetryCompose] = await Promise.all([
    read("services/telemetry/src/repository.ts"),
    read("services/telemetry/src/connectivity-relay.ts"),
    read("services/telemetry/src/config.ts"),
    read("services/telemetry/src/main.ts"),
    read("../connectivity-edge/compose.yml"),
    read("compose.telemetry.yml"),
  ]);
  const projector = serviceBlock(telemetryCompose, "telemetry-projector");

  assert.doesNotMatch(repository, /connectivity\.|relay_outbox|relay_receipts|node_leases/);
  assert.match(adapter, /Adapter exclusivo del plano Connectivity Edge/);
  assert.match(adapter, /"\$\{this\.schema\}"\."\$\{name\}"/);
  assert.match(config, /CONNECTIVITY_RELAY_DB_SCHEMA/);
  assert.match(main, /config\.relayEnabled\s*\?\s*new PostgresConnectivityRelayStore/);
  assert.match(edgeCompose, /ACTIUM_RUNTIME_DB_SCHEMA: public/);
  assert.match(edgeCompose, /CONNECTIVITY_RELAY_DB_SCHEMA: connectivity/);
  assert.doesNotMatch(telemetryCompose, /CONNECTIVITY_RELAY_ENABLED/);
  assert.doesNotMatch(projector, /connectivity_internal_relay_token/);
});
