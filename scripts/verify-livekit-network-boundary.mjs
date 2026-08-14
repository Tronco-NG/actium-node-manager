import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const dataPlaneRoot = resolve(import.meta.dirname, "../..");
const composeFile = resolve(dataPlaneRoot, "compose.livekit.yml");
const suffix = `${process.pid}-${Date.now().toString(36)}`;
const project = `actium-lab-livekit-gate-${suffix}`.toLowerCase();
const redisContainer = `${project}-redis`;
const livekitContainer = `${project}-livekit`;
const fabricNetwork = `${project}-fabric`;
const root = await mkdtemp(join(tmpdir(), "actium-livekit-gate-"));
const secrets = join(root, "secrets");
const unitId = "33333333-3333-4333-8333-333333333333";
const deploymentId = "44444444-4444-4444-8444-444444444444";
const fabricId = "55555555-5555-4555-8555-555555555555";
const redisPassword = "5a".repeat(32);
let composeStarted = false;
let networkCreated = false;

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: dataPlaneRoot,
    encoding: "utf8",
    env: { ...process.env, ...options.env },
    timeout: options.timeout ?? 120_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} fallo (${result.status})\n${result.stdout}\n${result.stderr}`);
  }
  return `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
}

const environment = {
  ACTIUM_RUNTIME_UNIT_PROJECT: project,
  ACTIUM_NODE_ROOT: root.replaceAll("\\", "/"),
  ACTIUM_RUNTIME_UNIT_ID: unitId,
  ACTIUM_FABRIC_NETWORK: fabricNetwork,
  ACTIUM_SECRETS_DIR: secrets.replaceAll("\\", "/"),
  ACTIUM_DEPLOYMENT_ID: deploymentId,
  ACTIUM_FABRIC_ID: fabricId,
  LIVEKIT_BIND_ADDRESS: "127.0.0.1",
  LIVEKIT_HTTP_PORT: "27880",
  LIVEKIT_RTC_TCP_PORT: "27881",
  LIVEKIT_UDP_MIN_PORT: "60200",
  LIVEKIT_UDP_MAX_PORT: "60210",
};

try {
  await mkdir(secrets, { recursive: true });
  await mkdir(join(root, "persistent", "runtime-units", unitId, "redis"), { recursive: true });
  await writeFile(join(secrets, "livekit_redis_password"), `${redisPassword}\n`, { mode: 0o600 });
  await writeFile(join(secrets, "livekit_keys"), `lk_phase3gate: ${"9b".repeat(32)}\n`, { mode: 0o600 });

  run("docker", ["network", "create", "--internal", fabricNetwork]);
  networkCreated = true;
  run("docker", ["compose", "-f", composeFile, "config", "--quiet"], { env: environment });
  run("docker", ["compose", "-f", composeFile, "up", "-d", "--wait"], {
    env: environment,
    timeout: 180_000,
  });
  composeStarted = true;

  const redisInspect = JSON.parse(run("docker", ["inspect", redisContainer]));
  const redisNetworks = Object.keys(redisInspect[0]?.NetworkSettings?.Networks ?? {});
  assert.deepEqual(redisNetworks, [`${project}_livekit-state`]);
  const stateNetwork = JSON.parse(run("docker", ["network", "inspect", redisNetworks[0]]));
  assert.equal(stateNetwork[0]?.Internal, true);

  const unauthenticated = run("docker", ["exec", redisContainer, "redis-cli", "ping"]);
  assert.match(unauthenticated, /NOAUTH Authentication required/);
  const authenticated = run("docker", [
    "exec",
    redisContainer,
    "/bin/sh",
    "-ec",
    "export REDISCLI_AUTH=\"$(tr -d '[:space:]' < /run/secrets/livekit_redis_password)\"; exec redis-cli ping",
  ]);
  assert.equal(authenticated, "PONG");

  const livekitInspect = JSON.parse(run("docker", ["inspect", livekitContainer]));
  assert.equal(livekitInspect[0]?.State?.Health?.Status, "healthy");
  console.log("livekit_network_boundary=PASS");
  console.log(`redis_network=${redisNetworks[0]}`);
  console.log("redis_unauthenticated=NOAUTH");
  console.log("redis_authenticated=PONG");
  console.log("livekit_health=healthy");
} finally {
  if (composeStarted) {
    spawnSync("docker", ["compose", "-f", composeFile, "down", "--remove-orphans"], {
      cwd: dataPlaneRoot,
      env: { ...process.env, ...environment },
      encoding: "utf8",
      timeout: 120_000,
    });
  }
  if (networkCreated) {
    spawnSync("docker", ["network", "rm", fabricNetwork], { encoding: "utf8", timeout: 30_000 });
  }
  await rm(root, { recursive: true, force: true });
}
