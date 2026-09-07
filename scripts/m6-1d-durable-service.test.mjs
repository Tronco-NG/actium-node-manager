import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const run = promisify(execFile);
const root = resolve(import.meta.dirname, "..");
const binary = resolve(
  root,
  process.platform === "win32"
    ? "src-tauri/target/debug/actium-authority-service.exe"
    : "src-tauri/target/debug/actium-authority-service",
);

const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

async function waitForHealth(url, child) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`authority service exited with ${child.exitCode}`);
    try {
      const response = await fetch(`${url}/health`);
      if (response.ok) return response.json();
    } catch {
      // The listener may still be binding.
    }
    await sleep(100);
  }
  throw new Error("authority service health timeout");
}

async function runCeremony(fixture, dataDir, offlineKeys, onlineKeys, offlineSealing, onlineSealing) {
  const args = [
    "run", "--quiet", "--manifest-path", "src-tauri/Cargo.toml", "-p", "actium-authority-service",
    "--bin", "actium-authority-ceremony", "--",
    "--offline-key-dir", offlineKeys,
    "--online-key-dir", onlineKeys,
    "--offline-sealing-key-file", offlineSealing,
    "--online-sealing-key-file", onlineSealing,
    "--state-out", join(dataDir, "authority-state.json"),
    "--trust-bundle-out", join(dataDir, "trust-bundle.json"),
    "--root-authority-id", "actium-product-root-v1",
    "--confirm", "OFFLINE_ROOT_OWNER_APPROVED",
  ];
  await run("cargo", args, { cwd: root, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
}

test("durable Authority Service carga bundle prefirmado y readiness tras reinicio del proceso", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "actium-m6-1d-service-"));
  const port = 19000 + Math.floor(Math.random() * 1000);
  const baseUrl = `http://127.0.0.1:${port}`;
  let child;
  try {
    const offlineKeys = join(fixture, "offline-root-keys");
    const onlineKeys = join(fixture, "online-keys");
    const dataDir = join(fixture, "authority");
    const offlineSealing = join(fixture, "offline.sealing");
    const onlineSealing = join(fixture, "online.sealing");
    const sealing = (value) => `ACTIUM-SEALING-KEY-V1\n${value.toString("base64url")}\n`;
    await writeFile(offlineSealing, sealing(randomBytes(32)));
    await writeFile(onlineSealing, sealing(randomBytes(32)));
    await runCeremony(fixture, dataDir, offlineKeys, onlineKeys, offlineSealing, onlineSealing);

    await run("cargo", ["build", "--quiet", "--manifest-path", "src-tauri/Cargo.toml", "-p", "actium-authority-service", "--bin", "actium-authority-service"], {
      cwd: root,
      windowsHide: true,
      maxBuffer: 2 * 1024 * 1024,
    });
    const serviceEnv = {
      ...process.env,
      ACTIUM_ENVIRONMENT: "lab",
      ACTIUM_AUTHORITY_LISTEN: `127.0.0.1:${port}`,
      ACTIUM_AUTHORITY_DATA_DIR: dataDir,
      ACTIUM_AUTHORITY_KEY_DIR: onlineKeys,
      ACTIUM_AUTHORITY_SEALING_KEY_FILE: onlineSealing,
      ACTIUM_AUTHORITY_TRUST_BUNDLE_FILE: join(dataDir, "trust-bundle.json"),
    };
    const startService = () => spawn(binary, [], {
      cwd: root,
      windowsHide: true,
      stdio: ["ignore", "ignore", "pipe"],
      env: serviceEnv,
    });
    const stopService = async () => {
      if (!child || child.exitCode !== null) return;
      const exited = new Promise((resolveExit) => child.once("exit", resolveExit));
      child.kill();
      await exited;
      child = undefined;
    };
    child = startService();

    const health = await waitForHealth(baseUrl, child);
    assert.deepEqual(
      { status: health.status, authorityState: health.authorityState, trustBundleState: health.trustBundleState },
      { status: "alive", authorityState: "INITIALIZED", trustBundleState: "READY" },
    );

    const headers = {
      "content-type": "application/json",
      "x-actium-authority-contract": "actium-authority-service@1.0.0",
      "x-actium-request-id": "m61d-service-readiness-1",
      "x-actium-service-id": "center",
    };
    const readiness = await fetch(`${baseUrl}/v1/readiness`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        contract: "actium-authority-service@1.0.0",
        operation: "readiness",
        requestId: "m61d-service-readiness-1",
        caller: "center",
        capability: "host_enrollment",
      }),
    });
    assert.equal(readiness.status, 200);
    assert.equal((await readiness.json()).status, "ready");

    const bundle = await fetch(`${baseUrl}/v1/trust-bundle`, {
      method: "POST",
      headers: {
        ...headers,
        "x-actium-request-id": "m61d-service-bundle-1",
      },
      body: JSON.stringify({
        contract: "actium-authority-service@1.0.0",
        operation: "trust_bundle",
        requestId: "m61d-service-bundle-1",
        caller: "center",
      }),
    });
    assert.equal(bundle.status, 200);
    const signedBundle = await bundle.json();
    assert.equal(typeof signedBundle.signature, "string");
    assert.equal(signedBundle.productRoots.length, 1);

    await stopService();
    child = startService();
    const restartedHealth = await waitForHealth(baseUrl, child);
    assert.deepEqual(
      { status: restartedHealth.status, authorityState: restartedHealth.authorityState, trustBundleState: restartedHealth.trustBundleState },
      { status: "alive", authorityState: "INITIALIZED", trustBundleState: "READY" },
    );
    await stopService();
    const state = JSON.parse(await readFile(join(dataDir, "authority-state.json"), "utf8"));
    assert.equal(state.publicOnlyKeyIds.length, 1);
    assert.equal(state.authorities.some((authority) => authority.keyId === state.publicOnlyKeyIds[0]), true);
  } finally {
    if (child && child.exitCode === null) child.kill();
    await rm(fixture, { recursive: true, force: true });
  }
});
