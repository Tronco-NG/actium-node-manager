import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import test from "node:test";

const run = promisify(execFile);
const root = resolve(import.meta.dirname, "..");

test("offline ceremony emits root-signed public state and no online root key", async () => {
  const fixture = await mkdtemp(join(tmpdir(), "actium m6 1d ceremony "));
  try {
    const offlineKeys = join(fixture, "offline-root-keys");
    const onlineKeys = join(fixture, "online-keys");
    const dataDir = join(fixture, "authority");
    const offlineSealing = join(offlineKeys, ".actium-root-sealing.key");
    const onlineSealing = join(fixture, "online.sealing");
    const sealing = (value) => `ACTIUM-SEALING-KEY-V1\n${value.toString("base64url")}\n`;
    await mkdir(offlineKeys, { recursive: true });
    await writeFile(offlineSealing, sealing(randomBytes(32)));
    await writeFile(onlineSealing, sealing(randomBytes(32)));

    const args = [
      "--offline-key-dir", offlineKeys,
      "--online-key-dir", onlineKeys,
      "--offline-sealing-key-file", offlineSealing,
      "--online-sealing-key-file", onlineSealing,
      "--state-out", join(dataDir, "authority-state.json"),
      "--trust-bundle-out", join(dataDir, "trust-bundle.json"),
      "--root-authority-id", "actium-product-root-v1",
      "--confirm", "OFFLINE_ROOT_OWNER_APPROVED",
    ];
    const command = ["run", "--quiet", "--manifest-path", "src-tauri/Cargo.toml", "-p", "actium-authority-service", "--bin", "actium-authority-ceremony", "--", ...args];
    await run("cargo", command, { cwd: root, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });

    const state = JSON.parse(await readFile(join(dataDir, "authority-state.json"), "utf8"));
    const bundle = JSON.parse(await readFile(join(dataDir, "trust-bundle.json"), "utf8"));
    assert.equal(state.publicOnlyKeyIds.length, 1);
    assert.equal(bundle.signingKeyId, state.publicOnlyKeyIds[0]);
    const onlineFiles = await readdir(onlineKeys);
    assert.ok(onlineFiles.length >= 6);
    assert.ok(onlineFiles.every((name) => !name.includes(state.publicOnlyKeyIds[0].replaceAll(":", "_"))));

    await assert.rejects(
      run("cargo", command, { cwd: root, windowsHide: true, maxBuffer: 2 * 1024 * 1024 }),
      /AUTHORITY_(CEREMONY_OUTPUT_ALREADY_EXISTS|ONLINE_KEY_DIR_ALREADY_EXISTS|OFFLINE_DIR_NOT_EMPTY)/,
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
