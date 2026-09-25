import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  IMPLEMENTED_RUNTIME_KINDS,
  overallFromComponents,
  profileHasInlineSecretValues,
} from "../src/workload-runtime.ts";
import { KNOWN_PROFILES } from "../src/capability-surface.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function read(relative) {
  return readFile(join(root, relative), "utf8");
}

test("F7 generic runtime kinds and native capability list stay separate", () => {
  assert.deepEqual([...IMPLEMENTED_RUNTIME_KINDS], ["OCI_CONTAINER", "OCI_COMPOSE"]);
  assert.ok(KNOWN_PROFILES.includes("site-core"));
  assert.equal(KNOWN_PROFILES.includes("oci-compose"), false);
});

test("F7 contracts and example never encode Fleetbase", async () => {
  const files = [
    "contracts/workload/v1/actium-workload-profile.schema.json",
    "contracts/workload/v1/actium-workload-deployment.schema.json",
    "contracts/workload/v1/actium-desired-workload-state.schema.json",
    "contracts/workload/v1/actium-workload-deployment-receipt.schema.json",
    "contracts/workload/v1/examples/generic-oci-compose.profile.json",
    "src/workload-runtime.ts",
    "src-tauri/actium-node-core/src/workload.rs",
  ];
  for (const file of files) {
    const body = await read(file);
    assert.equal(/fleetbase/i.test(body), false, file);
  }
});

test("example profile is OCI_COMPOSE with secret refs not values", async () => {
  const profile = JSON.parse(await read("contracts/workload/v1/examples/generic-oci-compose.profile.json"));
  assert.equal(profile.schema, "actium-workload-profile@1.0.0");
  assert.equal(profile.runtimeKind, "OCI_COMPOSE");
  assert.ok(profile.components.length >= 2);
  assert.ok(profile.secretRequirements.every((item) => item.secretId && !item.value));
  assert.equal(profileHasInlineSecretValues(profile), false);
  assert.equal(profileHasInlineSecretValues({ password: "x" }), true);
});

test("overall READY requires every component", () => {
  assert.equal(
    overallFromComponents([
      { status: "READY" },
      { status: "READY" },
    ]),
    "READY",
  );
  assert.equal(
    overallFromComponents([
      { status: "READY" },
      { status: "PENDING" },
    ]),
    "PENDING",
  );
});

test("catalog lists F7 workload contracts", async () => {
  const catalog = JSON.parse(await read("contracts/manifest.json"));
  const names = catalog.contracts.map((item) => item.contract_name);
  assert.ok(names.includes("actium-workload-profile"));
  assert.ok(names.includes("actium-desired-workload-state"));
});

test("workload dir only contains generic artifacts", async () => {
  const dir = join(root, "contracts/workload/v1");
  const names = await readdir(dir);
  assert.ok(names.includes("actium-workload-profile.schema.json"));
});
