import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manager = await readFile(resolve(root, "src/main.ts"), "utf8");
const supervisor = await readFile(resolve(root, "src-tauri/actium-node-supervisor/src/main.rs"), "utf8");

test("infraestructura usa binding firmado y no infiere Host desde grants", () => {
  assert.match(manager, /function infrastructureScope\(readiness: any\)/);
  assert.match(manager, /const binding = readiness\?\.hostBinding/);
  assert.doesNotMatch(manager, /infrastructureScope\(snapshot\?\.grants/);
  assert.match(manager, /<dt>Host ID<\/dt><dd>\$\{escapeHtml\(scope\?\.hostId \?\? "UNKNOWN"\)\}/);
  assert.match(manager, /function infrastructureReadinessTone\(state: unknown\)/);
  assert.match(manager, /return "bad";/);
});

test("supervisor separa approval signer y attestation autoritativa", () => {
  assert.match(supervisor, /SIGNING_APPROVAL_NOT_OBSERVED/);
  assert.match(supervisor, /join\("material-attestation\.json"\)/);
  assert.doesNotMatch(supervisor, /let center_approval_signer = HostReadinessCheck::ready\(format!\(/);
});

console.log("host-readiness-correctness: ok");
