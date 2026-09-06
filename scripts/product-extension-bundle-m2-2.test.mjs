import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const readJson = (relative) => JSON.parse(read(relative));

test("bundle v1 tiene identidad universal y contenido firmado", () => {
  const schema = readJson("contracts/extensions/v1/extension-bundle-manifest.schema.json");
  assert.deepEqual(schema.required, [
    "contract_name", "contract_version",
    "schema", "bundle_id", "product", "bundle_version", "platform", "architecture",
    "capabilities", "artifacts", "dependencies", "compatibility", "issued_at",
    "manifest_digest", "signing",
  ]);
  assert.equal(schema.properties.signing.properties.algorithm.const, "ed25519");
  assert.equal(schema.properties.compatibility.properties.base_runtime_contract.const, "actium-node-manager-host@1.0.0");
  assert.equal(schema.properties.product.properties.product_id.pattern, "^[a-z][a-z0-9-]{1,63}$");
  assert.equal(Object.hasOwn(schema.properties, "host_id"), false);
});

test("engine y supervisor ofrecen el mismo lifecycle seguro", () => {
  const engine = read("src-tauri/actium-node-core/src/extensions.rs");
  const ipc = read("src-tauri/actium-node-core/src/ipc.rs");
  const supervisor = read("src-tauri/actium-node-supervisor/src/main.rs");
  for (const state of ["DISCOVERED", "STAGED", "VERIFIED", "INSTALLED", "ACTIVE", "DEGRADED", "DISABLED", "FAILED", "ROLLED_BACK", "REVOKED"]) assert.match(engine, new RegExp(state));
  for (const command of ["ExtensionInstall", "ExtensionActivate", "ExtensionRollback", "ExtensionSetEnabled", "ExtensionRemove", "ExtensionStatus"]) {
    assert.match(ipc, new RegExp(command));
    assert.match(supervisor, new RegExp(command));
  }
  assert.match(engine, /EXTENSION_SYMLINK_FORBIDDEN/);
  assert.match(engine, /EXTENSION_ARTIFACT_DIGEST_MISMATCH/);
  assert.match(engine, /EXTENSION_KEY_REVOKED/);
});

test("Aegis producer usa fuentes de servicios y no PAYLOAD", () => {
  const producer = read("../ecosistema-aegis-control-local-backend/infrastructure/data-plane/scripts/build-actium-extension-bundle.mjs");
  assert.match(producer, /services/);
  assert.match(producer, /aegis\.people/);
  assert.match(producer, /--private-key/);
  assert.doesNotMatch(producer, /readFileSync\([^\n]*PAYLOAD\.json/);
  assert.doesNotMatch(producer, /prepare:payload/);
});

test("UI ofrece import y acciones sin pedir identidad de deployment", () => {
  const ui = read("src/main.ts");
  assert.match(ui, /Importar bundle/);
  assert.match(ui, /install_extension/);
  assert.match(ui, /set_extension_enabled/);
  assert.match(ui, /rollback_extension/);
  assert.match(ui, /remove_extension/);
  assert.doesNotMatch(ui, /prompt\([^\n]*(client_id|organization_id|site_id|host_id)/);
});
