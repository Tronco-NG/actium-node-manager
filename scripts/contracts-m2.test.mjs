import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

test("M2 contract catalog is versioned and neutral", () => {
  const catalog = readJson("contracts/manifest.json");
  assert.equal(catalog.product, "actium-node-manager");
  assert.equal(catalog.contract_catalog_version, "1.0.0");
  assert.equal(catalog.compatibility_policy, "pin-contract-name-and-version");
  assert.deepEqual(
    catalog.contracts.map(({ contract_name, contract_version }) => [contract_name, contract_version]),
    [
      ["actium-control-plane-config", "1.0.0"],
      ["actium-product-descriptor", "1.0.0"],
      ["actium-node-runtime-descriptor", "1.0.0"],
      ["actium-node-manager-host", "1.0.0"],
      ["actium-host-enrollment-ceremony", "1.0.0"],
      ["actium-product-extension-bundle", "1.0.0"],
      ["actium-trust-bundle", "1.0.0"],
      ["actium-release-manifest", "1.0.0"],
      ["actium-authority-service", "1.0.0"],
    ],
  );
});

test("M2 enrollment contract is hen-only and preserves the ceremony order", () => {
  const ceremony = readJson("contracts/host-enrollment/v1/ceremony.schema.json");
  assert.deepEqual(ceremony.properties.human_input.required, ["ticket"]);
  assert.match(ceremony.properties.human_input.properties.ticket.pattern, /^\^hen_/);
  assert.deepEqual(ceremony.properties.ordered_phases.const, [
    "challenge",
    "supervisor_pop",
    "complete",
    "pending_apply",
    "enrollment_package",
    "supervisor_apply",
    "signed_ack",
    "confirm",
    "enrolled_trusted",
    "signed_discovery",
  ]);
  assert.equal(ceremony.properties.confirmation.properties.required_ack_field.const, "enrollmentNonce");
});

test("M2 extension manifest has signed external-bundle fields", () => {
  const extension = readJson("contracts/extensions/v1/extension-bundle-manifest.schema.json");
  assert.deepEqual(extension.required, [
    "contract_name",
    "contract_version",
    "schema",
    "bundle_id",
    "product",
    "bundle_version",
    "platform",
    "architecture",
    "capabilities",
    "artifacts",
    "dependencies",
    "compatibility",
    "issued_at",
    "manifest_digest",
    "signing",
  ]);
  assert.equal(extension.properties.compatibility.properties.base_runtime_contract.const, "actium-node-manager-host@1.0.0");
  assert.equal(extension.properties.signing.properties.algorithm.const, "ed25519");
});

test("M2 base runtime contract is universal and external-bundle based", () => {
  const base = readJson("contracts/base-runtime/v1/actium-node-manager-host.schema.json");
  assert.equal(base.properties.contract_name.const, "actium-node-manager-host");
  assert.equal(base.properties.contract_version.const, "1.0.0");
  assert.equal(base.properties.product.const, "actium-node-manager");
  assert.equal(base.properties.runtime.const, "universal");
  assert.equal(base.properties.extension_boundary.const, "external-signed-bundle");
  assert.equal(base.properties.compatibility_policy.const, "pin-contract-name-and-version");
});

test("M2 target has no path-based cross-repository source dependency", () => {
  const forbidden = /(?:\.\.[\\/])+.*(?:ecosistema-aegis|actium-center)|infrastructure[\\/]data-plane[\\/]installer/iu;
  const files = [
    "src/main.ts",
    "src-tauri/src/lib.rs",
    "src-tauri/src/control_plane.rs",
    "src-tauri/actium-node-core/src/lib.rs",
    "src-tauri/actium-node-supervisor/src/main.rs",
  ];
  for (const relativePath of files) {
    assert.doesNotMatch(fs.readFileSync(path.join(root, relativePath), "utf8"), forbidden, relativePath);
  }
  assert.equal(fs.existsSync(path.join(root, "src-tauri/resources/node/PAYLOAD.json")), false);
});
