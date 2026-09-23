import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8").replaceAll("\r\n", "\n");
const deployment = read("src-tauri/actium-node-supervisor/src/deployment.rs");
const config = read("src-tauri/actium-node-supervisor/src/effective_config.rs");
const trust = read("src-tauri/actium-node-supervisor/src/trust_store.rs");
const packageScript = read("src-tauri/supervisor/postinst-debian.sh");
const wrapper = read("src-tauri/supervisor/install-supervisor-debian.sh");
const compatibility = JSON.parse(read("src-tauri/supervisor/compatibility-manifest.json"));

test("el deployment journal modela fases persistentes y recovery explícito", () => {
  for (const state of [
    "Created", "Staging", "Staged", "PreflightPassed", "ReadyToActivate", "Activating",
    "Verifying", "Committed", "RollingBack", "RolledBack", "Failed", "Blocked",
  ]) assert.ok(deployment.includes(state), `falta estado durable ${state}`);
  for (const field of [
    "deployment_id", "deployment_environment", "release_channel", "artifact_digest", "previous_artifact_digest", "config_digest",
    "config_generation", "trust_store_id", "trust_epoch", "authority_generation", "activation_generation",
  ]) assert.ok(deployment.includes(`pub ${field}:`), `falta field durable ${field}`);
  assert.match(deployment, /fn reconcile_deployment/);
  assert.match(deployment, /fn reconcile_pending_transactions/);
  assert.match(deployment, /fn verify_rollback_receipt/);
  assert.match(deployment, /fn restore_trust_store_snapshot/);
});

test("preflight, stage y runtime comparten migración y contrato tipado", () => {
  assert.match(config, /CURRENT_CONFIG_SCHEMA_VERSION: u32 = 3/);
  assert.match(config, /migrate_v1_to_v2/);
  assert.match(config, /migrate_v2_to_v3/);
  assert.match(config, /deployment_environment/);
  assert.match(deployment, /resolve_effective_supervisor_config/);
  assert.match(deployment, /fn preflight_candidate/);
  assert.match(deployment, /run_staged_config_check/);
  assert.match(deployment, /--check/);
  assert.match(deployment, /CONFIG_DIGEST_MISMATCH/);
  assert.match(trust, /TRUST_STORE_CHANNEL_MISMATCH/);
  assert.match(trust, /migrate_environment_metadata/);
  assert.equal(compatibility.releaseChannel, "RC");
  assert.equal(compatibility.supervisorConfigSchema.maximum, 3);
  assert.equal(compatibility.trustStoreSchema.maximum, 3);
});

test("dpkg termina en capa de paquete y nunca hace activation de canales", () => {
  assert.match(packageScript, /package configured; deployment-environment activation is an explicit transaction/);
  assert.match(packageScript, /systemctl daemon-reload/);
  assert.match(packageScript, /systemctl enable actium-node-deployment-reconcile\.service/);
  assert.match(packageScript, /systemctl enable actium-authority\.service/);
  assert.doesNotMatch(packageScript, /systemctl (?:start|restart|stop)|systemctl enable actium-node-supervisor|docker info|--preflight|--install|deployment activate/);
  assert.match(wrapper, /exec "\$binary" deployment "\$@"/);
  assert.doesNotMatch(wrapper, /restore_upgrade_state|upgrade-backups|data-inventory/);
});

test("la promoción LAB exige el mismo artifact y receipts ligados por digest", () => {
  assert.match(deployment, /fn write_lab_promotion_receipt/);
  assert.match(deployment, /fn verify_lab_promotion/);
  assert.match(deployment, /lab_receipt_digest/);
  assert.match(deployment, /"promote-lab"/);
  assert.match(deployment, /manager-ui-functional:PASS/);
  assert.match(deployment, /supervisor-channel-functional:PASS/);
  assert.match(deployment, /authority-trust-functional:PASS/);
  assert.match(deployment, /smoke_report_digest/);
  assert.match(deployment, /smoke_evidence_digest/);
  assert.match(deployment, /atomic_copy_file/);
  assert.match(deployment, /report\.result != "PASS"/);
  assert.match(deployment, /served\.artifact_digest != artifact_digest/);
});

console.log("m5-3-upgrade-compatibility: engine transaccional, dpkg separado y promoción LAB auditados");
