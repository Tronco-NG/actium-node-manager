import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const [ipc, journal, supervisor, tauri, manager, stableUnit, labUnit, stableConfig, labConfig] =
  await Promise.all([
    readFile(resolve(root, "src-tauri/actium-node-core/src/ipc.rs"), "utf8"),
    readFile(resolve(root, "src-tauri/actium-node-core/src/journal.rs"), "utf8"),
    readFile(resolve(root, "src-tauri/actium-node-supervisor/src/main.rs"), "utf8"),
    readFile(resolve(root, "src-tauri/src/lib.rs"), "utf8"),
    readFile(resolve(root, "src/main.ts"), "utf8"),
    readFile(resolve(root, "src-tauri/supervisor/actium-node-supervisor.service"), "utf8"),
    readFile(resolve(root, "src-tauri/supervisor/actium-node-supervisor-lab.service"), "utf8"),
    readFile(resolve(root, "src-tauri/supervisor/supervisor.toml"), "utf8"),
    readFile(resolve(root, "src-tauri/supervisor/supervisor.lab.toml"), "utf8"),
  ]);

test("la ceremonia Owner usa la cola durable y un contrato de idempotencia", () => {
  assert.match(ipc, /EnqueueAuthorityCeremony\(AuthorityCeremonyRequest\)/);
  assert.match(ipc, /trust_root_set/);
  assert.match(journal, /metadata_json TEXT/);
  assert.match(journal, /find_by_idempotency_key/);
  assert.match(supervisor, /action == "authority_ceremony"/);
  assert.match(supervisor, /inspect_then_recover_same_ceremony/);
  assert.match(supervisor, /operation_id/);
  assert.match(supervisor, /correlation_id/);
  assert.match(tauri, /fn enqueue_authority_ceremony/);
  assert.match(manager, /invoke<NodeOperationJob>\("enqueue_authority_ceremony"/);

  const executeStart = manager.indexOf("async function executeAuthorityCeremony");
  const executeEnd = manager.indexOf("async function", executeStart + 20);
  const executeBody = manager.slice(executeStart, executeEnd > executeStart ? executeEnd : undefined);
  assert.match(executeBody, /enqueue_authority_ceremony/);
  assert.doesNotMatch(executeBody, /authority_ceremony_execute/);
});

test("la configuración permite escritura efectiva en los directorios del sandbox", () => {
  assert.match(stableUnit, /ReadWritePaths=.*\/var\/lib\/actium\/authority/);
  assert.match(stableUnit, /\/srv\/actium-data\/authority-offline-root/);
  assert.match(stableUnit, /\/srv\/actium-data\/authority-recovery/);
  assert.match(labUnit, /\/var\/lib\/actium\/authority-lab/);
  assert.match(stableConfig, /authority_ceremony_mode = "production"/);
  assert.match(labConfig, /authority_ceremony_mode = "fixture"/);
});

test("el supervisor conserva fail-closed, lock compartido y no activa fixtures", () => {
  assert.match(supervisor, /effective_write_probe/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_LOCK_STATE_UNKNOWN/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_LOCK_STALE/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_FIXTURE_ACTIVATION_FORBIDDEN/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_TRUST_ROOT_SET/);
});

