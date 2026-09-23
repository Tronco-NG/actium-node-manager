import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const [ipc, journal, supervisor, tauri, manager, stableUnit, labUnit, stableConfig, labConfig, installer, postinst] =
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
    readFile(resolve(root, "src-tauri/supervisor/install-supervisor-debian.sh"), "utf8"),
    readFile(resolve(root, "src-tauri/supervisor/postinst-debian.sh"), "utf8"),
  ]);

test("la ceremonia Owner usa la cola durable y un contrato de idempotencia", () => {
  assert.match(ipc, /EnqueueAuthorityCeremony\(AuthorityCeremonyRequest\)/);
  assert.match(ipc, /trust_root_set/);
  assert.match(journal, /metadata_json TEXT/);
  assert.match(journal, /find_by_idempotency_key/);
  assert.match(supervisor, /action == "authority_ceremony"/);
  assert.match(supervisor, /inspect_then_recover_same_ceremony/);
  assert.match(supervisor, /authority_ceremony_offline_sealing_key_path/);
  assert.doesNotMatch(supervisor, /offline_root\.with_file_name/);
  assert.match(journal, /requeue_failed/);
  assert.match(journal, /retry_requested_after_failure/);
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
  assert.match(stableUnit, /SupplementaryGroups=actium-authority/);
  assert.match(stableUnit, /ReadWritePaths=.*\/var\/lib\/actium\/node-manager\/authority-lock/);
  assert.match(stableUnit, /\/srv\/actium-data\/authority-offline-root/);
  assert.match(stableUnit, /\/srv\/actium-data\/authority-recovery/);
  assert.match(labUnit, /\/var\/lib\/actium\/authority-lab/);
  assert.match(labUnit, /\/var\/lib\/actium\/node-manager\/authority-lock/);
  assert.match(stableConfig, /authority_ceremony_lock_root = "\/var\/lib\/actium\/node-manager\/authority-lock"/);
  assert.match(labConfig, /authority_ceremony_lock_root = "\/var\/lib\/actium\/node-manager\/authority-lock"/);
  assert.match(installer, /exec "\$binary" deployment "\$@"/);
  assert.doesNotMatch(installer, /trust_store_path|authority_lock_root|systemctl/);
  assert.match(stableConfig, /authority_ceremony_mode = "production"/);
  assert.match(labConfig, /authority_ceremony_mode = "fixture"/);
  assert.match(supervisor, /fn prepare_ceremony_directory/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_PERMISSION_DENIED:\{label\}/);
  assert.match(supervisor, /Some\(Uid::effective\(\)\)/);
  assert.match(postinst, /OFFLINE_ROOT=\$\(rooted \/srv\/actium-data\/authority-offline-root\)/);
  assert.match(postinst, /ensure_owned_dir_if_missing "\$OFFLINE_ROOT" 0700 root root/);
  assert.match(postinst, /AUTHORITY_STATE=\$\(rooted \/var\/lib\/actium\/authority\)/);
  assert.match(postinst, /ensure_owned_dir_if_missing "\$AUTHORITY_STATE" 0770 actium-authority actium-authority/);
  assert.match(postinst, /AUTHORITY_CONFIG=\$\(rooted \/etc\/actium\/authority\)/);
  assert.match(postinst, /ensure_owned_dir_if_missing "\$AUTHORITY_CONFIG" 0770 actium-authority actium-authority/);
  assert.doesNotMatch(postinst, /center-local\.token|chmod 0440|systemctl (?:start|restart)/);
  assert.match(postinst, /systemctl enable actium-node-deployment-reconcile\.service/);
  assert.match(postinst, /systemctl enable actium-authority\.service/);
  assert.doesNotMatch(postinst, /systemctl enable actium-node-supervisor(?:-lab)?\.service/);
});

test("el supervisor conserva fail-closed, lock compartido y no activa fixtures", () => {
  assert.match(supervisor, /effective_write_probe/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_LOCK_STATE_UNKNOWN/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_LOCK_STALE/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_FIXTURE_ACTIVATION_FORBIDDEN/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_TRUST_ROOT_SET/);
});
