import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

test("custody paths use the Supervisor boundary while retaining the optional picker", () => {
  const manager = read("src/main.ts");
  const tauri = read("src-tauri/src/lib.rs");
  const ipc = read("src-tauri/actium-node-core/src/ipc.rs");
  const supervisor = read("src-tauri/actium-node-supervisor/src/main.rs");

  assert.match(manager, /invoke<unknown>\("authority_ceremony_path_preflight"/);
  assert.match(manager, /id="authority-pick-offline"/);
  assert.match(manager, /id="authority-pick-recovery"/);
  assert.match(manager, /id="authority-validate-offline"/);
  assert.match(manager, /id="authority-validate-recovery"/);
  assert.match(manager, /id="authority-default-offline"/);
  assert.match(manager, /id="authority-default-recovery"/);
  assert.doesNotMatch(manager, /authority-offline-root" readonly/);
  assert.doesNotMatch(manager, /authority-recovery" readonly/);
  assert.match(manager, /await validateAuthorityCeremonyDirectory\(kind\)/);

  assert.match(tauri, /async fn pick_directory/);
  assert.match(tauri, /nearest visible parent/);
  assert.match(tauri, /AuthorityCeremonyPathPreflight\(request\)/);
  assert.doesNotMatch(tauri, /async fn pick_directory[\s\S]*?read_dir/);

  assert.match(ipc, /pub struct AuthorityCeremonyPathRequest/);
  assert.match(ipc, /AuthorityCeremonyPathPreflight\(AuthorityCeremonyPathRequest\)/);
  assert.match(ipc, /AuthorityCeremonyPath\(AuthorityCeremonyPathStatus\)/);

  assert.match(supervisor, /fn authority_ceremony_path_preflight/);
  assert.match(supervisor, /prepare_ceremony_directory\(&path, label\)/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_PATH_OVERLAP/);
  assert.match(supervisor, /AUTHORITY_CEREMONY_PATH_FORBIDDEN/);
});
