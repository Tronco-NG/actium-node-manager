import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

test("Authority Fabric Root brief rebuild UI contract", () => {
  const manager = read("src/main.ts");
  const tauri = read("src-tauri/src/lib.rs");
  const ceremonyBin = read("src-tauri/actium-authority-service/src/bin/authority-rebuild-trust-bundle.rs");
  const cargo = read("src-tauri/actium-authority-service/Cargo.toml");

  assert.match(manager, /Rebuild Trust Bundle \(Root brief\)/);
  assert.match(manager, /id="authority-root-brief-rebuild"/);
  assert.match(manager, /BRIEF_ROOT_REBUILD_APPROVED/);
  assert.match(manager, /Export ≠ rebuild/);
  assert.match(manager, /Exportar Trust Bundle público/);
  assert.match(manager, /STALE/);
  assert.match(manager, /ROOT_KEY_OFFLINE/);
  assert.match(manager, /invoke<AuthorityRootBriefRebuildResult>\("authority_root_brief_rebuild_trust_bundle"/);
  assert.match(manager, /id="root-brief-owner-confirm"/);
  assert.match(manager, /id="root-brief-execute"/);
  assert.doesNotMatch(manager, /BEGIN [A-Z ]*PRIVATE KEY/);
  assert.doesNotMatch(manager, /-----BEGIN/);
  assert.doesNotMatch(manager, /ACTIUM-SEALING-KEY-V1\\n[A-Za-z0-9_-]{40,}/);

  assert.match(tauri, /fn authority_root_brief_rebuild_trust_bundle/);
  assert.match(tauri, /BRIEF_ROOT_REBUILD_APPROVED/);
  assert.match(tauri, /async fn pick_open_file/);
  assert.match(tauri, /authority_root_brief_rebuild_trust_bundle,/);
  assert.match(tauri, /actium-authority-rebuild-trust-bundle/);
  assert.doesNotMatch(tauri, /BEGIN [A-Z ]*PRIVATE KEY/);
  assert.doesNotMatch(tauri, /-----BEGIN RSA PRIVATE KEY-----/);

  assert.match(ceremonyBin, /BRIEF_ROOT_REBUILD_APPROVED/);
  assert.match(ceremonyBin, /std::env::temp_dir\(\)/);
  assert.match(ceremonyBin, /center-authority-v2/);
  assert.match(ceremonyBin, /rootPrivateMaterial": "absent_from_output"/);
  assert.match(ceremonyBin, /descriptor\.status == AuthorityStatus::Revoked/);
  assert.match(ceremonyBin, /args\.root_key_id\.contains\(\['\/', '\\\\', '\.'\]\)/);
  assert.doesNotMatch(ceremonyBin, /println!\([^)]*private/i);
  assert.doesNotMatch(ceremonyBin, /-----BEGIN/);

  assert.match(cargo, /name = "actium-authority-rebuild-trust-bundle"/);
  assert.match(cargo, /path = "src\/bin\/authority-rebuild-trust-bundle.rs"/);
});
