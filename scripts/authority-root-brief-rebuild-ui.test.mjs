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
  assert.match(manager, /id="root-brief-resolve-canonical-paths"/);
  assert.match(manager, /invoke<AuthorityRootBriefPathResolution>\("authority_root_brief_resolve_paths"/);
  assert.match(manager, /RootBriefPathResolutionV1/);
  assert.match(manager, /authorityRootBriefPathBadge/);
  assert.match(manager, /field\.classification/);
  assert.match(manager, /field\.state/);
  assert.match(manager, /authorityRootBriefPathResolution\?\.ready/);
  assert.doesNotMatch(manager, /BEGIN [A-Z ]*PRIVATE KEY/);
  assert.doesNotMatch(manager, /-----BEGIN/);
  assert.doesNotMatch(manager, /ACTIUM-SEALING-KEY-V1\\n[A-Za-z0-9_-]{40,}/);

  assert.match(tauri, /fn authority_root_brief_rebuild_trust_bundle/);
  assert.match(tauri, /fn authority_root_brief_resolve_paths/);
  assert.match(tauri, /RootBriefPathResolutionV1/);
  assert.match(tauri, /ACTIUM_PRODUCT_ROOT_CUSTODY_V1/);
  assert.match(tauri, /\/srv\/actium\/custody\/authority\/product-root-v1/);
  assert.match(tauri, /\/var\/lib\/actium\/authority\/keys/);
  assert.match(tauri, /\.actium-root-sealing\.key/);
  assert.match(tauri, /TRANSFER_REQUIRED/);
  assert.match(tauri, /ROOT_BRIEF_PATH_RESOLUTION_CONTRACT/);
  assert.match(tauri, /authority_root_brief_resolve_paths,/);
  assert.match(tauri, /BRIEF_ROOT_REBUILD_APPROVED/);
  assert.match(tauri, /async fn pick_open_file/);
  assert.match(tauri, /authority_root_brief_rebuild_trust_bundle,/);
  assert.match(tauri, /actium-authority-rebuild-trust-bundle/);
  assert.doesNotMatch(tauri, /BEGIN [A-Z ]*PRIVATE KEY/);
  assert.doesNotMatch(tauri, /-----BEGIN RSA PRIVATE KEY-----/);

  const resolverStart = tauri.indexOf("fn resolve_authority_root_brief_paths");
  const resolverEnd = tauri.indexOf("\nfn read_trimmed", resolverStart);
  assert.ok(resolverStart >= 0 && resolverEnd > resolverStart);
  const resolver = tauri.slice(resolverStart, resolverEnd);
  assert.doesNotMatch(resolver, /Command::new|read_dir|walkdir|glob/i);
  assert.match(resolver, /no_side_effects: true/);
  assert.match(resolver, /ROOT_BRIEF_EXPECTED_CENTER_AUTHORITY_ID/);

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
