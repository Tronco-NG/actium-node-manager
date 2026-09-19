import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

test("Authority Fabric Root brief rebuild UI contract", () => {
  const manager = read("src/main.ts").replaceAll("\r\n", "\n");
  const resolutionTypeStart = manager.indexOf("type AuthorityRootBriefPathResolution = {");
  const resolutionTypeEnd = manager.indexOf("\n\ntype AuthorityCeremonyPathStatus", resolutionTypeStart);
  assert.ok(resolutionTypeStart >= 0 && resolutionTypeEnd > resolutionTypeStart);
  const resolutionType = manager.slice(resolutionTypeStart, resolutionTypeEnd);
  const preflightTypeStart = resolutionType.indexOf("  preflight: {");
  const preflightTypeEnd = resolutionType.indexOf("\n  };", preflightTypeStart);
  assert.ok(preflightTypeStart >= 0 && preflightTypeEnd > preflightTypeStart);
  const preflightType = resolutionType.slice(preflightTypeStart, preflightTypeEnd);
  for (const field of [
    "productRootIdentityMatch",
    "successorIdentityMatch",
    "outputCreatable",
  ]) {
    assert.match(preflightType, new RegExp(`\\b${field}:`));
  }
  for (const field of [
    "reasonCode",
    "productRootExpectedId",
    "productRootExpectedFingerprint",
    "productRootObservedId",
    "productRootObservedFingerprint",
    "productRootPublicOnly",
    "successorExpectedId",
    "successorExpectedFingerprint",
    "successorObservedId",
    "successorObservedFingerprint",
    "successorActivationEpoch",
    "successorObservedActivationEpoch",
    "outputState",
  ]) {
    assert.match(resolutionType, new RegExp(`\\b${field}\\?:`));
  }
  const ceremonyTypeStart = manager.indexOf("type AuthorityCeremonyProgress = {");
  const ceremonyTypeEnd = manager.indexOf("\n\ntype AuthorityTrustBundleExportResult", ceremonyTypeStart);
  assert.ok(ceremonyTypeStart >= 0 && ceremonyTypeEnd > ceremonyTypeStart);
  const ceremonyType = manager.slice(ceremonyTypeStart, ceremonyTypeEnd);
  assert.match(ceremonyType, /\btrustRootSet\?: string \| null;/);

  const tauri = read("src-tauri/src/lib.rs");
  const coreIpc = read("src-tauri/actium-node-core/src/ipc.rs");
  const supervisor = read("src-tauri/actium-node-supervisor/src/main.rs");
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
  assert.doesNotMatch(manager, /\/srv\/actium-data\/authority-offline-root/);
  assert.doesNotMatch(manager, /authority-default-offline/);
  assert.doesNotMatch(manager, /BEGIN [A-Z ]*PRIVATE KEY/);
  assert.doesNotMatch(manager, /-----BEGIN/);
  assert.doesNotMatch(manager, /ACTIUM-SEALING-KEY-V1\\n[A-Za-z0-9_-]{40,}/);

  assert.match(tauri, /fn authority_root_brief_rebuild_trust_bundle/);
  assert.match(tauri, /fn authority_root_brief_resolve_paths/);
  assert.match(tauri, /RootBriefPathResolutionV1/);
  assert.match(tauri, /SupervisorCommand::AuthorityRootBriefResolvePaths/);
  assert.match(tauri, /SupervisorReply::AuthorityRootBriefPathResolution/);
  assert.doesNotMatch(tauri, /\/srv\/actium\/custody\/authority\/product-root-v1/);
  assert.doesNotMatch(tauri, /actium-authority-rebuild-trust-bundle/);
  assert.match(tauri, /authority_root_brief_resolve_paths,/);
  assert.match(tauri, /async fn pick_open_file/);
  assert.match(tauri, /authority_root_brief_rebuild_trust_bundle,/);
  assert.match(tauri, /AUTHORITY_ROOT_BRIEF_SUPERVISOR_FEATURE_REQUIRED/);
  assert.match(tauri, /has_ipc_feature/);
  assert.match(tauri, /ROOT_BRIEF_RESOLUTION_FEATURE/);
  assert.match(tauri, /fn ensure_root_brief_resolution_feature/);
  const resolveStart = tauri.indexOf("fn authority_root_brief_resolve_paths");
  const resolveEnd = tauri.indexOf("\nfn ensure_root_brief_resolution_feature", resolveStart);
  const resolve = tauri.slice(resolveStart, resolveEnd);
  assert.ok(resolve.indexOf("SupervisorCommand::Ping") >= 0);
  assert.ok(resolve.indexOf("ensure_root_brief_resolution_feature") < resolve.indexOf("SupervisorCommand::AuthorityRootBriefResolvePaths"));
  assert.doesNotMatch(tauri, /BEGIN [A-Z ]*PRIVATE KEY/);
  assert.doesNotMatch(tauri, /-----BEGIN RSA PRIVATE KEY-----/);

  const rebuildStart = tauri.indexOf("async fn authority_root_brief_rebuild_trust_bundle");
  const rebuildEnd = tauri.indexOf("\nfn normalized_public_export_path", rebuildStart);
  assert.ok(rebuildStart >= 0 && rebuildEnd > rebuildStart);
  const rebuild = tauri.slice(rebuildStart, rebuildEnd);
  assert.doesNotMatch(rebuild, /Command::new|spawn_blocking|authority_root_brief_binary/);
  assert.match(rebuild, /AUTHORITY_ROOT_BRIEF_SUPERVISOR_BOUNDARY_REQUIRED/);

  assert.match(coreIpc, /AuthorityRootBriefResolvePaths/);
  assert.match(coreIpc, /AuthorityRootBriefPathResolution/);
  assert.match(coreIpc, /SUPERVISOR_VERSION: &str = "0\.5\.22"/);
  assert.match(coreIpc, /IPC_PROTOCOL_VERSION: u16 = 3/);
  assert.match(coreIpc, /authority_root_brief_resolution_v1/);
  assert.match(coreIpc, /fn has_ipc_feature/);
  assert.match(supervisor, /discover_root_brief_ceremony_journal/);
  assert.match(supervisor, /from_sealing_key_file_read_only/);
  assert.match(supervisor, /CEREMONY_JOURNAL_AMBIGUOUS/);
  assert.match(supervisor, /OUTPUT_NOT_CREATED_YET/);
  assert.match(supervisor, /OUTPUT_NOT_CREATABLE/);
  assert.match(supervisor, /OFFLINE_CUSTODY_INVALID/);
  assert.match(supervisor, /validate_root_brief_output_candidate_containment/);
  assert.match(supervisor, /SUCCESSOR_CAPABILITY_MISMATCH/);
  assert.match(supervisor, /fn validate_root_brief_ceremony_correlations/);
  assert.match(supervisor, /effective_trust_root_set/);
  assert.match(supervisor, /e8449370597112140e1527d9b39a5679bf82e373655f8a4c287970d98b9ddc83/);
  assert.match(supervisor, /6245ae735751ad31c934e3308400c9783254906cb641198a0b970e3020d58094/);
  assert.doesNotMatch(supervisor, /\/srv\/actium-data\/authority-offline-root\//);
  assert.match(manager, /Capability unavailable/);
  assert.match(manager, /Supervisor update required/);

  assert.match(ceremonyBin, /BRIEF_ROOT_REBUILD_APPROVED/);
  assert.match(ceremonyBin, /std::env::temp_dir\(\)/);
  assert.match(ceremonyBin, /resolve_root_brief_successor_authority_id/);
  assert.match(ceremonyBin, /rootPrivateMaterial": "absent_from_output"/);
  assert.match(ceremonyBin, /descriptor\.status == AuthorityStatus::Revoked/);
  assert.match(ceremonyBin, /args\.root_key_id\.contains\(\['\/', '\\\\', '\.'\]\)/);
  assert.doesNotMatch(ceremonyBin, /println!\([^)]*private/i);
  assert.doesNotMatch(ceremonyBin, /-----BEGIN/);

  assert.match(cargo, /name = "actium-authority-rebuild-trust-bundle"/);
  assert.match(cargo, /path = "src\/bin\/authority-rebuild-trust-bundle.rs"/);
});
