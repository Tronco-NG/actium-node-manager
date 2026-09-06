#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  CANONICAL_REPOSITORY,
  RELEASE_MANIFEST_SCHEMA,
  assertBuildId,
  assertManifestSchema,
  assertSha256,
  artifactDigestSet,
  gitState,
  readJson,
  repositoryFromOrigin,
  sameArtifactSet,
  sha256File,
  writeJson,
} from "./release-toolkit.mjs";

function args(argv) {
  const parsed = { root: path.resolve(import.meta.dirname, ".."), buildId: null, version: null, keyId: null, signature: null };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (["--root", "--build-id", "--version", "--signing-key-id", "--signature"].includes(value)) parsed[({ "--root": "root", "--build-id": "buildId", "--version": "version", "--signing-key-id": "keyId", "--signature": "signature" })[value]] = argv[++i];
  }
  return parsed;
}

function requireValue(value, error) {
  if (!value || !String(value).trim()) throw new Error(error);
  return String(value).trim();
}

function validateBuild(rootDir, manifest, buildDir) {
  assertManifestSchema(manifest, "actium-build-manifest@1.0.0", "BUILD_MANIFEST_SCHEMA_INVALID");
  assertBuildId(manifest.buildId);
  if (manifest.buildKind !== "candidate" || manifest.status !== "BUILT") throw new Error("RELEASE_BUILD_NOT_CANDIDATE");
  if (manifest.sourceRepo !== CANONICAL_REPOSITORY || repositoryFromOrigin(rootDir) !== CANONICAL_REPOSITORY) throw new Error("RELEASE_SOURCE_REPOSITORY_INVALID");
  if (manifest.sourceDirty !== false) throw new Error("RELEASE_SOURCE_DIRTY");
  const current = gitState(rootDir);
  if (current.dirty) throw new Error("RELEASE_SOURCE_DIRTY");
  if (manifest.sourceCommit !== current.commit) throw new Error("RELEASE_SOURCE_COMMIT_STALE");
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error("RELEASE_ARTIFACTS_MISSING");
  if (!Array.isArray(manifest.tests) || manifest.tests.some((test) => test.status !== "passed")) throw new Error("RELEASE_TEST_EVIDENCE_INCOMPLETE");
  for (const artifact of manifest.artifacts) {
    assertSha256(artifact.sha256);
    if (!/^artifacts\/[^/]+$/.test(artifact.uri)) throw new Error("RELEASE_ARTIFACT_URI_INVALID");
    const artifactPath = path.resolve(buildDir, artifact.uri);
    if (!artifactPath.startsWith(`${path.resolve(buildDir, "artifacts")}${path.sep}`) || !fs.existsSync(artifactPath)) throw new Error("RELEASE_ARTIFACT_NOT_FOUND");
    if (sha256File(artifactPath) !== artifact.sha256) throw new Error("RELEASE_ARTIFACT_DIGEST_MISMATCH");
  }
  return current;
}

export function promoteRelease({ rootDir, buildId, version, signingKeyId, signature, now = new Date().toISOString() }) {
  requireValue(version, "RELEASE_VERSION_REQUIRED");
  if (version.includes("/") || version.includes("\\")) throw new Error("RELEASE_VERSION_INVALID");
  if (/(?:^|[-.])(lab|stable|canary|pilot)(?:[-.]|$)/i.test(version)) throw new Error("RELEASE_VERSION_MUST_NOT_ENCODE_CHANNEL");
  requireValue(signingKeyId, "RELEASE_SIGNING_KEY_ID_REQUIRED");
  requireValue(signature, "RELEASE_SIGNATURE_REQUIRED");
  const buildRoot = path.join(rootDir, "dist", "builds");
  const buildDir = path.join(buildRoot, buildId);
  const manifestPath = path.join(buildDir, "build-manifest.json");
  if (!fs.existsSync(manifestPath)) throw new Error("RELEASE_BUILD_MANIFEST_NOT_FOUND");
  const build = readJson(manifestPath);
  const current = validateBuild(rootDir, build, buildDir);
  const releaseId = `release-${build.productId}-${version}-${build.platform}-${build.architecture}`.toLowerCase();
  const releaseDir = path.join(rootDir, "dist", "releases", version, build.platform, build.architecture);
  const releasePath = path.join(releaseDir, "release-manifest.json");
  if (fs.existsSync(releasePath)) {
    const existing = readJson(releasePath);
    assertManifestSchema(existing, RELEASE_MANIFEST_SCHEMA, "RELEASE_MANIFEST_SCHEMA_INVALID");
    if (existing.productId === build.productId && existing.version === version && sameArtifactSet(existing.artifacts, build.artifacts) && existing.sourceCommit === current.commit) {
      return { idempotent: true, releaseId: existing.releaseId, path: releasePath, manifest: existing };
    }
    throw new Error("RELEASE_ID_ALREADY_ASSIGNED_DIFFERENT_ARTIFACTS");
  }
  const release = {
    schema: RELEASE_MANIFEST_SCHEMA,
    contract: RELEASE_MANIFEST_SCHEMA,
    releaseId,
    productId: build.productId,
    version,
    buildId: build.buildId,
    sourceRepo: build.sourceRepo,
    sourceCommit: current.commit,
    platform: build.platform,
    architecture: build.architecture,
    artifacts: build.artifacts.map((artifact) => ({
      name: artifact.name,
      uri: `artifacts/sha256/${artifact.sha256}/${artifact.name}`,
      sha256: artifact.sha256,
      sizeBytes: artifact.sizeBytes,
    })),
    issuedAt: Math.floor(Date.parse(build.createdAt) / 1000),
    createdAt: build.createdAt,
    promotedAt: now,
    releaseStatus: "PROMOTED",
    compatibility: {
      baseRuntimeContract: "actium-node-manager-host@1.0.0",
      buildManifest: `builds/${build.buildId}/build-manifest.json`,
    },
    signing: { keyId: signingKeyId, algorithm: "Ed25519", signature },
  };
  writeJson(releasePath, release);
  writeJson(path.join(releaseDir, "build-reference.json"), {
    schema: "actium-release-build-reference@1.0.0",
    releaseId,
    buildId: build.buildId,
    sourceCommit: current.commit,
    artifactSha256: artifactDigestSet(release.artifacts).map((entry) => entry.split(":").at(-1)),
    buildManifest: `builds/${build.buildId}/build-manifest.json`,
  });
  return { idempotent: false, releaseId, path: releasePath, manifest: release };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const parsed = args(process.argv.slice(2));
    const buildId = requireValue(parsed.buildId, "RELEASE_BUILD_ID_REQUIRED");
    const result = promoteRelease({ rootDir: path.resolve(parsed.root), buildId, version: parsed.version, signingKeyId: parsed.keyId, signature: parsed.signature });
    console.log(`${result.idempotent ? "IDEMPOTENT" : "PROMOTED"}: ${result.releaseId}`);
    console.log(`release_manifest=${result.path}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
