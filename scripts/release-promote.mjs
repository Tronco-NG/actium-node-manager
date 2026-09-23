#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  CANONICAL_REPOSITORY,
  RELEASE_MANIFEST_SCHEMA,
  assertBuildId,
  assertManifestSchema,
  assertReleaseSigningRequest,
  assertSha256,
  artifactDigestSet,
  canonicalJson,
  createReleaseSigningRequest,
  gitState,
  readJson,
  repositoryFromOrigin,
  sha256File,
  writeJson,
} from "./release-toolkit.mjs";

const SAFE_SEGMENT = /^[a-zA-Z0-9][a-zA-Z0-9._+_-]{0,159}$/;

function requireValue(value, error) {
  if (!value || !String(value).trim()) throw new Error(error);
  return String(value).trim();
}

function assertSafeSegment(value, error) {
  if (typeof value !== "string" || !SAFE_SEGMENT.test(value) || value === "." || value === "..") {
    throw new Error(error);
  }
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
  assertSafeSegment(manifest.productId, "RELEASE_PRODUCT_ID_INVALID");
  assertSafeSegment(manifest.platform, "RELEASE_PLATFORM_INVALID");
  assertSafeSegment(manifest.architecture, "RELEASE_ARCHITECTURE_INVALID");
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) throw new Error("RELEASE_ARTIFACTS_MISSING");
  if (!Array.isArray(manifest.tests) || manifest.tests.length === 0 || manifest.tests.some((item) => item.status !== "passed")) {
    throw new Error("RELEASE_TEST_EVIDENCE_INCOMPLETE");
  }
  for (const artifact of manifest.artifacts) {
    assertSha256(artifact.sha256);
    assertSafeSegment(artifact.name, "RELEASE_ARTIFACT_NAME_INVALID");
    if (!/^artifacts\/[^/]+$/.test(artifact.uri)) throw new Error("RELEASE_ARTIFACT_URI_INVALID");
    const artifactPath = path.resolve(buildDir, artifact.uri);
    if (!artifactPath.startsWith(`${path.resolve(buildDir, "artifacts")}${path.sep}`) || !fs.existsSync(artifactPath)) {
      throw new Error("RELEASE_ARTIFACT_NOT_FOUND");
    }
    if (sha256File(artifactPath) !== artifact.sha256) throw new Error("RELEASE_ARTIFACT_DIGEST_MISMATCH");
    if (fs.statSync(artifactPath).size !== artifact.sizeBytes) throw new Error("RELEASE_ARTIFACT_SIZE_MISMATCH");
  }
}

function validateVersion(version) {
  requireValue(version, "RELEASE_VERSION_REQUIRED");
  assertSafeSegment(version, "RELEASE_VERSION_INVALID");
  if (/(?:^|[-.])(lab|stable|canary|pilot)(?:[-.]|$)/i.test(version)) {
    throw new Error("RELEASE_VERSION_MUST_NOT_ENCODE_CHANNEL");
  }
  return version;
}

function releaseDraft(build, version, promotedAt) {
  validateVersion(version);
  const promotedDate = new Date(promotedAt);
  const createdDate = new Date(build.createdAt);
  if (!Number.isFinite(promotedDate.getTime()) || !Number.isFinite(createdDate.getTime())) {
    throw new Error("RELEASE_TIMESTAMP_INVALID");
  }
  const releaseId = `release-${build.productId}-${version}-${build.platform}-${build.architecture}`.toLowerCase();
  assertSafeSegment(releaseId, "RELEASE_ID_INVALID");
  return {
    schema: RELEASE_MANIFEST_SCHEMA,
    contract: RELEASE_MANIFEST_SCHEMA,
    releaseId,
    productId: build.productId,
    version,
    buildId: build.buildId,
    sourceRepo: build.sourceRepo,
    sourceCommit: build.sourceCommit,
    platform: build.platform,
    architecture: build.architecture,
    artifacts: build.artifacts.map((artifact) => ({
      name: artifact.name,
      uri: `artifacts/sha256/${artifact.sha256}/${artifact.name}`,
      sha256: artifact.sha256,
      sizeBytes: artifact.sizeBytes,
    })),
    issuedAt: Math.floor(createdDate.getTime() / 1000),
    createdAt: build.createdAt,
    promotedAt: promotedDate.toISOString(),
    releaseStatus: "PROMOTED",
    compatibility: {
      baseRuntimeContract: "actium-node-manager-host@1.0.0",
      buildManifest: `builds/${build.buildId}/build-manifest.json`,
    },
  };
}

function loadCandidate(rootDir, buildId) {
  assertBuildId(buildId);
  const buildDir = path.join(rootDir, "dist", "builds", buildId);
  const manifestPath = path.join(buildDir, "build-manifest.json");
  if (!fs.existsSync(manifestPath)) throw new Error("RELEASE_BUILD_MANIFEST_NOT_FOUND");
  const build = readJson(manifestPath);
  validateBuild(rootDir, build, buildDir);
  return { build };
}

export function prepareRelease({ rootDir, buildId, version, now = new Date().toISOString() }) {
  validateVersion(version);
  const { build } = loadCandidate(rootDir, buildId);
  const manifest = releaseDraft(build, version, now);
  const completeRequest = createReleaseSigningRequest(manifest);
  const requestPath = path.join(
    rootDir,
    "dist",
    "release-signing-requests",
    `${buildId}-${completeRequest.payloadSha256.slice(0, 16)}.json`,
  );
  const alreadyExists = fs.existsSync(requestPath);
  if (alreadyExists) {
    const existing = readJson(requestPath);
    assertReleaseSigningRequest(existing);
    if (canonicalJson(existing) !== canonicalJson(completeRequest)) throw new Error("RELEASE_SIGNING_REQUEST_PATH_CONFLICT");
  } else {
    writeJson(requestPath, completeRequest);
  }
  return { idempotent: alreadyExists, releaseId: manifest.releaseId, path: requestPath, request: completeRequest };
}

function validateSigningResponse(response) {
  if (!response || typeof response !== "object" || Array.isArray(response)
      || Object.keys(response).sort().join("\0") !== ["algorithm", "keyId", "signature"].join("\0")
      || response.algorithm !== "Ed25519"
      || typeof response.keyId !== "string"
      || response.keyId.length < 1
      || response.keyId.length > 160
      || !/^[A-Za-z0-9._:-]+$/.test(response.keyId)
      || typeof response.signature !== "string"
      || !/^[A-Za-z0-9_-]{86}$/.test(response.signature)) {
    throw new Error("RELEASE_SIGNING_RESPONSE_INVALID");
  }
  const rawSignature = Buffer.from(response.signature, "base64url");
  if (rawSignature.length !== 64 || rawSignature.toString("base64url") !== response.signature) {
    throw new Error("RELEASE_SIGNING_RESPONSE_INVALID");
  }
  return response;
}

export function promoteRelease({ rootDir, signingRequestPath, signingResponsePath }) {
  const request = readJson(signingRequestPath);
  assertReleaseSigningRequest(request);
  const draft = request.manifest;
  const { build } = loadCandidate(rootDir, draft.buildId);
  const expectedDraft = releaseDraft(build, draft.version, draft.promotedAt);
  if (canonicalJson(expectedDraft) !== canonicalJson(draft)) throw new Error("RELEASE_SIGNING_REQUEST_BUILD_MISMATCH");

  const signature = validateSigningResponse(readJson(signingResponsePath));
  const release = { ...draft, signing: signature };
  const releaseDir = path.join(rootDir, "dist", "releases", draft.version, draft.platform, draft.architecture);
  const releasePath = path.join(releaseDir, "release-manifest.json");
  if (fs.existsSync(releasePath)) {
    const existing = readJson(releasePath);
    assertManifestSchema(existing, RELEASE_MANIFEST_SCHEMA, "RELEASE_MANIFEST_SCHEMA_INVALID");
    const { signing: existingSignature, ...existingDraft } = existing;
    if (canonicalJson(existingDraft) === canonicalJson(draft)
        && canonicalJson(existingSignature) === canonicalJson(signature)) {
      return { idempotent: true, releaseId: existing.releaseId, path: releasePath, manifest: existing };
    }
    throw new Error("RELEASE_ID_ALREADY_ASSIGNED_DIFFERENT_CONTENT");
  }

  writeJson(releasePath, release);
  writeJson(path.join(releaseDir, "build-reference.json"), {
    schema: "actium-release-build-reference@1.0.0",
    releaseId: draft.releaseId,
    buildId: draft.buildId,
    sourceCommit: draft.sourceCommit,
    artifactSha256: artifactDigestSet(draft.artifacts).map((entry) => entry.split(":").at(-1)),
    buildManifest: `builds/${draft.buildId}/build-manifest.json`,
  });
  return { idempotent: false, releaseId: draft.releaseId, path: releasePath, manifest: release };
}

function parseArgs(argv) {
  const parsed = { root: path.resolve(import.meta.dirname, ".."), signingRequest: null, signingResponse: null };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === "--root") parsed.root = argv[++i];
    if (value === "--signing-request") parsed.signingRequest = argv[++i];
    if (value === "--signing-response") parsed.signingResponse = argv[++i];
  }
  return parsed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    const signingRequestPath = requireValue(parsed.signingRequest, "RELEASE_SIGNING_REQUEST_REQUIRED");
    const signingResponsePath = requireValue(parsed.signingResponse, "RELEASE_SIGNING_RESPONSE_REQUIRED");
    const result = promoteRelease({
      rootDir: path.resolve(parsed.root),
      signingRequestPath: path.resolve(signingRequestPath),
      signingResponsePath: path.resolve(signingResponsePath),
    });
    console.log(`${result.idempotent ? "IDEMPOTENT" : "PROMOTED"}: ${result.releaseId}`);
    console.log(`release_manifest=${result.path}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
