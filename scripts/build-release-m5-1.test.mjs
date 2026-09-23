import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { assignReleaseChannel } from "./release-channel.mjs";
import { prepareRelease, promoteRelease } from "./release-promote.mjs";
import { BUILD_MANIFEST_SCHEMA, CANONICAL_REPOSITORY, RELEASE_MANIFEST_SCHEMA, RELEASE_MANIFEST_SIGNING_DOMAIN, canonicalJson, gitState, newBuildId, releaseManifestSigningPayload, sha256File, writeJson } from "./release-toolkit.mjs";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

function tempRepo() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "actium-m5-1-"));
  const git = (args) => execFileSync("git", args, { cwd: directory, stdio: "ignore" });
  git(["init", "-q"]);
  git(["config", "user.email", "test@actium.invalid"]);
  git(["config", "user.name", "Actium M5.1 test"]);
  git(["remote", "add", "origin", "https://github.com/Tronco-NG/actium-node-manager.git"]);
  fs.writeFileSync(path.join(directory, ".gitignore"), "dist/\n");
  fs.writeFileSync(path.join(directory, "seed.txt"), "seed\n");
  git(["add", ".gitignore", "seed.txt"]);
  git(["commit", "-qm", "fixture"]);
  return { directory, git };
}

function fixtureBuild(fixture, buildId, artifactText = "artifact\n") {
  const state = gitState(fixture.directory);
  const buildDir = path.join(fixture.directory, "dist", "builds", buildId);
  const artifactPath = path.join(buildDir, "artifacts", "manager.exe");
  fs.mkdirSync(path.dirname(artifactPath), { recursive: true });
  fs.writeFileSync(artifactPath, artifactText);
  const artifact = { name: "manager.exe", uri: "artifacts/manager.exe", sha256: sha256File(artifactPath), sizeBytes: fs.statSync(artifactPath).size };
  writeJson(path.join(buildDir, "build-manifest.json"), {
    schema: BUILD_MANIFEST_SCHEMA,
    contract: BUILD_MANIFEST_SCHEMA,
    buildId,
    productId: "actium-node-manager",
    productVersion: "0.7.0-rc.3",
    buildKind: "candidate",
    sourceRepo: CANONICAL_REPOSITORY,
    sourceCommit: state.commit,
    sourceDirty: false,
    platform: "windows",
    architecture: "x86_64",
    toolchain: { node: "fixture" },
    artifacts: [artifact],
    issuedAt: 1788696000,
    tests: [{ name: "candidate-contracts", status: "passed" }],
    status: "BUILT",
    createdAt: "2026-09-06T12:00:00.000Z",
  });
  return { state, buildDir, artifact };
}

test("compile queda separado de release y channel", () => {
  const build = read("scripts/build-master.mjs");
  assert.match(build, /build-manifest/);
  assert.doesNotMatch(build, /runCommand\([^\n]+release:promote|runCommand\([^\n]+release:channel/);
  assert.doesNotMatch(build, /writeJson\([^\n]*release/);
  assert.match(build, /ACTIUM_SOURCE_COMMIT = source\.commit/);
});

test("el manifiesto no conserva aliases duplicados del paquete Debian", () => {
  const build = read("scripts/build-master.mjs");
  assert.match(build, /const usedNames = new Map\(\)/);
  assert.match(build, /nameKey = name\.toLowerCase\(\)/);
  assert.match(build, /usedNames\.get\(nameKey\) === digest/);
});

test("build ids son independientes y únicos", () => {
  const input = { commit: "a".repeat(40), platform: "windows", architecture: "x86_64" };
  assert.notEqual(newBuildId(input), newBuildId(input));
});

test("candidate sucio y override stale se rechazan antes de promover", () => {
  const fixture = tempRepo();
  try {
    const build = fixtureBuild(fixture, "candidate-dirty");
    fs.writeFileSync(path.join(fixture.directory, "dirty.txt"), "dirty\n");
    assert.throws(() => prepareRelease({ rootDir: fixture.directory, buildId: "candidate-dirty", version: "0.7.0-rc.3" }), /RELEASE_SOURCE_DIRTY|RELEASE_SOURCE_COMMIT_STALE/);
    assert.match(read("scripts/build-master.mjs"), /BUILD_SOURCE_COMMIT_MISMATCH/);
    assert.equal(build.artifact.name, "manager.exe");
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("la solicitud fija el payload firmado y finalize es no-rebuild, inmutable e idempotente", () => {
  const fixture = tempRepo();
  try {
    const build = fixtureBuild(fixture, "candidate-clean");
    const prepared = prepareRelease({ rootDir: fixture.directory, buildId: "candidate-clean", version: "0.7.0-rc.3", now: "2026-09-23T12:00:00.000Z" });
    const preparedAgain = prepareRelease({ rootDir: fixture.directory, buildId: "candidate-clean", version: "0.7.0-rc.3", now: "2026-09-23T12:00:00.000Z" });
    assert.equal(preparedAgain.idempotent, true);
    assert.equal(preparedAgain.path, prepared.path);
    const request = JSON.parse(fs.readFileSync(prepared.path, "utf8"));
    const payload = Buffer.from(request.payload, "base64url").toString("utf8");
    assert.equal(payload, `${RELEASE_MANIFEST_SIGNING_DOMAIN}\0${canonicalJson(request.manifest)}`);
    assert.match(request.payloadSha256, /^[A-F0-9]{64}$/);

    const authorityResponse = { keyId: "fixture-key", signature: Buffer.alloc(64, 7).toString("base64url"), algorithm: "Ed25519" };
    const responsePath = path.join(fixture.directory, "dist", "authority-response.json");
    writeJson(responsePath, authorityResponse);
    const promoted = promoteRelease({ rootDir: fixture.directory, signingRequestPath: prepared.path, signingResponsePath: responsePath });
    assert.equal(promoted.manifest.artifacts[0].uri, `artifacts/sha256/${build.artifact.sha256}/${build.artifact.name}`);
    const before = sha256File(build.artifact.uri === "artifacts/manager.exe" ? path.join(build.buildDir, build.artifact.uri) : build.artifact.uri);
    const again = promoteRelease({ rootDir: fixture.directory, signingRequestPath: prepared.path, signingResponsePath: responsePath });
    assert.equal(again.idempotent, true);
    assert.equal(promoted.manifest.signing.keyId, authorityResponse.keyId);
    const differentResponsePath = path.join(fixture.directory, "dist", "authority-response-different.json");
    writeJson(differentResponsePath, { ...authorityResponse, signature: Buffer.alloc(64, 8).toString("base64url") });
    assert.throws(() => promoteRelease({ rootDir: fixture.directory, signingRequestPath: prepared.path, signingResponsePath: differentResponsePath }), /RELEASE_ID_ALREADY_ASSIGNED_DIFFERENT_CONTENT/);
    assert.equal(sha256File(path.join(build.buildDir, "artifacts", "manager.exe")), before);
    const rc = assignReleaseChannel({ rootDir: fixture.directory, releaseChannel: "RC", release: promoted.path });
    assert.equal(rc.assignment.releaseId, promoted.releaseId);
    const stable = assignReleaseChannel({ rootDir: fixture.directory, releaseChannel: "STABLE", release: promoted.path });
    assert.equal(stable.assignment.releaseId, promoted.releaseId);
    assert.equal(JSON.parse(fs.readFileSync(path.join(fixture.directory, "dist", "channels", "rc.json"), "utf8")).releaseChannel, "RC");
    assert.throws(() => assignReleaseChannel({ rootDir: fixture.directory, releaseChannel: "LAB", release: promoted.path }), /RELEASE_CHANNEL_INVALID/);
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("tampered artifact, release version con canal y release distinto fallan cerrado", () => {
  const fixture = tempRepo();
  try {
    const build = fixtureBuild(fixture, "candidate-tamper");
    fs.writeFileSync(path.join(build.buildDir, "artifacts", "manager.exe"), "tampered\n");
    assert.throws(() => prepareRelease({ rootDir: fixture.directory, buildId: "candidate-tamper", version: "0.7.0-rc.3" }), /RELEASE_ARTIFACT_DIGEST_MISMATCH/);
    assert.throws(() => prepareRelease({ rootDir: fixture.directory, buildId: "candidate-tamper", version: "0.7.0-lab.1" }), /RELEASE_VERSION_MUST_NOT_ENCODE_CHANNEL/);
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("el payload del release coincide con el vector compartido con Rust Trust Fabric", () => {
  const vector = JSON.parse(read("contracts/release/v1/release-manifest-signing-vector.json"));
  const payload = releaseManifestSigningPayload(vector.manifest);
  const digest = createHash("sha256").update(payload).digest("hex").toUpperCase();
  assert.equal(digest, vector.payloadSha256);
});

test("la respuesta del Authority debe estar bien formada y la solicitud no puede alterarse", () => {
  const fixture = tempRepo();
  try {
    fixtureBuild(fixture, "candidate-signed");
    const prepared = prepareRelease({ rootDir: fixture.directory, buildId: "candidate-signed", version: "0.7.0-rc.3", now: "2026-09-23T12:00:00.000Z" });
    const responsePath = path.join(fixture.directory, "dist", "authority-response.json");
    writeJson(responsePath, { keyId: "fixture-key", signature: "not-a-signature", algorithm: "Ed25519" });
    assert.throws(() => promoteRelease({ rootDir: fixture.directory, signingRequestPath: prepared.path, signingResponsePath: responsePath }), /RELEASE_SIGNING_RESPONSE_INVALID/);

    const request = JSON.parse(fs.readFileSync(prepared.path, "utf8"));
    request.manifest.version = "9.9.9";
    writeJson(prepared.path, request);
    assert.throws(() => promoteRelease({ rootDir: fixture.directory, signingRequestPath: prepared.path, signingResponsePath: responsePath }), /RELEASE_SIGNING_REQUEST_DIGEST_MISMATCH/);
    assert.equal(fs.existsSync(path.join(fixture.directory, "dist", "releases")), false);
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("scripts se pueden importar sin ejecutar operaciones", () => {
  assert.equal(pathToFileURL(path.join(root, "scripts", "release-promote.mjs")).protocol, "file:");
  assert.equal(spawnSync(process.execPath, [path.join(root, "scripts", "release-promote.mjs")], { cwd: root, encoding: "utf8" }).status, 1);
  assert.equal(spawnSync(process.execPath, [path.join(root, "scripts", "release-signing-request.mjs")], { cwd: root, encoding: "utf8" }).status, 1);
  assert.match(RELEASE_MANIFEST_SCHEMA, /actium-release-manifest@1\.0\.0/);
  const signingRequestSchema = JSON.parse(read("contracts/release/v1/actium-release-signing-request.schema.json"));
  assert.equal(signingRequestSchema.properties.capability.const, "product_signing");
  assert.equal(signingRequestSchema.properties.manifest.required.includes("signing"), false);
});
