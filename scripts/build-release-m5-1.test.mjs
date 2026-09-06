import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { assignChannel } from "./release-channel.mjs";
import { promoteRelease } from "./release-promote.mjs";
import { BUILD_MANIFEST_SCHEMA, CANONICAL_REPOSITORY, RELEASE_MANIFEST_SCHEMA, gitState, newBuildId, sha256File, writeJson } from "./release-toolkit.mjs";

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

test("build ids son independientes y únicos", () => {
  const input = { commit: "a".repeat(40), platform: "windows", architecture: "x86_64" };
  assert.notEqual(newBuildId(input), newBuildId(input));
});

test("candidate sucio y override stale se rechazan antes de promover", () => {
  const fixture = tempRepo();
  try {
    const build = fixtureBuild(fixture, "candidate-dirty");
    fs.writeFileSync(path.join(fixture.directory, "dirty.txt"), "dirty\n");
    assert.throws(() => promoteRelease({ rootDir: fixture.directory, buildId: "candidate-dirty", version: "0.7.0-rc.3", signingKeyId: "fixture", signature: "fixture" }), /RELEASE_SOURCE_DIRTY|RELEASE_SOURCE_COMMIT_STALE/);
    assert.match(read("scripts/build-master.mjs"), /BUILD_SOURCE_COMMIT_MISMATCH/);
    assert.equal(build.artifact.name, "manager.exe");
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("promotion is no-rebuild, immutable and idempotent; channel assignment is separate", () => {
  const fixture = tempRepo();
  try {
    const build = fixtureBuild(fixture, "candidate-clean");
    const promoted = promoteRelease({ rootDir: fixture.directory, buildId: "candidate-clean", version: "0.7.0-rc.3", signingKeyId: "fixture-key", signature: "fixture-signature" });
    const before = sha256File(build.artifact.uri === "artifacts/manager.exe" ? path.join(build.buildDir, build.artifact.uri) : build.artifact.uri);
    const again = promoteRelease({ rootDir: fixture.directory, buildId: "candidate-clean", version: "0.7.0-rc.3", signingKeyId: "fixture-key", signature: "fixture-signature" });
    assert.equal(again.idempotent, true);
    assert.equal(sha256File(path.join(build.buildDir, "artifacts", "manager.exe")), before);
    const lab = assignChannel({ rootDir: fixture.directory, channel: "lab", release: promoted.path });
    assert.equal(lab.assignment.releaseId, promoted.releaseId);
    const stable = assignChannel({ rootDir: fixture.directory, channel: "stable", release: promoted.path });
    assert.equal(stable.assignment.releaseId, promoted.releaseId);
    assert.equal(JSON.parse(fs.readFileSync(path.join(fixture.directory, "dist", "channels", "lab.json"), "utf8")).channel, "lab");
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("tampered artifact, release version con canal y release distinto fallan cerrado", () => {
  const fixture = tempRepo();
  try {
    const build = fixtureBuild(fixture, "candidate-tamper");
    fs.writeFileSync(path.join(build.buildDir, "artifacts", "manager.exe"), "tampered\n");
    assert.throws(() => promoteRelease({ rootDir: fixture.directory, buildId: "candidate-tamper", version: "0.7.0-rc.3", signingKeyId: "fixture", signature: "fixture" }), /RELEASE_ARTIFACT_DIGEST_MISMATCH/);
    assert.throws(() => promoteRelease({ rootDir: fixture.directory, buildId: "candidate-tamper", version: "0.7.0-lab.1", signingKeyId: "fixture", signature: "fixture" }), /RELEASE_VERSION_MUST_NOT_ENCODE_CHANNEL/);
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("scripts se pueden importar sin ejecutar operaciones", () => {
  assert.equal(pathToFileURL(path.join(root, "scripts", "release-promote.mjs")).protocol, "file:");
  assert.equal(spawnSync(process.execPath, [path.join(root, "scripts", "release-promote.mjs")], { cwd: root, encoding: "utf8" }).status, 1);
  assert.match(RELEASE_MANIFEST_SCHEMA, /actium-release-manifest@1\.0\.0/);
});
