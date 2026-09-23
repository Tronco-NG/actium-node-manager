#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { RELEASE_CHANNEL_SCHEMA, RELEASE_MANIFEST_SCHEMA, assertManifestSchema, artifactDigestSet, readJson, writeJson } from "./release-toolkit.mjs";

function parseArgs(argv) {
  const parsed = { root: path.resolve(import.meta.dirname, ".."), releaseChannel: null, release: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--root") parsed.root = argv[++i];
    if (argv[i] === "--release-channel" || argv[i] === "--channel") parsed.releaseChannel = argv[++i];
    if (argv[i] === "--release") parsed.release = argv[++i];
  }
  return parsed;
}

function findRelease(rootDir, releaseRef) {
  const direct = path.resolve(rootDir, releaseRef);
  if (fs.existsSync(direct)) return direct;
  const releaseRoot = path.join(rootDir, "dist", "releases");
  if (!fs.existsSync(releaseRoot)) throw new Error("CHANNEL_RELEASE_NOT_FOUND");
  const matches = [];
  for (const version of fs.readdirSync(releaseRoot)) {
    for (const platform of fs.readdirSync(path.join(releaseRoot, version))) {
      const platformDir = path.join(releaseRoot, version, platform);
      if (!fs.existsSync(platformDir)) continue;
      for (const architecture of fs.readdirSync(platformDir)) {
        const candidatePath = path.join(platformDir, architecture, "release-manifest.json");
        if (!fs.existsSync(candidatePath)) continue;
        const manifest = readJson(candidatePath);
        if (manifest.releaseId === releaseRef || manifest.version === releaseRef) matches.push(candidatePath);
      }
    }
  }
  if (matches.length !== 1) throw new Error(matches.length === 0 ? "CHANNEL_RELEASE_NOT_FOUND" : "CHANNEL_RELEASE_REFERENCE_AMBIGUOUS");
  return matches[0];
}

export function assignReleaseChannel({ rootDir, releaseChannel, release }) {
  const selectedReleaseChannel = releaseChannel;
  if (!["DEV", "RC", "STABLE"].includes(selectedReleaseChannel)) throw new Error("RELEASE_CHANNEL_INVALID");
  const releasePath = findRelease(rootDir, release);
  const manifest = readJson(releasePath);
  assertManifestSchema(manifest, RELEASE_MANIFEST_SCHEMA, "CHANNEL_RELEASE_SCHEMA_INVALID");
  if (manifest.releaseStatus !== "PROMOTED") throw new Error("CHANNEL_RELEASE_NOT_PROMOTED");
  const relativeRelease = path.relative(path.join(rootDir, "dist"), releasePath).replaceAll(path.sep, "/");
  const assignment = {
    schema: RELEASE_CHANNEL_SCHEMA,
    contract: RELEASE_CHANNEL_SCHEMA,
    releaseChannel: selectedReleaseChannel,
    releaseId: manifest.releaseId,
    releaseManifest: relativeRelease,
    releaseVersion: manifest.version,
    buildId: manifest.buildId,
    sourceCommit: manifest.sourceCommit,
    artifactSha256: manifest.artifacts.map((artifact) => artifact.sha256).sort(),
    assignedAt: new Date().toISOString(),
    status: "ASSIGNED",
  };
  const assignmentPath = path.join(rootDir, "dist", "channels", `${selectedReleaseChannel.toLowerCase()}.json`);
  if (fs.existsSync(assignmentPath)) {
    const existing = readJson(assignmentPath);
    if (existing.releaseId === assignment.releaseId && JSON.stringify(existing.artifactSha256) === JSON.stringify(assignment.artifactSha256)) return { idempotent: true, path: assignmentPath, assignment: existing };
    throw new Error("CHANNEL_ALREADY_ASSIGNED_DIFFERENT_RELEASE");
  }
  writeJson(assignmentPath, assignment);
  return { idempotent: false, path: assignmentPath, assignment };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (!parsed.releaseChannel || !parsed.release) throw new Error("RELEASE_CHANNEL_AND_RELEASE_REQUIRED");
    const result = assignReleaseChannel({ rootDir: path.resolve(parsed.root), releaseChannel: parsed.releaseChannel.toUpperCase(), release: parsed.release });
    console.log(`${result.idempotent ? "IDEMPOTENT" : "ASSIGNED"}: ${result.assignment.releaseChannel} -> ${result.assignment.releaseId}`);
    console.log(`channel_manifest=${result.path}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
