#!/usr/bin/env node
import path from "node:path";
import { pathToFileURL } from "node:url";
import { prepareRelease } from "./release-promote.mjs";

function parseArgs(argv) {
  const parsed = { root: path.resolve(import.meta.dirname, ".."), buildId: null, version: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--root") parsed.root = argv[++i];
    if (argv[i] === "--build-id") parsed.buildId = argv[++i];
    if (argv[i] === "--version") parsed.version = argv[++i];
  }
  return parsed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (!parsed.buildId) throw new Error("RELEASE_BUILD_ID_REQUIRED");
    if (!parsed.version) throw new Error("RELEASE_VERSION_REQUIRED");
    const result = prepareRelease({
      rootDir: path.resolve(parsed.root),
      buildId: parsed.buildId,
      version: parsed.version,
    });
    console.log(`${result.idempotent ? "IDEMPOTENT" : "PREPARED"}: ${result.releaseId}`);
    console.log(`signing_request=${result.path}`);
    console.log(`payload_sha256=${result.request.payloadSha256}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
