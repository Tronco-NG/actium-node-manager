import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const BUILD_MANIFEST_SCHEMA = "actium-build-manifest@1.0.0";
export const RELEASE_MANIFEST_SCHEMA = "actium-release-manifest@1.0.0";
export const RELEASE_CHANNEL_SCHEMA = "actium-release-channel@1.0.0";
export const CANONICAL_REPOSITORY = "Tronco-NG/actium-node-manager";

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256File(filePath) {
  return createHash("sha256").update(fs.readFileSync(filePath)).digest("hex").toUpperCase();
}

export function sha256Text(value) {
  return createHash("sha256").update(value, "utf8").digest("hex").toUpperCase();
}

export function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

export function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export function captureCommand(command, args, cwd) {
  const windowsNpmCommand = process.platform === "win32" && ["npm", "npx"].includes(command);
  const executable = windowsNpmCommand ? (process.env.ComSpec || "cmd.exe") : command;
  const executableArgs = windowsNpmCommand ? ["/d", "/s", "/c", `${command}.cmd`, ...args] : args;
  const result = spawnSync(executable, executableArgs, { cwd, encoding: "utf8", shell: false });
  return result.status === 0 ? result.stdout.trim() : "unknown";
}

export function gitState(rootDir) {
  const commit = captureCommand("git", ["rev-parse", "HEAD"], rootDir);
  if (!/^[0-9a-f]{40}$/i.test(commit)) throw new Error("BUILD_SOURCE_COMMIT_UNAVAILABLE");
  const status = spawnSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: rootDir, encoding: "utf8", shell: false });
  if (status.status !== 0) throw new Error("BUILD_SOURCE_STATUS_UNAVAILABLE");
  return { commit, dirty: Boolean(status.stdout.trim()), status: status.stdout.trim() };
}

export function repositoryFromOrigin(rootDir) {
  const origin = captureCommand("git", ["config", "--get", "remote.origin.url"], rootDir);
  const match = origin.match(/(?:github\.com[/:])([^/]+\/[^/.]+?)(?:\.git)?$/i);
  return match?.[1] || origin || "unknown";
}

export function newBuildId({ commit, platform, architecture }) {
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const entropy = randomBytes(4).toString("hex");
  return `build-${stamp}-${platform}-${architecture}-${commit.slice(0, 12)}-${entropy}`.toLowerCase();
}

export function assertBuildId(value) {
  if (!/^[a-z0-9][a-z0-9._-]{2,159}$/.test(value)) throw new Error("BUILD_ID_INVALID");
}

export function assertSha256(value, error = "ARTIFACT_SHA256_INVALID") {
  if (!/^[A-Fa-f0-9]{64}$/.test(value)) throw new Error(error);
}

export function assertManifestSchema(manifest, schema, error = "MANIFEST_SCHEMA_INVALID") {
  if (!manifest || manifest.schema !== schema || manifest.contract !== schema) throw new Error(error);
}

export function artifactDigestSet(artifacts) {
  return artifacts.map((artifact) => `${artifact.name}:${artifact.sha256}`).sort();
}

export function sameArtifactSet(left, right) {
  return JSON.stringify(artifactDigestSet(left)) === JSON.stringify(artifactDigestSet(right));
}

export function platformForTarget(targetOS) {
  if (targetOS === "windows") return "windows";
  if (targetOS === "linux") return "linux";
  if (targetOS === "macos") return "macos";
  return process.platform === "win32" ? "windows" : process.platform;
}

export function architectureForTarget() {
  if (["x64", "amd64"].includes(process.arch)) return "x86_64";
  if (["arm64"].includes(process.arch)) return "aarch64";
  return process.arch;
}
