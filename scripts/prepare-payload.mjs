import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { lstatSync } from "node:fs";
import { applyPayloadUnixModes } from "./payload-unix-modes.mjs";
import { canonicalizePayloadTextFiles, collectPayloadFiles, payloadTreeSha256 } from "./payload-text-normalizer.mjs";

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataPlaneRoot = resolve(installerRoot, "..");
const targetRoot = join(installerRoot, "src-tauri", "resources", "node");
const include = [
  "README.md",
  "compose.fabric.yml",
  "compose.agent.yml",
  "compose.site-core.yml",
  "compose.telemetry.yml",
  "compose.radio-control.yml",
  "compose.radio-saf.yml",
  "compose.turn.yml",
  "compose.livekit.yml",
  "compose.connectivity.yml",
  "compose.observability.yml",
  "bootstrap.ps1",
  "bootstrap.sh",
  "install-node.ps1",
  "install-node.sh",
  "manage-node.ps1",
  "manage-node.sh",
  "verify-node.ps1",
  "verify-node.sh",
  "node.env.example",
  "contracts",
  "coturn",
  "connectivity",
  "docs",
  "livekit",
  "migrations",
  "nats",
  "observability",
  "postgres",
  "scripts",
  "services",
];

const productChannel = process.env.ACTIUM_PRODUCT_CHANNEL === "stable" ? "stable" : "lab";
const versionFile = process.env.ACTIUM_DATA_PLANE_VERSION_FILE
  ?? (productChannel === "stable" ? "VERSION.stable" : "VERSION");
const version = (await readFile(join(dataPlaneRoot, versionFile), "utf8")).trim();

function toRepoRelative(absolute) {
  return relative(dataPlaneRoot, absolute).replaceAll("\\", "/");
}

function isTracked(relativePath, trackedFiles) {
  return relativePath.length > 0 && trackedFiles.has(relativePath);
}

function buildTrackedFiles() {
  const output = execFileSync("git", ["ls-files"], {
    cwd: dataPlaneRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

  return new Set(
    output
      .split(/\r?\n/u)
      .map((line) => line.replaceAll("\\", "/").trim())
      .filter((line) => line.length > 0),
  );
}

function gitMetadata() {
  try {
    const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: dataPlaneRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    const status = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    return { sourceCommit, sourceDirty: status.length > 0 };
  } catch (error) {
    throw new Error(`No se pudo vincular el payload a Git: ${error.message}`);
  }
}

await rm(targetRoot, { recursive: true, force: true });
await mkdir(targetRoot, { recursive: true });
const trackedFiles = buildTrackedFiles();

for (const entry of include) {
  const source = join(dataPlaneRoot, entry);
  const destination = join(targetRoot, entry);
  await cp(source, destination, {
    recursive: true,
    filter: (candidate) => {
      const metadata = lstatSync(candidate);
      if (metadata.isDirectory()) return true;

      const normalizedPath = toRepoRelative(candidate);
      return (
        !normalizedPath.includes("/node_modules/")
        && !normalizedPath.includes("/target/")
        && !normalizedPath.includes("/dist/")
        && !normalizedPath.endsWith("/node.env")
        && !normalizedPath.includes("/node.env.example")
        && !normalizedPath.includes("/secrets/")
        && isTracked(normalizedPath, trackedFiles)
      );
    },
  });
}

// El runtime verifica VERSION dentro del payload. Se materializa desde el
// archivo seleccionado por canal para que Stable y Lab compartan el mismo
// contrato sin empaquetar ambas identidades.
await writeFile(join(targetRoot, "VERSION"), `${version}\n`, "utf8");
await canonicalizePayloadTextFiles(targetRoot);
await applyPayloadUnixModes(targetRoot);

const files = await collectPayloadFiles(targetRoot);
const treeSha256 = payloadTreeSha256(files);
const source = gitMetadata();
if (process.env.ACTIUM_REQUIRE_CLEAN_WORKTREE === "true" && source.sourceDirty) {
  throw new Error("El bundle Lab exige un working tree limpio; no se generara un candidato ambiguo.");
}
await writeFile(
  join(targetRoot, "PAYLOAD.json"),
  `${JSON.stringify({
    schema: 3,
    releaseVersion: version,
    files,
    treeSha256,
    siteRuntimeSchema: "1.1",
    generatedAt: new Date().toISOString(),
    sourceCommit: source.sourceCommit,
    sourceDirty: source.sourceDirty,
    productChannel,
  }, null, 2)}\n`,
  "utf8",
);

console.log(`Payload Actium Data Plane ${version} schema 3 (${treeSha256.slice(0, 12)}) preparado en ${targetRoot}`);
