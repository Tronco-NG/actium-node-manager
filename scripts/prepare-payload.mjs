import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { lstatSync } from "node:fs";
import { applyPayloadUnixModes } from "./payload-unix-modes.mjs";
import { payloadGeneratedAt } from "./payload-provenance.mjs";
import { canonicalizePayloadTextFiles, collectPayloadFiles, payloadTreeSha256 } from "./payload-text-normalizer.mjs";

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataPlaneRoot = resolve(installerRoot, "..");
const targetRoot = join(installerRoot, "src-tauri", "resources", "node");
const include = [
  "README.md",
  "release-capabilities.json",
  "compose.fabric.yml",
  "compose.agent.yml",
  "compose.site-core.yml",
  "compose.site-core-candidate.yml",
  "compose.telemetry.yml",
  "compose.people.yml",
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
const releaseCapabilities = JSON.parse(await readFile(join(dataPlaneRoot, "release-capabilities.json"), "utf8"));
const supportedProfiles = releaseCapabilities?.releases?.[version]?.supportedProfiles;
const supportedFeatures = releaseCapabilities?.releases?.[version]?.supportedFeatures;
if (
  releaseCapabilities?.schema !== 1
  || !Array.isArray(supportedProfiles)
  || !Array.isArray(supportedFeatures)
  || supportedProfiles.length === 0
  || supportedProfiles.some((profile) => typeof profile !== "string" || !profile.trim())
  || supportedFeatures.some((feature) => typeof feature !== "string" || !feature.trim())
) {
  throw new Error(`release-capabilities.json no declara capacidades verificables para ${version}`);
}
if (version === "0.8.0-lab.32" && supportedProfiles.includes("people")) {
  throw new Error("Runtime 0.8.0-lab.32 no puede declarar soporte People");
}
if (version === "0.8.0-lab.32" && supportedFeatures.includes("site_core_candidate_v1")) {
  throw new Error("Runtime 0.8.0-lab.32 no puede declarar Site Core candidate");
}

function toRepoRelative(absolute) {
  return relative(dataPlaneRoot, absolute).replaceAll("\\", "/");
}

function isTracked(relativePath, trackedFiles) {
  return relativePath.length > 0 && trackedFiles.has(relativePath);
}

function isExcludedPayloadPath(relativePath) {
  const segments = relativePath.split("/");
  return (
    segments.includes("node_modules")
    || segments.includes("target")
    || segments.includes("dist")
    || segments.includes("secrets")
    || relativePath.endsWith("/node.env")
    || relativePath.endsWith("/node.env.example")
  );
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
    const commitDate = execFileSync("git", ["show", "-s", "--format=%cI", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    const status = execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    const sourceDirty = status.length > 0;
    return {
      sourceCommit,
      sourceDirty,
      generatedAt: payloadGeneratedAt({ sourceDirty, commitDate }),
    };
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
      const normalizedPath = toRepoRelative(candidate);
      if (isExcludedPayloadPath(normalizedPath)) return false;
      if (metadata.isDirectory()) return true;

      return (
        isTracked(normalizedPath, trackedFiles)
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
if (process.env.GITHUB_SHA && source.sourceCommit !== process.env.GITHUB_SHA) {
  throw new Error(`PAYLOAD sourceCommit ${source.sourceCommit} != GITHUB_SHA ${process.env.GITHUB_SHA}`);
}
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
    supportedProfiles,
    supportedFeatures,
    generatedAt: source.generatedAt,
    sourceCommit: source.sourceCommit,
    sourceDirty: source.sourceDirty,
    productChannel,
  }, null, 2)}\n`,
  "utf8",
);

console.log(`Payload Actium Data Plane ${version} schema 3 (${treeSha256.slice(0, 12)}) preparado en ${targetRoot}`);
