import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const payloadRoot = process.argv[2];
if (!payloadRoot) {
  console.error("Uso: node scripts/verify-payload-identity.mjs <payload-empaquetado>");
  process.exit(2);
}

const installerRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataPlaneRoot = resolve(installerRoot, "..");
const payload = JSON.parse(readFileSync(resolve(payloadRoot, "PAYLOAD.json"), "utf8"));
const expectedChannel = process.env.ACTIUM_PRODUCT_CHANNEL === "stable" ? "stable" : "lab";
const versionFile = expectedChannel === "stable" ? "VERSION.stable" : "VERSION";
const version = readFileSync(resolve(dataPlaneRoot, versionFile), "utf8").trim();
const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  cwd: dataPlaneRoot,
  encoding: "utf8",
}).trim();
const head = execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: repoRoot,
  encoding: "utf8",
}).trim();

if (payload.schema !== 3) {
  throw new Error(`PAYLOAD schema ${payload.schema} != 3`);
}
if (payload.productChannel !== expectedChannel) {
  throw new Error(`PAYLOAD productChannel ${payload.productChannel} != ${expectedChannel}`);
}
if (payload.releaseVersion !== version) {
  throw new Error(`PAYLOAD releaseVersion ${payload.releaseVersion} != ${version}`);
}
if (payload.sourceDirty !== false && process.env.ACTIUM_ALLOW_DIRTY !== "1") {
  throw new Error("PAYLOAD sourceDirty debe ser false para un release set publicable (use ACTIUM_ALLOW_DIRTY=1 para pruebas locales)");
}
if (payload.sourceCommit !== head && process.env.ACTIUM_ALLOW_DIRTY !== "1") {
  throw new Error(`PAYLOAD sourceCommit ${payload.sourceCommit} != git HEAD ${head} (use ACTIUM_ALLOW_DIRTY=1 para pruebas locales)`);
}
if (process.env.GITHUB_SHA && payload.sourceCommit !== process.env.GITHUB_SHA) {
  throw new Error(
    `PAYLOAD sourceCommit ${payload.sourceCommit} != GITHUB_SHA ${process.env.GITHUB_SHA}`,
  );
}

console.log(
  `Payload identity OK channel=${payload.productChannel} version=${payload.releaseVersion} sourceCommit=${payload.sourceCommit} treeSha256=${payload.treeSha256 ?? "n/d"}`,
);
