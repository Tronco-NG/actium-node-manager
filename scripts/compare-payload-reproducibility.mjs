import { readFileSync } from "node:fs";
import process from "node:process";

const args = process.argv.slice(2);
const leftPath = args[0] ?? process.env.ACTIUM_PAYLOAD_MANIFEST_WINDOWS;
const rightPath = args[1] ?? process.env.ACTIUM_PAYLOAD_MANIFEST_LINUX;

if (!leftPath || !rightPath) {
  console.error("Uso: node scripts/compare-payload-reproducibility.mjs <manifestWindows> <manifestLinux>");
  process.exit(1);
}

const left = JSON.parse(readFileSync(leftPath, "utf8"));
const right = JSON.parse(readFileSync(rightPath, "utf8"));

const paths = new Set();
for (const file of left.files) paths.add(file.path);
for (const file of right.files) paths.add(file.path);

let mismatchCount = 0;
const differences = [];
for (const path of [...paths].sort((leftValue, rightValue) => leftValue.localeCompare(rightValue))) {
  const leftFile = left.files?.find((file) => file.path === path);
  const rightFile = right.files?.find((file) => file.path === path);

  const leftSize = leftFile?.size ?? null;
  const rightSize = rightFile?.size ?? null;
  const leftSha = leftFile?.sha256 ?? null;
  const rightSha = rightFile?.sha256 ?? null;

  if (leftSize !== rightSize || leftSha !== rightSha) {
    mismatchCount += 1;
    differences.push(`${path} | ${leftSize} | ${rightSize} | ${leftSha} | ${rightSha}`);
  }
}

const metadataIssues = [
  left.releaseVersion !== right.releaseVersion ? `releaseVersion diferente: ${left.releaseVersion} vs ${right.releaseVersion}` : null,
  left.sourceCommit !== right.sourceCommit ? `sourceCommit diferente: ${left.sourceCommit} vs ${right.sourceCommit}` : null,
  left.files.length !== right.files.length ? `cantidad archivos diferente: ${left.files.length} vs ${right.files.length}` : null,
  left.treeSha256 !== right.treeSha256 ? `treeSha256 diferente: ${left.treeSha256} vs ${right.treeSha256}` : null,
];

for (const issue of metadataIssues) {
  if (issue !== null) {
    mismatchCount += 1;
  }
}

if (mismatchCount === 0) {
  console.log(`reproducible=true`);
  console.log(`releaseVersion=${left.releaseVersion}`);
  console.log(`sourceCommit=${left.sourceCommit}`);
  console.log(`files=${left.files.length}`);
  console.log(`treeSha256=${left.treeSha256}`);
  process.exit(0);
}

console.error(`reproducible=false`);
for (const issue of metadataIssues) {
  if (issue !== null) console.error(issue);
}
for (const diff of differences.slice(0, 300)) {
  console.error(diff);
}
process.exit(1);
