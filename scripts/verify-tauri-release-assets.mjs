import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const frontendDir = path.join(root, "dist", "frontend");
const indexPath = path.join(frontendDir, "index.html");

assert.ok(fs.existsSync(indexPath), `Falta el entrypoint frontend: ${indexPath}`);
const index = fs.readFileSync(indexPath, "utf8");
const assetReferences = [...index.matchAll(/(?:src|href)=["'](\/assets\/[^"']+)["']/g)].map((match) => match[1]);
assert.ok(assetReferences.length > 0, "El index.html no referencia assets frontend");

for (const reference of assetReferences) {
  const assetPath = path.join(frontendDir, reference.slice(1));
  assert.ok(fs.existsSync(assetPath), `Falta el asset frontend referenciado: ${assetPath}`);
  assert.ok(fs.statSync(assetPath).size > 0, `El asset frontend está vacío: ${assetPath}`);
}

console.log(`tauri-release-assets: ${assetReferences.length} assets presentes en ${frontendDir}`);
