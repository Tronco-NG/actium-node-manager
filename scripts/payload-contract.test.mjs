import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { resolve } from "node:path";
import { canonicalizePayloadTextFiles, collectPayloadFiles, payloadTreeSha256 } from "./payload-text-normalizer.mjs";
import { payloadGeneratedAt } from "./payload-provenance.mjs";

const dataPlaneRoot = resolve(import.meta.dirname, "../..");

test("install-node invoca bootstrap mediante /bin/sh", async () => {
  const source = await readFile(resolve(dataPlaneRoot, "install-node.sh"), "utf8");
  assert.match(source, /set -- \/bin\/sh "\$SCRIPT_ROOT\/bootstrap\.sh"/);
});

test("bootstrap materializa ambos aliases de perfiles desde una fuente unica", async () => {
  const source = await readFile(resolve(dataPlaneRoot, "bootstrap.sh"), "utf8");
  assert.match(source, /ACTIUM_PROFILES=\$PROFILES\r?\nACTIUM_ACTIVE_PROFILES=\$PROFILES/);
  assert.match(source, /exec \/bin\/sh "\$SCRIPT_ROOT\/manage-node\.sh" start/);
  assert.match(source, /find "\$SECRETS_DIR" -maxdepth 1 -type f -exec chmod 600 \{\} \\;/);
  assert.doesNotMatch(source, /chmod 600 "\$SECRETS_DIR"\/\*/);
});

test("manage-node valida Compose silenciosamente", async () => {
  const source = await readFile(resolve(dataPlaneRoot, "manage-node.sh"), "utf8");
  assert.match(source, /config\) docker "\$@" config --quiet/);
});

test("el empaquetador materializa VERSION antes de hashear el payload", async () => {
  const source = await readFile(resolve(dataPlaneRoot, "installer/scripts/prepare-payload.mjs"), "utf8");
  const materializeAt = source.indexOf('writeFile(join(targetRoot, "VERSION")');
  const canonicalizeAt = source.indexOf("canonicalizePayloadTextFiles(targetRoot)");
  const collectAt = source.indexOf("collectPayloadFiles(targetRoot)");

  assert.ok(materializeAt >= 0, "prepare-payload debe materializar VERSION");
  assert.ok(materializeAt < canonicalizeAt, "VERSION debe canonicalizarse con el resto del payload");
  assert.ok(canonicalizeAt < collectAt, "VERSION debe formar parte de files[] y treeSha256");
});

test("treeSha256 usa el mismo orden UTF-8 binario que Rust", () => {
  const digest = payloadTreeSha256([
    { path: "bootstrap.sh", size: 2, sha256: "0".repeat(64) },
    { path: "README.md", size: 1, sha256: "f".repeat(64) },
  ]);
  assert.equal(digest, "b48dd7f386365885ec26f39d359ad647b96849c348814235c0119314b0a777a2");
});

test("generatedAt de un candidato limpio deriva del commit y no del reloj", () => {
  const commitDate = "2026-08-14T12:34:56-03:00";
  const first = payloadGeneratedAt({
    sourceDirty: false,
    commitDate,
    now: new Date("2030-01-01T00:00:00Z"),
  });
  const second = payloadGeneratedAt({
    sourceDirty: false,
    commitDate,
    now: new Date("2040-01-01T00:00:00Z"),
  });
  assert.equal(first, "2026-08-14T15:34:56.000Z");
  assert.equal(second, first);
  assert.equal(
    payloadGeneratedAt({
      sourceDirty: true,
      commitDate,
      now: new Date("2030-01-01T00:00:00Z"),
    }),
    "2030-01-01T00:00:00.000Z",
  );
});

test("tar Linux fija orden, ownership, mtime y cabecera gzip", async () => {
  const source = await readFile(resolve(dataPlaneRoot, "installer/scripts/build-supervisor-linux.sh"), "utf8");
  assert.match(source, /git -C "\$installer_root" show -s --format=%ct HEAD/);
  assert.match(source, /--sort=name/);
  assert.match(source, /--mtime="@\$source_date_epoch"/);
  assert.match(source, /--owner=0/);
  assert.match(source, /--group=0/);
  assert.match(source, /--numeric-owner/);
  assert.match(source, /gzip -n -c/);
});

test("normalización de texto convierte CRLF/LF al mismo manifest", async () => {
  const root = await mkdtemp(join(tmpdir(), "actium-payload-repro-"));
  const candidateA = join(root, "candidateA");
  const candidateB = join(root, "candidateB");

  try {
    await mkdir(join(candidateA, "text"), { recursive: true });
    await mkdir(join(candidateA, "bin"), { recursive: true });
    await mkdir(join(candidateB, "text"), { recursive: true });
    await mkdir(join(candidateB, "bin"), { recursive: true });

    await writeFile(join(candidateA, "text/config"), "a\r\nb\r\n", "utf8");
    await writeFile(join(candidateA, "script.sh"), "#!/bin/sh\r\necho hi\r\n", "utf8");
    await writeFile(join(candidateB, "text/config"), "a\nb\n", "utf8");
    await writeFile(join(candidateB, "script.sh"), "#!/bin/sh\necho hi\n", "utf8");

    const binary = Buffer.from([0, 1, 2, 3, 0, 4]);
    await writeFile(join(candidateA, "bin/data.bin"), Buffer.from(binary));
    await writeFile(join(candidateB, "bin/data.bin"), Buffer.from(binary));

    await canonicalizePayloadTextFiles(candidateA);
    await canonicalizePayloadTextFiles(candidateB);

    const manifestA = await collectPayloadFiles(candidateA);
    const manifestB = await collectPayloadFiles(candidateB);

    const hashA = payloadTreeSha256(manifestA);
    const hashB = payloadTreeSha256(manifestB);
    assert.equal(hashA, hashB);

    const filesA = new Map(manifestA.map((entry) => [entry.path, `${entry.size}:${entry.sha256}`]));
    const filesB = new Map(manifestB.map((entry) => [entry.path, `${entry.size}:${entry.sha256}`]));
    assert.deepEqual(filesA, filesB);
    const shaBinaryA = createHash("sha256").update(binary).digest("hex");
    const binaryA = manifestA.find((entry) => entry.path === "bin/data.bin");
    const binaryB = manifestB.find((entry) => entry.path === "bin/data.bin");
    assert.ok(binaryA?.sha256 === binaryB?.sha256);
    assert.equal(binaryA?.sha256, shaBinaryA);
    assert.equal(binaryB?.sha256, shaBinaryA);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
