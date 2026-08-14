import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { resolve } from "node:path";

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
