import { spawnSync } from "node:child_process";

const windowsCwd = process.cwd();
const match = /^([A-Za-z]):[\\/](.*)$/.exec(windowsCwd);
if (!match) throw new Error(`Workspace Windows no reconocido: ${windowsCwd}`);
const linuxCwd = `/mnt/${match[1].toLowerCase()}/${match[2].replaceAll("\\", "/")}`;
const quotedCwd = `'${linuxCwd.replaceAll("'", "'\\''")}'`;
const command = `. ~/.cargo/env; cd ${quotedCwd}; export ACTIUM_ALLOW_DIRTY=1; sh ./scripts/build-supervisor-linux.sh`;
const result = spawnSync("wsl.exe", ["-d", "Debian", "--", "bash", "-lc", command], {
  stdio: "inherit",
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
