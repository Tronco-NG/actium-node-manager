import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const [, , channel, command, ...forwardedArgs] = process.argv;
if (!(["stable", "lab"].includes(channel)) || !(["dev", "build"].includes(command))) {
  console.error("Uso: node scripts/run-channel.mjs <stable|lab> <dev|build> [argumentos]");
  process.exit(2);
}

const environment = {
  ...process.env,
  ACTIUM_PRODUCT_CHANNEL: channel,
  VITE_ACTIUM_PRODUCT_CHANNEL: channel,
};
const workspace = process.cwd();
const payloadScript = path.join(workspace, "scripts", "prepare-payload.mjs");
const tauriCli = path.join(workspace, "node_modules", "@tauri-apps", "cli", "tauri.js");

const payload = spawnSync(process.execPath, [payloadScript], {
  cwd: workspace,
  env: environment,
  stdio: "inherit",
});
if (payload.error) {
  console.error(payload.error.message);
  process.exit(1);
}
if (payload.status !== 0) process.exit(payload.status ?? 1);

const tauriArgs = [tauriCli, command];
if (channel === "lab") {
  tauriArgs.push("--config", "src-tauri/tauri.lab.conf.json");
}
tauriArgs.push(...forwardedArgs);

const tauri = spawnSync(process.execPath, tauriArgs, {
  cwd: workspace,
  env: environment,
  stdio: "inherit",
});
if (tauri.error) console.error(tauri.error.message);
process.exit(tauri.status ?? 1);
