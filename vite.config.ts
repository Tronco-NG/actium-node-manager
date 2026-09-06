import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  server: {
    port: process.env.ACTIUM_PRODUCT_CHANNEL === "lab" ? 1438 : 1437,
    strictPort: true,
    // Cargo replaces and holds the Tauri executable while compiling on Windows.
    // It is a build artifact, never a frontend source, so Vite must not watch it.
    watch: {
      ignored: ["**/src-tauri/target/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: {
    // dist/ also stores immutable build manifests and candidate artifacts.
    // Keep those records when Vite refreshes the frontend output.
    emptyOutDir: false,
    target: process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari13",
    minify: process.env.TAURI_ENV_DEBUG ? false : "esbuild",
    sourcemap: Boolean(process.env.TAURI_ENV_DEBUG),
  },
});
