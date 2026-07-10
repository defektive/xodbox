import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// The admin UI is mounted under a configurable path prefix (ui_path) that is
// only known at runtime, so assets are emitted with relative URLs (base "./")
// and the router basename is injected by the Go server into index.html.
export default defineConfig({
  base: "./",
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: true,
  },
});
