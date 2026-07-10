import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// The admin UI is mounted under a configurable path prefix (ui_path) that is
// only known at runtime. The production build emits ABSOLUTE asset URLs under
// a placeholder base ("/__XODBOX_BASE__/") that the Go server rewrites to the
// configured ui_path when serving index.html. Absolute (not relative "./")
// URLs are required so deep SPA routes like /admin/requests/3 still resolve
// their assets to /admin/assets/... rather than /admin/requests/assets/....
// The dev server stays at "/" for a normal `npm run dev` experience.
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/__XODBOX_BASE__/" : "/",
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
}));
