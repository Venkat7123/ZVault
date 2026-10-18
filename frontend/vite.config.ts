import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The gateway serves the build from botsbank/dist (so the Dockerfile's `COPY botsbank` includes it).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../botsbank/dist",
    emptyOutDir: true,
    // Never inline assets as data: URIs: the gateway's CSP only allows files from itself.
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    // `npm run dev` talks to a gateway you can reach, e.g. through the SSH tunnel on :8000.
    proxy: {
      "/login": "http://127.0.0.1:8000",
      "/ask": "http://127.0.0.1:8000",
      "/logs": "http://127.0.0.1:8000",
      "/me": "http://127.0.0.1:8000",
      "/documents/scan": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
