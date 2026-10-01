import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    // Pages are split into their own JS chunks (React.lazy in App.jsx), but
    // CSS stays in one file loaded up front: several pages rely on styles that
    // another page's stylesheet defines (e.g. the shared .modal rules), and a
    // split stylesheet would only arrive once that other page was visited.
    cssCodeSplit: false,
  },
  // `npm test` (Vitest): component and unit tests under src/**/*.test.{js,jsx}
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.js",
    include: ["src/**/*.test.{js,jsx}"],
    css: false,
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    proxy: {
      "/auth": {
        target: "http://backend", // TODO: ofc its only for dev. 
        changeOrigin: true,
      },
      "/api": {
        target: "http://backend",
        changeOrigin: true,
      },
    },
  },
});
