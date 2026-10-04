/* global process */
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Development server only (`npm run dev`): /auth and /api go to the backend.
// Inside docker-compose the backend answers as http://backend; running the
// backend on the same machine instead, start Vite with
//   VITE_BACKEND_URL=http://127.0.0.1:8000 npm run dev
// The production build is served by the backend itself (same origin), so
// none of this applies there.
const BACKEND = process.env.VITE_BACKEND_URL || "http://backend";

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
      "/auth": { target: BACKEND, changeOrigin: true },
      "/api": { target: BACKEND, changeOrigin: true },
    },
  },
});
