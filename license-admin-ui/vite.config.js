import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Standalone admin UI for the License Server.
// In dev we proxy /api and /health to the license server (default :8001) so the
// browser talks to a same-origin path and avoids CORS quirks. In production set
// VITE_LICENSE_API_URL to the license server origin (server already sends CORS *).
const LICENSE_SERVER = process.env.LICENSE_SERVER_URL || "http://localhost:8001";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: LICENSE_SERVER, changeOrigin: true },
      "/health": { target: LICENSE_SERVER, changeOrigin: true },
    },
  },
});
