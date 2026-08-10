import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
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
