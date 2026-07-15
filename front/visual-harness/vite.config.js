import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Standalone build for the visual harness; output goes to the session
// scratchpad, never to front/dist.
export default defineConfig({
    root: __dirname,
    base: "./",
    plugins: [react()],
    build: {
        outDir: "/tmp/claude-1000/-home-zi-netease/5f643d88-9ed8-4bff-8cc4-5e5f885347f7/scratchpad/harness-dist",
        emptyOutDir: true,
    },
});
