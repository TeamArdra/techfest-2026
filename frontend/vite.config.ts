import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backendPort = process.env.VITE_BACKEND_PORT || "8000";

// The dev server proxies API + WebSocket to the FastAPI backend,
// so `npm run dev` (on :5173) works against `aegis serve` with no CORS fuss.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: `http://localhost:${backendPort}`, changeOrigin: true },
      "/health": { target: `http://localhost:${backendPort}`, changeOrigin: true },
      "/ws": { target: `ws://localhost:${backendPort}`, ws: true },
    },
  },
  build: { outDir: "dist", sourcemap: false },
});
