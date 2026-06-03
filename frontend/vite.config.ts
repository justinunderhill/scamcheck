import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The frontend talks ONLY to our own backend. In dev, proxy /api to uvicorn so
// the browser never needs to know the backend port (and never calls Google /
// VirusTotal directly). In prod, VITE_API_BASE_URL points at the deployed API.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
