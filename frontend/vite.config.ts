
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api/telemetry/latest": {
        target: "http://127.0.0.1:8000",
        rewrite: () => "/api/demo/telemetry/latest",
      },

      "/api/processes/latest": {
        target: "http://127.0.0.1:8000",
        rewrite: () => "/api/demo/processes/latest",
      },

      "/api/alerts": {
        target: "http://127.0.0.1:8000",
        rewrite: () => "/api/demo/alerts",
      },
      "/api/dashboard": {
        target: "http://127.0.0.1:8000",
      },
      "/api/network/latest": {
        rewrite: () => "/api/demo/network/latest",
        target: "http://127.0.0.1:8000",
      },
    },
  },
});
