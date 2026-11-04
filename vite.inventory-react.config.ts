import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "inventory-react-preview",
  plugins: [react()],
  build: {
    outDir: "../src-tauri/inventory-react-dist",
    emptyOutDir: true,
  },
});
