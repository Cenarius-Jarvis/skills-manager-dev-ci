import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "repository-preview",
  plugins: [react()],
  build: { outDir: "../src-tauri/repository-preview-dist", emptyOutDir: true },
});
