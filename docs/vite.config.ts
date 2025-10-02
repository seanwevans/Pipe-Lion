import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const repository = process.env.GITHUB_REPOSITORY;
const repositoryName = repository?.includes("/")
  ? repository.split("/")[1]
  : undefined;

// https://vite.dev/config/
export default defineConfig({
  base: repositoryName ? `/${repositoryName}/` : "/",
  plugins: [react()],
  test: {
    environment: "node",
    environmentMatchGlobs: [["src/**/*.test.tsx", "jsdom"]],
    setupFiles: "./src/test/setup.ts",
  },
});
