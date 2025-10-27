import react from "@vitejs/plugin-react";
import { defineConfig, type UserConfig } from "vite";
import type { UserConfig as VitestUserConfig } from "vitest/config";

const repository = process.env.GITHUB_REPOSITORY;
const repositoryName = repository?.includes("/")
  ? repository.split("/")[1]
  : undefined;

type ViteWithVitestConfig = UserConfig & {
  test?: VitestUserConfig["test"];
};

const config: ViteWithVitestConfig = {
  base: repositoryName ? `/${repositoryName}/` : "/",
  plugins: [react()],
  test: {
    environment: "node",
    environmentMatchGlobs: [["src/**/*.test.tsx", "jsdom"]],
    setupFiles: "./src/test/setup.ts",
  },
};

// https://vite.dev/config/
export default defineConfig(config);
