import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "reynard_caido_bridge",
  name: "Reynard Caido Bridge",
  description: "Local HTTP bridge that exposes Caido Replay, HTTP history, and findings to Reynard.",
  version: "0.1.0",
  author: {
    name: "Reynard",
  },
  plugins: [
    {
      kind: "backend",
      id: "backend",
      name: "Bridge Backend",
      root: "packages/backend",
    },
  ],
});
