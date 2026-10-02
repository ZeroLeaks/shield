import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    local: "src/local.ts",
    server: "src/server/index.ts",
    "providers/openai": "src/providers/openai.ts",
    "providers/anthropic": "src/providers/anthropic.ts",
    "providers/groq": "src/providers/groq.ts",
    "providers/ai-sdk": "src/providers/ai-sdk.ts",
    "providers/google": "src/providers/google.ts",
    "providers/mistral": "src/providers/mistral.ts",
    "providers/langchain": "src/providers/langchain.ts",
    "providers/mcp": "src/providers/mcp.ts",
    "providers/openai-agents": "src/providers/openai-agents.ts",
    model: "src/model/index.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  // Entry points share chunks, so the classifier weights ship once per format
  // instead of once per entry point.
  splitting: true,
  clean: true,
  outDir: "dist",
  sourcemap: true,
  // ES2019 makes esbuild compile `??` and `?.` inline. With ES2020 they
  // survive to the CommonJS conversion, which turns them into closures.
  target: "es2019",
  esbuildOptions(options) {
    // Keeps the weights and other sources out of the source maps.
    options.sourcesContent = false;
  },
});
