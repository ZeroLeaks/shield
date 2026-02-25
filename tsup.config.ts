import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "providers/openai": "src/providers/openai.ts",
    "providers/anthropic": "src/providers/anthropic.ts",
    "providers/groq": "src/providers/groq.ts",
    "providers/ai-sdk": "src/providers/ai-sdk.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  splitting: false,
  clean: true,
  outDir: "dist",
  sourcemap: true,
});
