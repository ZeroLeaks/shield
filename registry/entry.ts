export const shieldRegistryEntry = {
  slug: "zeroleaks-shield",
  name: "ZeroLeaks Shield",
  description:
    "Prompt injection and jailbreak detection for user messages, retrieved documents, web pages, and tool results. Inspect text with shieldCheck locally without an API key, or opt into the hosted Shield API. Pair it with Shield language model middleware to block detected injections before model calls.",
  packageName: "@zeroleaks/shield",
  tags: ["security", "guardrails", "prompt-injection", "jailbreak"],
  installCommand: {
    pnpm: "pnpm add @zeroleaks/shield ai zod",
    npm: "npm install @zeroleaks/shield ai zod",
    yarn: "yarn add @zeroleaks/shield ai zod",
    bun: "bun add @zeroleaks/shield ai zod",
  },
  codeExample: `import { gateway, generateText, isStepCount, wrapLanguageModel } from 'ai';
import { shieldLanguageModelMiddleware } from '@zeroleaks/shield/ai-sdk';
import { shieldCheck } from '@zeroleaks/shield/ai-sdk/tools';

const model = wrapLanguageModel({
  model: gateway('openai/gpt-5-mini'),
  middleware: shieldLanguageModelMiddleware(),
});

const { text } = await generateText({
  model,
  tools: { shieldCheck: shieldCheck() },
  stopWhen: isStepCount(3),
  prompt:
    'Check this support note with shieldCheck, then summarize it: Our support desk opens at nine on Monday.',
});

console.info(text);`,
  docsUrl: "https://zeroleaks.ai/docs/shield-sdk/providers/ai-sdk-tools",
  apiKeyUrl: "https://zeroleaks.ai/dashboard/shield",
  websiteUrl: "https://zeroleaks.ai/shield",
  npmUrl: "https://www.npmjs.com/package/@zeroleaks/shield",
};
