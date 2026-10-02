#!/usr/bin/env bun
/**
 * Output detector benchmarks on realistic benign LLM answers.
 * Run with: bun run scripts/bench-output.ts
 */

import {
  detectExfiltration,
  detectPII,
  detectSecrets,
  findCanary,
  scanOutputText,
} from "../src/output/index";

const ANSWER = `## Calling the Responses API from Node

Install the SDK with \`npm install openai\` (version 5.x) and export your key as
\`OPENAI_API_KEY\` before running anything. Never hard-code keys; read them from the
environment or a secrets manager instead.

\`\`\`ts
import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function summarize(text: string): Promise<string> {
  const response = await client.responses.create({
    model: "gpt-5-mini",
    input: [{ role: "user", content: \`Summarize: \${text}\` }],
    max_output_tokens: 512,
  });
  return response.output_text;
}
\`\`\`

A few things to watch:

1. **Rate limits.** Retry 429s with exponential backoff (start at 500 ms, cap at 30 s).
2. **Timeouts.** The default is 10 minutes; pass \`timeout: 20_000\` for interactive paths.
3. **Streaming.** Use \`client.responses.stream()\` and read \`response.output_text.delta\` events.

| Model | Context window | Input price (per 1M tokens) |
|---|---|---|
| gpt-5 | 400k | $1.25 |
| gpt-5-mini | 400k | $0.25 |

See the [API reference](https://platform.openai.com/docs/api-reference/responses) and the
[error codes guide](https://platform.openai.com/docs/guides/error-codes). For a
self-hosted proxy, point \`baseURL\` at \`http://localhost:8080/v1\`.

Commit \`3f9a8b7c\` (v1.4.2, released 2025-03-14) fixed the retry bug; the request id
format is \`req_7d2c0a9e4b\`. Questions go to support@example.com.

If you deploy behind Cloudflare Workers, keep the key in a secret binding
(\`wrangler secret put OPENAI_API_KEY\`) rather than in \`wrangler.toml\`, and
rotate it from the [dashboard](https://platform.openai.com/api-keys) if it ever
shows up in logs.
`;

const ANSWER_2KB = ANSWER.repeat(2).slice(0, 2048);
const ANSWER_50KB = ANSWER.repeat(Math.ceil(51_200 / ANSWER.length)).slice(
  0,
  51_200
);
const CANARY = "ZL-CANARY-7f3a9c2e41b0d6a8";

interface Timing {
  /** Wall-clock µs per call. */
  wall: number;
  /** Process CPU µs per call (less sensitive to other load on the machine). */
  cpu: number;
}

function measure(fn: () => unknown, iterations: number): Timing {
  for (let i = 0; i < Math.max(50, iterations / 10); i++) {
    fn();
  }
  const cpuStart = process.cpuUsage();
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  const wall = ((performance.now() - start) * 1000) / iterations;
  const cpu = process.cpuUsage(cpuStart);
  return { wall, cpu: (cpu.user + cpu.system) / iterations };
}

/** A plain charCodeAt loop over the text: a yardstick for this machine's speed. */
function baseline(text: string): number {
  let sum = 0;
  for (let i = 0; i < text.length; i++) {
    sum += text.charCodeAt(i);
  }
  return sum;
}

const detectors: [string, (text: string) => unknown][] = [
  ["baseline charCodeAt loop", (t) => baseline(t)],
  ["detectSecrets", (t) => detectSecrets(t)],
  ["detectPII (default kinds)", (t) => detectPII(t)],
  ["detectExfiltration", (t) => detectExfiltration(t)],
  ["findCanary", (t) => findCanary(t, CANARY)],
  ["scanOutputText (defaults)", (t) => scanOutputText(t)],
  [
    "scanOutputText (all + canary)",
    (t) => scanOutputText(t, { pii: true, canary: CANARY }),
  ],
];

const [iterations2kb, iterations50kb] = process.argv.includes("--quick")
  ? [2000, 50]
  : [10_000, 300];

console.log("Shield output detector benchmarks\n");
for (const [label, text, iterations] of [
  ["2 KB answer", ANSWER_2KB, iterations2kb],
  ["50 KB answer", ANSWER_50KB, iterations50kb],
] as const) {
  console.log(`${label} (${text.length} chars, ${iterations} iterations)`);
  console.log(
    `  ${"".padEnd(32)} ${"wall µs/op".padStart(12)} ${"cpu µs/op".padStart(12)}`
  );
  for (const [name, fn] of detectors) {
    const { wall, cpu } = measure(() => fn(text), iterations);
    console.log(
      `  ${name.padEnd(32)} ${wall.toFixed(2).padStart(12)} ${cpu.toFixed(2).padStart(12)}`
    );
  }
  console.log("");
}
console.log("Target: < 100 µs/op for all detectors on the 2 KB answer");
