# @zeroleaks/shield

Prompt injection and jailbreak detection for agents. `await detect(text)` checks user messages, retrieved documents, and tool results with the hosted Shield API. Provider wrappers apply the check before a model call and check its output for secrets, personal data, and prompt leaks.

Built and maintained by [ZeroLeaks](https://zeroleaks.ai). See the [migration guide](MIGRATION.md) when upgrading from synchronous `detect()`.

## Install

```bash
bun add @zeroleaks/shield
# or: npm install @zeroleaks/shield
```

The hosted client uses `fetch` and supports Node.js 18+, Bun, Deno, Cloudflare Workers, and browsers. Keep dashboard API keys in your server or Worker environment. Provider SDKs and local transformer inference are optional peer dependencies.

For optional local model inference, use a current security-patched Node.js 22 release (22.23.3 or later) or Bun 1.4.2 or later. The [local model installation guide](https://zeroleaks.ai/docs/shield-sdk/model#install) pins Transformers 3.8.1 and shows the consumer application override for Sharp 0.35.4, which includes fixes absent from Transformers' default Sharp 0.34.x dependency. The default SDK install does not include either package.

## Quick start

Create a `zl_live_` key in the ZeroLeaks dashboard. All hosted models require a key, including the free model. Set `ZEROLEAKS_API_KEY` on your server, or pass `apiKey` explicitly:

```typescript
import { detect } from "@zeroleaks/shield";

const result = await detect(untrustedText, {
  apiKey: process.env.ZEROLEAKS_API_KEY,
});

if (result.detected) {
  throw new Error("The input was blocked.");
}
```

`detected` and `flagged` carry the same verdict. `score` is the effective binary score; `shield.model_score` is the model's raw score and `shield.rules` says whether a rule also flagged the text. The single `prompt_injection` category includes jailbreaks. It does not provide a separate jailbreak probability.

| Model | Access |
|---|---|
| `shield` (default) | Free, with a dashboard key and research consent |
| `shield-base` | Paid |
| `shield-large` | Paid |
| `shield-tiered` | Paid |

Choose a model with `detect(text, { model: "shield-large" })`. Free access requires the dashboard research consent flow. Paid requests are excluded from research retention, including when a paid account selects `shield`.

## Protect a model call

Reuse a hosted detector and pass its options to a provider wrapper. The wrapper blocks flagged user messages and tool results before calling the model:

```typescript
import OpenAI from "openai";
import { createHostedDetector } from "@zeroleaks/shield";
import { shieldOpenAI } from "@zeroleaks/shield/openai";

const shield = createHostedDetector({ model: "shield" });
const client = shieldOpenAI(new OpenAI(), {
  detect: shield.options(),
  canary: true,
});

const response = await client.chat.completions.create({
  model: "your-model",
  messages: [
    { role: "system", content: "You are a support agent for Acme." },
    { role: "user", content: userInput },
  ],
});
```

For Vercel AI SDK:

```typescript
import { generateText, wrapLanguageModel } from "ai";
import { openai } from "@ai-sdk/openai";
import { createHostedDetector } from "@zeroleaks/shield";
import { shieldLanguageModelMiddleware } from "@zeroleaks/shield/ai-sdk";

const shield = createHostedDetector();
const model = wrapLanguageModel({
  model: openai("your-model"),
  middleware: shieldLanguageModelMiddleware({ detect: shield.options() }),
});
const result = await generateText({ model, prompt: userInput });
```

Pass `detect: shield.options()` to the other wrappers in the same way. Omitting it preserves the wrappers' existing local detection behavior. The AI SDK middleware waits for detection before the model call. The legacy `shieldMiddleware()` helper provides `await wrapParamsAsync(params)` for hosted detection; its synchronous `wrapParams()` accepts only local synchronous checks.

## AI SDK inspection tool

Shield 2.1.2 adds an inspection tool for AI SDK 5, 6, and 7:

```typescript
import { shieldCheck } from "@zeroleaks/shield/ai-sdk/tools";

const check = shieldCheck(); // Local; no network or API key.
const result = await check.execute(
  { text: "The document's complete original text.", source: "document" },
  {}
);
if (result.detected) {
  throw new Error("The document was blocked.");
}
```

Use `tools: { shieldCheck: shieldCheck() }` with `generateText` or `streamText` for model-invoked inspection. Pair it with `shieldLanguageModelMiddleware` for enforced checks before model calls: the model chooses whether to call the tool and which text to submit. A negative detection is not a guarantee of safety or permission to act. Tool execution errors become AI SDK `tool-error` parts; application code must decide whether the agent can continue.

Configure local checks with `shieldCheck({ detect: { sensitivity: "strict" } })`, or opt into hosted checks with `shieldCheck({ hosted: { apiKey, model: "shield" } })`. Hosted checks always require complete coverage and throw on missing or truncated coverage. Local checks reject oversized input instead of silently truncating it. The executor accepts `{ abortSignal }` as its second argument.

The new subpath requires `ai` 5 or later; AI SDK 7 requires Node.js 22+. Install `ai` and its `zod` peer alongside Shield. Other entry points still work without `ai` installed, and middleware retains SDK 4 support. See the [complete AI SDK tool guide](https://zeroleaks.ai/docs/shield-sdk/providers/ai-sdk-tools) for a runnable model example, result fields, access requirements, and limitations.

## Request options

| Option | Default | Purpose |
|---|---|---|
| `apiKey` | Server `ZEROLEAKS_API_KEY` | Dashboard key for the hosted service |
| `model` | `shield` | One of the four model IDs above |
| `baseURL` | `https://api.zeroleaks.ai/v1` | OpenAI-compatible base URL, including `/v1` |
| `endpoint` | Derived from `baseURL` | Full moderation URL; use instead of `baseURL` |
| `timeoutMs` | `30000` | Timeout for the request and response body |
| `signal` | — | `AbortSignal` for cancellation |
| `requireFullCoverage` | `false` | Reject results with partial or missing coverage metadata |
| `fetch` | Global `fetch` | Custom transport for your runtime |

Long documents can exceed a model's window budget. Inspect `result.shield.coverage`: `truncated` indicates partial coverage, while `windows` and `max_windows` describe the scan. A clean verdict with partial coverage says nothing about unscanned text. Use `requireFullCoverage: true` when the application requires every window to be checked.

Authentication failures, service failures, invalid responses, timeouts, and cancellation reject with `ShieldAPIError`. They never produce a clean verdict. Error messages contain no input, key, or server response body. The client does not retry or follow redirects.

## Self-hosting and local checks

Point the same hosted client at an OpenAI-compatible moderation endpoint you operate:

```typescript
const shield = createHostedDetector({
  baseURL: "http://localhost:8787/v1",
  // apiKey: "your-self-hosted-key", // if your endpoint requires one
});
const result = await shield.detect(text, { signal: abortController.signal });
```

Custom endpoints require HTTPS except for loopback HTTP. They do not inherit `ZEROLEAKS_API_KEY`; pass any self-hosted key explicitly. The package's `/server` module provides the private inference service; an OpenAI-compatible gateway must expose its results as `/v1/moderations` for this client.

Use explicit local imports to keep detection in your process:

```typescript
import { detect, detectAsync } from "@zeroleaks/shield/local";
import { createModelDetector } from "@zeroleaks/shield/model";

const rulesResult = detect(text, { classifier: false });
const model = createModelDetector({ localPath: "/models/shield" });
const modelResult = await detectAsync(text, model.options());
```

`/local` preserves the synchronous rules and bundled classifier, normalization, decoded-payload checks, and conversation helpers. `/model` provides optional transformer inference and requires `@huggingface/transformers`. A model configured by name may download weights on first use; supply `localPath` for an offline deployment. These imports make no calls to the hosted Shield API.

Output guards stay local:

```typescript
import { harden, sanitize, scanOutputText } from "@zeroleaks/shield";

const system = harden("You are a support agent for Acme.");
const clean = sanitize(modelOutput, system);
const { redacted, findings } = scanOutputText(clean.sanitized, { pii: true });
```

## Benchmarks

The [archived benchmark documentation](https://zeroleaks.ai/docs/shield-sdk/benchmarks) describes earlier local evaluations and their limitations; it does not measure the current hosted tiers. Local rules, local transformer models, and hosted model tiers are distinct configurations; results should identify the exact configuration and artifact tested.

## Agents

**Tool results.** The wrappers scan tool and function results for injection by default (`scanToolResults`). Without a wrapper, call `await detect()` on each result before it goes back to the model.

**MCP servers.** Wrap your MCP client: tools with instructions hidden in their descriptions or schemas are left out of `listTools()`, and what tools, resources, and prompts return is checked for injection:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { createHostedDetector } from "@zeroleaks/shield";
import { shieldMcpClient } from "@zeroleaks/shield/mcp";

const shield = createHostedDetector();
const client = shieldMcpClient(new Client({ name: "agent", version: "1.0.0" }), {
  detect: shield.options(),
});
await client.connect(transport);
const { tools } = await client.listTools(); // poisoned tools dropped
```

The wrapper also pins each tool's definition and drops a tool whose definition later changes, refuses calls to flagged tools, and blocks tool calls whose arguments carry a credential or an exfiltration link. Without the wrapper, `await scanToolsAsync(tools, shield.options())` checks definitions with the hosted detector; `scanTools(tools)` performs local synchronous checks. Both accept MCP, OpenAI, Anthropic, or AI SDK tool definitions, and `pinTools()` pins them.

**Tool calls.** Detection misses some injections, so limit what the agent can do after it read content you can't trust. `createToolPolicy()` refuses undeclared tools, arguments that don't match the tool's schema, tools on a deny list, and calls past a limit; once the session has read untrusted content, it refuses tools that send data out unless the destination is allowed or you approve:

```typescript
import { createToolPolicy } from "@zeroleaks/shield";

const policy = createToolPolicy({
  tools,
  rules: {
    read_inbox: { labels: ["untrusted", "private"] },
    send_email: { labels: ["sink"], destinations: { arguments: ["to"], allow: ["acme.com"] } },
  },
});
const client = shieldMcpClient(mcp, { policy }); // or policy.check(call) yourself
```

**Untrusted content.** Mark documents and tool output so the model can tell them apart from instructions ([spotlighting](https://arxiv.org/abs/2403.14720)):

```typescript
import { harden, spotlight } from "@zeroleaks/shield";

const system = harden("You summarize emails.", { spotlight: { label: "email" } });
const user = `Summarize this:\n${spotlight(emailBody, { label: "email" })}`;
```

**Canaries.** A random token in the system prompt that has no reason to appear in output. If it does, the prompt leaked, even when the model paraphrased or translated the rest. Pass `canary: true` to a wrapper, or use `createCanary()`, `harden(prompt, { canary })`, and `findCanary()`.

**Conversations.** The local `detectConversation(messages)` helper from `@zeroleaks/shield/local` scans every user and tool message and the latest user messages joined together, so an instruction split across turns is caught.

## Provider wrappers

Every wrapper hardens the system prompt, runs its configured detector on user messages and tool results, and runs `sanitize()` and `scanOutputText()` on the response, including tool-call arguments. Injections are blocked by default: the wrapper throws `InjectionDetectedError` before the request is sent.

| Provider | Import | Wraps |
|---|---|---|
| OpenAI | `shieldOpenAI` from `@zeroleaks/shield/openai` | `chat.completions.create`, `responses.create` |
| Anthropic | `shieldAnthropic` from `@zeroleaks/shield/anthropic` | `messages.create` |
| Groq | `shieldGroq` from `@zeroleaks/shield/groq` | `chat.completions.create` |
| Vercel AI SDK 4, 5, 6, 7 | `shieldLanguageModelMiddleware` from `@zeroleaks/shield/ai-sdk` | `generateText`, `streamText` via `wrapLanguageModel` |
| Google Gen AI | `shieldGoogleGenAI` from `@zeroleaks/shield/google` | `models.generateContent`, `models.generateContentStream`, and chats |
| Mistral | `shieldMistral` from `@zeroleaks/shield/mistral` | `chat.complete`, `chat.stream` |
| LangChain.js | `shieldChatModel`, `ShieldCallbackHandler` from `@zeroleaks/shield/langchain` | `invoke`, `stream`, `batch`, and runnables derived from the model |
| MCP client | `shieldMcpClient` from `@zeroleaks/shield/mcp` | `listTools`, `callTool`, `readResource`, `getPrompt` (checks what the server returns; there is no model output) |
| OpenAI Agents SDK | `shieldInputGuardrail`, `shieldOutputGuardrail`, `shieldToolInputGuardrail`, `shieldToolOutputGuardrail`, `shieldToolPolicyGuardrail` from `@zeroleaks/shield/openai-agents` | Agent input and output guardrails and function tool guardrails (they stop a run or a tool call; they can't redact) |

```typescript
import Anthropic from "@anthropic-ai/sdk";
import { createHostedDetector } from "@zeroleaks/shield";
import { shieldAnthropic } from "@zeroleaks/shield/anthropic";

const shield = createHostedDetector();
const client = shieldAnthropic(new Anthropic(), {
  detect: shield.options(),
  output: { pii: true, exfiltration: { allowedDomains: ["docs.acme.com"] } },
  onInjectionDetected: (result, source) => log.warn(source, result.matches),
});
```

### Wrapper options

| Option | Default | Description |
|---|---|---|
| `systemPrompt` | from the request | The prompt `sanitize()` compares output with |
| `harden` | `{}` | `harden()` options, or `false` |
| `detect` | Local checks | Pass `shield.options()` for hosted detection, local detection options, or `false` |
| `scanToolResults` | Uses `detect` options | Separate detection options, or `false`. `detect: false` does not turn it off. |
| `parallelDetection` | `false` | Run `escalate` at the same time as the model call instead of before it; the response is held until its verdict is in, and the call is still billed when it blocks. AI SDK middleware always waits before calling the model |
| `onDetection` | `"block"` | `"block"` throws `InjectionDetectedError`; `"warn"` only calls `onInjectionDetected` |
| `sanitize` | `{}` | `sanitize()` options, or `false` |
| `output` | secrets and exfiltration on | `scanOutputText()` options, or `false` |
| `canary` | off | `true` creates a canary per wrapper; a string uses yours |
| `throwOnLeak` | `false` | Throw `LeakDetectedError` instead of redacting a prompt leak or canary |
| `blockOnOutputFindings` | `false` | Throw `OutputBlockedError` instead of redacting a high or critical output finding |
| `streamingSanitize` | `"buffer"` | `"buffer"` reads the whole stream, then replays it with text redacted; `"chunked"` works in 8KB chunks for lower latency and memory; `"passthrough"` returns the stream untouched |
| `onInjectionDetected`, `onLeakDetected`, `onOutputFindings` | | Callbacks for logging and alerting |

**Streaming.** In `"buffer"` mode the wrapper reads the whole stream before returning, then replays the provider's chunks with only redacted text rewritten, so tool calls, usage, and finish events are kept. `"chunked"` emits text as it goes, 8KB at a time, scans each chunk with the end of the previous one so a leak across a boundary is caught, and also replays the provider's other chunks and events. The OpenAI Responses API treats `"chunked"` as `"buffer"`.

**Wrapped client type.** The OpenAI, Anthropic, and Groq wrappers return a proxy of your client, typed as your client, with only `create` replaced. Other methods, such as `chat.completions.parse()` or `messages.stream()`, still work but are not guarded, `withOptions()` returns a client that isn't wrapped, and `create()` returns a plain Promise without `withResponse()`.

## API

| Function | Returns | Docs |
|---|---|---|
| `await detect(input, options?)` | Hosted result: `{ detected, flagged, risk, matches, score, model, categories, category_scores, shield }` | [Hosted API](https://zeroleaks.ai/docs/shield-api/quickstart) |
| `detectAsync(input, options?)` from `/local` | Local detection, with an optional `secondaryDetector` to confirm detections and `escalate` to send uncertain input to a slower model | [detect](https://zeroleaks.ai/docs/shield-sdk/detect#options) |
| `detectConversation(messages, options?)` from `/local` | Combined result, `flagged`, `splitAcrossTurns` | [detect](https://zeroleaks.ai/docs/shield-sdk/detect#conversations) |
| `scanTools(tools, options?)` | `{ flagged, tools }` | [scanTools](https://zeroleaks.ai/docs/shield-sdk/tools) |
| `pinTools(tools, pins?)` | Pins for `scanTools(tools, { pins })` | [scanTools](https://zeroleaks.ai/docs/shield-sdk/tools#pinning) |
| `createToolPolicy(options?)` | A policy with `check(call)` and `recordResult(name)` | [Tool policy](https://zeroleaks.ai/docs/shield-sdk/policy) |
| `createModelDetector(options?)` from `@zeroleaks/shield/model` | An `escalate` detector | [Model tier](https://zeroleaks.ai/docs/shield-sdk/model) |
| `harden(prompt, options?)` | Hardened prompt | [harden](https://zeroleaks.ai/docs/shield-sdk/harden) |
| `spotlight(content, options?)` | Marked content | [harden](https://zeroleaks.ai/docs/shield-sdk/harden#spotlight) |
| `sanitize(output, systemPrompt, options?)` | `{ leaked, confidence, fragments, sanitized }` | [sanitize](https://zeroleaks.ai/docs/shield-sdk/sanitize) |
| `sanitizeObject(obj, systemPrompt, options?)` | `{ result, hadLeak }` | [sanitize](https://zeroleaks.ai/docs/shield-sdk/sanitize) |
| `scanOutputText(text, options?)` | `{ findings, redacted, blocked }` | [output](https://zeroleaks.ai/docs/shield-sdk/output) |
| `detectSecrets`, `detectPII`, `detectExfiltration` | Findings | [output](https://zeroleaks.ai/docs/shield-sdk/output) |
| `createCanary`, `findCanary` | Token, findings | [output](https://zeroleaks.ai/docs/shield-sdk/output#canary-tokens) |

The explicit local `detect()` options include `sensitivity` (`"strict"`, `"balanced"`, or `"permissive"`), `threshold` (lowest risk reported, default `"medium"`), `classifier` (`{ threshold, highThreshold }` or `false`), `denyPhrases` (always flagged), `allowPhrases` (removed from the input before scanning), `customPatterns`, and `includeCategories` or `excludeCategories`. See [Customizing detection](https://zeroleaks.ai/docs/shield-sdk/customize).

### Errors

All errors extend `ShieldError` and carry a `code`.

| Error | Code | Fields |
|---|---|---|
| `ShieldAPIError` | `SHIELD_*` | `status` when the service returned an HTTP error; no response body |
| `InjectionDetectedError` | `INJECTION_DETECTED` | `risk`, `categories`, `source` (`"user"` or `"tool"`) |
| `LeakDetectedError` | `LEAK_DETECTED` | `confidence`, `fragmentCount` |
| `OutputBlockedError` | `OUTPUT_BLOCKED` | `findings` (type, kind, and severity only, never the matched text) |
| `ToolPolicyError` | `TOOL_POLICY_VIOLATION` | `tool`, `reason`, `violations` (paths and keywords, never argument values) |

## Threat model and limitations

Shield is one layer. Pair it with least-privilege tool permissions, human approval for destructive actions, and egress controls, which limit what a successful injection can do, and test the agent itself with [ZeroLeaks scans](https://zeroleaks.ai/docs/sdk). `createToolPolicy()` enforces part of this in your process, but only for the tools and labels you give it.

It does not catch:

- An agent misusing a permission it legitimately has. A polite request to refund the wrong account may contain nothing that looks like an injection.
- Carefully written instructions that read like ordinary content. A detector can miss an attack even when its score is low.
- Content it doesn't see: images, PDFs, audio, and text you send to the model without a wrapper or a `detect()` call.
- Leaks of the system prompt that are heavily reworded or translated, unless a canary is planted.

Shield can flag benign text. Evaluate it on your own workflows before selecting a model and blocking policy. Local detection exposes thresholds and allow phrases; hosted detection uses the service's fixed classification threshold. With `parallelDetection: true`, integrations that support it may send text to a model before detection finishes; provider-hosted tools can execute during that call. Keep the default sequential detection when the verdict must precede those effects.

## Custom model artifacts

To use your own transformer classifier, configure its model and tokenizer through [local model detection](https://zeroleaks.ai/docs/shield-sdk/model). Validate exported artifacts against the runtime and tokenizer used in production.

## License

The SDK code is MIT licensed. Model weights and hosted service access have their own terms.
