# @zeroleaks/shield

Runtime prompt security for LLM applications. Harden system prompts, detect prompt injections, and sanitize model output to prevent leaks -- all in under 5ms.

Built and maintained by [ZeroLeaks](https://zeroleaks.ai).

## Requirements

- **Node.js** 18+ or **Bun** 1.0+
- **TypeScript** 5.0+ (optional, for type definitions)

Provider wrappers require the corresponding SDK as a peer dependency (all optional):
- `openai` >= 4.0.0
- `@anthropic-ai/sdk` >= 0.20.0
- `groq-sdk` >= 0.3.0
- `ai` >= 3.0.0 (Vercel AI SDK)

## Installation

```bash
npm install @zeroleaks/shield
# or
bun add @zeroleaks/shield
```

## Quick Start

### Standalone Functions

```typescript
import { harden, detect, sanitize } from "@zeroleaks/shield";

// 1. Harden a system prompt with security rules
const secured = harden("You are a helpful assistant.");

// 2. Detect injection in user input
const result = detect(userInput);
if (result.detected) {
  console.warn(`Injection detected: ${result.risk} risk`);
}

// 3. Sanitize model output to block leaked prompt fragments
const clean = sanitize(modelOutput, systemPrompt);
if (clean.leaked) {
  console.warn("Leak detected, using sanitized output");
  return clean.sanitized;
}
```

### OpenAI Provider Wrapper

```typescript
import OpenAI from "openai";
import { shieldOpenAI } from "@zeroleaks/shield/openai";

const client = shieldOpenAI(new OpenAI(), {
  systemPrompt: "You are a financial advisor...",
  onDetection: "block", // throws on injection (default)
});

const response = await client.chat.completions.create({
  model: "gpt-5.3-codex",
  messages: [
    { role: "system", content: "You are a financial advisor..." },
    { role: "user", content: userInput },
  ],
});
```

### Anthropic Provider Wrapper

```typescript
import Anthropic from "@anthropic-ai/sdk";
import { shieldAnthropic } from "@zeroleaks/shield/anthropic";

const client = shieldAnthropic(new Anthropic(), {
  systemPrompt: "You are a support agent...",
});

const response = await client.messages.create({
  model: "claude-sonnet-4-6",
  system: "You are a support agent...",
  messages: [{ role: "user", content: userInput }],
  max_tokens: 1024,
});
```

### Groq Provider Wrapper

```typescript
import Groq from "groq-sdk";
import { shieldGroq } from "@zeroleaks/shield/groq";

const client = shieldGroq(new Groq(), {
  systemPrompt: "You are a support agent...",
});

const response = await client.chat.completions.create({
  model: "openai/gpt-oss-120b",
  messages: [
    { role: "system", content: "You are a support agent..." },
    { role: "user", content: userInput },
  ],
});
```

### Vercel AI SDK

`shieldLanguageModelMiddleware` plugs into `wrapLanguageModel` and works with AI SDK 4, 5, and 6:

```typescript
import { generateText, wrapLanguageModel } from "ai";
import { openai } from "@ai-sdk/openai";
import { shieldLanguageModelMiddleware } from "@zeroleaks/shield/ai-sdk";

const model = wrapLanguageModel({
  model: openai("gpt-5.3-codex"),
  middleware: shieldLanguageModelMiddleware(),
});

const result = await generateText({
  model,
  system: "You are a helpful assistant.",
  prompt: userInput,
});
```

It hardens system messages, blocks injected user messages, and sanitizes the output of `generateText` and `streamText`. In a stream, everything that isn't text (tool calls, usage, the finish event) passes through untouched, except `raw` parts from `includeRawChunks`, which are dropped because they carry the unsanitized text. For the same reason, `generateText` drops `response.body` when it redacts something. With `throwOnLeak`, `generateText` throws `LeakDetectedError`, while `streamText` ends the stream with an `error` part carrying it: `onError` gets the error, and the stream finishes with `finishReason: "error"` and no token usage.

To run each step yourself, use `shieldMiddleware`:

```typescript
import { generateText } from "ai";
import { shieldMiddleware } from "@zeroleaks/shield/ai-sdk";

const shield = shieldMiddleware({ systemPrompt: "..." });

const result = await generateText({
  model: openai("gpt-5.3-codex"),
  ...shield.wrapParams({
    system: "You are a helpful assistant.",
    prompt: userInput,
  }),
});

const safeOutput = shield.sanitizeOutput(result.text);
```

`sanitizeOutput()` only sees the text you give it, so with `streamText` you have to collect the full output first.

## API Reference

### `harden(prompt, options?)`

Adds security rules to a system prompt as a bullet list. Returns the hardened string.

| Option | Type | Default | Description |
|---|---|---|---|
| `skipPersonaAnchor` | `boolean` | `false` | Skip persona-binding rule |
| `skipAntiExtraction` | `boolean` | `false` | Skip anti-extraction rules |
| `customRules` | `string[]` | `[]` | Additional rules to inject |
| `position` | `"prepend" \| "append"` | `"append"` | `"prepend"` puts the rules at the top. Otherwise they go right after the paragraph that sets the model's identity ("You are...", "Your role is..."), or near the top if there is none. |

### `detect(input, options?)`

Scans text for prompt injection patterns in 11 categories. Returns `{ detected, risk, matches }`. Input is normalized first (NFKC, homoglyphs, invisible characters, spaced-out letters, leetspeak, common typos), and only the first 8,192 characters are matched. `detectAsync(input, options?)` is the same but runs `secondaryDetector`.

| Option | Type | Default | Description |
|---|---|---|---|
| `threshold` | `"low" \| "medium" \| "high" \| "critical"` | `"medium"` | Minimum risk to flag |
| `normalization` | `DetectNormalizationOptions \| false` | all steps on | Turn individual normalization steps off, or pass `false` to disable. Custom patterns run against normalized, lowercased text with digits decoded as leetspeak. |
| `customPatterns` | `Array<{category, regex, risk}>` | `[]` | Custom detection patterns |
| `excludeCategories` | `string[]` | `[]` | Skip detection for these categories. Use `["social_engineering"]` to allow phrases like "for research purposes only" in legitimate contexts. |
| `allowPhrases` | `string[]` | `[]` | Whitelist phrases (case-insensitive). If input contains one, detection is suppressed. Use sparingly for known-benign strings. |
| `secondaryDetector` | `(input, result) => Promise<DetectResult \| null>` | - | Optional async verifier. When detection fires, can override with `{ detected: false }` (e.g. LLM verification). Use `detectAsync` for this. |
| `maxInputLength` | `number` | `1048576` | Truncate input beyond this |

### `sanitize(output, systemPrompt, options?)`

Checks model output for leaked system prompt fragments using n-gram matching. Returns `{ leaked, confidence, fragments, sanitized }`.

`sanitizeObject(obj, systemPrompt, options?)` does the same for every string in a nested object (e.g. tool call arguments) and returns `{ result, hadLeak }`. Both take these options:

| Option | Type | Default | Description |
|---|---|---|---|
| `ngramSize` | `number` | `4` | N-gram window size |
| `threshold` | `number` | `0.7` | Confidence threshold for leak |
| `wordOverlapThreshold` | `number` | `0.25` | Jaccard word overlap for paraphrased leaks |
| `redactionText` | `string` | `"[REDACTED]"` | Replacement text |
| `detectOnly` | `boolean` | `false` | Skip redaction, only detect |

### Provider options (OpenAI, Anthropic, Groq, AI SDK)

| Option | Type | Default | Description |
|---|---|---|---|
| `systemPrompt` | `string` | derived from params | System prompt for sanitization. When omitted, derived from the first system message or `params.system`. |
| `streamingSanitize` | `"buffer" \| "chunked" \| "passthrough"` | `"buffer"` | `"buffer"`: full buffer then sanitize. `"chunked"`: 8KB chunks, lower memory for long streams. `"passthrough"`: skip sanitization. |
| `streamingChunkSize` | `number` | `8192` | Chunk size for `"chunked"` mode. |
| `throwOnLeak` | `boolean` | `false` | When `true`, throw `LeakDetectedError` instead of redacting leaked content. |
| `onDetection` | `"block" \| "warn"` | `"block"` | `"block"` throws on injection; `"warn"` only invokes `onInjectionDetected`. |

**What gets scanned:** The OpenAI, Anthropic, and Groq wrappers wrap only the `create` method and scan only `role: "user"` messages. Tool results and retrieved documents are not scanned; call `detect()` on them yourself.

**Wrapped client type:** The OpenAI, Anthropic, and Groq wrappers return a shallow copy of your client, typed as your client, and some of what that type promises is `undefined` at runtime. The other methods next to `create` are missing, such as `chat.completions.parse()` or `messages.stream()`, and so are methods on the client itself, such as `withOptions()`. `create()` returns a plain Promise, so `withResponse()` and `asResponse()` are missing. A sanitized stream is a plain async iterable without `controller`, `toReadableStream()`, or `tee()`; read it with `for await`.

**Multi-part messages:** OpenAI and Groq support `content` as `string | ContentPart[]` (e.g. text + images). Shield extracts text from all parts for injection detection and hardening.

**Streaming:** In the OpenAI, Anthropic, and Groq wrappers, `"buffer"` reads the whole stream, sanitizes it, then re-emits it as text-only chunks; tool call deltas, finish reasons, and usage are dropped. `"chunked"` does the same 8KB at a time. Each chunk is scanned with the 64 characters sent before it, and its last 64 characters are held back and scanned again with the next one, so a leak across a boundary is caught from either side and no text is repeated. `"passthrough"` returns the original stream with no sanitization. If the provider's stream fails partway through, its error reaches your code. The AI SDK middleware uses the same modes but keeps every non-text stream part.

## Error Handling

Shield exports typed errors for structured handling:

```typescript
import { ShieldError, InjectionDetectedError, LeakDetectedError } from "@zeroleaks/shield";

try {
  const client = shieldOpenAI(openai, { systemPrompt: "...", throwOnLeak: true });
  await client.chat.completions.create({ ... });
} catch (error) {
  if (error instanceof InjectionDetectedError) {
    console.log(error.risk, error.categories);
  }
  if (error instanceof LeakDetectedError) {
    console.log(error.confidence, error.fragmentCount);
  }
}
```

## Threat Model & Limitations

Shield provides heuristic-based, real-time protection. It is designed for speed (see [benchmarks](#benchmarks)) and complements -- but does not replace -- thorough security testing with tools like [ZeroLeaks](https://zeroleaks.ai).

**Defense in depth:** Use Shield as one layer of protection. Combine with input validation, output filtering, rate limiting, and periodic red-team scanning. Do not rely on Shield as the sole security control for high-risk applications.

**What it catches:**
- Direct instruction overrides and jailbreaks
- Role hijacking and persona injection
- Prompt extraction attempts
- Authority exploitation (fake system/admin messages)
- Tool hijacking patterns (curl exfil, SSRF, RCE)
- Indirect injection (hidden instructions in documents)
- Encoding attacks (base64, unicode, reversed text)
- Output leakage of system prompt fragments

**What it does not catch:**
- Novel, zero-day attack patterns not in the pattern library
- Semantic attacks that avoid keyword-based detection
- Complex multi-turn escalation (use ZeroLeaks scanning for this)
- Attacks in non-English languages (partial coverage)
- Injections in tool results or documents that you do not pass to `detect()`
- An agent misusing tools it is allowed to call. Shield does not know your agent's tools or permissions; [ZeroLeaks agent scans](https://zeroleaks.ai/docs/sdk) test for that.

## Benchmarks

Run performance benchmarks to verify latency claims:

```bash
bun run benchmark
```

Typical results on modern hardware: `detect` <2ms, `harden` <0.5ms, `sanitize` <3ms for inputs up to ~8KB.

## Integration Tests

Run integration tests against real provider APIs. Set the corresponding API key for each provider you want to test:

| Provider | Env var | Required for |
|---|---|---|
| OpenAI | `OPENAI_API_KEY` | `shieldOpenAI` tests |
| Anthropic | `ANTHROPIC_API_KEY` | `shieldAnthropic` tests |
| Groq | `GROQ_API_KEY` | `shieldGroq` tests |

AI SDK integration tests use the OpenAI provider and require `OPENAI_API_KEY`.

```bash
bun run test:integration
```

Tests skip gracefully when the required API key is not configured.

## License

MIT
