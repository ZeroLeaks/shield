# Hosted detection migration

The root `detect()` function is now asynchronous and uses the Shield API. Local inference remains available through explicit imports. Existing provider wrappers keep their local behavior until you pass a hosted detector.

## Direct detection

Before:

```typescript
import { detect } from "@zeroleaks/shield";
const result = detect(text);
```

Hosted detection:

```typescript
import { detect } from "@zeroleaks/shield";
const result = await detect(text, {
  apiKey: process.env.ZEROLEAKS_API_KEY,
  model: "shield",
});
```

All hosted models require a dashboard key. `shield` is free with research consent; `shield-base`, `shield-large`, and `shield-tiered` require paid access. `ZEROLEAKS_API_KEY` is read automatically on servers when `apiKey` is omitted. A Worker can pass `env.ZEROLEAKS_API_KEY` explicitly.

`detected`, `risk`, `matches`, and `score` remain available. Hosted results also expose the moderation response's `flagged`, `categories`, `category_scores`, and `shield` metadata. The binary category covers both prompt injection and jailbreaks. Network, authorization, malformed-response, and timeout errors reject with `ShieldAPIError`; handle them as failed checks instead of treating the input as safe.

To keep the synchronous local implementation:

```typescript
import { detect } from "@zeroleaks/shield/local";
const result = detect(text, { classifier: false });
```

The root `detectLocal` export is an alias for this local function. Root `DetectOptions` and `DetectResult` describe hosted `detect()` and are aliases of `HostedDetectOptions` and `HostedDetectResult`. Use root `LocalDetectOptions` and `LocalDetectResult` for local detection and provider-wrapper options, or import `DetectOptions` and `DetectResult` from `@zeroleaks/shield/local`. Local thresholds, patterns, allow phrases, and normalization options do not configure hosted model classification.

## Provider wrappers

```typescript
import { createHostedDetector } from "@zeroleaks/shield";
import { shieldOpenAI } from "@zeroleaks/shield/openai";

const shield = createHostedDetector({ model: "shield-large" });
const client = shieldOpenAI(openaiClient, { detect: shield.options() });
```

The same `detect: shield.options()` works with `shieldLanguageModelMiddleware()` for AI SDK, and the other provider wrappers. Tool results inherit those detection options. The wrappers await the hosted verdict by default and stop on service errors. Explicitly configured local model and rule checks keep their existing behavior.

The synchronous legacy helper `shieldMiddleware().wrapParams()` rejects asynchronous detectors. Use `await shieldMiddleware({ detect: shield.options() }).wrapParamsAsync(params)`, or the AI SDK's `shieldLanguageModelMiddleware()` integration.

MCP wrappers await hosted checks for tool definitions as well as tool results. For direct tool-definition checks use `await scanToolsAsync(tools, shield.options())`. Synchronous `scanTools()` rejects async detector options and keeps its local behavior otherwise.

## Local transformer models

```typescript
import { detectAsync } from "@zeroleaks/shield/local";
import { createModelDetector } from "@zeroleaks/shield/model";

const model = createModelDetector({ localPath: "/models/shield" });
const result = await detectAsync(text, model.options());
```

Root `detectAsync()` is retained for compatibility and still performs local detection with optional async model or LLM checks. It is not an alias for the new hosted `detect()`.

## Custom endpoints and long inputs

`baseURL` includes the API version, such as `https://shield.example.invalid/v1`; `endpoint` specifies the complete moderation URL instead. Custom endpoints do not inherit the production API key. Pass a key explicitly if your endpoint needs one. HTTPS is required except for loopback HTTP during local development.

Inspect `result.shield.coverage` for a long document's window coverage. By default a partial scan returns its verdict with `truncated: true`. Set `requireFullCoverage: true` to reject partial scans or responses without coverage metadata. `signal` and `timeoutMs` control cancellation and request duration.
