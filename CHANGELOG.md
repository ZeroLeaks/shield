# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - Unreleased

### Added

- **`DetectOptions.normalization`:** Configurable normalization before detection (homoglyph folding, invisible character stripping, whitespace collapsing, joining spaced-out letters, lowercasing, leetspeak decoding, typo and phonetic repair). On by default; pass `false` to disable.
- **`DetectNormalizationOptions`** type export
- **`ShieldLanguageModelMiddleware`** type export

### Changed

- **`harden`:** Rewrote the persona anchor and default security rules. Rules are now inserted as a bullet list after the prompt's identity paragraph instead of appended under a `### Security Rules` heading. `position: "prepend"` still puts them first.
- **`shieldGroq`:** Now delegates to `shieldOpenAI`; behavior is unchanged

### Fixed

- **`shieldLanguageModelMiddleware`:** Implements the AI SDK 5 and 6 middleware interface and still works on AI SDK 4. Before, `generateText` output came back unsanitized on AI SDK 5 and 6, and `streamText` failed with `NoOutputGeneratedError` on 6, streamed no text on 5, and never finished on 4. Streams now keep tool calls, reasoning, usage, the finish event, and provider metadata on text. Output is checked against the system prompt as written rather than the hardened one, which had diluted the leak score. `streamingSanitize: "chunked"` and `streamingChunkSize` now apply here too. With `throwOnLeak`, a leak in a stream ends it with an `error` part in place of the leaked text, so on all three versions `onError` fires, `result.text` settles, and `toUIMessageStreamResponse()` or `toDataStreamResponse()` sends the client an error instead of aborting. The model's `finish` part is dropped with the rest of the stream, so the call reports no token usage. `raw` stream parts (`includeRawChunks`) are dropped, and `generateText` drops `response.body` when it redacts text, because both carry the unsanitized output.
- **`streamingSanitize: "chunked"`:** Stopped repeating the 64-character overlap at every chunk boundary. The last 64 characters of a chunk are now held back and scanned again with the next one, and each chunk is scanned with the 64 characters sent before it, redacted or not. The stream carries the model's output once, and a leak across a boundary is redacted on both sides of it. A `streamingChunkSize` of 0 or less used to loop forever; it now counts as 1.
- **`shieldMiddleware().wrapParams`:** Returns the type it was given, so spreading the result into `generateText` or `streamText` type-checks. It also runs detection on user messages passed as `prompt`, which AI SDK 5 and 6 accept. AI SDK 6 system messages in `system`, alone or in an array, are accepted and hardened, and keep their `providerOptions`.
- **`shieldOpenAI`, `shieldAnthropic`, `shieldGroq`:** Accept `OpenAI`, `Anthropic`, and `Groq` client instances and return the same client type. Before, passing a real client failed to type-check. The type promises more than the wrapped copy has: the client's other methods, such as `withOptions()` and `chat.completions.parse()`, are missing, `create()` returns a plain Promise without `withResponse()`, and a sanitized stream is a plain async iterable without `toReadableStream()` or `controller`. These type-check and are `undefined` at runtime.
- **Streaming in the OpenAI, Anthropic, and Groq wrappers:** An error partway through the provider's stream now reaches your code. `"buffer"` mode used to return the provider's already-read stream, and `"chunked"` mode ended the stream early without an error.

## [1.1.0] - 2026-02-25

### Added

- **`excludeCategories`:** Skip detection for categories (e.g. `["social_engineering"]`) to reduce false positives
- **`allowPhrases`:** Whitelist phrases; input containing one suppresses detection
- **`secondaryDetector`:** Optional async verifier for LLM-based override of heuristic detection
- **`detectAsync`:** Async variant supporting `secondaryDetector`
- **`streamingSanitize: "chunked"`:** Process streams in 8KB chunks to limit memory for long outputs
- **`streamingChunkSize`:** Configurable chunk size for chunked mode (default 8192)
- **`shieldLanguageModelMiddleware`:** AI SDK middleware for automatic hardening, detection, and output sanitization (no manual `sanitizeOutput`)

### Changed

- **Dependencies:** Upgraded to ai ^6, openai ^6, @ai-sdk/openai ^3, @anthropic-ai/sdk ^0.78, groq-sdk ^0.37
- **Providers:** Use `detectAsync` when `secondaryDetector` is configured

## [1.0.0] - 2026-02-25

### Added

- **Core functions:** `harden`, `detect`, `sanitize`, `sanitizeObject`
- **Provider wrappers:** OpenAI, Anthropic, Groq, Vercel AI SDK
- **Injection detection:** Pattern-based detection with many categories (instruction override, role hijack, prompt extraction, authority exploit, tool hijacking, etc.)
- **Leak sanitization:** N-gram matching with paraphrased leak detection
- **Typed errors:** `InjectionDetectedError`, `LeakDetectedError`, `ShieldError`
- **Multi-part messages:** Text extraction from `ContentPart[]` for OpenAI/Groq (text + images)
- **System prompt derivation:** Auto-derive from params when `systemPrompt` not provided
- **Streaming:** Sanitized content yielded in chunks to preserve streaming UX
- **`throwOnLeak` option:** Throw `LeakDetectedError` instead of redacting when leak detected
- **AI SDK system array:** Harden `system` when passed as array of parts
- **Integration tests:** Opt-in tests for OpenAI (Anthropic, Groq when keys configured)
- **Benchmarks:** `bun run benchmark` for performance verification

### Security

- Heuristic-based; use as defense-in-depth, not sole protection
- See README Threat Model for limitations
