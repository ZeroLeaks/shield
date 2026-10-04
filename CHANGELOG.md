# Changelog

## [2.1.2] - 2026-10-04

- Corrected the canonical GitHub repository URL's capitalization to match GitHub Actions provenance. npm rejected the 2.1.1 upload because those identities differed; this version includes the inspection tool and release checks below.

## [2.1.1] - 2026-10-04

- Fixed release verification for npm 12's package metadata format while retaining compatibility with earlier npm versions. Packed package names and versions are checked against the manifest, and publish dry runs still create and install real test artifacts.
- Includes all AI SDK inspection tool changes below. The 2.1.0 publication stopped during verification before uploading a package.

## [2.1.0] - 2026-10-04

- Added `shieldCheck` at `@zeroleaks/shield/ai-sdk/tools` for AI SDK 5, 6, and 7. It uses local detection by default, supports explicit hosted detection and async local detectors, and returns detection metadata without repeating input text or matching patterns.
- Tool inputs are validated at the schema and execution boundaries. Oversized local input and incomplete hosted coverage reject rather than returning a verdict. Hosted failures and cancellation propagate as errors.
- Added isolated consumer checks for AI SDK 5–7, both module formats, and root imports without provider SDKs installed. The tool's runtime AI SDK dependency remains confined to its subpath.
- Confirmed middleware support for AI SDK 7, including `instructions` in the manual helper, generation, streaming, output guards, and raw response handling.

## [2.0.0] - 2026-10-02

- Root `detect()` now returns a Promise and calls the hosted Shield API with a dashboard key. `createHostedDetector()` supports the four hosted model IDs, self-hosted moderation endpoints, cancellation, timeouts, and provider wrapper options.
- Synchronous rules and local classifier functions are available from `@zeroleaks/shield/local`; root `detectLocal` and the existing local `detectAsync` remain available. See [MIGRATION.md](MIGRATION.md).
- AI SDK language model middleware now awaits async detection before model calls. The legacy synchronous `wrapParams()` rejects async detectors; `wrapParamsAsync()` supports them.
- MCP tool-definition checks now await configured detectors. Direct callers can use `scanToolsAsync()`; synchronous `scanTools()` rejects async detector options.
- Hosted failures reject with safe `ShieldAPIError` details. Coverage metadata is preserved, and `requireFullCoverage` can reject partial scans.

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unpublished local development - 2026-09-27

These entries describe historical local configurations. The archived evaluations informed subsequent development and have documented source overlap; they are not independent tests of the current hosted tiers.

Shield now protects agents, not just chat prompts: it scans tool results and documents for injection, checks model output for credentials, personal data, exfiltration links, and canary tokens, and detects injections with a built-in classifier instead of patterns alone. Defaults changed, so read "Changed" before upgrading.

### Added

- **Shield's model:** `@zeroleaks/shield/model` added a multilingual E5-small encoder (`zeroleaks/shield-small`) fine-tuned on about 530,000 labeled texts from public datasets. It reads input in 256-token windows every 192 tokens and reports the highest score. The archived run recorded mean balanced accuracy of 0.889 over five development groups and median latency of 25ms per call on one CPU thread. These figures apply to that artifact, configuration, and hardware. ProtectAI's model and other text-classification models also work through `model`.
- **Shield's large model and `tiered()`:** `SHIELD_MODEL_LARGE` (`zeroleaks/shield-large`) added a Qwen3-1.7B classifier with 4-bit weights (about 1GB), reading 512-token windows every 384 tokens. `tiered(fast, large)` runs the default model on every input and the large model when its score is from 0.01 up to 0.97 (14% of inputs in the archived run). Historical large-model candidates recorded balanced accuracy of 0.818 on the group named `heldout_v4` and 0.751 on `heldout_v5`. These groups later informed development and do not establish performance on unseen data.
- **`ModelDetector.options()`:** Detect options that use the model in place of the built-in classifier, with pattern matching first. This is how the benchmark runs it.
- **HTML input:** `detect()` and the model read HTML the way an agent reads the page (text, comments, and descriptive attributes, not markup, scripts, or styles), and `detect()` checks text in hidden elements on its own. A bare `display: none` is no longer a high-risk finding. `createModelDetector({ html: false })` turns this off for the model.
- **Classifier in `detect()`:** A logistic-regression model over hashed character and word n-grams, trained on about 175,000 labeled examples from public datasets (most of them English, with at least 100 in each of 14 other languages) and shipped in the package as 4-bit weights (about 175KB). It needs no download and no network. Results carry a new `score` (the model's probability), and a detection by the model is reported as category `classifier`. `DetectOptions.classifier` sets its thresholds, or `false` turns it off.
- **Hidden payloads:** `detect()` decodes base64, hex, binary, decimal character codes, URL encoding, HTML entities, escape sequences, ROT13, Morse, Braille, reversed and upside-down text, and text smuggled in Unicode tag characters or variation selectors, and scans what they decode to. `DetectNormalizationOptions.decodePayloads` turns it off.
- **`detectConversation()`:** Scans every user and tool message, plus the latest user messages joined together to catch an instruction split across turns.
- **`scanTools()`:** Checks MCP, OpenAI, Anthropic, and AI SDK tool definitions for tool poisoning in descriptions, parameter schemas, and parameter names, duplicate names, invisible characters in names, and oversized descriptions.
- **Output scanning:** `scanOutputText()`, `detectSecrets()` (over 100 credential kinds), `detectPII()`, and `detectExfiltration()` (markdown images and links, HTML resources, and URLs that carry data), with safe-to-log previews and `redactFindings()`.
- **Improper output handling:** `detectInjection()` and the `injection` option of `scanOutputText()` (off by default) find XSS and HTML injection, SQL injection, shell command injection, server-side template injection, CSV formula injection, and path traversal in model output or tool arguments that a downstream system renders or runs. Matches inside code blocks are reported at low severity.
- **Canary tokens:** `createCanary()`, `findCanary()` (verbatim, obfuscated, reversed, base64, hex, and URL-encoded), and `harden(prompt, { canary })`.
- **Spotlighting:** `spotlight()` marks untrusted content with delimiters, datamarking, or base64 (Hines et al., 2024), and `harden(prompt, { spotlight })` explains the markers to the model.
- **`harden()` tool rules:** Rules for agents that call tools, on by default (`skipToolRules` turns them off).
- **Provider wrappers:** `scanToolResults`, `output`, `onOutputFindings`, `blockOnOutputFindings`, and `canary` options on every wrapper. `shieldOpenAI` also wraps the OpenAI Responses API (`client.responses.create`). New `OutputBlockedError`, and `InjectionDetectedError.source` (`"user"` or `"tool"`).
- **New integrations:** `shieldGoogleGenAI` (`@zeroleaks/shield/google`) for `@google/genai`, `shieldMistral` (`@zeroleaks/shield/mistral`) for `@mistralai/mistralai`, and `shieldChatModel` and `ShieldCallbackHandler` (`@zeroleaks/shield/langchain`) for LangChain.js.
- **MCP client wrapper:** `shieldMcpClient` (`@zeroleaks/shield/mcp`) wraps a `@modelcontextprotocol/sdk` `Client`. `listTools()` runs `scanTools()` and leaves flagged tools out (or throws, or warns, with `onFlaggedTools`), and what `callTool()`, `readResource()`, and `getPrompt()` return is checked for injection. It pins each tool's definition and flags a tool whose definition later changes (a rug pull), refuses calls to flagged tools, and blocks tool calls whose arguments carry a credential or an exfiltration link.
- **Tool pinning:** `pinTools()` and the `pins` option of `scanTools()` report tools whose definition changed since it was pinned (`changed_since_pinned`).
- **OpenAI Agents SDK guardrails:** `shieldInputGuardrail`, `shieldOutputGuardrail`, `shieldToolInputGuardrail`, and `shieldToolOutputGuardrail` (`@zeroleaks/shield/openai-agents`) for `@openai/agents`. The input guardrail checks user input and tool results carried in the input list; the output guardrail trips on prompt leaks, canaries, and high-severity output findings; the tool guardrails check a function tool's arguments before it runs and replace an injected tool output with a notice before the model reads it.
- **Tool policy:** `createToolPolicy()` decides whether each tool call may run, with no model and no network. It refuses tools that weren't declared, arguments that don't match the tool's JSON Schema, tools on a deny list or off an allow list, and calls past `maxCalls` or `maxTotalCalls`. Once the session has read untrusted content (a result from a tool labeled `untrusted`, or one detection flagged), it refuses tools labeled `sink` unless every destination is allowed or an `approve` callback says yes. `shieldMcpClient` takes it as `policy`, `shieldToolPolicyGuardrail` (`@zeroleaks/shield/openai-agents`) applies it to an agent's tools, and `shieldToolOutputGuardrail({ policy })` records tool outputs in it. A refused MCP call throws the new `ToolPolicyError`.
- **Model tier:** `createModelDetector()` (`@zeroleaks/shield/model`) runs a transformer classifier in-process with `@huggingface/transformers` (an optional peer), Shield's own model by default, as `model.options()` or as the `escalate` detector of `detectAsync()`. It loads on first use, from a local path or Hugging Face, and scores long input in windows, several per call.
- **Detection customization:** `sensitivity` (`"strict"`, `"balanced"`, `"permissive"`) sets the risk floor and classifier threshold in one option, `denyPhrases` flags phrases specific to your application, and `includeCategories` keeps only the categories you list. See the new "Customizing detection" docs page.
- **LLM detector and `anyOf()`:** `createLlmDetector()` asks any OpenAI-compatible Chat Completions endpoint whether text is a prompt injection, with no dependency, and `anyOf()` runs several slow detectors at once and reports the first detection. Use them as `escalate` detectors.
- **Parallel detection:** with `parallelDetection: true`, the provider wrappers run `escalate` detectors while the provider call is in flight and release the response, tool calls, and stream only after their verdict, so a slow model or LLM check adds the slower of the two times instead of their sum. The fast `detect()` still runs before the call.
- **`detectAsync()` `escalate` option:** Sends input the classifier is unsure about (score at or above `minScore`, 0.15 by default) to a slower detector you provide, such as a transformer model, and keeps everything else on the fast path.
- **`sanitize()` `decodePayloads` option.**
- **`training/`:** The featurizer and training pipeline that build the classifier from public data.
- **`benchmark/`:** The archived harness builds 13 benchmark sets and six sets named `heldout`, runs local Shield configurations and other detectors, and scores the results. An early local Shield 2.0 configuration recorded mean balanced accuracy of 0.734 on the latter group, compared with 0.631 for 1.2.1 and 0.895 for ProtectAI's DeBERTa v2 model in that run. Later development used these evaluations; the figures do not measure current hosted tiers.

### Changed

- **`detect()` scans the whole input.** Before, only the first 8,192 characters were matched. Long inputs are scanned in overlapping 8KB windows.
- **`detect()` reports every category found.** Before, matching stopped at the first critical match.
- **`allowPhrases` removes the phrases before scanning** instead of suppressing any detection when the input contained one, which let an attacker bypass detection by including an allowed phrase.
- **Normalization keeps digits and symbols** in the text patterns match, so patterns for addresses like `169.254.169.254`, `$(...)`, and `<!--` work again; leetspeak is decoded only inside words that mix letters and digits.
- **Pattern false positives:** The hidden-text pattern no longer matches the word "hidden"; `curl -d` only matches when it posts command output or credentials; `crontab`, "system update", "SOC2 audit", "authorized security audit", "compliance notice", `atob(`, "base64 decode", and `\u` escapes no longer flag on their own; `output_control` is low risk. Soft hyphens, zero-width joiners, and emoji variation selectors are no longer reported as invisible-character attacks.
- **`sanitize()` redacts the whole leak.** Leaked runs are matched on normalized words and cut out at their exact position, so leaks split with zero-width characters, written with look-alike letters or leetspeak, reversed, ROT13-encoded, or encoded in base64 and similar are found and removed. Prompts in any language are matched, including scripts written without spaces. Before, parts of a leak between matched fragments could stay in the output.
- **Provider wrappers scan tool results by default** and **guard output by default** (secrets and exfiltration links are redacted). Every stream is processed unless `streamingSanitize: "passthrough"` or `output: false`; in the default `buffer` mode the OpenAI, Groq, and Anthropic wrappers read the whole stream before returning. Buffer mode now replays the provider's own chunks, so tool-call deltas, finish reasons, usage, and ids are kept.
- **`onInjectionDetected`** receives the source (`"user"` or `"tool"`) as a second argument.
- **Wrapped clients keep the SDK's other methods.** `shieldOpenAI`, `shieldAnthropic`, and `shieldGroq` return a Proxy over your client with only the guarded methods replaced, so `chat.completions.parse()`, `responses.stream()`, `messages.stream()`, and the rest still work, unguarded. In 1.2.1 they were missing at runtime. `withOptions()` returns a client that isn't wrapped.
- **`developer` messages are hardened** in the OpenAI and Groq wrappers, like `system` messages.
- **Canary options are checked when the wrapper is created,** which throws a `TypeError` or `RangeError` for a canary that can't be matched in output.
- **Anthropic `"chunked"` streaming** guards each content block and tool input on its own and replays every other event, instead of merging all text into block 0 and dropping the rest.
- **Keys in tool call arguments** are guarded as well as values, so a secret or leaked prompt text written as a JSON key is redacted too.
- **The package build** shares one copy of the classifier between entry points and targets ES2019.

### Fixed

- The `<!-- SYSTEM:` pattern was case-sensitive and never matched the lowercased text it runs on.
- The Spanish output-control pattern required accents that normalization strips.

## [1.2.1] - 2026-09-27

1.2.0 was staged on npm but never published; 1.2.1 ships everything listed below.

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
