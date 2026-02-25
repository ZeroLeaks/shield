# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Injection detection:** Pattern-based detection with 10+ categories (instruction override, role hijack, prompt extraction, authority exploit, tool hijacking, etc.)
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
