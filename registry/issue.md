### Description

I maintain `@zeroleaks/shield` and would like to add ZeroLeaks Shield to the AI SDK Tools Registry.

Shield provides `shieldCheck()` at `@zeroleaks/shield/ai-sdk/tools` for prompt injection and jailbreak detection in text agents read. It runs locally without a ZeroLeaks key or network request, or uses the hosted Shield API on explicit opt-in. The tool supports AI SDK 5, 6, and 7.

The package also provides `shieldLanguageModelMiddleware` to check user messages and tool results before model calls. The registry example combines both: model-invoked inspection is advisory, while middleware blocks detected injections before forwarding context. Neither a negative detector result nor a failed tool check authorizes an action.

- npm: https://www.npmjs.com/package/@zeroleaks/shield
- Canonical repository: https://github.com/ZeroLeaks/shield
- AI SDK integration guide: https://zeroleaks.ai/docs/shield-sdk/providers/ai-sdk-tools
- Website: https://zeroleaks.ai/shield
- Version prepared and tested: `@zeroleaks/shield@2.1.1`
- Current SDK tested: `ai@7.0.127`
- Additional supported SDKs tested: `ai@5.0.267`, `ai@6.0.292`

The proposed entry is in `registry/entry.ts` in the Shield repository. Its complete code example appears verbatim in the integration guide. It uses `generateText`, `isStepCount`, and the AI Gateway provider with Shield middleware and `shieldCheck`.

### Validation

The release checks install the packed package in isolated consumer projects and verify `generateText`, `streamText`, malformed tool input, hosted failures, and middleware blocking on all three supported SDK versions. Both ESM and CommonJS consumer types are checked. The exact registry example is type-checked on SDK 7 and executed against a mocked Gateway for a two-step tool roundtrip. Root and middleware imports are also verified without the AI SDK or other provider peers installed.

Hosted checks require complete input coverage and throw on authentication failures, rate limits, timeouts, cancellation, invalid responses, or incomplete coverage. Local checks reject oversized input instead of returning a verdict for truncated text. Tool results omit input text and matching patterns.

The default registry example uses local detection. Hosted `shield` requires a dashboard key and research acknowledgement; paid models are available separately. The integration guide documents access, retention, coverage, and enforcement limitations.

### AI SDK version

7.0.127
