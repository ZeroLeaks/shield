Title: feat(tools-registry): add zeroleaks-shield

Adds [ZeroLeaks Shield](https://zeroleaks.ai/shield) to the tools registry with `shieldCheck` from [`@zeroleaks/shield`](https://www.npmjs.com/package/@zeroleaks/shield). It inspects text for prompt injection and jailbreaks locally by default, with hosted detection available on explicit opt-in. The example combines the tool with language model middleware that blocks detected injections before model calls. Model-invoked inspection is advisory; detection results do not authorize agent actions.

The entry links directly to the [AI SDK integration guide](https://zeroleaks.ai/docs/shield-sdk/providers/ai-sdk-tools). Its example uses current AI SDK imports, AI Gateway, and `isStepCount`. Local detection needs no ZeroLeaks key; the Gateway model needs `AI_GATEWAY_API_KEY`.

Validation for Shield 2.1.2:

- 1,263 passing tests, with two optional model tests skipped.
- Isolated packed-package consumers on AI SDK 5.0.267, 6.0.292, and 7.0.127, covering generation, streaming, malformed inputs, hosted errors, and middleware blocking.
- Strict ESM and CommonJS consumer types; root and middleware imports without optional provider SDKs installed.
- Exact registry example type-checked and executed against a mocked Gateway for a two-step tool roundtrip, without live inference calls.
- Registry entry formatted and type-checked against the upstream `Tool` interface.
