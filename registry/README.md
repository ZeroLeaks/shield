# AI SDK registry submission

`entry.ts` contains the proposed object for `vercel/ai`'s `content/tools-registry/registry.ts`. `issue.md` is a ready-to-submit documentation-addition request. Neither file submits anything upstream.

The public integration guide is `https://zeroleaks.ai/docs/shield-sdk/providers/ai-sdk-tools`. Its main example must match `entry.ts` exactly. The ZeroLeaks app's package verifier checks that parity; Shield's isolated package verifier type-checks and executes the registry snippet.

Before submitting, confirm that npm serves `@zeroleaks/shield@2.1.0` and the integration guide is live. The source repository, README, public docs, and published package must describe the same exports and supported SDK versions.

Run the release checks from the Shield repository:

```bash
bun install --frozen-lockfile
bun run typecheck
bun run test
bun run build
bun run test:package
```

The package verifier uses isolated npm installations and mocked model/API responses. It requires network access to npm, Node.js 22 or later, and no live model or Shield credentials. It does not send probe text to an external inference service.

The published entry should keep local detection as the default example and link directly to the AI SDK tool guide. An optional ZeroLeaks API key is documented on that page; it is not a prerequisite for the local tool. The model example requires `AI_GATEWAY_API_KEY`.

Follow the current [contribution guide](https://github.com/vercel/ai/blob/main/contributing/add-new-tool-to-registry.md). An issue-first documentation request has recent precedent, but may cause their automation to open a PR. Hold both the issue and PR until submission is authorized.
