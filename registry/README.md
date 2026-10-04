# AI SDK registry submission

`entry.ts` contains the proposed object for `vercel/ai`'s `content/tools-registry/registry.ts`. `vercel-ai.patch` adds that object to the registry; it was formatted and type-checked against upstream commit `7c41e416b6d5ca630cc5f72b330e6c4743f82265`. `pr.md` contains the PR title and description, and `issue.md` is an optional documentation-addition request. These files do not submit anything upstream.

The public integration guide is `https://zeroleaks.ai/docs/shield-sdk/providers/ai-sdk-tools`. Its main example must match `entry.ts` exactly. The ZeroLeaks app's package verifier checks that parity; Shield's isolated package verifier type-checks and executes the registry snippet.

Before submitting, confirm that npm serves `@zeroleaks/shield@2.1.1` and the integration guide is live. The source repository, README, public docs, and published package must describe the same exports and supported SDK versions.

The 2.1.1 release passed code and package checks but npm rejected authentication (`ENEEDAUTH`). It is not published yet. No npm token is configured in the repository or its `npm` environment. The app documentation PR also requires a review before production deployment: https://github.com/x1xhlol/zeroleaks-v2/pull/229.

An npm package administrator can authorize the existing workflow in the package's [trusted publisher settings](https://www.npmjs.com/package/@zeroleaks/shield/access), following [npm's instructions](https://docs.npmjs.com/trusted-publishers/). Use the exact GitHub owner `ZeroLeaks`, repository `shield`, workflow filename `publish.yml`, and environment `npm`. Permit direct `npm publish`; staged-only permission will not publish this release. The workflow already uses GitHub-hosted runners, Node 24, current npm, and `id-token: write`.

After authorization, retry the current workflow, then verify the registry version. Verbose npm logs report the OIDC exchange reason if authentication fails:

```bash
gh workflow run publish.yml --repo ZeroLeaks/shield --ref master -f dry_run=false -f npm_tag=latest
npm view @zeroleaks/shield@2.1.1 version
```

Once npm serves the release, update the GitHub release's pending status and remove this publication-blocker note. Confirm the integration guide is deployed before submitting upstream.

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

Once the prerequisites above are live and submission is authorized, apply the patch in a current `vercel/ai` checkout:

```bash
git apply --check /path/to/shield/registry/vercel-ai.patch
git apply /path/to/shield/registry/vercel-ai.patch
```

Rebase the entry if upstream has changed, then use the repository's current formatting and validation commands before submitting.
