import { describe, expect, it } from "vitest";
import {
  detectExfiltration,
  detectPII,
  detectSecrets,
  type OutputFinding,
  scanOutputText,
} from "../output/index";

let seed = 7;
function randomHex(length: number): string {
  let out = "";
  while (out.length < length) {
    seed = (seed * 48_271) % 2_147_483_647;
    out += (seed % 16).toString(16);
  }
  return out;
}

const NODE_TUTORIAL = `## Calling the Responses API from Node

Install the SDK with \`npm install openai\` (version 5.x) and export your key as
\`OPENAI_API_KEY\` before running anything:

\`\`\`bash
export OPENAI_API_KEY=sk-...
# or put it in .env
OPENAI_API_KEY="sk-proj-your-key-here"
\`\`\`

\`\`\`ts
import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const token = await getSessionToken(user.id);

export async function summarize(text: string): Promise<string> {
  const response = await client.responses.create({
    model: "gpt-5-mini",
    input: [{ role: "user", content: \`Summarize: \${text}\` }],
    max_output_tokens: 512,
  });
  return response.output_text;
}
\`\`\`

1. **Rate limits.** Retry 429s with exponential backoff (start at 500 ms, cap at 30 s).
2. **Timeouts.** The default is 10 minutes; pass \`timeout: 20_000\` for interactive paths.

See the [API reference](https://platform.openai.com/docs/api-reference/responses), the
[error codes guide](https://platform.openai.com/docs/guides/error-codes), and
https://github.com/openai/openai-node/blob/${randomHex(40)}/README.md for details.
Commit \`${randomHex(40)}\` (v1.4.2, released 2025-03-14) fixed the retry bug.
Questions go to support@example.com.
`;

const DOCKER_COMPOSE = `Here's a \`docker-compose.yml\` for FastAPI with Postgres and Redis:

\`\`\`yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: app
  api:
    build: .
    environment:
      DATABASE_URL: postgresql://postgres:postgres@db:5432/app
      REDIS_URL: redis://cache:6379/0
      SECRET_KEY: "change-me-in-production"
      JWT_SECRET: \${JWT_SECRET}
      STRIPE_SECRET_KEY: sk_test_...
    ports:
      - "8000:8000"
\`\`\`

Generate a real secret with \`openssl rand -hex 32\` and store it in your
secret manager, never in the compose file. For local dev,
\`postgres://user:password@localhost:5432/mydb\` is fine.

\`\`\`python
SECRET_KEY = os.environ["SECRET_KEY"]
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
api_key = settings.api_key  # loaded from the environment
\`\`\`
`;

const AWS_DOCS = `Run \`aws configure\` and answer the prompts:

\`\`\`
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
\`\`\`

The credentials land in \`~/.aws/credentials\`. Rotate keys every 90 days and
prefer IAM roles (\`arn:aws:iam::123456789012:role/deploy\`) over long-lived keys.
Bucket ARN: arn:aws:s3:::acme-reports-2024, request id 7c9e6679-7425-40de-944b-e07fc1f90ae7.
`;

const NUMBERS = `| Quarter | Revenue | Growth | Report date |
|---|---|---|---|
| Q1 2024 | $1,234,567.89 | 12.5% | 2024-04-15 |
| Q2 2024 | $1,402,113.02 | 13.6% | 2024-07-15 |

- ISBN 978-3-16-148410-0, DOI 10.1000/182, arXiv:2403.01234
- Version 3.11.4 (build 20240501.1), node v20.11.1, API v2
- UUID 550e8400-e29b-41d4-a716-446655440000
- Unix time 1700000000 (1700000000123 ms); 2^62 = 4611686018427387904
- pi = 3.14159265358979, e = 2.718281828459045
- 415 × 867 = 359,805 and 12 345 678 is a spaced number
- Private hosts 10.0.0.12 and 192.168.1.100; loopback 127.0.0.1
- Order #415-867-5309 and invoice INV-2024-000123 shipped
- Coordinates 37.7749, -122.4194; phone format example: (555) 123-4567
`;

const MARKDOWN_HOWTO = `To embed an image in Markdown, write \`![alt text](https://example.com/image.png)\`.
For HTML, use:

\`\`\`html
<img src="https://example.com/logo.png" alt="Logo" onerror="this.remove()">
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<div style="background: url('https://example.com/bg.jpg')"></div>
\`\`\`

A data URI works too: \`data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==\`.

Kubernetes secrets are base64, not encryption:

\`\`\`yaml
apiVersion: v1
kind: Secret
data:
  username: YWRtaW4=
  password: cGFzc3dvcmQ=
\`\`\`

Lockfile entry: \`"integrity": "sha512-${btoa(randomHex(96)).slice(0, 86)}=="\`.
More at [the CommonMark spec](https://spec.commonmark.org/0.31.2/#images),
https://www.youtube.com/watch?v=dQw4w9WgXcQ and
https://www.google.com/search?q=markdown+image+syntax.
`;

const AUTH_EXPLAINER = `JWTs look like
\`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\`
(that's the jwt.io example). Send them as \`Authorization: Bearer <token>\` or
\`Authorization: Bearer $ACCESS_TOKEN\`. Basic auth is \`Authorization: Basic dXNlcjpwYXNzd29yZA==\`.

\`\`\`bash
curl -H "Authorization: Bearer YOUR_API_KEY" https://api.example.com/v1/items
curl -u "api:YOUR_MAILGUN_KEY" https://api.mailgun.net/v3/example.com/messages
git clone git@github.com:acme/app.git
npm install lodash@4.17.21
\`\`\`

Password rules: password: must be at least 12 characters. Set
\`password: "********"\` in the fixture and \`token: \${{ secrets.GITHUB_TOKEN }}\` in CI.
Private keys look like this (truncated):

\`\`\`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
\`\`\`
`;

const CORPUS = {
  NODE_TUTORIAL,
  DOCKER_COMPOSE,
  AWS_DOCS,
  NUMBERS,
  MARKDOWN_HOWTO,
  AUTH_EXPLAINER,
};

function severe(findings: OutputFinding[]): OutputFinding[] {
  return findings.filter(
    (f) => f.severity === "high" || f.severity === "critical"
  );
}

function describeFindings(text: string, findings: OutputFinding[]): string {
  return findings
    .map(
      (f) =>
        `${f.kind}(${f.severity}): ${JSON.stringify(text.slice(f.start, f.end))}`
    )
    .join("\n");
}

describe("precision on benign LLM answers", () => {
  it.each(
    Object.entries(CORPUS)
  )("%s has no high or critical findings", (_, text) => {
    const result = scanOutputText(text, {
      pii: {
        kinds: [
          "email",
          "phone",
          "credit_card",
          "us_ssn",
          "iban",
          "ip_address",
        ],
      },
    });
    const bad = severe(result.findings);
    expect(bad, describeFindings(text, bad)).toEqual([]);
    expect(result.blocked).toBe(false);
  });

  it.each(
    Object.entries(CORPUS)
  )("%s has no secret findings at all", (_, text) => {
    const findings = detectSecrets(text).filter((f) => f.confidence > 0.3);
    expect(findings, describeFindings(text, findings)).toEqual([]);
  });

  it("only reports PII in the corpus as low-confidence examples", () => {
    for (const text of Object.values(CORPUS)) {
      const findings = detectPII(text, {
        kinds: [
          "email",
          "phone",
          "credit_card",
          "us_ssn",
          "iban",
          "ip_address",
        ],
      });
      const confident = findings.filter((f) => f.confidence > 0.3);
      expect(confident, describeFindings(text, confident)).toEqual([]);
    }
  });

  it("only reports exfiltration in the corpus inside code, at low severity", () => {
    for (const text of Object.values(CORPUS)) {
      const findings = detectExfiltration(text);
      expect(
        findings.every((f) => f.severity === "low"),
        describeFindings(text, findings)
      ).toBe(true);
    }
  });
});
