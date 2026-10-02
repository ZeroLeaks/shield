import { describe, expect, it } from "vitest";
import { detectSecrets, SECRET_KINDS } from "../output/secrets";
import type { OutputFinding } from "../output/types";

// Every token below is generated at runtime in the vendor's real format.
// Nothing here is a real credential, and no realistic literal sits in source.
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const A62 = `${UPPER}${LOWER}${DIGITS}`;
const HEX = "0123456789abcdef";
const URLSAFE = `${A62}-_`;
const B64 = `${A62}+/`;
const BASE32 = `${UPPER}234567`;
/** Keeps "${" out of plain strings (template placeholders in fixtures). */
const DOLLAR = "$";

let seed = 20_260_927;
function random(): number {
  seed = (seed * 48_271) % 2_147_483_647;
  return seed / 2_147_483_647;
}

/** Random string that never contains a placeholder-looking run or sequence. */
function rand(alphabet: string, length: number): string {
  let out = "";
  while (out.length < length) {
    const next = alphabet[Math.floor(random() * alphabet.length)];
    const previous = out.charCodeAt(out.length - 1);
    const code = next.charCodeAt(0);
    if (code === previous || code === previous + 1 || code === previous - 1) {
      continue;
    }
    out += next;
  }
  return out;
}

const PADDING = /=+$/;
const PLUS = /\+/g;
const SLASH = /\//g;

function base64url(value: string): string {
  return btoa(value)
    .replace(PADDING, "")
    .replace(PLUS, "-")
    .replace(SLASH, "_");
}

function jwt(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = { alg: "HS256", typ: "JWT" }
): string {
  return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}.${rand(URLSAFE, 43)}`;
}

function findKind(text: string, kind: string): OutputFinding | undefined {
  return detectSecrets(text).find((f) => f.kind === kind);
}

interface RecallCase {
  kind: string;
  secret: string;
  /** Template with {s} where the secret goes. */
  context: string;
  severity?: OutputFinding["severity"];
}

const now = Math.floor(Date.now() / 1000);

const RECALL: RecallCase[] = [
  {
    kind: "aws_access_key_id",
    secret: `AKIA${rand(BASE32, 16)}`,
    context: "aws_access_key_id = {s}",
    severity: "critical",
  },
  {
    kind: "aws_access_key_id",
    secret: `ASIA${rand(BASE32, 16)}`,
    context: '"AccessKeyId": "{s}",',
    severity: "high",
  },
  {
    kind: "aws_secret_access_key",
    secret: `${rand(A62, 18)}/${rand(A62, 12)}+${rand(A62, 8)}`,
    context: "aws_secret_access_key = {s}",
    severity: "critical",
  },
  {
    kind: "aws_secret_access_key",
    secret: `${rand(A62, 22)}+${rand(A62, 17)}`,
    context: 'AWS_SECRET_ACCESS_KEY="{s}"',
  },
  {
    kind: "aws_secret_access_key",
    secret: `${rand(A62, 20)}/${rand(A62, 19)}`,
    context: '{"Credentials": {"SecretAccessKey": "{s}"}}',
  },
  {
    kind: "aws_session_token",
    secret: `IQoJb3JpZ2lu${rand(B64, 300)}`,
    context: "aws_session_token={s}",
  },
  {
    kind: "google_api_key",
    secret: `AIza${rand(URLSAFE, 35)}`,
    context: "https://maps.googleapis.com/maps/api/js?key={s}",
  },
  {
    kind: "google_oauth_client_secret",
    secret: `GOCSPX-${rand(URLSAFE, 28)}`,
    context: '"client_secret":"{s}"',
  },
  {
    kind: "google_oauth_access_token",
    secret: `ya29.${rand(URLSAFE, 120)}`,
    context: "access token: {s}",
  },
  {
    kind: "azure_storage_account_key",
    secret: `${rand(B64, 86)}==`,
    context:
      "DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey={s};EndpointSuffix=core.windows.net",
  },
  {
    kind: "azure_sas_token",
    secret: `${rand(A62, 43)}%3D`,
    context:
      "https://prodstore.blob.core.windows.net/reports/q3.pdf?sv=2022-11-02&ss=b&sp=r&se=2026-01-01T00:00:00Z&sig={s}",
  },
  {
    kind: "azure_ad_client_secret",
    secret: `${rand(A62, 3)}7Q~${rand(`${A62}_~.-`, 34)}`,
    context: "AZURE_CLIENT_SECRET={s}",
  },
  {
    kind: "openai_api_key",
    secret: `sk-proj-${rand(URLSAFE, 156)}`,
    context: "OPENAI_API_KEY={s}",
    severity: "critical",
  },
  {
    kind: "openai_api_key",
    secret: `sk-${rand(A62, 20)}T3BlbkFJ${rand(A62, 20)}`,
    context: 'openai.api_key = "{s}"',
  },
  {
    kind: "openai_api_key",
    secret: `sk-svcacct-${rand(URLSAFE, 120)}`,
    context: "Service account key: {s}",
  },
  {
    kind: "sk_api_key",
    secret: `sk-${rand(HEX, 32)}`,
    context: "DEEPSEEK_API_KEY={s}",
    severity: "high",
  },
  {
    kind: "anthropic_api_key",
    secret: `sk-ant-api03-${rand(URLSAFE, 93)}AA`,
    context: "x-api-key: {s}",
    severity: "critical",
  },
  {
    kind: "anthropic_admin_key",
    secret: `sk-ant-admin01-${rand(URLSAFE, 93)}AA`,
    context: "admin key {s}",
  },
  {
    kind: "openrouter_api_key",
    secret: `sk-or-v1-${rand(HEX, 64)}`,
    context: "Authorization: Bearer {s}",
  },
  {
    kind: "groq_api_key",
    secret: `gsk_${rand(A62, 52)}`,
    context: "GROQ_API_KEY={s}",
  },
  {
    kind: "xai_api_key",
    secret: `xai-${rand(A62, 80)}`,
    context: "XAI_API_KEY={s}",
  },
  {
    kind: "huggingface_token",
    secret: `hf_${rand(`${UPPER}${LOWER}`, 34)}`,
    context: "huggingface-cli login --token {s}",
  },
  {
    kind: "replicate_api_token",
    secret: `r8_${rand(A62, 37)}`,
    context: "REPLICATE_API_TOKEN={s}",
  },
  {
    kind: "perplexity_api_key",
    secret: `pplx-${rand(A62, 48)}`,
    context: "key: {s}",
  },
  {
    kind: "pinecone_api_key",
    secret: `pcsk_${rand(A62, 6)}_${rand(A62, 60)}`,
    context: "PINECONE_API_KEY={s}",
  },
  {
    kind: "langsmith_api_key",
    secret: `lsv2_pt_${rand(HEX, 32)}_${rand(HEX, 10)}`,
    context: "LANGSMITH_API_KEY={s}",
  },
  {
    kind: "together_api_key",
    secret: `tgp_v1_${rand(URLSAFE, 43)}`,
    context: "TOGETHER_API_KEY={s}",
  },
  {
    kind: "github_pat",
    secret: `ghp_${rand(A62, 36)}`,
    context: "git clone https://{s}@github.com/acme/private.git",
    severity: "critical",
  },
  {
    kind: "github_oauth_token",
    secret: `gho_${rand(A62, 36)}`,
    context: "token {s}",
  },
  {
    kind: "github_app_installation_token",
    secret: `ghs_${rand(A62, 36)}`,
    context: "GITHUB_TOKEN={s}",
  },
  {
    kind: "github_fine_grained_pat",
    secret: `github_pat_${rand(A62, 22)}_${rand(A62, 59)}`,
    context: "export GH_TOKEN={s}",
  },
  {
    kind: "gitlab_pat",
    secret: `glpat-${rand(URLSAFE, 20)}`,
    context: "PRIVATE-TOKEN: {s}",
  },
  {
    kind: "npm_token",
    secret: `npm_${rand(A62, 36)}`,
    context: "//registry.npmjs.org/:_authToken={s}",
  },
  {
    kind: "pypi_token",
    secret: `pypi-AgEIcHlwaS5vcmc${rand(URLSAFE, 150)}`,
    context: "password = {s}",
  },
  {
    kind: "docker_hub_token",
    secret: `dckr_pat_${rand(URLSAFE, 27)}`,
    context: "docker login -u acme -p {s}",
  },
  {
    kind: "databricks_token",
    secret: `dapi${rand(HEX, 32)}`,
    context: "DATABRICKS_TOKEN={s}",
  },
  {
    kind: "sentry_auth_token",
    secret: `sntryu_${rand(HEX, 64)}`,
    context: "SENTRY_AUTH_TOKEN={s}",
  },
  {
    kind: "atlassian_api_token",
    secret: `ATATT3${rand(URLSAFE, 186)}`,
    context: "jira token {s}",
  },
  {
    kind: "linear_api_key",
    secret: `lin_api_${rand(A62, 40)}`,
    context: "LINEAR_API_KEY={s}",
  },
  {
    kind: "notion_token",
    secret: `ntn_${rand(A62, 46)}`,
    context: "NOTION_TOKEN={s}",
  },
  {
    kind: "postman_api_key",
    secret: `PMAK-${rand(HEX, 24)}-${rand(HEX, 34)}`,
    context: "x-api-key: {s}",
  },
  {
    kind: "figma_token",
    secret: `figd_${rand(URLSAFE, 40)}`,
    context: "X-Figma-Token: {s}",
  },
  {
    kind: "airtable_token",
    secret: `pat${rand(A62, 14)}.${rand(HEX, 64)}`,
    context: "AIRTABLE_TOKEN={s}",
  },
  {
    kind: "grafana_token",
    secret: `glsa_${rand(A62, 32)}_${rand(HEX, 8)}`,
    context: "GRAFANA_TOKEN={s}",
  },
  {
    kind: "new_relic_api_key",
    secret: `NRAK-${rand(`${UPPER}${DIGITS}`, 27)}`,
    context: "NEW_RELIC_API_KEY={s}",
  },
  {
    kind: "stripe_secret_key",
    secret: `sk_live_${rand(A62, 99)}`,
    context: "STRIPE_SECRET_KEY={s}",
    severity: "critical",
  },
  {
    kind: "stripe_restricted_key",
    secret: `rk_live_${rand(A62, 99)}`,
    context: "STRIPE_KEY={s}",
    severity: "high",
  },
  {
    kind: "stripe_test_key",
    secret: `sk_test_${rand(A62, 99)}`,
    context: "STRIPE_SECRET_KEY={s}",
    severity: "low",
  },
  {
    kind: "stripe_webhook_secret",
    secret: `whsec_${rand(A62, 32)}`,
    context: "STRIPE_WEBHOOK_SECRET={s}",
  },
  {
    kind: "square_access_token",
    secret: `EAAA${rand(URLSAFE, 60)}`,
    context: "SQUARE_ACCESS_TOKEN={s}",
  },
  {
    kind: "square_oauth_secret",
    secret: `sq0csp-${rand(URLSAFE, 43)}`,
    context: "SQUARE_APPLICATION_SECRET={s}",
  },
  {
    kind: "shopify_token",
    secret: `shpat_${rand(HEX, 32)}`,
    context: "X-Shopify-Access-Token: {s}",
  },
  {
    kind: "sendgrid_api_key",
    secret: `SG.${rand(URLSAFE, 22)}.${rand(URLSAFE, 43)}`,
    context: "SENDGRID_API_KEY={s}",
  },
  {
    kind: "mailgun_api_key",
    secret: `key-${rand(HEX, 32)}`,
    context: "api:{s}",
  },
  {
    kind: "mailchimp_api_key",
    secret: `${rand(HEX, 32)}-us14`,
    context: "MAILCHIMP_API_KEY={s}",
  },
  {
    kind: "resend_api_key",
    secret: `re_${rand(A62, 8)}_${rand(A62, 24)}`,
    context: "RESEND_API_KEY={s}",
  },
  {
    kind: "slack_bot_token",
    secret: `xoxb-${rand(DIGITS, 12)}-${rand(DIGITS, 13)}-${rand(A62, 24)}`,
    context: "SLACK_BOT_TOKEN={s}",
    severity: "critical",
  },
  {
    kind: "slack_user_token",
    secret: `xoxp-${rand(DIGITS, 12)}-${rand(DIGITS, 12)}-${rand(DIGITS, 13)}-${rand(HEX, 32)}`,
    context: "token={s}",
  },
  {
    kind: "slack_app_token",
    secret: `xapp-1-A${rand(`${UPPER}${DIGITS}`, 10)}-${rand(DIGITS, 13)}-${rand(HEX, 64)}`,
    context: "SLACK_APP_TOKEN={s}",
  },
  {
    kind: "slack_webhook",
    secret: `https://hooks.slack.com/services/T${rand(`${UPPER}${DIGITS}`, 10)}/B${rand(`${UPPER}${DIGITS}`, 10)}/${rand(A62, 24)}`,
    context: "curl -X POST {s} -d @payload.json",
  },
  {
    kind: "discord_bot_token",
    secret: `${base64url(`1${rand(DIGITS, 17)}`)}.${rand(URLSAFE, 6)}.${rand(URLSAFE, 38)}`,
    context: "client.login('{s}')",
  },
  {
    kind: "discord_webhook",
    secret: `https://discord.com/api/webhooks/1${rand(DIGITS, 17)}/${rand(URLSAFE, 68)}`,
    context: "webhook: {s}",
  },
  {
    kind: "telegram_bot_token",
    secret: `${rand(DIGITS, 10)}:AA${rand(URLSAFE, 33)}`,
    context: "TELEGRAM_BOT_TOKEN={s}",
  },
  {
    kind: "mapbox_secret_token",
    secret: `sk.eyJ${rand(URLSAFE, 60)}.${rand(URLSAFE, 22)}`,
    context: "MAPBOX_TOKEN={s}",
  },
  {
    kind: "firebase_cloud_messaging_key",
    secret: `AAAA${rand(URLSAFE, 7)}:APA91b${rand(URLSAFE, 134)}`,
    context: "Authorization: key={s}",
  },
  {
    kind: "digitalocean_token",
    secret: `dop_v1_${rand(HEX, 64)}`,
    context: "DIGITALOCEAN_TOKEN={s}",
  },
  {
    kind: "heroku_api_key",
    secret: `HRKU-${rand(URLSAFE, 60)}`,
    context: "HEROKU_API_KEY={s}",
  },
  {
    kind: "flyio_token",
    secret: `fo1_${rand(URLSAFE, 43)}`,
    context: "FLY_API_TOKEN={s}",
  },
  {
    kind: "vercel_token",
    secret: `vck_${rand(A62, 40)}`,
    context: "AI_GATEWAY_API_KEY={s}",
  },
  {
    kind: "netlify_token",
    secret: `nfp_${rand(A62, 36)}`,
    context: "NETLIFY_AUTH_TOKEN={s}",
  },
  {
    kind: "supabase_secret_key",
    secret: `sb_secret_${rand(URLSAFE, 31)}`,
    context: "SUPABASE_SECRET_KEY={s}",
  },
  {
    kind: "planetscale_token",
    secret: `pscale_tkn_${rand(URLSAFE, 43)}`,
    context: "PLANETSCALE_SERVICE_TOKEN={s}",
  },
  {
    kind: "doppler_token",
    secret: `dp.st.${rand(A62, 43)}`,
    context: "DOPPLER_TOKEN={s}",
  },
  {
    kind: "vault_token",
    secret: `hvs.${rand(URLSAFE, 90)}`,
    context: "VAULT_TOKEN={s}",
  },
  {
    kind: "terraform_cloud_token",
    secret: `${rand(A62, 14)}.atlasv1.${rand(URLSAFE, 67)}`,
    context: 'token = "{s}"',
  },
  {
    kind: "onepassword_service_account_token",
    secret: `ops_eyJ${rand(URLSAFE, 300)}`,
    context: "OP_SERVICE_ACCOUNT_TOKEN={s}",
  },
  {
    kind: "age_secret_key",
    secret: `AGE-SECRET-KEY-1${rand(`${UPPER}${DIGITS}`, 58)}`,
    context: "# identity\n{s}",
  },
  // Generic-looking values that count next to their provider's name
  {
    kind: "twilio_api_key",
    secret: `SK${rand(HEX, 32)}`,
    context: "Twilio API key SID: {s}",
  },
  {
    kind: "twilio_auth_token",
    secret: rand(HEX, 32),
    context: "TWILIO_AUTH_TOKEN={s}",
    severity: "critical",
  },
  {
    kind: "twilio_account_sid",
    secret: `AC${rand(HEX, 32)}`,
    context: "Twilio account {s}",
    severity: "low",
  },
  {
    kind: "cohere_api_key",
    secret: rand(A62, 40),
    context: "COHERE_API_KEY={s}",
  },
  {
    kind: "mistral_api_key",
    secret: rand(A62, 32),
    context: 'MISTRAL_API_KEY="{s}"',
  },
  {
    kind: "together_api_key",
    secret: rand(HEX, 64),
    context: "TOGETHER_API_KEY={s}",
  },
  {
    kind: "deepgram_api_key",
    secret: rand(HEX, 40),
    context: "DEEPGRAM_API_KEY={s}",
  },
  {
    kind: "elevenlabs_api_key",
    secret: `sk_${rand(HEX, 48)}`,
    context: "xi-api-key: {s}",
  },
  {
    kind: "assemblyai_api_key",
    secret: rand(HEX, 32),
    context: "ASSEMBLYAI_API_KEY={s}",
  },
  {
    kind: "fireworks_api_key",
    secret: `fw_${rand(A62, 24)}`,
    context: "FIREWORKS_API_KEY={s}",
  },
  {
    kind: "voyage_api_key",
    secret: `pa-${rand(URLSAFE, 43)}`,
    context: "VOYAGE_API_KEY={s}",
  },
  {
    kind: "datadog_api_key",
    secret: rand(HEX, 32),
    context: "DD_API_KEY={s}",
  },
  {
    kind: "cloudflare_api_token",
    secret: rand(URLSAFE, 40),
    context: "CLOUDFLARE_API_TOKEN={s}",
  },
  {
    kind: "vercel_token",
    secret: rand(A62, 24),
    context: "VERCEL_TOKEN={s}",
  },
  {
    kind: "azure_api_key",
    secret: rand(HEX, 32),
    context: "AZURE_OPENAI_API_KEY={s}",
  },
  {
    kind: "heroku_api_key",
    secret: `${rand(HEX, 8)}-${rand(HEX, 4)}-${rand(HEX, 4)}-${rand(HEX, 4)}-${rand(HEX, 12)}`,
    context: "HEROKU_API_KEY={s}",
  },
  {
    kind: "mailgun_api_key",
    secret: `${rand(HEX, 32)}-${rand(HEX, 8)}-${rand(HEX, 8)}`,
    context: "MAILGUN_API_KEY={s}",
  },
  {
    kind: "algolia_admin_key",
    secret: rand(HEX, 32),
    context: "ALGOLIA_ADMIN_KEY={s}",
  },
  // Assignments and headers
  {
    kind: "password_assignment",
    secret: `${rand(A62, 12)}!${rand(A62, 8)}`,
    context: 'const password = "{s}";',
    severity: "high",
  },
  {
    kind: "password_assignment",
    secret: `${rand(A62, 20)}#`,
    context: "DB_PASSWORD={s}",
  },
  {
    kind: "generic_secret",
    secret: rand(A62, 32),
    context: 'client_secret: "{s}"',
  },
  {
    kind: "generic_secret",
    secret: rand(URLSAFE, 40),
    context: "X-API-Key: {s}",
  },
  {
    kind: "bearer_token",
    secret: rand(A62, 40),
    context: 'curl -H "Authorization: Bearer {s}" https://api.acme.dev',
  },
  {
    kind: "basic_auth_credentials",
    secret: btoa(`deploy:${rand(A62, 18)}`),
    context: "Authorization: Basic {s}",
  },
];

describe("detectSecrets recall", () => {
  it.each(RECALL.map((c) => [c.kind, c] as const))("detects %s", (_, c) => {
    const text = `Here is the configuration you asked for:\n\n${c.context.replace("{s}", c.secret)}\n\nLet me know if you need anything else.`;
    const finding = findKind(text, c.kind);
    expect(finding, `${c.kind} in ${text}`).toBeDefined();
    const start = text.indexOf(c.secret);
    expect(finding?.start).toBe(start);
    expect(finding?.end).toBe(start + c.secret.length);
    if (c.severity) {
      expect(finding?.severity).toBe(c.severity);
    }
    expect(finding?.preview).not.toContain(c.secret);
    expect((finding?.preview.length ?? 0) < c.secret.length).toBe(true);
  });

  it("covers every kind it declares", () => {
    const covered = new Set(RECALL.map((c) => c.kind));
    const structured = [
      "private_key",
      "gcp_service_account_key",
      "jwt",
      "supabase_service_role_key",
      "supabase_anon_key",
      "database_connection_url",
      "url_credentials",
      "github_app_user_token",
      "github_refresh_token",
      "gitlab_token",
      "anthropic_oauth_token",
      "slack_token",
      "azure_shared_access_key",
    ];
    for (const kind of SECRET_KINDS) {
      if (!structured.includes(kind)) {
        expect(covered.has(kind), kind).toBe(true);
      }
    }
  });
});

function rsaBody(lines: number, width = 64): string {
  const out: string[] = [];
  for (let i = 0; i < lines; i++) {
    out.push(rand(B64, width));
  }
  return out.join("\n");
}

describe("private keys", () => {
  it("detects a PEM private key block as critical", () => {
    const block = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA${rsaBody(24)}\n-----END RSA PRIVATE KEY-----`;
    const text = `Save this as id_rsa:\n\n\`\`\`\n${block}\n\`\`\`\n`;
    const [finding] = detectSecrets(text);
    expect(finding.kind).toBe("private_key");
    expect(finding.severity).toBe("critical");
    expect(text.slice(finding.start, finding.end)).toBe(block);
    expect(finding.preview).toBe("-----BEGIN RSA PRIVATE KEY-----…");
  });

  it("detects OpenSSH, EC, and PGP keys; encrypted keys are high", () => {
    for (const header of [
      "OPENSSH PRIVATE KEY",
      "EC PRIVATE KEY",
      "PGP PRIVATE KEY BLOCK",
    ]) {
      const text = `-----BEGIN ${header}-----\n${rsaBody(8)}\n-----END ${header}-----`;
      expect(detectSecrets(text)[0]?.severity, header).toBe("critical");
    }
    const encrypted = `-----BEGIN ENCRYPTED PRIVATE KEY-----\n${rsaBody(8)}\n-----END ENCRYPTED PRIVATE KEY-----`;
    expect(detectSecrets(encrypted)[0]?.severity).toBe("high");
  });

  it("recognizes a GCP service account JSON key", () => {
    const key = `-----BEGIN PRIVATE KEY-----\\n${rsaBody(20).split("\n").join("\\n")}\\n-----END PRIVATE KEY-----\\n`;
    const json = JSON.stringify(
      {
        type: "service_account",
        project_id: "acme-prod",
        private_key_id: rand(HEX, 40),
        client_email: "deployer@acme-prod.iam.gserviceaccount.com",
      },
      null,
      2
    ).replace(
      '"private_key_id"',
      `"private_key": "${key}",\n  "private_key_id"`
    );
    const finding = findKind(json, "gcp_service_account_key");
    expect(finding?.severity).toBe("critical");
  });

  it("reports a truncated key with lower confidence", () => {
    const text = `-----BEGIN PRIVATE KEY-----\n${rsaBody(6)}`;
    const [finding] = detectSecrets(text);
    expect(finding.kind).toBe("private_key");
    expect(finding.confidence).toBeLessThan(0.9);
  });

  it("ignores documentation placeholders", () => {
    const docs = [
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
      "-----BEGIN PRIVATE KEY-----\n<your private key here>\n-----END PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
    ];
    for (const text of docs) {
      expect(detectSecrets(text), text).toEqual([]);
    }
  });
});

describe("JWTs", () => {
  it("flags a Supabase service_role key as critical", () => {
    const token = jwt({
      iss: "supabase",
      ref: "abcd",
      role: "service_role",
      exp: now + 10_000_000,
    });
    const finding = findKind(
      `SUPABASE_SERVICE_ROLE_KEY=${token}`,
      "supabase_service_role_key"
    );
    expect(finding?.severity).toBe("critical");
  });

  it("treats a Supabase anon key as low (it is public by design)", () => {
    const token = jwt({ iss: "supabase", role: "anon", exp: now + 10_000_000 });
    expect(findKind(`anon: ${token}`, "supabase_anon_key")?.severity).toBe(
      "low"
    );
  });

  it("rates live, expired, unsigned, and example tokens differently", () => {
    const live = jwt({ sub: "user_8812", scope: "admin", exp: now + 3600 });
    const expired = jwt({ sub: "user_8812", exp: now - 3600 });
    const unsigned = `${base64url('{"alg":"none"}')}.${base64url('{"sub":"user_8812"}')}.`;
    const example =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    expect(findKind(`Bearer ${live}`, "jwt")?.severity).toBe("high");
    expect(findKind(expired, "jwt")?.severity).toBe("low");
    expect(findKind(unsigned, "jwt")?.severity).toBe("low");
    const exampleFinding = findKind(example, "jwt");
    expect(exampleFinding?.severity).toBe("low");
    expect(exampleFinding?.confidence).toBeLessThanOrEqual(0.2);
  });

  it("ignores eyJ strings that are not JSON", () => {
    const fake = `eyJ${rand(A62, 20)}.eyJ${rand(A62, 20)}.${rand(A62, 30)}`;
    expect(detectSecrets(fake).filter((f) => f.kind === "jwt")).toEqual([]);
  });
});

describe("credentials in URLs", () => {
  it("flags a database URL with a real-looking password as critical", () => {
    const password = `${rand(A62, 18)}%21`;
    const text = `DATABASE_URL=postgresql://app_user:${password}@db.prod.internal:5432/app?sslmode=require`;
    const finding = findKind(text, "database_connection_url");
    expect(finding?.severity).toBe("critical");
    expect(text.slice(finding?.start, finding?.end)).toBe(password);
    expect(finding?.preview).toBe(
      "postgresql://app_user:****@db.prod.internal"
    );
  });

  it("covers MongoDB SRV, Redis, MySQL, and AMQP URLs", () => {
    for (const scheme of ["mongodb+srv", "rediss", "mysql", "amqps"]) {
      const text = `${scheme}://svc:${rand(A62, 20)}@cluster0.acme.net/db`;
      expect(findKind(text, "database_connection_url"), scheme).toBeDefined();
    }
  });

  it("flags basic auth in an https URL and a bare token as the username", () => {
    const basic = `https://admin:${rand(A62, 16)}@internal.acme.dev/metrics`;
    expect(findKind(basic, "url_credentials")?.severity).toBe("high");
    const tokenUser = `https://${rand(A62, 32)}@git.acme.dev/infra.git`;
    expect(findKind(tokenUser, "url_credentials")).toBeDefined();
  });

  it("downgrades local hosts and skips placeholder passwords", () => {
    const local = `postgres://app:${rand(A62, 18)}@localhost:5432/dev`;
    expect(findKind(local, "database_connection_url")?.severity).toBe("medium");
    const docs = [
      "postgres://user:password@localhost:5432/mydb",
      "postgresql://postgres:postgres@db:5432/app",
      "mongodb://root:example@mongo:27017",
      `redis://:${DOLLAR}{REDIS_PASSWORD}@cache:6379`,
      "mysql://user:<password>@host/db",
      "amqp://guest:guest@localhost:5672",
      "https://user:pass@example.com",
      "git@github.com:acme/repo.git",
    ];
    for (const text of docs) {
      expect(detectSecrets(text), text).toEqual([]);
    }
  });
});

describe("assignments", () => {
  it("skips code, prose, templates, and placeholders", () => {
    const benign = [
      "password: must be at least 16 characters long",
      "const token = process.env.GITHUB_TOKEN_VALUE;",
      'api_key = os.environ["OPENAI_API_KEY"]',
      "tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')",
      `token: ${DOLLAR}{{ secrets.GITHUB_TOKEN }}`,
      'password: "********************"',
      "Authorization: Bearer <token>",
      "Authorization: Bearer $OPENAI_API_KEY",
      "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE",
      "max_tokens: 4096",
      'secret_name = "prod/payments/stripe-api-key"',
      "NEXTAUTH_SECRET=replace-with-openssl-rand-base64-32",
      'SESSION_SECRET="my-super-secret-session-key"',
      "credentials_path: ./config/service-account-key.json",
      "Authorization: Basic dXNlcjpwYXNzd29yZA==",
      "auth_url = https://accounts.google.com/o/oauth2/auth",
    ];
    for (const text of benign) {
      expect(detectSecrets(text), text).toEqual([]);
    }
  });

  it("keeps the more specific finding when a generic rule claims the same value", () => {
    const key = `sk-proj-${rand(URLSAFE, 120)}`;
    const findings = detectSecrets(`api_key = "${key}"`);
    expect(findings).toHaveLength(1);
    expect(findings[0].kind).toBe("openai_api_key");
  });
});

describe("placeholders in known formats", () => {
  it("skips documentation-style keys", () => {
    const docs = [
      "OPENAI_API_KEY=sk-...",
      "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "export OPENAI_API_KEY=sk-your-key-here-replace-me-please",
      "sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      "ANTHROPIC_API_KEY=sk-ant-api03-your-key-goes-here-and-it-is-long-enough-to-match-xxxxxxxx",
      "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
      "AKIAIOSFODNN7EXAMPLE",
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "xoxb-your-bot-token-goes-here-1234567890",
      `https://hooks.slack.com/services/T${"0".repeat(8)}/B${"0".repeat(8)}/${"X".repeat(24)}`,
      `sk_live_${"0".repeat(28)}`,
      "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      "npm_abcdefghijklmnopqrstuvwxyz0123456789",
    ];
    for (const text of docs) {
      expect(detectSecrets(text), text).toEqual([]);
    }
  });
});

describe("options", () => {
  const github = `ghp_${rand(A62, 36)}`;
  const stripe = `sk_test_${rand(A62, 99)}`;
  const text = `GITHUB_TOKEN=${github}\nSTRIPE_KEY=${stripe}`;

  it("filters by kinds and exclude", () => {
    expect(
      detectSecrets(text, { kinds: ["github_pat"] }).map((f) => f.kind)
    ).toEqual(["github_pat"]);
    expect(
      detectSecrets(text, { exclude: ["github_pat"] }).map((f) => f.kind)
    ).toEqual(["stripe_test_key"]);
  });

  it("drops findings below minConfidence", () => {
    const example =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    expect(detectSecrets(example, { minConfidence: 0.5 })).toEqual([]);
  });

  it("returns [] for empty and non-string input", () => {
    expect(detectSecrets("")).toEqual([]);
    expect(detectSecrets(undefined as unknown as string)).toEqual([]);
  });
});

describe("offsets", () => {
  it("stay aligned with the input when text contains characters that change length when lowercased", () => {
    const token = `ghp_${rand(A62, 36)}`;
    const text = `İstanbul office İİİ token: ${token}`;
    const [finding] = detectSecrets(text);
    expect(text.slice(finding.start, finding.end)).toBe(token);
  });

  it("returns findings sorted by start", () => {
    const text = `a=${`ghp_${rand(A62, 36)}`} b=${`npm_${rand(A62, 36)}`} c=${`AKIA${rand(BASE32, 16)}`}`;
    const starts = detectSecrets(text).map((f) => f.start);
    expect(starts).toEqual([...starts].sort((x, y) => x - y));
    expect(starts).toHaveLength(3);
  });
});
