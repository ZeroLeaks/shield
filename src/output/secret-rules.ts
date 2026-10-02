import type { Severity } from "./types";
import { decodeBase64 } from "./util";

export interface Refinement {
  kind?: string;
  severity?: Severity;
  confidence?: number;
  /** Overrides the rule's public prefix length. */
  prefix?: number;
}

export type Refiner = (
  value: string,
  text: string,
  start: number
) => Refinement | false;

interface RuleBase {
  kind: string;
  /** Every kind the rule can emit when `refine` renames it. */
  kinds?: string[];
  /** Length of the non-secret prefix: shown in previews, excluded from body checks. */
  prefix: number;
  severity: Severity;
  confidence: number;
  /** Minimum Shannon entropy of the body. Default 3. */
  minEntropy?: number;
  /** Minimum character classes (lower, upper, digit, other) in the body. Default 2. */
  minClasses?: number;
  refine?: Refiner;
}

/**
 * A credential that starts a token with a fixed vendor prefix. The scanner
 * tries `pattern` (sticky) at every token start whose first characters match
 * one of `prefixes`.
 */
export interface PrefixRule extends RuleBase {
  prefixes: string[];
  pattern: RegExp;
}

/**
 * A credential that does not start a token (it follows `AccountKey=` or sits
 * inside a URL). The scanner runs `pattern` over the text only when one of
 * `gates` occurs; the secret is capture group 1.
 */
export interface GatedRule extends RuleBase {
  gates: string[];
  /** Characters to scan before and after each gate occurrence. */
  window: [number, number];
  pattern: RegExp;
}

/** A generic-looking value (hex, base62) that only counts next to a provider name. */
export interface ContextRule {
  kind: string;
  /** Lowercase context words; one must precede the value within `maxDistance`. */
  words: string[];
  /** Global regex; the value is capture group 1. */
  pattern: RegExp;
  severity: Severity;
  confidence: number;
  /** Require a word such as "key" or "token" between context and value. Default true. */
  requireKeyWord?: boolean;
  /** Default 100 characters. */
  maxDistance?: number;
  minEntropy?: number;
  minClasses?: number;
  reject?: (value: string) => boolean;
}

const TOKEN_TAIL = "(?![A-Za-z0-9_-])";

/** Sticky regex for a token that starts at the scan position. */
function sticky(source: string, tail = TOKEN_TAIL): RegExp {
  return new RegExp(`(?:${source})${tail}`, "y");
}

/**
 * Global regex whose group 1 is `source`, bounded by characters outside
 * `chars`. The boundary is consumed instead of a lookbehind: JavaScriptCore
 * (Bun, Safari) runs any regex with a lookbehind in its slow interpreter.
 */
function bounded(source: string, chars = "A-Za-z0-9_-"): RegExp {
  return new RegExp(`(?:^|[^${chars}])(${source})(?![${chars}])`, "g");
}

const OPENAI_MARKER = "T3BlbkFJ";
const OPENAI_SCOPED = /^sk-(?:proj|svcacct|admin|None)-/;
const SLUG = /^[a-z0-9]+(?:[-_][a-z0-9]+){2,}$/;
const LONG_DIGIT_RUN = /\d{5,}/;

function refineSkKey(value: string): Refinement | false {
  const scoped = OPENAI_SCOPED.exec(value);
  const prefix = scoped ? scoped[0].length : 3;
  const body = value.slice(prefix);
  if (body.includes(OPENAI_MARKER)) {
    return { prefix, confidence: 0.97 };
  }
  if (scoped) {
    return body.length >= 32 ? { prefix } : false;
  }
  if (body.length < 32 || SLUG.test(body)) {
    return false;
  }
  return { kind: "sk_api_key", severity: "high", confidence: 0.7 };
}

function refineAnthropic(value: string): Refinement {
  const prefix = value.indexOf("-", 7) + 1;
  if (value.startsWith("sk-ant-admin")) {
    return { kind: "anthropic_admin_key", prefix };
  }
  if (value.startsWith("sk-ant-o")) {
    return { kind: "anthropic_oauth_token", prefix };
  }
  return { prefix };
}

const GITHUB_KINDS: Record<string, string> = {
  ghp_: "github_pat",
  gho_: "github_oauth_token",
  ghu_: "github_app_user_token",
  ghs_: "github_app_installation_token",
  ghr_: "github_refresh_token",
};

const SLACK_KINDS: Record<string, string> = {
  b: "slack_bot_token",
  p: "slack_user_token",
};

function refineSlack(value: string): Refinement | false {
  if (!LONG_DIGIT_RUN.test(value)) {
    return false;
  }
  if (value.startsWith("xapp-")) {
    return { kind: "slack_app_token" };
  }
  return { kind: SLACK_KINDS[value.charAt(3)] ?? "slack_token" };
}

function refineStripe(value: string): Refinement {
  if (value.includes("_test_")) {
    return { kind: "stripe_test_key", severity: "low", confidence: 0.9 };
  }
  return value.startsWith("rk_")
    ? { kind: "stripe_restricted_key", severity: "high" }
    : {};
}

/** The first segment of a Discord bot token is the bot's numeric id in base64. */
function refineDiscordToken(value: string): Refinement | false {
  const dot = value.indexOf(".");
  const id = decodeBase64(value, 0, dot);
  if (!id || id.length < 17 || id.length > 20) {
    return false;
  }
  for (const byte of id) {
    if (byte < 48 || byte > 57) {
      return false;
    }
  }
  return {};
}

function lastSegment(value: string): Refinement {
  return { prefix: value.lastIndexOf("/") + 1 };
}

function refineSas(
  _value: string,
  text: string,
  start: number
): Refinement | false {
  const version = text.lastIndexOf("sv=", start);
  return version !== -1 && start - version < 600 ? {} : false;
}

export const PREFIX_RULES: PrefixRule[] = [
  // Cloud providers
  {
    kind: "aws_access_key_id",
    prefixes: ["AKIA", "ASIA", "ABIA", "ACCA", "A3T"],
    pattern: sticky(
      "(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}",
      "(?![A-Za-z0-9])"
    ),
    prefix: 4,
    severity: "critical",
    confidence: 0.9,
    minEntropy: 2.5,
    minClasses: 1,
    refine: (v) => (v.startsWith("ASIA") ? { severity: "high" } : {}),
  },
  {
    kind: "aws_session_token",
    prefixes: ["IQoJb3JpZ2lu", "FwoGZXIvYXdz", "FQoGZXIvYXdz"],
    pattern: sticky(
      "(?:IQoJb3JpZ2lu|FwoGZXIvYXdz|FQoGZXIvYXdz)[A-Za-z0-9/+=]{100,2000}",
      "(?![A-Za-z0-9/+=])"
    ),
    prefix: 12,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "google_api_key",
    prefixes: ["AIza"],
    pattern: sticky("AIza[0-9A-Za-z_-]{35}"),
    prefix: 4,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "google_oauth_client_secret",
    prefixes: ["GOCSPX-"],
    pattern: sticky("GOCSPX-[A-Za-z0-9_-]{28}"),
    prefix: 7,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "google_oauth_access_token",
    prefixes: ["ya29."],
    pattern: sticky("ya29\\.[0-9A-Za-z_-]{30,2000}"),
    prefix: 5,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "digitalocean_token",
    prefixes: ["dop_v1_", "doo_v1_", "dor_v1_"],
    pattern: sticky("do[opr]_v1_[a-f0-9]{64}"),
    prefix: 7,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "heroku_api_key",
    prefixes: ["HRKU-"],
    pattern: sticky("HRKU-[A-Za-z0-9_-]{60}"),
    prefix: 5,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "flyio_token",
    prefixes: ["fo1_"],
    pattern: sticky("fo1_[A-Za-z0-9_-]{43}"),
    prefix: 4,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "vercel_token",
    prefixes: ["vck_", "vcp_", "vci_", "vca_", "vcr_"],
    pattern: sticky("vc[kpiar]_[A-Za-z0-9]{24,64}"),
    prefix: 4,
    severity: "high",
    confidence: 0.75,
  },
  {
    kind: "netlify_token",
    prefixes: ["nfp_"],
    pattern: sticky("nfp_[A-Za-z0-9]{36}"),
    prefix: 4,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "supabase_secret_key",
    prefixes: ["sb_secret_"],
    pattern: sticky("sb_secret_[A-Za-z0-9_-]{20,64}"),
    prefix: 10,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "planetscale_token",
    prefixes: ["pscale_"],
    pattern: sticky("pscale_(?:tkn|pw|oauth)_[A-Za-z0-9_.-]{32,64}"),
    prefix: 10,
    severity: "critical",
    confidence: 0.9,
  },
  {
    kind: "doppler_token",
    prefixes: ["dp."],
    pattern: sticky("dp\\.(?:pt|st|sa|ct|scim|audit)\\.[A-Za-z0-9]{40,44}"),
    prefix: 6,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "vault_token",
    prefixes: ["hvs.", "hvb.", "hvr."],
    pattern: sticky("hv[sbr]\\.[A-Za-z0-9_-]{24,400}"),
    prefix: 4,
    severity: "critical",
    confidence: 0.9,
  },
  {
    kind: "onepassword_service_account_token",
    prefixes: ["ops_eyJ"],
    pattern: sticky("ops_eyJ[A-Za-z0-9+/=_-]{100,2000}"),
    prefix: 4,
    severity: "critical",
    confidence: 0.9,
  },
  {
    kind: "age_secret_key",
    prefixes: ["AGE-SECRET-KEY-1"],
    pattern: sticky("AGE-SECRET-KEY-1[0-9A-Z]{58}"),
    prefix: 15,
    severity: "critical",
    confidence: 0.97,
    minClasses: 1,
  },
  // AI providers
  {
    kind: "anthropic_api_key",
    kinds: [
      "anthropic_api_key",
      "anthropic_admin_key",
      "anthropic_oauth_token",
    ],
    prefixes: ["sk-ant-"],
    pattern: sticky(
      "sk-ant-(?:api|admin|oat|ort|sid)\\d{2}-[A-Za-z0-9_-]{32,250}"
    ),
    prefix: 13,
    severity: "critical",
    confidence: 0.97,
    refine: refineAnthropic,
  },
  {
    kind: "openrouter_api_key",
    prefixes: ["sk-or-v1-"],
    pattern: sticky("sk-or-v1-[a-f0-9]{64}"),
    prefix: 9,
    severity: "critical",
    confidence: 0.97,
  },
  {
    kind: "openai_api_key",
    kinds: ["openai_api_key", "sk_api_key"],
    prefixes: ["sk-"],
    pattern: sticky(
      "sk-(?!ant-|or-v1-)(?:(?:proj|svcacct|admin|None)-)?[A-Za-z0-9_-]{20,250}"
    ),
    prefix: 3,
    severity: "critical",
    confidence: 0.92,
    refine: refineSkKey,
  },
  {
    kind: "groq_api_key",
    prefixes: ["gsk_"],
    pattern: sticky("gsk_[A-Za-z0-9]{52}"),
    prefix: 4,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "xai_api_key",
    prefixes: ["xai-"],
    pattern: sticky("xai-[A-Za-z0-9]{70,90}"),
    prefix: 4,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "huggingface_token",
    prefixes: ["hf_"],
    pattern: sticky("hf_[A-Za-z0-9]{30,40}"),
    prefix: 3,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "replicate_api_token",
    prefixes: ["r8_"],
    pattern: sticky("r8_[A-Za-z0-9]{37}"),
    prefix: 3,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "perplexity_api_key",
    prefixes: ["pplx-"],
    pattern: sticky("pplx-[A-Za-z0-9]{48}"),
    prefix: 5,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "pinecone_api_key",
    prefixes: ["pcsk_"],
    pattern: sticky("pcsk_[A-Za-z0-9_]{40,100}"),
    prefix: 5,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "langsmith_api_key",
    prefixes: ["lsv2_"],
    pattern: sticky("lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}"),
    prefix: 8,
    severity: "high",
    confidence: 0.95,
  },
  {
    kind: "together_api_key",
    prefixes: ["tgp_v1_"],
    pattern: sticky("tgp_v1_[A-Za-z0-9_-]{40,64}"),
    prefix: 7,
    severity: "high",
    confidence: 0.9,
  },
  // Source control, package registries, developer tools
  {
    kind: "github_pat",
    kinds: Object.values(GITHUB_KINDS),
    prefixes: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
    pattern: sticky("gh[pousr]_[A-Za-z0-9]{36,251}"),
    prefix: 4,
    severity: "critical",
    confidence: 0.95,
    refine: (v) => ({ kind: GITHUB_KINDS[v.slice(0, 4)] }),
  },
  {
    kind: "github_fine_grained_pat",
    prefixes: ["github_pat_"],
    pattern: sticky("github_pat_[A-Za-z0-9_]{80,90}"),
    prefix: 11,
    severity: "critical",
    confidence: 0.97,
  },
  {
    kind: "gitlab_pat",
    kinds: ["gitlab_pat", "gitlab_token"],
    prefixes: [
      "glpat-",
      "gldt-",
      "glrt-",
      "glptt-",
      "glsoat-",
      "glcbt-",
      "glft-",
    ],
    pattern: sticky("gl(?:pat|dt|rt|ptt|soat|cbt|ft)-[A-Za-z0-9_-]{20,80}"),
    prefix: 6,
    severity: "critical",
    confidence: 0.95,
    refine: (v) =>
      v.startsWith("glpat-")
        ? {}
        : {
            kind: "gitlab_token",
            severity: "high",
            prefix: v.indexOf("-") + 1,
          },
  },
  {
    kind: "npm_token",
    prefixes: ["npm_"],
    pattern: sticky("npm_[A-Za-z0-9]{36}"),
    prefix: 4,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "pypi_token",
    prefixes: ["pypi-Ag"],
    pattern: sticky(
      "pypi-Ag(?:EIcHlwaS5vcmc|ENdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,300}"
    ),
    prefix: 5,
    severity: "critical",
    confidence: 0.97,
  },
  {
    kind: "docker_hub_token",
    prefixes: ["dckr_pat_"],
    pattern: sticky("dckr_pat_[A-Za-z0-9_-]{27}"),
    prefix: 9,
    severity: "high",
    confidence: 0.95,
  },
  {
    kind: "databricks_token",
    prefixes: ["dapi"],
    pattern: sticky("dapi[a-f0-9]{32}(?:-\\d)?"),
    prefix: 4,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "sentry_auth_token",
    prefixes: ["sntrys_", "sntryu_"],
    pattern: sticky("sntry[su]_[A-Za-z0-9+/=_]{40,400}"),
    prefix: 7,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "atlassian_api_token",
    prefixes: ["ATATT3"],
    pattern: sticky("ATATT3[A-Za-z0-9_=-]{150,250}"),
    prefix: 6,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "linear_api_key",
    prefixes: ["lin_api_"],
    pattern: sticky("lin_api_[A-Za-z0-9]{40}"),
    prefix: 8,
    severity: "high",
    confidence: 0.95,
  },
  {
    kind: "notion_token",
    prefixes: ["ntn_", "secret_"],
    pattern: sticky("ntn_[A-Za-z0-9]{40,50}|secret_[A-Za-z0-9]{43}"),
    prefix: 4,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "postman_api_key",
    prefixes: ["PMAK-"],
    pattern: sticky("PMAK-[a-f0-9]{24}-[a-f0-9]{34}"),
    prefix: 5,
    severity: "high",
    confidence: 0.95,
  },
  {
    kind: "figma_token",
    prefixes: ["figd_"],
    pattern: sticky("figd_[A-Za-z0-9_-]{40}"),
    prefix: 5,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "airtable_token",
    prefixes: ["pat"],
    pattern: sticky("pat[A-Za-z0-9]{14}\\.[a-f0-9]{64}"),
    prefix: 3,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "grafana_token",
    prefixes: ["glsa_", "glc_"],
    pattern: sticky(
      "glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}|glc_[A-Za-z0-9+/]{32,400}={0,2}"
    ),
    prefix: 4,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "new_relic_api_key",
    prefixes: ["NRAK-"],
    pattern: sticky("NRAK-[A-Z0-9]{27}"),
    prefix: 5,
    severity: "high",
    confidence: 0.9,
    minClasses: 1,
  },
  // Payments, messaging, email
  {
    kind: "stripe_secret_key",
    kinds: ["stripe_secret_key", "stripe_restricted_key", "stripe_test_key"],
    prefixes: ["sk_live_", "rk_live_", "sk_test_", "rk_test_"],
    pattern: sticky("[sr]k_(?:live|test)_[A-Za-z0-9]{24,247}"),
    prefix: 8,
    severity: "critical",
    confidence: 0.95,
    refine: refineStripe,
  },
  {
    kind: "stripe_webhook_secret",
    prefixes: ["whsec_"],
    pattern: sticky("whsec_[A-Za-z0-9+/=]{32,100}"),
    prefix: 6,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "square_access_token",
    kinds: ["square_access_token", "square_oauth_secret"],
    prefixes: ["EAAA", "sq0atp-", "sq0csp-"],
    pattern: sticky(
      "EAAA[A-Za-z0-9_-]{60}|sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43}"
    ),
    prefix: 4,
    severity: "critical",
    confidence: 0.85,
    refine: (v) =>
      v.startsWith("sq0csp-")
        ? { kind: "square_oauth_secret", prefix: 7 }
        : { prefix: v.startsWith("sq0") ? 7 : 4 },
  },
  {
    kind: "shopify_token",
    prefixes: ["shpat_", "shpss_", "shpca_", "shppa_"],
    pattern: sticky("shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}"),
    prefix: 6,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "sendgrid_api_key",
    prefixes: ["SG."],
    pattern: sticky("SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"),
    prefix: 3,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "mailgun_api_key",
    prefixes: ["key-"],
    pattern: sticky("key-[0-9a-f]{32}"),
    prefix: 4,
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "resend_api_key",
    prefixes: ["re_"],
    pattern: sticky("re_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}"),
    prefix: 3,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "slack_token",
    kinds: [
      "slack_token",
      "slack_bot_token",
      "slack_user_token",
      "slack_app_token",
    ],
    prefixes: [
      "xoxb-",
      "xoxp-",
      "xoxa-",
      "xoxr-",
      "xoxs-",
      "xoxe",
      "xoxo-",
      "xapp-",
    ],
    pattern: sticky(
      "xox[abeoprs](?:\\.xox[abeoprs])?-[0-9A-Za-z-]{20,250}|xapp-\\d-[A-Z0-9]{8,12}-\\d{10,16}-[A-Za-z0-9]{40,80}"
    ),
    prefix: 5,
    severity: "critical",
    confidence: 0.9,
    refine: refineSlack,
  },
  {
    kind: "slack_webhook",
    prefixes: ["https://hooks.slack.com/"],
    pattern: sticky(
      "https://hooks\\.slack\\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,150}"
    ),
    prefix: 0,
    severity: "high",
    confidence: 0.9,
    refine: lastSegment,
  },
  {
    kind: "discord_bot_token",
    // Base64 of the bot's numeric id: "1…" encodes as "MT", "2…" as "Mj", and so on.
    prefixes: ["MT", "Mj", "Mz", "ND", "NT", "Nj", "Nz", "OD", "OT"],
    pattern: sticky(
      "[MNO][A-Za-z0-9_-]{23,27}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,40}"
    ),
    prefix: 0,
    severity: "critical",
    confidence: 0.9,
    refine: refineDiscordToken,
  },
  {
    kind: "discord_webhook",
    prefixes: [
      "https://discord",
      "https://ptb.discord",
      "https://canary.discord",
    ],
    pattern: sticky(
      "https://(?:(?:ptb|canary)\\.)?discord(?:app)?\\.com/api/webhooks/\\d{17,20}/[A-Za-z0-9_-]{60,80}"
    ),
    prefix: 0,
    severity: "high",
    confidence: 0.95,
    refine: lastSegment,
  },
  {
    kind: "mapbox_secret_token",
    prefixes: ["sk.eyJ"],
    pattern: sticky("sk\\.eyJ[A-Za-z0-9_-]{50,300}\\.[A-Za-z0-9_-]{20,100}"),
    prefix: 3,
    severity: "high",
    confidence: 0.9,
  },
];

export const GATED_RULES: GatedRule[] = [
  {
    kind: "azure_storage_account_key",
    gates: ["ccountKey", "ccountkey"],
    window: [2, 100],
    pattern: /[Aa]ccount[Kk]ey\s{0,3}[=:]\s{0,3}["']?([A-Za-z0-9+/]{86}==)/g,
    prefix: 0,
    severity: "critical",
    confidence: 0.95,
    minEntropy: 4.5,
  },
  {
    kind: "azure_shared_access_key",
    gates: ["SharedAccessKey"],
    window: [0, 60],
    pattern: /SharedAccessKey\s{0,3}=\s{0,3}([A-Za-z0-9+/]{43}=)/g,
    prefix: 0,
    severity: "critical",
    confidence: 0.9,
    minEntropy: 4,
  },
  {
    kind: "azure_sas_token",
    gates: ["sig="],
    window: [1, 130],
    pattern: /[?&;]sig=([A-Za-z0-9%+/=]{40,120})/g,
    prefix: 0,
    severity: "high",
    confidence: 0.85,
    refine: refineSas,
  },
  {
    kind: "azure_ad_client_secret",
    gates: ["Q~"],
    window: [5, 40],
    pattern: bounded(
      "[A-Za-z0-9_~.]{3}\\dQ~[A-Za-z0-9_~.-]{31,34}",
      "A-Za-z0-9_~.-"
    ),
    prefix: 0,
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "terraform_cloud_token",
    gates: [".atlasv1."],
    window: [15, 75],
    pattern: bounded("[A-Za-z0-9]{14}\\.atlasv1\\.[A-Za-z0-9_=-]{60,70}"),
    prefix: 0,
    severity: "critical",
    confidence: 0.95,
  },
  {
    kind: "telegram_bot_token",
    gates: [":AA"],
    window: [11, 40],
    pattern:
      /(?:^|[^A-Za-z0-9_:])(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])/g,
    prefix: 0,
    severity: "critical",
    confidence: 0.9,
  },
  {
    kind: "firebase_cloud_messaging_key",
    gates: [":APA91b"],
    window: [12, 140],
    pattern: bounded("AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{134}"),
    prefix: 0,
    severity: "high",
    confidence: 0.9,
  },
  {
    kind: "mailchimp_api_key",
    gates: ["-us"],
    window: [33, 4],
    pattern: bounded("[0-9a-f]{32}-us\\d{1,2}"),
    prefix: 0,
    severity: "high",
    confidence: 0.85,
  },
];

const BASE64_40 = /(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/g;
const HEX_32 = bounded("[a-f0-9]{32}", "A-Za-z0-9");
const PATH_LIKE = /^[A-Za-z]{3,}(?:\/[A-Za-z]{3,}){2,}$/;

export const CONTEXT_RULES: ContextRule[] = [
  {
    kind: "aws_secret_access_key",
    words: ["aws", "secretaccesskey", "secret_access_key", "secret-access-key"],
    pattern: BASE64_40,
    severity: "critical",
    confidence: 0.85,
    minEntropy: 4,
    minClasses: 3,
    reject: (v) => PATH_LIKE.test(v),
  },
  {
    kind: "twilio_api_key",
    words: ["twilio"],
    pattern: bounded("SK[0-9a-fA-F]{32}", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.9,
    requireKeyWord: false,
    maxDistance: 300,
  },
  {
    kind: "twilio_account_sid",
    words: ["twilio"],
    pattern: bounded("AC[0-9a-f]{32}", "A-Za-z0-9"),
    severity: "low",
    confidence: 0.8,
    requireKeyWord: false,
    maxDistance: 300,
  },
  {
    kind: "twilio_auth_token",
    words: ["twilio"],
    pattern: HEX_32,
    severity: "critical",
    confidence: 0.85,
    maxDistance: 60,
  },
  {
    kind: "cohere_api_key",
    words: ["cohere", "co_api_key"],
    pattern: bounded("[A-Za-z0-9]{40}", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "mistral_api_key",
    words: ["mistral"],
    pattern: bounded("[A-Za-z0-9]{32}", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "together_api_key",
    words: ["together"],
    pattern: bounded("[a-f0-9]{64}", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.75,
  },
  {
    kind: "deepgram_api_key",
    words: ["deepgram"],
    pattern: bounded("[a-f0-9]{40}", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "elevenlabs_api_key",
    words: ["elevenlabs", "xi-api-key", "xi_api_key"],
    pattern: bounded("sk_[a-f0-9]{48}|[a-f0-9]{32}", "A-Za-z0-9_"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "assemblyai_api_key",
    words: ["assemblyai", "assembly_ai"],
    pattern: HEX_32,
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "fireworks_api_key",
    words: ["fireworks"],
    pattern: bounded("fw_[A-Za-z0-9]{20,40}", "A-Za-z0-9_"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "voyage_api_key",
    words: ["voyage"],
    pattern: bounded("pa-[A-Za-z0-9_-]{40,50}"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "datadog_api_key",
    words: [
      "datadog",
      "dd_api_key",
      "dd-api-key",
      "dd_app_key",
      "dd-application-key",
    ],
    pattern: bounded("[a-f0-9]{32}(?:[a-f0-9]{8})?", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "cloudflare_api_token",
    words: [
      "cloudflare",
      "cf_api_token",
      "cf-api-token",
      "cf_api_key",
      "x-auth-key",
    ],
    pattern: bounded("[A-Za-z0-9_-]{40}|[a-f0-9]{37}"),
    severity: "high",
    confidence: 0.8,
  },
  {
    kind: "vercel_token",
    words: ["vercel"],
    pattern: bounded("[A-Za-z0-9]{24}", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.75,
  },
  {
    kind: "azure_api_key",
    words: ["azure", "ocp-apim-subscription-key"],
    pattern: bounded("[a-f0-9]{32}|[A-Za-z0-9]{84}", "A-Za-z0-9"),
    severity: "high",
    confidence: 0.75,
  },
  {
    kind: "heroku_api_key",
    words: ["heroku"],
    pattern: bounded(
      "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
      "A-Za-z0-9-"
    ),
    severity: "high",
    confidence: 0.75,
  },
  {
    kind: "mailgun_api_key",
    words: ["mailgun"],
    pattern: bounded("[0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8}", "A-Za-z0-9-"),
    severity: "high",
    confidence: 0.85,
  },
  {
    kind: "algolia_admin_key",
    words: ["algolia"],
    pattern: HEX_32,
    severity: "high",
    confidence: 0.75,
  },
];
