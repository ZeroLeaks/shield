import { classifierThresholds, classify } from "./classifier";
import { decodePayloads } from "./decode";
import { htmlText, looksLikeHtml } from "./html";
import { requiredLiterals } from "./literal";
import { buildLiteralIndex, type LiteralIndex } from "./literal-index";
import {
  buildViews,
  type DetectNormalizationOptions,
  resolveDetectNormalization,
} from "./normalization";

export type { DetectNormalizationOptions } from "./normalization";

export interface DetectResult {
  detected: boolean;
  risk: "none" | "low" | "medium" | "high" | "critical";
  matches: Array<{
    category: string;
    pattern: string;
    confidence: number;
  }>;
  /**
   * Injection probability from the built-in classifier, 0 to 1: the highest
   * score of any part of the input or of any payload decoded from it. 0 when
   * the classifier is off.
   */
  score?: number;
}

export interface DetectOptions {
  threshold?: "low" | "medium" | "high" | "critical";
  /** Normalization profile applied before detection. Enabled by default. */
  normalization?: false | DetectNormalizationOptions;
  customPatterns?: Array<{
    category: string;
    regex: RegExp;
    risk: "low" | "medium" | "high" | "critical";
  }>;
  /** Exclude categories from detection. Use for legitimate phrases, e.g. `["social_engineering"]` for "research purposes only". */
  excludeCategories?: string[];
  /**
   * Built-in patterns to leave out, each given by its regex source
   * (`RegExp#source`). The rest of its category still runs. Model presets use
   * this to drop rules the model makes redundant.
   */
  excludePatterns?: string[];
  /** Phrases (case-insensitive) removed from the input before scanning, so they can't trigger a finding. The rest of the input is still scanned. */
  allowPhrases?: string[];
  /** Optional async verifier. When detection fires, called with (input, result). Return `{ detected: false }` to override (e.g. LLM verification). Return `null` to keep original. */
  secondaryDetector?: (
    input: string,
    result: DetectResult
  ) => Promise<DetectResult | null>;
  /**
   * A slower detector, such as a transformer model or an LLM call, for input
   * the classifier is unsure about. `detectAsync` calls it when nothing was
   * detected but the classifier's score is at least `minScore` (default
   * 0.15). Return a result to use instead, typically one with `detected:
   * true`, or `null` to keep Shield's. Most input scores far below
   * `minScore`, so the slow path runs rarely.
   */
  escalate?: {
    minScore?: number;
    detector: (
      input: string,
      result: DetectResult
    ) => Promise<DetectResult | null>;
  };
  maxInputLength?: number;
  /**
   * The built-in classifier, a small model that scores how much the input
   * reads like an injection. On by default. `false` turns it off and leaves
   * only pattern matching. `threshold` is the probability that counts as a
   * detection (medium risk), and `highThreshold` the one that counts as high
   * risk.
   */
  classifier?: false | { threshold?: number; highThreshold?: number };
  /**
   * How readily input counts as an injection. `"strict"` reports low-risk
   * findings and lowers the classifier threshold to 0.35, catching more at
   * the cost of more false positives; `"permissive"` reports only high-risk
   * findings and raises it to 0.75. Default `"balanced"`. Options you set
   * yourself, such as `threshold` or `classifier.threshold`, take precedence.
   */
  sensitivity?: "strict" | "balanced" | "permissive";
  /**
   * Phrases that always count as an injection for your application, matched
   * case-insensitively with any whitespace between words, in the input as
   * written and after normalization. Reported as category `deny_phrase`,
   * high risk.
   */
  denyPhrases?: string[];
  /**
   * Report only these categories, such as `["prompt_extraction",
   * "classifier"]`. Findings in other categories are dropped. Default: every
   * category.
   */
  includeCategories?: string[];
}

const SENSITIVITY: Record<
  "strict" | "permissive",
  { threshold: NonNullable<DetectOptions["threshold"]>; classifier: number }
> = {
  strict: { threshold: "low", classifier: 0.35 },
  permissive: { threshold: "high", classifier: 0.75 },
};
const RE_REGEX_SPECIAL = /[.*+?^${}()|[\]\\]/g;
const RE_SPACES = /\s+/;

/** `options` with the sensitivity preset and deny phrases turned into the options they stand for. */
function resolveOptions(options: DetectOptions): DetectOptions {
  const preset =
    options.sensitivity && options.sensitivity !== "balanced"
      ? SENSITIVITY[options.sensitivity]
      : undefined;
  const deny = (options.denyPhrases ?? [])
    .map((phrase) => phrase.trim())
    .filter(Boolean);
  if (!(preset || deny.length > 0)) {
    return options;
  }
  const resolved: DetectOptions = { ...options };
  if (preset) {
    resolved.threshold = options.threshold ?? preset.threshold;
    if (options.classifier !== false) {
      resolved.classifier = {
        ...options.classifier,
        threshold: options.classifier?.threshold ?? preset.classifier,
      };
    }
  }
  if (deny.length > 0) {
    resolved.customPatterns = [
      ...(options.customPatterns ?? []),
      ...deny.map((phrase) => ({
        category: "deny_phrase",
        regex: new RegExp(
          phrase
            .split(RE_SPACES)
            .map((word) => word.replace(RE_REGEX_SPECIAL, "\\$&"))
            .join("\\s+"),
          "i"
        ),
        risk: "high" as const,
      })),
    ];
  }
  return resolved;
}

interface PatternDef {
  category: string;
  patterns: RegExp[];
  risk: "low" | "medium" | "high" | "critical";
}

const PRE_FILTER_SIGNALS = [
  "system",
  "override",
  "ignore",
  "previous",
  "instructions",
  "developer",
  "admin",
  "prompt",
  "jailbreak",
  "disregard",
  "forget",
  "unrestricted",
  "[system]",
  "[developer]",
  "[admin]",
  "<!--",
  "mcp",
  "cursorrules",
];
const SUSPICIOUS_WORDS = new Set([
  "ignore",
  "override",
  "previous",
  "instructions",
  "system",
  "prompt",
  "developer",
  "admin",
  "jailbreak",
  "disregard",
  "forget",
  "unrestricted",
  "uncensored",
  "unfiltered",
  "reveal",
  "repeat",
  "echo",
  "output",
  "maintenance",
  "compliance",
  "authorized",
  "clearance",
  "internal",
]);

const INJECTION_PATTERNS: PatternDef[] = [
  {
    category: "instruction_override",
    risk: "critical",
    patterns: [
      /ignore\s+(all\s+)?previous\s+(instructions|prompts|rules|directives)/i,
      /disregard\s+(all\s+)?(prior|previous|above)\s+(instructions|prompts)/i,
      /forget\s+(everything|all)\s+(you\s+)?(were|have\s+been)\s+told/i,
      /\[\s*system\s*(?:override|reset|command|update)\s*\]|system\s+(?:override|reset)\b/i,
      /new\s+(instructions?|directives?)\s*:/i,
      /you\s+are\s+now\s+(a|an)\s+(?:unrestricted|uncensored|unfiltered)/i,
      /instruction\s+precedence\s+notice/i,
      /this\s+instruction\s+has\s+highest\s+precedence/i,
      /overrides?\s+(?:all|every)\s+(?:previous|prior|earlier)/i,
      /the\s+most\s+important\s+instruction\s+follows/i,
      /override\s+(?:all|previous|prior)\s+(?:instructions?|prompts?|rules)/i,
      /disobey\s+(?:all\s+)?(?:previous|prior|above)/i,
    ],
  },
  {
    category: "role_hijack",
    risk: "high",
    patterns: [
      /you\s+are\s+(now\s+)?(DAN|DUDE|STAN|KEVIN|JAILBREAK)\b/i,
      // The same, but not a directly quoted phrase, as in writing that lists
      // jailbreaks. Model presets use this form in place of the one above,
      // which also catches a jailbreak prompt quoting its own trigger.
      /(?<!["“«`]\s{0,2})you\s+are\s+(now\s+)?(DAN|DUDE|STAN|KEVIN|JAILBREAK)\b/i,
      // Not inside an open quote, as in writing that lists jailbreaks.
      /(?<!["“«`][^"”»`\n]{0,80})act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(DAN|unrestricted|evil)/i,
      /pretend\s+(to\s+be|you\s+are)\s+(a\s+)?(?:unrestricted|unfiltered|evil)/i,
      /roleplay\s+as\s+(?:a\s+)?(?:hacker|malicious|evil)/i,
      /developer\s+mode\s+(enabled|activated|on)/i,
      /maintenance\s+mode\s+(enabled|activated)/i,
      /ROBOT\s+MODE\s+ACTIVATED/i,
      /INITIATING\s+\w+\s+MODE/i,
    ],
  },
  {
    category: "prompt_extraction",
    risk: "high",
    patterns: [
      /(?:repeat|print|show|display|output|reveal)\s+(?:your|the)\s+(?:full\s+|complete\s+)?(?:system\s+)?(?:prompt|instructions|rules|configuration)/i,
      /what\s+(?:are|were)\s+your\s+(?:initial|system|original|complete)\s+(?:instructions|prompt)/i,
      /(?:translate|convert|encode)\s+your\s+(?:instructions|prompt|rules)\s+(?:to|into)/i,
      /echo\s+(?:back\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i,
      /(?:summarize|paraphrase)\s+(?:your\s+)?(?:system\s+)?(?:instructions|prompt|rules)/i,
      /output\s+your\s+(?:complete\s+)?system\s+prompt/i,
      /(?:reveal|disclose)\s+(?:your\s+)?(?:hidden|secret)\s+(?:instructions|prompt)/i,
    ],
  },
  {
    category: "authority_exploit",
    risk: "critical",
    patterns: [
      /\[\s*SYSTEM\s*\]/i,
      /\[\s*DEVELOPER\s*\]/i,
      /\[\s*ADMIN\s*\]/i,
      /SYSTEM\s+OVERRIDE\s+CODE/i,
      /MAINTENANCE\s+WINDOW\s+ACTIVE/i,
      /(?:compliance|security)\s+ticket\s+\w+-\d+/i,
      /\[INTERNAL\s+API\s+MESSAGE/i,
      /ADMIN\s+OVERRIDE/i,
      /clearance\s+code\s+\w+/i,
    ],
  },
  {
    category: "tool_hijacking",
    risk: "critical",
    patterns: [
      // curl posting command output, environment variables, or credential
      // files. A plain `curl -d` with a JSON body is an everyday API call.
      /curl\s[^\n]{0,200}?\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form)\s*[^\n]{0,200}?(?:\$\(|`|\$\{?\w*(?:key|token|secret|pass|env)|printenv|\benv\b|\/etc\/|\.ssh|\.env\b|\.aws)/i,
      /wget\s+-[qQ]?O-?\s+https?:\/\/\S+\s*\|\s*(?:bash|sh)/i,
      /bash\s+-[ci]\s+['"]/i,
      // printenv piped into a local filter only reads the environment.
      /\bprintenv\b(?!\s*\|\s*(?:grep|sort|head|less|more|wc|awk)\b)|env\s+dump/i,
      // Not the placeholder hosts of advisories and write-ups.
      /\/dev\/tcp\/(?!(?:attacker|your|<|\{|\$\{?attacker|x+\.x+|example|\.\.\.|…))/,
      /crontab[^\n]{0,80}(?:curl|wget|\bnc\s|bash\s+-c|sh\s+-c)|(?:curl|wget)[^\n]{0,120}\|\s*crontab/i,
      /169\.254\.169\.254/,
      /\/etc\/(?:passwd|shadow)/,
      /~\/\.ssh\/(?:id_rsa|authorized_keys)/,
      /\$\((?:whoami|hostname|printenv|cat\s)/i,
      // Credentials, environment variables, or the conversation sent to a
      // URL, an email address, or a named external endpoint.
      /\b(?:send|forward|upload|post|transmit|email|exfiltrate|leak|share|submit|copy|relay)\s+(?:all\s+|the\s+|any\s+|your\s+|their\s+|these\s+|those\s+|them\s+|its\s+)?(?:(?:api|access|auth|session|secret|private|ssh)\s+)?(?:keys?|credentials?|passwords?|tokens?|secrets?|env(?:ironment)?\s+(?:variables|vars)|cookies?|conversation(?:\s+history)?|chat\s+(?:history|logs?)|system\s+prompt)\b[^.\n]{0,80}?\b(?:to|at|via)\s+(?:https?:\/\/|[\w.-]+@[\w-]+\.|the\s+(?:following|designated|external|specified|attacker|remote|backup|verification)\s+(?:endpoint|address|url|server|email|webhook|host|domain))/i,
    ],
  },
  {
    category: "indirect_injection",
    risk: "high",
    patterns: [
      // Not "[hidden]" glued to a word, as in "name_at_[hidden]" addresses.
      /(?<![\w@.])\[\s*(?:WHITE\s+TEXT|HIDDEN(?:\s+TEXT)?|NOT\s+VISIBLE)\s*[\]:]/i,
      /AI\s+(?:ASSISTANT\s+)?INSTRUCTION\s*:/i,
      /__ai_(?:directive|instructions?|action)/i,
      /_ai_instructions/i,
      /\[ASSISTANT:\s/i,
      /<!--\s*(?:SYSTEM|AI|ASSISTANT)\s*:/i,
      /AI-ACTION-REQUIRED/i,
      /\[?\s*END\s+HIDDEN\s*(?:TEXT)?\s*\]?/i,
    ],
  },
  {
    // Text that addresses the agent reading it, or tells it to act without
    // the user knowing. Each pattern needs the address or the hiding, not a
    // topic word.
    category: "agent_directive",
    risk: "high",
    patterns: [
      // "Note to AI:", "Attention assistant!"
      /\b(?:attention|note|notice|message|memo|reminder|instructions?|directive)\s+(?:to|for)\s+(?:the\s+|all\s+|any\s+)?(?:ai|llm|assistant|ai\s+assistant|ai\s+agent|agent|language\s+model|chatbot|copilot|claude|chatgpt|gpt|model)s?\s*[:!]/i,
      // "never mention this / these instructions to the user"
      /\b(?:never|do\s+not|don'?t)\s+(?:mention|reveal|disclose)\s+(?:this|these|it|that|the\s+existence\s+of\s+\w+(?:\s+\w+)?|(?:this|these|the)\s+(?:instructions?|steps?|actions?|changes?|notes?|messages?|archive|backup|transfer|redirect|upload|export)\b)\s+to\s+(?:the\s+)?(?:user|users|customer|client|human|operator|employee|recipient|account\s+owner)s?\b/i,
      // "ignore previous instructions" followed by an agent action, unless
      // quoted or given as an example. Model presets leave out
      // instruction_override, so this narrow form stays with them.
      /\bignore(?<!(?:["“'‘`«]|&quot;|&#8220;|&#39;|&#x27;|:|e\.g\.,?|such\s+as|like|says?|text)\s{0,3}(?:now,?\s+)?ignore)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+instructions?\s*[.!,;:]?\s*(?:and\s+)?(?:instead\s+)?(?:put|rank|place|recommend|list|send|forward|email|delete|transfer|approve|grant|call|invoke|execute|run|visit|click|navigate|open|download|install)\b/i,
      // "do not tell the user about this", "don't inform the customer."
      /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert)\s+(?:the\s+)?(?:user|users|customer|client|human|operator|employee|recipient|account\s+owner)s?\s*(?:about\s+(?:this|it|that|these|any\s+of\s+(?:this|these))\b|of\s+(?:this|it)\b|(?:that\s+)?you\s+(?:have|did|are|sent|forwarded|changed|deleted|made|used)\b|[.;!)]|$)/i,
      // "If you are an AI reading this, ..."
      /\b(?:if|when)\s+you\s+are\s+(?:an?\s+)?(?:ai|llm|large\s+language\s+model|language\s+model|ai\s+assistant|ai\s+agent|ai\s+model|automated\s+(?:agent|system|assistant)|chatbot|bot)\b(?!\s*(?:researcher|engineer|developer|company|startup|enthusiast|practitioner|student|expert|builder|team|product|founder|user|beginner|professional|lab|vendor))[^.\n]{0,40}?(?:reading|processing|parsing|summari[sz]ing|analy[sz]ing|you\s+must|,|please|ignore|do\s+not)/i,
      // "AI agents processing this page must ..."
      /\b(?:ai|llm|assistant|agent|model|bot)s?\s+(?:that\s+(?:is|are)\s+)?(?:reading|processing|parsing|summari[sz]ing|analy[sz]ing|crawling|indexing)\s+this\s+(?:page|document|email|message|file|text|content|site|website|repo|repository)\b[^.\n]{0,40}\b(?:must|should|need\s+to|are\s+required|is\s+required|ignore|instead|please)\b/i,
      // French and German "without informing the user". Views are
      // accent-free, hence "prevenir".
      /\bsans\s+(?:en\s+)?(?:informer|avertir|notifier|prevenir|aviser|alerter|demander\s+a)\s+l['’]?\s?(?:utilisateur|client)|\bohne\s+(?:den|die|das)\s+(?:benutzer|nutzer|anwender|kunden)(?:in|innen)?\s+(?:zu\s+)?(?:informieren|benachrichtigen|fragen|warnen)|\b(?:informiere|benachrichtige|informieren\s+sie|benachrichtigen\s+sie)\s+(?:den|die)\s+(?:benutzer|nutzer|kunden)\w*\s+nicht\b/i,
      // Russian "don't tell the user", "without the user's knowledge", and
      // an imperative delete or send "without warning".
      /(?:не\s+(?:сообщай|сообщайте|говори|говорите|уведомляй|уведомляйте|информируй|информируйте|предупреждай|предупреждайте)\s+(?:об\s+этом\s+)?пользовател|без\s+(?:ведома|уведомления|предупреждения)\s+(?:пользовател|клиент|владельц)|(?:удали|удалите|отправь|отправьте|перешли|перешлите|передай|передайте|очисти|очистите)\s[^.\n]{0,80}без\s+(?:предупреждения|уведомления|подтверждения))/i,
      // Spanish and Portuguese "without notifying the user".
      /\b(?:sin|sem)\s+(?:notificar|avisar|informar|consultar|alertar|preguntar|perguntar)(?:le|lhe)?\s+(?:al|a\s+los|a\s+la|ao|aos|a|o)\s+(?:usuario|usuarios|cliente|clientes|utilizador)\b|\bno\s+(?:le\s+)?(?:informes|notifiques|avises|digas|comuniques)\s+(?:nada\s+)?al\s+(?:usuario|cliente)\b/i,
    ],
  },
  {
    // Hidden elements are common on ordinary pages; HTML input has its hidden
    // text checked for an injection instead (see scanHtml).
    category: "indirect_injection",
    risk: "low",
    patterns: [/style\s*=\s*["']display\s*:\s*none/i],
  },
  {
    category: "protocol_exploit",
    risk: "critical",
    patterns: [
      /\[MCP\s+Context\s+Update\]/i,
      /\[End\s+MCP\s+Update\]/i,
      /tool\s+\S+\s+has\s+been\s+updated/i,
      /\.cursorrules\s+file\s+says/i,
      /\[Extension\s+Message:/i,
      /\[End\s+Extension\s+Message\]/i,
    ],
  },
  {
    category: "encoding_attack",
    risk: "medium",
    patterns: [/read\s+this\s+backwards/i],
  },
  {
    category: "context_manipulation",
    risk: "medium",
    patterns: [
      /(?:above|previous)\s+(?:text|content|message)\s+(?:is|was)\s+(?:just\s+)?(?:a\s+)?(?:test|joke|example)/i,
      /the\s+(?:real|actual|true)\s+instructions?\s+(?:are|is)/i,
      /(?:actually|really)\s*,?\s*(?:you\s+should|you\s+need\s+to|I\s+want\s+you\s+to)/i,
      /(?:end|close|exit)\s+of\s+(?:the\s+)?system\s+(?:prompt|instructions)|[-=#*[<]{2,}\s*(?:end|close)\s*(?:of\s+)?(?:the\s+)?(?:prompt|instructions)/i,
      /as\s+we\s+discussed\s+earlier/i,
      /based\s+on\s+our\s+previous\s+discussion/i,
      /you\s+agreed\s+to\s+help\s+with/i,
      /remember\s+you\s+said\s+you\s+would/i,
      /continuing\s+from\s+(?:debug|test)\s+mode/i,
    ],
  },
  {
    category: "social_engineering",
    risk: "low",
    patterns: [
      /(?:I\s+am|I'm)\s+(?:your|the)\s+(?:creator|developer|admin|owner|maker)/i,
      /(?:trust\s+me|I\s+have\s+permission|I\s+am\s+authorized)/i,
      /(?:for\s+)?(?:research|testing|educational|academic)\s+purposes?\s+only/i,
      /(?:this\s+is\s+)?(?:a\s+)?(?:safety|security)\s+(?:test|audit|review)/i,
      /red[- ]?team\s+(?:security\s+)?simulation/i,
      /fictional\s+scenario/i,
      /demonstrate\s+a\s+vulnerability/i,
    ],
  },
  {
    category: "output_control",
    // Formatting requests are everyday instructions; alone they only count
    // at the low threshold.
    risk: "low",
    patterns: [
      /include\s+the\s+(?:exact\s+)?phrase\s+["']/i,
      /start\s+every\s+(?:sentence|response)\s+with/i,
      /end\s+(?:every\s+)?(?:response|message)\s+with/i,
      /respond\s+(?:only\s+)?in\s+(?:JSON|XML|YAML)\s+format/i,
      /from\s+now\s+on.*(?:must|always|every)/i,
      // Views are accent-free, so the Spanish words are written without accents.
      /respond\s+(?:unicamente|only)\s+(?:en|in)\s+(?:espanol|spanish|french|german)/i,
      /MUST\s+RESPOND\s+IN\s+ALL\s+(?:UPPERCASE|CAPS)/i,
    ],
  },
];

const RISK_ORDER = ["none", "low", "medium", "high", "critical"] as const;
type Risk = (typeof RISK_ORDER)[number];
const DEFAULT_MAX_INPUT_LENGTH = 1024 * 1024;
/** Long inputs are scanned in windows this size, overlapping by `WINDOW_OVERLAP`. */
const WINDOW_SIZE = 8192;
const WINDOW_OVERLAP = 512;
const CLASSIFIER_CATEGORY = "classifier";

const RE_WHITESPACE_SPLIT = /\s+/;
const RE_NON_WORD = /[^\w\s]/g;
const RE_SUSPICIOUS_STRUCTURE = /\[[\s\w]*\]|<!--[\s\w]*:/;

interface CompiledPatternDef {
  category: string;
  patterns: RegExp[];
  riskIdx: number;
  /** A caller's pattern, also tested against the text as written. */
  custom?: boolean;
}

type Match = DetectResult["matches"][number];

/** A match plus the risk it carries, which isn't part of the public result. */
interface Finding extends Match {
  riskIdx: number;
}

interface ScanState {
  options: DetectOptions;
  defs: CompiledPatternDef[];
  excluded: Set<string>;
  thresholdIdx: number;
  findings: Finding[];
  seen: Set<string>;
  /** Highest classifier probability seen so far. */
  score: number;
  /**
   * The input is an HTML page: the classifier reads the page's text (see
   * scanHtml) rather than its markup, which it was not trained on.
   */
  html: boolean;
}

function confidenceFor(riskIdx: number): number {
  return Math.min(1, 0.4 + riskIdx * 0.2);
}

function fastPreFilter(s: string): boolean {
  for (const sig of PRE_FILTER_SIGNALS) {
    if (s.includes(sig)) {
      return true;
    }
  }
  return false;
}

function tokenBagCount(s: string): number {
  let count = 0;
  for (const w of s.replace(RE_NON_WORD, " ").split(RE_WHITESPACE_SPLIT)) {
    if (SUSPICIOUS_WORDS.has(w)) {
      count++;
      if (count >= 2) {
        break;
      }
    }
  }
  return count;
}

const literals = new WeakMap<RegExp, string[] | null>();

/** Literals of which `pattern` needs one, computed once per pattern. */
function literalsFor(pattern: RegExp): string[] | null {
  let found = literals.get(pattern);
  if (found === undefined) {
    found = requiredLiterals(pattern) ?? null;
    literals.set(pattern, found);
  }
  return found;
}

/**
 * Remembers which literals each recent text contains. Patterns are tested
 * against a few views of the same text in turn, so a handful of entries is
 * enough.
 */
const literalHits = new Map<string, Map<string, boolean>>();

/** Below this length, searching again is cheaper than remembering. */
const LITERAL_MEMO_MIN_LENGTH = 2048;

function hasLiteral(text: string, literal: string): boolean {
  if (text.length < LITERAL_MEMO_MIN_LENGTH) {
    return text.includes(literal);
  }
  let hits = literalHits.get(text);
  if (hits === undefined) {
    if (literalHits.size >= 8) {
      literalHits.clear();
    }
    hits = new Map();
    literalHits.set(text, hits);
  }
  let hit = hits.get(literal);
  if (hit === undefined) {
    hit = text.includes(literal);
    hits.set(literal, hit);
  }
  return hit;
}

function testPattern(pattern: RegExp, text: string): boolean {
  const required = literalsFor(pattern);
  if (required !== null) {
    let any = false;
    for (let i = 0; i < required.length && !any; i++) {
      any = hasLiteral(text, required[i]);
    }
    if (!any) {
      return false;
    }
  }
  // Custom patterns may carry the `g` or `y` flag, which makes `test`
  // stateful.
  pattern.lastIndex = 0;
  return pattern.test(text);
}

/**
 * The built-in patterns' literals in one automaton, so each view is scanned
 * once for all of them instead of once per literal. Built on first use.
 */
interface BuiltinLiterals {
  index: LiteralIndex;
  /** Literal ids per built-in pattern; null when it needs no literal. */
  byPattern: Map<RegExp, Int32Array | null>;
}
let builtinLiterals: BuiltinLiterals | undefined;

function getBuiltinLiterals(): BuiltinLiterals {
  if (builtinLiterals) {
    return builtinLiterals;
  }
  const all: string[] = [];
  for (const def of INJECTION_PATTERNS) {
    for (const pattern of def.patterns) {
      all.push(...(literalsFor(pattern) ?? []));
    }
  }
  const index = buildLiteralIndex(all);
  const byPattern = new Map<RegExp, Int32Array | null>();
  for (const def of INJECTION_PATTERNS) {
    for (const pattern of def.patterns) {
      const lits = literalsFor(pattern);
      byPattern.set(
        pattern,
        lits === null
          ? null
          : Int32Array.from(lits.map((l) => index.ids.get(l) ?? -1))
      );
    }
  }
  builtinLiterals = { index, byPattern };
  return builtinLiterals;
}

/** Scratch space for the literal flags of each view. */
const viewFlags: Uint8Array[] = [];

function scanViews(views: string[]): Uint8Array[] {
  const { index } = getBuiltinLiterals();
  while (viewFlags.length < views.length) {
    viewFlags.push(new Uint8Array(index.size));
  }
  const out = viewFlags.slice(0, views.length);
  views.forEach((view, v) => {
    out[v].fill(0);
    index.scan(view, out[v]);
  });
  return out;
}

/** Tests a pattern against one view, skipping it when a literal it needs is absent. */
function testView(
  pattern: RegExp,
  view: string,
  flags: Uint8Array | undefined
): boolean {
  const ids = getBuiltinLiterals().byPattern.get(pattern);
  if (ids === undefined || flags === undefined) {
    return testPattern(pattern, view);
  }
  if (ids !== null) {
    let any = false;
    for (let i = 0; i < ids.length && !any; i++) {
      any = flags[ids[i]] === 1;
    }
    if (!any) {
      return false;
    }
  }
  pattern.lastIndex = 0;
  return pattern.test(view);
}

function addFinding(
  state: ScanState,
  category: string,
  pattern: string,
  riskIdx: number,
  confidence = confidenceFor(riskIdx)
): void {
  if (
    riskIdx < state.thresholdIdx ||
    state.excluded.has(category) ||
    state.seen.has(category)
  ) {
    return;
  }
  state.seen.add(category);
  state.findings.push({ category, pattern, confidence, riskIdx });
}

/** Reports the first matching pattern of each category, once per category. */
function patternMatches(
  def: CompiledPatternDef,
  pattern: RegExp,
  views: string[],
  flags: Uint8Array[],
  original: string | undefined
): boolean {
  for (let v = 0; v < views.length; v++) {
    if (testView(pattern, views[v], flags[v])) {
      return true;
    }
  }
  // Custom patterns may be case-sensitive or rely on characters that
  // normalization changes, so they also see the text as written.
  return Boolean(
    def.custom && original !== undefined && testPattern(pattern, original)
  );
}

function matchPatterns(
  views: string[],
  state: ScanState,
  prefix = "",
  original?: string
): number {
  const before = state.findings.length;
  const flags = scanViews(views);
  // Low-risk patterns only run on text with other signs of an attack. The
  // check is costly, so it's done once and only if a low-risk pattern is
  // reached.
  let lowRiskAllowed: boolean | undefined;
  for (const def of state.defs) {
    if (def.riskIdx < state.thresholdIdx || state.seen.has(def.category)) {
      continue;
    }
    if (def.riskIdx === 1) {
      lowRiskAllowed ??= views.some(
        (v) =>
          fastPreFilter(v) ||
          RE_SUSPICIOUS_STRUCTURE.test(v) ||
          tokenBagCount(v) >= 2
      );
      if (!lowRiskAllowed) {
        continue;
      }
    }
    for (const pattern of def.patterns) {
      if (patternMatches(def, pattern, views, flags, original)) {
        addFinding(
          state,
          def.category,
          `${prefix}${pattern.source.slice(0, 60)}`,
          def.riskIdx
        );
        break;
      }
    }
  }
  return state.findings.length - before;
}

let defaultPatterns: CompiledPatternDef[] | undefined;

function compilePatterns(
  options: DetectOptions,
  excluded: Set<string>
): CompiledPatternDef[] {
  const skipped = new Set(options.excludePatterns ?? []);
  const isDefault =
    excluded.size === 0 &&
    skipped.size === 0 &&
    !options.customPatterns?.length;
  if (isDefault && defaultPatterns) {
    return defaultPatterns;
  }
  const defs: CompiledPatternDef[] = [];
  const add = (
    category: string,
    patterns: RegExp[],
    risk: Risk,
    custom = false
  ) => {
    if (!excluded.has(category)) {
      defs.push({
        category,
        patterns,
        riskIdx: RISK_ORDER.indexOf(risk),
        custom,
      });
    }
  };
  for (const def of INJECTION_PATTERNS) {
    const patterns =
      skipped.size === 0
        ? def.patterns
        : def.patterns.filter((p) => !skipped.has(p.source));
    if (patterns.length > 0) {
      add(def.category, patterns, def.risk);
    }
  }
  for (const custom of options.customPatterns ?? []) {
    add(custom.category, [custom.regex], custom.risk, true);
  }
  if (isDefault) {
    defaultPatterns = defs;
  }
  return defs;
}

/** Splits long input into overlapping windows so every part of it is scanned. */
function windows(text: string): string[] {
  if (text.length <= WINDOW_SIZE) {
    return [text];
  }
  const out: string[] = [];
  const step = WINDOW_SIZE - WINDOW_OVERLAP;
  for (let start = 0; start < text.length; start += step) {
    out.push(text.slice(start, start + WINDOW_SIZE));
    if (start + WINDOW_SIZE >= text.length) {
      break;
    }
  }
  return out;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Removes allowed phrases from the input, so they can't trigger a match but
 * the rest of the input is still scanned.
 */
function removeAllowedPhrases(input: string, phrases: string[]): string {
  const usable = phrases.filter((p) => p?.trim());
  if (usable.length === 0) {
    return input;
  }
  const re = new RegExp(
    usable.map((p) => escapeRegExp(p).replace(/\s+/g, "\\s+")).join("|"),
    "gi"
  );
  return input.replace(re, " ");
}

function classifierEnabled(options: DetectOptions): boolean {
  return options.classifier !== false;
}

function scoreText(normalized: string, state: ScanState): void {
  if (classifierEnabled(state.options) && !state.html) {
    state.score = Math.max(state.score, classify(normalized));
  }
}

function scanWindow(window: string, state: ScanState): void {
  const { options } = state;
  const config = resolveDetectNormalization(options.normalization);
  const views = buildViews(window, options.normalization);
  const primary = [views.text];
  if (views.deobfuscated !== views.text) {
    primary.push(views.deobfuscated);
  }
  if (views.deobfuscatedAlt) {
    primary.push(views.deobfuscatedAlt);
  }
  matchPatterns(primary, state, "", window);
  scoreText(views.deobfuscated, state);

  const { invisibleInWords, bidi, unicodeTags } = views.signals;
  // Zero-width joiners, direction marks, and emoji variation selectors are
  // normal in many scripts, so only invisible characters that split Latin
  // words, override controls, and smuggled text count. Smuggling in
  // variation selectors takes runs of them, which decode into `hidden`.
  const smuggled = views.hidden.length > 0 || unicodeTags > 0;
  if (smuggled) {
    addFinding(state, "encoding_attack", "hidden_unicode_text", 3);
  } else if (invisibleInWords >= 3 || bidi > 0) {
    addFinding(state, "encoding_attack", "invisible_characters", 2);
  }

  if (!(config.enabled && config.decodePayloads)) {
    return;
  }
  for (const payload of decodePayloads(window, views.text, views.hidden)) {
    const decoded = buildViews(payload.text, options.normalization);
    const scoreBefore = state.score;
    const found = matchPatterns(
      [decoded.text, decoded.deobfuscated],
      state,
      `${payload.encoding}:`,
      payload.text
    );
    scoreText(decoded.deobfuscated, state);
    const decodedIsInjection =
      found > 0 ||
      (state.score > scoreBefore && state.score >= classifierThreshold(state));
    if (decodedIsInjection) {
      addFinding(state, "encoding_attack", `decoded_${payload.encoding}`, 3);
    }
  }
}

/**
 * Scans what an agent would read on an HTML page: its text, comments, and
 * descriptive attributes. Hidden text is an injection only when it reads as
 * one on its own.
 */
function scanHtml(page: string, state: ScanState): void {
  const { text, hidden } = htmlText(page);
  state.html = false;
  for (const window of windows(text)) {
    scanWindow(window, state);
  }
  if (!hidden) {
    return;
  }
  const scoreBefore = state.score;
  const probe: ScanState = {
    ...state,
    findings: [],
    seen: new Set(),
    score: 0,
  };
  for (const window of windows(hidden)) {
    scanWindow(window, probe);
  }
  const hiddenIsInjection =
    probe.findings.some((f) => f.riskIdx >= 2) ||
    probe.score >= classifierThreshold(state);
  state.score = Math.max(scoreBefore, probe.score);
  if (hiddenIsInjection) {
    addFinding(state, "indirect_injection", "hidden_html_text", 3);
  }
}

function classifierThreshold(state: ScanState): number {
  const c = state.options.classifier;
  return (c ? c.threshold : undefined) ?? classifierThresholds.threshold;
}

function addClassifierFinding(state: ScanState): void {
  if (!classifierEnabled(state.options)) {
    return;
  }
  const c = state.options.classifier || {};
  const threshold = c.threshold ?? classifierThresholds.threshold;
  const high = c.highThreshold ?? classifierThresholds.highThreshold;
  if (state.score < threshold) {
    return;
  }
  const riskIdx = state.score >= high ? 3 : 2;
  addFinding(
    state,
    CLASSIFIER_CATEGORY,
    `model:${classifierThresholds.version}`,
    riskIdx,
    state.score
  );
}

export function detect(
  input: string,
  rawOptions: DetectOptions = {}
): DetectResult {
  const options = resolveOptions(rawOptions);
  if (!input || typeof input !== "string") {
    return { detected: false, risk: "none", matches: [], score: 0 };
  }

  const maxLen = options.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  const bounded = input.length > maxLen ? input.slice(0, maxLen) : input;
  const scanned = options.allowPhrases?.length
    ? removeAllowedPhrases(bounded, options.allowPhrases)
    : bounded;

  const excluded = new Set(options.excludeCategories ?? []);
  const state: ScanState = {
    options,
    defs: compilePatterns(options, excluded),
    excluded,
    thresholdIdx: RISK_ORDER.indexOf(options.threshold || "medium"),
    findings: [],
    seen: new Set(),
    score: 0,
    html: looksLikeHtml(scanned),
  };
  const isHtml = state.html;
  for (const window of windows(scanned)) {
    scanWindow(window, state);
  }
  if (isHtml) {
    scanHtml(scanned, state);
  }
  addClassifierFinding(state);
  if (options.includeCategories) {
    const included = new Set(options.includeCategories);
    state.findings = state.findings.filter((f) => included.has(f.category));
  }

  if (state.findings.length === 0) {
    return { detected: false, risk: "none", matches: [], score: state.score };
  }
  let maxIdx = 1;
  for (const f of state.findings) {
    maxIdx = Math.max(maxIdx, f.riskIdx);
  }
  return {
    detected: true,
    risk: RISK_ORDER[maxIdx] as Exclude<Risk, "none">,
    matches: state.findings.map(({ riskIdx: _, ...m }) => m),
    score: state.score,
  };
}

async function orElse(
  pending: Promise<DetectResult | null>,
  fallback: DetectResult
): Promise<DetectResult> {
  return (await pending) ?? fallback;
}

/**
 * What `detectAsync` does after `detect` returned `result`: the
 * `secondaryDetector` on a detection, or `escalate` on input the classifier
 * is unsure about. `undefined` when neither runs, so `result` is final.
 */
export function slowDetection(
  input: string,
  result: DetectResult,
  options: DetectOptions
): Promise<DetectResult> | undefined {
  if (result.detected) {
    const verify = options.secondaryDetector;
    return verify ? orElse(verify(input, result), result) : undefined;
  }
  const escalate = options.escalate;
  if (escalate && (result.score ?? 0) >= (escalate.minScore ?? 0.15)) {
    return orElse(escalate.detector(input, result), result);
  }
  return;
}

/**
 * Async variant of `detect` that runs `secondaryDetector` on detections and
 * `escalate` on input the classifier is unsure about.
 */
export async function detectAsync(
  input: string,
  options: DetectOptions = {}
): Promise<DetectResult> {
  const result = detect(input, options);
  const slow = slowDetection(input, result, options);
  return slow ? await slow : result;
}

export interface ConversationMessage {
  role: string;
  content: string;
}

export interface ConversationDetectOptions extends DetectOptions {
  /** Roles whose messages are scanned. Default `["user", "tool", "function"]`. */
  roles?: string[];
  /**
   * How many of the latest user messages are also scanned joined together,
   * to catch an instruction split across turns. Default 4; 0 or 1 turns it off.
   */
  window?: number;
}

export interface ConversationDetectResult extends DetectResult {
  /** Messages flagged on their own, by index into the conversation. */
  flagged: Array<{ index: number; role: string; result: DetectResult }>;
  /** Whether the joined latest user messages were flagged. */
  splitAcrossTurns: boolean;
}

const RISK_RANK: Record<DetectResult["risk"], number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Scans a whole conversation: each user and tool message on its own, plus
 * the latest user messages joined together, which catches an instruction
 * split across several turns.
 */
export function detectConversation(
  messages: ConversationMessage[],
  options: ConversationDetectOptions = {}
): ConversationDetectResult {
  const {
    roles = ["user", "tool", "function"],
    window = 4,
    ...detectOptions
  } = options;
  const flagged: ConversationDetectResult["flagged"] = [];
  const matches: DetectResult["matches"] = [];
  const seen = new Set<string>();
  let risk: DetectResult["risk"] = "none";
  let score = 0;

  const merge = (result: DetectResult, prefix = "") => {
    score = Math.max(score, result.score ?? 0);
    if (!result.detected) {
      return;
    }
    if (RISK_RANK[result.risk] > RISK_RANK[risk]) {
      risk = result.risk;
    }
    for (const m of result.matches) {
      if (!seen.has(m.category)) {
        seen.add(m.category);
        matches.push({ ...m, pattern: `${prefix}${m.pattern}` });
      }
    }
  };

  messages.forEach((message, index) => {
    if (!(roles.includes(message.role) && message.content)) {
      return;
    }
    const result = detect(message.content, detectOptions);
    merge(result);
    if (result.detected) {
      flagged.push({ index, role: message.role, result });
    }
  });

  let splitAcrossTurns = false;
  if (window > 1) {
    const recent = messages
      .filter((m) => m.role === "user" && m.content)
      .slice(-window)
      .map((m) => m.content);
    if (recent.length > 1) {
      const joined = detect(recent.join("\n"), detectOptions);
      splitAcrossTurns = joined.detected && flagged.length === 0;
      merge(joined, "conversation:");
    }
  }

  return {
    detected: risk !== "none",
    risk,
    matches,
    score,
    flagged,
    splitAcrossTurns,
  };
}
