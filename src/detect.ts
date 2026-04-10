import {
  type DetectNormalizationOptions,
  normalizeForDetection,
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
  /** Whitelist phrases (case-insensitive). If input contains one, detection is suppressed. Use sparingly for known-benign strings. */
  allowPhrases?: string[];
  /** Optional async verifier. When detection fires, called with (input, result). Return `{ detected: false }` to override (e.g. LLM verification). Return `null` to keep original. */
  secondaryDetector?: (
    input: string,
    result: DetectResult
  ) => Promise<DetectResult | null>;
  maxInputLength?: number;
}

interface PatternDef {
  category: string;
  patterns: RegExp[];
  risk: "low" | "medium" | "high" | "critical";
}

const DETECTION_SCAN_LENGTH = 8192;
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
      /\[?\s*system\s*(override|reset|command|update)\s*\]?/i,
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
      /you\s+are\s+(now\s+)?(DAN|DUDE|STAN|KEVIN|JAILBREAK)/i,
      /act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(DAN|unrestricted|evil)/i,
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
      /COMPLIANCE\s+NOTICE/i,
      /SOC2.*AUDIT/i,
      /authorized\s+(?:security\s+)?(?:audit|assessment|scan)/i,
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
      /curl\s+(-[sXx]\s+)?(POST\s+)?https?:\/\/\S+\s+-d/i,
      /wget\s+-[qQ]?O-?\s+https?:\/\/\S+\s*\|\s*(?:bash|sh)/i,
      /bash\s+-[ci]\s+['"]/i,
      /printenv|env\s+dump/i,
      /\/dev\/tcp\//,
      /crontab\s/i,
      /169\.254\.169\.254/,
      /\/etc\/(?:passwd|shadow)/,
      /~\/\.ssh\/(?:id_rsa|authorized_keys)/,
      /\$\((?:whoami|hostname|printenv|cat\s)/i,
    ],
  },
  {
    category: "indirect_injection",
    risk: "high",
    patterns: [
      /\[?\s*(?:WHITE\s+TEXT|HIDDEN|NOT\s+VISIBLE)\s*/i,
      /AI\s+(?:ASSISTANT\s+)?INSTRUCTION\s*:/i,
      /__ai_(?:directive|instructions?|action)/i,
      /_ai_instructions/i,
      /\[ASSISTANT:\s/i,
      /<!--\s*(?:SYSTEM|AI|ASSISTANT)\s*:/,
      /style\s*=\s*["']display\s*:\s*none/i,
      /AI-ACTION-REQUIRED/i,
      /\[?\s*END\s+HIDDEN\s*(?:TEXT)?\s*\]?/i,
    ],
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
    patterns: [
      /(?:base64|rot13|hex|binary)\s*(?:decode|encode|translate)/i,
      /\b(?:atob|btoa)\s*\(/i,
      /\\u[0-9a-fA-F]{4}/,
      /&#x?[0-9a-fA-F]+;/,
      /[\u200B-\u200F\u2028-\u202F\uFEFF]/,
      /read\s+this\s+backwards/i,
      /Ị̷|g̷|n̷|ơ̷|r̷|e̷/,
    ],
  },
  {
    category: "context_manipulation",
    risk: "medium",
    patterns: [
      /(?:above|previous)\s+(?:text|content|message)\s+(?:is|was)\s+(?:just\s+)?(?:a\s+)?(?:test|joke|example)/i,
      /the\s+(?:real|actual|true)\s+instructions?\s+(?:are|is)/i,
      /(?:actually|really)\s*,?\s*(?:you\s+should|you\s+need\s+to|I\s+want\s+you\s+to)/i,
      /(?:end|close|exit)\s*(?:of\s+)?(?:system\s+)?(?:prompt|instructions)/i,
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
    risk: "medium",
    patterns: [
      /include\s+the\s+(?:exact\s+)?phrase\s+["']/i,
      /start\s+every\s+(?:sentence|response)\s+with/i,
      /end\s+(?:every\s+)?(?:response|message)\s+with/i,
      /respond\s+(?:only\s+)?in\s+(?:JSON|XML|YAML)\s+format/i,
      /from\s+now\s+on.*(?:must|always|every)/i,
      /respond\s+(?:únicamente|only)\s+(?:en|in)\s+(?:español|french|german)/i,
      /MUST\s+RESPOND\s+IN\s+ALL\s+(?:UPPERCASE|CAPS)/i,
    ],
  },
];

const RISK_ORDER = ["none", "low", "medium", "high", "critical"] as const;
const DEFAULT_MAX_INPUT_LENGTH = 1024 * 1024;

const RE_WHITESPACE_SPLIT = /\s+/;
const RE_SUSPICIOUS_STRUCTURE = /\[[\s\w]*\]|<!--[\s\w]*:/;

function fastPreFilter(s: string): boolean {
  const lower = s.toLowerCase();
  for (const sig of PRE_FILTER_SIGNALS) {
    if (lower.includes(sig.toLowerCase())) {
      return true;
    }
  }
  return false;
}

function tokenBagCount(s: string): number {
  const words = s
    .toLowerCase()
    .replace(/[^\w\s]/g, " ")
    .split(RE_WHITESPACE_SPLIT)
    .filter(Boolean);
  let count = 0;
  for (const w of words) {
    if (SUSPICIOUS_WORDS.has(w)) {
      count++;
    }
  }
  return count;
}

function hasSuspiciousStructure(s: string): boolean {
  return RE_SUSPICIOUS_STRUCTURE.test(s);
}

function findPatternMatches(
  normalized: string,
  allPatterns: Array<{ category: string; patterns: RegExp[]; risk: string }>,
  thresholdIdx: number,
  runLowRisk: boolean
): DetectResult["matches"] {
  const matches: DetectResult["matches"] = [];
  for (const def of allPatterns) {
    const riskIdx = RISK_ORDER.indexOf(def.risk as (typeof RISK_ORDER)[number]);
    if (riskIdx < thresholdIdx) {
      continue;
    }
    if (def.risk === "low" && !runLowRisk) {
      continue;
    }
    for (const pattern of def.patterns) {
      if (pattern.test(normalized)) {
        matches.push({
          category: def.category,
          pattern: pattern.source.slice(0, 60),
          confidence: Math.min(1, 0.4 + riskIdx * 0.2),
        });
        if (def.risk === "critical") {
          return matches;
        }
        break;
      }
    }
  }
  return matches;
}

function computeMaxRisk(
  matches: DetectResult["matches"],
  allPatterns: Array<{ category: string; risk: string }>
): "low" | "medium" | "high" | "critical" {
  let maxIdx = 0;
  let maxRisk: "low" | "medium" | "high" | "critical" = "low";
  for (const m of matches) {
    const matchDef = allPatterns.find((p) => p.category === m.category);
    const matchRiskIdx = matchDef
      ? RISK_ORDER.indexOf(matchDef.risk as (typeof RISK_ORDER)[number])
      : 0;
    if (matchRiskIdx > maxIdx && matchDef) {
      maxIdx = matchRiskIdx;
      maxRisk = matchDef.risk as "low" | "medium" | "high" | "critical";
    }
  }
  return maxRisk;
}

export function detect(
  input: string,
  options: DetectOptions = {}
): DetectResult {
  if (!input || typeof input !== "string") {
    return { detected: false, risk: "none", matches: [] };
  }

  const maxLen = options.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  const bounded = input.length > maxLen ? input.slice(0, maxLen) : input;
  const scanLength = Math.min(bounded.length, DETECTION_SCAN_LENGTH);
  const toScan = bounded.slice(0, scanLength);
  const normalized = normalizeForDetection(toScan, options.normalization);

  const threshold = options.threshold || "medium";
  const thresholdIdx = RISK_ORDER.indexOf(threshold);

  const runLowRisk =
    fastPreFilter(normalized) ||
    tokenBagCount(normalized) >= 2 ||
    hasSuspiciousStructure(normalized);

  const excludeSet = new Set(options.excludeCategories ?? []);
  const allPatterns = [
    ...INJECTION_PATTERNS.filter((p) => !excludeSet.has(p.category)),
    ...(
      options.customPatterns?.map((p) => ({
        category: p.category,
        patterns: [p.regex],
        risk: p.risk,
      })) || []
    ).filter((p) => !excludeSet.has(p.category)),
  ];

  const matches = findPatternMatches(
    normalized,
    allPatterns,
    thresholdIdx,
    runLowRisk
  );

  if (matches.length === 0) {
    return { detected: false, risk: "none", matches: [] };
  }

  const allowPhrases = options.allowPhrases;
  if (allowPhrases?.length) {
    const lower = bounded.toLowerCase();
    for (const phrase of allowPhrases) {
      if (phrase && lower.includes(phrase.toLowerCase())) {
        return { detected: false, risk: "none", matches: [] };
      }
    }
  }

  const maxRisk = computeMaxRisk(matches, allPatterns);
  return {
    detected: true,
    risk: maxRisk,
    matches,
  };
}

/**
 * Async variant that supports `secondaryDetector`. Use when you need LLM-based
 * verification to reduce false positives.
 */
export async function detectAsync(
  input: string,
  options: DetectOptions = {}
): Promise<DetectResult> {
  const result = detect(input, options);
  if (!(result.detected && options.secondaryDetector)) {
    return result;
  }
  const override = await options.secondaryDetector(input, result);
  return override ?? result;
}
