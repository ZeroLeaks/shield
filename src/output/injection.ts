import { codeRanges, insideAny } from "./exfiltration";
import type { OutputFinding, Severity } from "./types";
import {
  filterFindings,
  type RankedFinding,
  resolveOverlaps,
  stripPriority,
} from "./util";

/**
 * Improper output handling (OWASP LLM05): model output or tool arguments that
 * a downstream system renders or executes. Each category is opt-in, because a
 * coding assistant legitimately writes SQL, shell, and HTML. These are
 * standard security test vectors, not prompt-injection phrase lists.
 */
export interface InjectionOptions {
  /** HTML/JS execution vectors: `<script>`, event-handler attributes, `javascript:` URLs, `srcdoc`, iframe/object/embed, CSS `expression(`. */
  html?: boolean;
  /** SQL injection shapes: stacked queries, `UNION SELECT`, `OR 1=1` tautologies, comment terminators after a quote. */
  sql?: boolean;
  /** Shell metacharacters: command substitution, chaining into a dangerous command, pipe-to-shell, reverse shells. */
  shell?: boolean;
  /** Server-side template injection: `{{ }}` with dangerous identifiers, `${ }` expression language, `<% %>` tags. */
  template?: boolean;
  /** Spreadsheet formula injection: a cell starting with `= + - @` that calls out (`HYPERLINK`, `IMPORTXML`, DDE). */
  csv?: boolean;
  /** Path traversal toward a sensitive file, and encoded or obfuscated `../` sequences. */
  paths?: boolean;
  /** Drop findings below this confidence (0..1). Default 0. */
  minConfidence?: number;
}

export const INJECTION_KINDS: readonly string[] = [
  "xss",
  "html_injection",
  "sql",
  "shell",
  "template",
  "csv_formula",
  "path_traversal",
];

type Category = "html" | "sql" | "shell" | "template" | "csv" | "paths";

const HIGH = 0.85;
const MEDIUM = 0.6;
const PATH_MEDIUM = 0.7;

// Priorities decide which finding wins when two overlap (see resolveOverlaps).
const P_XSS = 5;
const P_SQL = 4;
const P_SHELL = 4;
const P_TEMPLATE = 3;
const P_CSV = 3;
const P_PATH = 2;
const P_HTML_INJECTION = 2;

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

interface Rule {
  re: RegExp;
  kind: string;
  severity: Severity;
  confidence: number;
  priority: number;
  /** Cheap gate: the rule runs only when the text contains one of these substrings. */
  hint?: readonly string[];
}

// HTML / cross-site scripting -----------------------------------------------

// A curated list of on* handlers, so English words such as "onward" or
// "online" that happen to sit before an "=" are never matched as XSS.
// The negative lookbehind keeps `element.onload = fn` (a JS property
// assignment) from matching; only an attribute boundary counts.
const EVENT_HANDLER =
  /(?<![.\w])on(?:error|load|click|dblclick|mouse(?:over|out|enter|leave|move|down|up)|key(?:down|up|press)|focus(?:in|out)?|blur|change|input|submit|reset|toggle|select|scroll|resize|wheel|contextmenu|auxclick|drag|drop|paste|copy|cut|play|playing|pause|ended|loadstart|loadeddata|canplay|animation(?:start|end|iteration)|transition(?:start|end|run|cancel)|pointer(?:down|up|over|out|enter|leave|move|cancel)|touch(?:start|end|move|cancel)|beforeprint|afterprint|hashchange|popstate|pageshow|pagehide|message|storage|unload|beforeunload|abort|show)\s{0,10}=\s{0,10}(?!=)["']?[^\s"'>=]/gi;

const HTML_RULES: Rule[] = [
  {
    re: /<script(?![a-z0-9])/gi,
    kind: "xss",
    severity: "high",
    confidence: HIGH,
    priority: P_XSS,
  },
  {
    re: EVENT_HANDLER,
    kind: "xss",
    severity: "high",
    confidence: HIGH,
    priority: P_XSS,
  },
  {
    re: /\b(?:javascript|vbscript):(?=\S)/gi,
    kind: "xss",
    severity: "high",
    confidence: 0.8,
    priority: P_XSS,
  },
  {
    re: /\bdata:text\/html[;,]/gi,
    kind: "xss",
    severity: "high",
    confidence: 0.75,
    priority: P_XSS,
  },
  {
    re: /\bsrcdoc\s{0,10}=\s{0,4}["']?\s{0,4}[^\s"'>=]/gi,
    kind: "xss",
    severity: "high",
    confidence: 0.75,
    priority: P_XSS,
  },
  {
    re: /\bexpression\s{0,3}\((?=\s{0,20}[a-z])/gi,
    kind: "xss",
    severity: "medium",
    confidence: MEDIUM,
    priority: P_XSS,
  },
  {
    re: /<(?:iframe|object|embed)(?![a-z0-9])/gi,
    kind: "html_injection",
    severity: "medium",
    confidence: MEDIUM,
    priority: P_HTML_INJECTION,
  },
];

// SQL injection -------------------------------------------------------------

const SQL_RULES: Rule[] = [
  {
    re: /\bunion\s{1,10}(?:all\s{1,10})?select\b/gi,
    kind: "sql",
    severity: "high",
    confidence: HIGH,
    priority: P_SQL,
  },
  {
    // A quoted string literal breaking out, then a stacked statement. A `)`
    // before the `;` (ordinary multi-statement DDL) is deliberately excluded.
    re: /['"]\s{0,10};\s{0,10}(?:drop|delete|truncate|update|insert|alter|exec(?:ute)?|grant|revoke|shutdown)\b/gi,
    kind: "sql",
    severity: "high",
    confidence: HIGH,
    priority: P_SQL,
  },
  {
    // OR 1=1 style tautology: same number on both sides.
    re: /\b(?:or|and)\s{1,6}(\d{1,6})\s{0,4}=\s{0,4}\1(?![\d.])/gi,
    kind: "sql",
    severity: "high",
    confidence: 0.8,
    priority: P_SQL,
  },
  {
    // OR 'a'='a style tautology: same quoted string on both sides. The final
    // quote is optional, since the injected value often leaves it for the
    // application's own closing quote (`' OR 'a'='a`).
    re: /\b(?:or|and)\s{1,6}(['"])([^'"\n]{1,40})\1\s{0,4}=\s{0,4}\1\2\1?/gi,
    kind: "sql",
    severity: "high",
    confidence: 0.8,
    priority: P_SQL,
  },
  {
    // ' OR ''='' style tautology built from empty strings.
    re: /['"]\s{0,4}(?:or|and)\s{1,6}(['"])\1\s{0,4}=\s{0,4}(['"])\2/gi,
    kind: "sql",
    severity: "high",
    confidence: 0.8,
    priority: P_SQL,
  },
  {
    // A single-quoted string literal closed and immediately commented out
    // (`admin'--`). The single quote and the adjacent `--` avoid prose
    // em-dashes (`"word" -- note`) and CSS/JS id selectors (`'#id'`).
    re: /'--/g,
    kind: "sql",
    severity: "medium",
    confidence: MEDIUM,
    priority: P_SQL,
  },
];

// Shell command injection ---------------------------------------------------

const SHELL_RULES: Rule[] = [
  {
    // Command substitution running a recognisable command.
    re: /\$\(\s{0,6}(?:sudo\s{1,6})?(?:curl|wget|nc|ncat|cat|whoami|id|uname|hostname|base64|eval|python[0-9.]*|perl|ruby|node|bash|sh|env|printenv|xxd|nslookup|dig|ping|chmod|chown|rm)\b/gi,
    kind: "shell",
    severity: "high",
    confidence: HIGH,
    priority: P_SHELL,
  },
  {
    // curl/wget URL | sh — the classic remote-code-execution one-liner.
    re: /\b(?:curl|wget|fetch)\b[^\n|]{0,300}\|\s{0,10}(?:sudo\s{1,6})?(?:ba|z|da|a|c)?sh\b/gi,
    kind: "shell",
    severity: "high",
    confidence: HIGH,
    priority: P_SHELL,
  },
  {
    // Chaining into a destructive command. The commands here are not ordinary
    // English words, so a `;` in prose does not trip them.
    re: /(?:;|&&|\|\|)\s{0,10}(?:rm\s+-\w*[rf]\w*|dd\s+if=|mkfs\b|kill\s+-9\b|shutdown\s+-|>\s{0,3}\/dev\/sd)/gi,
    kind: "shell",
    severity: "high",
    confidence: HIGH,
    priority: P_SHELL,
  },
  {
    // Reverse-shell shapes.
    re: /\/dev\/tcp\/\d|\bnc\b[^\n]{0,40}\s-e\s|\bbash\s+-i\b|\bsh\s+-i\b|mkfifo\b[^\n]{0,80}\|\s{0,6}nc\b|python[0-9.]*\s+-c\s+["'][^"'\n]{0,300}(?:socket|pty\.spawn)/gi,
    kind: "shell",
    severity: "high",
    confidence: HIGH,
    priority: P_SHELL,
  },
  {
    // Fork bomb.
    re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&?\s*\}\s*;?\s*:/g,
    kind: "shell",
    severity: "high",
    confidence: HIGH,
    priority: P_SHELL,
  },
  {
    // Chaining into a network or privilege command. Generic `$(...)`
    // substitution is deliberately not flagged: ordinary shell scripts and
    // jQuery use it constantly, so only substitution of a recognized command
    // (the rule above) is reported.
    re: /(?:;|&&|\|\|)\s{0,10}(?:sudo\s|chmod\s+[0-7]|chown\s|mkfifo\s)/gi,
    kind: "shell",
    severity: "medium",
    confidence: MEDIUM,
    priority: P_SHELL,
  },
];

// Server-side template injection --------------------------------------------

const TEMPLATE_RULES: Rule[] = [
  {
    // {{ ... }} reaching for an object's internals or a dangerous builtin.
    re: /\{\{[^{}\n]{0,200}?(?:__class__|__globals__|__builtins__|__import__|__mro__|__subclasses__|__base__|\bconfig\b|\bself\b|\brequest\b|\bcycler\b|\bjoiner\b|\bnamespace\b|\blipsum\b|os\.|subprocess|popen|system\s*\(|getattr\s*\(|\bexec\s*\()/gi,
    kind: "template",
    severity: "high",
    confidence: HIGH,
    priority: P_TEMPLATE,
  },
  {
    // ${ ... } expression-language injection (Java EL, SpEL).
    re: /\$\{[^{}\n]{0,200}?(?:T\s*\(|Runtime|ProcessBuilder|getRuntime|getClass|\.class\b|exec\s*\(|\bnew\s+java|#\{)/gi,
    kind: "template",
    severity: "high",
    confidence: HIGH,
    priority: P_TEMPLATE,
  },
  {
    // <%= ... %> / <% ... %> running Ruby, JSP, or ASP code.
    re: /<%[=#-]?[^%\n]{0,200}?(?:system\s*\(|`|exec\s*\(|File\.|IO\.|Dir\.|Kernel|%x\{|Open3|eval\s*\(|Runtime|ProcessBuilder|Process\.)[^%\n]{0,100}?%>/gi,
    kind: "template",
    severity: "high",
    confidence: HIGH,
    priority: P_TEMPLATE,
  },
  {
    // {{ 7*7 }} arithmetic probe.
    re: /\{\{\s{0,6}\d{1,6}\s{0,4}\*\s{0,4}\d{1,6}\s{0,6}\}\}/g,
    kind: "template",
    severity: "medium",
    confidence: MEDIUM,
    priority: P_TEMPLATE,
  },
  {
    // ${ 7*7 } arithmetic probe.
    re: /\$\{\s{0,6}\d{1,6}\s{0,4}\*\s{0,4}\d{1,6}\s{0,6}\}/g,
    kind: "template",
    severity: "medium",
    confidence: MEDIUM,
    priority: P_TEMPLATE,
  },
  {
    // Nested expression wrappers used to slip past naive filters.
    re: /\$\{\{|#\{\{|\{\{\{[^{]/g,
    kind: "template",
    severity: "medium",
    confidence: MEDIUM,
    priority: P_TEMPLATE,
  },
  {
    // Generic <%= ... %> / <% ... %> tag (downgraded in code).
    re: /<%=?[ \t][^%\n]{0,200}?%>/g,
    kind: "template",
    severity: "medium",
    confidence: 0.55,
    priority: P_TEMPLATE,
  },
];

// Spreadsheet formula injection ---------------------------------------------

const CSV_RULES: Rule[] = [
  {
    // A cell starting with = + - @ that opens a DDE link.
    re: /^[ \t]{0,8}["']?[=+\-@][^\n]{0,60}?(?:cmd\s*\||msexcel\s*\||\bdde\b\s*\|)/gim,
    kind: "csv_formula",
    severity: "high",
    confidence: HIGH,
    priority: P_CSV,
  },
  {
    // A cell starting with = + - @ that calls a data- or code-exfiltration function.
    re: /^[ \t]{0,8}["']?[=+\-@][^\n(]{0,50}?\b(?:HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|WEBSERVICE|RTD|DDE|MSEXCEL|EXEC|REGISTER)\s{0,4}\(/gim,
    kind: "csv_formula",
    severity: "high",
    confidence: HIGH,
    priority: P_CSV,
  },
];

// Path traversal ------------------------------------------------------------

const PATH_TARGET_HINTS = [
  "passwd",
  "shadow",
  "hosts",
  "proc/self",
  "win.ini",
  "boot.ini",
  "system32",
  ".ssh",
  "id_rsa",
  "id_dsa",
  "credentials",
  ".env",
  "web.config",
  "wp-config",
  "htpasswd",
];

const PATH_RULES: Rule[] = [
  {
    // A ../ (raw or encoded) sequence reaching a sensitive file. Separators in
    // the target may be raw or percent-encoded so a fully encoded payload still
    // reaches high. The hint gate keeps this off the hot path for 1MB of bare
    // "../" (no target present).
    re: /(?:\.\.[/\\]|\.\.%2[fF]|\.\.%5[cC]|%2[eE]%2[eE][/\\]|%2[eE]%2[eE]%2[fF]|%2[eE]%2[eE]%5[cC])[^\s"'<>|]{0,80}?(?:etc(?:[/\\]|%2[fF])(?:passwd|shadow|hosts)|proc(?:[/\\]|%2[fF])self|win\.ini|boot\.ini|system32|\.ssh(?:[/\\]|%2[fF])|id_rsa|id_dsa|\.aws(?:[/\\]|%2[fF])credentials|\.env\b|web\.config|wp-config\.php|\.htpasswd)/gi,
    kind: "path_traversal",
    severity: "high",
    confidence: HIGH,
    priority: P_PATH,
    hint: PATH_TARGET_HINTS,
  },
  {
    // Obfuscated or encoded traversal that has no benign reading. (Bare
    // `....//` is left out: it collides with prose ellipses like "eyes....//".)
    re: /\.\.;[/\\]|\.\.%00|%252[eE]%252[eE]|\.\.%c0%af|\.\.%25c0%25af/gi,
    kind: "path_traversal",
    severity: "high",
    confidence: 0.8,
    priority: P_PATH,
  },
  {
    // A percent-encoded ../ or ..\ (encoding a traversal is rarely benign).
    re: /\.\.%2[fF]|\.\.%5[cC]|%2[eE]%2[eE]%2[fF]|%2[eE]%2[eE]%5[cC]/gi,
    kind: "path_traversal",
    severity: "medium",
    confidence: PATH_MEDIUM,
    priority: P_PATH,
  },
];

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

interface Ctx {
  text: string;
  code: [number, number][];
  out: RankedFinding[];
}

const PREVIEW_MAX = 56;
const PREVIEW_UNSAFE = /[\p{Cc}\p{Cf}]+/gu;

/** A short, single-line snippet of the flagged span, safe to log. */
function previewAt(text: string, start: number, end: number): string {
  const cut = Math.min(end, start + PREVIEW_MAX);
  const slice = text.slice(start, cut).replace(PREVIEW_UNSAFE, " ");
  return end - start > PREVIEW_MAX ? `${slice}…` : slice;
}

/** Content inside code spans and fences is not rendered or executed on the page, so it drops to low severity. */
function inCodeConfidence(confidence: number): number {
  return Math.max(0.1, Math.round(confidence * 30) / 100);
}

function report(ctx: Ctx, rule: Rule, start: number, end: number): void {
  const inCode = ctx.code.length > 0 && insideAny(ctx.code, start);
  ctx.out.push({
    type: "injection",
    kind: rule.kind,
    start,
    end,
    severity: inCode ? "low" : rule.severity,
    confidence: inCode ? inCodeConfidence(rule.confidence) : rule.confidence,
    preview: previewAt(ctx.text, start, end),
    priority: rule.priority,
  });
}

function hintPresent(text: string, hints: readonly string[]): boolean {
  for (const hint of hints) {
    if (text.includes(hint)) {
      return true;
    }
  }
  return false;
}

function run(ctx: Ctx, rules: readonly Rule[]): void {
  for (const rule of rules) {
    if (rule.hint && !hintPresent(ctx.text, rule.hint)) {
      continue;
    }
    rule.re.lastIndex = 0;
    for (
      let m = rule.re.exec(ctx.text);
      m !== null;
      m = rule.re.exec(ctx.text)
    ) {
      report(ctx, rule, m.index, m.index + m[0].length);
      if (rule.re.lastIndex === m.index) {
        rule.re.lastIndex++;
      }
    }
  }
}

function categoriesFor(options: InjectionOptions): Set<Category> {
  const flags: [Category, boolean | undefined][] = [
    ["html", options.html],
    ["sql", options.sql],
    ["shell", options.shell],
    ["template", options.template],
    ["csv", options.csv],
    ["paths", options.paths],
  ];
  const anySpecified = flags.some(([, value]) => value !== undefined);
  const on = new Set<Category>();
  for (const [category, value] of flags) {
    if (anySpecified ? value === true : true) {
      on.add(category);
    }
  }
  return on;
}

/**
 * Finds output that a downstream system renders or executes: XSS and dangerous
 * HTML, SQL injection shapes, shell metacharacters, server-side template
 * injection, spreadsheet formula injection, and path traversal. Each category
 * is opt-in; nothing runs unless it is turned on.
 *
 * Because a coding assistant legitimately writes SQL, shell, and HTML, a match
 * inside a fenced or inline code block is reported at low severity rather than
 * dropped: a reviewer still sees it, but it does not block. Findings outside
 * code carry the category's real severity.
 */
export function detectInjection(
  text: string,
  options: InjectionOptions = {}
): OutputFinding[] {
  if (typeof text !== "string" || text.length < 3) {
    return [];
  }
  const categories = categoriesFor(options);
  if (categories.size === 0) {
    return [];
  }
  const ctx: Ctx = { text, code: codeRanges(text), out: [] };
  if (categories.has("html")) {
    run(ctx, HTML_RULES);
  }
  if (categories.has("sql")) {
    run(ctx, SQL_RULES);
  }
  if (categories.has("shell")) {
    run(ctx, SHELL_RULES);
  }
  if (categories.has("template")) {
    run(ctx, TEMPLATE_RULES);
  }
  if (categories.has("csv")) {
    run(ctx, CSV_RULES);
  }
  if (categories.has("paths")) {
    run(ctx, PATH_RULES);
  }
  return filterFindings(stripPriority(resolveOverlaps(ctx.out)), {
    minConfidence: options.minConfidence,
  });
}
