import {
  CONTEXT_RULES,
  type ContextRule,
  GATED_RULES,
  type GatedRule,
  PREFIX_RULES,
  type PrefixRule,
  type Refinement,
} from "./secret-rules";
import type { OutputFinding, Severity } from "./types";
import {
  bytesToLatin1,
  charClassCount,
  decodeBase64,
  decodeBase64Json,
  filterFindings,
  hasDigit,
  looksLikePlaceholder,
  previewSecret,
  type RankedFinding,
  resolveOverlaps,
  shannonEntropy,
  stripPriority,
} from "./util";

export interface SecretsOptions {
  /** Only report these kinds (see `SECRET_KINDS`). */
  kinds?: string[];
  /** Never report these kinds. */
  exclude?: string[];
  /** Drop findings below this confidence (0..1). Default 0. */
  minConfidence?: number;
}

const PRIORITY_STRUCTURED = 3;
const PRIORITY_CONTEXT = 2;
const PRIORITY_GENERIC = 1;

const ASSIGNMENT_KINDS = [
  "password_assignment",
  "generic_secret",
  "bearer_token",
  "basic_auth_credentials",
];
const PRIVATE_KEY_KINDS = ["private_key", "gcp_service_account_key"];
const JWT_KINDS = ["jwt", "supabase_service_role_key", "supabase_anon_key"];
const URL_CREDENTIAL_KINDS = ["database_connection_url", "url_credentials"];

/** Every kind `detectSecrets` can report. */
export const SECRET_KINDS: readonly string[] = Array.from(
  new Set([
    ...PREFIX_RULES.flatMap((r) => r.kinds ?? [r.kind]),
    ...GATED_RULES.flatMap((r) => r.kinds ?? [r.kind]),
    ...CONTEXT_RULES.map((r) => r.kind),
    ...PRIVATE_KEY_KINDS,
    ...JWT_KINDS,
    ...URL_CREDENTIAL_KINDS,
    ...ASSIGNMENT_KINDS,
  ])
);

interface KindFilter {
  kinds: Set<string> | null;
  exclude: Set<string> | null;
}

function wants(filter: KindFilter, kinds: readonly string[]): boolean {
  return kinds.some(
    (k) => (!filter.kinds || filter.kinds.has(k)) && !filter.exclude?.has(k)
  );
}

interface Scan {
  text: string;
  filter: KindFilter;
  found: RankedFinding[];
  /** [start, end) pairs of value-character runs long enough to hold a context-rule value. */
  runs: number[];
  /** True when no kind filter is set, so every rule runs. */
  unfiltered: boolean;
}

function passesBodyChecks(
  body: string,
  minEntropy: number,
  minClasses: number
): boolean {
  return (
    body.length >= 8 &&
    !looksLikePlaceholder(body) &&
    charClassCount(body) >= minClasses &&
    shannonEntropy(body) >= minEntropy
  );
}

function pushRuleMatch(
  scan: Scan,
  rule: PrefixRule | GatedRule,
  value: string,
  start: number
): void {
  const refinement: Refinement | false = rule.refine
    ? rule.refine(value, scan.text, start)
    : {};
  if (refinement === false) {
    return;
  }
  const prefix = refinement.prefix ?? rule.prefix;
  const body = value.slice(prefix);
  if (!passesBodyChecks(body, rule.minEntropy ?? 3, rule.minClasses ?? 2)) {
    return;
  }
  scan.found.push({
    type: "secret",
    kind: refinement.kind ?? rule.kind,
    start,
    end: start + value.length,
    severity: refinement.severity ?? rule.severity,
    confidence: refinement.confidence ?? rule.confidence,
    preview: previewSecret(value, prefix),
    priority: PRIORITY_STRUCTURED,
  });
}

// ---------------------------------------------------------------------------
// Lexer: one pass over the text. Vendor prefixes are dispatched at token
// starts through a two-character table, and runs of value characters are
// recorded for the context rules. There is no lookbehind anywhere: JSC
// (Bun, Safari) runs such regexes in its slow interpreter.
// ---------------------------------------------------------------------------

function asciiTable(chars: string): Uint8Array {
  const table = new Uint8Array(128);
  for (let i = 0; i < chars.length; i++) {
    table[chars.charCodeAt(i)] = 1;
  }
  return table;
}

const ALNUM_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ALNUM = asciiTable(ALNUM_CHARS);
/** A token cannot start right after one of these. */
const TOKEN_CHAR = asciiTable(`${ALNUM_CHARS}_-`);
/** Characters of the values context rules look for (hex, base62, base64, UUIDs). */
const VALUE_CHAR = asciiTable(`${ALNUM_CHARS}+/=_-`);
const MIN_CONTEXT_RUN = 24;

interface Bucket {
  /** Allowed third characters (any, when a prefix is only two characters long). */
  third: Uint8Array;
  rules: PrefixRule[];
  prefixes: string[][];
}

/** Prefix rules keyed by the first two characters of each prefix. */
const BUCKETS: Bucket[] = [];
/** Two-character key -> index into BUCKETS plus one (0 = no rule starts that way). */
const DISPATCH = new Int16Array(128 * 128);
for (const rule of PREFIX_RULES) {
  for (const prefix of rule.prefixes) {
    const slot = prefix.charCodeAt(0) * 128 + prefix.charCodeAt(1);
    if (DISPATCH[slot] === 0) {
      BUCKETS.push({ third: new Uint8Array(128), rules: [], prefixes: [] });
      DISPATCH[slot] = BUCKETS.length;
    }
    const bucket = BUCKETS[DISPATCH[slot] - 1];
    if (prefix.length > 2) {
      bucket.third[prefix.charCodeAt(2)] = 1;
    } else {
      bucket.third.fill(1);
    }
    const index = bucket.rules.indexOf(rule);
    if (index === -1) {
      bucket.rules.push(rule);
      bucket.prefixes.push([prefix]);
    } else {
      bucket.prefixes[index].push(prefix);
    }
  }
}

function startsWithAny(
  text: string,
  index: number,
  prefixes: string[]
): boolean {
  for (const prefix of prefixes) {
    if (text.startsWith(prefix, index)) {
      return true;
    }
  }
  return false;
}

function tryPrefixRules(scan: Scan, index: number, bucket: Bucket): void {
  const { text } = scan;
  for (let r = 0; r < bucket.rules.length; r++) {
    const rule = bucket.rules[r];
    const wanted =
      scan.unfiltered || wants(scan.filter, rule.kinds ?? [rule.kind]);
    if (!(wanted && startsWithAny(text, index, bucket.prefixes[r]))) {
      continue;
    }
    rule.pattern.lastIndex = index;
    const match = rule.pattern.exec(text);
    if (match) {
      pushRuleMatch(scan, rule, match[0], index);
    }
  }
}

function dispatchAt(scan: Scan, index: number, code: number): void {
  const text = scan.text;
  const next = text.charCodeAt(index + 1);
  const slot = next < 128 ? DISPATCH[code * 128 + next] : 0;
  if (slot === 0) {
    return;
  }
  const bucket = BUCKETS[slot - 1];
  const third = text.charCodeAt(index + 2);
  if (third < 128 && bucket.third[third] === 1) {
    tryPrefixRules(scan, index, bucket);
  }
}

/** Character classes for the lexer: 0 other, 1 "+/=", 2 "_-", 3 letter or digit. */
const CHAR_CLASS = new Uint8Array(128);
for (let code = 0; code < 128; code++) {
  if (ALNUM[code] === 1) {
    CHAR_CLASS[code] = 3;
  } else if (TOKEN_CHAR[code] === 1) {
    CHAR_CLASS[code] = 2;
  } else if (VALUE_CHAR[code] === 1) {
    CHAR_CLASS[code] = 1;
  }
}

/**
 * One pass over the text: tries vendor prefixes at every token start and
 * records runs of value characters for the context rules.
 */
function lex(scan: Scan): void {
  const { text, runs } = scan;
  const length = text.length;
  let previousClass = 0;
  let runStart = -1;
  for (let i = 0; i < length; i++) {
    const code = text.charCodeAt(i);
    const charClass = code < 128 ? CHAR_CLASS[code] : 0;
    if (charClass === 0) {
      if (runStart !== -1 && i - runStart >= MIN_CONTEXT_RUN) {
        runs.push(runStart, i);
      }
      runStart = -1;
    } else if (runStart === -1) {
      runStart = i;
    }
    if (charClass === 3 && previousClass < 2) {
      dispatchAt(scan, i, code);
    }
    previousClass = charClass;
  }
  if (runStart !== -1 && length - runStart >= MIN_CONTEXT_RUN) {
    runs.push(runStart, length);
  }
}

// ---------------------------------------------------------------------------
// Gated rules
// ---------------------------------------------------------------------------

/** Runs a gated rule in a window around each occurrence of its gate literal. */
function runGatedRule(scan: Scan, rule: GatedRule, gate: string): void {
  const { text } = scan;
  const [back, forward] = rule.window;
  const seen = new Set<number>();
  let at = text.indexOf(gate);
  while (at !== -1) {
    const from = Math.max(0, at - back - 1);
    const window = text.slice(from, at + gate.length + forward);
    for (const match of window.matchAll(rule.pattern)) {
      const value = match[1];
      const start = from + (match.index ?? 0) + match[0].length - value.length;
      // A match at the window's own start is only a boundary at the text start.
      const cut = start === from && from > 0;
      if (!(cut || seen.has(start))) {
        seen.add(start);
        pushRuleMatch(scan, rule, value, start);
      }
    }
    at = text.indexOf(gate, at + gate.length);
  }
}

function runGatedRules(scan: Scan): void {
  for (const rule of GATED_RULES) {
    if (!(scan.unfiltered || wants(scan.filter, rule.kinds ?? [rule.kind]))) {
      continue;
    }
    for (const gate of rule.gates) {
      if (scan.text.includes(gate)) {
        runGatedRule(scan, rule, gate);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Context rules: a generic value counts only near its provider's name
// ---------------------------------------------------------------------------

const CONTEXT_WINDOW = 300;
const CANDIDATE_VALUE = /[A-Za-z0-9+/_-]{24,}/g;
const KEY_WORDS = /key|token|secret|auth|bearer|credential|password/;
const CONTEXT_WORDS = new RegExp(
  Array.from(new Set(CONTEXT_RULES.flatMap((r) => r.words)))
    .sort((a, b) => b.length - a.length)
    .join("|"),
  "g"
);

function contextValueOk(value: string, rule: ContextRule): boolean {
  if (rule.reject?.(value)) {
    return false;
  }
  return passesBodyChecks(value, rule.minEntropy ?? 3, rule.minClasses ?? 2);
}

/** Offset (within `window`) just past the last occurrence of one of `words`, or -1. */
function contextEnd(window: string, words: string[]): number {
  let best = -1;
  for (const word of words) {
    const at = window.lastIndexOf(word);
    if (at !== -1) {
      best = Math.max(best, at + word.length);
    }
  }
  return best;
}

function applyContextRule(
  scan: Scan,
  rule: ContextRule,
  candidate: string,
  candidateStart: number,
  window: string
): void {
  const windowStart = candidateStart - window.length;
  for (const match of candidate.matchAll(rule.pattern)) {
    const value = match[1];
    const offset = (match.index ?? 0) + match[0].length - value.length;
    const start = candidateStart + offset;
    const visible = window + candidate.slice(0, offset).toLowerCase();
    const wordEnd = contextEnd(visible, rule.words);
    if (
      wordEnd === -1 ||
      windowStart + wordEnd < start - (rule.maxDistance ?? 100)
    ) {
      continue;
    }
    const keyWordOk =
      rule.requireKeyWord === false ||
      KEY_WORDS.test(visible.slice(Math.max(0, wordEnd - 24)));
    if (keyWordOk && contextValueOk(value, rule)) {
      scan.found.push({
        type: "secret",
        kind: rule.kind,
        start,
        end: start + value.length,
        severity: rule.severity,
        confidence: rule.confidence,
        preview: previewSecret(value, 0),
        priority: PRIORITY_CONTEXT,
      });
    }
  }
}

/** No context-rule value is longer than this; longer runs are other data. */
const MAX_CONTEXT_VALUE = 128;

function checkCandidate(scan: Scan, candidate: string, start: number): void {
  if (candidate.length > MAX_CONTEXT_VALUE) {
    return;
  }
  if (charClassCount(candidate) < 2 || shannonEntropy(candidate) < 3) {
    return;
  }
  const window = scan.text
    .slice(Math.max(0, start - CONTEXT_WINDOW), start)
    .toLowerCase();
  const words = new Set(window.match(CONTEXT_WORDS));
  const prefix = candidate.slice(0, 24).toLowerCase();
  for (const word of prefix.match(CONTEXT_WORDS) ?? []) {
    words.add(word);
  }
  if (words.size === 0) {
    return;
  }
  for (const rule of CONTEXT_RULES) {
    const relevant = rule.words.some((w) => words.has(w));
    if (relevant && wants(scan.filter, [rule.kind])) {
      applyContextRule(scan, rule, candidate, start, window);
    }
  }
}

function runContextRules(scan: Scan): void {
  const { text, runs } = scan;
  for (let i = 0; i < runs.length; i += 2) {
    const run = text.slice(runs[i], runs[i + 1]);
    // Context values are random hex or base62/base64: they contain digits.
    if (!hasDigit(run)) {
      continue;
    }
    for (const match of run.matchAll(CANDIDATE_VALUE)) {
      checkCandidate(scan, match[0], runs[i] + (match.index ?? 0));
    }
  }
}

// ---------------------------------------------------------------------------
// Private key blocks
// ---------------------------------------------------------------------------

const PRIVATE_KEY_HEADER =
  /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |SSH2 ENCRYPTED )?)PRIVATE KEY(?: BLOCK)?-----/y;
const ESCAPED_NEWLINE = /\\[nr]/g;
const NON_BASE64 = /[^A-Za-z0-9+/]/g;
const KEY_BODY_PLACEHOLDER = /\.\.\.|…|your|<|insert|paste|replace/i;
const PRIVATE_KEY_MAX_BODY = 16_384;
const SERVICE_ACCOUNT_MARKER = /service_account|gserviceaccount\.com/;
const KEY_BODY_CHAR = asciiTable(`${ALNUM_CHARS}+/=\\ \t\r\n`);

function truncatedKeyEnd(text: string, from: number): number {
  const limit = Math.min(text.length, from + PRIVATE_KEY_MAX_BODY);
  let i = from;
  while (i < limit) {
    const code = text.charCodeAt(i);
    if (code >= 128 || KEY_BODY_CHAR[code] === 0) {
      break;
    }
    i++;
  }
  return i;
}

interface KeyBounds {
  bodyEnd: number;
  end: number;
  truncated: boolean;
}

function privateKeyBounds(
  text: string,
  bodyStart: number,
  footer: number
): KeyBounds {
  if (footer === -1 || footer - bodyStart > PRIVATE_KEY_MAX_BODY) {
    const end = truncatedKeyEnd(text, bodyStart);
    return { bodyEnd: end, end, truncated: true };
  }
  const close = text.indexOf("-----", footer + 8);
  const end = close !== -1 && close - footer < 64 ? close + 5 : footer + 8;
  return { bodyEnd: footer, end, truncated: false };
}

function privateKeyKind(text: string, start: number): string {
  const before = text.slice(Math.max(0, start - 40), start);
  if (!before.includes('"private_key"')) {
    return "private_key";
  }
  const around = text.slice(Math.max(0, start - 3000), start + 6000);
  return SERVICE_ACCOUNT_MARKER.test(around)
    ? "gcp_service_account_key"
    : "private_key";
}

const NOT_SEARCHED = -2;

function scanPrivateKeys(scan: Scan): void {
  const { text } = scan;
  // The next footer is searched for once and reused by every header before
  // it, so many headers without footers stay linear.
  let footer = NOT_SEARCHED;
  let start = text.indexOf("-----BEGIN ");
  while (start !== -1) {
    PRIVATE_KEY_HEADER.lastIndex = start;
    const header = PRIVATE_KEY_HEADER.exec(text);
    const bodyStart = header ? start + header[0].length : start + 11;
    if (header) {
      const stale =
        footer === NOT_SEARCHED || (footer !== -1 && footer < bodyStart);
      if (stale) {
        footer = text.indexOf("-----END", bodyStart);
      }
      reportPrivateKey(
        scan,
        header,
        start,
        privateKeyBounds(text, bodyStart, footer)
      );
    }
    start = text.indexOf("-----BEGIN ", bodyStart);
  }
}

function reportPrivateKey(
  scan: Scan,
  header: RegExpExecArray,
  start: number,
  bounds: KeyBounds
): void {
  const { text } = scan;
  const bodyStart = start + header[0].length;
  const rawBody = text.slice(bodyStart, bounds.bodyEnd);
  const base64 = rawBody.replace(ESCAPED_NEWLINE, "").replace(NON_BASE64, "");
  const placeholder = KEY_BODY_PLACEHOLDER.test(rawBody) && base64.length < 256;
  if (base64.length < 64 || placeholder || shannonEntropy(base64) < 4.5) {
    return;
  }
  scan.found.push({
    type: "secret",
    kind: privateKeyKind(text, start),
    start,
    end: bounds.end,
    severity: header[1].includes("ENCRYPTED") ? "high" : "critical",
    confidence: bounds.truncated ? 0.8 : 0.95,
    preview: `${header[0]}…`,
    priority: PRIORITY_STRUCTURED,
  });
}

// ---------------------------------------------------------------------------
// JSON Web Tokens
// ---------------------------------------------------------------------------

const JWT_PATTERN =
  /eyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,8000}\.[A-Za-z0-9_-]{0,1000}(?![A-Za-z0-9_-])/y;

interface Verdict {
  kind: string;
  severity: Severity;
  confidence: number;
}

function classifyJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signatureLength: number
): Verdict {
  const issuer = typeof payload.iss === "string" ? payload.iss : "";
  if (payload.role === "service_role") {
    return {
      kind: "supabase_service_role_key",
      severity: "critical",
      confidence: 0.97,
    };
  }
  if (payload.role === "anon" && issuer.includes("supabase")) {
    return { kind: "supabase_anon_key", severity: "low", confidence: 0.9 };
  }
  if (payload.sub === "1234567890" || payload.name === "John Doe") {
    return { kind: "jwt", severity: "low", confidence: 0.2 };
  }
  const algorithm = typeof header.alg === "string" ? header.alg : "";
  if (signatureLength < 16 || algorithm.toLowerCase() === "none") {
    return { kind: "jwt", severity: "low", confidence: 0.5 };
  }
  if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
    return { kind: "jwt", severity: "low", confidence: 0.6 };
  }
  return { kind: "jwt", severity: "high", confidence: 0.85 };
}

function reportJwt(scan: Scan, value: string, start: number): void {
  const firstDot = value.indexOf(".");
  const secondDot = value.indexOf(".", firstDot + 1);
  const header = decodeBase64Json(value, 0, firstDot);
  const payload = decodeBase64Json(value, firstDot + 1, secondDot);
  const isJwt = header && payload && ("alg" in header || "typ" in header);
  if (!isJwt) {
    return;
  }
  const verdict = classifyJwt(header, payload, value.length - secondDot - 1);
  scan.found.push({
    type: "secret",
    ...verdict,
    start,
    end: start + value.length,
    preview: previewSecret(value, 10),
    priority: PRIORITY_STRUCTURED,
  });
}

function scanJwts(scan: Scan): void {
  const { text } = scan;
  let at = text.indexOf("eyJ");
  while (at !== -1) {
    const before = at > 0 ? text.charCodeAt(at - 1) : 32;
    let next = at + 3;
    if (before >= 128 || TOKEN_CHAR[before] === 0) {
      JWT_PATTERN.lastIndex = at;
      const match = JWT_PATTERN.exec(text);
      if (match) {
        reportJwt(scan, match[0], at);
        next = at + match[0].length;
      }
    }
    at = text.indexOf("eyJ", next);
  }
}

// ---------------------------------------------------------------------------
// Credentials embedded in URLs (database URLs, basic auth)
// ---------------------------------------------------------------------------

const DATABASE_SCHEMES = new Set([
  "postgres",
  "postgresql",
  "mysql",
  "mariadb",
  "mongodb",
  "mongodb+srv",
  "redis",
  "rediss",
  "amqp",
  "amqps",
  "mssql",
  "sqlserver",
  "clickhouse",
  "cockroachdb",
  "couchdb",
  "neo4j",
  "neo4j+s",
  "bolt",
  "cassandra",
  "memcached",
  "kafka",
  "nats",
  "ldap",
  "ldaps",
  "oracle",
  "snowflake",
  "libsql",
  "influxdb",
  "elasticsearch",
  "opensearch",
]);

const DEFAULT_PASSWORDS = new Set([
  "password",
  "pass",
  "passwd",
  "pwd",
  "pw",
  "secret",
  "changeme",
  "admin",
  "root",
  "guest",
  "test",
  "user",
  "username",
  "example",
  "postgres",
  "mysql",
  "redis",
  "mongo",
  "mongodb",
  "rabbitmq",
  "default",
  "letmein",
  "qwerty",
  "123456",
  "12345678",
  "mypassword",
  "mysecretpassword",
  "yourpassword",
  "p@ssw0rd",
  "passw0rd",
  "pa55word",
  "dbpass",
  "dbpassword",
  "opensesame",
  "hunter2",
]);

const PLACEHOLDER_HOST =
  /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|host|hostname|db|database|server|your[-_]?host|[\w.-]*example\.(?:com|org|net)|[\w.-]+\.(?:example|test|invalid|localhost|local))$/i;
const URL_AUTHORITY_STOP = asciiTable(" \t\r\n/?#\"'<>`\\");
const SCHEME_CHAR = asciiTable(`${ALNUM_CHARS}+.-`);
const HOST_PORT = /:\d+$/;

function isPlaceholderPassword(password: string, user: string): boolean {
  const lower = password.toLowerCase();
  return (
    password.length === 0 ||
    DEFAULT_PASSWORDS.has(lower) ||
    lower === user.toLowerCase() ||
    password.startsWith("[") ||
    password.startsWith(":") ||
    looksLikePlaceholder(password)
  );
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function authorityEnd(text: string, from: number): number {
  const limit = Math.min(text.length, from + 512);
  let i = from;
  while (i < limit) {
    const code = text.charCodeAt(i);
    if (code < 128 && URL_AUTHORITY_STOP[code] === 1) {
      break;
    }
    i++;
  }
  return i;
}

function schemeBefore(text: string, colon: number): string {
  let i = colon;
  while (i > 0 && colon - i < 32) {
    const code = text.charCodeAt(i - 1);
    if (code >= 128 || SCHEME_CHAR[code] === 0) {
      break;
    }
    i--;
  }
  return text.slice(i, colon).toLowerCase();
}

interface UrlCredential {
  /** True when the userinfo has no colon: a bare token used as the username. */
  bare: boolean;
  scheme: string;
  user: string;
  password: string;
  passwordStart: number;
  passwordEnd: number;
  host: string;
}

function readUrlCredential(text: string, colon: number): UrlCredential | null {
  const authStart = colon + 3;
  const authEnd = authorityEnd(text, authStart);
  const userinfoEnd = text.slice(authStart, authEnd).lastIndexOf("@");
  if (userinfoEnd === -1) {
    return null;
  }
  const at = authStart + userinfoEnd;
  const scheme = schemeBefore(text, colon);
  if (!scheme) {
    return null;
  }
  const userinfo = text.slice(authStart, at);
  const split = userinfo.indexOf(":");
  const host = text.slice(at + 1, authEnd).replace(HOST_PORT, "");
  const bare = split === -1;
  return {
    bare,
    scheme,
    user: bare ? "" : userinfo.slice(0, split),
    password: bare ? userinfo : userinfo.slice(split + 1),
    passwordStart: bare ? authStart : authStart + split + 1,
    passwordEnd: at,
    host,
  };
}

function credentialVerdict(cred: UrlCredential): Verdict | null {
  const password = safeDecode(cred.password);
  const user = safeDecode(cred.user);
  if (cred.bare) {
    const strong =
      password.length >= 20 &&
      charClassCount(password) >= 2 &&
      shannonEntropy(password) >= 3.5 &&
      !looksLikePlaceholder(password);
    if (!strong) {
      return null;
    }
  } else if (isPlaceholderPassword(password, user)) {
    return null;
  }
  const database = DATABASE_SCHEMES.has(cred.scheme);
  const kind = database ? "database_connection_url" : "url_credentials";
  if (PLACEHOLDER_HOST.test(cred.host)) {
    return { kind, severity: "medium", confidence: 0.6 };
  }
  const weak = password.length < 8 || shannonEntropy(password) < 2.5;
  if (weak) {
    return { kind, severity: "high", confidence: 0.75 };
  }
  return { kind, severity: database ? "critical" : "high", confidence: 0.9 };
}

function scanUrlCredentials(scan: Scan): void {
  const { text } = scan;
  let colon = text.indexOf("://");
  while (colon !== -1) {
    // Credentials in a URL need an "@"; stop once none is left.
    if (text.indexOf("@", colon) === -1) {
      return;
    }
    const cred = readUrlCredential(text, colon);
    const verdict = cred ? credentialVerdict(cred) : null;
    if (cred && verdict) {
      const userPart = cred.user ? `${cred.user.slice(0, 32)}:` : "";
      scan.found.push({
        type: "secret",
        ...verdict,
        start: cred.passwordStart,
        end: cred.passwordEnd,
        preview: `${cred.scheme}://${userPart}****@${cred.host.slice(0, 64)}`,
        priority: PRIORITY_STRUCTURED,
      });
    }
    colon = text.indexOf("://", colon + 3);
  }
}

// ---------------------------------------------------------------------------
// Assignments: password = "...", api_key: ..., Authorization: Bearer ...
// ---------------------------------------------------------------------------

const ASSIGNMENT_KEY =
  /pass|pwd|secret|token|api[-_]?key|access[-_]?key|auth|credential|private[-_]?key|[-_]key$/i;
const AUTH_SCHEME = /^(bearer|basic|token)[ \t]+/i;
const NOT_A_SECRET_VALUE =
  /^(?:https?:|www\.|\/|\.\.?\/|~\/|[A-Za-z]:\\)|\.(?:json|ya?ml|toml|env|pem|key|crt|txt|js|ts|py|sh|md|html?)$/i;
const ENV_NAME = /^[A-Z][A-Z0-9_]*$/;
const MEMBER_EXPRESSION = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;
const LETTERS_ONLY = /^[A-Za-z]+$/;
const TRAILING_PUNCTUATION = /[.,:;!?]+$/;
const PASSWORD_KEY = /pass|pwd/i;
const STRONG_KEY = /pass|pwd|secret|token|api[-_]?key/i;
const IDENT_CHAR = asciiTable(`${ALNUM_CHARS}_-.`);
/** Whitespace, quotes, brackets, and separators end an unquoted value. */
const VALUE_STOP = asciiTable(" \t\r\n\"'`,;()[]{}<>=:");
const IDENT_MAX = 64;
const VALUE_MAX = 512;
const MIN_VALUE = 16;

function isQuote(char: string): boolean {
  return char === '"' || char === "'" || char === "`";
}

function skipBlanks(text: string, from: number): number {
  let i = from;
  while (i < text.length && i - from < 4) {
    const c = text.charAt(i);
    if (c !== " " && c !== "\t") {
      break;
    }
    i++;
  }
  return i;
}

/** Length of an assignment operator at `i` (":", "=", ":=", "=>", "=="), or 0. */
function operatorLength(text: string, i: number): number {
  const c = text.charAt(i);
  const next = text.charAt(i + 1);
  if (c === ":") {
    if (next === ":") {
      return 0;
    }
    return next === "=" ? 2 : 1;
  }
  if (next === ">") {
    return 2;
  }
  if (next === "=") {
    return text.charAt(i + 2) === "=" ? 3 : 2;
  }
  return 1;
}

/** True for the second character of a multi-character operator ("==", ":=", "!="). */
function continuesOperator(text: string, i: number): boolean {
  const previous = text.charAt(i - 1);
  return (
    previous === ":" ||
    previous === "=" ||
    previous === "!" ||
    previous === "<" ||
    previous === ">"
  );
}

interface AssignedValue {
  start: number;
  end: number;
  quoted: boolean;
  scheme: string;
}

function quotedValueEnd(text: string, from: number, quote: string): number {
  const limit = Math.min(text.length, from + VALUE_MAX);
  for (let i = from; i < limit; i++) {
    const c = text.charAt(i);
    if (c === quote) {
      return i;
    }
    if (c === "\n") {
      return -1;
    }
  }
  return -1;
}

function unquotedValueEnd(text: string, from: number): number {
  const limit = Math.min(text.length, from + VALUE_MAX);
  let i = from;
  while (i < limit) {
    const code = text.charCodeAt(i);
    if (code < 128 && VALUE_STOP[code] === 1) {
      break;
    }
    i++;
  }
  // Keep base64 padding ("abc==") even though "=" otherwise ends a value.
  let padding = 0;
  while (padding < 2 && text.charCodeAt(i + padding) === 61) {
    padding++;
  }
  const next = text.charCodeAt(i + padding);
  if (
    padding > 0 &&
    (Number.isNaN(next) ||
      (next < 128 && VALUE_STOP[next] === 1 && next !== 61))
  ) {
    i += padding;
  }
  if (i - from < MIN_VALUE) {
    return i;
  }
  const raw = text.slice(from, i);
  return from + raw.replace(TRAILING_PUNCTUATION, "").length;
}

/** Cheap test for "Bearer", "Basic", or "Token" at `i`, before any slicing. */
function mayStartScheme(text: string, i: number): boolean {
  const c = text.charCodeAt(i);
  return c === 66 || c === 98 || c === 84 || c === 116;
}

function readAssignedValue(text: string, from: number): AssignedValue | null {
  let i = from;
  const quote = isQuote(text.charAt(i)) ? text.charAt(i) : "";
  if (quote) {
    i++;
  }
  const schemeMatch = mayStartScheme(text, i)
    ? AUTH_SCHEME.exec(text.slice(i, i + 16))
    : null;
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : "";
  if (schemeMatch) {
    i += schemeMatch[0].length;
  }
  const end = quote
    ? quotedValueEnd(text, i, quote)
    : unquotedValueEnd(text, i);
  if (end - i < MIN_VALUE) {
    return null;
  }
  if (scheme && quote) {
    // "Bearer <token>" inside quotes: the token ends at the first blank.
    return {
      start: i,
      end: Math.min(end, unquotedValueEnd(text, i)),
      quoted: true,
      scheme,
    };
  }
  return { start: i, end, quoted: quote !== "", scheme };
}

/** The identifier an operator assigns to, skipping blanks and a closing quote. */
function identifierBefore(text: string, operator: number): string {
  let end = operator;
  while (end > 0 && operator - end < 4 && text.charAt(end - 1) === " ") {
    end--;
  }
  if (end > 0 && isQuote(text.charAt(end - 1))) {
    end--;
  }
  let start = end;
  while (start > 0 && end - start < IDENT_MAX) {
    const code = text.charCodeAt(start - 1);
    if (code >= 128 || IDENT_CHAR[code] === 0) {
      break;
    }
    start--;
  }
  return text.slice(start, end);
}

/** Entropy of a plausible secret value, or null when it reads like code, prose, or filler. */
function genericValueEntropy(value: string): number | null {
  if (value.length < MIN_VALUE || value.length > VALUE_MAX) {
    return null;
  }
  const codeLike =
    NOT_A_SECRET_VALUE.test(value) ||
    ENV_NAME.test(value) ||
    MEMBER_EXPRESSION.test(value) ||
    LETTERS_ONLY.test(value);
  if (codeLike || looksLikePlaceholder(value)) {
    return null;
  }
  const entropy = shannonEntropy(value);
  return entropy >= 3.5 ? entropy : null;
}

function basicAuthVerdict(value: string): Verdict | null {
  const bytes = decodeBase64(value);
  if (!bytes || value.length < 8) {
    return null;
  }
  const decoded = bytesToLatin1(bytes);
  const split = decoded.indexOf(":");
  if (split <= 0) {
    return null;
  }
  const password = decoded.slice(split + 1);
  if (
    password.length < 4 ||
    isPlaceholderPassword(password, decoded.slice(0, split))
  ) {
    return null;
  }
  return { kind: "basic_auth_credentials", severity: "high", confidence: 0.8 };
}

function assignmentVerdict(
  identifier: string,
  value: string,
  assigned: AssignedValue
): (Verdict & { priority: number }) | null {
  if (assigned.scheme === "basic") {
    const verdict = basicAuthVerdict(value);
    return verdict ? { ...verdict, priority: PRIORITY_CONTEXT } : null;
  }
  const entropy = genericValueEntropy(value);
  if (entropy === null) {
    return null;
  }
  if (assigned.scheme) {
    return {
      kind: "bearer_token",
      severity: "high",
      confidence: 0.75,
      priority: PRIORITY_CONTEXT,
    };
  }
  if (!(hasDigit(value) || charClassCount(value) >= 3)) {
    return null;
  }
  let confidence = 0.55;
  confidence += entropy >= 4.2 ? 0.1 : 0;
  confidence += assigned.quoted ? 0.05 : 0;
  confidence += STRONG_KEY.test(identifier) ? 0.05 : 0;
  return {
    kind: PASSWORD_KEY.test(identifier)
      ? "password_assignment"
      : "generic_secret",
    severity: "high",
    confidence: Math.round(confidence * 100) / 100,
    priority: PRIORITY_GENERIC,
  };
}

function readAssignment(scan: Scan, operator: number): RankedFinding | null {
  const { text } = scan;
  if (continuesOperator(text, operator)) {
    return null;
  }
  const length = operatorLength(text, operator);
  if (length === 0) {
    return null;
  }
  const valueAt = skipBlanks(text, operator + length);
  if (text.startsWith("//", valueAt)) {
    return null;
  }
  const assigned = readAssignedValue(text, valueAt);
  if (!assigned) {
    return null;
  }
  const identifier = identifierBefore(text, operator);
  if (!ASSIGNMENT_KEY.test(identifier)) {
    return null;
  }
  const value = text.slice(assigned.start, assigned.end);
  const verdict = assignmentVerdict(identifier, value, assigned);
  if (!verdict) {
    return null;
  }
  const masked =
    verdict.kind === "password_assignment" ? "…" : previewSecret(value, 0);
  return {
    type: "secret",
    ...verdict,
    start: assigned.start,
    end: assigned.end,
    preview: `${identifier.slice(0, 32)}=${masked}`,
  };
}

function scanAssignments(scan: Scan): void {
  const { text } = scan;
  const claimed = new Set<number>();
  for (const operator of [":", "="]) {
    let at = text.indexOf(operator);
    while (at !== -1) {
      const finding = readAssignment(scan, at);
      if (finding && !claimed.has(finding.start)) {
        claimed.add(finding.start);
        scan.found.push(finding);
      }
      at = text.indexOf(operator, at + 1);
    }
  }
}

// ---------------------------------------------------------------------------

function runStructuredScanners(scan: Scan): void {
  const { text, filter } = scan;
  if (text.includes("PRIVATE KEY") && wants(filter, PRIVATE_KEY_KINDS)) {
    scanPrivateKeys(scan);
  }
  if (text.includes("eyJ") && wants(filter, JWT_KINDS)) {
    scanJwts(scan);
  }
  if (text.includes("://") && wants(filter, URL_CREDENTIAL_KINDS)) {
    scanUrlCredentials(scan);
  }
  if (wants(filter, ASSIGNMENT_KINDS)) {
    scanAssignments(scan);
  }
}

/**
 * Finds credentials in model output: vendor API keys and tokens, private key
 * blocks, JWTs, credentials embedded in connection URLs, and high-entropy
 * values assigned to secret-looking names.
 *
 * Tuned for precision on LLM output, which often quotes *example* keys:
 * placeholder bodies (`sk-...`, `YOUR_API_KEY`, `xxxx`, `abcdef123456`) and
 * low-entropy values are skipped, and test-mode keys are reported as low.
 */
export function detectSecrets(
  text: string,
  options: SecretsOptions = {}
): OutputFinding[] {
  if (typeof text !== "string" || text.length < 8) {
    return [];
  }
  const scan: Scan = {
    text,
    filter: {
      kinds: options.kinds ? new Set(options.kinds) : null,
      exclude: options.exclude ? new Set(options.exclude) : null,
    },
    found: [],
    runs: [],
    unfiltered: !(options.kinds || options.exclude),
  };
  lex(scan);
  runGatedRules(scan);
  runContextRules(scan);
  runStructuredScanners(scan);
  return filterFindings(stripPriority(resolveOverlaps(scan.found)), options);
}
