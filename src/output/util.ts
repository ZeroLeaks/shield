import type { OutputFinding, Severity } from "./types";

export const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function atLeast(severity: Severity, floor: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[floor];
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  const length = value.length;
  if (length === 0) {
    return 0;
  }
  const counts = new Map<number, number>();
  for (let i = 0; i < length; i++) {
    const code = value.charCodeAt(i);
    counts.set(code, (counts.get(code) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Longest run of one repeated character. */
export function longestRun(value: string): number {
  let best = value.length > 0 ? 1 : 0;
  let run = 1;
  for (let i = 1; i < value.length; i++) {
    run = value.charCodeAt(i) === value.charCodeAt(i - 1) ? run + 1 : 1;
    if (run > best) {
      best = run;
    }
  }
  return best;
}

/** Longest run of consecutive character codes, ascending or descending ("abcdef", "987654"). */
export function longestSequence(value: string): number {
  let best = value.length > 0 ? 1 : 0;
  let up = 1;
  let down = 1;
  for (let i = 1; i < value.length; i++) {
    const delta = value.charCodeAt(i) - value.charCodeAt(i - 1);
    up = delta === 1 ? up + 1 : 1;
    down = delta === -1 ? down + 1 : 1;
    best = Math.max(best, up, down);
  }
  return best;
}

/** Number of character classes present: lowercase, uppercase, digit, other. */
export function charClassCount(value: string): number {
  let lower = 0;
  let upper = 0;
  let digit = 0;
  let other = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 97 && c <= 122) {
      lower = 1;
    } else if (c >= 65 && c <= 90) {
      upper = 1;
    } else if (c >= 48 && c <= 57) {
      digit = 1;
    } else {
      other = 1;
    }
  }
  return lower + upper + digit + other;
}

export function hasDigit(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 48 && c <= 57) {
      return true;
    }
  }
  return false;
}

const PLACEHOLDER_MARKERS = [
  "example",
  "sample",
  "dummy",
  "placeholder",
  "your",
  "xxxx",
  "changeme",
  "change_me",
  "change-me",
  "redacted",
  "insert",
  "replace",
  "fake",
  "mock",
  "todo",
  "fixme",
  "test",
  "here",
  "secret",
  "token",
  "password",
  "passwd",
  "apikey",
  "api_key",
  "api-key",
  "foobar",
  "lorem",
  "...",
  "…",
  "***",
  "###",
  "___",
  "---",
];

function capitalize(word: string): string {
  return word.charAt(0).toUpperCase() + word.slice(1);
}

const PLACEHOLDER_FORMS: string[] = [];
for (const marker of PLACEHOLDER_MARKERS) {
  PLACEHOLDER_FORMS.push(marker);
  const upper = marker.toUpperCase();
  if (upper !== marker) {
    PLACEHOLDER_FORMS.push(upper, capitalize(marker));
  }
}

const TEMPLATE_SYNTAX = /[<>{}$`\s]|%s|%\(/;

/**
 * True when a secret body reads like documentation filler rather than a live
 * value: marker words ("your", "example", "xxxx"), template syntax, long runs
 * of one character, or a keyboard sequence such as "abcdef" or "123456".
 *
 * Marker words are matched in lowercase, UPPERCASE, and Capitalized form only,
 * so random mixed-case key bodies almost never trip them by chance.
 */
export function looksLikePlaceholder(body: string): boolean {
  if (TEMPLATE_SYNTAX.test(body)) {
    return true;
  }
  for (const form of PLACEHOLDER_FORMS) {
    if (body.includes(form)) {
      return true;
    }
  }
  return longestRun(body) >= 6 || longestSequence(body) >= 6;
}

/**
 * Safe preview of a secret: the public prefix (capped at a third of the value)
 * plus the last four characters when the secret part is long enough.
 */
export function previewSecret(value: string, prefixLength: number): string {
  const headLength = Math.min(prefixLength, Math.floor(value.length / 3));
  const head = value.slice(0, headLength);
  const tail = value.length - headLength >= 16 ? value.slice(-4) : "";
  return `${head}…${tail}`;
}

const BASE64_VALUES = new Int8Array(128).fill(-1);
const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
for (let i = 0; i < BASE64_ALPHABET.length; i++) {
  BASE64_VALUES[BASE64_ALPHABET.charCodeAt(i)] = i;
}
BASE64_VALUES["-".charCodeAt(0)] = 62;
BASE64_VALUES["_".charCodeAt(0)] = 63;

/**
 * Lenient base64 / base64url decoder. Padding is optional and ignored; any
 * other character outside the alphabet makes the input invalid (null).
 */
export function decodeBase64(
  input: string,
  from = 0,
  to = input.length
): Uint8Array | null {
  const out = new Uint8Array(Math.floor(((to - from) * 3) / 4) + 1);
  let size = 0;
  let buffer = 0;
  let bits = 0;
  for (let i = from; i < to; i++) {
    const code = input.charCodeAt(i);
    if (code === 61) {
      continue;
    }
    const value = code < 128 ? BASE64_VALUES[code] : -1;
    if (value < 0) {
      return null;
    }
    buffer = buffer * 64 + value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      const divisor = 2 ** bits;
      out[size] = Math.floor(buffer / divisor);
      size++;
      buffer %= divisor;
    }
  }
  return out.subarray(0, size);
}

export function bytesToLatin1(bytes: Uint8Array): string {
  let out = "";
  const chunk = 8192;
  for (let i = 0; i < bytes.length; i += chunk) {
    out += String.fromCharCode.apply(
      null,
      bytes.subarray(i, i + chunk) as unknown as number[]
    );
  }
  return out;
}

/** Decodes base64url JSON (JWT segments). Returns null for anything that is not a JSON object. */
export function decodeBase64Json(
  input: string,
  from = 0,
  to = input.length
): Record<string, unknown> | null {
  const bytes = decodeBase64(input, from, to);
  // JSON.parse throws on anything else, and exceptions are slow.
  if (!bytes || bytes.length < 2 || bytes[0] !== 123) {
    return null;
  }
  let last = bytes.length - 1;
  while (last > 0 && bytes[last] <= 32) {
    last--;
  }
  if (bytes[last] !== 125) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(bytesToLatin1(bytes));
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return null;
  }
  return null;
}

/** Last element of an array (`Array.prototype.at` is ES2022; this package targets ES2020). */
export function lastItem<T>(items: readonly T[]): T | undefined {
  // biome-ignore lint/style/useAtIndex: the ES2020 target does not include Array.prototype.at.
  return items[items.length - 1];
}

/** Finding plus an internal priority used when two detectors claim the same span. */
export interface RankedFinding extends OutputFinding {
  priority: number;
}

function outranks(a: RankedFinding, b: RankedFinding): boolean {
  if (a.priority !== b.priority) {
    return a.priority > b.priority;
  }
  if (a.confidence !== b.confidence) {
    return a.confidence > b.confidence;
  }
  return a.end - a.start > b.end - b.start;
}

function resolveCluster(cluster: RankedFinding[], out: RankedFinding[]): void {
  if (cluster.length === 1) {
    out.push(cluster[0]);
    return;
  }
  const ranked = [...cluster].sort((a, b) => {
    if (outranks(a, b)) {
      return -1;
    }
    return outranks(b, a) ? 1 : 0;
  });
  const kept: RankedFinding[] = [];
  for (const candidate of ranked) {
    const overlaps = kept.some(
      (k) => candidate.start < k.end && k.start < candidate.end
    );
    if (!overlaps) {
      kept.push(candidate);
    }
  }
  out.push(...kept);
}

/**
 * Drops findings that overlap a better one (higher priority, then confidence,
 * then length). Runs in O(n log n) by resolving each overlapping cluster alone.
 */
export function resolveOverlaps(findings: RankedFinding[]): RankedFinding[] {
  if (findings.length < 2) {
    return findings;
  }
  const sorted = [...findings].sort(
    (a, b) => a.start - b.start || b.end - a.end
  );
  const out: RankedFinding[] = [];
  let cluster: RankedFinding[] = [sorted[0]];
  let clusterEnd = sorted[0].end;
  for (let i = 1; i < sorted.length; i++) {
    const finding = sorted[i];
    if (finding.start < clusterEnd) {
      cluster.push(finding);
      clusterEnd = Math.max(clusterEnd, finding.end);
    } else {
      resolveCluster(cluster, out);
      cluster = [finding];
      clusterEnd = finding.end;
    }
  }
  resolveCluster(cluster, out);
  return out.sort((a, b) => a.start - b.start || b.end - a.end);
}

export function stripPriority(findings: RankedFinding[]): OutputFinding[] {
  return findings.map((f) => ({
    type: f.type,
    kind: f.kind,
    start: f.start,
    end: f.end,
    severity: f.severity,
    confidence: f.confidence,
    preview: f.preview,
  }));
}

export function compareFindings(a: OutputFinding, b: OutputFinding): number {
  return a.start - b.start || b.end - a.end;
}

/** Filters by kind allow/deny lists and a confidence floor. */
export function filterFindings<T extends OutputFinding>(
  findings: T[],
  options: { kinds?: string[]; exclude?: string[]; minConfidence?: number }
): T[] {
  const kinds = options.kinds ? new Set(options.kinds) : null;
  const exclude = options.exclude ? new Set(options.exclude) : null;
  const minConfidence = options.minConfidence ?? 0;
  return findings.filter(
    (f) =>
      (!kinds || kinds.has(f.kind)) &&
      !exclude?.has(f.kind) &&
      f.confidence >= minConfidence
  );
}
