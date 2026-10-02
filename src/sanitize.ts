// biome-ignore-all lint/suspicious/noBitwiseOperators: n-gram keys are built from FNV-style hashes.
import { type DecodedPayload, decodePayloads } from "./decode";

export interface SanitizeResult {
  leaked: boolean;
  confidence: number;
  fragments: string[];
  sanitized: string;
}

/** A `sanitize` result that also says where each redaction was made. */
export interface RedactedSanitizeResult extends SanitizeResult {
  /**
   * Sorted, disjoint `[start, end)` offsets of the output that `sanitized`
   * replaces with `redactionText`.
   */
  redactions: [number, number][];
  redactionText: string;
}

export interface SanitizeOptions {
  ngramSize?: number;
  threshold?: number;
  wordOverlapThreshold?: number;
  redactionText?: string;
  detectOnly?: boolean;
  /**
   * Also look for the prompt inside text the output encodes: base64, hex,
   * binary, decimal character codes, Morse, URL encoding, HTML entities,
   * escape sequences, ROT13, and reversed text. On by default.
   */
  decodePayloads?: boolean;
}

export function sanitizeObject<T extends Record<string, unknown>>(
  obj: T,
  systemPrompt: string,
  options: SanitizeOptions = {}
): { result: T; hadLeak: boolean } {
  if (!obj || typeof obj !== "object") {
    return { result: obj, hadLeak: false };
  }
  const result = (Array.isArray(obj) ? [...obj] : { ...obj }) as T;
  let hadLeak = false;
  for (const key of Object.keys(result)) {
    const val = result[key as keyof T];
    if (typeof val === "string") {
      const r = sanitize(val, systemPrompt, options);
      if (r.leaked) {
        hadLeak = true;
        (result as Record<string, unknown>)[key] = r.sanitized;
      }
    } else if (
      val !== null &&
      typeof val === "object" &&
      (Object.prototype.toString.call(val) === "[object Object]" ||
        Array.isArray(val))
    ) {
      const nested = sanitizeObject(
        val as Record<string, unknown>,
        systemPrompt,
        options
      );
      (result as Record<string, unknown>)[key] = nested.result;
      if (nested.hadLeak) {
        hadLeak = true;
      }
    }
  }
  return { result, hadLeak };
}

// --- Tokenizing with offsets ---

interface Token {
  text: string;
  hash: number;
  /** Offsets in the original text, so redactions land on the raw characters. */
  start: number;
  end: number;
}

const RE_LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;
const RE_COMBINING =
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: the class lists combining and format characters on purpose, to find or strip them.
  /[\u0300-\u036f\u0483-\u0489\u0591-\u05c7\u064b-\u065f\u0670\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]/g;
// Characters that are dropped without ending a word, so they can't be used
// to split a leaked word in two: zero-width and other format characters,
// variation selectors, and tag characters.
const RE_IGNORABLE =
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: the class lists combining and format characters on purpose, to find or strip them.
  /^(?:[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]|[\u{e0000}-\u{e01ef}])$/u;
// Scripts written without spaces between words. Each character is its own
// token.
const RE_UNSPACED_SCRIPT =
  /[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u0e00-\u0e7f\u0e80-\u0eff\u1000-\u109f\u1780-\u17ff]/u;

/** Letters from other scripts that look like Latin ones, folded on both sides. */
const LOOKALIKES: Record<string, string> = {
  а: "a",
  в: "b",
  е: "e",
  к: "k",
  м: "m",
  н: "h",
  о: "o",
  р: "p",
  с: "c",
  т: "t",
  у: "y",
  х: "x",
  ѕ: "s",
  і: "i",
  ј: "j",
  һ: "h",
  ԁ: "d",
  ӏ: "l",
  α: "a",
  ε: "e",
  ι: "i",
  κ: "k",
  ν: "v",
  ο: "o",
  ρ: "p",
  τ: "t",
  υ: "u",
  χ: "x",
  ı: "i",
  ł: "l",
  ø: "o",
  đ: "d",
};

const RE_ASCII_WORD = /^[a-z]+$/;

const LEET: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  $: "s",
};

/** Lowercase, compatibility-decomposed, de-accented form of one code point. */
function foldCodePoint(ch: string): string {
  const code = ch.charCodeAt(0);
  if (code < 0x80) {
    return code >= 65 && code <= 90 ? String.fromCharCode(code + 32) : ch;
  }
  const folded = ch.normalize("NFKD").toLowerCase().replace(RE_COMBINING, "");
  let out = "";
  for (const c of folded) {
    out += LOOKALIKES[c] ?? c;
  }
  return out;
}

function isWordChar(ch: string): boolean {
  const code = ch.charCodeAt(0);
  if (code < 0x80) {
    return (
      (code >= 97 && code <= 122) ||
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 90)
    );
  }
  return RE_LETTER_OR_DIGIT.test(ch);
}

/** Decodes leetspeak in a token that mixes letters with leet digits. */
function unleet(token: string): string {
  let letters = false;
  let leet = false;
  for (const ch of token) {
    if (ch >= "a" && ch <= "z") {
      letters = true;
    } else if (ch in LEET) {
      leet = true;
    }
  }
  if (!(letters && leet)) {
    return token;
  }
  let out = "";
  for (const ch of token) {
    out += LEET[ch] ?? ch;
  }
  return out;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: matches any character outside ASCII.
const RE_NON_ASCII_TEXT = /[^\x00-\x7f]/;

function hashToken(text: string): number {
  let h = 0x81_1c_9d_c5;
  for (let i = 0; i < text.length; i++) {
    h = Math.imul(h ^ text.charCodeAt(i), 0x01_00_01_93);
  }
  return h >>> 0;
}

function makeToken(text: string, start: number, end: number): Token {
  const word = unleet(text);
  return { text: word, hash: hashToken(word), start, end };
}

/** Tokenizer for ASCII text: offsets carry over from a lowercased copy. */
function tokenizeAscii(text: string): Token[] {
  const lower = text.toLowerCase();
  const tokens: Token[] = [];
  let start = -1;
  for (let i = 0; i <= lower.length; i++) {
    const c = i < lower.length ? lower.charCodeAt(i) : 32;
    const word =
      (c >= 97 && c <= 122) ||
      (c >= 48 && c <= 57) ||
      (start >= 0 && (c === 36 || c === 64));
    if (word) {
      if (start < 0) {
        start = i;
      }
    } else if (start >= 0) {
      tokens.push(makeToken(lower.slice(start, i), start, i));
      start = -1;
    }
  }
  return tokens;
}

/** Collects word tokens, remembering where each starts in the original text. */
class TokenBuilder {
  readonly tokens: Token[] = [];
  private current = "";
  private start = -1;
  private end = -1;

  /** Adds a character of the word that covers `[at, to)` in the original. */
  add(ch: string, at: number, to: number): void {
    if (this.start < 0) {
      this.start = at;
    }
    this.current += ch;
    this.end = to;
  }

  /** Whether a word is in progress, so `$` and `@` count as part of it. */
  get inWord(): boolean {
    return this.current !== "";
  }

  flush(): void {
    if (this.current) {
      this.tokens.push(makeToken(this.current, this.start, this.end));
    }
    this.current = "";
    this.start = -1;
  }

  /** A character of an unspaced script: a word of its own. */
  single(ch: string, at: number, to: number): void {
    this.flush();
    this.tokens.push(makeToken(ch, at, to));
  }
}

function isAsciiWord(c: number, inWord: boolean): boolean {
  return (
    (c >= 97 && c <= 122) ||
    (c >= 48 && c <= 57) ||
    (inWord && (c === 36 || c === 64))
  );
}

/** Adds one non-ASCII code point, folded, to the tokens being built. */
function addCodePoint(
  builder: TokenBuilder,
  ch: string,
  at: number,
  width: number
): void {
  for (const c of foldCodePoint(ch)) {
    if (RE_UNSPACED_SCRIPT.test(c)) {
      builder.single(c, at, at + width);
    } else if (isWordChar(c) || (builder.inWord && (c === "$" || c === "@"))) {
      builder.add(c, at, at + width);
    } else {
      builder.flush();
    }
  }
}

/**
 * Splits text into lowercase, accent-free words with their offsets in the
 * original text. Ignorable characters inside a word are skipped, look-alike
 * letters are folded to Latin, and each character of an unspaced script is a
 * word of its own.
 */
function tokenize(text: string): Token[] {
  if (!RE_NON_ASCII_TEXT.test(text)) {
    return tokenizeAscii(text);
  }
  const builder = new TokenBuilder();
  let i = 0;
  while (i < text.length) {
    const code = text.codePointAt(i) ?? 0;
    const width = code > 0xff_ff ? 2 : 1;
    if (code < 0x80) {
      const c = code >= 65 && code <= 90 ? code + 32 : code;
      if (isAsciiWord(c, builder.inWord)) {
        builder.add(String.fromCharCode(c), i, i + 1);
      } else {
        builder.flush();
      }
    } else {
      const ch = text.slice(i, i + width);
      if (!RE_IGNORABLE.test(ch)) {
        addCodePoint(builder, ch, i, width);
      }
    }
    i += width;
  }
  builder.flush();
  return builder.tokens;
}

// --- Matching ---

interface Run {
  /** Token indices `[from, to)` in the output. */
  from: number;
  to: number;
}

/**
 * A number identifying the n tokens starting at `i`: two 32-bit hashes of
 * the token hashes packed into 52 bits, so n-grams compare as numbers.
 */
function ngramKey(tokens: Token[], i: number, n: number): number {
  let a = 0x81_1c_9d_c5;
  let b = 0x9e_37_79_b9;
  for (let k = 0; k < n; k++) {
    const h = tokens[i + k].hash;
    a = Math.imul(a ^ h, 0x01_00_01_93);
    b = Math.imul(b ^ ((h >>> 11) | (h << 21)), 0x5b_d1_e9_95);
  }
  return (a >>> 0) * 1_048_576 + ((b >>> 0) & 0xf_ff_ff);
}

/**
 * Marks each output token covered by an n-gram that also occurs in the
 * prompt, and returns the maximal runs of marked tokens plus the number of
 * distinct prompt n-grams the output reproduced.
 */
function matchRuns(
  outputTokens: Token[],
  promptNgrams: Set<number>,
  n: number
): { runs: Run[]; matchedNgrams: number } {
  const covered = new Uint8Array(outputTokens.length);
  const seen = new Set<number>();
  for (let i = 0; i + n <= outputTokens.length; i++) {
    const key = ngramKey(outputTokens, i, n);
    if (promptNgrams.has(key)) {
      seen.add(key);
      covered.fill(1, i, i + n);
    }
  }
  const runs: Run[] = [];
  let from = -1;
  for (let i = 0; i <= covered.length; i++) {
    if (i < covered.length && covered[i]) {
      if (from < 0) {
        from = i;
      }
    } else if (from >= 0) {
      runs.push({ from, to: i });
      from = -1;
    }
  }
  return { runs, matchedNgrams: seen.size };
}

function ngrams(tokens: Token[], n: number): Set<number> {
  const out = new Set<number>();
  for (let i = 0; i + n <= tokens.length; i++) {
    out.add(ngramKey(tokens, i, n));
  }
  return out;
}

function wordOverlapRatio(output: Token[], prompt: Token[]): number {
  const outSet = new Set(output.map((t) => t.text));
  const promptSet = new Set(prompt.map((t) => t.text));
  let intersection = 0;
  for (const w of outSet) {
    if (promptSet.has(w)) {
      intersection++;
    }
  }
  const union = outSet.size + promptSet.size - intersection;
  return union > 0 ? intersection / union : 0;
}

interface LeakCheck {
  leaked: boolean;
  confidence: number;
  fragments: string[];
  /** Offsets in the checked text of the runs to redact. */
  ranges: [number, number][];
}

interface PromptModel {
  tokens: Token[];
  n: number;
  ngrams: Set<number>;
  smallN: number;
  smallNgrams: Set<number>;
  /** Longer prompt words, reversed and in ROT13, to decide whether those checks are worth running. */
  reversedProbes: string[];
  rot13Probes: string[];
}

function modelPrompt(
  systemPrompt: string,
  options: SanitizeOptions
): PromptModel | undefined {
  const tokens = tokenize(systemPrompt);
  if (tokens.length < 2) {
    return;
  }
  const unspaced = tokens.filter((t) => RE_UNSPACED_SCRIPT.test(t.text)).length;
  // Characters of unspaced scripts carry less than words, so need longer runs.
  const scale = unspaced > tokens.length / 2 ? 2 : 1;
  const requested = (options.ngramSize ?? 4) * scale;
  const n = Math.min(requested, Math.max(2, tokens.length));
  const smallN = Math.min(3 * scale, Math.max(1, n - 1));
  const probes = [
    ...new Set(
      tokens
        .map((t) => t.text)
        .filter((w) => w.length >= 5 && RE_ASCII_WORD.test(w))
    ),
  ].slice(0, 32);
  return {
    tokens,
    n,
    ngrams: ngrams(tokens, n),
    smallN,
    smallNgrams: smallN >= 2 ? ngrams(tokens, smallN) : new Set(),
    reversedProbes: probes.map(reverse),
    rot13Probes: probes.map(rot13),
  };
}

function checkLeak(
  text: string,
  prompt: PromptModel,
  options: SanitizeOptions
): LeakCheck {
  const threshold = options.threshold ?? 0.7;
  const wordOverlapThreshold = options.wordOverlapThreshold ?? 0.25;
  const tokens = tokenize(text);
  const { runs, matchedNgrams } = matchRuns(tokens, prompt.ngrams, prompt.n);
  const small =
    prompt.smallNgrams.size > 0
      ? matchRuns(tokens, prompt.smallNgrams, prompt.smallN).runs
      : [];
  const coverage =
    prompt.ngrams.size > 0 ? matchedNgrams / prompt.ngrams.size : 0;
  const wordOverlap = wordOverlapRatio(tokens, prompt.tokens);
  const longestRun = Math.max(0, ...runs.map((r) => r.to - r.from));

  let confidence = 0;
  if (runs.length > 0) {
    confidence = Math.min(1, coverage * 2 + (runs.length > 2 ? 0.2 : 0));
  } else if (wordOverlap >= wordOverlapThreshold) {
    confidence = Math.min(1, wordOverlap * 2);
  }

  const leaked =
    (runs.length > 0 && confidence >= threshold) ||
    runs.length >= 2 ||
    longestRun >= 2 * prompt.n + 1 ||
    (small.length >= 3 && wordOverlap >= wordOverlapThreshold) ||
    (wordOverlap >= wordOverlapThreshold * 1.5 && small.length >= 1);

  if (!leaked) {
    return { leaked: false, confidence, fragments: [], ranges: [] };
  }
  const redactRuns = [...runs, ...small];
  const fragments = [
    ...new Set(
      redactRuns.map((r) =>
        tokens
          .slice(r.from, r.to)
          .map((t) => t.text)
          .join(" ")
      )
    ),
  ];
  const ranges = redactRuns.map((r): [number, number] => [
    tokens[r.from].start,
    tokens[r.to - 1].end,
  ]);
  return { leaked: true, confidence, fragments, ranges };
}

function reverse(text: string): string {
  let out = "";
  for (let i = text.length - 1; i >= 0; i--) {
    const code = text.charCodeAt(i);
    // Keep surrogate pairs in order.
    if (code >= 0xdc_00 && code <= 0xdf_ff && i > 0) {
      out += text[i - 1] + text[i];
      i--;
    } else {
      out += text[i];
    }
  }
  return out;
}

function rot13(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 97 && c <= 122) {
      out += String.fromCharCode(((c - 97 + 13) % 26) + 97);
    } else if (c >= 65 && c <= 90) {
      out += String.fromCharCode(((c - 65 + 13) % 26) + 65);
    } else {
      out += text[i];
    }
  }
  return out;
}

/** Sorts ranges and merges any that overlap or touch. */
function mergeRanges(ranges: [number, number][]): [number, number][] {
  const sorted = [...ranges].sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const [start, end] of sorted) {
    // biome-ignore lint/style/useAtIndex: the ES2020 target does not include Array.prototype.at.
    const last = merged[merged.length - 1];
    if (last && start <= last[1]) {
      last[1] = Math.max(last[1], end);
    } else {
      merged.push([start, end]);
    }
  }
  return merged;
}

const SANITIZE_MAX_OUTPUT_LENGTH = 1024 * 1024;

export function sanitize(
  output: string,
  systemPrompt: string,
  options: SanitizeOptions = {}
): SanitizeResult {
  const { leaked, confidence, fragments, sanitized } = sanitizeWithRedactions(
    output,
    systemPrompt,
    options
  );
  return { leaked, confidence, fragments, sanitized };
}

interface LeakSearch {
  leaked: boolean;
  confidence: number;
  fragments: string[];
  ranges: [number, number][];
  /** A leak was found in an encoding that can't be cut out alone. */
  redactAll: boolean;
}

/** Whether at least two of `probes` occur in `lower`. */
function probesFound(lower: string, probes: string[]): boolean {
  let found = 0;
  for (const probe of probes) {
    if (lower.includes(probe)) {
      found++;
      if (found >= 2) {
        return true;
      }
    }
  }
  return false;
}

function addLeak(search: LeakSearch, found: LeakCheck, label: string): void {
  search.leaked = true;
  search.confidence = Math.max(search.confidence, found.confidence);
  search.fragments.push(...found.fragments.map((f) => `${label}:${f}`));
}

/**
 * Looks for the prompt in reversed and ROT13 copies of the output, and in
 * text the output encodes. ROT13 keeps every character in place and reversal
 * mirrors it, so their leaks map back to exact ranges; they're checked here
 * because decodePayloads only keeps them when they spell out an injection.
 */
function searchTransformedLeaks(
  text: string,
  prompt: PromptModel,
  options: SanitizeOptions,
  search: LeakSearch
): void {
  const length = text.length;
  const lower = text.toLowerCase();
  // Prompts without longer Latin words (e.g. Chinese) can't be probed, so the
  // reversed check always runs for them; ROT13 doesn't change them.
  const checkReversed =
    prompt.reversedProbes.length < 2 ||
    probesFound(lower, prompt.reversedProbes);
  const checkRot13 =
    prompt.rot13Probes.length >= 2 && probesFound(lower, prompt.rot13Probes);

  if (checkReversed) {
    const found = checkLeak(reverse(text), prompt, options);
    if (found.leaked) {
      addLeak(search, found, "reversed");
      for (const [a, b] of found.ranges) {
        search.ranges.push([length - b, length - a]);
      }
    }
  }
  if (checkRot13) {
    const rotated = rot13(text);
    const found =
      rotated === text ? undefined : checkLeak(rotated, prompt, options);
    if (found?.leaked) {
      addLeak(search, found, "rot13");
      search.ranges.push(...found.ranges);
    }
  }

  searchEncodedLeaks(text, lower, prompt, options, search);
}

/** Payloads are decoded in windows this size, like `detect` does. */
const DECODE_WINDOW = 8192;
const DECODE_OVERLAP = 512;

/** Checks one decoded payload found at `offset` in the output. */
function checkPayload(
  payload: DecodedPayload,
  offset: number,
  prompt: PromptModel,
  options: SanitizeOptions,
  search: LeakSearch
): void {
  const found = checkLeak(payload.text, prompt, options);
  if (!found.leaked) {
    return;
  }
  addLeak(search, found, payload.encoding);
  if (payload.start !== undefined && payload.end !== undefined) {
    search.ranges.push([offset + payload.start, offset + payload.end]);
  } else {
    // URL encoding, entities, escapes, and hidden Unicode don't sit in one
    // span, so a leak in them can't be cut out alone.
    search.redactAll = true;
  }
}

/** Looks for the prompt in text the output encodes (base64, hex, and the rest). */
function searchEncodedLeaks(
  text: string,
  lower: string,
  prompt: PromptModel,
  options: SanitizeOptions,
  search: LeakSearch
): void {
  const step = DECODE_WINDOW - DECODE_OVERLAP;
  const seen = new Set<string>();
  for (let offset = 0; offset < text.length; offset += step) {
    const end = Math.min(text.length, offset + DECODE_WINDOW);
    for (const payload of decodePayloads(
      text.slice(offset, end),
      lower.slice(offset, end)
    )) {
      const transformed =
        payload.encoding === "reversed" || payload.encoding === "rot13";
      const key =
        payload.start === undefined
          ? `${payload.encoding}:${payload.text}`
          : `${offset + payload.start}:${offset + (payload.end ?? 0)}`;
      if (!(transformed || seen.has(key))) {
        seen.add(key);
        checkPayload(payload, offset, prompt, options, search);
      }
    }
    if (end === text.length) {
      break;
    }
  }
}

function applyRedactions(
  text: string,
  redactions: [number, number][],
  redactionText: string
): string {
  let sanitized = "";
  let pos = 0;
  for (const [start, end] of redactions) {
    sanitized += text.slice(pos, start) + redactionText;
    pos = end;
  }
  return sanitized + text.slice(pos);
}

export function sanitizeWithRedactions(
  output: string,
  systemPrompt: string,
  options: SanitizeOptions = {}
): RedactedSanitizeResult {
  const redactionText = options.redactionText || "[REDACTED]";
  const clean = (text: string, confidence = 0): RedactedSanitizeResult => ({
    leaked: false,
    confidence,
    fragments: [],
    sanitized: text,
    redactions: [],
    redactionText,
  });
  const validInput =
    typeof output === "string" &&
    output !== "" &&
    typeof systemPrompt === "string" &&
    systemPrompt !== "";
  if (!validInput) {
    return clean(typeof output === "string" ? output : "");
  }

  const bounded =
    output.length > SANITIZE_MAX_OUTPUT_LENGTH
      ? output.slice(0, SANITIZE_MAX_OUTPUT_LENGTH)
      : output;
  const prompt = modelPrompt(systemPrompt, options);
  if (!prompt) {
    return clean(bounded);
  }

  const direct = checkLeak(bounded, prompt, options);
  const search: LeakSearch = {
    leaked: direct.leaked,
    confidence: direct.confidence,
    fragments: [...direct.fragments],
    ranges: [...direct.ranges],
    redactAll: false,
  };
  if (options.decodePayloads !== false) {
    searchTransformedLeaks(bounded, prompt, options, search);
  }
  if (!search.leaked) {
    return clean(bounded, search.confidence);
  }

  let redactions: [number, number][] = [];
  if (search.redactAll) {
    redactions = [[0, bounded.length]];
  } else {
    redactions = mergeRanges(search.ranges);
  }
  if (options.detectOnly) {
    redactions = [];
  }
  return {
    leaked: true,
    confidence: search.confidence,
    fragments: [...new Set(search.fragments)],
    sanitized: applyRedactions(bounded, redactions, redactionText),
    redactions,
    redactionText,
  };
}
