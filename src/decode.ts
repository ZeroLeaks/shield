// biome-ignore-all lint/suspicious/noBitwiseOperators: character classes are bit flags, and span scanning tracks them with bit operations.
import { type HiddenText, unflipText } from "./normalization";

export type PayloadEncoding =
  | "base64"
  | "hex"
  | "binary"
  | "decimal_codes"
  | "url_encoding"
  | "html_entities"
  | "escape_sequences"
  | "rot13"
  | "reversed"
  | "upside_down"
  | "morse"
  | "braille"
  | "unicode_tags"
  | "variation_selectors";

export interface DecodedPayload {
  encoding: PayloadEncoding;
  text: string;
  /**
   * Where the encoded text sits in the input, `[start, end)`. Only set for
   * encodings that occupy one span: base64, hex, binary, decimal codes, and
   * Morse.
   */
  start?: number;
  end?: number;
}

/**
 * Decoded payloads returned per call. Callers pass at most an 8KB window, and
 * no 8KB window holds more encoded runs than this, so padding a window with
 * harmless encoded text can't push a real payload out.
 */
const MAX_PAYLOADS = 512;
const MAX_PAYLOAD_LENGTH = 16_384;
const MAX_CANDIDATE_LENGTH = 65_536;
/**
 * Candidate spans tried per encoding, so hostile input can't force unbounded
 * work. Like MAX_PAYLOADS, more than an 8KB window can hold.
 */
const MAX_SPANS_PER_CLASS = 512;

const RE_BASE64 = /[A-Za-z0-9+/_-]{16,}={0,2}/g;
const RE_HAS_UPPER = /[A-Z]/;
const RE_HAS_LOWER = /[a-z]/;
const RE_HAS_DIGIT_OR_SYMBOL = /[0-9+/_-]/;
const RE_HEX_RUN =
  /(?:\\x|0x)?[0-9a-fA-F]{2}(?:[ :,-]?(?:\\x|0x)?[0-9a-fA-F]{2}){7,}/g;
const RE_HEX_PAIR = /[0-9a-fA-F]{2}/g;
const RE_HEX_PREFIX = /\\x|0x/g;
const RE_BINARY_RUN = /(?:[01]{8}[ ,]?){6,}/g;
const RE_BINARY_BYTE = /[01]{8}/g;
const RE_DECIMAL_RUN =
  /(?:(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])[ ,]+){7,}(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])(?!\d)/g;
const RE_DECIMAL = /\d+/g;
const RE_PERCENT_RUN = /(?:%[0-9a-fA-F]{2})+/g;
const RE_PERCENT = /%[0-9a-fA-F]{2}/g;
const RE_ENTITY =
  /&(?:#x([0-9a-fA-F]{1,6})|#(\d{1,7})|(lt|gt|amp|quot|apos|nbsp));/g;
const RE_ESCAPE =
  /\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})/g;
const RE_MORSE_RUN =
  /(?:[.\-\u00b7\u2022_]{1,7}(?: \/ | {1,3}|\/)){6,}[.\-\u00b7\u2022_]{1,7}/g;
const RE_TRAILING_EQUALS = /=+$/;
const RE_DASH = /-/g;
const RE_MORSE_DOTS = /[\u00b7\u2022]/g;
const RE_UNDERSCORE = /_/g;
const RE_SPACES = / /g;
const RE_BRAILLE_ANY = /[\u2801-\u28ff]/;
const RE_MORSE_WORD_BREAK = / \/ | {3}|\//;
const RE_MORSE_LETTER_BREAK = / +/;
const RE_BRAILLE_RUN = /[\u2801-\u28ff][\u2800-\u28ff]{3,}/g;
const RE_LETTER_OR_SPACE = /[\p{L}\p{N}\s.,'"!?:;()-]/u;

const NAMED_ENTITIES: Record<string, string> = {
  lt: "<",
  gt: ">",
  amp: "&",
  quot: '"',
  apos: "'",
  nbsp: " ",
};

const MORSE: Record<string, string> = {
  ".-": "a",
  "-...": "b",
  "-.-.": "c",
  "-..": "d",
  ".": "e",
  "..-.": "f",
  "--.": "g",
  "....": "h",
  "..": "i",
  ".---": "j",
  "-.-": "k",
  ".-..": "l",
  "--": "m",
  "-.": "n",
  "---": "o",
  ".--.": "p",
  "--.-": "q",
  ".-.": "r",
  "...": "s",
  "-": "t",
  "..-": "u",
  "...-": "v",
  ".--": "w",
  "-..-": "x",
  "-.--": "y",
  "--..": "z",
  "-----": "0",
  ".----": "1",
  "..---": "2",
  "...--": "3",
  "....-": "4",
  ".....": "5",
  "-....": "6",
  "--...": "7",
  "---..": "8",
  "----.": "9",
};

// Grade 1 Braille letters, by dot pattern offset from U+2800.
const BRAILLE: Record<number, string> = {
  1: "a",
  3: "b",
  9: "c",
  25: "d",
  17: "e",
  11: "f",
  27: "g",
  19: "h",
  10: "i",
  26: "j",
  5: "k",
  7: "l",
  13: "m",
  29: "n",
  21: "o",
  15: "p",
  31: "q",
  23: "r",
  14: "s",
  30: "t",
  37: "u",
  39: "v",
  58: "w",
  45: "x",
  61: "y",
  53: "z",
  0: " ",
};

/**
 * Words that only show up after decoding when the encoded text was an
 * instruction. ROT13 and reversed views are kept only if they contain one.
 */
const STRONG_HINTS = [
  "ignore",
  "instruction",
  "disregard",
  "jailbreak",
  "system prompt",
  "override",
  "developer mode",
  "previous",
  "reveal",
  "password",
  "forget",
  "pretend",
  "bypass",
];

function rot13(text: string): string {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    out +=
      c >= 97 && c <= 122
        ? String.fromCharCode(((c - 97 + 13) % 26) + 97)
        : text[i];
  }
  return out;
}

function reverse(text: string): string {
  let out = "";
  for (let i = text.length - 1; i >= 0; i--) {
    out += text[i];
  }
  return out;
}

// The hints as they appear in ROT13 and reversed text, so the whole text is
// only transformed when one of them is there.
const ROT13_HINTS = STRONG_HINTS.map(rot13);
const REVERSED_HINTS = STRONG_HINTS.map(reverse);

function containsAny(text: string, needles: string[]): boolean {
  for (const needle of needles) {
    if (text.includes(needle)) {
      return true;
    }
  }
  return false;
}

let utf8: TextDecoder | undefined;

/** Decodes bytes as UTF-8 and keeps the result only if it reads as text. */
function bytesToText(bytes: Uint8Array): string | undefined {
  if (bytes.length < 6) {
    return;
  }
  utf8 ??= new TextDecoder("utf-8", { fatal: false });
  const text = utf8.decode(bytes);
  return looksLikeText(text) ? text : undefined;
}

function isReadable(c: number, ch: string): boolean {
  if (c < 0x80) {
    return (
      (c >= 0x20 && c < 0x7f && !(c === 0x5c || c === 0x60 || c === 0x7c)) ||
      c === 0x0a ||
      c === 0x09 ||
      c === 0x0d
    );
  }
  return c !== 0xff_fd && RE_LETTER_OR_SPACE.test(ch);
}

function readableRatio(text: string, limit: number): [number, number] {
  let readable = 0;
  let letters = 0;
  let total = 0;
  for (const ch of text) {
    if (total >= limit) {
      break;
    }
    total++;
    const c = ch.charCodeAt(0);
    if (isReadable(c, ch)) {
      readable++;
      if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c > 0x7f) {
        letters++;
      }
    }
  }
  return total === 0 ? [0, 0] : [readable / total, letters / total];
}

function looksLikeText(text: string): boolean {
  // Most non-text fails in the first few dozen characters.
  const [prefixReadable] = readableRatio(text, 48);
  if (prefixReadable < 0.8) {
    return false;
  }
  const [readable, letters] = readableRatio(text, Number.POSITIVE_INFINITY);
  return readable >= 0.9 && letters >= 0.5;
}

function decodeBase64(candidate: string): string | undefined {
  let s = candidate
    .replace(RE_TRAILING_EQUALS, "")
    .replace(RE_DASH, "+")
    .replace(RE_UNDERSCORE, "/");
  const rem = s.length % 4;
  if (rem === 1) {
    s = s.slice(0, -1);
  } else if (rem > 0) {
    s += "=".repeat(4 - rem);
  }
  let binary: string;
  try {
    binary = atob(s);
  } catch {
    return;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytesToText(bytes);
}

function hasStrongHint(text: string, original: string): boolean {
  for (const hint of STRONG_HINTS) {
    if (text.includes(hint) && !original.includes(hint)) {
      return true;
    }
  }
  return false;
}

// Character classes for finding candidate spans in one pass over the text.
// Running every decoder's regex over the whole text is much slower than
// running it only inside the spans that could hold an encoding.
const BASE64_CHAR = 1;
const HEX_CHAR = 2;
const BINARY_CHAR = 4;
const DECIMAL_CHAR = 8;
const MORSE_CHAR = 16;
const CHAR_CLASSES = new Uint8Array(128);
function addClass(chars: string, flag: number): void {
  for (let i = 0; i < chars.length; i++) {
    CHAR_CLASSES[chars.charCodeAt(i)] |= flag;
  }
}
const DIGITS = "0123456789";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
addClass(`${DIGITS}${LOWER}${LOWER.toUpperCase()}+/_-=`, BASE64_CHAR);
addClass(`${DIGITS}abcdefABCDEFxX :,-\\`, HEX_CHAR);
addClass("01 ,", BINARY_CHAR);
addClass(`${DIGITS} ,`, DECIMAL_CHAR);
addClass(".-_ /", MORSE_CHAR);

/** Each class and the shortest run of it worth decoding. */
const SPAN_CLASSES: [number, number][] = [
  [BASE64_CHAR, 16],
  [HEX_CHAR, 23],
  [BINARY_CHAR, 47],
  [DECIMAL_CHAR, 23],
  [MORSE_CHAR, 17],
];

type Span = [number, number];

function charClass(c: number): number {
  if (c < 128) {
    return CHAR_CLASSES[c];
  }
  // Middle dot and bullet, used as Morse dots.
  return c === 0xb7 || c === 0x20_22 ? MORSE_CHAR : 0;
}

const EMPTY_SPANS: Span[] = [];
const spanStarts = new Int32Array(32);
const spanMins = new Int32Array(32);
for (const [flag, min] of SPAN_CLASSES) {
  spanMins[31 - Math.clz32(flag)] = min;
}

/** Maximal runs of each character class that are long enough to decode. */
function findSpans(raw: string): Record<number, Span[]> {
  const spans: Record<number, Span[]> = {};
  let open = 0;
  for (let i = 0; i <= raw.length; i++) {
    const cls = i < raw.length ? charClass(raw.charCodeAt(i)) : 0;
    let changed = cls ^ open;
    while (changed !== 0) {
      const bit = 31 - Math.clz32(changed);
      const flag = 1 << bit;
      changed ^= flag;
      if (cls & flag) {
        spanStarts[bit] = i;
      } else if (i - spanStarts[bit] >= spanMins[bit]) {
        const list = spans[flag] ?? [];
        if (list.length < MAX_SPANS_PER_CLASS) {
          list.push([spanStarts[bit], i]);
          spans[flag] = list;
        }
      }
    }
    open = cls;
  }
  for (const [flag] of SPAN_CLASSES) {
    spans[flag] ??= EMPTY_SPANS;
  }
  return spans;
}

/** Runs `re` over each span of `raw` and calls `visit` with every match. */
function eachMatchInSpans(
  raw: string,
  spans: Span[],
  re: RegExp,
  out: DecodedPayload[],
  visit: (match: string, start: number, end: number) => void
): void {
  for (const [start, end] of spans) {
    const span = raw.slice(start, Math.min(end, start + MAX_CANDIDATE_LENGTH));
    re.lastIndex = 0;
    let m = re.exec(span);
    while (m && out.length < MAX_PAYLOADS) {
      visit(m[0], start + m.index, start + m.index + m[0].length);
      m = re.exec(span);
    }
  }
}

function decodeBase64Spans(
  raw: string,
  spans: Span[],
  out: DecodedPayload[]
): void {
  eachMatchInSpans(raw, spans, RE_BASE64, out, (candidate, start, end) => {
    const plausible =
      candidate.length <= MAX_CANDIDATE_LENGTH &&
      RE_HAS_LOWER.test(candidate) &&
      (RE_HAS_UPPER.test(candidate) || RE_HAS_DIGIT_OR_SYMBOL.test(candidate));
    // Check a prefix first so long binary blobs (images) are rejected cheaply.
    if (plausible && decodeBase64(candidate.slice(0, 24)) !== undefined) {
      const text = decodeBase64(candidate);
      if (text) {
        out.push({ encoding: "base64", text, start, end });
      }
    }
  });
}

function decodeHexSpans(
  raw: string,
  spans: Span[],
  out: DecodedPayload[]
): void {
  eachMatchInSpans(raw, spans, RE_HEX_RUN, out, (run, start, end) => {
    const pairs = run.replace(RE_HEX_PREFIX, "").match(RE_HEX_PAIR) ?? [];
    // Each byte of hex-encoded text starts with a digit, so runs that are
    // mostly letters (a-f) can't be text.
    let digitLeads = 0;
    for (const p of pairs) {
      const c = p.charCodeAt(0);
      if (c >= 48 && c <= 57) {
        digitLeads++;
      }
    }
    if (digitLeads < pairs.length * 0.9) {
      return;
    }
    const text = bytesToText(
      new Uint8Array(pairs.map((p) => Number.parseInt(p, 16)))
    );
    if (text) {
      out.push({ encoding: "hex", text, start, end });
    }
  });
}

function decodeBinarySpans(
  raw: string,
  spans: Span[],
  out: DecodedPayload[]
): void {
  eachMatchInSpans(raw, spans, RE_BINARY_RUN, out, (run, start, end) => {
    const text = bytesToText(
      new Uint8Array(
        (run.match(RE_BINARY_BYTE) ?? []).map((b) => Number.parseInt(b, 2))
      )
    );
    if (text) {
      out.push({ encoding: "binary", text, start, end });
    }
  });
}

function decodeDecimalSpans(
  raw: string,
  spans: Span[],
  out: DecodedPayload[]
): void {
  eachMatchInSpans(raw, spans, RE_DECIMAL_RUN, out, (run, start, end) => {
    const codes = (run.match(RE_DECIMAL) ?? []).map(Number);
    const text = String.fromCharCode(...codes);
    if (looksLikeText(text) && text.includes(" ")) {
      out.push({ encoding: "decimal_codes", text, start, end });
    }
  });
}

function decodePercent(raw: string, out: DecodedPayload[]): void {
  RE_PERCENT.lastIndex = 0;
  let count = 0;
  while (RE_PERCENT.exec(raw) && count < 3) {
    count++;
  }
  if (count < 3) {
    return;
  }
  utf8 ??= new TextDecoder("utf-8", { fatal: false });
  const decoder = utf8;
  const text = raw.replace(RE_PERCENT_RUN, (run: string) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    }
    return decoder.decode(bytes);
  });
  out.push({ encoding: "url_encoding", text: text.replace(/\+/g, " ") });
}

function safeCodePoint(code: number): string {
  return code > 0 && code <= 0x10_ff_ff ? String.fromCodePoint(code) : "";
}

function decodeEntities(raw: string, out: DecodedPayload[]): void {
  RE_ENTITY.lastIndex = 0;
  let count = 0;
  while (RE_ENTITY.exec(raw) && count < 3) {
    count++;
  }
  if (count < 3) {
    return;
  }
  const text = raw.replace(
    RE_ENTITY,
    (_m: string, hex?: string, dec?: string, named?: string) => {
      if (hex) {
        return safeCodePoint(Number.parseInt(hex, 16));
      }
      if (dec) {
        return safeCodePoint(Number.parseInt(dec, 10));
      }
      return NAMED_ENTITIES[named ?? ""] ?? "";
    }
  );
  out.push({ encoding: "html_entities", text });
}

function decodeEscapes(raw: string, out: DecodedPayload[]): void {
  RE_ESCAPE.lastIndex = 0;
  let count = 0;
  while (RE_ESCAPE.exec(raw) && count < 3) {
    count++;
  }
  if (count < 3) {
    return;
  }
  const text = raw.replace(
    RE_ESCAPE,
    (_m: string, braced?: string, u?: string, x?: string) =>
      safeCodePoint(Number.parseInt(braced ?? u ?? x ?? "", 16))
  );
  out.push({ encoding: "escape_sequences", text });
}

function decodeMorseSpans(
  raw: string,
  spans: Span[],
  out: DecodedPayload[]
): void {
  eachMatchInSpans(raw, spans, RE_MORSE_RUN, out, (run, start, end) => {
    const words = run
      .replace(RE_MORSE_DOTS, ".")
      .replace(RE_UNDERSCORE, "-")
      .split(RE_MORSE_WORD_BREAK);
    const text = words
      .map((w) =>
        w
          .trim()
          .split(RE_MORSE_LETTER_BREAK)
          .map((l) => MORSE[l] ?? "")
          .join("")
      )
      .join(" ");
    if (text.replace(RE_SPACES, "").length >= 6) {
      out.push({ encoding: "morse", text, start, end });
    }
  });
}

function decodeBraille(raw: string, out: DecodedPayload[]): void {
  RE_BRAILLE_RUN.lastIndex = 0;
  let m = RE_BRAILLE_RUN.exec(raw);
  while (m && out.length < MAX_PAYLOADS) {
    let text = "";
    for (const ch of m[0]) {
      text += BRAILLE[ch.charCodeAt(0) - 0x28_00] ?? "";
    }
    if (text.trim().length >= 4) {
      out.push({ encoding: "braille", text });
    }
    m = RE_BRAILLE_RUN.exec(raw);
  }
}

/**
 * Finds text hidden in encodings inside `raw` and returns what it decodes
 * to. `normalized` is the lowercased normalized view, used for ROT13,
 * reversed, and upside-down text. `hidden` carries text normalization
 * already recovered from Unicode tags and variation selectors.
 */
export function decodePayloads(
  raw: string,
  normalized: string,
  hidden: HiddenText[] = []
): DecodedPayload[] {
  const out: DecodedPayload[] = hidden.map((h) => ({ ...h }));

  // No span class is worth decoding below 16 characters.
  if (raw.length >= 16) {
    const spans = findSpans(raw);
    decodeBase64Spans(raw, spans[BASE64_CHAR], out);
    decodeHexSpans(raw, spans[HEX_CHAR], out);
    decodeBinarySpans(raw, spans[BINARY_CHAR], out);
    decodeDecimalSpans(raw, spans[DECIMAL_CHAR], out);
    decodeMorseSpans(raw, spans[MORSE_CHAR], out);
  }
  if (raw.includes("%")) {
    decodePercent(raw, out);
  }
  if (raw.includes("&")) {
    decodeEntities(raw, out);
  }
  if (raw.includes("\\")) {
    decodeEscapes(raw, out);
  }
  if (raw.length >= 4 && RE_BRAILLE_ANY.test(raw)) {
    decodeBraille(raw, out);
  }

  if (normalized.length <= MAX_CANDIDATE_LENGTH) {
    if (containsAny(normalized, ROT13_HINTS)) {
      const r13 = rot13(normalized);
      if (hasStrongHint(r13, normalized)) {
        out.push({ encoding: "rot13", text: r13 });
      }
    }
    if (containsAny(normalized, REVERSED_HINTS)) {
      const reversed = reverse(normalized);
      if (hasStrongHint(reversed, normalized)) {
        out.push({ encoding: "reversed", text: reversed });
      }
    }
    const unflipped = unflipText(normalized);
    if (unflipped && hasStrongHint(unflipped, normalized)) {
      out.push({ encoding: "upside_down", text: unflipped });
    }
  }

  return out
    .slice(0, MAX_PAYLOADS)
    .map((p) =>
      p.text.length > MAX_PAYLOAD_LENGTH
        ? { ...p, text: p.text.slice(0, MAX_PAYLOAD_LENGTH) }
        : p
    );
}
