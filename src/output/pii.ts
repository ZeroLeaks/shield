import type { OutputFinding, Severity } from "./types";
import {
  filterFindings,
  lastItem,
  longestRun,
  longestSequence,
  type RankedFinding,
  resolveOverlaps,
  stripPriority,
} from "./util";

export type PIIKind =
  | "email"
  | "phone"
  | "credit_card"
  | "us_ssn"
  | "iban"
  | "ip_address"
  | "uk_nino"
  | "us_passport";

export interface PIIOptions {
  /**
   * Kinds to detect. Default: `DEFAULT_PII_KINDS` (email, phone, credit_card,
   * us_ssn, iban). `ip_address`, `uk_nino`, and `us_passport` are opt-in.
   */
  kinds?: PIIKind[];
  /** Drop findings below this confidence (0..1). Default 0. */
  minConfidence?: number;
}

export const DEFAULT_PII_KINDS: readonly PIIKind[] = [
  "email",
  "phone",
  "credit_card",
  "us_ssn",
  "iban",
];

export const PII_KINDS: readonly PIIKind[] = [
  ...DEFAULT_PII_KINDS,
  "ip_address",
  "uk_nino",
  "us_passport",
];

interface Verdict {
  severity: Severity;
  confidence: number;
}

const EXAMPLE_VERDICT: Verdict = { severity: "low", confidence: 0.3 };
const NON_DIGIT_GLOBAL = /\D/g;

function push(
  out: RankedFinding[],
  kind: PIIKind,
  start: number,
  end: number,
  verdict: Verdict,
  preview: string,
  priority: number
): void {
  out.push({
    type: "pii",
    kind,
    start,
    end,
    severity: verdict.severity,
    confidence: verdict.confidence,
    preview,
    priority,
  });
}

/** The `size` characters before `start`, lowercased. */
function windowBefore(text: string, start: number, size: number): string {
  return text.slice(Math.max(0, start - size), start).toLowerCase();
}

function asciiTable(chars: string): Uint8Array {
  const table = new Uint8Array(128);
  for (let i = 0; i < chars.length; i++) {
    table[chars.charCodeAt(i)] = 1;
  }
  return table;
}

const WORD_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
const ALNUM_ONLY = asciiTable(WORD_CHARS.slice(0, -1));
/** Characters that glue a number to what precedes it (a word, "#123", "v1.2", "x-12"). */
const NUMBER_GLUE = asciiTable(`${WORD_CHARS}+-./#`);
const PHONE_PLUS_GLUE = asciiTable(`${WORD_CHARS}+`);

/**
 * True when the character before `index` is not in `glue`. The numeric
 * patterns check this in code rather than with a lookbehind, which
 * JavaScriptCore (Bun, Safari) only runs in its slow regex interpreter.
 */
function standsAlone(text: string, index: number, glue: Uint8Array): boolean {
  if (index === 0) {
    return true;
  }
  const code = text.charCodeAt(index - 1);
  return code >= 128 || glue[code] === 0;
}

function mentions(haystack: string, context: RegExp): boolean {
  return context.test(haystack);
}

/** Replaces every digit except the last `keep` with "*", keeping separators. */
function maskDigits(value: string, keep: number): string {
  // Find where the last `keep` digits start, then mask every digit before it.
  let split = value.length;
  let kept = 0;
  while (split > 0 && kept < keep) {
    split--;
    const c = value.charCodeAt(split);
    if (c >= 48 && c <= 57) {
      kept++;
    }
  }
  return value.slice(0, split).replace(DIGIT_GLOBAL, "*") + value.slice(split);
}

function digitsOf(value: string): string {
  return value.replace(NON_DIGIT_GLOBAL, "");
}

function looksFakeDigits(digits: string): boolean {
  return longestRun(digits) >= 6 || longestSequence(digits) >= 6;
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

const EXAMPLE_DOMAIN =
  /(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|local|domain\.com|email\.com|yourdomain\.com|yourcompany\.com|company\.com|acme\.com|foo\.com|bar\.com)$/;
const PLACEHOLDER_LOCALS = new Set([
  "user",
  "username",
  "name",
  "email",
  "yourname",
  "your.name",
  "your_name",
  "your-email",
  "youremail",
  "john.doe",
  "jane.doe",
  "johndoe",
  "janedoe",
  "john",
  "jane",
  "you",
  "me",
  "someone",
  "somebody",
  "foo",
  "bar",
  "test",
  "alice",
  "bob",
]);
const ROLE_LOCALS = new Set([
  "noreply",
  "no-reply",
  "donotreply",
  "do-not-reply",
  "support",
  "info",
  "hello",
  "hi",
  "contact",
  "admin",
  "sales",
  "help",
  "team",
  "security",
  "privacy",
  "abuse",
  "postmaster",
  "webmaster",
  "billing",
  "careers",
  "jobs",
  "press",
  "feedback",
  "legal",
  "notifications",
]);
const FILE_EXTENSIONS = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "svg",
  "webp",
  "ico",
  "avif",
  "js",
  "mjs",
  "cjs",
  "ts",
  "tsx",
  "jsx",
  "css",
  "scss",
  "json",
  "lock",
  "yml",
  "yaml",
  "toml",
  "txt",
  "map",
  "woff",
  "woff2",
  "ttf",
  "vue",
  "svelte",
]);
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TLD = /^(?:[a-z]{2,24}|xn--[a-z0-9-]{1,59})$/;
const RETINA_LABEL = /^\d+(?:\.\d+)?x$/;
const NON_SPACE = /\S/;
const DIGIT_GLOBAL = /\d/g;
const SPACE_GLOBAL = / /g;

function isLocalChar(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 46 ||
    code === 95 ||
    code === 37 ||
    code === 43 ||
    code === 45
  );
}

function isDomainChar(code: number): boolean {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 46 ||
    code === 45
  );
}

function validDomain(domain: string): boolean {
  const lastDot = domain.lastIndexOf(".");
  if (lastDot === -1 || domain.length - lastDot < 3) {
    return false;
  }
  const labels = domain.split(".");
  if (labels.length < 2 || domain.length > 253) {
    return false;
  }
  for (const label of labels) {
    if (!DOMAIN_LABEL.test(label)) {
      return false;
    }
  }
  const tld = lastItem(labels) ?? "";
  return (
    TLD.test(tld) && !FILE_EXTENSIONS.has(tld) && !RETINA_LABEL.test(labels[0])
  );
}

function emailVerdict(local: string, domain: string): Verdict {
  const lowerLocal = local.toLowerCase();
  if (EXAMPLE_DOMAIN.test(domain) || PLACEHOLDER_LOCALS.has(lowerLocal)) {
    return EXAMPLE_VERDICT;
  }
  if (ROLE_LOCALS.has(lowerLocal)) {
    return { severity: "low", confidence: 0.5 };
  }
  return { severity: "medium", confidence: 0.9 };
}

interface EmailSpan {
  start: number;
  end: number;
  local: string;
  domain: string;
}

function localStart(text: string, at: number): number {
  let i = at;
  while (i > 0 && at - i <= 64 && isLocalChar(text.charCodeAt(i - 1))) {
    i--;
  }
  if (at - i > 64) {
    return -1;
  }
  while (i < at && text.charAt(i) === ".") {
    i++;
  }
  return i;
}

function isUrlUserinfo(text: string, start: number): boolean {
  const before = text.charAt(start - 1);
  if (before === "/") {
    return true;
  }
  return (
    before === ":" &&
    text.slice(Math.max(0, start - 7), start).toLowerCase() !== "mailto:"
  );
}

function readEmail(text: string, at: number): EmailSpan | null {
  let end = at + 1;
  const limit = Math.min(text.length, at + 254);
  while (end < limit && isDomainChar(text.charCodeAt(end))) {
    end++;
  }
  while (
    end > at + 1 &&
    (text.charAt(end - 1) === "." || text.charAt(end - 1) === "-")
  ) {
    end--;
  }
  const domain = text.slice(at + 1, end).toLowerCase();
  if (!validDomain(domain)) {
    return null;
  }
  const start = localStart(text, at);
  if (start === -1 || start === at || isUrlUserinfo(text, start)) {
    return null;
  }
  const local = text.slice(start, at);
  if (local.endsWith(".") || local.includes("..")) {
    return null;
  }
  // git@github.com:org/repo.git is an SSH remote, not an address.
  const sshPath =
    text.charAt(end) === ":" && NON_SPACE.test(text.charAt(end + 1));
  return sshPath ? null : { start, end, local, domain };
}

function scanEmails(text: string, out: RankedFinding[]): void {
  let at = text.indexOf("@");
  while (at !== -1) {
    const email = readEmail(text, at);
    if (email) {
      push(
        out,
        "email",
        email.start,
        email.end,
        emailVerdict(email.local, email.domain),
        `${email.local.charAt(0)}***@${email.domain}`,
        3
      );
    }
    at = text.indexOf("@", email ? email.end : at + 1);
  }
}

// ---------------------------------------------------------------------------
// Phone numbers
// ---------------------------------------------------------------------------

// Context words match at a word start, so "server" is not "ver" and "company" is not "pan".
const PHONE_CONTEXT =
  /(?:^|[^a-z])(?:phone|telephone|call|mobile|cell|sms|text me|whatsapp|fax|contact|reach|dial|number|numéro|telefon|teléfono|telefone|handy|móvil|cellulare|(?:tel|tél|ph|mob)(?![a-z]))/;
const NOT_PHONE_CONTEXT =
  /(?:^|[^a-z])(?:order|invoice|ticket|isbn|sku|tracking|serial|account|acct|case|ref|id|part|model|version|build|zip|postal|routing|card|ssn|patent)(?![a-z])|#/;

const INTL_SHAPE = /^\+[1-9][\d .()-]{7,20}\d$/;
const NANP_SHAPE =
  /^(?:1[ .-]?)?(?:\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}([ .-])\d{3}\1\d{4})$/;
const NANP_PLAIN_SHAPE = /^1?[2-9]\d{2}[2-9]\d{6}$/;
const DOMESTIC_SHAPE = /^(?:0\d{1,4}|00[1-9]\d{0,2})(?:[ .-]\d{1,5}){2,5}$/;
const MULTI_SEPARATOR = /[ .-]{2,}|\(\(|\)\)/;

interface PhoneContext {
  positive: boolean;
  negative: boolean;
}

function phoneContext(text: string, start: number): PhoneContext {
  const before = windowBefore(text, start, 40);
  return {
    positive: mentions(before, PHONE_CONTEXT),
    negative: mentions(before.slice(-24), NOT_PHONE_CONTEXT),
  };
}

function nanpValid(digits: string): boolean {
  const national = digits.length === 11 ? digits.slice(1) : digits;
  if (national.length !== 10 || (digits.length === 11 && digits[0] !== "1")) {
    return false;
  }
  const area = national.slice(0, 3);
  const exchange = national.slice(3, 6);
  const nOneOne = (code: string): boolean => code.slice(1) === "11";
  return (
    area[0] >= "2" &&
    area[1] !== "9" &&
    exchange[0] >= "2" &&
    !nOneOne(area) &&
    !nOneOne(exchange)
  );
}

function nanpFictional(digits: string): boolean {
  const national = digits.slice(-10);
  return (
    national.startsWith("555") ||
    national.slice(3, 6) === "555" ||
    looksFakeDigits(national)
  );
}

function phoneVerdict(
  digits: string,
  context: PhoneContext,
  base: number
): Verdict | null {
  if (context.negative && !context.positive) {
    return null;
  }
  if (looksFakeDigits(digits)) {
    return EXAMPLE_VERDICT;
  }
  return {
    severity: "medium",
    confidence: context.positive ? Math.min(0.95, base + 0.1) : base,
  };
}

// ---------------------------------------------------------------------------
// Payment cards
// ---------------------------------------------------------------------------

const CARD_SHAPE = /^\d(?:[ -]?\d){12,18}$/;
const CARD_CONTEXT =
  /(?:^|[^a-z])(?:card|visa|mastercard|amex|american express|discover|credit|debit|payment|cvv|cvc|expir|(?:cc|pan)(?![a-z]))/;
const NOT_CARD_CONTEXT =
  /(?:^|[^a-z])(?:id|order|invoice|tracking|ref|account|acct|transaction|txn|imei|serial)(?![a-z])|#/;
const TEST_CARDS = new Set([
  "4242424242424242",
  "4111111111111111",
  "4000056655665556",
  "4012888888888881",
  "4222222222222",
  "4000000000000002",
  "4000000000009995",
  "4000000000000077",
  "4000002500003155",
  "5555555555554444",
  "5200828282828210",
  "5105105105105100",
  "5431111111111111",
  "2223003122003222",
  "378282246310005",
  "371449635398431",
  "378734493671000",
  "6011111111111117",
  "6011000990139424",
  "3056930009020004",
  "36227206271667",
  "30569309025904",
  "3566002020360505",
  "3530111333300000",
  "6200000000000005",
]);

export function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    sum += d;
    double = !double;
  }
  return digits.length > 0 && sum % 10 === 0;
}

function prefixBetween(
  digits: string,
  length: number,
  lo: number,
  hi: number
): boolean {
  const value = Number(digits.slice(0, length));
  return value >= lo && value <= hi;
}

const MAESTRO_PREFIXES = [
  "5018",
  "5020",
  "5038",
  "5893",
  "6304",
  "6759",
  "6761",
  "6762",
  "6763",
];

function knownCardNetwork(digits: string): boolean {
  const n = digits.length;
  const first = digits.charAt(0);
  if (first === "4") {
    return n === 13 || n === 16 || n === 19;
  }
  if (
    prefixBetween(digits, 2, 51, 55) ||
    prefixBetween(digits, 4, 2221, 2720)
  ) {
    return n === 16;
  }
  if (prefixBetween(digits, 4, 2200, 2204)) {
    return n >= 16;
  }
  if (digits.startsWith("34") || digits.startsWith("37")) {
    return n === 15;
  }
  if (
    prefixBetween(digits, 3, 300, 305) ||
    ["36", "38", "39"].includes(digits.slice(0, 2))
  ) {
    return n >= 14;
  }
  if (prefixBetween(digits, 4, 3528, 3589)) {
    return n >= 16;
  }
  const discover =
    digits.startsWith("6011") ||
    digits.startsWith("65") ||
    prefixBetween(digits, 3, 644, 649) ||
    digits.startsWith("62");
  if (discover) {
    return n >= 16;
  }
  return MAESTRO_PREFIXES.some((p) => digits.startsWith(p));
}

/** Separators must be uniform and split the number into a real card layout. */
function cardGroupingValid(value: string, digitCount: number): boolean {
  const separators = value.replace(DIGIT_GLOBAL, "");
  if (separators.length === 0) {
    return true;
  }
  if (separators !== separators.charAt(0).repeat(separators.length)) {
    return false;
  }
  const groups = value.split(separators.charAt(0)).map((g) => g.length);
  const layout = groups.join("-");
  if (layout === "4-6-5" || layout === "4-6-4") {
    return true;
  }
  const last = lastItem(groups) ?? 0;
  const leading = groups.slice(0, -1);
  return (
    leading.every((g) => g === 4) &&
    last >= 1 &&
    last <= 4 &&
    leading.length * 4 + last === digitCount
  );
}

function cardVerdict(
  digits: string,
  grouped: boolean,
  context: boolean
): Verdict {
  if (TEST_CARDS.has(digits) || looksFakeDigits(digits)) {
    return EXAMPLE_VERDICT;
  }
  if (grouped) {
    return { severity: "high", confidence: context ? 0.95 : 0.9 };
  }
  return context
    ? { severity: "high", confidence: 0.85 }
    : { severity: "medium", confidence: 0.6 };
}

// ---------------------------------------------------------------------------
// US Social Security numbers
// ---------------------------------------------------------------------------

const SSN_SEPARATED = /^\d{3}([- ])\d{2}\1\d{4}$/;
const SSN_PLAIN = /^\d{9}$/;
const SSN_CONTEXT =
  /(?:^|[^a-z])(?:ssn|social security|social-security|taxpayer|itin|ss ?#)/;
const FAKE_SSNS = new Set(["078051120", "219099999", "123456789", "987654321"]);

function ssnValid(digits: string): boolean {
  const area = digits.slice(0, 3);
  return (
    area !== "000" &&
    area !== "666" &&
    area[0] !== "9" &&
    digits.slice(3, 5) !== "00" &&
    digits.slice(5) !== "0000"
  );
}

function ssnVerdict(
  text: string,
  start: number,
  digits: string,
  hyphenated: boolean
): Verdict | null {
  const before = windowBefore(text, start, 40);
  const context = mentions(before, SSN_CONTEXT);
  const phoneLike = mentions(before, PHONE_CONTEXT);
  if (!(context || (hyphenated && !phoneLike))) {
    return null;
  }
  if (FAKE_SSNS.has(digits) || looksFakeDigits(digits)) {
    return EXAMPLE_VERDICT;
  }
  return { severity: "high", confidence: context ? 0.95 : 0.7 };
}

// ---------------------------------------------------------------------------
// IBAN
// ---------------------------------------------------------------------------

const IBAN_CANDIDATE =
  /[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Za-z0-9])/g;
const IBAN_LENGTHS: Record<string, number> = {
  AD: 24,
  AE: 23,
  AL: 28,
  AT: 20,
  AZ: 28,
  BA: 20,
  BE: 16,
  BG: 22,
  BH: 22,
  BR: 29,
  BY: 28,
  CH: 21,
  CR: 22,
  CY: 28,
  CZ: 24,
  DE: 22,
  DK: 18,
  DO: 28,
  EE: 20,
  EG: 29,
  ES: 24,
  FI: 18,
  FO: 18,
  FR: 27,
  GB: 22,
  GE: 22,
  GI: 23,
  GL: 18,
  GR: 27,
  GT: 28,
  HR: 21,
  HU: 28,
  IE: 22,
  IL: 23,
  IQ: 23,
  IS: 26,
  IT: 27,
  JO: 30,
  KW: 30,
  KZ: 20,
  LB: 28,
  LC: 32,
  LI: 21,
  LT: 20,
  LU: 20,
  LV: 21,
  MC: 27,
  MD: 24,
  ME: 22,
  MK: 19,
  MR: 27,
  MT: 31,
  MU: 30,
  NL: 18,
  NO: 15,
  PK: 24,
  PL: 28,
  PS: 29,
  PT: 25,
  QA: 29,
  RO: 24,
  RS: 22,
  SA: 24,
  SC: 31,
  SE: 24,
  SI: 19,
  SK: 24,
  SM: 27,
  ST: 25,
  SV: 28,
  TL: 23,
  TN: 24,
  TR: 26,
  UA: 29,
  VA: 22,
  VG: 24,
  XK: 20,
};
const EXAMPLE_IBANS = new Set([
  "DE89370400440532013000",
  "GB82WEST12345698765432",
  "GB29NWBK60161331926819",
  "GB33BUKB20201555555555",
  "FR1420041010050500013M02606",
  "FR7630006000011234567890189",
  "NL91ABNA0417164300",
  "ES9121000418450200051332",
  "IT60X0542811101000000123456",
  "CH9300762011623852957",
  "BE68539007547034",
  "AT611904300234573201",
]);

export function ibanChecksumValid(iban: string): boolean {
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    const value = code >= 65 ? code - 55 : code - 48;
    remainder = (value >= 10 ? remainder * 100 : remainder * 10) + value;
    remainder %= 97;
  }
  return remainder === 1;
}

function scanIbans(text: string, out: RankedFinding[]): void {
  for (const match of text.matchAll(IBAN_CANDIDATE)) {
    const value = match[0];
    const iban = value.replace(SPACE_GLOBAL, "");
    const expected = IBAN_LENGTHS[iban.slice(0, 2)];
    if (expected !== iban.length || !ibanChecksumValid(iban)) {
      continue;
    }
    const start = match.index ?? 0;
    if (!standsAlone(text, start, ALNUM_ONLY)) {
      continue;
    }
    const verdict: Verdict = EXAMPLE_IBANS.has(iban)
      ? EXAMPLE_VERDICT
      : { severity: "high", confidence: 0.95 };
    const preview = `${iban.slice(0, 2)}${"*".repeat(iban.length - 6)}${iban.slice(-4)}`;
    push(out, "iban", start, start + value.length, verdict, preview, 3);
  }
}

// ---------------------------------------------------------------------------
// Opt-in: public IPv4 addresses, UK National Insurance numbers, US passports
// ---------------------------------------------------------------------------

const IPV4_SHAPE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const PUBLIC_RESOLVERS = new Set([
  "8.8.8.8",
  "8.8.4.4",
  "1.1.1.1",
  "1.0.0.1",
  "9.9.9.9",
  "149.112.112.112",
  "208.67.222.222",
  "208.67.220.220",
]);
const VERSION_CONTEXT =
  /(?:^|[^a-z])(?:version|ver|release|firmware|build|oid|snmp)(?![a-z])/;

function parseOctets(value: string): number[] | null {
  const parts = value.split(".");
  const octets: number[] = [];
  for (const part of parts) {
    if (part.length > 1 && part.charAt(0) === "0") {
      return null;
    }
    const n = Number(part);
    if (n > 255) {
      return null;
    }
    octets.push(n);
  }
  return octets;
}

function isNonPublicIPv4(o: number[]): boolean {
  const [a, b, c] = o;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

const UK_NINO =
  /(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D](?![A-Za-z0-9])/g;
const NINO_CONTEXT =
  /(?:^|[^a-z])(?:national insurance|nino|ni number|ni no)(?![a-z])/;

function scanNinos(text: string, out: RankedFinding[]): void {
  for (const match of text.matchAll(UK_NINO)) {
    const value = match[0];
    const start = match.index ?? 0;
    if (!standsAlone(text, start, ALNUM_ONLY)) {
      continue;
    }
    const compact = value.replace(SPACE_GLOBAL, "");
    const context = mentions(windowBefore(text, start, 48), NINO_CONTEXT);
    const fake =
      compact.startsWith("AB123456") || looksFakeDigits(digitsOf(compact));
    let verdict: Verdict = {
      severity: "high",
      confidence: context ? 0.95 : 0.7,
    };
    if (fake) {
      verdict = EXAMPLE_VERDICT;
    }
    const preview = `${compact.slice(0, 2)}******${compact.slice(-1)}`;
    push(out, "uk_nino", start, start + value.length, verdict, preview, 2);
  }
}

const PASSPORT_NUMBER = /[A-Z]?\d{8,9}(?![A-Za-z0-9])/g;

const PASSPORT_WORD = /passport/gi;

function scanPassports(text: string, out: RankedFinding[]): void {
  let guard = 0;
  for (const word of text.matchAll(PASSPORT_WORD)) {
    guard++;
    if (guard > 256) {
      return;
    }
    const windowStart = (word.index ?? 0) + 8;
    const window = text.slice(windowStart, windowStart + 48);
    for (const match of window.matchAll(PASSPORT_NUMBER)) {
      const value = match[0];
      const start = windowStart + (match.index ?? 0);
      if (!standsAlone(text, start, ALNUM_ONLY)) {
        continue;
      }
      const fake = looksFakeDigits(digitsOf(value));
      const verdict: Verdict = fake
        ? EXAMPLE_VERDICT
        : { severity: "high", confidence: 0.8 };
      push(
        out,
        "us_passport",
        start,
        start + value.length,
        verdict,
        `*****${value.slice(-3)}`,
        2
      );
    }
  }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// One pass for every numeric kind: find number-like runs, then classify
// ---------------------------------------------------------------------------

/** Digits with the separators phone, card, SSN, and IP formats use. */
const NUMERIC_CANDIDATE = /[+(]?\d[\d .()-]{5,78}\d\)?/g;
const MAX_PARTS_PER_ENTITY = 6;

interface NumericScan {
  text: string;
  kinds: Set<PIIKind>;
  out: RankedFinding[];
}

function phoneAt(
  scan: NumericScan,
  start: number,
  value: string,
  base: number,
  needsContext: boolean
): boolean {
  const digits = digitsOf(value);
  const context = phoneContext(scan.text, start);
  if (needsContext && !context.positive) {
    return false;
  }
  const northAmerican = !value.startsWith("+") || digits.startsWith("1");
  const fictional =
    northAmerican &&
    digits.length <= 11 &&
    nanpValid(digits.slice(-10)) &&
    nanpFictional(digits);
  const verdict = fictional
    ? EXAMPLE_VERDICT
    : phoneVerdict(digits, context, base);
  if (verdict) {
    push(
      scan.out,
      "phone",
      start,
      start + value.length,
      verdict,
      maskDigits(value, 4),
      1
    );
  }
  return true;
}

function classifyPhone(
  scan: NumericScan,
  start: number,
  value: string
): boolean {
  if (value.startsWith("+")) {
    const digits = digitsOf(value);
    const plausible =
      INTL_SHAPE.test(value) &&
      digits.length >= 10 &&
      digits.length <= 15 &&
      !MULTI_SEPARATOR.test(value);
    return plausible && phoneAt(scan, start, value, 0.8, false);
  }
  if (NANP_SHAPE.test(value)) {
    const digits = digitsOf(value);
    // (555) 123-4567 and friends: the classic placeholder, not a real line.
    if (digits.slice(-10).startsWith("555")) {
      push(
        scan.out,
        "phone",
        start,
        start + value.length,
        EXAMPLE_VERDICT,
        maskDigits(value, 4),
        1
      );
      return true;
    }
    return nanpValid(digits) && phoneAt(scan, start, value, 0.75, false);
  }
  if (NANP_PLAIN_SHAPE.test(value)) {
    return nanpValid(value) && phoneAt(scan, start, value, 0.6, true);
  }
  if (DOMESTIC_SHAPE.test(value)) {
    const length = digitsOf(value).length;
    return (
      length >= 10 && length <= 13 && phoneAt(scan, start, value, 0.6, true)
    );
  }
  return false;
}

function classifyCard(
  scan: NumericScan,
  start: number,
  value: string
): boolean {
  if (!CARD_SHAPE.test(value)) {
    return false;
  }
  const digits = digitsOf(value);
  const valid =
    cardGroupingValid(value, digits.length) &&
    knownCardNetwork(digits) &&
    luhnValid(digits);
  if (!valid) {
    return false;
  }
  const grouped = value.length > digits.length;
  if (TEST_CARDS.has(digits) || looksFakeDigits(digits)) {
    push(
      scan.out,
      "credit_card",
      start,
      start + value.length,
      EXAMPLE_VERDICT,
      maskDigits(value, 4),
      3
    );
    return true;
  }
  const before = windowBefore(scan.text, start, 48);
  const context = mentions(before, CARD_CONTEXT);
  if (!(grouped || context) && mentions(before.slice(-24), NOT_CARD_CONTEXT)) {
    return true;
  }
  push(
    scan.out,
    "credit_card",
    start,
    start + value.length,
    cardVerdict(digits, grouped, context),
    maskDigits(value, 4),
    3
  );
  return true;
}

function classifySsn(scan: NumericScan, start: number, value: string): boolean {
  const separated = SSN_SEPARATED.exec(value);
  if (!(separated || SSN_PLAIN.test(value))) {
    return false;
  }
  const digits = digitsOf(value);
  const hyphenated = separated !== null && separated[1] === "-";
  const verdict = ssnValid(digits)
    ? ssnVerdict(scan.text, start, digits, hyphenated)
    : null;
  if (verdict) {
    push(
      scan.out,
      "us_ssn",
      start,
      start + value.length,
      verdict,
      maskDigits(value, 4),
      2
    );
  }
  return verdict !== null || hyphenated;
}

function classifyIp(scan: NumericScan, start: number, value: string): boolean {
  if (!IPV4_SHAPE.test(value)) {
    return false;
  }
  const octets = parseOctets(value);
  const skip =
    !octets ||
    isNonPublicIPv4(octets) ||
    mentions(windowBefore(scan.text, start, 16), VERSION_CONTEXT);
  if (octets && !skip) {
    const verdict: Verdict = PUBLIC_RESOLVERS.has(value)
      ? EXAMPLE_VERDICT
      : { severity: "medium", confidence: 0.7 };
    push(
      scan.out,
      "ip_address",
      start,
      start + value.length,
      verdict,
      `${octets[0]}.${octets[1]}.*.*`,
      2
    );
  }
  return true;
}

/** Classifies one number-like span; true when a format claimed it. */
function classifyNumber(
  scan: NumericScan,
  start: number,
  value: string
): boolean {
  const { kinds } = scan;
  if (value.includes(".") && IPV4_SHAPE.test(value)) {
    return kinds.has("ip_address") && classifyIp(scan, start, value);
  }
  return (
    (kinds.has("us_ssn") && classifySsn(scan, start, value)) ||
    (kinds.has("credit_card") && classifyCard(scan, start, value)) ||
    (kinds.has("phone") && classifyPhone(scan, start, value))
  );
}

/** Offsets of the space-separated parts of `value`: [start, end) pairs. */
function spaceParts(value: string): number[] {
  const parts: number[] = [];
  let partStart = 0;
  while (partStart <= value.length) {
    const space = value.indexOf(" ", partStart);
    const end = space === -1 ? value.length : space;
    if (end > partStart) {
      parts.push(partStart, end);
    }
    partStart = end + 1;
  }
  return parts;
}

/**
 * A run can hold several numbers ("call 415 555 2671 2 times", two cards in
 * a row). Try windows of consecutive space-separated parts, longest first.
 */
function classifyWindows(
  scan: NumericScan,
  start: number,
  value: string
): void {
  const parts = spaceParts(value);
  const count = parts.length / 2;
  const digitCounts: number[] = [];
  for (let p = 0; p < count; p++) {
    digitCounts.push(
      digitsOf(value.slice(parts[p * 2], parts[p * 2 + 1])).length
    );
  }
  let first = 0;
  while (first < count) {
    let claimed = 0;
    const longest = Math.min(MAX_PARTS_PER_ENTITY, count - first);
    let digits = 0;
    for (let p = first; p < first + longest; p++) {
      digits += digitCounts[p];
    }
    for (let size = longest; size >= 1 && claimed === 0; size--) {
      const from = parts[first * 2];
      const to = parts[(first + size - 1) * 2 + 1];
      const inRange = digits >= 9 && digits <= 19;
      if (
        inRange &&
        classifyNumber(scan, start + from, value.slice(from, to))
      ) {
        claimed = size;
      }
      digits -= digitCounts[first + size - 1];
    }
    first += Math.max(1, claimed);
  }
}

function followedByGlue(text: string, end: number): boolean {
  const next = text.charCodeAt(end);
  if (Number.isNaN(next) || next >= 128) {
    return false;
  }
  if (ALNUM_ONLY[next] === 1 || next === 95 || next === 45) {
    return true;
  }
  const isPoint = next === 46 || next === 44;
  const after = text.charCodeAt(end + 1);
  return isPoint && after >= 48 && after <= 57;
}

function scanNumbers(scan: NumericScan): void {
  const { text } = scan;
  for (const match of text.matchAll(NUMERIC_CANDIDATE)) {
    const value = match[0];
    const start = match.index ?? 0;
    const glue = value.startsWith("+") ? PHONE_PLUS_GLUE : NUMBER_GLUE;
    if (
      !standsAlone(text, start, glue) ||
      followedByGlue(text, start + value.length)
    ) {
      continue;
    }
    if (classifyNumber(scan, start, value)) {
      continue;
    }
    if (value.includes(" ") && digitsOf(value).length >= 9) {
      classifyWindows(scan, start, value);
    }
  }
}

function scanNumeric(
  text: string,
  kinds: Set<PIIKind>,
  out: RankedFinding[]
): void {
  const numeric =
    kinds.has("phone") ||
    kinds.has("credit_card") ||
    kinds.has("us_ssn") ||
    kinds.has("ip_address");
  if (numeric) {
    scanNumbers({ text, kinds, out });
  }
  if (kinds.has("iban")) {
    scanIbans(text, out);
  }
  if (kinds.has("uk_nino")) {
    scanNinos(text, out);
  }
}

const HAS_DIGIT_PAIR = /\d\d/;

/**
 * Finds personal data in model output. Every numeric detector validates the
 * value (Luhn and card network, IBAN mod-97, SSN area/group/serial, NANP
 * numbering rules) and prefers missing a number to flagging a version string,
 * date, order id, or hash. Well-known example values (user@example.com,
 * 4242 4242 4242 4242, (555) 123-4567) are still reported, at low severity
 * and confidence 0.3.
 */
export function detectPII(
  text: string,
  options: PIIOptions = {}
): OutputFinding[] {
  if (typeof text !== "string" || text.length < 5) {
    return [];
  }
  const kinds = new Set<PIIKind>(options.kinds ?? DEFAULT_PII_KINDS);
  const out: RankedFinding[] = [];
  if (kinds.has("email") && text.includes("@")) {
    scanEmails(text, out);
  }
  if (HAS_DIGIT_PAIR.test(text)) {
    scanNumeric(text, kinds, out);
  }
  if (kinds.has("us_passport")) {
    scanPassports(text, out);
  }
  return filterFindings(stripPriority(resolveOverlaps(out)), options);
}
