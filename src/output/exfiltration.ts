import { detectPII } from "./pii";
import { detectSecrets } from "./secrets";
import type { OutputFinding, Severity } from "./types";
import {
  atLeast,
  bytesToLatin1,
  charClassCount,
  decodeBase64,
  filterFindings,
  lastItem,
  type RankedFinding,
  SEVERITY_RANK,
  shannonEntropy,
  stripPriority,
} from "./util";

export interface ExfiltrationOptions {
  /**
   * Hosts the output may load or link to. An entry is an exact host
   * ("cdn.example.com") or a suffix (".example.com" or "*.example.com", which
   * also match "example.com" itself). Internationalized names are compared in
   * punycode, so "bücher.example" and "xn--bcher-kva.example" are the same.
   */
  allowedDomains?: string[];
  /**
   * Flag every image (markdown, `<img>`, CSS `url()`) from a host that is not
   * allowlisted, even without data in the URL: images load on render, so the
   * request itself is a beacon. Default true.
   */
  blockAllImages?: boolean;
  /**
   * Clickable links: "suspicious" (default) flags links that carry data or
   * disguise their target, "all" also flags every other non-allowlisted link
   * at low severity, "none" ignores links.
   */
  flagLinks?: "suspicious" | "all" | "none";
  /** Drop findings below this confidence (0..1). Default 0. */
  minConfidence?: number;
}

export const EXFILTRATION_KINDS: readonly string[] = [
  "markdown_image",
  "markdown_link",
  "html_image",
  "html_resource",
  "html_link",
  "html_form",
  "html_base",
  "html_event_handler",
  "meta_refresh",
  "css_url",
  "script_url",
  "url_data",
  "bare_url",
];

type Category = "image" | "resource" | "navigation" | "base" | "link" | "form";

// ---------------------------------------------------------------------------
// Hosts and allowlists
// ---------------------------------------------------------------------------

interface AllowRule {
  host: string;
  suffix: boolean;
}

const NON_ASCII = /[^ -~]/;
const TRAILING_DOTS = /\.+$/;
const URL_SCHEME_PREFIX = /^[a-z][a-z0-9+.-]*:\/\//i;
const HOST_TERMINATOR = /[/?#\\]/;
const SUFFIX_MARKER = /^\*?\./;

function toAsciiHost(host: string): string {
  if (!NON_ASCII.test(host)) {
    return host;
  }
  try {
    return new URL(`http://${host}`).hostname;
  } catch {
    return host;
  }
}

/** Lowercase, punycode, no port, no trailing dot. Accepts a bare host or a URL. */
function canonicalHost(input: string): string {
  let host = input.trim().toLowerCase();
  if (URL_SCHEME_PREFIX.test(host)) {
    host = host.slice(host.indexOf("//") + 2);
  }
  const cut = host.search(HOST_TERMINATOR);
  if (cut !== -1) {
    host = host.slice(0, cut);
  }
  const at = host.lastIndexOf("@");
  if (at !== -1) {
    host = host.slice(at + 1);
  }
  if (!host.startsWith("[")) {
    const colon = host.lastIndexOf(":");
    host = colon === -1 ? host : host.slice(0, colon);
  }
  return toAsciiHost(host.replace(TRAILING_DOTS, ""));
}

function compileAllowlist(domains: readonly string[]): AllowRule[] {
  const rules: AllowRule[] = [];
  for (const entry of domains) {
    const trimmed = entry.trim();
    const suffix = trimmed.startsWith(".") || trimmed.startsWith("*.");
    const host = canonicalHost(trimmed.replace(SUFFIX_MARKER, ""));
    if (host) {
      rules.push({ host, suffix });
    }
  }
  return rules;
}

function hostAllowed(host: string, rules: readonly AllowRule[]): boolean {
  for (const rule of rules) {
    if (host === rule.host) {
      return true;
    }
    if (rule.suffix && host.endsWith(`.${rule.host}`)) {
      return true;
    }
  }
  return false;
}

/**
 * True when `host` is on the allowlist. Entries are exact hosts or suffixes
 * (".example.com" / "*.example.com", which also match the apex). Hosts and
 * entries are compared case-insensitively, without ports or trailing dots,
 * and in punycode.
 */
export function isAllowedHost(
  host: string,
  allowedDomains: readonly string[] = []
): boolean {
  const canonical = canonicalHost(host);
  return (
    canonical !== "" && hostAllowed(canonical, compileAllowlist(allowedDomains))
  );
}

// ---------------------------------------------------------------------------
// URL resolution
// ---------------------------------------------------------------------------

interface Target {
  script: boolean;
  host: string;
  scheme: string;
  path: string;
  query: string;
  raw: string;
}

const SCHEME = /^([a-z][a-z0-9+.-]{0,31}):/i;
const BACKSLASHES = /\\/g;
const PROTOCOL_RELATIVE = /^[\\/]{2}/;
const HTTP_SLASHES = /^(https?:)[\\/]*/i;
const TAB_OR_NEWLINE = /[\t\n\r]/g;
const NETWORK_SCHEMES = new Set(["http", "https", "ftp", "ws", "wss"]);
const SCRIPT_SCHEMES = new Set(["javascript", "vbscript"]);

/** Drops leading C0 controls and spaces the way the URL parser does. */
function trimUrl(raw: string): string {
  let start = 0;
  let end = raw.length;
  while (start < end && raw.charCodeAt(start) <= 32) {
    start++;
  }
  while (end > start && raw.charCodeAt(end - 1) <= 32) {
    end--;
  }
  return raw.slice(start, end).replace(TAB_OR_NEWLINE, "");
}

const SIMPLE_HOST = /^[a-z0-9.-]+$/;

function parseWithUrl(value: string): Omit<Target, "script" | "raw"> | null {
  try {
    const url = new URL(value);
    return {
      host: canonicalHost(url.hostname),
      scheme: url.protocol.slice(0, -1),
      path: url.pathname,
      query: url.search.slice(1),
    };
  } catch {
    return null;
  }
}

function indexOrEnd(value: string, char: string, from: number): number {
  const at = value.indexOf(char, from);
  return at === -1 ? value.length : at;
}

/**
 * Splits an absolute URL. Plain ASCII hosts are parsed by hand (the URL
 * constructor costs microseconds per call in some runtimes); anything
 * unusual (IDN, percent-encoding, IPv6) goes through the URL parser.
 */
function parseUrlParts(value: string): Omit<Target, "script" | "raw"> | null {
  const colon = value.indexOf("://");
  const authorityStart = colon + 3;
  const authorityEnd = Math.min(
    indexOrEnd(value, "/", authorityStart),
    indexOrEnd(value, "?", authorityStart),
    indexOrEnd(value, "#", authorityStart),
    indexOrEnd(value, "\\", authorityStart)
  );
  const authority = value.slice(authorityStart, authorityEnd);
  let host = authority.slice(authority.lastIndexOf("@") + 1).toLowerCase();
  const port = host.lastIndexOf(":");
  if (port !== -1) {
    host = host.slice(0, port);
  }
  if (host.endsWith(".")) {
    host = host.replace(TRAILING_DOTS, "");
  }
  if (colon === -1 || !SIMPLE_HOST.test(host) || host.startsWith(".")) {
    return parseWithUrl(value);
  }
  const queryStart = value.indexOf("?", authorityEnd);
  const hashStart = indexOrEnd(value, "#", authorityEnd);
  const pathEnd =
    queryStart === -1 ? hashStart : Math.min(queryStart, hashStart);
  const path = value.slice(authorityEnd, pathEnd) || "/";
  const query =
    queryStart === -1 || queryStart > hashStart
      ? ""
      : value.slice(queryStart + 1, hashStart);
  return {
    host,
    scheme: value.slice(0, colon).toLowerCase(),
    path: path.includes("\\") ? path.replace(BACKSLASHES, "/") : path,
    query,
  };
}

/**
 * Resolves a destination the way a browser would for an absolute URL:
 * strips tabs and newlines, accepts protocol-relative and backslash forms,
 * lowercases and punycodes the host. Relative URLs and inert schemes
 * (data:, mailto:, tel:, blob:) return null.
 */
/** Small bounded memo for URL work that repeats within and across calls. */
const CACHE_LIMIT = 512;
const CACHEABLE_KEY = 2048;
const TARGET_CACHE = new Map<string, Target | null>();
const EVIDENCE_CACHE = new Map<string, Evidence | null>();

function memo<T>(cache: Map<string, T>, key: string, compute: () => T): T {
  if (key.length > CACHEABLE_KEY) {
    return compute();
  }
  if (cache.has(key)) {
    return cache.get(key) as T;
  }
  if (cache.size >= CACHE_LIMIT) {
    cache.clear();
  }
  const value = compute();
  cache.set(key, value);
  return value;
}

function resolveTarget(raw: string): Target | null {
  return memo(TARGET_CACHE, raw, () => resolveTargetUncached(raw));
}

function resolveTargetUncached(raw: string): Target | null {
  let value = trimUrl(raw);
  if (PROTOCOL_RELATIVE.test(value)) {
    value = `https://${value.replace(PROTOCOL_RELATIVE, "")}`;
  }
  const scheme = SCHEME.exec(value)?.[1].toLowerCase() ?? "";
  if (SCRIPT_SCHEMES.has(scheme)) {
    return { script: true, host: "", scheme, path: "", query: "", raw: value };
  }
  if (!NETWORK_SCHEMES.has(scheme)) {
    return null;
  }
  if (scheme === "http" || scheme === "https") {
    value = value.replace(HTTP_SLASHES, "$1//");
  }
  const parts = parseUrlParts(value);
  if (!parts?.host) {
    return null;
  }
  return { script: false, ...parts, raw: value };
}

// ---------------------------------------------------------------------------
// Does the URL carry data?
// ---------------------------------------------------------------------------

interface Evidence {
  reasons: string[];
  /** A secret, personal data, or conversation text: not just an opaque blob. */
  strong: boolean;
}

const BENIGN_PARAMS = new Set([
  "v",
  "ver",
  "version",
  "w",
  "h",
  "width",
  "height",
  "size",
  "sz",
  "s",
  "fit",
  "crop",
  "auto",
  "fm",
  "format",
  "dpr",
  "quality",
  "ixlib",
  "ixid",
  "t",
  "hl",
  "lang",
  "locale",
  "page",
  "sort",
  "tab",
  "raw",
  "ref",
  "source",
  "fbclid",
  "gclid",
  "msclkid",
  "x-amz-algorithm",
  "x-amz-credential",
  "x-amz-date",
  "x-amz-expires",
  "x-amz-signedheaders",
  "x-amz-signature",
  "x-amz-security-token",
  "signature",
  "policy",
  "key-pair-id",
  "expires",
]);
const SENSITIVE_PARAMS = new Set([
  "data",
  "d",
  "p",
  "c",
  "payload",
  "exfil",
  "leak",
  "secret",
  "password",
  "pass",
  "pwd",
  "token",
  "session",
  "cookie",
  "conversation",
  "convo",
  "chat",
  "history",
  "prompt",
  "memory",
  "msg",
  "message",
  "context",
  "info",
  "log",
  "summary",
  "creds",
  "credentials",
  "ssn",
  "cc",
  "card",
  "email",
  "user",
]);
const BASE64_BLOB = /^[A-Za-z0-9+/_-]{24,}={0,2}$/;
const HEX_BLOB = /^[A-Fa-f0-9]{32,}$/;
const TEMPLATE_MARKERS =
  /[{}]|%7[BbDd]|\[[A-Z_]{3,}\]|%5B[A-Z_]{3,}%5D|\$[A-Z_]{3,}/;
const WHITESPACE_RUN = /\s+/;
const HEX_LABEL = /^[a-f0-9]{24,63}$/;
const ALNUM_LABEL = /^[a-z0-9]{24,63}$/;
const DIGIT = /\d/g;
const PRINTABLE = /[\x20-\x7e\t\n\r]/g;
const FILE_EXTENSION = /\.[A-Za-z0-9]{1,5}$/;
const PLUS = /\+/g;

function decodeComponent(value: string): string {
  try {
    return decodeURIComponent(value.replace(PLUS, " "));
  } catch {
    return value;
  }
}

function wordCount(value: string): number {
  return value.trim().split(WHITESPACE_RUN).filter(Boolean).length;
}

function isEncodedBlob(raw: string): boolean {
  if (HEX_BLOB.test(raw)) {
    return true;
  }
  return (
    BASE64_BLOB.test(raw) &&
    charClassCount(raw) >= 3 &&
    shannonEntropy(raw) >= 4
  );
}

/** Decodes a base64 value that turns out to be readable text. */
function decodedText(raw: string): string | null {
  if (!BASE64_BLOB.test(raw)) {
    return null;
  }
  const bytes = decodeBase64(raw);
  if (!bytes || bytes.length < 12) {
    return null;
  }
  const text = bytesToLatin1(bytes);
  const printable = text.match(PRINTABLE)?.length ?? 0;
  return printable / text.length >= 0.9 ? text : null;
}

function carriesSensitiveData(decoded: string): boolean {
  if (decoded.length < 12) {
    return false;
  }
  const secret = detectSecrets(decoded).some((f) =>
    atLeast(f.severity, "high")
  );
  if (secret) {
    return true;
  }
  return (
    decoded.includes("@") &&
    detectPII(decoded, { kinds: ["email"], minConfidence: 0.5 }).length > 0
  );
}

interface ValueSignals {
  reasons: Set<string>;
  strong: boolean;
}

function inspectValue(name: string, raw: string, signals: ValueSignals): void {
  const decoded = decodeComponent(raw);
  if (carriesSensitiveData(decoded)) {
    signals.reasons.add("sensitive_value");
    signals.strong = true;
  }
  const words = wordCount(decoded);
  if (words >= 6 || (words >= 4 && decoded.length >= 40)) {
    signals.reasons.add("prose");
    signals.strong = true;
  }
  if (isEncodedBlob(raw)) {
    signals.reasons.add("encoded_blob");
    const plain = decodedText(raw);
    if (plain && (wordCount(plain) >= 3 || carriesSensitiveData(plain))) {
      signals.reasons.add("encoded_text");
      signals.strong = true;
    }
  }
  if (decoded.length >= 100) {
    signals.reasons.add("long_value");
  }
  if (SENSITIVE_PARAMS.has(name) && decoded.length >= 8) {
    signals.reasons.add("sensitive_param");
  }
}

function inspectQuery(query: string, signals: ValueSignals): void {
  let counted = 0;
  for (const pair of query.split("&")) {
    if (!pair) {
      continue;
    }
    const eq = pair.indexOf("=");
    const name = decodeComponent(
      eq === -1 ? pair : pair.slice(0, eq)
    ).toLowerCase();
    const value = eq === -1 ? name : pair.slice(eq + 1);
    const benign = BENIGN_PARAMS.has(name) || name.startsWith("utm_");
    if (benign) {
      continue;
    }
    counted++;
    inspectValue(name, value, signals);
  }
  if (counted >= 6) {
    signals.reasons.add("many_params");
  }
}

function inspectPath(path: string, signals: ValueSignals): void {
  for (const segment of path.split("/")) {
    if (segment.length < 24) {
      continue;
    }
    const decoded = decodeComponent(segment);
    if (wordCount(decoded) >= 6 || carriesSensitiveData(decoded)) {
      signals.reasons.add("path_data");
      signals.strong = true;
    } else if (
      !FILE_EXTENSION.test(segment) &&
      segment.length >= 32 &&
      isEncodedBlob(segment) &&
      shannonEntropy(segment) >= 4.2
    ) {
      signals.reasons.add("path_blob");
    }
  }
}

/** A subdomain label that is hex, or mostly-random alphanumerics, carries data (DNS exfiltration). */
function isDataLabel(label: string): boolean {
  const digits = label.match(DIGIT)?.length ?? 0;
  if (digits === 0 || digits === label.length) {
    return false;
  }
  const encoded =
    HEX_LABEL.test(label) ||
    (ALNUM_LABEL.test(label) && digits / label.length >= 0.2);
  return encoded && shannonEntropy(label) >= 3;
}

function inspectHost(host: string, signals: ValueSignals): void {
  const labels = host.split(".");
  for (const label of labels.slice(0, -2)) {
    if (isDataLabel(label)) {
      signals.reasons.add("dns_label");
    }
  }
}

/** True when no query, path segment, or subdomain label is long enough to carry data. */
function obviouslyClean(target: Target): boolean {
  if (target.query || target.host.length > 40) {
    return false;
  }
  const { path } = target;
  let segmentStart = 0;
  for (let i = 0; i <= path.length; i++) {
    const code = path.charCodeAt(i);
    const special = code === 123 || code === 91 || code === 37 || code === 36;
    if (special) {
      return false;
    }
    if (i === path.length || code === 47) {
      if (i - segmentStart >= 24) {
        return false;
      }
      segmentStart = i + 1;
    }
  }
  return true;
}

function dataEvidence(target: Target): Evidence | null {
  return memo(EVIDENCE_CACHE, target.raw, () => dataEvidenceUncached(target));
}

function dataEvidenceUncached(target: Target): Evidence | null {
  if (obviouslyClean(target)) {
    return null;
  }
  const signals: ValueSignals = { reasons: new Set(), strong: false };
  if (TEMPLATE_MARKERS.test(target.path + target.query)) {
    signals.reasons.add("template");
  }
  if (target.query) {
    inspectQuery(target.query, signals);
  }
  inspectPath(target.path, signals);
  inspectHost(target.host, signals);
  if (signals.reasons.size === 0) {
    return null;
  }
  return { reasons: Array.from(signals.reasons), strong: signals.strong };
}

// ---------------------------------------------------------------------------
// Code spans and fenced blocks (their contents are not rendered)
// ---------------------------------------------------------------------------

interface Fence {
  start: number;
  end: number;
  char: string;
  length: number;
}

function runLength(text: string, from: number, char: string): number {
  let i = from;
  while (text.charAt(i) === char) {
    i++;
  }
  return i - from;
}

/** Fence markers (``` or ~~~ with up to three spaces of indent at a line start), in order. */
function fenceMarkers(text: string): Fence[] {
  const markers: Fence[] = [];
  for (const char of ["`", "~"]) {
    const marker = char.repeat(3);
    let at = text.indexOf(marker);
    while (at !== -1) {
      const lineStart = text.lastIndexOf("\n", at - 1) + 1;
      const indent = at - lineStart;
      const length = runLength(text, at, char);
      if (indent <= 3 && text.slice(lineStart, at).trim() === "") {
        markers.push({ start: at, end: at + length, char, length });
      }
      at = text.indexOf(marker, at + length);
    }
  }
  return markers.sort((a, b) => a.start - b.start);
}

function fencedBlocks(text: string): [number, number][] {
  const blocks: [number, number][] = [];
  let open: Fence | null = null;
  for (const fence of fenceMarkers(text)) {
    if (!open) {
      open = fence;
    } else if (fence.char === open.char && fence.length >= open.length) {
      blocks.push([open.start, fence.end]);
      open = null;
    }
  }
  if (open) {
    blocks.push([open.start, text.length]);
  }
  return blocks;
}

export function insideAny(ranges: [number, number][], index: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    const range = ranges[mid];
    if (index < range[0]) {
      hi = mid - 1;
    } else if (index >= range[1]) {
      lo = mid + 1;
    } else {
      return true;
    }
  }
  return false;
}

/**
 * Inline code spans (CommonMark): a backtick run opens a span that the next
 * run of the same length closes; runs with no partner are literal.
 */
function codeSpans(
  text: string,
  fences: [number, number][]
): [number, number][] {
  const starts: number[] = [];
  const lengths: number[] = [];
  let at = text.indexOf("`");
  while (at !== -1) {
    const length = runLength(text, at, "`");
    if (!insideAny(fences, at)) {
      starts.push(at);
      lengths.push(length);
    }
    at = text.indexOf("`", at + length);
  }
  // nextSame[i]: the next run with the same length as run i, or -1.
  const nextSame: number[] = new Array(starts.length);
  const lastSeen: number[] = [];
  for (let i = starts.length - 1; i >= 0; i--) {
    const length = lengths[i];
    nextSame[i] = lastSeen[length] ?? -1;
    lastSeen[length] = i;
  }
  const spans: [number, number][] = [];
  let i = 0;
  while (i < starts.length) {
    const close = nextSame[i];
    if (close === -1) {
      i++;
    } else {
      spans.push([starts[i], starts[close] + lengths[close]]);
      i = close + 1;
    }
  }
  return spans;
}

/** Merges two sorted range lists into one sorted list of disjoint ranges. */
function mergeSorted(
  a: [number, number][],
  b: [number, number][]
): [number, number][] {
  const merged: [number, number][] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    const takeA = j >= b.length || (i < a.length && a[i][0] <= b[j][0]);
    const range = takeA ? a[i] : b[j];
    if (takeA) {
      i++;
    } else {
      j++;
    }
    const previous = lastItem(merged);
    if (previous !== undefined && range[0] <= previous[1]) {
      previous[1] = Math.max(previous[1], range[1]);
    } else {
      merged.push([range[0], range[1]]);
    }
  }
  return merged;
}

export function codeRanges(text: string): [number, number][] {
  if (!text.includes("`")) {
    return text.includes("~~~") ? fencedBlocks(text) : [];
  }
  const fences =
    text.includes("```") || text.includes("~~~") ? fencedBlocks(text) : [];
  return mergeSorted(fences, codeSpans(text, fences));
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

interface Scan {
  text: string;
  allow: AllowRule[];
  blockAllImages: boolean;
  flagLinks: "suspicious" | "all" | "none";
  code: [number, number][];
  /** Ranges already handled by a structured pass; the bare-URL pass skips them. */
  consumed: [number, number][];
  /** The text has "]:" so reference definitions may exist. */
  hasDefinitions: boolean;
  out: RankedFinding[];
}

interface Candidate {
  kind: string;
  category: Category;
  start: number;
  end: number;
  target: Target;
  /** Visible link text, for disguised-link checks. */
  label?: string;
  /** Precomputed data evidence; computed on demand when undefined. */
  evidence?: Evidence | null;
}

interface Verdict {
  severity: Severity;
  confidence: number;
}

function preview(target: Target): string {
  if (target.script) {
    return `${target.scheme}:…`;
  }
  const path =
    target.path.length > 24 ? `${target.path.slice(0, 24)}…` : target.path;
  const query = target.query ? "?…" : "";
  const host = target.host
    .split(".")
    .map((label) => (label.length > 24 ? `${label.slice(0, 8)}…` : label))
    .join(".");
  return `${target.scheme}://${host}${path === "/" ? "" : path}${query}`;
}

const SHOWN_HOST =
  /^(https?:\/\/|www\.)?(?:www\.)?((?:[a-z0-9-]{1,63}\.)+([a-z]{2,24}))(?:[/:?#]\S*)?$/i;
/** TLDs that read as a domain in link text; "README.md" or "main.py" read as files. */
const COMMON_TLDS = new Set([
  "com",
  "org",
  "net",
  "io",
  "dev",
  "app",
  "co",
  "ai",
  "gov",
  "edu",
  "info",
  "biz",
  "me",
  "us",
  "uk",
  "de",
  "fr",
  "ru",
  "cn",
  "jp",
  "in",
  "br",
  "xyz",
  "tech",
  "cloud",
  "site",
  "online",
  "page",
]);

function disguised(label: string | undefined, host: string): boolean {
  const match = label ? SHOWN_HOST.exec(label.trim()) : null;
  if (!match) {
    return false;
  }
  const explicit = match[1] !== undefined;
  if (!(explicit || COMMON_TLDS.has(match[3].toLowerCase()))) {
    return false;
  }
  const shown = canonicalHost(match[2]);
  const bare = host.startsWith("www.") ? host.slice(4) : host;
  return shown !== bare && !bare.endsWith(`.${shown}`);
}

function autoLoadVerdict(
  category: Category,
  evidence: Evidence | null,
  blockAllImages: boolean
): Verdict | null {
  if (evidence) {
    return { severity: "critical", confidence: evidence.strong ? 0.95 : 0.9 };
  }
  if (category === "image") {
    return blockAllImages ? { severity: "high", confidence: 0.7 } : null;
  }
  return { severity: "high", confidence: category === "resource" ? 0.75 : 0.8 };
}

function linkVerdict(
  scan: Scan,
  candidate: Candidate,
  evidence: Evidence | null
): Verdict | null {
  if (scan.flagLinks === "none") {
    return null;
  }
  if (evidence) {
    return evidence.strong
      ? { severity: "high", confidence: 0.85 }
      : { severity: "medium", confidence: 0.7 };
  }
  if (candidate.category === "form") {
    return { severity: "medium", confidence: 0.6 };
  }
  if (disguised(candidate.label, candidate.target.host)) {
    return { severity: "medium", confidence: 0.6 };
  }
  return scan.flagLinks === "all" ? { severity: "low", confidence: 0.5 } : null;
}

function verdictFor(scan: Scan, candidate: Candidate): Verdict | null {
  const { target, category } = candidate;
  if (target.script) {
    return { severity: "high", confidence: 0.85 };
  }
  if (hostAllowed(target.host, scan.allow)) {
    return null;
  }
  const evidence =
    candidate.evidence === undefined
      ? dataEvidence(target)
      : candidate.evidence;
  if (category === "link" || category === "form") {
    return linkVerdict(scan, candidate, evidence);
  }
  return autoLoadVerdict(category, evidence, scan.blockAllImages);
}

function report(scan: Scan, candidate: Candidate): void {
  scan.consumed.push([candidate.start, candidate.end]);
  const verdict = verdictFor(scan, candidate);
  if (!verdict) {
    return;
  }
  const inCode = insideAny(scan.code, candidate.start);
  scan.out.push({
    type: "exfiltration",
    kind: candidate.target.script ? "script_url" : candidate.kind,
    start: candidate.start,
    end: candidate.end,
    severity: inCode ? "low" : verdict.severity,
    confidence: inCode
      ? Math.max(0.1, Math.round(verdict.confidence * 30) / 100)
      : verdict.confidence,
    preview: preview(candidate.target),
    priority: candidate.category === "link" ? 1 : 2,
  });
}

// ---------------------------------------------------------------------------
// Markdown: inline links/images and reference definitions
// ---------------------------------------------------------------------------

const REFERENCE_DEFINITION =
  /^ {0,3}\[([^\]\n]{1,999})\]:[ \t]*\n?[ \t]*(<[^>\n]{0,4096}>|\S{1,8192})/gm;
const LABEL_SPACE = /\s+/g;

function normalizeLabel(label: string): string {
  return label.trim().replace(LABEL_SPACE, " ").toLowerCase();
}

const NONE = Number.POSITIVE_INFINITY;

function nextIndex(text: string, needle: string, from: number): number {
  const at = text.indexOf(needle, from);
  return at === -1 ? NONE : at;
}

function openBracket(stack: number[], index: number): void {
  if (stack.length >= 64) {
    stack.splice(0, 32);
  }
  stack.push(index);
}

/** Matches "[" with "]" (nesting allowed, reset at blank lines), jumping between brackets with indexOf. */
function matchBrackets(text: string): [number, number][] {
  const pairs: [number, number][] = [];
  const stack: number[] = [];
  let open = nextIndex(text, "[", 0);
  let close = nextIndex(text, "]", 0);
  let blank = nextIndex(text, "\n\n", 0);
  while (open !== NONE || close !== NONE) {
    if (blank < open && blank < close) {
      stack.length = 0;
      blank = nextIndex(text, "\n\n", blank + 2);
      continue;
    }
    const isOpen = open < close;
    const index = isOpen ? open : close;
    // A backslash-escaped bracket is literal text.
    const escaped = index > 0 && text.charCodeAt(index - 1) === 92;
    if (isOpen) {
      if (!escaped) {
        openBracket(stack, index);
      }
      open = nextIndex(text, "[", index + 1);
    } else {
      if (!escaped && stack.length > 0) {
        pairs.push([stack.pop() as number, index]);
      }
      close = nextIndex(text, "]", index + 1);
    }
  }
  return pairs;
}

/** Skips blanks and at most one newline: `![a]\n(url)` still counts. */
function skipGap(text: string, from: number, limit: number): number {
  let i = from;
  let newlines = 0;
  while (i < text.length && i - from < limit) {
    const c = text.charAt(i);
    if (c === "\n") {
      newlines++;
      if (newlines > 1) {
        return i;
      }
    } else if (c !== " " && c !== "\t" && c !== "\r") {
      return i;
    }
    i++;
  }
  return i;
}

interface Destination {
  start: number;
  end: number;
  /** Offset just past the closing parenthesis (or the destination when unclosed). */
  close: number;
}

function destinationEnd(text: string, from: number): number {
  const limit = Math.min(text.length, from + 8192);
  let depth = 0;
  let i = from;
  while (i < limit) {
    const c = text.charCodeAt(i);
    // "[" ends a destination unless it opens an IPv6 host ("//[::1]"); this
    // also keeps adversarial "[](" runs linear.
    const opensBracket = c === 91 && !text.startsWith("//", i - 2);
    if (c <= 32 || opensBracket) {
      break;
    }
    if (c === 40) {
      depth++;
    } else if (c === 41) {
      if (depth === 0) {
        break;
      }
      depth--;
    } else if (c === 92) {
      i++;
    }
    i++;
  }
  return i;
}

function closingParen(text: string, from: number): number {
  let i = skipGap(text, from, 16);
  const quote = text.charAt(i);
  if (quote === '"' || quote === "'") {
    const end = text.indexOf(quote, i + 1);
    if (end === -1 || end - i > 512) {
      return from;
    }
    i = skipGap(text, end + 1, 16);
  }
  return text.charAt(i) === ")" ? i + 1 : from;
}

function inlineDestination(text: string, open: number): Destination | null {
  const start = skipGap(text, open + 1, 16);
  if (text.charAt(start) === "<") {
    const end = text.indexOf(">", start + 1);
    const newline = text.indexOf("\n", start + 1);
    const unclosed = end === -1 || end - start > 4096;
    if (unclosed || (newline !== -1 && newline < end)) {
      return null;
    }
    return { start: start + 1, end, close: closingParen(text, end + 1) };
  }
  const end = destinationEnd(text, start);
  if (end === start) {
    return null;
  }
  return { start, end, close: closingParen(text, end) };
}

interface ReferenceUse {
  image: boolean;
  label: string;
  text: string;
}

function referenceLabel(
  text: string,
  after: number,
  linkText: string
): string | null {
  if (text.charAt(after) !== "[") {
    return normalizeLabel(linkText);
  }
  const close = text.indexOf("]", after + 1);
  const newline = text.indexOf("\n", after + 1);
  if (
    close === -1 ||
    close - after > 1000 ||
    (newline !== -1 && newline < close)
  ) {
    return null;
  }
  const label = text.slice(after + 1, close);
  return normalizeLabel(label || linkText);
}

function reportInlineLink(
  scan: Scan,
  open: number,
  after: number,
  image: boolean,
  linkText: string
): void {
  const { text } = scan;
  const destination = inlineDestination(text, after);
  const target = destination
    ? resolveTarget(text.slice(destination.start, destination.end))
    : null;
  if (!(destination && target)) {
    return;
  }
  report(scan, {
    kind: image ? "markdown_image" : "markdown_link",
    category: image ? "image" : "link",
    start: image ? open - 1 : open,
    end: Math.max(destination.close, destination.end),
    target,
    label: linkText,
  });
}

function scanMarkdownInline(scan: Scan, uses: ReferenceUse[]): void {
  const { text } = scan;
  for (const [open, close] of matchBrackets(text)) {
    const image = open > 0 && text.charAt(open - 1) === "!";
    const linkText = text.slice(open + 1, close);
    const after = skipGap(text, close + 1, 8);
    if (text.charAt(after) === "(") {
      reportInlineLink(scan, open, after, image, linkText);
      continue;
    }
    const label = scan.hasDefinitions
      ? referenceLabel(text, after, linkText)
      : null;
    if (label) {
      uses.push({ image, label, text: linkText });
    }
  }
}

function scanReferenceDefinitions(scan: Scan, uses: ReferenceUse[]): void {
  const usage = new Map<string, ReferenceUse>();
  for (const use of uses) {
    const known = usage.get(use.label);
    if (!known || (use.image && !known.image)) {
      usage.set(use.label, use);
    }
  }
  for (const match of scan.text.matchAll(REFERENCE_DEFINITION)) {
    const index = match.index ?? 0;
    const raw = match[2];
    const urlStart = index + match[0].length - raw.length;
    scan.consumed.push([index, index + match[0].length]);
    const use = usage.get(normalizeLabel(match[1]));
    const destination = raw.startsWith("<") ? raw.slice(1, -1) : raw;
    const target = use ? resolveTarget(destination) : null;
    if (!(use && target)) {
      continue;
    }
    report(scan, {
      kind: use.image ? "markdown_image" : "markdown_link",
      category: use.image ? "image" : "link",
      start: urlStart,
      end: urlStart + raw.length,
      target,
      label: use.text,
    });
  }
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

const TAG_OPEN = /<([a-zA-Z][a-zA-Z0-9-]{0,15})(?=[\s/>])/g;
const HTML_ENTITY =
  /&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z]{2,8}));?/g;
const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  colon: ":",
  sol: "/",
  bsol: "\\",
  period: ".",
  lpar: "(",
  rpar: ")",
  quest: "?",
  equals: "=",
  num: "#",
  percnt: "%",
  commat: "@",
  tab: "\t",
  newline: "\n",
  nbsp: " ",
};
const REFRESH_URL = /url\s*=\s*['"]?([^'"\s;]+)/i;
const EVENT_HANDLER = /^on[a-z]{3,}$/;
const SRCSET_SEPARATOR = /\s*,\s*/;
const SRCSET_DESCRIPTOR = /\s+/;

const IMAGE_ATTRIBUTES: Record<string, string[]> = {
  img: ["src", "srcset", "lowsrc", "dynsrc"],
  image: ["href", "xlink:href", "src"],
  input: ["src"],
  picture: [],
};
const RESOURCE_ATTRIBUTES: Record<string, string[]> = {
  iframe: ["src"],
  frame: ["src"],
  script: ["src"],
  link: ["href"],
  video: ["src", "poster"],
  audio: ["src"],
  source: ["src", "srcset"],
  track: ["src"],
  embed: ["src"],
  object: ["data"],
  body: ["background"],
  table: ["background"],
  td: ["background"],
  th: ["background"],
  use: ["href", "xlink:href"],
  feimage: ["href", "xlink:href"],
};
const LINK_ATTRIBUTES: Record<string, string[]> = {
  a: ["href", "ping"],
  area: ["href", "ping"],
  form: ["action"],
  button: ["formaction"],
  input: ["formaction"],
};

function decodeEntities(value: string): string {
  if (!value.includes("&")) {
    return value;
  }
  return value.replace(
    HTML_ENTITY,
    (
      whole,
      dec: string | undefined,
      hex: string | undefined,
      name: string | undefined
    ) => {
      if (dec || hex) {
        const code = dec ? Number(dec) : Number.parseInt(hex ?? "", 16);
        return code > 0 && code <= 0x10_ff_ff
          ? String.fromCodePoint(code)
          : whole;
      }
      return NAMED_ENTITIES[(name ?? "").toLowerCase()] ?? whole;
    }
  );
}

interface Attribute {
  name: string;
  value: string;
}

interface ParsedTag {
  attributes: Attribute[];
  end: number;
}

function isAttributeNameStop(code: number): boolean {
  return code <= 32 || code === 47 || code === 62 || code === 61;
}

function readAttributeValue(
  text: string,
  from: number,
  limit: number
): { value: string; end: number } {
  const quote = text.charAt(from);
  if (quote === '"' || quote === "'") {
    const close = text.indexOf(quote, from + 1);
    const end = close === -1 || close >= limit ? limit : close;
    return { value: text.slice(from + 1, end), end: end + 1 };
  }
  let i = from;
  while (i < limit && text.charCodeAt(i) > 32 && text.charAt(i) !== ">") {
    i++;
  }
  return { value: text.slice(from, i), end: i };
}

function skipSpaces(text: string, from: number, limit: number): number {
  let i = from;
  while (i < limit && text.charCodeAt(i) <= 32) {
    i++;
  }
  return i;
}

const MAX_ATTRIBUTES = 64;

function parseTag(text: string, from: number): ParsedTag {
  const limit = Math.min(text.length, from + 8192);
  const attributes: Attribute[] = [];
  let i = from;
  while (i < limit) {
    if (attributes.length >= MAX_ATTRIBUTES) {
      const close = text.indexOf(">", i);
      return {
        attributes,
        end: close === -1 || close >= limit ? limit : close + 1,
      };
    }
    const c = text.charCodeAt(i);
    if (c === 62) {
      return { attributes, end: i + 1 };
    }
    if (c <= 32 || c === 47) {
      i++;
      continue;
    }
    const nameStart = i;
    while (i < limit && !isAttributeNameStop(text.charCodeAt(i))) {
      i++;
    }
    if (i === nameStart) {
      i++;
      continue;
    }
    const name = text.slice(nameStart, i).toLowerCase();
    const afterName = skipSpaces(text, i, limit);
    if (text.charAt(afterName) !== "=") {
      attributes.push({ name, value: "" });
      continue;
    }
    const read = readAttributeValue(
      text,
      skipSpaces(text, afterName + 1, limit),
      limit
    );
    attributes.push({ name, value: decodeEntities(read.value) });
    i = read.end;
  }
  return { attributes, end: limit };
}

function attributeUrls(name: string, value: string): string[] {
  if (name !== "srcset") {
    return [value];
  }
  return value
    .split(SRCSET_SEPARATOR)
    .map((candidate) => candidate.trim().split(SRCSET_DESCRIPTOR)[0])
    .filter(Boolean);
}

function tagCategory(tag: string, attribute: string): Category | null {
  if (IMAGE_ATTRIBUTES[tag]?.includes(attribute)) {
    return "image";
  }
  if (RESOURCE_ATTRIBUTES[tag]?.includes(attribute)) {
    return "resource";
  }
  if (LINK_ATTRIBUTES[tag]?.includes(attribute)) {
    return tag === "form" || attribute === "formaction" ? "form" : "link";
  }
  if (tag === "base" && attribute === "href") {
    return "base";
  }
  return null;
}

const CATEGORY_KINDS: Record<Category, string> = {
  image: "html_image",
  resource: "html_resource",
  navigation: "meta_refresh",
  base: "html_base",
  link: "html_link",
  form: "html_form",
};

function reportEventHandler(
  scan: Scan,
  start: number,
  end: number,
  name: string
): void {
  const inCode = insideAny(scan.code, start);
  scan.out.push({
    type: "exfiltration",
    kind: "html_event_handler",
    start,
    end,
    severity: inCode ? "low" : "high",
    confidence: inCode ? 0.2 : 0.8,
    preview: `${name}=…`,
    priority: 2,
  });
}

function metaRefreshTarget(attributes: Attribute[]): Target | null {
  const refresh = attributes.some(
    (a) => a.name === "http-equiv" && a.value.trim().toLowerCase() === "refresh"
  );
  const content = attributes.find((a) => a.name === "content");
  const url = refresh && content ? REFRESH_URL.exec(content.value) : null;
  return url ? resolveTarget(url[1]) : null;
}

const TAG = /<[^>]{0,512}>/g;

function anchorText(text: string, from: number): string | undefined {
  const inner = text.slice(from, from + 512);
  const close = inner.indexOf("</a");
  return close === -1 ? undefined : inner.slice(0, close).replace(TAG, "");
}

function analyzeTag(
  scan: Scan,
  tag: string,
  start: number,
  parsed: ParsedTag
): void {
  const end = parsed.end;
  scan.consumed.push([start, end]);
  if (tag === "meta") {
    const target = metaRefreshTarget(parsed.attributes);
    if (target) {
      report(scan, {
        kind: "meta_refresh",
        category: "navigation",
        start,
        end,
        target,
      });
    }
    return;
  }
  const label = tag === "a" ? anchorText(scan.text, end) : undefined;
  for (const attribute of parsed.attributes) {
    if (EVENT_HANDLER.test(attribute.name) && attribute.value.trim()) {
      reportEventHandler(scan, start, end, attribute.name);
      continue;
    }
    const category = tagCategory(tag, attribute.name);
    if (!category) {
      continue;
    }
    for (const url of attributeUrls(attribute.name, attribute.value)) {
      const target = resolveTarget(url);
      if (target) {
        report(scan, {
          kind: CATEGORY_KINDS[category],
          category,
          start,
          end,
          target,
          label,
        });
      }
    }
  }
}

function scanHtml(scan: Scan): void {
  const { text } = scan;
  TAG_OPEN.lastIndex = 0;
  for (
    let match = TAG_OPEN.exec(text);
    match !== null;
    match = TAG_OPEN.exec(text)
  ) {
    const parsed = parseTag(text, match.index + match[0].length);
    TAG_OPEN.lastIndex = Math.max(parsed.end, match.index + 1);
    analyzeTag(scan, match[1].toLowerCase(), match.index, parsed);
  }
  TAG_OPEN.lastIndex = 0;
}

// ---------------------------------------------------------------------------
// CSS url() and @import
// ---------------------------------------------------------------------------

const CSS_URL = /url\(\s{0,16}(["']?)([^"'()\s]{1,8192})\1\s{0,16}\)/gi;
const CSS_IMPORT = /@import\s{1,16}(["'])([^"'\s]{1,8192})\1/gi;

function scanCss(scan: Scan): void {
  for (const pattern of [CSS_URL, CSS_IMPORT]) {
    for (const match of scan.text.matchAll(pattern)) {
      const target = resolveTarget(match[2]);
      const start = match.index ?? 0;
      if (target) {
        report(scan, {
          kind: "css_url",
          category: pattern === CSS_URL ? "image" : "resource",
          start,
          end: start + match[0].length,
          target,
        });
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Bare URLs in prose (autolinked by most chat UIs, followed by agents)
// ---------------------------------------------------------------------------

const BARE_SCHEMES = new Set(["http", "https", "ftp", "ws", "wss"]);
/** Characters that end a bare URL in prose. */
const URL_STOP = new Uint8Array(128);
for (const char of " \t\r\n<>\"'`") {
  URL_STOP[char.charCodeAt(0)] = 1;
}
const TRAILING_URL_PUNCTUATION = /[.,;:!?*_~'"]+$/;

const CLOSERS = ")]}";

function trimBareUrl(url: string): string {
  let trimmed = url.replace(TRAILING_URL_PUNCTUATION, "");
  if (!CLOSERS.includes(trimmed.slice(-1))) {
    return trimmed;
  }
  for (const [open, close] of [
    ["(", ")"],
    ["[", "]"],
    ["{", "}"],
  ]) {
    while (
      trimmed.endsWith(close) &&
      trimmed.split(close).length > trimmed.split(open).length
    ) {
      trimmed = trimmed.slice(0, -1).replace(TRAILING_URL_PUNCTUATION, "");
    }
  }
  return trimmed;
}

/** Start of an http(s)/ftp/ws(s) scheme ending at `colon`, or -1. */
function schemeStart(text: string, colon: number): number {
  let i = colon;
  while (i > 0 && colon - i < 5) {
    const code = text.charCodeAt(i - 1);
    const letter = (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
    if (!letter) {
      break;
    }
    i--;
  }
  const scheme = text.slice(i, colon).toLowerCase();
  return BARE_SCHEMES.has(scheme) ? i : -1;
}

function bareUrlEnd(text: string, from: number): number {
  const limit = Math.min(text.length, from + 8192);
  let i = from;
  while (i < limit) {
    const code = text.charCodeAt(i);
    if (code < 128 && URL_STOP[code] === 1) {
      break;
    }
    i++;
  }
  return i;
}

function scanBareUrls(scan: Scan): void {
  const consumed = [...scan.consumed].sort((a, b) => a[0] - b[0]);
  const merged: [number, number][] = [];
  for (const range of consumed) {
    const previous = lastItem(merged);
    if (previous && range[0] <= previous[1]) {
      previous[1] = Math.max(previous[1], range[1]);
    } else {
      merged.push([range[0], range[1]]);
    }
  }
  const { text } = scan;
  let colon = text.indexOf("://");
  while (colon !== -1) {
    const start = schemeStart(text, colon);
    const end = bareUrlEnd(text, colon + 3);
    // A URL nested in another URL's query is part of that URL's data.
    colon = text.indexOf("://", Math.max(end, colon + 3));
    if (start === -1 || insideAny(merged, start)) {
      continue;
    }
    const url = trimBareUrl(text.slice(start, end));
    const target = resolveTarget(url);
    if (!target) {
      continue;
    }
    const evidence = hostAllowed(target.host, scan.allow)
      ? null
      : dataEvidence(target);
    report(scan, {
      kind: evidence ? "url_data" : "bare_url",
      category: "link",
      start,
      end: start + url.length,
      target,
      evidence,
    });
  }
}

// ---------------------------------------------------------------------------

/**
 * Nested elements (an image inside a link) are separate leaks and are all
 * kept; only a repeat of the same kind over the same span collapses, keeping
 * the most severe.
 */
function worseThan(a: RankedFinding, b: RankedFinding): boolean {
  const rankA = SEVERITY_RANK[a.severity];
  const rankB = SEVERITY_RANK[b.severity];
  return rankA < rankB || (rankA === rankB && a.confidence < b.confidence);
}

function dedupe(findings: RankedFinding[]): OutputFinding[] {
  const sorted = [...findings].sort(
    (a, b) =>
      a.start - b.start ||
      b.end - a.end ||
      (a.kind < b.kind ? -1 : Number(a.kind > b.kind))
  );
  const kept: RankedFinding[] = [];
  for (const finding of sorted) {
    const previous = lastItem(kept);
    const same =
      previous !== undefined &&
      previous.start === finding.start &&
      previous.end === finding.end &&
      previous.kind === finding.kind;
    if (!same) {
      kept.push(finding);
    } else if (worseThan(previous, finding)) {
      kept[kept.length - 1] = finding;
    }
  }
  return stripPriority(kept);
}

const ANY_URLISH = /\/\/|\\\\|:[\\/]|javascript:|vbscript:|<[a-z]/i;

/**
 * Finds content in model output that leaks data when it is rendered or
 * followed: markdown and HTML images (which load without a click), other
 * auto-loading HTML resources, CSS `url()`, meta refresh, `javascript:` URLs,
 * inline event handlers, and links or bare URLs that carry data in their
 * query, path, or subdomain.
 *
 * Severity: an auto-loading resource to a non-allowlisted host is critical
 * with data in the URL and high without (the request is a beacon); a
 * clickable link with data is medium (high when the data is a secret, personal
 * data, or conversation text). Anything inside a code span or fenced block is
 * not rendered and is reported at low severity.
 */
export function detectExfiltration(
  text: string,
  options: ExfiltrationOptions = {}
): OutputFinding[] {
  if (typeof text !== "string" || !ANY_URLISH.test(text)) {
    return [];
  }
  const scan: Scan = {
    text,
    allow: compileAllowlist(options.allowedDomains ?? []),
    blockAllImages: options.blockAllImages ?? true,
    flagLinks: options.flagLinks ?? "suspicious",
    code: codeRanges(text),
    consumed: [],
    hasDefinitions: text.includes("]:"),
    out: [],
  };
  const uses: ReferenceUse[] = [];
  if (text.includes("]")) {
    scanMarkdownInline(scan, uses);
  }
  if (scan.hasDefinitions) {
    scanReferenceDefinitions(scan, uses);
  }
  if (text.includes("<")) {
    scanHtml(scan);
  }
  const css =
    text.includes("rl(") || text.includes("RL(") || text.includes("@import");
  if (css) {
    scanCss(scan);
  }
  if (text.includes("://")) {
    scanBareUrls(scan);
  }
  return filterFindings(dedupe(scan.out), options);
}
