/**
 * What every provider wrapper shares: its options, injection checks on user
 * input and tool results, and the output guard that redacts prompt leaks,
 * credentials, exfiltration links, and canaries.
 */

import {
  type DetectOptions,
  type DetectResult,
  detect,
  detectAsync,
  slowDetection,
} from "../detect";
import {
  InjectionDetectedError,
  type InjectionSource,
  LeakDetectedError,
  OutputBlockedError,
} from "../errors";
import type { HardenOptions } from "../harden";
import {
  createCanary,
  DEFAULT_REDACTION_TEXT,
  findCanary,
  mergeRanges,
  type OutputFinding,
  type ScanOutputOptions,
  type Severity,
  scanOutputText,
} from "../output";
import {
  type SanitizeOptions,
  type SanitizeResult,
  sanitizeWithRedactions,
} from "../sanitize";
import {
  type ChunkResult,
  isAsyncIterable,
  STREAM_OVERLAP,
  type WindowScan,
} from "./utils";

export interface ShieldProviderOptions {
  /** System prompt for sanitization. When omitted, derived from the request's system prompt. */
  systemPrompt?: string;
  harden?: HardenOptions | false;
  /** Injection detection on user messages. `false` turns it off. */
  detect?: DetectOptions | false;
  /**
   * Injection detection on tool results and retrieved documents, the main
   * channel for indirect injection. Default on, with the `detect` options.
   * Pass options to use different ones, or `false` to turn it off;
   * `detect: false` does not turn it off.
   */
  scanToolResults?: boolean | DetectOptions;
  /**
   * Run `escalate` at the same time as the provider call instead of before
   * it. The response, with any tool calls in it, is held until the verdict
   * is in, and thrown away if it is an injection; the call is still made and
   * billed. The fast check still runs first and blocks before the call, and
   * a `secondaryDetector`, which only runs on text the fast check flagged,
   * still runs before the call. Default `false`.
   */
  parallelDetection?: boolean;
  sanitize?: SanitizeOptions | false;
  /** `"buffer"`: full buffer then sanitize. `"chunked"`: 8KB chunks, lower memory (the OpenAI Responses API treats it as `"buffer"`). `"passthrough"`: skip sanitization and output scanning. */
  streamingSanitize?: "buffer" | "chunked" | "passthrough";
  /** Chunk size for "chunked" mode (default 8192). */
  streamingChunkSize?: number;
  onDetection?: "block" | "warn";
  throwOnLeak?: boolean;
  /** Called on every detection, with where it was found. */
  onInjectionDetected?: (result: DetectResult, source: InjectionSource) => void;
  onLeakDetected?: (result: SanitizeResult) => void;
  /** Scan model output for credentials, exfiltration links, and optionally personal data and canaries, and redact what's found. `false` turns it off. Default: secrets and exfiltration on, PII off. */
  output?: false | ScanOutputOptions;
  /** Called with the findings whenever output scanning finds something. */
  onOutputFindings?: (findings: OutputFinding[]) => void;
  /** Throw OutputBlockedError instead of redacting when a finding is high or critical severity. */
  blockOnOutputFindings?: boolean;
  /** Plant a canary token in the hardened system prompt and treat its appearance in output as a leak. `true` creates one per wrapper instance. */
  canary?: string | boolean;
}

/** How much of a JSON tool result's string values is scanned, and the longest text cached. */
export const MAX_TOOL_TEXT = 64 * 1024;
const CACHE_ENTRIES = 256;
/** Output scanning holds back more text in chunked mode, for long findings. */
const OUTPUT_OVERLAP = 512;
const MAX_OBJECT_DEPTH = 64;

const SEVERITY_RANK: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * The strings in a JSON value, joined with newlines, up to 64KB. Keys are
 * left out, since the model reads them as structure rather than
 * instructions.
 */
export function jsonText(value: unknown, limit = MAX_TOOL_TEXT): string {
  const parts: string[] = [];
  let size = 0;
  const stack: unknown[] = [value];
  const seen = new Set<object>();
  while (stack.length > 0 && size < limit) {
    const item = stack.pop();
    if (typeof item === "string") {
      if (item) {
        const part = item.slice(0, limit - size);
        parts.push(part);
        size += part.length + 1;
      }
      continue;
    }
    if (item === null || typeof item !== "object" || seen.has(item)) {
      continue;
    }
    seen.add(item);
    const children = Array.isArray(item) ? item : Object.values(item);
    for (let i = children.length - 1; i >= 0; i--) {
      stack.push(children[i]);
    }
  }
  return parts.join("\n");
}

interface Lru<V> {
  get(key: string): V | undefined;
  set(key: string, value: V): void;
}

function createLru<V>(max: number): Lru<V> {
  const map = new Map<string, V>();
  return {
    get(key) {
      const value = map.get(key);
      if (value !== undefined) {
        map.delete(key);
        map.set(key, value);
      }
      return value;
    },
    set(key, value) {
      map.delete(key);
      map.set(key, value);
      if (map.size > max) {
        const oldest = map.keys().next();
        if (!oldest.done) {
          map.delete(oldest.value);
        }
      }
    },
  };
}

export interface InputGuard {
  /** Whether user messages are checked. */
  readonly user: boolean;
  /** Whether tool results are checked. */
  readonly tool: boolean;
  /** Reports an injection in `text`, and throws unless `onDetection` is "warn". Runs `secondaryDetector` and `escalate`. */
  check(text: string, source: InjectionSource): Promise<void>;
  /** Same, without `secondaryDetector` and `escalate`. */
  checkSync(text: string, source: InjectionSource): void;
  /**
   * Like `check`, but returns the result instead of throwing, whatever
   * `onDetection` is. An injection is still reported to
   * `onInjectionDetected`. `undefined` when `text` is empty or detection is
   * off for `source`.
   */
  inspect(
    text: string,
    source: InjectionSource
  ): Promise<DetectResult | undefined>;
  /** The checks of one request. Never share a scope between requests. */
  begin(): InputScope;
}

/**
 * The checks of one request. Without `parallelDetection`, `check` is
 * `InputGuard.check` and `settle` does nothing. With it, `check` reports
 * what the fast check finds right away, as `InputGuard.check` would, and
 * starts `escalate` without waiting for it; `settle` waits for every
 * verdict it started, in order, and reports them the same way.
 */
export interface InputScope {
  /** Whether tool results are checked. */
  readonly tool: boolean;
  /** Whether a verdict `check` started has not settled cleanly yet. */
  readonly pending: boolean;
  check(text: string, source: InjectionSource): Promise<void>;
  /**
   * Waits for the verdicts `check` started and reports them: throws
   * `InjectionDetectedError` unless `onDetection` is "warn", or the error a
   * detector threw. Calling it again returns the same result.
   */
  settle(): Promise<void>;
}

const noop = (): void => undefined;

/** Whether `detectAsync` can give a different result than `detect`. */
function hasAsyncDetector(options: DetectOptions): boolean {
  return Boolean(options.secondaryDetector || options.escalate);
}

function toolDetectOptions(
  options: ShieldProviderOptions
): DetectOptions | null {
  const { scanToolResults } = options;
  if (scanToolResults === false) {
    return null;
  }
  if (typeof scanToolResults === "object") {
    return scanToolResults;
  }
  return options.detect || {};
}

/**
 * Detection is deterministic for fixed options, and agent loops resend the
 * whole history every turn, so results for texts up to 64KB are cached.
 * Results a `secondaryDetector` or `escalate` detector could change are not.
 */
function createInputGuard(options: ShieldProviderOptions): InputGuard {
  const byUser = options.detect === false ? null : options.detect || {};
  const byTool = toolDetectOptions(options);
  const cache = createLru<DetectResult>(CACHE_ENTRIES);
  const optionsFor = (source: InjectionSource) =>
    source === "user" ? byUser : byTool;
  const cacheKey = (
    text: string,
    source: InjectionSource,
    detectOptions: DetectOptions
  ): string | undefined =>
    hasAsyncDetector(detectOptions) || text.length > MAX_TOOL_TEXT
      ? undefined
      : `${source}:${text}`;

  const report = (result: DetectResult, source: InjectionSource): void => {
    if (!result.detected) {
      return;
    }
    options.onInjectionDetected?.(result, source);
    if ((options.onDetection ?? "block") === "block") {
      throw new InjectionDetectedError(
        result.risk,
        result.matches.map((m) => m.category),
        source
      );
    }
  };

  const detectSync = (
    text: string,
    source: InjectionSource,
    detectOptions: DetectOptions
  ): DetectResult => {
    const key = cacheKey(text, source, detectOptions);
    let result = key === undefined ? undefined : cache.get(key);
    if (!result) {
      result = detect(text, detectOptions);
      if (key !== undefined) {
        cache.set(key, result);
      }
    }
    return result;
  };

  const run = async (
    text: string,
    source: InjectionSource
  ): Promise<DetectResult | undefined> => {
    const detectOptions = optionsFor(source);
    if (!(detectOptions && text)) {
      return;
    }
    return hasAsyncDetector(detectOptions)
      ? await detectAsync(text, detectOptions)
      : detectSync(text, source, detectOptions);
  };

  const user = byUser !== null;
  const tool = byTool !== null;
  const check = async (text: string, source: InjectionSource) => {
    const result = await run(text, source);
    if (result) {
      report(result, source);
    }
  };
  const serial: InputScope = {
    tool,
    pending: false,
    check,
    settle: () => Promise.resolve(),
  };

  const parallelScope = (): InputScope => {
    const started: Array<{
      verdict: Promise<DetectResult>;
      source: InjectionSource;
    }> = [];
    let settling: Promise<void> | undefined;
    let pending = false;

    const reportAll = async (batch: typeof started): Promise<void> => {
      for (const { verdict, source } of batch) {
        report(await verdict, source);
      }
    };

    return {
      tool,
      get pending() {
        return pending;
      },
      async check(text, source) {
        const detectOptions = optionsFor(source);
        if (!(detectOptions && text)) {
          return;
        }
        if (!hasAsyncDetector(detectOptions)) {
          report(detectSync(text, source, detectOptions), source);
          return;
        }
        const result = detect(text, detectOptions);
        const slow = slowDetection(text, result, detectOptions);
        if (!slow) {
          report(result, source);
          return;
        }
        if (result.detected) {
          // Text the fast check flagged waits for the secondaryDetector, so
          // it never reaches the provider unless the verifier clears it.
          report(await slow, source);
          return;
        }
        // Left unawaited if a later check throws first.
        slow.catch(noop);
        started.push({ verdict: slow, source });
        pending = true;
      },
      settle() {
        if (started.length > 0) {
          const batch = started.splice(0);
          const next = (settling ?? Promise.resolve()).then(() =>
            reportAll(batch)
          );
          settling = next;
          next.then(() => {
            if (settling === next && started.length === 0) {
              pending = false;
            }
          }, noop);
        }
        return settling ?? Promise.resolve();
      },
    };
  };

  return {
    user,
    tool,
    check,
    checkSync(text, source) {
      const detectOptions = optionsFor(source);
      if (detectOptions && text) {
        report(detectSync(text, source, detectOptions), source);
      }
    },
    async inspect(text, source) {
      const result = await run(text, source);
      if (result?.detected) {
        options.onInjectionDetected?.(result, source);
      }
      return result;
    },
    begin: options.parallelDetection ? parallelScope : () => serial,
  };
}

/** Closes `iterator` without waiting for it. */
function close(iterator: AsyncIterator<unknown>): void {
  iterator.return?.().then(noop, noop);
}

/**
 * Stops a stream nobody will read, as far as the SDK allows: aborts the
 * request of an OpenAI or Anthropic stream, cancels a `ReadableStream`
 * (Mistral), and closes an iterator (Google, which gives no way to abort
 * the request other than the caller's own `abortSignal`).
 */
function discard(value: unknown, iterator?: AsyncIterator<unknown>): void {
  if (typeof value !== "object" || value === null) {
    return;
  }
  const { controller } = value as { controller?: { abort?: unknown } };
  const abort = controller?.abort;
  const aborted = typeof abort === "function";
  if (aborted) {
    abort.call(controller);
  }
  if (iterator) {
    close(iterator);
  } else if (
    typeof ReadableStream !== "undefined" &&
    value instanceof ReadableStream
  ) {
    if (!value.locked) {
      value.cancel().then(noop, noop);
    }
  } else if (!aborted && isAsyncIterable(value)) {
    close(value[Symbol.asyncIterator]());
  }
}

/**
 * Calls the provider. If the call fails, the verdicts `scope` started are
 * waited for first and their error wins, as it would have with the checks
 * run before the call.
 */
export async function callProvider<T>(
  scope: InputScope,
  call: () => T | PromiseLike<T>
): Promise<T> {
  try {
    return await call();
  } catch (error) {
    await scope.settle();
    throw error;
  }
}

/**
 * Returns `value` once every verdict `scope` started is in. If they block,
 * `value` is thrown away, a stream is stopped, and the error is thrown.
 */
export async function whenSettled<T>(scope: InputScope, value: T): Promise<T> {
  try {
    await scope.settle();
  } catch (error) {
    discard(value);
    throw error;
  }
  return value;
}

/**
 * A stream that yields `stream`'s items as they come and ends once every
 * verdict `scope` started is in, for buffer mode: the stream is read while
 * they come in, and nothing reaches the caller before they are. A blocking
 * verdict stops the stream and is thrown right away; an error from the
 * stream waits for the verdicts, whose error wins. Returns `stream` itself
 * when nothing is pending.
 */
export function endWhenSettled<T>(
  scope: InputScope,
  stream: AsyncIterable<T>
): AsyncIterable<T> {
  return scope.pending ? readUntilSettled(scope, stream) : stream;
}

async function* readUntilSettled<T>(
  scope: InputScope,
  stream: AsyncIterable<T>
): AsyncGenerator<T> {
  const settled = scope.settle();
  // Rejects when a verdict blocks, and never resolves.
  const blocked = settled.then(() => new Promise<never>(noop));
  blocked.catch(noop);
  const iterator = stream[Symbol.asyncIterator]();
  let done = false;
  try {
    while (!done) {
      const step = await Promise.race([iterator.next(), blocked]);
      done = step.done === true;
      if (!done) {
        yield step.value;
      }
    }
  } catch (error) {
    await settled;
    throw error;
  } finally {
    if (!done) {
      discard(stream, iterator);
    }
  }
  await settled;
}

/**
 * `stream` once every verdict `scope` started is in, for streams that only
 * send their request when first read. Its first item is read right away, so
 * the request runs alongside the verdicts. A blocking verdict closes the
 * stream and is thrown.
 */
export async function prefetchWhenSettled<T>(
  scope: InputScope,
  stream: AsyncIterable<T>
): Promise<AsyncGenerator<T>> {
  const iterator = stream[Symbol.asyncIterator]();
  const first = iterator.next();
  first.then(noop, noop);
  try {
    await scope.settle();
  } catch (error) {
    discard(stream, iterator);
    throw error;
  }
  return (async function* () {
    let done = false;
    try {
      let step = await first;
      while (!step.done) {
        yield step.value;
        step = await iterator.next();
      }
      done = true;
    } finally {
      if (!done) {
        discard(stream, iterator);
      }
    }
  })();
}

/** What one scan found, before any error is thrown. */
export interface Verdict {
  /** The prompt leak or canary to throw with `throwOnLeak`. */
  leak?: LeakDetectedError;
  /** The error to throw with `blockOnOutputFindings`. */
  block?: OutputBlockedError;
}

export interface OutputGuard {
  /** Whether output needs scanning for a request with this system prompt. */
  active(systemPrompt: string | undefined): boolean;
  /** Scans one string, reports what it found, and returns it redacted. Throws per `throwOnLeak` and `blockOnOutputFindings`. */
  text(text: string, systemPrompt: string | undefined): string;
  /** `text()` for every string in a JSON-like value, reported once. Returns `value` itself when nothing changed. */
  value<T>(value: T, systemPrompt: string | undefined): T;
  /**
   * Scans a string, or every string in a JSON-like value, and reports what
   * it found like `text()` and `value()`, but returns the errors instead of
   * throwing them. `leak` is set for any prompt leak or canary, whatever
   * `throwOnLeak` is; `block` only with `blockOnOutputFindings`.
   */
  inspect(value: unknown, systemPrompt: string | undefined): Verdict;
  /** The scan the chunked sanitizer runs on each window. */
  scanWindow(text: string, systemPrompt: string): WindowScan;
  /** How many characters chunked mode scans each chunk with on either side. */
  overlap(chunkSize: number): number;
  /** Reports one chunked result without throwing. */
  report(result: ChunkResult): Verdict;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function canaryList(value: ScanOutputOptions["canary"]): string[] {
  if (value === undefined) {
    return [];
  }
  return typeof value === "string" ? [value] : [...value];
}

function outputOptionsFor(
  options: ShieldProviderOptions,
  canaries: string[]
): ScanOutputOptions | null {
  if (options.output === false) {
    return canaries.length > 0
      ? { secrets: false, pii: false, exfiltration: false, canary: canaries }
      : null;
  }
  const base = options.output ?? {};
  const all = [...new Set([...canaryList(base.canary), ...canaries])];
  return all.length > 0 ? { ...base, canary: all } : base;
}

function isBlocking(finding: OutputFinding): boolean {
  return SEVERITY_RANK[finding.severity] >= SEVERITY_RANK.high;
}

function applyRedactions(text: string, scan: WindowScan): string {
  if (scan.redactions.length === 0) {
    return text;
  }
  let out = "";
  let pos = 0;
  for (const [i, [start, end]] of scan.redactions.entries()) {
    out +=
      text.slice(pos, start) + (scan.replacements?.[i] ?? scan.redactionText);
    pos = end;
  }
  return out + text.slice(pos);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Object.prototype.toString.call(value) === "[object Object]";
}

/**
 * An object with `entries` as its own properties, in order. Keys that were
 * rewritten get a numeric suffix if they would collide with another key.
 */
function objectFrom(
  entries: Array<{ key: string; rewritten: boolean; value: unknown }>
): Record<string, unknown> {
  const taken = new Set(entries.filter((e) => !e.rewritten).map((e) => e.key));
  const out: Record<string, unknown> = {};
  for (const entry of entries) {
    let key = entry.key;
    if (entry.rewritten) {
      for (let n = 2; taken.has(key); n++) {
        key = `${entry.key}_${n}`;
      }
      taken.add(key);
    }
    // Plain assignment would set the prototype for a "__proto__" key.
    Object.defineProperty(out, key, {
      value: entry.value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * `value` with `fn` applied to every string in its plain objects and arrays,
 * keys included, copied only where something changed.
 */
function mapStrings(
  value: unknown,
  fn: (text: string) => string,
  depth = 0
): unknown {
  if (typeof value === "string") {
    return fn(value);
  }
  if (depth >= MAX_OBJECT_DEPTH) {
    return value;
  }
  if (Array.isArray(value)) {
    let copy: unknown[] | undefined;
    for (const [i, item] of value.entries()) {
      const next = mapStrings(item, fn, depth + 1);
      if (next !== item) {
        copy ??= [...value];
        copy[i] = next;
      }
    }
    return copy ?? value;
  }
  if (!isPlainObject(value)) {
    return value;
  }
  let changed = false;
  const entries = Object.keys(value).map((key) => {
    const child = value[key];
    const next = mapStrings(child, fn, depth + 1);
    const safeKey = fn(key);
    changed ||= next !== child || safeKey !== key;
    return { key: safeKey, rewritten: safeKey !== key, value: next };
  });
  return changed ? objectFrom(entries) : value;
}

function createOutputGuard(
  options: ShieldProviderOptions,
  canaries: string[]
): OutputGuard {
  const sanitizeOptions =
    options.sanitize === false ? null : options.sanitize || {};
  const outputOptions = outputOptionsFor(options, canaries);
  const promptRedaction = sanitizeOptions?.redactionText || "[REDACTED]";
  const outputRedaction =
    outputOptions?.redactionText ??
    sanitizeOptions?.redactionText ??
    DEFAULT_REDACTION_TEXT;
  const promptRanges = new WeakSet<OutputFinding>();

  const replacementFor = (merged: readonly OutputFinding[]): string => {
    const first = merged.find((f) => !promptRanges.has(f));
    if (!first) {
      return promptRedaction;
    }
    return typeof outputRedaction === "function"
      ? outputRedaction(first, merged)
      : outputRedaction;
  };

  const scanWindow = (text: string, systemPrompt: string): WindowScan => {
    const leak: WindowScan = sanitizeWithRedactions(
      text,
      sanitizeOptions ? systemPrompt : "",
      sanitizeOptions ?? {}
    );
    if (!outputOptions) {
      return leak;
    }
    const { findings } = scanOutputText(text, outputOptions);
    if (findings.length === 0) {
      return leak;
    }
    const floor = SEVERITY_RANK[outputOptions.redactMinSeverity ?? "low"];
    const ranges: OutputFinding[] = leak.redactions.map(([start, end]) => {
      const range: OutputFinding = {
        type: "prompt_leak",
        kind: "system_prompt",
        start,
        end,
        severity: "high",
        confidence: leak.confidence,
        preview: "",
      };
      promptRanges.add(range);
      return range;
    });
    ranges.push(...findings.filter((f) => SEVERITY_RANK[f.severity] >= floor));
    const merged = mergeRanges(ranges, text.length);
    return {
      ...leak,
      redactions: merged.map((r): [number, number] => [r.start, r.end]),
      replacements: merged.map((r) => replacementFor(r.findings)),
      findings,
    };
  };

  const notify = (
    leak: SanitizeResult | undefined,
    findings: OutputFinding[],
    sanitized: string
  ): Verdict => {
    const verdict: Verdict = {};
    if (leak?.leaked) {
      options.onLeakDetected?.(leak);
      verdict.leak = new LeakDetectedError(
        leak.confidence,
        leak.fragments.length
      );
    }
    if (findings.length === 0) {
      return verdict;
    }
    options.onOutputFindings?.(findings);
    const canaryFindings = findings.filter((f) => f.type === "canary");
    if (canaryFindings.length > 0) {
      const confidence = Math.max(...canaryFindings.map((f) => f.confidence));
      options.onLeakDetected?.({
        leaked: true,
        confidence,
        fragments: canaryFindings.map((f) => f.preview),
        sanitized,
      });
      verdict.leak ??= new LeakDetectedError(confidence, canaryFindings.length);
    }
    if (options.blockOnOutputFindings && findings.some(isBlocking)) {
      verdict.block = new OutputBlockedError(findings);
    }
    return verdict;
  };

  const enforce = (verdict: Verdict): void => {
    if (verdict.leak && options.throwOnLeak) {
      throw verdict.leak;
    }
    if (verdict.block) {
      throw verdict.block;
    }
  };

  const leakOf = (scan: WindowScan): SanitizeResult | undefined =>
    scan.leaked
      ? {
          leaked: true,
          confidence: scan.confidence,
          fragments: scan.fragments,
          sanitized: scan.sanitized,
        }
      : undefined;

  const scanText = (
    text: string,
    systemPrompt: string | undefined
  ): { result: string; verdict: Verdict } => {
    const scan = scanWindow(text, systemPrompt ?? "");
    const sanitized = applyRedactions(text, scan);
    const verdict = notify(leakOf(scan), scan.findings ?? [], sanitized);
    return { result: sanitized, verdict };
  };

  const scanValue = <T>(
    value: T,
    systemPrompt: string | undefined
  ): { result: T; verdict: Verdict } => {
    const scans: WindowScan[] = [];
    const result = mapStrings(value, (text) => {
      const scan = scanWindow(text, systemPrompt ?? "");
      scans.push(scan);
      return applyRedactions(text, scan);
    }) as T;
    const leaks = scans.filter((scan) => scan.leaked);
    const findings = scans.flatMap((scan) => scan.findings ?? []);
    if (leaks.length === 0 && findings.length === 0) {
      return { result, verdict: {} };
    }
    const sanitized = JSON.stringify(result);
    const leak =
      leaks.length > 0
        ? {
            leaked: true,
            confidence: Math.max(...leaks.map((scan) => scan.confidence)),
            fragments: leaks.flatMap((scan) => scan.fragments),
            sanitized,
          }
        : undefined;
    return { result, verdict: notify(leak, findings, sanitized) };
  };

  return {
    active: (systemPrompt) =>
      outputOptions !== null || (sanitizeOptions !== null && !!systemPrompt),
    text(text, systemPrompt) {
      const { result, verdict } = scanText(text, systemPrompt);
      enforce(verdict);
      return result;
    },
    value(value, systemPrompt) {
      const { result, verdict } = scanValue(value, systemPrompt);
      enforce(verdict);
      return result;
    },
    inspect: (value, systemPrompt) =>
      typeof value === "string"
        ? scanText(value, systemPrompt).verdict
        : scanValue(value, systemPrompt).verdict,
    scanWindow,
    overlap: (chunkSize) =>
      outputOptions
        ? Math.min(OUTPUT_OVERLAP, Math.max(STREAM_OVERLAP, chunkSize))
        : STREAM_OVERLAP,
    report: (result) =>
      notify(
        result.leaked
          ? {
              leaked: true,
              confidence: result.confidence,
              fragments: result.fragments,
              sanitized: result.sanitized,
            }
          : undefined,
        result.findings,
        result.sanitized
      ),
  };
}

export interface Shield {
  input: InputGuard;
  output: OutputGuard;
  /** Options for `harden`, with the canary, or `false`. */
  harden: HardenOptions | false;
}

/**
 * Throws now what `findCanary` would throw on every scan: a `TypeError` for a
 * canary that isn't one token of letters, digits, hyphens, or underscores,
 * and a `RangeError` for one too short to find reliably.
 */
function validateCanary(canary: unknown, option: string): string {
  if (typeof canary !== "string") {
    throw new TypeError(`${option} must be a string`);
  }
  try {
    findCanary("", canary);
  } catch (error) {
    if (error instanceof RangeError) {
      throw new RangeError(`${option}: ${error.message}`);
    }
    if (error instanceof TypeError) {
      throw new TypeError(`${option}: ${error.message}`);
    }
    throw error;
  }
  return canary;
}

/** Resolves a wrapper's options once, when the wrapper is created. */
export function createShield(options: ShieldProviderOptions): Shield {
  const hardenOptions = options.harden === false ? false : options.harden || {};
  let canary: string | undefined;
  if (options.canary === true) {
    canary = createCanary();
  } else if (typeof options.canary === "string") {
    canary = validateCanary(options.canary, "canary");
  }
  const planted =
    hardenOptions && hardenOptions.canary !== undefined
      ? validateCanary(hardenOptions.canary, "harden.canary")
      : undefined;
  if (options.output) {
    for (const extra of canaryList(options.output.canary)) {
      validateCanary(extra, "output.canary");
    }
  }
  const canaries = [...new Set([canary, planted].filter(isNonEmptyString))];
  return {
    input: createInputGuard(options),
    output: createOutputGuard(options, canaries),
    harden:
      hardenOptions && canary ? { ...hardenOptions, canary } : hardenOptions,
  };
}
