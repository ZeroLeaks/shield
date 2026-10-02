/**
 * Shared utilities for provider wrappers.
 * Handles OpenAI/Groq-compatible message content (string | ContentPart[]).
 */

import type { OutputFinding } from "../output";
import type { RedactedSanitizeResult, SanitizeResult } from "../sanitize";

interface ContentPart {
  type: string;
  text?: string;
}

/** Extract text from message content (string or array of text/image parts). */
export function extractOpenAIContentText(
  content: string | ContentPart[] | null | undefined
): string {
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return "";
  }
  return content
    .filter(
      (p): p is ContentPart & { text: string } =>
        p.type === "text" && typeof p.text === "string"
    )
    .map((p) => p.text)
    .join(" ");
}

/** Yield sanitized string in chunks to preserve streaming UX. */
const STREAM_CHUNK_SIZE = 64;

export function* chunkString(
  str: string,
  size = STREAM_CHUNK_SIZE
): Generator<string> {
  for (let i = 0; i < str.length; i += size) {
    yield str.slice(i, i + size);
  }
}

/** Default number of characters each chunk is scanned with on either side. */
export const STREAM_OVERLAP = 64;

/**
 * Longest redaction held back at the end of a chunk to be scanned again with
 * the next one. Covers a private key block, the longest finding there is.
 */
const MAX_HELD_REDACTION = 32 * 1024;

export function isAsyncIterable<T>(value: unknown): value is AsyncIterable<T> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as AsyncIterable<T>)[Symbol.asyncIterator] === "function"
  );
}

/** The scan of one window of streamed text. */
export interface WindowScan extends RedactedSanitizeResult {
  /** Replacement text for each redaction, by index. `redactionText` when missing. */
  replacements?: string[];
  /** Output findings, with offsets into the window. */
  findings?: OutputFinding[];
}

/**
 * `sanitized` is the text to emit. The other fields describe the scan of the
 * window that text came from, except `findings`, which only holds the output
 * findings that start in the emitted text, with offsets into the whole text
 * pushed so far.
 */
export interface ChunkResult extends SanitizeResult {
  findings: OutputFinding[];
}

export interface ChunkedSanitizer {
  /** Add text and return the sanitized text that is now safe to emit. */
  push(text: string): ChunkResult[];
  /** Sanitize and return whatever is still held back. */
  flush(): ChunkResult | undefined;
}

function shiftFindings(
  findings: OutputFinding[],
  offset: number
): OutputFinding[] {
  return findings.map((f) => ({
    ...f,
    start: f.start + offset,
    end: f.end + offset,
  }));
}

/**
 * Sanitizes text `chunkSize` characters at a time and emits every character
 * exactly once. Each window is scanned together with the last `overlap`
 * characters emitted before it, redacted or not, and the last `overlap`
 * characters after its final redaction are held back and scanned again with
 * the next window. A leak that straddles a boundary is caught from either
 * side. A redaction that runs to the end of a window may go on past it (a
 * private key cut in half), so it is held back too, up to 32KB, and scanned
 * again whole. Pass `Infinity` to sanitize everything on `flush()`.
 */
export function createChunkedSanitizer(
  systemPrompt: string,
  sanitizeFn: (output: string, prompt: string) => WindowScan,
  chunkSize: number,
  overlap = STREAM_OVERLAP
): ChunkedSanitizer {
  const size = Math.max(1, chunkSize);
  const keep = Math.max(1, overlap);
  let context = "";
  let held = "";
  let buffer = "";
  let endsRedacted = false;
  /** Offset of `context` in the text pushed so far. */
  let offset = 0;
  /** Whether `held` was scanned and nothing in it needs redacting. */
  let heldClean = true;
  /** Findings that start in `held`, reported if it is emitted unscanned. */
  let heldFindings: OutputFinding[] = [];

  const cutPoint = (
    window: string,
    start: number,
    redactions: [number, number][]
  ): { cut: number; holding: boolean } => {
    // Redactions are sorted and disjoint, so the last one ends last.
    const count = redactions.length;
    const last = count > 0 ? redactions[count - 1] : undefined;
    const holding =
      last !== undefined &&
      last[1] >= window.length &&
      last[0] >= start &&
      window.length - last[0] <= MAX_HELD_REDACTION;
    if (!holding) {
      return {
        cut: Math.max(start, last ? last[1] : 0, window.length - keep),
        holding: false,
      };
    }
    const before = count > 1 ? redactions[count - 2][1] : 0;
    return {
      cut: Math.max(start, before, Math.min(last[0], window.length - keep)),
      holding: true,
    };
  };

  const scan = (pending: string, final: boolean): ChunkResult => {
    const window = context + pending;
    const start = context.length;
    const scanned = sanitizeFn(window, systemPrompt);
    const { leaked, confidence, fragments, redactions, redactionText } =
      scanned;
    const { cut, holding } = final
      ? { cut: window.length, holding: false }
      : cutPoint(window, start, redactions);

    let sanitized = "";
    let pos = start;
    let emittedEnd = 0;
    for (const [i, [from, to]] of redactions.entries()) {
      if (from >= cut) {
        break;
      }
      emittedEnd = to;
      if (to <= start) {
        continue;
      }
      sanitized += window.slice(pos, from);
      // A redaction that began in the context continues the one already
      // emitted, if the emitted text ended in one.
      if (from >= start || !endsRedacted) {
        sanitized += scanned.replacements?.[i] ?? redactionText;
      }
      pos = to;
    }
    sanitized += window.slice(pos, cut);

    const findings = scanned.findings ?? [];
    const emitted = findings.filter((f) => f.start >= start && f.start < cut);
    const windowOffset = offset;
    heldFindings = shiftFindings(
      findings.filter((f) => f.start >= cut),
      windowOffset
    );
    heldClean = !holding;

    if (cut > start) {
      endsRedacted = emittedEnd === cut;
    }
    const contextStart = Math.max(0, cut - keep);
    context = window.slice(contextStart, cut);
    offset += contextStart;
    held = window.slice(cut);
    return {
      leaked,
      confidence,
      fragments,
      sanitized,
      findings: shiftFindings(emitted, windowOffset),
    };
  };

  return {
    push(text) {
      buffer += text;
      const results: ChunkResult[] = [];
      while (buffer.length >= size) {
        const chunk = buffer.slice(0, size);
        buffer = buffer.slice(size);
        results.push(scan(held + chunk, false));
      }
      return results;
    },
    flush() {
      if (!buffer && heldClean) {
        // The held tail was already scanned with the window it came from,
        // and nothing in it was redacted.
        const rest = held;
        const findings = heldFindings;
        held = "";
        heldFindings = [];
        return rest
          ? {
              leaked: false,
              confidence: 0,
              fragments: [],
              sanitized: rest,
              findings,
            }
          : undefined;
      }
      const pending = held + buffer;
      buffer = "";
      return pending ? scan(pending, true) : undefined;
    },
  };
}
