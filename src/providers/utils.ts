/**
 * Shared utilities for provider wrappers.
 * Handles OpenAI/Groq-compatible message content (string | ContentPart[]).
 */

import type { RedactedSanitizeResult, SanitizeResult } from "../sanitize";

type ContentPart = { type: string; text?: string };

/** Extract text from message content (string or array of text/image parts). */
export function extractOpenAIContentText(
  content: string | ContentPart[] | null | undefined
): string {
  if (content == null) return "";
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
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

const STREAM_OVERLAP = 64;

/** Extract text from OpenAI-style stream chunk. */
export function extractOpenAIChunkText(chunk: {
  choices?: Array<{ delta?: { content?: string } }>;
}): string {
  const content = chunk?.choices?.[0]?.delta?.content;
  return typeof content === "string" ? content : "";
}

/**
 * Each result's `sanitized` is the text to emit, and its other fields
 * describe the scan of the window that text came from.
 */
export interface ChunkedSanitizer {
  /** Add text and return the sanitized text that is now safe to emit. */
  push(text: string): SanitizeResult[];
  /** Sanitize and return whatever is still held back. */
  flush(): SanitizeResult | undefined;
}

/**
 * Sanitizes text `chunkSize` characters at a time and emits every character
 * exactly once. Each window is scanned together with the last
 * `STREAM_OVERLAP` characters emitted before it, redacted or not, and the
 * last `STREAM_OVERLAP` characters after its final redaction are held back
 * and scanned again with the next window. A leak that straddles a boundary
 * is caught from either side. Pass `Infinity` to sanitize everything on
 * `flush()`.
 */
export function createChunkedSanitizer(
  systemPrompt: string,
  sanitizeFn: (output: string, prompt: string) => RedactedSanitizeResult,
  chunkSize: number
): ChunkedSanitizer {
  const size = Math.max(1, chunkSize);
  let context = "";
  let held = "";
  let buffer = "";
  let endsRedacted = false;

  const scan = (pending: string, final: boolean): SanitizeResult => {
    const window = context + pending;
    const start = context.length;
    const { leaked, confidence, fragments, redactions, redactionText } =
      sanitizeFn(window, systemPrompt);
    const lastEnd = Math.max(0, ...redactions.map(([, end]) => end));
    const cut = final
      ? window.length
      : Math.max(start, lastEnd, window.length - STREAM_OVERLAP);

    let sanitized = "";
    let pos = start;
    for (const [from, to] of redactions) {
      if (to <= start) {
        continue;
      }
      sanitized += window.slice(pos, from);
      // A redaction that began in the context continues the one already
      // emitted, if the emitted text ended in one.
      if (from >= start || !endsRedacted) {
        sanitized += redactionText;
      }
      pos = to;
    }
    sanitized += window.slice(pos, cut);

    if (cut > start) {
      endsRedacted = lastEnd === cut;
    }
    context = window.slice(Math.max(0, cut - STREAM_OVERLAP), cut);
    held = window.slice(cut);
    return { leaked, confidence, fragments, sanitized };
  };

  return {
    push(text) {
      buffer += text;
      const results: SanitizeResult[] = [];
      while (buffer.length >= size) {
        const chunk = buffer.slice(0, size);
        buffer = buffer.slice(size);
        results.push(scan(held + chunk, false));
      }
      return results;
    },
    flush() {
      if (!buffer) {
        // The held tail was already scanned with the window it came from,
        // and nothing in it was redacted.
        const rest = held;
        held = "";
        return rest
          ? { leaked: false, confidence: 0, fragments: [], sanitized: rest }
          : undefined;
      }
      const pending = held + buffer;
      buffer = "";
      return scan(pending, true);
    },
  };
}

/** Sanitize a text stream in chunks to limit memory. */
export async function* sanitizeTextStreamChunked(
  textStream: AsyncIterable<string>,
  systemPrompt: string,
  sanitizeFn: (output: string, prompt: string) => RedactedSanitizeResult,
  chunkSize = 8192
): AsyncGenerator<SanitizeResult, void, unknown> {
  const sanitizer = createChunkedSanitizer(systemPrompt, sanitizeFn, chunkSize);
  for await (const chunk of textStream) {
    yield* sanitizer.push(chunk);
  }
  const last = sanitizer.flush();
  if (last) {
    yield last;
  }
}

/** Adapt OpenAI/Groq stream to text stream for chunked sanitization. */
export async function* openAIStreamToText(
  stream: AsyncIterable<{ choices?: Array<{ delta?: { content?: string } }> }>
): AsyncGenerator<string, void, unknown> {
  for await (const chunk of stream) {
    const t = extractOpenAIChunkText(chunk);
    if (t) yield t;
  }
}

/** Adapt Anthropic stream to text stream for chunked sanitization. */
export async function* anthropicStreamToText(
  stream: AsyncIterable<{
    type?: string;
    delta?: { type?: string; text?: string };
  }>
): AsyncGenerator<string, void, unknown> {
  for await (const event of stream) {
    if (event?.type === "content_block_delta" && event.delta?.text) {
      yield event.delta.text;
    }
  }
}
