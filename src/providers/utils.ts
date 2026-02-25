/**
 * Shared utilities for provider wrappers.
 * Handles OpenAI/Groq-compatible message content (string | ContentPart[]).
 */

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

export interface SanitizeChunkResult {
  sanitized: string;
  leaked: boolean;
}

/** Extract text from OpenAI-style stream chunk. */
export function extractOpenAIChunkText(chunk: {
  choices?: Array<{ delta?: { content?: string } }>;
}): string {
  const content = chunk?.choices?.[0]?.delta?.content;
  return typeof content === "string" ? content : "";
}

/**
 * Sanitize a text stream in chunks to limit memory. Buffers `chunkSize` bytes
 * at a time, overlaps with previous chunk for n-gram continuity.
 */
export async function* sanitizeTextStreamChunked(
  textStream: AsyncIterable<string>,
  systemPrompt: string,
  sanitizeFn: (
    output: string,
    prompt: string
  ) => SanitizeChunkResult,
  chunkSize = 8192
): AsyncGenerator<SanitizeChunkResult, void, unknown> {
  let buffer = "";
  let prevOverlap = "";

  for await (const chunk of textStream) {
    buffer += chunk;

    while (buffer.length >= chunkSize) {
      const toProcess = prevOverlap + buffer.slice(0, chunkSize);
      buffer = buffer.slice(chunkSize);
      prevOverlap = toProcess.slice(-STREAM_OVERLAP);

      yield sanitizeFn(toProcess, systemPrompt);
    }
  }

  if (buffer.length > 0) {
    const toProcess = prevOverlap + buffer;
    yield sanitizeFn(toProcess, systemPrompt);
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
  stream: AsyncIterable<{ type?: string; delta?: { type?: string; text?: string } }>
): AsyncGenerator<string, void, unknown> {
  for await (const event of stream) {
    if (event?.type === "content_block_delta" && event.delta?.text) {
      yield event.delta.text;
    }
  }
}
