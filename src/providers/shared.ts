/**
 * Helpers the Google, Mistral, and LangChain wrappers share: hardening a
 * list of content parts, and guarding text that a stream spreads over many
 * chunks.
 */

import type { LeakDetectedError } from "../errors";
import { type HardenOptions, harden } from "../harden";
import {
  MAX_TOOL_TEXT,
  type OutputGuard,
  type ShieldProviderOptions,
} from "./guard";
import {
  type ChunkedSanitizer,
  type ChunkResult,
  createChunkedSanitizer,
} from "./utils";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const TEXT_MIME = /^(text\/|application\/(json|xml)\b)/i;

/**
 * The text of base64 `data` with a `text/*`, `application/json`, or
 * `application/xml` MIME type, up to 64KB. Empty for any other data.
 */
export function decodeTextBlob(data: unknown, mimeType: unknown): string {
  if (
    !(
      typeof data === "string" &&
      typeof mimeType === "string" &&
      TEXT_MIME.test(mimeType)
    )
  ) {
    return "";
  }
  const size = Math.ceil(MAX_TOOL_TEXT / 3) * 4;
  let binary: string;
  try {
    binary = atob(data.slice(0, size));
  } catch {
    // Not base64: the provider rejects it anyway.
    return "";
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/**
 * `items` with their text joined into the first item that has text, and
 * hardened. The other text items are dropped; every other item stays where
 * it was. Returns `items` itself when none has text.
 */
export function hardenTextItems<T>(
  items: readonly T[],
  textOf: (item: T) => string,
  withText: (item: T, text: string) => T,
  options: HardenOptions
): T[] {
  const text = items.map(textOf).filter(Boolean).join("\n");
  if (!text) {
    return [...items];
  }
  const hardened = harden(text, options);
  const out: T[] = [];
  let placed = false;
  for (const item of items) {
    if (!textOf(item)) {
      out.push(item);
    } else if (!placed) {
      out.push(withText(item, hardened));
      placed = true;
    }
  }
  return out;
}

/**
 * One place in one chunk that holds a piece of a streamed text, such as a
 * candidate's answer or a tool call's arguments.
 */
export interface TextSlot {
  /** The text the piece belongs to. */
  key: string;
  /** The piece. */
  text: string;
  set(text: string): void;
}

/**
 * Guards each key's text whole and writes the result back over the same
 * slots: each slot takes as many characters as it held, and the last one
 * takes the rest. Returns the keys whose text changed.
 */
export function rewriteSlots(
  slots: readonly TextSlot[],
  guard: (text: string) => string
): Set<string> {
  const groups = new Map<string, TextSlot[]>();
  for (const slot of slots) {
    const group = groups.get(slot.key);
    if (group) {
      group.push(slot);
    } else {
      groups.set(slot.key, [slot]);
    }
  }
  const changed = new Set<string>();
  for (const [key, group] of groups) {
    const text = group.map((slot) => slot.text).join("");
    const safe = text ? guard(text) : text;
    if (safe === text) {
      continue;
    }
    changed.add(key);
    let pos = 0;
    for (const [i, slot] of group.entries()) {
      const end =
        i === group.length - 1
          ? safe.length
          : Math.min(pos + slot.text.length, safe.length);
      slot.set(safe.slice(pos, end));
      pos = end;
    }
  }
  return changed;
}

export interface SlotSanitizer {
  /** Rewrites each slot with the text of its key that is safe to emit so far. */
  push(slots: readonly TextSlot[]): void;
  /** Guards and returns what each key still holds back. */
  flush(): Map<string, string>;
  /** Throws the leak kept for `throwOnLeak`, once every text was emitted. */
  finish(): void;
}

/**
 * Chunked streaming: each key's text goes through its own chunked
 * sanitizer. A blocked finding throws right away; a leak with `throwOnLeak`
 * is thrown by `finish()`, as the OpenAI wrapper does.
 */
export function createSlotSanitizer(
  systemPrompt: string,
  output: OutputGuard,
  options: ShieldProviderOptions
): SlotSanitizer {
  const chunkSize = options.streamingChunkSize ?? 8192;
  const overlap = output.overlap(chunkSize);
  const sanitizers = new Map<string, ChunkedSanitizer>();
  let leak: LeakDetectedError | undefined;

  const emit = (results: ChunkResult[]): string => {
    let text = "";
    for (const result of results) {
      const verdict = output.report(result);
      leak ??= verdict.leak;
      if (verdict.block && !(verdict.leak && options.throwOnLeak)) {
        throw verdict.block;
      }
      text += result.sanitized;
    }
    return text;
  };

  const sanitizerFor = (key: string): ChunkedSanitizer => {
    let sanitizer = sanitizers.get(key);
    if (!sanitizer) {
      sanitizer = createChunkedSanitizer(
        systemPrompt,
        output.scanWindow,
        chunkSize,
        overlap
      );
      sanitizers.set(key, sanitizer);
    }
    return sanitizer;
  };

  return {
    push(slots) {
      for (const slot of slots) {
        const text = emit(sanitizerFor(slot.key).push(slot.text));
        if (text !== slot.text) {
          slot.set(text);
        }
      }
    },
    flush() {
      const rest = new Map<string, string>();
      for (const [key, sanitizer] of sanitizers) {
        const last = sanitizer.flush();
        const text = last ? emit([last]) : "";
        if (text) {
          rest.set(key, text);
        }
      }
      sanitizers.clear();
      return rest;
    },
    finish() {
      if (leak && options.throwOnLeak) {
        throw leak;
      }
    },
  };
}

/**
 * Chunked streaming with the chunks re-emitted one behind, so the text each
 * key still holds back at the end goes into the last chunk, ahead of what
 * it carries (a finish reason, usage).
 */
export async function* chunkedReplay<C>(
  stream: AsyncIterable<C>,
  sanitizer: SlotSanitizer,
  slotsOf: (chunk: C) => TextSlot[],
  append: (chunk: C, key: string, text: string) => void
): AsyncGenerator<C> {
  let last: C | undefined;
  let held = false;
  for await (const chunk of stream) {
    sanitizer.push(slotsOf(chunk));
    if (held) {
      yield last as C;
    }
    last = chunk;
    held = true;
  }
  if (held) {
    for (const [key, text] of sanitizer.flush()) {
      append(last as C, key, text);
    }
    yield last as C;
  }
  sanitizer.finish();
}

/**
 * Wraps `target` so the given properties read as `overrides`. Every other
 * property reads from `target`, with methods bound to it, so SDK classes that
 * keep state in private fields still work.
 */
export function withOverrides<T extends object>(
  target: T,
  overrides: Record<string, unknown>
): T {
  const bound = new WeakMap<object, unknown>();
  const keys = new Set(Object.keys(overrides));
  const has = (key: PropertyKey): key is string =>
    typeof key === "string" && keys.has(key);
  return new Proxy(target, {
    get(object, key) {
      if (has(key)) {
        return overrides[key];
      }
      const value: unknown = Reflect.get(object, key, object);
      if (typeof value !== "function") {
        return value;
      }
      let method = bound.get(value);
      if (!method) {
        method = value.bind(object);
        bound.set(value, method);
      }
      return method;
    },
    has(object, key) {
      return has(key) || Reflect.has(object, key);
    },
  });
}

/**
 * `source` as a stream of the same kind as `original`: a `ReadableStream`
 * with `original`'s prototype if it was one (the Mistral SDK's
 * `EventStream`), `source` itself otherwise.
 */
export function streamLike<T>(
  source: AsyncIterable<T>,
  original: unknown
): AsyncIterable<T> {
  if (
    typeof ReadableStream === "undefined" ||
    !(original instanceof ReadableStream)
  ) {
    return source;
  }
  const iterator = source[Symbol.asyncIterator]();
  const stream = new ReadableStream<T>(
    {
      async pull(controller) {
        const next = await iterator.next();
        if (next.done) {
          controller.close();
        } else {
          controller.enqueue(next.value);
        }
      },
      async cancel(reason) {
        await iterator.return?.(reason);
      },
    },
    { highWaterMark: 0 }
  );
  Object.setPrototypeOf(stream, Object.getPrototypeOf(original));
  return stream as unknown as AsyncIterable<T>;
}
