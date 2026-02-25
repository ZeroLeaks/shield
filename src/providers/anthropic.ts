import {
  type DetectOptions,
  type DetectResult,
  detectAsync,
} from "../detect";
import { InjectionDetectedError, LeakDetectedError } from "../errors";
import { type HardenOptions, harden } from "../harden";
import {
  type SanitizeOptions,
  type SanitizeResult,
  sanitize,
  sanitizeObject,
} from "../sanitize";
import {
  anthropicStreamToText,
  chunkString,
  sanitizeTextStreamChunked,
} from "./utils";

export interface ShieldAnthropicOptions {
  systemPrompt?: string;
  harden?: HardenOptions | false;
  detect?: DetectOptions | false;
  sanitize?: SanitizeOptions | false;
  /** `"buffer"`: full buffer then sanitize. `"chunked"`: 8KB chunks, lower memory. `"passthrough"`: skip sanitization. */
  streamingSanitize?: "buffer" | "chunked" | "passthrough";
  /** Chunk size for "chunked" mode (default 8192). */
  streamingChunkSize?: number;
  onDetection?: "block" | "warn";
  throwOnLeak?: boolean;
  onInjectionDetected?: (result: DetectResult) => void;
  onLeakDetected?: (result: SanitizeResult) => void;
}

type MessageContent = string | Array<{ type: string; text: string }>;

function extractText(content: MessageContent): string {
  if (typeof content === "string") {
    return content;
  }
  return (
    content
      ?.filter((b) => b.type === "text")
      .map((b) => b.text)
      .join(" ") || ""
  );
}

function isAsyncIterable<T>(value: unknown): value is AsyncIterable<T> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as AsyncIterable<T>)[Symbol.asyncIterator] === "function"
  );
}

export function shieldAnthropic<
  T extends { messages: { create: (...args: unknown[]) => unknown } },
>(client: T, options: ShieldAnthropicOptions = {}): T {
  const originalCreate = client.messages.create.bind(client.messages);

  const wrappedCreate = async (...args: unknown[]) => {
    const originalParams =
      (args[0] as {
        system?: string | Array<{ type: string; text: string }>;
        messages?: Array<{ role: string; content: MessageContent }>;
        stream?: boolean;
        [key: string]: unknown;
      }) ?? {};

    const params = {
      ...originalParams,
      system: originalParams.system,
      messages: Array.isArray(originalParams.messages)
        ? originalParams.messages.map((m) => ({ ...m }))
        : originalParams.messages,
    };
    args[0] = params;

    const derivedSystemPrompt =
      options.systemPrompt ??
      (typeof params.system === "string"
        ? params.system
        : Array.isArray(params.system)
          ? params.system
              .filter((b) => b.type === "text" && typeof b.text === "string")
              .map((b) => (b as { type: string; text: string }).text)
              .join(" ")
          : undefined);

    if (options.harden !== false && params.system) {
      if (typeof params.system === "string") {
        params.system = harden(params.system, options.harden || {});
      } else if (Array.isArray(params.system)) {
        params.system = params.system.map((b) =>
          b.type === "text" && typeof b.text === "string"
            ? { ...b, text: harden(b.text, options.harden || {}) }
            : b
        );
      }
    }

    if (options.detect !== false && params.messages) {
      for (const msg of params.messages) {
        if (msg.role === "user") {
          const content = extractText(msg.content);
          if (content) {
            const result = await detectAsync(content, options.detect || {});
            if (result.detected) {
              options.onInjectionDetected?.(result);
              if ((options.onDetection ?? "block") === "block") {
                throw new InjectionDetectedError(
                  result.risk,
                  result.matches.map((m) => m.category)
                );
              }
            }
          }
        }
      }
    }

    const response = await originalCreate(...args);

    const streamMode = options.streamingSanitize ?? "buffer";
    const shouldProcessStream =
      originalParams.stream === true &&
      isAsyncIterable(response) &&
      options.sanitize !== false &&
      streamMode !== "passthrough" &&
      derivedSystemPrompt;

    if (shouldProcessStream) {
      const sanitizeOpts = options.sanitize || {};
      const anthropicStream = response as AsyncIterable<{
        type?: string;
        delta?: { type?: string; text?: string };
      }>;

      if (streamMode === "chunked") {
        const chunkSize = options.streamingChunkSize ?? 8192;
        const sanitizeFn = (o: string, p: string) => {
          const r = sanitize(o, p, sanitizeOpts);
          return { sanitized: r.sanitized, leaked: r.leaked };
        };
        return (async function* () {
          let hadLeak = false;
          try {
            for await (const result of sanitizeTextStreamChunked(
              anthropicStreamToText(anthropicStream),
              derivedSystemPrompt,
              sanitizeFn,
              chunkSize
            )) {
              if (result.leaked) {
                hadLeak = true;
                options.onLeakDetected?.({
                  leaked: true,
                  confidence: 1,
                  fragments: [],
                  sanitized: result.sanitized,
                });
              }
              if (result.sanitized) {
                for (const c of chunkString(result.sanitized)) {
                  yield {
                    type: "content_block_delta",
                    delta: { type: "text_delta", text: c },
                    index: 0,
                  };
                }
              }
            }
          } catch {
            return response;
          }
          if (hadLeak && options.throwOnLeak) {
            throw new LeakDetectedError(1, 0);
          }
        })();
      }

      let accumulated = "";
      try {
        for await (const event of anthropicStream) {
          if (event?.type === "content_block_delta" && event.delta?.text) {
            accumulated += event.delta.text;
          }
        }
      } catch {
        return response;
      }
      const result = sanitize(
        accumulated,
        derivedSystemPrompt,
        sanitizeOpts
      );
      if (result.leaked) {
        options.onLeakDetected?.(result);
        if (options.throwOnLeak) {
          throw new LeakDetectedError(
            result.confidence,
            result.fragments.length
          );
        }
      }
      const sanitizedContent = result.leaked ? result.sanitized : accumulated;
      return (async function* () {
        for (const chunk of chunkString(sanitizedContent)) {
          yield {
            type: "content_block_delta",
            delta: { type: "text_delta", text: chunk },
            index: 0,
          };
        }
      })();
    }

    const resp = response as {
      content?: Array<{
        type: string;
        text?: string;
        input?: Record<string, unknown>;
      }>;
    };
    if (options.sanitize !== false && derivedSystemPrompt && resp?.content) {
      for (const block of resp.content) {
        if (block.type === "text" && typeof block.text === "string") {
          const result = sanitize(
            block.text,
            derivedSystemPrompt,
            options.sanitize || {}
          );
          if (result.leaked) {
            options.onLeakDetected?.(result);
            if (options.throwOnLeak) {
              throw new LeakDetectedError(
                result.confidence,
                result.fragments.length
              );
            }
            block.text = result.sanitized;
          }
        }
        if (
          block.type === "tool_use" &&
          block.input &&
          typeof block.input === "object"
        ) {
          const { result, hadLeak } = sanitizeObject(
            block.input,
            derivedSystemPrompt,
            options.sanitize || {}
          );
          if (hadLeak) {
            options.onLeakDetected?.({
              leaked: true,
              confidence: 1,
              fragments: [],
              sanitized: JSON.stringify(result),
            });
            if (options.throwOnLeak) {
              throw new LeakDetectedError(1, 0);
            }
            block.input = result;
          }
        }
      }
    }

    return response;
  };

  return {
    ...client,
    messages: {
      ...client.messages,
      create: wrappedCreate as T["messages"]["create"],
    },
  } as T;
}
