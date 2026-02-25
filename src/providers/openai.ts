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
} from "../sanitize";
import {
  chunkString,
  extractOpenAIContentText,
  openAIStreamToText,
  sanitizeTextStreamChunked,
} from "./utils";

export interface ShieldOpenAIOptions {
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

type ContentPart = { type: string; text?: string };
type ChatCompletionParams = {
  messages?: Array<{ role: string; content?: string | ContentPart[] | null }>;
  stream?: boolean;
  [key: string]: unknown;
};

function isAsyncIterable<T>(value: unknown): value is AsyncIterable<T> {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as AsyncIterable<T>)[Symbol.asyncIterator] === "function"
  );
}

export function shieldOpenAI<
  T extends {
    chat: { completions: { create: (...args: unknown[]) => unknown } };
  },
>(client: T, options: ShieldOpenAIOptions = {}): T {
  const originalCreate = client.chat.completions.create.bind(
    client.chat.completions
  );

  const wrappedCreate = async (...args: unknown[]) => {
    const originalParams = (args[0] as ChatCompletionParams) ?? {};

    const params = {
      ...originalParams,
      messages: Array.isArray(originalParams.messages)
        ? originalParams.messages.map((m) => ({ ...m }))
        : originalParams.messages,
    };
    args[0] = params;

    const derivedSystemPrompt =
      options.systemPrompt ??
      (() => {
        const sys = params.messages?.find((m) => m.role === "system");
        return sys ? extractOpenAIContentText(sys.content) : undefined;
      })();

    if (params.messages) {
      if (options.harden !== false) {
        for (const msg of params.messages) {
          if (msg.role === "system") {
            const text = extractOpenAIContentText(msg.content);
            if (text) {
              const hardened = harden(text, options.harden || {});
              if (typeof msg.content === "string") {
                msg.content = hardened;
              } else if (Array.isArray(msg.content)) {
                msg.content = [{ type: "text" as const, text: hardened }];
              }
            }
          }
        }
      }

      if (options.detect !== false) {
        for (const msg of params.messages) {
          if (msg.role === "user") {
            const text = extractOpenAIContentText(msg.content);
            if (text) {
              const result = await detectAsync(text, options.detect || {});
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
    }

    const response = await originalCreate(...args);

    const streamMode = options.streamingSanitize ?? "buffer";
    const shouldProcessStream =
      params.stream === true &&
      isAsyncIterable(response) &&
      options.sanitize !== false &&
      streamMode !== "passthrough" &&
      derivedSystemPrompt;

    if (shouldProcessStream) {
      const sanitizeOpts = options.sanitize || {};

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
              openAIStreamToText(
                response as AsyncIterable<{
                  choices?: Array<{ delta?: { content?: string } }>;
                }>
              ),
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
                    choices: [{ delta: { content: c }, index: 0 }],
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
        for await (const chunk of response as AsyncIterable<{
          choices?: Array<{ delta?: { content?: string } }>;
        }>) {
          const content = chunk?.choices?.[0]?.delta?.content;
          if (typeof content === "string") {
            accumulated += content;
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
            choices: [{ delta: { content: chunk }, index: 0 }],
          };
        }
      })();
    }

    const resp = response as {
      choices?: Array<{
        message?: {
          content?: string;
          tool_calls?: Array<{ function?: { arguments?: string } }>;
        };
      }>;
    };
    if (
      options.sanitize !== false &&
      derivedSystemPrompt &&
      resp?.choices?.[0]?.message
    ) {
      const msg = resp.choices[0].message;
      if (typeof msg.content === "string") {
        const result = sanitize(
          msg.content,
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
          msg.content = result.sanitized;
        }
      }
      const toolCalls = msg.tool_calls;
      if (Array.isArray(toolCalls)) {
        for (const tc of toolCalls) {
          const args = tc.function?.arguments;
          if (typeof args === "string") {
            const result = sanitize(
              args,
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
              if (tc.function) tc.function.arguments = result.sanitized;
            }
          }
        }
      }
    }

    return response;
  };

  return {
    ...client,
    chat: {
      ...client.chat,
      completions: {
        ...client.chat.completions,
        create: wrappedCreate as T["chat"]["completions"]["create"],
      },
    },
  } as T;
}
