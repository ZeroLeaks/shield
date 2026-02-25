import {
  type DetectOptions,
  type DetectResult,
  detect,
  detectAsync,
} from "../detect";
import { InjectionDetectedError, LeakDetectedError } from "../errors";
import { type HardenOptions, harden } from "../harden";
import {
  type SanitizeOptions,
  type SanitizeResult,
  sanitize,
} from "../sanitize";
import { chunkString } from "./utils";

export interface ShieldAISdkOptions {
  systemPrompt?: string;
  harden?: HardenOptions | false;
  detect?: DetectOptions | false;
  sanitize?: SanitizeOptions | false;
  /** `"buffer"`: full buffer. `"chunked"`: 8KB chunks. `"passthrough"`: skip sanitization. */
  streamingSanitize?: "buffer" | "chunked" | "passthrough";
  /** Chunk size for "chunked" mode (default 8192). */
  streamingChunkSize?: number;
  onDetection?: "block" | "warn";
  throwOnLeak?: boolean;
  onInjectionDetected?: (result: DetectResult) => void;
  onLeakDetected?: (result: SanitizeResult) => void;
}

type MessagePart = { type: string; text?: string };
interface AISdkParams {
  system?: string | Array<{ type: string; text?: string }>;
  prompt?: string | MessagePart[];
  messages?: Array<{
    role: string;
    content: string | MessagePart[];
  }>;
  [key: string]: unknown;
}

function extractMessageText(content: string | MessagePart[]): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .filter(
      (p): p is MessagePart & { text: string } =>
        p.type === "text" && typeof p.text === "string"
    )
    .map((p) => p.text)
    .join(" ");
}

function extractSystemText(
  system: string | Array<{ type: string; text?: string }> | undefined
): string {
  if (!system) return "";
  if (typeof system === "string") return system;
  if (!Array.isArray(system)) return "";
  return system
    .filter(
      (p): p is { type: string; text: string } =>
        p.type === "text" && typeof p.text === "string"
    )
    .map((p) => p.text)
    .join(" ");
}

export function shieldMiddleware(options: ShieldAISdkOptions = {}) {
  return {
    wrapParams(params: AISdkParams): AISdkParams {
      const result = { ...params };

      const derivedSystemPrompt =
        options.systemPrompt ?? extractSystemText(result.system);

      if (options.harden !== false && result.system) {
        const text = extractSystemText(result.system);
        if (text) {
          const hardened = harden(text, options.harden || {});
          if (typeof result.system === "string") {
            result.system = hardened;
          } else if (Array.isArray(result.system)) {
            result.system = [{ type: "text" as const, text: hardened }];
          }
        }
      }

      if (options.detect !== false && result.prompt) {
        const promptText =
          typeof result.prompt === "string"
            ? result.prompt
            : extractMessageText(result.prompt as MessagePart[]);
        if (promptText) {
          const detection = detect(promptText, options.detect || {});
          if (detection.detected) {
            options.onInjectionDetected?.(detection);
            if ((options.onDetection ?? "block") === "block") {
              throw new InjectionDetectedError(
                detection.risk,
                detection.matches.map((m) => m.category)
              );
            }
          }
        }
      }

      if (options.detect !== false && result.messages) {
        for (const msg of result.messages) {
          if (msg.role === "user") {
            const text = extractMessageText(msg.content);
            if (!text) continue;
            const detection = detect(text, options.detect || {});
            if (detection.detected) {
              options.onInjectionDetected?.(detection);
              if ((options.onDetection ?? "block") === "block") {
                throw new InjectionDetectedError(
                  detection.risk,
                  detection.matches.map((m) => m.category)
                );
              }
            }
          }
        }
      }

      return result;
    },

    sanitizeOutput(text: string, systemPrompt?: string): string {
      const effectiveSystem = systemPrompt ?? options.systemPrompt;
      if (options.sanitize === false || !effectiveSystem) {
        return text;
      }

      const result = sanitize(text, effectiveSystem, options.sanitize || {});
      if (result.leaked) {
        options.onLeakDetected?.(result);
        if (options.throwOnLeak) {
          throw new LeakDetectedError(
            result.confidence,
            result.fragments.length
          );
        }
        return result.sanitized;
      }
      return text;
    },
  };
}

/** Extract system prompt from AI SDK internal prompt format. */
function extractSystemFromPrompt(
  prompt: Array<{ role: string; content: unknown }> | undefined
): string {
  if (!Array.isArray(prompt)) return "";
  const sys = prompt.find((m) => m.role === "system");
  if (!sys || typeof sys.content !== "string") return "";
  return sys.content;
}

/** Extract user text from AI SDK internal prompt format. */
function extractUserTextFromPrompt(
  prompt: Array<{ role: string; content: unknown }> | undefined
): string[] {
  if (!Array.isArray(prompt)) return [];
  return prompt
    .filter((m) => m.role === "user")
    .flatMap((m) => {
      const c = m.content;
      if (Array.isArray(c)) {
        return c
          .filter(
            (p): p is { type: string; text: string } =>
              p &&
              typeof p === "object" &&
              p.type === "text" &&
              typeof (p as { text?: unknown }).text === "string"
          )
          .map((p) => p.text);
      }
      return [];
    });
}

/**
 * AI SDK Language Model Middleware. Use with `wrapLanguageModel` for automatic
 * hardening, injection detection, and output sanitization. No need to call
 * `sanitizeOutput` manually.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel, generateText } from "ai";
 * import { createOpenAI } from "@ai-sdk/openai";
 * import { shieldLanguageModelMiddleware } from "@zeroleaks/shield/ai-sdk";
 *
 * const openai = createOpenAI({ apiKey: process.env.OPENAI_API_KEY });
 * const model = wrapLanguageModel({
 *   model: openai("gpt-5.3-codex"),
 *   middleware: shieldLanguageModelMiddleware({ systemPrompt: "You are helpful." }),
 * });
 *
 * const result = await generateText({ model, prompt: "Hi" });
 * // result.text is automatically sanitized
 * ```
 */
export function shieldLanguageModelMiddleware(
  options: ShieldAISdkOptions = {}
): {
  middlewareVersion: "v1";
  transformParams: (opts: {
    type: "generate" | "stream";
    params: { prompt?: Array<{ role: string; content: unknown }> };
  }) => Promise<{ prompt?: Array<{ role: string; content: unknown }> }>;
  wrapGenerate: (opts: {
    doGenerate: () => Promise<{ text?: string; [key: string]: unknown }>;
    params: { prompt?: Array<{ role: string; content: unknown }> };
  }) => Promise<{ text?: string; [key: string]: unknown }>;
  wrapStream?: (opts: {
    doStream: () => Promise<{
      stream: ReadableStream<{ type: string; textDelta?: string }>;
      [key: string]: unknown;
    }>;
    params: { prompt?: Array<{ role: string; content: unknown }> };
  }) => Promise<{
    stream: ReadableStream<{ type: string; textDelta?: string }>;
    [key: string]: unknown;
  }>;
} {
  return {
    middlewareVersion: "v1",

    transformParams: async ({ params }) => {
      const prompt = params.prompt;
      const systemText =
        options.systemPrompt ?? extractSystemFromPrompt(prompt);

      if (options.harden !== false && prompt) {
        for (const msg of prompt) {
          if (msg.role === "system" && typeof msg.content === "string") {
            msg.content = harden(msg.content, options.harden || {});
          }
        }
      }

      if (options.detect !== false) {
        const userTexts = extractUserTextFromPrompt(prompt);
        for (const text of userTexts) {
          if (!text) continue;
          const result = detect(text, options.detect || {});
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

      return params;
    },

    wrapGenerate: async ({ doGenerate, params }) => {
      const result = await doGenerate();
      const systemText =
        options.systemPrompt ?? extractSystemFromPrompt(params.prompt);

      if (options.sanitize === false || !systemText || result.text == null) {
        return result;
      }

      const sanitized = sanitize(
        result.text,
        systemText,
        options.sanitize || {}
      );
      if (sanitized.leaked) {
        options.onLeakDetected?.(sanitized);
        if (options.throwOnLeak) {
          throw new LeakDetectedError(
            sanitized.confidence,
            sanitized.fragments.length
          );
        }
        return { ...result, text: sanitized.sanitized };
      }
      return result;
    },

    wrapStream:
      options.streamingSanitize === "passthrough"
        ? undefined
        : async ({ doStream, params }) => {
            const { stream, ...rest } = await doStream();
            const systemText =
              options.systemPrompt ?? extractSystemFromPrompt(params.prompt);

            if (options.sanitize === false || !systemText) {
              return { stream, ...rest };
            }

            let accumulated = "";
            const reader = stream.getReader();
            const decoder = new TextDecoder();
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                const part = value as { type?: string; textDelta?: string };
                if (
                  part?.type === "text-delta" &&
                  typeof part.textDelta === "string"
                ) {
                  accumulated += part.textDelta;
                }
              }
            } finally {
              reader.releaseLock();
            }

            const sanitized = sanitize(
              accumulated,
              systemText,
              options.sanitize || {}
            );
            if (sanitized.leaked) {
              options.onLeakDetected?.(sanitized);
              if (options.throwOnLeak) {
                throw new LeakDetectedError(
                  sanitized.confidence,
                  sanitized.fragments.length
                );
              }
            }
            const content = sanitized.leaked
              ? sanitized.sanitized
              : accumulated;

            const newStream = new ReadableStream<{
              type: "text-delta";
              textDelta: string;
            }>({
              start(controller) {
                for (const chunk of chunkString(content)) {
                  controller.enqueue({
                    type: "text-delta" as const,
                    textDelta: chunk,
                  });
                }
                controller.close();
              },
            });

            return { ...rest, stream: newStream };
          },
  };
}
