import { type DetectOptions, type DetectResult, detect } from "../detect";
import { InjectionDetectedError, LeakDetectedError } from "../errors";
import { type HardenOptions, harden } from "../harden";
import {
  type SanitizeOptions,
  type SanitizeResult,
  sanitize,
  sanitizeWithRedactions,
} from "../sanitize";
import {
  type ChunkedSanitizer,
  chunkString,
  createChunkedSanitizer,
} from "./utils";

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
interface Message {
  role: string;
  content: string | MessagePart[];
}
/** AI SDK 6 also accepts system messages, alone or in an array, as `system`. */
interface SystemMessage {
  role: "system";
  content: string;
}
interface AISdkParams {
  system?: string | SystemMessage | Array<SystemMessage | MessagePart>;
  /** AI SDK 5 and later also accept an array of messages here. */
  prompt?: string | Array<MessagePart | Message>;
  messages?: Message[];
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

function isMessage(item: MessagePart | Message): item is Message {
  return "role" in item;
}

function hardenSystemMessage(
  message: SystemMessage,
  options: HardenOptions
): SystemMessage {
  return message.content
    ? { ...message, content: harden(message.content, options) }
    : message;
}

/**
 * Hardens `system` in the shape it came in. Each system message is hardened
 * on its own, as the language model middleware does, and an array of text
 * parts becomes a single hardened text part.
 */
function hardenSystem(
  system: NonNullable<AISdkParams["system"]>,
  options: HardenOptions
): AISdkParams["system"] {
  if (typeof system === "string") {
    return harden(system, options);
  }
  if (!Array.isArray(system)) {
    return hardenSystemMessage(system, options);
  }
  const parts = system.filter((item): item is MessagePart => !isMessage(item));
  if (parts.length < system.length) {
    return system.map((item) =>
      isMessage(item) ? hardenSystemMessage(item, options) : item
    );
  }
  const text = extractMessageText(parts);
  return text ? [{ type: "text", text: harden(text, options) }] : system;
}

/** `prompt` and every user message, whether in `messages` or in `prompt`. */
function extractUserInputs(params: AISdkParams): string[] {
  const { prompt } = params;
  const promptItems = Array.isArray(prompt) ? prompt : [];
  const messages = [
    ...(params.messages ?? []),
    ...promptItems.filter(isMessage),
  ];
  return [
    typeof prompt === "string"
      ? prompt
      : extractMessageText(
          promptItems.filter((p): p is MessagePart => !isMessage(p))
        ),
    ...messages
      .filter((m) => m.role === "user")
      .map((m) => extractMessageText(m.content)),
  ];
}

function checkInput(text: string, options: ShieldAISdkOptions): void {
  const result = detect(text, options.detect || {});
  if (!result.detected) {
    return;
  }
  options.onInjectionDetected?.(result);
  if ((options.onDetection ?? "block") === "block") {
    throw new InjectionDetectedError(
      result.risk,
      result.matches.map((m) => m.category)
    );
  }
}

function reportLeak(result: SanitizeResult, options: ShieldAISdkOptions): void {
  if (!result.leaked) {
    return;
  }
  options.onLeakDetected?.(result);
  if (options.throwOnLeak) {
    throw new LeakDetectedError(result.confidence, result.fragments.length);
  }
}

function sanitizeOutputText(
  text: string,
  systemPrompt: string,
  options: ShieldAISdkOptions
): string {
  const result = sanitize(text, systemPrompt, options.sanitize || {});
  reportLeak(result, options);
  return result.leaked ? result.sanitized : text;
}

export function shieldMiddleware(options: ShieldAISdkOptions = {}) {
  return {
    wrapParams<P extends AISdkParams>(params: P): P {
      if (options.detect !== false) {
        for (const text of extractUserInputs(params)) {
          checkInput(text, options);
        }
      }

      if (options.harden === false || !params.system) {
        return { ...params };
      }
      return {
        ...params,
        system: hardenSystem(params.system, options.harden || {}),
      };
    },

    sanitizeOutput(text: string, systemPrompt?: string): string {
      const effectiveSystem = systemPrompt ?? options.systemPrompt;
      if (options.sanitize === false || !effectiveSystem) {
        return text;
      }
      return sanitizeOutputText(text, effectiveSystem, options);
    },
  };
}

interface PromptMessage {
  role: string;
  content: unknown;
}

/** The part of the call options every AI SDK middleware version receives. */
interface LanguageModelCallOptions {
  prompt: PromptMessage[];
}

interface LanguageModelGenerateResult {
  /** AI SDK 5 and later. */
  content?: Array<{ type: string; text?: string }>;
  /** AI SDK 4. */
  text?: string;
  /** AI SDK 5 and later. Its `body` is the provider's raw response. */
  response?: object;
  /** AI SDK 4. Its `body` is the provider's raw response. */
  rawResponse?: object;
}

/**
 * AI SDK 5 and later send `text-delta` parts with an `id` and `delta`.
 * AI SDK 4 sends them with `textDelta` and no id.
 */
interface LanguageModelStreamPart {
  type: string;
  id?: string;
  delta?: string;
  textDelta?: string;
  providerMetadata?: unknown;
  error?: unknown;
}

interface LanguageModelStreamResult {
  stream: ReadableStream<LanguageModelStreamPart>;
}

/** Assignable to `LanguageModelMiddleware` from AI SDK 4, 5, and 6. */
export interface ShieldLanguageModelMiddleware {
  readonly specificationVersion: "v3";
  transformParams: <P extends LanguageModelCallOptions>(options: {
    params: P;
  }) => Promise<P>;
  wrapGenerate: <R extends LanguageModelGenerateResult>(options: {
    doGenerate: () => PromiseLike<R>;
    params: LanguageModelCallOptions;
  }) => Promise<R>;
  wrapStream: <R extends LanguageModelStreamResult>(options: {
    doStream: () => PromiseLike<R>;
    params: LanguageModelCallOptions;
  }) => Promise<R>;
}

/** Extract system prompt from AI SDK internal prompt format. */
function extractSystemFromPrompt(prompt: PromptMessage[]): string {
  return prompt
    .filter(
      (m): m is { role: string; content: string } =>
        m.role === "system" && typeof m.content === "string"
    )
    .map((m) => m.content)
    .join("\n");
}

/** Extract user text from AI SDK internal prompt format. */
function extractUserTextFromPrompt(prompt: PromptMessage[]): string[] {
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
 * Sanitizes the text of a `doGenerate` result. If any of it was redacted, the
 * provider's raw response body is dropped too, since it still holds the
 * original text.
 */
function sanitizeGenerateResult<R extends LanguageModelGenerateResult>(
  result: R,
  systemPrompt: string,
  options: ShieldAISdkOptions
): R {
  let redacted = false;
  const sanitizeText = (text: string): string => {
    const sanitized = sanitizeOutputText(text, systemPrompt, options);
    redacted ||= sanitized !== text;
    return sanitized;
  };

  let sanitized = result;
  if (result.content) {
    sanitized = {
      ...result,
      content: result.content.map((part) =>
        part.type === "text" && typeof part.text === "string"
          ? { ...part, text: sanitizeText(part.text) }
          : part
      ),
    };
  } else if (typeof result.text === "string") {
    sanitized = { ...result, text: sanitizeText(result.text) };
  }
  if (!redacted) {
    return sanitized;
  }
  const { response, rawResponse } = sanitized;
  return {
    ...sanitized,
    ...(response && { response: { ...response, body: undefined } }),
    ...(rawResponse && { rawResponse: { ...rawResponse, body: undefined } }),
  };
}

/** `part` with its text replaced, in the field its AI SDK version uses. */
function withText(
  part: LanguageModelStreamPart,
  text: string
): LanguageModelStreamPart {
  return part.id === undefined
    ? { ...part, textDelta: text }
    : { ...part, delta: text };
}

/**
 * Sanitizes the text parts of a model stream and passes every other part
 * through, except `raw` parts, which carry the provider's chunks before
 * sanitization. Each text block is held until it ends (or, with a finite
 * `chunkSize`, until a chunk fills), then re-emitted in 64-character deltas
 * ahead of its `text-end`, or ahead of `finish` on AI SDK 4.
 *
 * With `throwOnLeak`, a leak ends the stream with an `error` part in place
 * of the leaked text. Every AI SDK version reports an `error` part through
 * `onError` and `fullStream` and still settles its result promises, which
 * erroring the stream itself does not do on AI SDK 4 and 5.
 */
function sanitizeTextParts(
  systemPrompt: string,
  chunkSize: number,
  options: ShieldAISdkOptions
): TransformStream<LanguageModelStreamPart, LanguageModelStreamPart> {
  type Controller = TransformStreamDefaultController<LanguageModelStreamPart>;
  const scan = (text: string, prompt: string) =>
    sanitizeWithRedactions(text, prompt, options.sanitize || {});
  const blocks = new Map<string | undefined, ChunkedSanitizer>();

  /** Returns false if a leak ended the stream. */
  const enqueueText = (
    controller: Controller,
    part: LanguageModelStreamPart,
    results: SanitizeResult[]
  ): boolean => {
    for (const result of results) {
      if (result.leaked) {
        options.onLeakDetected?.(result);
      }
      if (result.leaked && options.throwOnLeak) {
        controller.enqueue({
          type: "error",
          error: new LeakDetectedError(
            result.confidence,
            result.fragments.length
          ),
        });
        controller.terminate();
        return false;
      }
      for (const text of chunkString(result.sanitized)) {
        controller.enqueue(withText(part, text));
      }
    }
    return true;
  };

  const flushBlock = (
    controller: Controller,
    id: string | undefined
  ): boolean => {
    const last = blocks.get(id)?.flush();
    blocks.delete(id);
    return (
      !last ||
      enqueueText(
        controller,
        id === undefined ? { type: "text-delta" } : { type: "text-delta", id },
        [last]
      )
    );
  };

  const flushBlocks = (controller: Controller): boolean => {
    for (const id of blocks.keys()) {
      if (!flushBlock(controller, id)) {
        return false;
      }
    }
    return true;
  };

  const pushDelta = (
    controller: Controller,
    part: LanguageModelStreamPart
  ): void => {
    let block = blocks.get(part.id);
    if (!block) {
      block = createChunkedSanitizer(systemPrompt, scan, chunkSize);
      blocks.set(part.id, block);
    }
    const results = block.push(part.delta ?? part.textDelta ?? "");
    if (!enqueueText(controller, part, results)) {
      return;
    }
    // Keep provider metadata that arrives on a delta whose text is still
    // held back.
    if (part.providerMetadata && !results.some((r) => r.sanitized)) {
      controller.enqueue(withText(part, ""));
    }
  };

  return new TransformStream({
    transform(part, controller) {
      if (part.type === "raw") {
        return;
      }
      if (part.type === "text-delta") {
        pushDelta(controller, part);
        return;
      }
      if (part.type === "text-end" && !flushBlock(controller, part.id)) {
        return;
      }
      if (part.type === "finish" && !flushBlocks(controller)) {
        return;
      }
      controller.enqueue(part);
    },
    flush(controller) {
      flushBlocks(controller);
    },
  });
}

/**
 * AI SDK language model middleware. Pass it to `wrapLanguageModel` for
 * automatic hardening, injection detection, and output sanitization in
 * `generateText` and `streamText`, with no manual `sanitizeOutput` call.
 * Works with AI SDK 4, 5, and 6.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel, generateText } from "ai";
 * import { openai } from "@ai-sdk/openai";
 * import { shieldLanguageModelMiddleware } from "@zeroleaks/shield/ai-sdk";
 *
 * const model = wrapLanguageModel({
 *   model: openai("gpt-5.5"),
 *   middleware: shieldLanguageModelMiddleware(),
 * });
 *
 * const result = await generateText({ model, system: "You are helpful.", prompt: "Hi" });
 * // result.text is sanitized against the system prompt
 * ```
 */
export function shieldLanguageModelMiddleware(
  options: ShieldAISdkOptions = {}
): ShieldLanguageModelMiddleware {
  // The AI SDK hands the params object transformParams returns to
  // wrapGenerate and wrapStream, so key the pre-hardening prompt on it.
  // Params from anywhere else fall back to `options.systemPrompt` or the
  // system messages they carry.
  const systemPrompts = new WeakMap<LanguageModelCallOptions, string>();
  const systemPromptFor = (params: LanguageModelCallOptions): string =>
    systemPrompts.get(params) ??
    options.systemPrompt ??
    extractSystemFromPrompt(params.prompt);

  return {
    specificationVersion: "v3",

    transformParams: ({ params }) => {
      if (options.detect !== false) {
        for (const text of extractUserTextFromPrompt(params.prompt)) {
          checkInput(text, options);
        }
      }

      const prompt =
        options.harden === false
          ? params.prompt
          : params.prompt.map((msg) =>
              msg.role === "system" && typeof msg.content === "string"
                ? { ...msg, content: harden(msg.content, options.harden || {}) }
                : msg
            );
      const transformed = { ...params, prompt };
      systemPrompts.set(
        transformed,
        options.systemPrompt ?? extractSystemFromPrompt(params.prompt)
      );
      return Promise.resolve(transformed);
    },

    wrapGenerate: async ({ doGenerate, params }) => {
      const result = await doGenerate();
      const systemText = systemPromptFor(params);
      if (options.sanitize === false || !systemText) {
        return result;
      }
      return sanitizeGenerateResult(result, systemText, options);
    },

    wrapStream: async ({ doStream, params }) => {
      const result = await doStream();
      const systemText = systemPromptFor(params);
      const mode = options.streamingSanitize ?? "buffer";
      if (options.sanitize === false || mode === "passthrough" || !systemText) {
        return result;
      }

      const chunkSize =
        mode === "chunked"
          ? (options.streamingChunkSize ?? 8192)
          : Number.POSITIVE_INFINITY;
      return {
        ...result,
        stream: result.stream.pipeThrough(
          sanitizeTextParts(systemText, chunkSize, options)
        ),
      };
    },
  };
}
