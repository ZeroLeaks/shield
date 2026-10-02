import { type HardenOptions, harden } from "../harden";
import {
  callProvider,
  createShield,
  endWhenSettled,
  type InputScope,
  type OutputGuard,
  type ShieldProviderOptions,
  whenSettled,
} from "./guard";
import { shieldResponsesCreate } from "./openai-responses";
import {
  createSlotSanitizer,
  isRecord,
  type SlotSanitizer,
  type TextSlot,
  withOverrides,
} from "./shared";
import {
  chunkString,
  extractOpenAIContentText,
  isAsyncIterable,
} from "./utils";

export interface ShieldOpenAIOptions extends ShieldProviderOptions {}

interface ContentPart {
  type: string;
  text?: string;
}
interface ChatMessage {
  role: string;
  content?: string | ContentPart[] | null;
}
interface ChatCompletionParams {
  messages?: ChatMessage[];
  stream?: boolean;
  [key: string]: unknown;
}

interface ToolCall {
  index?: number;
  function?: { arguments?: string; [key: string]: unknown };
  custom?: { input?: string; [key: string]: unknown };
  [key: string]: unknown;
}

interface ChatChoice {
  index?: number;
  message?: {
    content?: string | null;
    tool_calls?: ToolCall[];
    function_call?: { arguments?: string };
  };
  delta?: {
    content?: string | null;
    tool_calls?: ToolCall[];
    [key: string]: unknown;
  };
  logprobs?: unknown;
  [key: string]: unknown;
}

interface ChatChunk {
  choices?: ChatChoice[];
  [key: string]: unknown;
}

/** System and developer messages: the instructions the model follows. */
function isInstruction(message: ChatMessage): boolean {
  return message?.role === "system" || message?.role === "developer";
}

/** The text of every system and developer message, joined. */
function instructionText(
  messages: ChatMessage[] | undefined
): string | undefined {
  const text = (messages ?? [])
    .filter(isInstruction)
    .map((m) => extractOpenAIContentText(m.content))
    .filter(Boolean)
    .join("\n");
  return text || undefined;
}

function hardenMessages(
  messages: ChatMessage[],
  options: HardenOptions | false
): void {
  if (!options) {
    return;
  }
  for (const msg of messages) {
    if (!isInstruction(msg)) {
      continue;
    }
    const text = extractOpenAIContentText(msg.content);
    if (!text) {
      continue;
    }
    const hardened = harden(text, options);
    if (typeof msg.content === "string") {
      msg.content = hardened;
    } else if (Array.isArray(msg.content)) {
      msg.content = [{ type: "text" as const, text: hardened }];
    }
  }
}

async function checkMessages(
  messages: ChatMessage[],
  input: InputScope
): Promise<void> {
  for (const msg of messages) {
    if (msg.role === "user") {
      await input.check(extractOpenAIContentText(msg.content), "user");
    } else if (msg.role === "tool" || msg.role === "function") {
      await input.check(extractOpenAIContentText(msg.content), "tool");
    }
  }
}

/** Guards the tool call arguments of a message, in place. */
function guardToolCalls(
  message: NonNullable<ChatChoice["message"]>,
  guard: (text: string) => string
): void {
  for (const call of message.tool_calls ?? []) {
    if (typeof call.function?.arguments === "string") {
      call.function.arguments = guard(call.function.arguments);
    }
    if (typeof call.custom?.input === "string") {
      call.custom.input = guard(call.custom.input);
    }
  }
  if (typeof message.function_call?.arguments === "string") {
    message.function_call.arguments = guard(message.function_call.arguments);
  }
}

/** Guards the text and tool call arguments of every choice, in place. */
function guardCompletion(
  response: unknown,
  systemPrompt: string | undefined,
  output: OutputGuard
): void {
  const choices = (response as ChatChunk | undefined)?.choices;
  if (!Array.isArray(choices)) {
    return;
  }
  const guard = (text: string): string => output.text(text, systemPrompt);
  for (const choice of choices) {
    const msg = choice?.message;
    if (!msg) {
      continue;
    }
    if (typeof msg.content === "string") {
      const safe = guard(msg.content);
      if (safe !== msg.content) {
        msg.content = safe;
        // Log probabilities list the tokens of the original text.
        if (choice.logprobs) {
          choice.logprobs = null;
        }
      }
    }
    guardToolCalls(msg, guard);
  }
}

const choiceKey = (choice: ChatChoice, position: number): string =>
  String(choice.index ?? position);

const callKey = (choice: string, call: ToolCall): string =>
  `${choice}:${call.index ?? 0}`;

/** A chunk that carries one piece of a choice's rewritten text. */
function textChunk(chunk: ChatChunk, choice: ChatChoice, text: string) {
  const { usage: _usage, ...rest } = chunk;
  const piece: ChatChoice = {
    ...choice,
    delta: { content: text },
    finish_reason: null,
  };
  if ("logprobs" in choice) {
    piece.logprobs = null;
  }
  return { ...rest, choices: [piece] };
}

/**
 * The tool calls with each rewritten argument string whole in its first
 * non-empty delta, and emptied in later ones.
 */
function rewriteCalls(
  calls: ToolCall[],
  choice: string,
  args: Map<string, string>,
  started: Set<string>
): ToolCall[] {
  return calls.map((call) => {
    const key = callKey(choice, call);
    const safe = args.get(key);
    const current = call.function?.arguments;
    if (safe === undefined || typeof current !== "string") {
      return call;
    }
    const first = current.length > 0 && !started.has(key);
    if (first) {
      started.add(key);
    }
    return {
      ...call,
      function: { ...call.function, arguments: first ? safe : "" },
    };
  });
}

/**
 * Replays the chunks with each rewritten text and tool call argument string
 * in place of the original. A rewritten text goes out in 64-character pieces
 * where its first non-empty delta was; a rewritten argument string goes out
 * whole in its first delta. Later deltas of either are emptied.
 */
function* rewriteChunks(
  chunks: ChatChunk[],
  texts: Map<string, string>,
  args: Map<string, string>
): Generator<ChatChunk> {
  const started = new Set<string>();

  /** This delta's text. Pieces before it go out ahead of the chunk, in `before`. */
  const textFor = (
    chunk: ChatChunk,
    choice: ChatChoice,
    key: string,
    safe: string,
    before: ChatChunk[]
  ): string => {
    if (!choice.delta?.content || started.has(key)) {
      return "";
    }
    started.add(key);
    const pieces = [...chunkString(safe)];
    const last = pieces.pop() ?? "";
    before.push(...pieces.map((p) => textChunk(chunk, choice, p)));
    return last;
  };

  const rewriteChoice = (
    chunk: ChatChunk,
    choice: ChatChoice,
    position: number,
    before: ChatChunk[]
  ): ChatChoice => {
    const { delta } = choice;
    if (!delta) {
      return choice;
    }
    const key = choiceKey(choice, position);
    const safe = texts.get(key);
    let next = delta;
    if (safe !== undefined && typeof delta.content === "string") {
      const content = textFor(chunk, choice, key, safe, before);
      if (content !== delta.content) {
        next = { ...next, content };
      }
    }
    if (Array.isArray(delta.tool_calls)) {
      const calls = rewriteCalls(delta.tool_calls, key, args, started);
      if (calls.some((call, i) => call !== delta.tool_calls?.[i])) {
        next = { ...next, tool_calls: calls };
      }
    }
    if (next === delta) {
      return choice;
    }
    return "logprobs" in choice
      ? { ...choice, delta: next, logprobs: null }
      : { ...choice, delta: next };
  };

  for (const chunk of chunks) {
    const original = chunk?.choices;
    if (!Array.isArray(original)) {
      yield chunk;
      continue;
    }
    const before: ChatChunk[] = [];
    const choices = original.map((choice, position) =>
      rewriteChoice(chunk, choice, position, before)
    );
    yield* before;
    yield choices.some((choice, i) => choice !== original[i])
      ? { ...chunk, choices }
      : chunk;
  }
}

/**
 * Reads the whole stream, guards the full text and tool call arguments of
 * each choice, and replays the chunks. Nothing else in them changes.
 */
async function bufferStream(
  stream: AsyncIterable<ChatChunk>,
  systemPrompt: string | undefined,
  output: OutputGuard
): Promise<AsyncIterable<ChatChunk>> {
  const chunks: ChatChunk[] = [];
  const texts = new Map<string, string>();
  const args = new Map<string, string>();
  const append = (map: Map<string, string>, key: string, text: string) =>
    map.set(key, (map.get(key) ?? "") + text);
  for await (const chunk of stream) {
    chunks.push(chunk);
    for (const [position, choice] of (chunk?.choices ?? []).entries()) {
      const key = choiceKey(choice, position);
      if (typeof choice.delta?.content === "string") {
        append(texts, key, choice.delta.content);
      }
      for (const call of choice.delta?.tool_calls ?? []) {
        if (typeof call.function?.arguments === "string") {
          append(args, callKey(key, call), call.function.arguments);
        }
      }
    }
  }

  const rewritten = (map: Map<string, string>): Map<string, string> => {
    const out = new Map<string, string>();
    for (const [key, text] of map) {
      const safe = text ? output.text(text, systemPrompt) : text;
      if (safe !== text) {
        out.set(key, safe);
      }
    }
    return out;
  };
  const safeTexts = rewritten(texts);
  const safeArgs = rewritten(args);
  const replay =
    safeTexts.size === 0 && safeArgs.size === 0
      ? chunks
      : rewriteChunks(chunks, safeTexts, safeArgs);
  return (async function* () {
    yield* replay;
  })();
}

/**
 * A choice's text and its tool calls' argument strings in one chunk, as
 * slots. Rewriting the text drops the choice's log probabilities, which list
 * the tokens of the original.
 */
function choiceSlots(choice: ChatChoice, key: string): TextSlot[] {
  const { delta } = choice;
  if (!isRecord(delta)) {
    return [];
  }
  const slots: TextSlot[] = [];
  if (typeof delta.content === "string") {
    slots.push({
      key,
      text: delta.content,
      set: (text) => {
        delta.content = text;
        if (choice.logprobs) {
          choice.logprobs = null;
        }
      },
    });
  }
  for (const call of delta.tool_calls ?? []) {
    const fn = call?.function;
    if (typeof fn?.arguments === "string") {
      slots.push({
        key: callKey(key, call),
        text: fn.arguments,
        set: (text) => {
          fn.arguments = text;
        },
      });
    }
  }
  return slots;
}

/** Adds held-back text for `key`, choice `choice`'s text or one of its tool calls, to `chunk`. */
function appendHeld(
  chunk: ChatChunk,
  choice: string,
  key: string,
  text: string
): void {
  chunk.choices ??= [];
  let target = chunk.choices.find(
    (c, position) => choiceKey(c, position) === choice
  );
  if (!target) {
    target = { index: Number(choice), delta: {}, finish_reason: null };
    chunk.choices.push(target);
  }
  target.delta ??= {};
  const { delta } = target;
  if (key === choice) {
    delta.content =
      (typeof delta.content === "string" ? delta.content : "") + text;
    if (target.logprobs) {
      target.logprobs = null;
    }
    return;
  }
  const index = Number(key.slice(choice.length + 1));
  delta.tool_calls ??= [];
  const call = delta.tool_calls.find((c) => (c.index ?? 0) === index);
  if (!call) {
    delta.tool_calls.push({ index, function: { arguments: text } });
    return;
  }
  call.function ??= {};
  call.function.arguments = (call.function.arguments ?? "") + text;
}

/**
 * Guards each choice's text and each tool call's arguments in chunks, and
 * replays the provider's chunks with the guarded text in place of the
 * original, one chunk behind. What a choice still holds back goes into the
 * chunk with its finish reason, or into the last chunk. With `throwOnLeak`,
 * a leak is thrown once everything was emitted.
 */
async function* chunkedStream(
  stream: AsyncIterable<ChatChunk>,
  systemPrompt: string | undefined,
  output: OutputGuard,
  options: ShieldOpenAIOptions
): AsyncGenerator<ChatChunk> {
  const open = new Map<string, SlotSanitizer>();
  const finished: SlotSanitizer[] = [];
  const flush = (chunk: ChatChunk, choice: string): void => {
    const sanitizer = open.get(choice);
    if (!sanitizer) {
      return;
    }
    open.delete(choice);
    finished.push(sanitizer);
    for (const [key, text] of sanitizer.flush()) {
      appendHeld(chunk, choice, key, text);
    }
  };

  /** Rewrites the text in `chunk`, and flushes the choices it finishes into it. */
  const guardChunk = (chunk: ChatChunk): void => {
    for (const [position, choice] of (chunk?.choices ?? []).entries()) {
      const key = choiceKey(choice, position);
      const slots = choiceSlots(choice, key);
      if (slots.length > 0) {
        let sanitizer = open.get(key);
        if (!sanitizer) {
          sanitizer = createSlotSanitizer(systemPrompt ?? "", output, options);
          open.set(key, sanitizer);
        }
        sanitizer.push(slots);
      }
      if (choice?.finish_reason != null) {
        flush(chunk, key);
      }
    }
  };

  let last: ChatChunk | undefined;
  for await (const chunk of stream) {
    guardChunk(chunk);
    if (last !== undefined) {
      yield last;
    }
    last = chunk;
  }
  if (last !== undefined) {
    for (const key of [...open.keys()]) {
      flush(last, key);
    }
    yield last;
  }
  for (const sanitizer of finished) {
    sanitizer.finish();
  }
}

export function shieldOpenAI<
  // Method syntax makes the parameter check bivariant, so the SDK client's
  // `create` overloads, which take specific param types, satisfy it.
  T extends { chat: { completions: { create(...args: unknown[]): unknown } } },
>(client: T, options: ShieldOpenAIOptions = {}): T {
  const shield = createShield(options);
  const { chat } = client;
  const { completions } = chat;
  const originalCreate = completions.create.bind(completions);

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
      options.systemPrompt ?? instructionText(params.messages);

    const scope = shield.input.begin();
    if (params.messages) {
      hardenMessages(params.messages, shield.harden);
      await checkMessages(params.messages, scope);
    }

    const response = await callProvider(scope, () => originalCreate(...args));
    const { output } = shield;
    const streamMode = options.streamingSanitize ?? "buffer";

    if (params.stream === true && isAsyncIterable<ChatChunk>(response)) {
      if (streamMode === "passthrough" || !output.active(derivedSystemPrompt)) {
        return whenSettled(scope, response);
      }
      return streamMode === "chunked"
        ? chunkedStream(
            await whenSettled(scope, response),
            derivedSystemPrompt,
            output,
            options
          )
        : await bufferStream(
            endWhenSettled(scope, response),
            derivedSystemPrompt,
            output
          );
    }

    await whenSettled(scope, response);
    if (output.active(derivedSystemPrompt)) {
      guardCompletion(response, derivedSystemPrompt, output);
    }
    return response;
  };

  const overrides: Record<string, unknown> = {
    chat: withOverrides(chat, {
      completions: withOverrides(completions, { create: wrappedCreate }),
    }),
  };
  const { responses } = client as { responses?: unknown };
  if (isRecord(responses) && typeof responses.create === "function") {
    overrides.responses = withOverrides(responses, {
      create: shieldResponsesCreate(
        responses.create.bind(responses),
        options,
        shield
      ),
    });
  }
  return withOverrides(client, overrides);
}
