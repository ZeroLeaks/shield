/**
 * LangChain.js (`@langchain/core`). `shieldChatModel` wraps a chat model so
 * every call through it is guarded; `ShieldCallbackHandler` checks the runs
 * it is attached to without changing them.
 */

import { BaseCallbackHandler } from "@langchain/core/callbacks/base";
import type { DocumentInterface } from "@langchain/core/documents";
import type { Serialized } from "@langchain/core/load/serializable";
import type { BaseMessage } from "@langchain/core/messages";
import type { LLMResult } from "@langchain/core/outputs";
import { type HardenOptions, harden } from "../harden";
import {
  callProvider,
  createShield,
  endWhenSettled,
  type InputScope,
  jsonText,
  type OutputGuard,
  prefetchWhenSettled,
  type Shield,
  type ShieldProviderOptions,
  whenSettled,
} from "./guard";
import {
  hardenTextItems,
  isRecord,
  rewriteSlots,
  type TextSlot,
  withOverrides,
} from "./shared";

export interface ShieldChatModelOptions extends ShieldProviderOptions {}

/**
 * The callback handler can't rewrite prompts or streams or hold a response
 * back, so it takes no hardening, streaming, or parallel detection options.
 */
export type ShieldCallbackHandlerOptions = Omit<
  ShieldProviderOptions,
  "harden" | "streamingSanitize" | "streamingChunkSize" | "parallelDetection"
>;

type Role = "system" | "user" | "tool" | "ai";

const ROLES: Record<string, Role> = {
  system: "system",
  developer: "system",
  human: "user",
  user: "user",
  tool: "tool",
  function: "tool",
  ai: "ai",
  assistant: "ai",
};

function roleOf(message: unknown): Role | undefined {
  if (!isRecord(message)) {
    return;
  }
  let type: unknown = message.type;
  if (typeof message.getType === "function") {
    type = message.getType();
  } else if (typeof message._getType === "function") {
    type = message._getType();
  }
  if (type === "generic") {
    type = message.role;
  }
  return typeof type === "string" ? ROLES[type] : undefined;
}

function isTextBlock(
  block: unknown
): block is Record<string, unknown> & { text: string } {
  return (
    isRecord(block) && block.type === "text" && typeof block.text === "string"
  );
}

function blockText(block: unknown): string {
  return isTextBlock(block) ? block.text : "";
}

/** Text of message content: a string, or its text blocks joined with `separator`. */
function contentText(content: unknown, separator = "\n"): string {
  if (typeof content === "string") {
    return content;
  }
  return Array.isArray(content)
    ? content.map(blockText).filter(Boolean).join(separator)
    : "";
}

/** A copy of `message` with `content`, made with its own class. */
function withContent(
  message: Record<string, unknown>,
  content: unknown
): unknown {
  const Message = message.constructor;
  if (typeof Message !== "function" || Message === Object) {
    return { ...message, content };
  }
  const fields: Record<string, unknown> = { content };
  for (const key of [
    "name",
    "id",
    "role",
    "additional_kwargs",
    "response_metadata",
  ]) {
    if (message[key] !== undefined) {
      fields[key] = message[key];
    }
  }
  return new (Message as new (fields: object) => unknown)(fields);
}

function hardenMessage(message: unknown, options: HardenOptions): unknown {
  if (!isRecord(message)) {
    return message;
  }
  const { content } = message;
  if (Array.isArray(content)) {
    const blocks = hardenTextItems(
      content,
      blockText,
      (block, text) => ({ ...(block as object), text }),
      options
    );
    return withContent(message, blocks);
  }
  return typeof content === "string" && content
    ? withContent(message, harden(content, options))
    : message;
}

async function checkMessages(
  messages: readonly unknown[],
  input: Pick<InputScope, "check">
): Promise<void> {
  for (const message of messages) {
    const role = roleOf(message);
    if ((role === "user" || role === "tool") && isRecord(message)) {
      await input.check(contentText(message.content), role);
    }
  }
}

/** The system prompt of `messages`: the text of the first system message. */
function systemPromptOf(messages: readonly unknown[]): string | undefined {
  for (const message of messages) {
    if (roleOf(message) === "system" && isRecord(message)) {
      const text = contentText(message.content);
      if (text) {
        return text;
      }
    }
  }
}

interface ArgsContext {
  /** Guarded arguments of the parsed tool calls that changed, by call id. */
  changed: Map<string, unknown>;
  /** Ids of every parsed tool call. */
  known: Set<string>;
  text(text: string): string;
  value(value: unknown): unknown;
}

/** Content blocks that carry tool call arguments, and the field that holds them. */
const ARGUMENT_FIELDS: Record<string, string> = {
  tool_use: "input",
  tool_call: "args",
  tool_call_chunk: "args",
  function_call: "arguments",
};

type ArgumentsHolder = [Record<string, unknown>, string, unknown];

function* contentArguments(content: unknown): Generator<ArgumentsHolder> {
  for (const block of Array.isArray(content) ? (content as unknown[]) : []) {
    const field = isRecord(block) ? ARGUMENT_FIELDS[String(block.type)] : "";
    if (field && isRecord(block) && field in block) {
      yield [block, field, block.id];
    }
  }
}

function* kwargsArguments(kwargs: unknown): Generator<ArgumentsHolder> {
  if (!isRecord(kwargs)) {
    return;
  }
  const calls = Array.isArray(kwargs.tool_calls) ? kwargs.tool_calls : [];
  for (const call of calls) {
    if (isRecord(call) && isRecord(call.function)) {
      yield [call.function, "arguments", call.id];
    }
  }
  if (isRecord(kwargs.function_call)) {
    yield [kwargs.function_call, "arguments", undefined];
  }
}

/**
 * The other places a provider keeps tool call arguments: content blocks,
 * tool call chunks, invalid tool calls, and the raw OpenAI tool calls.
 */
function* rawArguments(
  message: Record<string, unknown>
): Generator<ArgumentsHolder> {
  yield* contentArguments(message.content);
  for (const key of ["tool_call_chunks", "invalid_tool_calls"]) {
    const calls = message[key];
    for (const call of Array.isArray(calls) ? calls : []) {
      if (isRecord(call)) {
        yield [call, "args", call.id];
      }
    }
  }
  yield* kwargsArguments(message.additional_kwargs);
}

/**
 * Guards one copy of tool call arguments. A copy of a parsed call takes that
 * call's guarded arguments, so each finding is reported once.
 */
function guardArguments(
  holder: Record<string, unknown>,
  field: string,
  id: unknown,
  context: ArgsContext
): boolean {
  const value = holder[field];
  const key = typeof id === "string" ? id : undefined;
  if (key !== undefined && context.changed.has(key)) {
    const safe = context.changed.get(key);
    holder[field] = typeof value === "string" ? JSON.stringify(safe) : safe;
    return true;
  }
  if (key !== undefined && context.known.has(key)) {
    return false;
  }
  let safe = value;
  if (typeof value === "string") {
    safe = value ? context.text(value) : value;
  } else if (isRecord(value)) {
    safe = context.value(value);
  }
  if (safe === value) {
    return false;
  }
  holder[field] = safe;
  return true;
}

/** Guards the text of message content in place. */
function guardContent(
  message: Record<string, unknown>,
  guard: (text: string) => string
): boolean {
  const { content } = message;
  if (typeof content === "string") {
    const safe = content ? guard(content) : content;
    if (safe === content) {
      return false;
    }
    message.content = safe;
    return true;
  }
  if (!Array.isArray(content)) {
    return false;
  }
  const slots: TextSlot[] = [];
  for (const block of content as unknown[]) {
    if (isTextBlock(block)) {
      slots.push({
        key: "text",
        text: block.text,
        set: (text) => {
          block.text = text;
        },
      });
    }
  }
  return rewriteSlots(slots, guard).size > 0;
}

/** Guards the text and every copy of the tool call arguments of an AI message, in place. */
function guardMessage(
  message: Record<string, unknown>,
  context: Omit<ArgsContext, "changed" | "known">
): boolean {
  let changed = guardContent(message, context.text);
  const args: ArgsContext = {
    ...context,
    changed: new Map(),
    known: new Set(),
  };
  const calls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
  for (const call of calls) {
    if (!isRecord(call)) {
      continue;
    }
    const id = typeof call.id === "string" ? call.id : undefined;
    if (id !== undefined) {
      args.known.add(id);
    }
    if (!isRecord(call.args)) {
      continue;
    }
    const safe = context.value(call.args);
    if (safe !== call.args) {
      call.args = safe;
      changed = true;
      if (id !== undefined) {
        args.changed.set(id, safe);
      }
    }
  }
  for (const [holder, field, id] of rawArguments(message)) {
    changed = guardArguments(holder, field, id, args) || changed;
  }
  return changed;
}

/** Log probabilities list the tokens of the original text. */
function dropLogprobs(...holders: unknown[]): void {
  for (const holder of holders) {
    if (isRecord(holder) && holder.logprobs !== undefined) {
      holder.logprobs = undefined;
    }
  }
}

/** Guards a generation or generation chunk in place. Returns whether anything changed. */
function guardGeneration(
  generation: unknown,
  systemPrompt: string | undefined,
  output: OutputGuard
): boolean {
  if (!isRecord(generation)) {
    return false;
  }
  const text = (value: string): string => output.text(value, systemPrompt);
  const { message } = generation;
  if (!isRecord(message)) {
    const before = generation.text;
    if (typeof before === "string" && before) {
      generation.text = text(before);
    }
    return generation.text !== before;
  }
  const changed = guardMessage(message, {
    text,
    value: (value) => output.value(value, systemPrompt),
  });
  if (changed) {
    generation.text = contentText(message.content, "");
    dropLogprobs(generation.generationInfo, message.response_metadata);
  }
  return changed;
}

interface GenerationChunk {
  text?: string;
  concat?(chunk: GenerationChunk): GenerationChunk;
}

/**
 * The chunks unchanged if the message they make up is clean, or that
 * message, guarded, as a single chunk.
 */
function guardChunks(
  chunks: GenerationChunk[],
  systemPrompt: string | undefined,
  output: OutputGuard
): GenerationChunk[] {
  const [first, ...rest] = chunks;
  if (!first) {
    return chunks;
  }
  let whole = first;
  for (const chunk of rest) {
    if (typeof whole.concat !== "function") {
      // Not chunks that add up: guard each on its own.
      for (const each of chunks) {
        guardGeneration(each, systemPrompt, output);
      }
      return chunks;
    }
    whole = whole.concat(chunk);
  }
  return guardGeneration(whole, systemPrompt, output) ? [whole] : chunks;
}

interface RunManager {
  handleLLMNewToken(...args: unknown[]): unknown;
}

function isRunManager(value: unknown): value is RunManager {
  return isRecord(value) && typeof value.handleLLMNewToken === "function";
}

/**
 * A run manager that holds back the tokens the model streams, so callback
 * handlers only see the guarded text. `emitted()` tells whether the model
 * streamed any.
 */
function muteTokens(runManager: unknown): {
  manager: unknown;
  emitted(): boolean;
} {
  if (!isRunManager(runManager)) {
    return { manager: runManager, emitted: () => false };
  }
  let emitted = false;
  const manager = withOverrides(runManager, {
    handleLLMNewToken: () => {
      emitted = true;
      return Promise.resolve();
    },
  });
  return { manager, emitted: () => emitted };
}

/**
 * A run manager that holds back the tokens the model streams until
 * `release()`, which sends them on in order. Tokens after that go straight
 * through.
 */
function holdTokens(runManager: unknown): {
  manager: unknown;
  release(): Promise<void>;
} {
  if (!isRunManager(runManager)) {
    return { manager: runManager, release: () => Promise.resolve() };
  }
  let held: unknown[][] | undefined = [];
  const manager = withOverrides(runManager, {
    handleLLMNewToken: (...args: unknown[]) => {
      if (!held) {
        return runManager.handleLLMNewToken(...args);
      }
      held.push(args);
      return Promise.resolve();
    },
  });
  return {
    manager,
    async release() {
      const tokens = held ?? [];
      held = undefined;
      for (const args of tokens) {
        await runManager.handleLLMNewToken(...args);
      }
    },
  };
}

/** Sends each generation's guarded text as one token, in place of the tokens the model streamed. */
async function replayTokens(
  runManager: unknown,
  generations: unknown[]
): Promise<void> {
  if (!isRunManager(runManager)) {
    return;
  }
  for (const generation of generations) {
    const text = isRecord(generation) ? generation.text : undefined;
    await runManager.handleLLMNewToken(typeof text === "string" ? text : "");
  }
}

type Method = (...args: unknown[]) => unknown;

interface ChatModelLike {
  invoke(...args: unknown[]): unknown;
}

function isChatModel(value: unknown): value is object {
  return (
    isRecord(value) &&
    typeof value._generate === "function" &&
    typeof value.invoke === "function"
  );
}

/** The topmost definition of a method in `target`'s prototype chain: the base class's. */
function baseMethod(target: object, key: string): unknown {
  let base: unknown;
  for (
    let proto: object | null = target;
    proto;
    proto = Object.getPrototypeOf(proto)
  ) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, key);
    if (descriptor && "value" in descriptor) {
      base = descriptor.value;
    }
  }
  return base;
}

/** Every proxy `shieldChatModel` made, from any options. */
const shielded = new WeakSet<object>();

/**
 * Makes the proxies for one set of options. Models that methods of a
 * shielded model return (from `bindTools`, `withConfig`, and the like) are
 * shielded with the same options.
 */
function createChatModelShield(options: ShieldChatModelOptions) {
  const shield: Shield = createShield(options);
  const { output } = shield;
  const proxies = new WeakMap<object, object>();

  const prepare = async (
    messages: unknown,
    scope: InputScope
  ): Promise<{ messages: unknown; systemPrompt: string | undefined }> => {
    if (!Array.isArray(messages)) {
      return { messages, systemPrompt: options.systemPrompt };
    }
    const systemPrompt = options.systemPrompt ?? systemPromptOf(messages);
    const hardenOptions = shield.harden;
    const prepared = hardenOptions
      ? messages.map((message) =>
          roleOf(message) === "system"
            ? hardenMessage(message, hardenOptions)
            : message
        )
      : messages;
    await checkMessages(messages, scope);
    return { messages: prepared, systemPrompt };
  };

  /**
   * `_generate`: guards the input, then every generation of the result.
   * Tokens the model streams to callbacks are held back while the output
   * guard or a verdict needs them to be.
   */
  const generate = async (
    target: object,
    original: Method,
    [messages, callOptions, runManager, ...rest]: unknown[]
  ): Promise<unknown> => {
    const scope = shield.input.begin();
    const prepared = await prepare(messages, scope);
    const active = output.active(prepared.systemPrompt);
    const tokens = active || scope.pending ? muteTokens(runManager) : undefined;
    const result = await callProvider(scope, () =>
      original.call(
        target,
        prepared.messages,
        callOptions,
        tokens ? tokens.manager : runManager,
        ...rest
      )
    );
    await whenSettled(scope, result);
    const generations = isRecord(result) ? result.generations : undefined;
    if (!Array.isArray(generations)) {
      return result;
    }
    if (active) {
      for (const generation of generations) {
        guardGeneration(generation, prepared.systemPrompt, output);
      }
    }
    if (tokens?.emitted()) {
      await replayTokens(runManager, generations);
    }
    return result;
  };

  /**
   * `_streamResponseChunks`: guards the input, reads every chunk, and
   * replays them if the message they make up is clean, or that message,
   * guarded, as one chunk. `"chunked"` works like `"buffer"`. Without
   * output guarding, a pending verdict holds the first chunk, and the
   * tokens streamed to callbacks with it, until it is in.
   */
  async function* stream(
    target: object,
    original: Method,
    [messages, callOptions, runManager, ...rest]: unknown[]
  ): AsyncGenerator<unknown> {
    const scope = shield.input.begin();
    const prepared = await prepare(messages, scope);
    const call = (manager: unknown) =>
      original.call(
        target,
        prepared.messages,
        callOptions,
        manager,
        ...rest
      ) as AsyncIterable<GenerationChunk>;
    if (
      options.streamingSanitize === "passthrough" ||
      !output.active(prepared.systemPrompt)
    ) {
      if (!scope.pending) {
        yield* call(runManager);
        return;
      }
      const tokens = holdTokens(runManager);
      const chunks = await prefetchWhenSettled(scope, call(tokens.manager));
      await tokens.release();
      yield* chunks;
      return;
    }
    const tokens = muteTokens(runManager);
    const chunks: GenerationChunk[] = [];
    for await (const chunk of endWhenSettled(scope, call(tokens.manager))) {
      chunks.push(chunk);
    }
    for (const chunk of guardChunks(chunks, prepared.systemPrompt, output)) {
      yield chunk;
      if (tokens.emitted() && isRunManager(runManager)) {
        await runManager.handleLLMNewToken(
          chunk.text ?? "",
          undefined,
          undefined,
          undefined,
          undefined,
          { chunk }
        );
      }
    }
  }

  const wrap = (model: object): object => {
    const existing = proxies.get(model);
    if (existing) {
      return existing;
    }
    const methods = new Map<
      PropertyKey,
      { original: Method; wrapped: Method }
    >();
    const memo = (
      key: PropertyKey,
      original: Method,
      make: (original: Method) => Method
    ): Method => {
      const hit = methods.get(key);
      if (hit?.original === original) {
        return hit.wrapped;
      }
      const wrapped = make(original);
      methods.set(key, { original, wrapped });
      return wrapped;
    };

    const methodFor = (target: object, key: PropertyKey, method: Method) => {
      switch (key) {
        case "_generate":
          return memo(
            key,
            method,
            (fn) =>
              (...args) =>
                generate(target, fn, args)
          );
        case "_streamResponseChunks":
          // Left alone when not overridden, so LangChain can tell the model
          // does not stream.
          return method === baseMethod(target, key)
            ? method
            : memo(
                key,
                method,
                (fn) =>
                  (...args) =>
                    stream(target, fn, args)
              );
        case "_streamChatModelEvents":
          // The base implementation builds the events from the guarded
          // `_streamResponseChunks`, in place of a provider's own.
          return baseMethod(target, key) ?? method;
        default:
          return memo(
            key,
            method,
            (fn) =>
              function (this: unknown, ...args: unknown[]) {
                return shieldResult(Reflect.apply(fn, this, args));
              }
          );
      }
    };

    const proxy = new Proxy(model, {
      get(target, key, receiver) {
        const value: unknown = Reflect.get(target, key, receiver);
        return typeof value === "function" && key !== "constructor"
          ? methodFor(target, key, value as Method)
          : value;
      },
    });
    proxies.set(model, proxy);
    shielded.add(proxy);
    return proxy;
  };

  /** Shields a chat model a method returned, or the one a runnable it returned is bound to. */
  const shieldResult = (value: unknown): unknown => {
    if (isChatModel(value)) {
      return shielded.has(value) ? value : wrap(value);
    }
    let node = value;
    for (let depth = 0; depth < 8 && isRecord(node); depth++) {
      const { bound } = node;
      if (isChatModel(bound)) {
        if (!shielded.has(bound)) {
          node.bound = wrap(bound);
        }
        break;
      }
      node = bound;
    }
    return value;
  };

  return wrap;
}

/**
 * Wraps a LangChain chat model (any `BaseChatModel`, such as `ChatOpenAI` or
 * `ChatAnthropic`) so `invoke`, `stream`, `batch`, and `streamEvents` are
 * guarded: system messages are hardened, human messages and tool messages
 * are checked for injections, and the AI message's text and tool call
 * arguments are guarded. Runnables made from it with `bindTools`,
 * `withConfig`, `withStructuredOutput`, or `pipe` keep the guard.
 *
 * @example
 * ```ts
 * import { ChatOpenAI } from "@langchain/openai";
 * import { shieldChatModel } from "@zeroleaks/shield/langchain";
 *
 * const model = shieldChatModel(new ChatOpenAI({ model: "gpt-5.5" }));
 * const reply = await model.invoke([
 *   ["system", "You are a support agent."],
 *   ["human", "Hi"],
 * ]);
 * ```
 */
export function shieldChatModel<
  // Method syntax makes the parameter check bivariant, so any chat model's
  // `invoke`, which takes specific input types, satisfies it.
  T extends ChatModelLike,
>(model: T, options: ShieldChatModelOptions = {}): T {
  if (!isChatModel(model)) {
    throw new TypeError(
      "shieldChatModel expects a LangChain chat model (one with _generate)"
    );
  }
  return createChatModelShield(options)(model) as T;
}

/** What a tool returned: a string, a ToolMessage, or anything else as JSON. */
function toolOutputText(output: unknown): string {
  if (typeof output === "string") {
    return output;
  }
  if (isRecord(output) && "content" in output) {
    return contentText(output.content);
  }
  return jsonText(output);
}

/** Runs the output guard over a generation without changing it. */
function inspectGeneration(
  generation: unknown,
  systemPrompt: string | undefined,
  output: OutputGuard
): void {
  if (!isRecord(generation)) {
    return;
  }
  const { message } = generation;
  if (!isRecord(message)) {
    if (typeof generation.text === "string" && generation.text) {
      output.text(generation.text, systemPrompt);
    }
    return;
  }
  const text = contentText(message.content, "");
  if (text) {
    output.text(text, systemPrompt);
  }
  const calls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
  for (const call of calls) {
    if (isRecord(call) && isRecord(call.args)) {
      output.value(call.args, systemPrompt);
    }
  }
  const invalid = Array.isArray(message.invalid_tool_calls)
    ? message.invalid_tool_calls
    : [];
  for (const call of invalid) {
    if (isRecord(call) && typeof call.args === "string" && call.args) {
      output.text(call.args, systemPrompt);
    }
  }
}

/**
 * Checks the runs it is attached to, for chains and agents you don't want to
 * wrap: human and tool messages at the start of a chat model run, tool
 * outputs, and retrieved documents for injections, and the model's output
 * for prompt leaks, credentials, exfiltration links, and canaries.
 *
 * Callbacks can stop a run by throwing, but can't change what flows through
 * it: nothing is redacted or hardened. Output findings are reported through
 * `onOutputFindings` and `onLeakDetected`, and only stop the run with
 * `throwOnLeak` or `blockOnOutputFindings`. With streaming, the output check
 * runs after the text was streamed, so it can only fail the run. Use
 * `shieldChatModel` to redact.
 *
 * @example
 * ```ts
 * const handler = new ShieldCallbackHandler({ blockOnOutputFindings: true });
 * await agent.invoke(input, { callbacks: [handler] });
 * ```
 */
export class ShieldCallbackHandler extends BaseCallbackHandler {
  name = "ShieldCallbackHandler";

  private readonly shield: Shield;
  private readonly systemPrompt: string | undefined;
  /** The system prompt of each chat model run in progress, by run id. */
  private readonly systemPrompts = new Map<string, string>();

  constructor(options: ShieldCallbackHandlerOptions = {}) {
    // Errors only reach the run from handlers LangChain awaits, which
    // raiseError turns on.
    super({ raiseError: true });
    this.shield = createShield(options);
    this.systemPrompt = options.systemPrompt;
  }

  /** Returns itself: its only state is keyed by run id, so copies can share it. */
  copy(): this {
    return this;
  }

  async handleChatModelStart(
    _llm: Serialized,
    messages: BaseMessage[][],
    runId: string
  ): Promise<void> {
    for (const group of messages) {
      await checkMessages(group, this.shield.input);
    }
    const systemPrompt = systemPromptOf(messages.flat());
    if (systemPrompt) {
      this.systemPrompts.set(runId, systemPrompt);
    }
  }

  handleLLMEnd(result: LLMResult, runId: string): void {
    const systemPrompt = this.systemPrompt ?? this.systemPrompts.get(runId);
    this.systemPrompts.delete(runId);
    const { output } = this.shield;
    if (!output.active(systemPrompt)) {
      return;
    }
    for (const generation of result.generations.flat()) {
      inspectGeneration(generation, systemPrompt, output);
    }
  }

  handleLLMError(_error: Error, runId: string): void {
    this.systemPrompts.delete(runId);
  }

  async handleToolEnd(output: unknown): Promise<void> {
    await this.shield.input.check(toolOutputText(output), "tool");
  }

  async handleRetrieverEnd(documents: DocumentInterface[]): Promise<void> {
    for (const document of documents) {
      await this.shield.input.check(document.pageContent, "tool");
    }
  }
}
