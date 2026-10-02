/**
 * Wraps a Mistral client (`@mistralai/mistralai`): `chat.complete` and
 * `chat.stream`.
 */

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
import {
  chunkedReplay,
  createSlotSanitizer,
  hardenTextItems,
  isRecord,
  rewriteSlots,
  streamLike,
  type TextSlot,
  withOverrides,
} from "./shared";
import { isAsyncIterable } from "./utils";

export interface ShieldMistralOptions extends ShieldProviderOptions {}

interface ContentChunk {
  type?: string;
  text?: unknown;
  [key: string]: unknown;
}

interface ToolCall {
  index?: number;
  function?: { arguments?: unknown; [key: string]: unknown };
  [key: string]: unknown;
}

interface Message {
  role?: string;
  content?: string | ContentChunk[] | null;
  toolCalls?: ToolCall[] | null;
  [key: string]: unknown;
}

interface Choice {
  index?: number;
  message?: Message;
  messages?: Message[];
  delta?: Message;
  [key: string]: unknown;
}

interface Completion {
  choices?: Choice[];
  [key: string]: unknown;
}

/** What `chat.stream` yields: server-sent events that carry a completion chunk. */
interface CompletionEvent {
  data?: Completion;
  [key: string]: unknown;
}

interface Request {
  messages?: Message[];
  [key: string]: unknown;
}

/** Text chunks may leave out their type. Thinking chunks are left out. */
function isTextChunk(chunk: unknown): chunk is ContentChunk & { text: string } {
  return (
    isRecord(chunk) &&
    typeof chunk.text === "string" &&
    (chunk.type === undefined || chunk.type === "text")
  );
}

function chunkText(chunk: unknown): string {
  return isTextChunk(chunk) ? chunk.text : "";
}

function contentText(content: Message["content"]): string {
  if (typeof content === "string") {
    return content;
  }
  return Array.isArray(content)
    ? content.map(chunkText).filter(Boolean).join("\n")
    : "";
}

function hardenContent(
  content: Message["content"],
  options: HardenOptions
): Message["content"] {
  if (typeof content === "string") {
    return content ? harden(content, options) : content;
  }
  if (!Array.isArray(content)) {
    return content;
  }
  return hardenTextItems(
    content,
    chunkText,
    (chunk, text) => ({ ...chunk, text }),
    options
  );
}

function hardenSystemMessages(
  messages: Message[],
  options: HardenOptions
): void {
  for (const message of messages) {
    if (message?.role === "system") {
      message.content = hardenContent(message.content, options);
    }
  }
}

async function checkMessages(
  messages: Message[],
  input: InputScope
): Promise<void> {
  for (const message of messages) {
    if (message?.role === "user") {
      await input.check(contentText(message.content), "user");
    } else if (message?.role === "tool") {
      await input.check(contentText(message.content), "tool");
    }
  }
}

/** The text of a message's content, as slots under `key`. */
function contentSlots(message: Message, key: string): TextSlot[] {
  const { content } = message;
  if (typeof content === "string") {
    return [
      {
        key,
        text: content,
        set: (text) => {
          message.content = text;
        },
      },
    ];
  }
  if (!Array.isArray(content)) {
    return [];
  }
  return content.filter(isTextChunk).map((chunk) => ({
    key,
    text: chunk.text,
    set: (text: string) => {
      chunk.text = text;
    },
  }));
}

const choiceKey = (choice: Choice, position: number): string =>
  String(choice?.index ?? position);

/** Guards arguments given as an object, in place. Returns the string ones as slots. */
function toolCallSlots(
  message: Message,
  key: string,
  systemPrompt: string | undefined,
  output: OutputGuard
): TextSlot[] {
  const slots: TextSlot[] = [];
  for (const [position, call] of (message.toolCalls ?? []).entries()) {
    const fn = call?.function;
    if (!isRecord(fn)) {
      continue;
    }
    if (typeof fn.arguments === "string") {
      slots.push({
        key: `${key}:tool:${call.index ?? position}`,
        text: fn.arguments,
        set: (text) => {
          fn.arguments = text;
        },
      });
    } else if (isRecord(fn.arguments)) {
      fn.arguments = output.value(fn.arguments, systemPrompt);
    }
  }
  return slots;
}

/** Guards the text and tool call arguments of every message of a completion, in place. */
function guardCompletion(
  response: unknown,
  systemPrompt: string | undefined,
  output: OutputGuard
): void {
  const choices = (response as Completion | undefined)?.choices;
  if (!Array.isArray(choices)) {
    return;
  }
  const guard = (text: string): string => output.text(text, systemPrompt);
  for (const [position, choice] of choices.entries()) {
    const messages = [choice?.message, ...(choice?.messages ?? [])];
    for (const [i, message] of messages.entries()) {
      if (!isRecord(message)) {
        continue;
      }
      const key = `${choiceKey(choice, position)}:${i}`;
      rewriteSlots(contentSlots(message, key), guard);
      for (const slot of toolCallSlots(message, key, systemPrompt, output)) {
        rewriteSlots([slot], guard);
      }
    }
  }
}

/** The text and string tool call arguments of every delta in an event. */
function eventSlots(
  event: CompletionEvent,
  systemPrompt: string | undefined,
  output: OutputGuard
): { text: TextSlot[]; args: TextSlot[] } {
  const text: TextSlot[] = [];
  const args: TextSlot[] = [];
  for (const [position, choice] of (event?.data?.choices ?? []).entries()) {
    const { delta } = choice ?? {};
    if (!isRecord(delta)) {
      continue;
    }
    const key = choiceKey(choice, position);
    text.push(...contentSlots(delta, key));
    args.push(...toolCallSlots(delta, key, systemPrompt, output));
  }
  return { text, args };
}

/**
 * Reads the whole stream, guards each choice's full text and each tool
 * call's full arguments, and replays the events with them rewritten in
 * place. Nothing else in them changes.
 */
async function bufferStream(
  stream: AsyncIterable<CompletionEvent>,
  systemPrompt: string | undefined,
  output: OutputGuard
): Promise<AsyncGenerator<CompletionEvent>> {
  const events: CompletionEvent[] = [];
  for await (const event of stream) {
    events.push(event);
  }
  const slots = events.flatMap((event) => {
    const { text, args } = eventSlots(event, systemPrompt, output);
    return [...text, ...args];
  });
  rewriteSlots(slots, (text) => output.text(text, systemPrompt));
  return (async function* () {
    yield* events;
  })();
}

/** Adds `text` to the content of choice `key` in `event`. */
function appendText(event: CompletionEvent, key: string, text: string): void {
  event.data ??= {};
  event.data.choices ??= [];
  let choice = event.data.choices.find(
    (c, position) => choiceKey(c, position) === key
  );
  if (!choice) {
    choice = { index: Number(key), delta: {}, finishReason: null };
    event.data.choices.push(choice);
  }
  choice.delta ??= {};
  const { delta } = choice;
  const { content } = delta;
  if (typeof content === "string") {
    delta.content = content + text;
    return;
  }
  if (!Array.isArray(content)) {
    delta.content = text;
    return;
  }
  const last = content.filter(isTextChunk).pop();
  if (last) {
    last.text += text;
  } else {
    content.push({ type: "text", text });
  }
}

/**
 * Guards each choice's text in chunks. Tool call arguments, which Mistral
 * sends whole in one delta, are guarded delta by delta.
 */
function chunkedStream(
  stream: AsyncIterable<CompletionEvent>,
  systemPrompt: string | undefined,
  output: OutputGuard,
  options: ShieldMistralOptions
): AsyncGenerator<CompletionEvent> {
  const sanitizer = createSlotSanitizer(systemPrompt ?? "", output, options);
  const guard = (text: string): string => output.text(text, systemPrompt);
  return chunkedReplay(
    stream,
    sanitizer,
    (event) => {
      const { text, args } = eventSlots(event, systemPrompt, output);
      for (const slot of args) {
        rewriteSlots([slot], guard);
      }
      return text;
    },
    appendText
  );
}

type Method = (...args: unknown[]) => Promise<unknown>;

interface Chat {
  complete(...args: unknown[]): unknown;
  stream(...args: unknown[]): unknown;
}

export function shieldMistral<
  // Method syntax makes the parameter check bivariant, so the SDK's `chat`,
  // whose methods take specific request types, satisfies it.
  T extends { chat: Chat },
>(client: T, options: ShieldMistralOptions = {}): T {
  const shield = createShield(options);
  const { chat } = client;

  /** Copies, hardens, and checks the request. Returns it and its system prompt. */
  const prepare = async (
    request: unknown,
    scope: InputScope
  ): Promise<{ params: Request; systemPrompt: string | undefined }> => {
    const original = (request ?? {}) as Request;
    const messages = Array.isArray(original.messages)
      ? original.messages.map((m) => ({ ...m }))
      : undefined;
    const params: Request = messages
      ? { ...original, messages }
      : { ...original };
    const system = messages?.find((m) => m?.role === "system");
    const systemPrompt =
      options.systemPrompt ??
      ((system && contentText(system.content)) || undefined);
    if (messages) {
      if (shield.harden) {
        hardenSystemMessages(messages, shield.harden);
      }
      await checkMessages(messages, scope);
    }
    return { params, systemPrompt };
  };

  const complete: Method = async (request, ...rest) => {
    const scope = shield.input.begin();
    const { params, systemPrompt } = await prepare(request, scope);
    const response = await callProvider(scope, () =>
      chat.complete(params, ...rest)
    );
    await whenSettled(scope, response);
    if (shield.output.active(systemPrompt)) {
      guardCompletion(response, systemPrompt, shield.output);
    }
    return response;
  };

  const stream: Method = async (request, ...rest) => {
    const scope = shield.input.begin();
    const { params, systemPrompt } = await prepare(request, scope);
    const events = await callProvider(scope, () =>
      chat.stream(params, ...rest)
    );
    const mode = options.streamingSanitize ?? "buffer";
    if (
      mode === "passthrough" ||
      !shield.output.active(systemPrompt) ||
      !isAsyncIterable<CompletionEvent>(events)
    ) {
      return whenSettled(scope, events);
    }
    const guarded =
      mode === "chunked"
        ? chunkedStream(
            await whenSettled(scope, events),
            systemPrompt,
            shield.output,
            options
          )
        : await bufferStream(
            endWhenSettled(scope, events),
            systemPrompt,
            shield.output
          );
    return streamLike(guarded, events);
  };

  return withOverrides(client, {
    chat: withOverrides(chat, { complete, stream }),
  });
}
