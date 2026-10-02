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
  createSlotSanitizer,
  type SlotSanitizer,
  type TextSlot,
  withOverrides,
} from "./shared";
import { chunkString, isAsyncIterable } from "./utils";

export interface ShieldAnthropicOptions extends ShieldProviderOptions {}

type MessageContent = string | Array<{ type: string; text: string }>;

interface Block {
  type?: string;
  text?: unknown;
  content?: unknown;
  source?: unknown;
  [key: string]: unknown;
}

interface StreamEvent {
  type?: string;
  index?: number;
  delta?: {
    type?: string;
    text?: string;
    partial_json?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

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

function isBlock(value: unknown): value is Block {
  return typeof value === "object" && value !== null;
}

/** Text of the text blocks in `blocks`. */
function textBlocks(blocks: unknown): string {
  if (!Array.isArray(blocks)) {
    return "";
  }
  return blocks
    .filter(
      (b): b is Block & { text: string } =>
        isBlock(b) && b.type === "text" && typeof b.text === "string"
    )
    .map((b) => b.text)
    .join("\n");
}

/** Text of a document block with a plain text or content source. PDFs and URLs are not read. */
function documentText(block: unknown): string {
  if (!(isBlock(block) && isBlock(block.source))) {
    return "";
  }
  const { source } = block;
  if (source.type === "text" && typeof source.data === "string") {
    return source.data;
  }
  if (source.type === "content") {
    return typeof source.content === "string"
      ? source.content
      : textBlocks(source.content);
  }
  return "";
}

/** Text of the blocks a tool result holds: text, documents, and search results. */
function nestedText(blocks: unknown[]): string {
  const texts: string[] = [];
  for (const block of blocks) {
    if (!isBlock(block)) {
      continue;
    }
    if (block.type === "text" && typeof block.text === "string") {
      texts.push(block.text);
    } else if (block.type === "document") {
      texts.push(documentText(block));
    } else if (block.type === "search_result") {
      texts.push(textBlocks(block.content));
    }
  }
  return texts.filter(Boolean).join("\n");
}

/**
 * Text the model reads from outside the conversation: tool results,
 * documents, search results, and fetched web pages. `undefined` for any
 * other block.
 */
function externalText(block: Block): string | undefined {
  switch (block.type) {
    case "tool_result":
      if (typeof block.content === "string") {
        return block.content;
      }
      return Array.isArray(block.content) ? nestedText(block.content) : "";
    case "document":
      return documentText(block);
    case "search_result":
      return textBlocks(block.content);
    case "web_fetch_tool_result":
      return isBlock(block.content) && block.content.type === "web_fetch_result"
        ? documentText(block.content.content)
        : "";
    default:
      return;
  }
}

async function checkMessages(
  messages: Array<{ role: string; content: MessageContent }>,
  input: InputScope
): Promise<void> {
  for (const msg of messages) {
    if (msg.role === "user") {
      await input.check(extractText(msg.content), "user");
    }
    if (!(input.tool && Array.isArray(msg.content))) {
      continue;
    }
    for (const block of msg.content as unknown[]) {
      const text = isBlock(block) ? externalText(block) : undefined;
      if (text) {
        await input.check(text, "tool");
      }
    }
  }
}

/**
 * Replays the events with each rewritten text and tool input in place of the
 * original. A rewritten text replaces its first non-empty delta with
 * 64-character deltas; a rewritten tool input goes out whole in its first
 * delta. Their other deltas are dropped.
 */
function* rewriteEvents(
  events: StreamEvent[],
  rewritten: Map<string, Segment>
): Generator<StreamEvent> {
  const started = new Set<string>();
  for (const event of events) {
    const key = blockKey(event);
    const segment = key === undefined ? undefined : rewritten.get(key);
    const current = segment ? event.delta?.[segment.field] : undefined;
    if (!(segment && key !== undefined && typeof current === "string")) {
      yield event;
      continue;
    }
    if (!current || started.has(key)) {
      continue;
    }
    started.add(key);
    const pieces =
      segment.field === "text" ? chunkString(segment.text) : [segment.text];
    for (const piece of pieces) {
      yield { ...event, delta: { ...event.delta, [segment.field]: piece } };
    }
  }
}

/** The streamed text of one content block: its text or its tool input JSON. */
interface Segment {
  field: "text" | "partial_json";
  text: string;
}

/** The content block a delta event belongs to. */
function blockKey(event: StreamEvent): string | undefined {
  return event?.type === "content_block_delta" && event.delta
    ? String(event.index ?? 0)
    : undefined;
}

function segmentField(event: StreamEvent): Segment["field"] | undefined {
  if (typeof event.delta?.text === "string") {
    return "text";
  }
  if (typeof event.delta?.partial_json === "string") {
    return "partial_json";
  }
}

/**
 * Reads the whole stream, guards the full text and tool input of each
 * content block, and replays the events. Nothing else in them changes.
 */
async function bufferStream(
  stream: AsyncIterable<StreamEvent>,
  systemPrompt: string | undefined,
  output: OutputGuard
): Promise<AsyncIterable<StreamEvent>> {
  const events: StreamEvent[] = [];
  const segments = new Map<string, Segment>();
  for await (const event of stream) {
    events.push(event);
    const key = blockKey(event);
    const field = key === undefined ? undefined : segmentField(event);
    if (key === undefined || !field) {
      continue;
    }
    const segment = segments.get(key) ?? { field, text: "" };
    segment.text += event.delta?.[field] ?? "";
    segments.set(key, segment);
  }

  const rewritten = new Map<string, Segment>();
  for (const [key, segment] of segments) {
    const safe = segment.text
      ? output.text(segment.text, systemPrompt)
      : segment.text;
    if (safe !== segment.text) {
      rewritten.set(key, { field: segment.field, text: safe });
    }
  }
  const replay =
    rewritten.size === 0 ? events : rewriteEvents(events, rewritten);
  return (async function* () {
    yield* replay;
  })();
}

/** A content block being streamed in chunked mode. */
interface OpenBlock {
  sanitizer: SlotSanitizer;
  field: Segment["field"];
  /** The block's last delta event, the shape for what is flushed. */
  template: StreamEvent;
}

/**
 * Guards the text and tool input JSON of each content block in chunks and
 * replays the events with the guarded text in place of the original. Delta
 * events whose text is all held back are left out, and what a block still
 * holds back goes out in one more delta ahead of its `content_block_stop`.
 * Every other event passes through in order. With `throwOnLeak`, a leak is
 * thrown once everything was emitted.
 */
async function* chunkedStream(
  stream: AsyncIterable<StreamEvent>,
  systemPrompt: string | undefined,
  output: OutputGuard,
  options: ShieldAnthropicOptions
): AsyncGenerator<StreamEvent> {
  const open = new Map<string, OpenBlock>();
  const finished: SlotSanitizer[] = [];

  function* flush(key: string): Generator<StreamEvent> {
    const block = open.get(key);
    if (!block) {
      return;
    }
    open.delete(key);
    finished.push(block.sanitizer);
    const text = block.sanitizer.flush().get(key);
    if (text) {
      const { template, field } = block;
      yield { ...template, delta: { ...template.delta, [field]: text } };
    }
  }

  for await (const event of stream) {
    const key = blockKey(event);
    const field = key === undefined ? undefined : segmentField(event);
    if (key === undefined || !field) {
      if (event?.type === "content_block_stop") {
        yield* flush(String(event.index ?? 0));
      }
      yield event;
      continue;
    }
    let block = open.get(key);
    if (!block) {
      block = {
        sanitizer: createSlotSanitizer(systemPrompt ?? "", output, options),
        field,
        template: event,
      };
      open.set(key, block);
    }
    block.template = event;
    const delta = { ...event.delta };
    const slot: TextSlot = {
      key,
      text: delta[field] ?? "",
      set: (text) => {
        delta[field] = text;
      },
    };
    block.sanitizer.push([slot]);
    if (delta[field]) {
      yield { ...event, delta };
    }
  }
  for (const key of [...open.keys()]) {
    yield* flush(key);
  }
  for (const sanitizer of finished) {
    sanitizer.finish();
  }
}

async function guardStream(
  stream: AsyncIterable<StreamEvent>,
  systemPrompt: string | undefined,
  output: OutputGuard,
  options: ShieldAnthropicOptions,
  scope: InputScope
): Promise<AsyncIterable<StreamEvent>> {
  const mode = options.streamingSanitize ?? "buffer";
  if (mode === "passthrough") {
    return whenSettled(scope, stream);
  }
  return mode === "chunked"
    ? chunkedStream(
        await whenSettled(scope, stream),
        systemPrompt,
        output,
        options
      )
    : await bufferStream(endWhenSettled(scope, stream), systemPrompt, output);
}

/** Guards text blocks and tool inputs of a message, in place. */
function guardMessage(
  response: unknown,
  systemPrompt: string | undefined,
  output: OutputGuard
): void {
  const content = (response as { content?: Block[] } | undefined)?.content;
  if (!Array.isArray(content)) {
    return;
  }
  for (const block of content) {
    if (block?.type === "text" && typeof block.text === "string") {
      block.text = output.text(block.text, systemPrompt);
    }
    if (
      block?.type === "tool_use" &&
      block.input &&
      typeof block.input === "object"
    ) {
      block.input = output.value(block.input, systemPrompt);
    }
  }
}

type System = string | Array<{ type: string; text: string }>;

function systemText(system: System | undefined): string | undefined {
  if (typeof system === "string") {
    return system;
  }
  if (!Array.isArray(system)) {
    return;
  }
  return system
    .filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join(" ");
}

function hardenSystem(system: System, options: HardenOptions): System {
  if (typeof system === "string") {
    return harden(system, options);
  }
  if (!Array.isArray(system)) {
    return system;
  }
  return system.map((b) =>
    b.type === "text" && typeof b.text === "string"
      ? { ...b, text: harden(b.text, options) }
      : b
  );
}

export function shieldAnthropic<
  // Method syntax makes the parameter check bivariant, so the SDK client's
  // `create` overloads, which take specific param types, satisfy it.
  T extends { messages: { create(...args: unknown[]): unknown } },
>(client: T, options: ShieldAnthropicOptions = {}): T {
  const shield = createShield(options);
  const { messages } = client;
  const originalCreate = messages.create.bind(messages);

  const wrappedCreate = async (...args: unknown[]) => {
    const originalParams =
      (args[0] as {
        system?: System;
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
      options.systemPrompt ?? systemText(params.system);
    if (shield.harden && params.system) {
      params.system = hardenSystem(params.system, shield.harden);
    }
    const scope = shield.input.begin();
    if (params.messages) {
      await checkMessages(params.messages, scope);
    }

    const response = await callProvider(scope, () => originalCreate(...args));
    if (!shield.output.active(derivedSystemPrompt)) {
      return whenSettled(scope, response);
    }
    if (
      originalParams.stream === true &&
      isAsyncIterable<StreamEvent>(response)
    ) {
      return guardStream(
        response,
        derivedSystemPrompt,
        shield.output,
        options,
        scope
      );
    }
    await whenSettled(scope, response);
    guardMessage(response, derivedSystemPrompt, shield.output);
    return response;
  };

  return withOverrides(client, {
    messages: withOverrides(messages, { create: wrappedCreate }),
  });
}
