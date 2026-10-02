/**
 * `client.responses.create` for the OpenAI wrapper: hardens instructions,
 * checks user input and tool outputs, and guards the output text and
 * function call arguments, streamed or not.
 */

import { type HardenOptions, harden } from "../harden";
import {
  callProvider,
  type InputScope,
  type OutputGuard,
  type Shield,
  type ShieldProviderOptions,
  whenSettled,
} from "./guard";
import { chunkString, isAsyncIterable } from "./utils";

interface Part {
  type?: string;
  text?: unknown;
  [key: string]: unknown;
}

interface InputItem {
  type?: string;
  role?: string;
  content?: string | Part[];
  output?: unknown;
  [key: string]: unknown;
}

interface ResponsesParams {
  instructions?: unknown;
  input?: string | InputItem[];
  stream?: boolean;
  [key: string]: unknown;
}

interface OutputPart {
  type?: string;
  text?: string;
  logprobs?: unknown[];
  [key: string]: unknown;
}

interface OutputItem {
  id?: string;
  type?: string;
  content?: OutputPart[];
  arguments?: string;
  input?: string;
  [key: string]: unknown;
}

interface ResponseBody {
  output?: OutputItem[];
  output_text?: string;
  [key: string]: unknown;
}

interface StreamEvent {
  type?: string;
  item_id?: string;
  output_index?: number;
  content_index?: number;
  delta?: string;
  text?: string;
  arguments?: string;
  input?: string;
  sequence_number?: number;
  logprobs?: unknown[];
  part?: OutputPart;
  item?: OutputItem;
  response?: ResponseBody;
  [key: string]: unknown;
}

/** Input items that carry what a tool returned. Computer call outputs are screenshots. */
const TOOL_OUTPUT_TYPES = new Set([
  "function_call_output",
  "custom_tool_call_output",
  "mcp_call",
  "local_shell_call_output",
  "shell_call_output",
  "apply_patch_call_output",
]);

function isMessage(item: InputItem): boolean {
  return (
    typeof item.role === "string" &&
    (item.type === undefined || item.type === "message")
  );
}

function isSystemMessage(item: InputItem): boolean {
  return (
    isMessage(item) && (item.role === "system" || item.role === "developer")
  );
}

function inputText(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return "";
  }
  return content
    .filter(
      (p): p is Part & { text: string } =>
        p?.type === "input_text" && typeof p.text === "string"
    )
    .map((p) => p.text)
    .join(" ");
}

/** Text of a tool output: a string, or its text, stdout, and stderr parts. */
function toolOutputText(item: InputItem): string {
  const { output } = item;
  if (typeof output === "string") {
    return output;
  }
  if (!Array.isArray(output)) {
    return "";
  }
  const texts: string[] = [];
  for (const part of output) {
    if (!part || typeof part !== "object") {
      continue;
    }
    const { text, stdout, stderr } = part as Record<string, unknown>;
    for (const value of [text, stdout, stderr]) {
      if (typeof value === "string" && value) {
        texts.push(value);
      }
    }
  }
  return texts.join("\n");
}

/** `instructions` and the text of every system and developer message, joined. */
function systemText(params: ResponsesParams): string | undefined {
  const texts = [
    typeof params.instructions === "string" ? params.instructions : "",
    ...(Array.isArray(params.input) ? params.input : [])
      .filter(isSystemMessage)
      .map((item) => inputText(item.content)),
  ].filter(Boolean);
  return texts.length > 0 ? texts.join("\n") : undefined;
}

function hardenParams(
  params: ResponsesParams,
  items: InputItem[],
  options: HardenOptions
): void {
  if (typeof params.instructions === "string" && params.instructions) {
    params.instructions = harden(params.instructions, options);
  }
  for (const item of items) {
    const text = isSystemMessage(item) ? inputText(item.content) : "";
    if (!text) {
      continue;
    }
    const hardened = harden(text, options);
    item.content =
      typeof item.content === "string"
        ? hardened
        : [{ type: "input_text", text: hardened }];
  }
}

async function checkInput(
  params: ResponsesParams,
  items: InputItem[],
  input: InputScope
): Promise<void> {
  if (typeof params.input === "string") {
    await input.check(params.input, "user");
  }
  for (const item of items) {
    if (isMessage(item) && item.role === "user") {
      await input.check(inputText(item.content), "user");
    } else if (!isMessage(item) && TOOL_OUTPUT_TYPES.has(item.type ?? "")) {
      await input.check(toolOutputText(item), "tool");
    }
  }
}

/** Guards each text once per key, so every event that repeats it agrees. */
type Lookup = (key: string, text: string) => string;

function createLookup(
  output: OutputGuard,
  systemPrompt: string | undefined
): Lookup {
  const seen = new Map<string, { text: string; safe: string }>();
  return (key, text) => {
    const hit = seen.get(key);
    if (hit && hit.text === text) {
      return hit.safe;
    }
    const safe = output.text(text, systemPrompt);
    seen.set(key, { text, safe });
    return safe;
  };
}

const textKey = (itemId: unknown, contentIndex: unknown): string =>
  `text:${String(itemId)}:${String(contentIndex)}`;
const argumentsKey = (itemId: unknown): string => `args:${String(itemId)}`;
const inputKey = (itemId: unknown): string => `input:${String(itemId)}`;

/** A part with its text replaced, without the log probabilities of the old text. */
function withText(part: OutputPart, text: string): OutputPart {
  return Array.isArray(part.logprobs)
    ? { ...part, text, logprobs: [] }
    : { ...part, text };
}

function rewriteMessage(
  item: OutputItem & { content: OutputPart[] },
  id: string,
  lookup: Lookup
): OutputItem {
  let content: OutputPart[] | undefined;
  for (const [i, part] of item.content.entries()) {
    if (part?.type !== "output_text" || typeof part.text !== "string") {
      continue;
    }
    const safe = lookup(textKey(id, i), part.text);
    if (safe !== part.text) {
      content ??= [...item.content];
      content[i] = withText(part, safe);
    }
  }
  return content ? { ...item, content } : item;
}

/** Output items whose tool call arguments are guarded, and the field that holds them. */
const ARGUMENT_FIELDS: Record<string, "arguments" | "input"> = {
  function_call: "arguments",
  custom_tool_call: "input",
};

function rewriteItem(item: OutputItem, id: string, lookup: Lookup): OutputItem {
  if (item?.type === "message" && Array.isArray(item.content)) {
    return rewriteMessage(
      item as OutputItem & { content: OutputPart[] },
      id,
      lookup
    );
  }
  const field = ARGUMENT_FIELDS[item?.type ?? ""];
  const value = field ? item[field] : undefined;
  if (!field || typeof value !== "string") {
    return item;
  }
  const safe = lookup(
    field === "arguments" ? argumentsKey(id) : inputKey(id),
    value
  );
  return safe === value ? item : { ...item, [field]: safe };
}

/** What the SDK's `output_text` holds: every output text part, joined. */
function joinOutputText(items: OutputItem[]): string {
  let text = "";
  for (const item of items) {
    if (item?.type !== "message" || !Array.isArray(item.content)) {
      continue;
    }
    for (const part of item.content) {
      if (part?.type === "output_text" && typeof part.text === "string") {
        text += part.text;
      }
    }
  }
  return text;
}

/** The response with its output rewritten, or `undefined` if nothing changed. */
function rewriteResponse(
  response: ResponseBody,
  lookup: Lookup
): ResponseBody | undefined {
  if (!Array.isArray(response?.output)) {
    return;
  }
  let changed = false;
  const output = response.output.map((item, i) => {
    const next = rewriteItem(item, item?.id ?? `#${i}`, lookup);
    changed ||= next !== item;
    return next;
  });
  if (!changed) {
    return;
  }
  return typeof response.output_text === "string"
    ? { ...response, output, output_text: joinOutputText(output) }
    : { ...response, output };
}

/** `deltas` as they were, or `safe` in 64-character deltas shaped like them. */
function* replaceDeltas(
  deltas: StreamEvent[],
  text: string,
  safe: string
): Generator<StreamEvent> {
  if (safe === text) {
    yield* deltas;
    return;
  }
  const [template] = deltas;
  if (!template) {
    return;
  }
  // Each piece takes the sequence number of the delta in its place, and the
  // pieces past the last delta take that delta's.
  const lastIndex = deltas.length - 1;
  let i = 0;
  for (const piece of chunkString(safe)) {
    const event: StreamEvent = { ...template, delta: piece };
    const sequence = deltas[Math.min(i, lastIndex)].sequence_number;
    if (sequence !== undefined) {
      event.sequence_number = sequence;
    }
    if (Array.isArray(template.logprobs)) {
      event.logprobs = [];
    }
    i++;
    yield event;
  }
}

interface StreamGuard {
  handle(event: StreamEvent): Iterable<StreamEvent>;
  /** Deltas whose done event never came. */
  finish(): Iterable<StreamEvent>;
}

/**
 * Holds back text, function call argument, and custom tool input deltas
 * until their `done` event, guards the full text, and re-emits it in 64-character deltas
 * shaped like the originals. Events that repeat the text (content part,
 * output item, and the final response) carry the guarded version. Every other
 * event passes through in order.
 */
function createStreamGuard(lookup: Lookup): StreamGuard {
  const held = new Map<string, StreamEvent[]>();
  const hold = (key: string, event: StreamEvent): StreamEvent[] => {
    const deltas = held.get(key);
    if (deltas) {
      deltas.push(event);
    } else {
      held.set(key, [event]);
    }
    return [];
  };

  function* release(
    key: string,
    done: StreamEvent,
    field: "text" | "arguments" | "input"
  ): Generator<StreamEvent> {
    const deltas = held.get(key) ?? [];
    held.delete(key);
    const streamed = deltas.map((d) => d.delta ?? "").join("");
    const value = done[field];
    const full = typeof value === "string" ? value : streamed;
    const safe = lookup(key, full);
    yield* replaceDeltas(deltas, streamed, safe);
    if (safe === full) {
      yield done;
      return;
    }
    const event: StreamEvent = { ...done, [field]: safe };
    if (Array.isArray(done.logprobs)) {
      event.logprobs = [];
    }
    yield event;
  }

  const rewritePart = (event: StreamEvent): StreamEvent => {
    const { part } = event;
    if (part?.type !== "output_text" || typeof part.text !== "string") {
      return event;
    }
    const safe = lookup(textKey(event.item_id, event.content_index), part.text);
    return safe === part.text
      ? event
      : { ...event, part: withText(part, safe) };
  };

  const rewriteDoneItem = (event: StreamEvent): StreamEvent => {
    const { item } = event;
    if (!item) {
      return event;
    }
    const next = rewriteItem(
      item,
      item.id ?? `#${String(event.output_index)}`,
      lookup
    );
    return next === item ? event : { ...event, item: next };
  };

  const rewriteFinal = (event: StreamEvent): StreamEvent => {
    const next = event.response
      ? rewriteResponse(event.response, lookup)
      : undefined;
    return next ? { ...event, response: next } : event;
  };

  const handlers: Record<
    string,
    (event: StreamEvent) => Iterable<StreamEvent>
  > = {
    "response.output_text.delta": (e) =>
      hold(textKey(e.item_id, e.content_index), e),
    "response.function_call_arguments.delta": (e) =>
      hold(argumentsKey(e.item_id), e),
    "response.output_text.done": (e) =>
      release(textKey(e.item_id, e.content_index), e, "text"),
    "response.function_call_arguments.done": (e) =>
      release(argumentsKey(e.item_id), e, "arguments"),
    "response.custom_tool_call_input.delta": (e) =>
      hold(inputKey(e.item_id), e),
    "response.custom_tool_call_input.done": (e) =>
      release(inputKey(e.item_id), e, "input"),
    "response.content_part.done": (e) => [rewritePart(e)],
    "response.output_item.done": (e) => [rewriteDoneItem(e)],
    "response.completed": (e) => [rewriteFinal(e)],
    "response.incomplete": (e) => [rewriteFinal(e)],
    "response.failed": (e) => [rewriteFinal(e)],
  };

  return {
    handle(event) {
      const handler = handlers[event?.type ?? ""];
      return handler ? handler(event) : [event];
    },
    *finish() {
      for (const [key, deltas] of held) {
        const text = deltas.map((d) => d.delta ?? "").join("");
        yield* replaceDeltas(deltas, text, lookup(key, text));
      }
      held.clear();
    },
  };
}

async function* guardStream(
  stream: AsyncIterable<StreamEvent>,
  lookup: Lookup
): AsyncGenerator<StreamEvent> {
  const guard = createStreamGuard(lookup);
  for await (const event of stream) {
    yield* guard.handle(event);
  }
  yield* guard.finish();
}

/** Guards a non-streamed response in place. */
function guardResponse(response: unknown, lookup: Lookup): void {
  if (!response || typeof response !== "object") {
    return;
  }
  const body = response as ResponseBody;
  const next = rewriteResponse(body, lookup);
  if (!next) {
    return;
  }
  body.output = next.output;
  if (typeof next.output_text === "string") {
    body.output_text = next.output_text;
  }
}

/**
 * Wraps `responses.create`. `"chunked"` streaming works like `"buffer"`: each
 * text is held until its `done` event.
 */
export function shieldResponsesCreate(
  originalCreate: (...args: unknown[]) => unknown,
  options: ShieldProviderOptions,
  shield: Shield
): (...args: unknown[]) => Promise<unknown> {
  return async (...args: unknown[]) => {
    const original = (args[0] as ResponsesParams) ?? {};
    const params: ResponsesParams = {
      ...original,
      input: Array.isArray(original.input)
        ? original.input.map((item) => ({ ...item }))
        : original.input,
    };
    args[0] = params;

    const systemPrompt = options.systemPrompt ?? systemText(params);
    const items = Array.isArray(params.input) ? params.input : [];
    if (shield.harden) {
      hardenParams(params, items, shield.harden);
    }
    const scope = shield.input.begin();
    await checkInput(params, items, scope);

    const response = await callProvider(scope, () => originalCreate(...args));
    const { output } = shield;
    if (!output.active(systemPrompt)) {
      return whenSettled(scope, response);
    }
    const lookup = createLookup(output, systemPrompt);
    if (params.stream === true && isAsyncIterable<StreamEvent>(response)) {
      return options.streamingSanitize === "passthrough"
        ? whenSettled(scope, response)
        : guardStream(await whenSettled(scope, response), lookup);
    }
    await whenSettled(scope, response);
    guardResponse(response, lookup);
    return response;
  };
}
