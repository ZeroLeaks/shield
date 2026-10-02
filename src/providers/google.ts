/**
 * Wraps a Google Gen AI SDK client (`@google/genai`): `models.generateContent`,
 * `models.generateContentStream`, and chats created from `chats.create`.
 */

import { type HardenOptions, harden } from "../harden";
import {
  callProvider,
  createShield,
  endWhenSettled,
  type InputGuard,
  type InputScope,
  jsonText,
  type OutputGuard,
  prefetchWhenSettled,
  type ShieldProviderOptions,
  whenSettled,
} from "./guard";
import {
  chunkedReplay,
  createSlotSanitizer,
  decodeTextBlob,
  hardenTextItems,
  isRecord,
  rewriteSlots,
  type TextSlot,
  withOverrides,
} from "./shared";
import { isAsyncIterable } from "./utils";

export interface ShieldGoogleGenAIOptions extends ShieldProviderOptions {}

interface Part {
  text?: unknown;
  thought?: unknown;
  functionCall?: unknown;
  functionResponse?: unknown;
  inlineData?: unknown;
  [key: string]: unknown;
}

interface Content {
  role?: string;
  parts?: Part[];
  [key: string]: unknown;
}

interface Candidate {
  index?: number;
  content?: Content;
  logprobsResult?: unknown;
  [key: string]: unknown;
}

interface Response {
  candidates?: Candidate[];
  [key: string]: unknown;
}

interface Config {
  systemInstruction?: unknown;
  tools?: unknown;
  [key: string]: unknown;
}

interface Params {
  contents?: unknown;
  config?: Config;
  [key: string]: unknown;
}

/** A tool the SDK calls itself during automatic function calling. */
interface CallableTool {
  callTool(calls: unknown): Promise<unknown>;
}

function isContent(value: unknown): value is Content {
  return isRecord(value) && Array.isArray(value.parts);
}

/** Whether `part` is answer text: text that is not a thought. */
function isAnswerText(part: unknown): part is Part & { text: string } {
  return (
    isRecord(part) && typeof part.text === "string" && part.thought !== true
  );
}

/** Text of a part the model reads as text. Thoughts are left out. */
function partText(part: unknown): string {
  return isAnswerText(part) ? part.text : "";
}

/** Text of a string or a part, as `contents` and `systemInstruction` allow. */
function itemText(item: unknown): string {
  return typeof item === "string" ? item : partText(item);
}

function toPart(item: unknown): Part {
  if (typeof item === "string") {
    return { text: item };
  }
  return isRecord(item) ? item : {};
}

/**
 * `contents` as a list of contents, the way the SDK reads it: a string, a
 * part, or a list of parts is one user turn.
 */
function toContents(contents: unknown): Content[] {
  if (Array.isArray(contents)) {
    if (contents.length === 0) {
      return [];
    }
    return isContent(contents[0])
      ? contents.filter(isContent)
      : [{ role: "user", parts: contents.map(toPart) }];
  }
  if (isContent(contents)) {
    return [contents];
  }
  return contents === undefined || contents === null
    ? []
    : [{ role: "user", parts: [toPart(contents)] }];
}

function systemText(instruction: unknown): string {
  if (Array.isArray(instruction)) {
    return instruction.map(itemText).filter(Boolean).join("\n");
  }
  if (isContent(instruction)) {
    return systemText(instruction.parts);
  }
  return itemText(instruction);
}

function withItemText(item: unknown, text: string): unknown {
  return isRecord(item) ? { ...item, text } : text;
}

/** Hardens `systemInstruction` in the shape it came in. */
function hardenInstruction(
  instruction: unknown,
  options: HardenOptions
): unknown {
  if (Array.isArray(instruction)) {
    return hardenTextItems(instruction, itemText, withItemText, options);
  }
  if (isContent(instruction)) {
    return {
      ...instruction,
      parts: hardenTextItems(
        instruction.parts ?? [],
        partText,
        (part, text) => ({ ...part, text }),
        options
      ),
    };
  }
  const text = itemText(instruction);
  return text ? withItemText(instruction, harden(text, options)) : instruction;
}

/** Text of inline data sent as a text document, up to 64KB. */
function inlineText(blob: unknown): string {
  return isRecord(blob) ? decodeTextBlob(blob.data, blob.mimeType) : "";
}

/** Text the model reads from outside the conversation: tool results and inline text documents. */
function externalText(part: unknown): string {
  if (!isRecord(part)) {
    return "";
  }
  if (isRecord(part.functionResponse)) {
    return jsonText(part.functionResponse.response);
  }
  return inlineText(part.inlineData);
}

async function checkParts(
  parts: unknown,
  input: Pick<InputScope, "check">
): Promise<void> {
  if (!Array.isArray(parts)) {
    return;
  }
  for (const part of parts) {
    const text = externalText(part);
    if (text) {
      await input.check(text, "tool");
    }
  }
}

async function checkContents(
  contents: unknown,
  input: InputScope
): Promise<void> {
  for (const content of toContents(contents)) {
    const parts = content.parts ?? [];
    if ((content.role ?? "user") === "user") {
      await input.check(parts.map(partText).filter(Boolean).join("\n"), "user");
    }
    if (input.tool) {
      await checkParts(parts, input);
    }
  }
}

function isCallableTool(tool: unknown): tool is CallableTool {
  return isRecord(tool) && typeof tool.callTool === "function";
}

/**
 * `tool` with the results of `callTool` checked before the SDK sends them
 * to the model, as it does during automatic function calling.
 */
function guardCallableTool(tool: CallableTool, input: InputGuard): object {
  return withOverrides(tool, {
    callTool: async (calls: unknown) => {
      const parts = await tool.callTool(calls);
      await checkParts(parts, input);
      return parts;
    },
  });
}

/**
 * `tool` running the calls the SDK makes during automatic function calling
 * only once every verdict `scope` started is in.
 */
function holdCallableTool(tool: CallableTool, scope: InputScope): object {
  return withOverrides(tool, {
    callTool: async (calls: unknown) => {
      await scope.settle();
      return tool.callTool(calls);
    },
  });
}

const candidateKey = (candidate: Candidate, position: number): string =>
  String(candidate?.index ?? position);

/** Guards the arguments of a function call part, in place. */
function guardFunctionCall(
  part: Part,
  systemPrompt: string | undefined,
  output: OutputGuard
): void {
  const call = part.functionCall;
  if (!isRecord(call)) {
    return;
  }
  if (isRecord(call.args)) {
    call.args = output.value(call.args, systemPrompt);
  }
  if (Array.isArray(call.partialArgs)) {
    call.partialArgs = output.value(call.partialArgs, systemPrompt);
  }
}

/**
 * The answer text parts of every candidate in a response, keyed by
 * candidate. Function call arguments are guarded on the way, in place.
 */
function responseSlots(
  response: unknown,
  systemPrompt: string | undefined,
  output: OutputGuard
): TextSlot[] {
  const candidates = (response as Response | undefined)?.candidates;
  if (!Array.isArray(candidates)) {
    return [];
  }
  const slots: TextSlot[] = [];
  for (const [position, candidate] of candidates.entries()) {
    const parts = candidate?.content?.parts;
    if (!Array.isArray(parts)) {
      continue;
    }
    const key = candidateKey(candidate, position);
    for (const part of parts) {
      if (!isRecord(part)) {
        continue;
      }
      guardFunctionCall(part, systemPrompt, output);
      if (isAnswerText(part)) {
        slots.push({
          key,
          text: part.text,
          set: (text) => {
            part.text = text;
          },
        });
      }
    }
  }
  return slots;
}

/** Log probabilities list the tokens of the original text. */
function dropLogprobs(response: unknown, changed: Set<string>): void {
  const candidates = (response as Response | undefined)?.candidates;
  if (!Array.isArray(candidates) || changed.size === 0) {
    return;
  }
  for (const [position, candidate] of candidates.entries()) {
    if (
      candidate?.logprobsResult !== undefined &&
      changed.has(candidateKey(candidate, position))
    ) {
      candidate.logprobsResult = undefined;
    }
  }
}

/** Guards a response in place, so the SDK's `text` getter reads the guarded text. */
function guardResponse(
  response: unknown,
  systemPrompt: string | undefined,
  output: OutputGuard
): void {
  const changed = rewriteSlots(
    responseSlots(response, systemPrompt, output),
    (text) => output.text(text, systemPrompt)
  );
  dropLogprobs(response, changed);
}

/**
 * Reads the whole stream, guards each candidate's full text and every
 * function call, and replays the chunks with the text rewritten in place.
 * Nothing else in them changes.
 */
async function bufferStream(
  stream: AsyncIterable<Response>,
  systemPrompt: string | undefined,
  output: OutputGuard
): Promise<AsyncGenerator<Response>> {
  const chunks: Response[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  const slots = chunks.flatMap((chunk) =>
    responseSlots(chunk, systemPrompt, output)
  );
  const changed = rewriteSlots(slots, (text) =>
    output.text(text, systemPrompt)
  );
  for (const chunk of chunks) {
    dropLogprobs(chunk, changed);
  }
  return (async function* () {
    yield* chunks;
  })();
}

/** Adds `text` to the answer of candidate `key` in `chunk`. */
function appendText(chunk: Response, key: string, text: string): void {
  chunk.candidates ??= [];
  let candidate = chunk.candidates.find(
    (c, position) => candidateKey(c, position) === key
  );
  if (!candidate) {
    candidate = { index: Number(key) };
    chunk.candidates.push(candidate);
  }
  candidate.content ??= { role: "model" };
  candidate.content.parts ??= [];
  const { parts } = candidate.content;
  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i];
    if (isAnswerText(part)) {
      part.text += text;
      return;
    }
  }
  parts.push({ text });
}

function chunkedStream(
  stream: AsyncIterable<Response>,
  systemPrompt: string | undefined,
  output: OutputGuard,
  options: ShieldGoogleGenAIOptions
): AsyncGenerator<Response> {
  const sanitizer = createSlotSanitizer(systemPrompt ?? "", output, options);
  return chunkedReplay(
    stream,
    sanitizer,
    (chunk) => {
      const slots = responseSlots(chunk, systemPrompt, output);
      const logprobs = new Set(slots.map((slot) => slot.key));
      dropLogprobs(chunk, logprobs);
      return slots;
    },
    appendText
  );
}

type Method = (...args: unknown[]) => Promise<unknown>;

interface Models {
  generateContent(...args: unknown[]): unknown;
  generateContentStream(...args: unknown[]): unknown;
}

export function shieldGoogleGenAI<
  // Method syntax makes the parameter check bivariant, so the SDK's
  // `models`, whose methods take specific param types, satisfy it.
  T extends { models: Models },
>(ai: T, options: ShieldGoogleGenAIOptions = {}): T {
  const shield = createShield(options);
  const { models } = ai;
  const tools = new WeakMap<object, object>();

  const guardTool = (tool: CallableTool): object => {
    if (!shield.input.tool) {
      return tool;
    }
    let guarded = tools.get(tool);
    if (!guarded) {
      guarded = guardCallableTool(tool, shield.input);
      tools.set(tool, guarded);
    }
    return guarded;
  };

  /**
   * Callable tools with their results checked, and, while a verdict is
   * pending, their calls held until it is in.
   */
  const guardTools = (list: unknown, scope: InputScope): unknown => {
    const hold = scope.pending;
    if (!(Array.isArray(list) && (shield.input.tool || hold))) {
      return list;
    }
    return list.map((tool) => {
      if (!isCallableTool(tool)) {
        return tool;
      }
      const guarded = guardTool(tool);
      return hold ? holdCallableTool(guarded as CallableTool, scope) : guarded;
    });
  };

  /** Copies, hardens, and checks the request. Returns it and its system prompt. */
  const prepare = async (
    request: unknown,
    scope: InputScope
  ): Promise<{ params: Params; systemPrompt: string | undefined }> => {
    const original = (request ?? {}) as Params;
    const config = original.config && { ...original.config };
    const params: Params = config ? { ...original, config } : { ...original };
    const instruction = config?.systemInstruction;
    const systemPrompt =
      options.systemPrompt ?? (systemText(instruction) || undefined);
    if (config && shield.harden && instruction !== undefined) {
      config.systemInstruction = hardenInstruction(instruction, shield.harden);
    }
    await checkContents(params.contents, scope);
    if (config?.tools !== undefined) {
      config.tools = guardTools(config.tools, scope);
    }
    return { params, systemPrompt };
  };

  const generateContent: Method = async (request, ...rest) => {
    const scope = shield.input.begin();
    const { params, systemPrompt } = await prepare(request, scope);
    const response = await callProvider(scope, () =>
      models.generateContent(params, ...rest)
    );
    await whenSettled(scope, response);
    if (shield.output.active(systemPrompt)) {
      guardResponse(response, systemPrompt, shield.output);
    }
    return response;
  };

  const generateContentStream: Method = async (request, ...rest) => {
    const scope = shield.input.begin();
    const { params, systemPrompt } = await prepare(request, scope);
    const stream = await callProvider(scope, () =>
      models.generateContentStream(params, ...rest)
    );
    if (!isAsyncIterable<Response>(stream)) {
      return whenSettled(scope, stream);
    }
    const mode = options.streamingSanitize ?? "buffer";
    const guarded =
      mode !== "passthrough" && shield.output.active(systemPrompt);
    if (guarded && mode !== "chunked") {
      return await bufferStream(
        endWhenSettled(scope, stream),
        systemPrompt,
        shield.output
      );
    }
    // With automatic function calling, the SDK only sends the request when
    // the stream is first read.
    const settled = scope.pending
      ? await prefetchWhenSettled(scope, stream)
      : stream;
    return guarded
      ? chunkedStream(settled, systemPrompt, shield.output, options)
      : settled;
  };

  const wrappedModels = withOverrides(models, {
    generateContent,
    generateContentStream,
  });
  const overrides: Record<string, unknown> = { models: wrappedModels };

  // A chat calls the `models` it was created with.
  const { chats } = ai as { chats?: unknown };
  if (isRecord(chats) && "modelsModule" in chats) {
    overrides.chats = Object.create(chats, {
      modelsModule: { value: wrappedModels },
    });
  }
  return withOverrides(ai, overrides);
}
