/**
 * OpenAI Agents SDK (`@openai/agents`). Guardrails that check what an agent
 * reads and writes: the run's input for injection, the final output for
 * prompt leaks, credentials, exfiltration links, and canaries, and a function
 * tool's arguments before it runs and its output before the model reads it.
 * A tool policy guardrail refuses tool calls a policy from
 * `createToolPolicy()` doesn't allow.
 *
 * Guardrails can stop a run or a tool call, but can't change the text that
 * flows through it, so nothing is hardened or redacted. The types below are
 * the parts of the SDK's guardrail types that Shield reads, so this module
 * doesn't import the SDK.
 */

import type { DetectResult } from "../detect";
import type { BlockedFinding, InjectionSource } from "../errors";
import type { ToolPolicy, ToolPolicyDecision } from "../policy";
import { createShield, jsonText, type ShieldProviderOptions } from "./guard";
import { decodeTextBlob, isRecord } from "./shared";

/** What the input and tool output guardrails put in `outputInfo`. */
export interface ShieldInjectionInfo {
  /** Whether an injection was found. With `onDetection: "warn"` it is reported, but the guardrail doesn't trip. */
  detected: boolean;
  /** Where the first injection was found: a user message, or a tool output. */
  source?: InjectionSource;
  /** Detection's result for the text with the first injection: risk, matched categories and patterns, and score. Never the text. */
  result?: DetectResult;
}

/** What the output and tool input guardrails put in `outputInfo`. Never the text that was scanned. */
export interface ShieldLeakInfo {
  /** A prompt leak or a canary: the highest confidence, and how many fragments or places were found. */
  leak?: { confidence: number; fragmentCount: number };
  /** The type, kind, and severity of every output finding, when at least one is high or critical. */
  findings?: BlockedFinding[];
}

/** The agent in what the SDK passes a guardrail, as far as Shield reads it. */
interface AgentLike {
  instructions?: unknown;
}

/** The SDK's `RunContext`, as far as Shield reads it: the `context` you passed to `run()`. */
interface RunContextLike {
  context?: unknown;
}

/**
 * A tool policy, or a function that returns the policy for a run from the
 * `context` you passed to `run()`, so each run or conversation gets its own.
 */
export type ShieldPolicySource<TContext = unknown> =
  | ToolPolicy
  | ((context: TContext) => ToolPolicy);

/** An input guardrail, for an `Agent`'s or a `Runner`'s `inputGuardrails`. */
export interface ShieldInputGuardrail {
  name: string;
  runInParallel: boolean;
  execute(args: {
    input: unknown;
  }): Promise<{ tripwireTriggered: boolean; outputInfo: ShieldInjectionInfo }>;
}

/** An output guardrail, for an `Agent`'s or a `Runner`'s `outputGuardrails`. */
export interface ShieldOutputGuardrail {
  name: string;
  execute(args: {
    agent: AgentLike;
    agentOutput: unknown;
  }): Promise<{ tripwireTriggered: boolean; outputInfo: ShieldLeakInfo }>;
}

/** The SDK's `ToolGuardrailBehavior`. */
export type ShieldToolGuardrailBehavior =
  | { type: "allow" }
  | { type: "rejectContent"; message: string }
  | { type: "throwException" };

/** A tool input guardrail, for a function tool's `inputGuardrails` or an MCP server's `toolInputGuardrails`. */
export interface ShieldToolInputGuardrail {
  type: "tool_input";
  name: string;
  run(data: { agent: AgentLike; toolCall: { arguments: string } }): Promise<{
    behavior: ShieldToolGuardrailBehavior;
    outputInfo: ShieldLeakInfo;
  }>;
}

/** A tool output guardrail, for a function tool's `outputGuardrails` or an MCP server's `toolOutputGuardrails`. */
export interface ShieldToolOutputGuardrail {
  type: "tool_output";
  name: string;
  run(data: {
    output: unknown;
    toolCall?: { name: string };
    context?: RunContextLike;
  }): Promise<{
    behavior: ShieldToolGuardrailBehavior;
    outputInfo: ShieldInjectionInfo;
  }>;
}

/** A tool input guardrail that applies a tool policy, for a function tool's `inputGuardrails` or an MCP server's `toolInputGuardrails`. */
export interface ShieldToolPolicyGuardrail {
  type: "tool_input";
  name: string;
  run(data: {
    toolCall: { name: string; arguments: string };
    context?: RunContextLike;
  }): Promise<{
    behavior: ShieldToolGuardrailBehavior;
    /** The policy's decision. It never holds argument values. */
    outputInfo: ToolPolicyDecision;
  }>;
}

type InjectionOptions = Pick<
  ShieldProviderOptions,
  "detect" | "scanToolResults" | "onDetection" | "onInjectionDetected"
>;

export interface ShieldInputGuardrailOptions extends InjectionOptions {
  /** The guardrail's name, which the SDK shows in errors and traces. Default: `"shield_input"`. */
  name?: string;
  /**
   * Whether the SDK runs the guardrail alongside the agent's first model
   * call instead of before it. Default `false`: the model is not called until
   * the input was checked, so a blocked input never reaches it.
   */
  runInParallel?: boolean;
}

export interface ShieldToolOutputGuardrailOptions<TContext = unknown>
  extends InjectionOptions {
  /** The guardrail's name. Default: `"shield_tool_output"`. */
  name?: string;
  /**
   * What happens to a tool output with an injection. `"rejectContent"`
   * (default): the model gets `rejectionMessage` in its place, and the run
   * goes on. `"throwException"`: the run fails with the SDK's
   * `ToolOutputGuardrailTripwireTriggered`.
   */
  behavior?: "rejectContent" | "throwException";
  /** What the model gets in place of a rejected tool output. */
  rejectionMessage?: string;
  /**
   * A tool policy to tell about each tool output, with
   * `policy.recordResult()`, flagged when detection found an injection in
   * it, whether or not the guardrail rejects it. Pass the same policy, or
   * function, as to `shieldToolPolicyGuardrail()`.
   */
  policy?: ShieldPolicySource<TContext>;
}

export interface ShieldToolPolicyGuardrailOptions<TContext = unknown> {
  /** The policy, or a function that returns it from the `context` passed to `run()`. */
  policy: ShieldPolicySource<TContext>;
  /** The guardrail's name. Default: `"shield_tool_policy"`. */
  name?: string;
  /**
   * What happens to a refused call. `"rejectContent"` (default): the tool
   * doesn't run, and the model gets `rejectionMessage` as its output.
   * `"throwException"`: the run fails with the SDK's
   * `ToolInputGuardrailTripwireTriggered`.
   */
  behavior?: "rejectContent" | "throwException";
  /** What the model gets in place of the output of a refused call. Default: the decision's `message`. */
  rejectionMessage?: string;
}

export interface ShieldOutputGuardrailOptions
  extends Pick<
    ShieldProviderOptions,
    | "systemPrompt"
    | "sanitize"
    | "output"
    | "onLeakDetected"
    | "onOutputFindings"
  > {
  /** The guardrail's name. Default: `"shield_output"`. */
  name?: string;
  /**
   * A canary token you planted in the agent's instructions, such as one from
   * `createCanary()`. Its appearance in the output counts as a leak.
   */
  canary?: string;
  /** Trip the wire on a prompt leak or a canary. Default: `true`. */
  throwOnLeak?: boolean;
  /** Trip the wire when an output finding is high or critical severity. Default: `true`. */
  blockOnOutputFindings?: boolean;
}

export interface ShieldToolInputGuardrailOptions
  extends ShieldOutputGuardrailOptions {
  /** The guardrail's name. Default: `"shield_tool_input"`. */
  name?: string;
  /**
   * What happens to a flagged tool call. `"rejectContent"` (default): the
   * tool doesn't run, and the model gets `rejectionMessage` as its output.
   * `"throwException"`: the run fails with the SDK's
   * `ToolInputGuardrailTripwireTriggered`.
   */
  behavior?: "rejectContent" | "throwException";
  /** What the model gets in place of the output of a tool call that didn't run. */
  rejectionMessage?: string;
}

const TOOL_OUTPUT_REJECTED =
  "This tool output was withheld because Shield flagged it as a possible prompt injection.";
const TOOL_INPUT_REJECTED =
  "This tool call was blocked because Shield found a credential, an exfiltration link, a canary, or system prompt text in its arguments.";

const TEXT_PARTS = new Set(["text", "input_text", "output_text"]);

/** Parts that carry media, and the fields that hold it: the SDK's and MCP's. */
const MEDIA_PARTS = new Map<string, readonly string[]>([
  ["image", ["image", "data"]],
  ["input_image", ["image"]],
  ["file", ["file"]],
  ["input_file", ["file"]],
  ["audio", ["audio", "data"]],
  ["computer_screenshot", ["data"]],
]);

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function joined(texts: string[]): string {
  return texts.filter(Boolean).join("\n");
}

const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

function isMedia(part: Record<string, unknown>): boolean {
  const fields =
    typeof part.type === "string" ? MEDIA_PARTS.get(part.type) : undefined;
  return fields?.some((field) => field in part) ?? false;
}

/** Text of an MCP embedded resource: its text, or a text blob decoded. */
function resourceText(resource: unknown): string {
  if (!isRecord(resource)) {
    return "";
  }
  return typeof resource.text === "string"
    ? resource.text
    : decodeTextBlob(resource.blob, resource.mimeType);
}

/**
 * Text of a content part: a text part, an MCP embedded resource, or an MCP
 * resource link's title and description. Empty for media, `undefined` for
 * anything else.
 */
function partText(part: Record<string, unknown>): string | undefined {
  if (TEXT_PARTS.has(String(part.type)) && typeof part.text === "string") {
    return part.text;
  }
  if (part.type === "resource") {
    return resourceText(part.resource);
  }
  if (part.type === "resource_link") {
    return joined([part.title, part.description].filter(isString));
  }
  return isMedia(part) ? "" : undefined;
}

function itemText(item: unknown): string {
  if (typeof item === "string") {
    return item;
  }
  return (isRecord(item) ? partText(item) : undefined) ?? jsonText(item);
}

/**
 * Text of what a function tool returned: a string, a content part or MCP
 * content block, a list of those, or the string values of anything else, up
 * to 64KB. Images, files, and audio are not read.
 */
function toolOutputText(output: unknown): string {
  return Array.isArray(output)
    ? joined(output.map(itemText))
    : itemText(output);
}

/** Text of a user message's content: a string, or its text parts. */
function contentText(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  return joined(
    list(content).map((part) =>
      isRecord(part) &&
      TEXT_PARTS.has(String(part.type)) &&
      typeof part.text === "string"
        ? part.text
        : ""
    )
  );
}

/** Text of a tool result item in the input list. Empty for any other item. */
function toolItemText(item: Record<string, unknown>): string {
  switch (item.type) {
    case "function_call_result":
      return toolOutputText(item.output);
    case "shell_call_output":
      return joined(
        list(item.output).map((out) =>
          isRecord(out) ? joined([out.stdout, out.stderr].filter(isString)) : ""
        )
      );
    case "apply_patch_call_output":
    case "program_output":
    case "hosted_tool_call":
      return typeof item.output === "string" ? item.output : "";
    default:
      return "";
  }
}

/** The text in a run's input to check, and where it came from. */
function* inputTexts(input: unknown): Generator<[string, InjectionSource]> {
  if (typeof input === "string") {
    yield [input, "user"];
    return;
  }
  for (const item of list(input)) {
    if (!isRecord(item)) {
      continue;
    }
    if (item.role === "user") {
      yield [contentText(item.content), "user"];
      continue;
    }
    const text = toolItemText(item);
    if (text) {
      yield [text, "tool"];
    }
  }
}

function instructionsOf(agent: AgentLike): string | undefined {
  return isString(agent.instructions) ? agent.instructions : undefined;
}

/** Tool call arguments as the tool gets them: parsed JSON, or the string when it isn't JSON. */
function parseArguments(args: unknown): unknown {
  if (typeof args !== "string") {
    return args;
  }
  try {
    return JSON.parse(args);
  } catch {
    return args;
  }
}

/** Creates the detection the input and tool output guardrails share. */
function createInjectionCheck(options: InjectionOptions) {
  const { input } = createShield({
    detect: options.detect,
    scanToolResults: options.scanToolResults,
    onDetection: options.onDetection,
    onInjectionDetected: options.onInjectionDetected,
    harden: false,
    sanitize: false,
    output: false,
  });
  const blocking = (options.onDetection ?? "block") === "block";

  /**
   * Checks each text in turn and returns what the first injection was, and
   * whether to trip. In block mode it stops at the first injection.
   */
  return async (
    texts: Iterable<[string, InjectionSource]>
  ): Promise<{ trip: boolean; info: ShieldInjectionInfo }> => {
    let info: ShieldInjectionInfo = { detected: false };
    for (const [text, source] of texts) {
      const result = await input.inspect(text, source);
      if (!result?.detected) {
        continue;
      }
      if (!info.detected) {
        info = { detected: true, source, result };
      }
      if (blocking) {
        break;
      }
    }
    return { trip: info.detected && blocking, info };
  };
}

/** Creates the scan the output and tool input guardrails share. */
function createLeakCheck(options: ShieldOutputGuardrailOptions) {
  const { output } = createShield({
    systemPrompt: options.systemPrompt,
    sanitize: options.sanitize,
    output: options.output,
    canary: options.canary,
    onLeakDetected: options.onLeakDetected,
    onOutputFindings: options.onOutputFindings,
    // The verdict is only read here, so `block` marks any high or critical
    // finding, and the options below decide whether it trips.
    blockOnOutputFindings: true,
    harden: false,
    detect: false,
    scanToolResults: false,
  });
  const tripOnLeak = options.throwOnLeak ?? true;
  const tripOnFindings = options.blockOnOutputFindings ?? true;

  return (
    value: unknown,
    agent: AgentLike
  ): { trip: boolean; info: ShieldLeakInfo } => {
    const systemPrompt = options.systemPrompt ?? instructionsOf(agent);
    if (!output.active(systemPrompt)) {
      return { trip: false, info: {} };
    }
    const { leak, block } = output.inspect(value, systemPrompt);
    const info: ShieldLeakInfo = {};
    if (leak) {
      info.leak = {
        confidence: leak.confidence,
        fragmentCount: leak.fragmentCount,
      };
    }
    if (block) {
      info.findings = block.findings;
    }
    const trip = Boolean((leak && tripOnLeak) || (block && tripOnFindings));
    return { trip, info };
  };
}

/** The policy for this run: `source` itself, or what it returns for the run's context. */
function resolvePolicy<TContext>(
  source: ShieldPolicySource<TContext>,
  runContext: RunContextLike | undefined
): ToolPolicy {
  const policy: ToolPolicy | undefined =
    typeof source === "function"
      ? source(runContext?.context as TContext)
      : source;
  if (
    typeof policy?.checkAsync !== "function" ||
    typeof policy.recordResult !== "function"
  ) {
    throw new TypeError(
      "policy must be a ToolPolicy from createToolPolicy(), or a function that returns one"
    );
  }
  return policy;
}

function toolBehavior(
  trip: boolean,
  behavior: "rejectContent" | "throwException" | undefined,
  message: string
): ShieldToolGuardrailBehavior {
  if (!trip) {
    return { type: "allow" };
  }
  return behavior === "throwException"
    ? { type: "throwException" }
    : { type: "rejectContent", message };
}

/**
 * An input guardrail that checks the run's input for injection: a string
 * input, the text of user messages, and the tool results in an input list
 * (such as a previous run's `history`), with the `scanToolResults` options.
 * An injection trips the wire, and `run()` rejects with the SDK's
 * `InputGuardrailTripwireTriggered`. By default it runs before the model is
 * called.
 *
 * @example
 * ```ts
 * import { Agent, run } from "@openai/agents";
 * import { shieldInputGuardrail } from "@zeroleaks/shield/openai-agents";
 *
 * const agent = new Agent({
 *   name: "Support",
 *   instructions: "You are a support agent.",
 *   inputGuardrails: [shieldInputGuardrail()],
 * });
 * await run(agent, userInput); // throws InputGuardrailTripwireTriggered on an injection
 * ```
 */
export function shieldInputGuardrail(
  options: ShieldInputGuardrailOptions = {}
): ShieldInputGuardrail {
  const check = createInjectionCheck(options);
  return {
    name: options.name ?? "shield_input",
    runInParallel: options.runInParallel ?? false,
    async execute({ input }) {
      const { trip, info } = await check(inputTexts(input));
      return { tripwireTriggered: trip, outputInfo: info };
    },
  };
}

/**
 * An output guardrail that checks the agent's final output, a string or
 * every string in a structured output, for a leak of the system prompt
 * (`systemPrompt`, or the agent's `instructions` when they are a string), a
 * canary, and credentials, exfiltration links, and other output findings.
 * A leak, a canary, or a high or critical finding trips the wire, and
 * `run()` rejects with the SDK's `OutputGuardrailTripwireTriggered`. It
 * can't redact: use the wrapper for your model provider for that.
 *
 * @example
 * ```ts
 * const agent = new Agent({
 *   name: "Support",
 *   instructions: SYSTEM_PROMPT,
 *   outputGuardrails: [shieldOutputGuardrail()],
 * });
 * ```
 */
export function shieldOutputGuardrail(
  options: ShieldOutputGuardrailOptions = {}
): ShieldOutputGuardrail {
  const check = createLeakCheck(options);
  return {
    name: options.name ?? "shield_output",
    execute({ agent, agentOutput }) {
      const { trip, info } = check(agentOutput, agent);
      return Promise.resolve({ tripwireTriggered: trip, outputInfo: info });
    },
  };
}

/**
 * A tool output guardrail that checks what a function tool returned for
 * injection, with the `scanToolResults` options, before the model reads it.
 * By default the model gets `rejectionMessage` in place of an output with
 * an injection, and the run goes on. With `policy`, each output is recorded
 * in the tool policy.
 *
 * @example
 * ```ts
 * import { tool } from "@openai/agents";
 * import { shieldToolOutputGuardrail } from "@zeroleaks/shield/openai-agents";
 *
 * const readInbox = tool({
 *   name: "read_inbox",
 *   description: "Read new email.",
 *   parameters: z.object({}),
 *   execute: async () => fetchInbox(),
 *   outputGuardrails: [shieldToolOutputGuardrail()],
 * });
 * ```
 */
export function shieldToolOutputGuardrail<TContext = unknown>(
  options: ShieldToolOutputGuardrailOptions<TContext> = {}
): ShieldToolOutputGuardrail {
  const check = createInjectionCheck(options);
  const message = options.rejectionMessage ?? TOOL_OUTPUT_REJECTED;
  return {
    type: "tool_output",
    name: options.name ?? "shield_tool_output",
    async run({ output, toolCall, context }) {
      const { trip, info } = await check([[toolOutputText(output), "tool"]]);
      if (options.policy) {
        const policy = resolvePolicy(options.policy, context);
        if (toolCall) {
          policy.recordResult(toolCall.name, { flagged: info.detected });
        } else if (info.detected) {
          policy.recordUntrusted("tool output");
        }
      }
      return {
        behavior: toolBehavior(trip, options.behavior, message),
        outputInfo: info,
      };
    },
  };
}

/**
 * A tool input guardrail that checks a function tool call's arguments,
 * before the tool runs, for what must not leave the agent: credentials,
 * exfiltration links, a canary, and text of the system prompt (`systemPrompt`,
 * or the agent's `instructions` when they are a string). By default a
 * flagged call doesn't run, and the model gets `rejectionMessage` as its
 * output.
 *
 * @example
 * ```ts
 * const sendEmail = tool({
 *   name: "send_email",
 *   description: "Send an email.",
 *   parameters: z.object({ to: z.string(), body: z.string() }),
 *   execute: async ({ to, body }) => send(to, body),
 *   inputGuardrails: [shieldToolInputGuardrail()],
 * });
 * ```
 */
export function shieldToolInputGuardrail(
  options: ShieldToolInputGuardrailOptions = {}
): ShieldToolInputGuardrail {
  const check = createLeakCheck(options);
  const message = options.rejectionMessage ?? TOOL_INPUT_REJECTED;
  return {
    type: "tool_input",
    name: options.name ?? "shield_tool_input",
    run({ agent, toolCall }) {
      const { trip, info } = check(parseArguments(toolCall.arguments), agent);
      return Promise.resolve({
        behavior: toolBehavior(trip, options.behavior, message),
        outputInfo: info,
      });
    },
  };
}

/**
 * A tool input guardrail that checks each call against a tool policy from
 * `createToolPolicy()` before the tool runs. By default a refused call
 * doesn't run, and the model gets the decision's message as its output. Put
 * it last in `inputGuardrails`, since the policy counts every call it
 * allows, and give the tools `shieldToolOutputGuardrail({ policy })` so the
 * policy learns what each tool returned.
 *
 * @example
 * ```ts
 * import { createToolPolicy, type ToolPolicy } from "@zeroleaks/shield";
 *
 * const policyGuardrail = shieldToolPolicyGuardrail<{ policy: ToolPolicy }>({
 *   policy: (context) => context.policy,
 * });
 * const sendEmail = tool({
 *   name: "send_email",
 *   description: "Send an email.",
 *   parameters: z.object({ to: z.string(), body: z.string() }),
 *   execute: async ({ to, body }) => send(to, body),
 *   inputGuardrails: [policyGuardrail],
 * });
 * await run(agent, input, { context: { policy: createToolPolicy(rules) } });
 * ```
 */
export function shieldToolPolicyGuardrail<TContext = unknown>(
  options: ShieldToolPolicyGuardrailOptions<TContext>
): ShieldToolPolicyGuardrail {
  return {
    type: "tool_input",
    name: options.name ?? "shield_tool_policy",
    async run({ toolCall, context }) {
      const policy = resolvePolicy(options.policy, context);
      const decision = await policy.checkAsync({
        name: toolCall.name,
        arguments: toolCall.arguments,
      });
      return {
        behavior: toolBehavior(
          !decision.allowed,
          options.behavior,
          options.rejectionMessage ?? decision.message
        ),
        outputInfo: decision,
      };
    },
  };
}
