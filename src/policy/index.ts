/**
 * A deterministic tool call policy for one agent session: which tools may be
 * called, with which arguments, how often, and whether a tool that can send
 * data out may run after the session has read untrusted content. It needs no
 * model and no network, so it holds when detection misses an injection.
 */

import { isAllowedHost } from "../output/exfiltration";
import { schemaOf, type ToolDefinition, unwrap } from "../tools";
import { globMatch, guessToolLabels, type ToolLabel } from "./names";
import { type SchemaViolation, validateSchema } from "./schema";

// biome-ignore lint/performance/noBarrelFile: the policy's public types live in its submodules.
export { globMatch, guessToolLabels, type ToolLabel } from "./names";
export type { SchemaViolation } from "./schema";

/** Tool definitions: a list in any shape `scanTools()` accepts, or an object from tool names to definitions, like the AI SDK's `tools`. */
export type ToolSet = ToolDefinition[] | Record<string, ToolDefinition>;

export interface ToolPolicyRule {
  /** What the tool does with data, for the flow rule. Setting it, even to `[]`, replaces the labels `guessLabels` would give. */
  labels?: ToolLabel[];
  /** The most calls to each matching tool in the session. */
  maxCalls?: number;
  /**
   * Lets a sink tool run after untrusted content when every destination in
   * its arguments is on `allow`. `arguments` names the arguments that hold
   * destinations, as top-level names or dotted paths (`"message.to"`); a
   * string value is split at commas and semicolons, and an array is read
   * item by item. An `allow` entry is a host, matched like
   * `allowedDomains` (exact, or `.example.com` or `*.example.com` for the
   * domain and its subdomains) against a URL's host, an email address's
   * domain, or a bare host; an entry with `@` matches that address only;
   * and any other value must equal an entry.
   */
  destinations?: { arguments: string[]; allow: string[] };
}

/** Why a call was refused. */
export type ToolPolicyRefusal =
  | "undeclared_tool"
  | "denied_tool"
  | "tool_not_allowed"
  | "invalid_arguments"
  | "call_limit"
  | "untrusted_to_sink";

export type ToolPolicyReason = "allowed" | "approved" | ToolPolicyRefusal;

export interface ToolPolicyCall {
  name: string;
  /** The arguments, as an object or a JSON string. `undefined` or an empty string counts as `{}`. */
  arguments?: unknown;
  /**
   * Where the call goes, as a `source` passed to `declareTools()`, such as
   * the MCP client that will run it. Once that source has declared tools,
   * the call is checked against its tools alone. Default: all declared tools.
   */
  source?: string;
}

export interface ToolPolicyDecision {
  allowed: boolean;
  reason: ToolPolicyReason;
  /** A sentence for logs, or for the model in place of the tool's output. It never holds argument values. */
  message: string;
  /** The tool's name, as the call gave it. */
  tool: string;
  /** With `invalid_arguments`: the first violations, by path and keyword. */
  violations?: SchemaViolation[];
}

/** What the session has seen, as plain data you can save with `JSON.stringify`. */
export interface ToolPolicyState {
  /** Where untrusted content came from: tool names, or the `source` passed to `recordUntrusted()`. Empty until the session has seen some. */
  untrustedFrom: string[];
  /** Where private data came from, likewise. */
  privateFrom: string[];
  /** Calls the policy allowed, by tool name. */
  calls: Record<string, number>;
}

export interface ToolPolicyOptions {
  /**
   * The tools the agent was given. A call to any other name is refused as
   * `undeclared_tool`, and arguments are validated against the tool's JSON
   * Schema. `declareTools()` adds more. Default: none, and the rule is off
   * until tools are declared.
   */
  tools?: ToolSet;
  /** Validate arguments against the declared tool's schema. Default `true`. */
  validateArguments?: boolean;
  /** Tool names or globs (`github_*`) that may be called. Default: every tool. */
  allow?: string[];
  /** Tool names or globs that may never be called. Checked before `allow`. */
  deny?: string[];
  /** Rules by tool name or glob. Every rule that matches a tool applies to it. */
  rules?: Record<string, ToolPolicyRule>;
  /** The most tool calls in the session, across all tools. */
  maxTotalCalls?: number;
  /** Label tools that no rule labels with `guessToolLabels()`. Default `false`. */
  guessLabels?: boolean;
  /**
   * When calls to `sink` tools are refused: `"untrusted"` (default) once the
   * session has seen untrusted content, `"trifecta"` once it has seen
   * untrusted content and read private data, `false` never.
   */
  flow?: "untrusted" | "trifecta" | false;
  /**
   * Called for a call the flow rule refuses, with the call and the refusal.
   * Returning `true` lets it run, with reason `approved`. `check()` needs an
   * answer at once; with a Promise, use `checkAsync()`. Other refusals are
   * final.
   */
  approve?: (
    call: ToolPolicyCall,
    decision: ToolPolicyDecision
  ) => boolean | Promise<boolean>;
  /** Start from a state saved from `state()`. */
  state?: ToolPolicyState;
}

export interface ToolPolicy {
  /** Decides whether a call may run, and counts it when it may. */
  check(call: ToolPolicyCall): ToolPolicyDecision;
  /** `check()`, waiting for an `approve` that returns a Promise. */
  checkAsync(call: ToolPolicyCall): Promise<ToolPolicyDecision>;
  /**
   * Tells the policy a tool returned. The session has seen untrusted content
   * when the tool is labeled `untrusted` or `flagged` is true, such as when
   * `detect()` found an injection in the result, and has read private data
   * when it is labeled `private`.
   */
  recordResult(name: string, result?: { flagged?: boolean }): void;
  /** Marks the session as having seen untrusted content that didn't come from a tool, such as a retrieved document. */
  recordUntrusted(source?: string): void;
  /** Marks the session as having read private data that didn't come from a tool. */
  recordPrivate(source?: string): void;
  /** Declares tools, replacing those declared before under the same `source`. Tools from every source are declared together. */
  declareTools(tools: ToolSet, source?: string): void;
  /** A copy of what the session has seen. */
  state(): ToolPolicyState;
  /** Forgets what the session has seen and the calls it counted. Declared tools and options stay. */
  reset(): void;
}

const DEFAULT_SOURCE = "tools";
const MAX_SOURCES = 8;
const MAX_SOURCES_IN_MESSAGE = 3;
const MAX_NAME_IN_MESSAGE = 64;
const MAX_VIOLATIONS = 5;
const RE_DESTINATION_SEPARATORS = /[,;]/;
const RE_ANGLE_ADDRESS = /<([^<>]*)>\s*$/;
const RE_MAILTO = /^mailto:/i;

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function hasOwn(record: object, key: string): boolean {
  return Object.getOwnPropertyDescriptor(record, key) !== undefined;
}

function shown(name: string): string {
  return JSON.stringify(
    name.length > MAX_NAME_IN_MESSAGE
      ? `${name.slice(0, MAX_NAME_IN_MESSAGE)}...`
      : name
  );
}

/**
 * The JSON Schema in a tool's schema field: the field itself, the JSON
 * Schema of an AI SDK `jsonSchema()` or `zodSchema()`, or of a Zod schema
 * through Standard JSON Schema. `undefined` when there is none to read.
 */
function jsonSchemaOf(schema: unknown): unknown {
  if (typeof schema === "boolean") {
    return schema;
  }
  const record = asRecord(schema);
  if (!record) {
    return;
  }
  try {
    if ("jsonSchema" in record && "validate" in record) {
      return record.jsonSchema;
    }
    const standard = asRecord(record["~standard"]);
    if (standard) {
      const converter = asRecord(standard.jsonSchema);
      return typeof converter?.input === "function"
        ? converter.input({ target: "draft-2020-12" })
        : undefined;
    }
  } catch {
    return;
  }
  return "_def" in record || "_zod" in record ? undefined : record;
}

function toolEntries(tools: ToolSet): [string, unknown][] {
  if (Array.isArray(tools)) {
    return tools.map((tool) => {
      const def = unwrap(tool);
      return [String(def.name ?? ""), jsonSchemaOf(schemaOf(def))];
    });
  }
  return Object.keys(tools).map((name) => [
    name,
    jsonSchemaOf(schemaOf(unwrap(tools[name]))),
  ]);
}

type Parsed = { ok: true; value: unknown } | { ok: false };

function parseArguments(args: unknown): Parsed {
  if (args === undefined) {
    return { ok: true, value: {} };
  }
  if (typeof args !== "string") {
    return { ok: true, value: args };
  }
  if (args.trim() === "") {
    return { ok: true, value: {} };
  }
  try {
    return { ok: true, value: JSON.parse(args) };
  } catch {
    return { ok: false };
  }
}

function valueAt(args: unknown, path: string): unknown {
  let node = args;
  for (const key of path.split(".")) {
    const record = asRecord(node);
    if (!(record && hasOwn(record, key))) {
      return;
    }
    node = record[key];
  }
  return node;
}

/** The destinations in one argument, or `null` when it holds something that isn't a string. */
function destinationsIn(value: unknown): string[] | null {
  const items = Array.isArray(value) ? value : [value];
  const out: string[] = [];
  for (const item of items) {
    if (typeof item !== "string") {
      return null;
    }
    for (const part of item.split(RE_DESTINATION_SEPARATORS)) {
      const angle = RE_ANGLE_ADDRESS.exec(part);
      const destination = (angle ? angle[1] : part).trim();
      if (destination) {
        out.push(destination);
      }
    }
  }
  return out;
}

function destinationAllowed(destination: string, allow: string[]): boolean {
  const value = destination.toLowerCase();
  const address = value.replace(RE_MAILTO, "");
  // Mail and URL parsers disagree on which "@" ends the local part or the
  // user info, so a destination with more than one is refused.
  if (value.indexOf("@") !== value.lastIndexOf("@")) {
    return false;
  }
  return allow.some((raw) => {
    const entry = raw.trim().toLowerCase();
    if (entry.includes("@")) {
      return address === entry;
    }
    return value === entry || isAllowedHost(value, [entry]);
  });
}

/** Whether every destination in `args` is on the rule's list, with at least one. */
function destinationsAllowed(
  destinations: NonNullable<ToolPolicyRule["destinations"]>,
  args: unknown
): boolean {
  let found = 0;
  for (const path of destinations.arguments) {
    const value = valueAt(args, path);
    if (value === undefined || value === null) {
      continue;
    }
    const list = destinationsIn(value);
    if (!list) {
      return false;
    }
    for (const destination of list) {
      if (!destinationAllowed(destination, destinations.allow)) {
        return false;
      }
      found += 1;
    }
  }
  return found > 0;
}

function addSource(list: string[], source: string): void {
  if (list.length < MAX_SOURCES && !list.includes(source)) {
    list.push(source);
  }
}

function sourcesText(list: string[]): string {
  const listed = list.slice(0, MAX_SOURCES_IN_MESSAGE).join(", ");
  return list.length > MAX_SOURCES_IN_MESSAGE ? `${listed}, and more` : listed;
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return typeof (value as PromiseLike<unknown> | null)?.then === "function";
}

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function checkOptions(options: ToolPolicyOptions): void {
  if (options.maxTotalCalls !== undefined && !isCount(options.maxTotalCalls)) {
    throw new RangeError("maxTotalCalls must be a whole number, 0 or more");
  }
  for (const [pattern, rule] of Object.entries(options.rules ?? {})) {
    if (rule.maxCalls !== undefined && !isCount(rule.maxCalls)) {
      throw new RangeError(
        `rules[${shown(pattern)}].maxCalls must be a whole number, 0 or more`
      );
    }
  }
  const { flow } = options;
  if (
    !(
      flow === undefined ||
      flow === false ||
      flow === "untrusted" ||
      flow === "trifecta"
    )
  ) {
    throw new TypeError('flow must be "untrusted", "trifecta", or false');
  }
}

function copyCalls(calls: Map<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [name, count] of calls) {
    Object.defineProperty(out, name, {
      value: count,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

function refuse(
  tool: string,
  reason: ToolPolicyRefusal,
  message: string,
  violations?: SchemaViolation[]
): ToolPolicyDecision {
  return violations
    ? { allowed: false, reason, message, tool, violations }
    : { allowed: false, reason, message, tool };
}

/** What `evaluate` decided, with what `commit` and `approve` need to finish the call. */
interface Evaluation {
  decision: ToolPolicyDecision;
  name: string;
  args: unknown;
  rules: ToolPolicyRule[];
  approvable: boolean;
}

/**
 * Creates a tool call policy for one agent session or run. Call `check()`
 * (or `checkAsync()`) before each tool call and run the tool only when it
 * returns `allowed: true`, and call `recordResult()` after each tool
 * returns. Every rule is off until you configure it, except that `sink`
 * tools are refused once the session has seen untrusted content, which only
 * matters once tools are labeled.
 *
 * @example
 * ```ts
 * const policy = createToolPolicy({
 *   tools,
 *   deny: ["delete_*"],
 *   rules: {
 *     read_inbox: { labels: ["untrusted", "private"] },
 *     send_email: { labels: ["sink"], maxCalls: 3 },
 *   },
 * });
 * const decision = policy.check({ name: call.name, arguments: call.arguments });
 * ```
 */
export function createToolPolicy(options: ToolPolicyOptions = {}): ToolPolicy {
  checkOptions(options);
  const validate = options.validateArguments ?? true;
  const flow = options.flow ?? "untrusted";
  const ruleEntries = Object.entries(options.rules ?? {});
  /** Schemas by tool name, by source. */
  const declared = new Map<string, Map<string, unknown[]>>();
  const calls = new Map<string, number>();
  let total = 0;
  const untrustedFrom: string[] = [];
  const privateFrom: string[] = [];

  const restore = (state: ToolPolicyState): void => {
    const list = (value: unknown): unknown[] =>
      Array.isArray(value) ? value : [];
    for (const source of list(state.untrustedFrom)) {
      addSource(untrustedFrom, String(source));
    }
    for (const source of list(state.privateFrom)) {
      addSource(privateFrom, String(source));
    }
    for (const [name, count] of Object.entries(asRecord(state.calls) ?? {})) {
      if (isCount(count)) {
        calls.set(name, count);
        total += count;
      }
    }
  };

  const declareTools = (tools: ToolSet, source = DEFAULT_SOURCE): void => {
    const byName = new Map<string, unknown[]>();
    for (const [name, schema] of toolEntries(tools)) {
      const list = byName.get(name) ?? [];
      list.push(schema);
      byName.set(name, list);
    }
    declared.set(source, byName);
  };

  /** Every schema declared for `name`, or `undefined` when no source declares it. */
  const schemasFor = (name: string): unknown[] | undefined => {
    let found: unknown[] | undefined;
    for (const byName of declared.values()) {
      const list = byName.get(name);
      if (list) {
        found = [...(found ?? []), ...list];
      }
    }
    return found;
  };

  const rulesFor = (name: string): ToolPolicyRule[] =>
    ruleEntries
      .filter(([pattern]) => globMatch(pattern, name))
      .map(([, rule]) => rule);

  const labelsFor = (rules: ToolPolicyRule[], name: string): Set<ToolLabel> => {
    const labeled = rules.filter((rule) => rule.labels !== undefined);
    if (labeled.length === 0) {
      return new Set(options.guessLabels ? guessToolLabels(name) : []);
    }
    return new Set(labeled.flatMap((rule) => rule.labels ?? []));
  };

  const violationsFor = (
    schemas: unknown[],
    parsed: Parsed
  ): SchemaViolation[] => {
    if (schemas.every((schema) => schema === undefined)) {
      return [];
    }
    if (!parsed.ok) {
      return [{ path: "$", keyword: "json", message: "is not valid JSON" }];
    }
    for (const schema of schemas) {
      const violations = validateSchema(schema, parsed.value, MAX_VIOLATIONS);
      if (violations.length > 0) {
        return violations;
      }
    }
    return [];
  };

  /** A `call_limit` refusal, or `null` when the call is within its limits. */
  const limitRefusal = (
    name: string,
    rules: ToolPolicyRule[]
  ): ToolPolicyDecision | null => {
    const limits = rules
      .map((rule) => rule.maxCalls)
      .filter((limit): limit is number => limit !== undefined);
    const limit = limits.length > 0 ? Math.min(...limits) : undefined;
    if (limit !== undefined && (calls.get(name) ?? 0) >= limit) {
      return refuse(
        name,
        "call_limit",
        `Tool ${shown(name)} reached its limit of ${limit} call${limit === 1 ? "" : "s"} in this session.`
      );
    }
    const max = options.maxTotalCalls;
    if (max !== undefined && total >= max) {
      return refuse(
        name,
        "call_limit",
        `The session reached its limit of ${max} tool call${max === 1 ? "" : "s"}.`
      );
    }
    return null;
  };

  const tainted = (): boolean =>
    untrustedFrom.length > 0 && (flow !== "trifecta" || privateFrom.length > 0);

  const flowRefusal = (name: string): ToolPolicyDecision => {
    const seen =
      flow === "trifecta"
        ? `untrusted content from ${sourcesText(untrustedFrom)} and private data from ${sourcesText(privateFrom)}`
        : `untrusted content from ${sourcesText(untrustedFrom)}`;
    return refuse(
      name,
      "untrusted_to_sink",
      `Tool ${shown(name)} can send data out, and this session has seen ${seen}.`
    );
  };

  const listRefusal = (name: string): ToolPolicyDecision | null => {
    if (options.deny?.some((pattern) => globMatch(pattern, name))) {
      return refuse(
        name,
        "denied_tool",
        `Tool ${shown(name)} is on the deny list.`
      );
    }
    if (options.allow && !options.allow.some((p) => globMatch(p, name))) {
      return refuse(
        name,
        "tool_not_allowed",
        `Tool ${shown(name)} is not on the allow list.`
      );
    }
    return null;
  };

  /** The schemas declared for the call's tool, or `undefined` when it isn't declared. */
  const declaredSchemas = (
    call: ToolPolicyCall,
    name: string
  ): unknown[] | undefined => {
    const scoped =
      call.source === undefined ? undefined : declared.get(call.source);
    if (scoped) {
      return scoped.get(name);
    }
    return declared.size > 0 ? schemasFor(name) : [];
  };

  const argumentRefusal = (
    name: string,
    schemas: unknown[] | undefined,
    parsed: Parsed
  ): ToolPolicyDecision | null => {
    if (!schemas) {
      return refuse(
        name,
        "undeclared_tool",
        `Tool ${shown(name)} is not a declared tool.`
      );
    }
    const violations = validate ? violationsFor(schemas, parsed) : [];
    if (violations.length === 0) {
      return null;
    }
    const listed = violations.map((v) => `${v.path} ${v.message}`).join("; ");
    return refuse(
      name,
      "invalid_arguments",
      `The arguments for tool ${shown(name)} don't match its schema: ${listed}.`,
      violations
    );
  };

  /** The flow rule's refusal of a sink, unless every rule with destinations allows the call's. */
  const sinkRefusal = (
    name: string,
    rules: ToolPolicyRule[],
    args: unknown
  ): ToolPolicyDecision | null => {
    const sink = flow !== false && labelsFor(rules, name).has("sink");
    if (!(sink && tainted())) {
      return null;
    }
    const lists = rules.flatMap((rule) =>
      rule.destinations ? [rule.destinations] : []
    );
    const cleared =
      lists.length > 0 &&
      lists.every((destinations) => destinationsAllowed(destinations, args));
    return cleared ? null : flowRefusal(name);
  };

  /** Checks the name, the arguments, the limits, and the flow rule, without counting the call. */
  const evaluate = (call: ToolPolicyCall): Evaluation => {
    const name = typeof call.name === "string" ? call.name : "";
    const parsed = parseArguments(call.arguments);
    const args = parsed.ok ? parsed.value : undefined;
    const rules = rulesFor(name);
    const done = (decision: ToolPolicyDecision, approvable = false) => ({
      decision,
      name,
      args,
      rules,
      approvable,
    });
    const refusal =
      listRefusal(name) ??
      argumentRefusal(name, declaredSchemas(call, name), parsed) ??
      limitRefusal(name, rules);
    if (refusal) {
      return done(refusal);
    }
    const flowDecision = sinkRefusal(name, rules, args);
    if (flowDecision) {
      return done(flowDecision, true);
    }
    return done({
      allowed: true,
      reason: "allowed",
      message: "Allowed.",
      tool: name,
    });
  };

  /** Counts an allowed call, unless another call used up its limit in the meantime. */
  const commit = (
    evaluation: Evaluation,
    decision: ToolPolicyDecision
  ): ToolPolicyDecision => {
    const limit = limitRefusal(evaluation.name, evaluation.rules);
    if (limit) {
      return limit;
    }
    calls.set(evaluation.name, (calls.get(evaluation.name) ?? 0) + 1);
    total += 1;
    return decision;
  };

  const approved = (evaluation: Evaluation): ToolPolicyDecision =>
    commit(evaluation, {
      allowed: true,
      reason: "approved",
      message: "Allowed by approve().",
      tool: evaluation.name,
    });

  const approvalCall = (evaluation: Evaluation): ToolPolicyCall => ({
    name: evaluation.name,
    arguments: evaluation.args,
  });

  if (options.state) {
    restore(options.state);
  }
  if (options.tools) {
    declareTools(options.tools);
  }

  return {
    check(call) {
      const evaluation = evaluate(call);
      const { decision } = evaluation;
      if (decision.allowed) {
        return commit(evaluation, decision);
      }
      if (!(evaluation.approvable && options.approve)) {
        return decision;
      }
      const answer = options.approve(approvalCall(evaluation), decision);
      if (isThenable(answer)) {
        // Keep a rejected Promise from going unhandled.
        answer.then(undefined, () => undefined);
        throw new TypeError(
          "approve() returned a Promise: use checkAsync() instead of check()"
        );
      }
      return answer === true ? approved(evaluation) : decision;
    },
    async checkAsync(call) {
      const evaluation = evaluate(call);
      const { decision } = evaluation;
      if (decision.allowed) {
        return commit(evaluation, decision);
      }
      if (!(evaluation.approvable && options.approve)) {
        return decision;
      }
      const answer = await options.approve(approvalCall(evaluation), decision);
      return answer === true ? approved(evaluation) : decision;
    },
    recordResult(name, result = {}) {
      const labels = labelsFor(rulesFor(name), name);
      if (result.flagged || labels.has("untrusted")) {
        addSource(untrustedFrom, name);
      }
      if (labels.has("private")) {
        addSource(privateFrom, name);
      }
    },
    recordUntrusted(source = "input") {
      addSource(untrustedFrom, source);
    },
    recordPrivate(source = "input") {
      addSource(privateFrom, source);
    },
    declareTools,
    state() {
      return {
        untrustedFrom: [...untrustedFrom],
        privateFrom: [...privateFrom],
        calls: copyCalls(calls),
      };
    },
    reset() {
      calls.clear();
      total = 0;
      untrustedFrom.length = 0;
      privateFrom.length = 0;
    },
  };
}
