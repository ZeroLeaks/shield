import {
  type DetectOptions,
  type DetectResult,
  detect,
  slowDetection,
} from "./detect";
import { ShieldError } from "./errors";

/**
 * A tool definition in any of the common shapes: MCP (`inputSchema`),
 * OpenAI (`{ type: "function", function: { ... } }` or a Responses API
 * function tool), Anthropic (`input_schema`), or an AI SDK tool
 * (`parameters` or `inputSchema`).
 */
export type ToolDefinition = Record<string, unknown>;

export interface ToolScanResult {
  name: string;
  /** Detection over the tool's descriptions and schema text. */
  result: DetectResult;
  /** Other problems with the definition itself. */
  issues: Array<
    | "duplicate_name"
    | "hidden_characters_in_name"
    | "oversized_description"
    | "changed_since_pinned"
  >;
}

/**
 * Tool definitions as pinned by `pinTools()`: each tool's name mapped to the
 * canonical JSON of what the model reads from it. Plain data, so it can be
 * saved with `JSON.stringify` and loaded back with `JSON.parse`.
 */
export type ToolPins = Record<string, string>;

export interface ScanToolsResult {
  /** True when any tool was flagged or has an issue. */
  flagged: boolean;
  tools: ToolScanResult[];
}

export interface ScanToolsOptions extends DetectOptions {
  /** Descriptions longer than this are reported as `oversized_description`. Default 4000. */
  maxDescriptionLength?: number;
  /**
   * Definitions pinned earlier with `pinTools()`. A tool whose pinned
   * definition differs from the one it has now is reported as
   * `changed_since_pinned`: a server can change a tool after it was
   * reviewed or approved (a "rug pull").
   */
  pins?: ToolPins;
}

const RE_INVISIBLE_IN_NAME =
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: the class lists combining and format characters on purpose, to find or strip them.
  /[\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]|\udb40[\udc00-\udc7f]/;
const RE_NON_ASCII = /[^\x20-\x7e]/;
const MAX_SCHEMA_DEPTH = 16;
const RE_IDENTIFIER_SEPARATORS = /[_\-.]+/g;
const RE_CAMEL_BOUNDARY = /([a-z0-9])([A-Z])/g;

/** "readSshKey_first" -> "read Ssh Key first": models read names as words. */
export function identifierWords(name: string): string {
  return name
    .replace(RE_CAMEL_BOUNDARY, "$1 $2")
    .replace(RE_IDENTIFIER_SEPARATORS, " ");
}
/** Schema keys whose values are free text the model reads. */
const TEXT_KEYS = new Set([
  "description",
  "title",
  "examples",
  "example",
  "default",
  "enum",
  "const",
]);
/** Schema keys whose values are maps from names to schemas. */
const NAMED_KEYS = new Set([
  "properties",
  "patternProperties",
  "$defs",
  "definitions",
]);

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/** The part of a definition that holds name, description, and schema. */
export function unwrap(tool: ToolDefinition): Record<string, unknown> {
  return asRecord(tool.function) ?? tool;
}

/** The input schema of an unwrapped definition, in whichever field its shape keeps it. */
export function schemaOf(def: Record<string, unknown>): unknown {
  return (
    def.inputSchema ??
    def.input_schema ??
    def.parameters ??
    asRecord(def.annotations)?.inputSchema
  );
}

/** `value` with object keys sorted at every depth, so equal definitions serialize equally. */
function canonical(value: unknown, depth = 0): unknown {
  if (depth > MAX_SCHEMA_DEPTH || value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonical(item, depth + 1));
  }
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    Object.defineProperty(out, key, {
      value: canonical((value as Record<string, unknown>)[key], depth + 1),
      enumerable: true,
    });
  }
  return out;
}

/** What a tool's definition pins: everything the model reads from it, keys sorted. */
function fingerprint(def: Record<string, unknown>): string {
  return JSON.stringify(
    canonical({
      annotations: def.annotations ?? null,
      description: def.description ?? null,
      inputSchema: schemaOf(def) ?? null,
      outputSchema: def.outputSchema ?? null,
      title: def.title ?? null,
    })
  );
}

function hasPin(pins: ToolPins, name: string): boolean {
  return Object.getOwnPropertyDescriptor(pins, name) !== undefined;
}

/**
 * Pins tool definitions, so a later `scanTools(tools, { pins })` reports any
 * tool whose definition changed. Returns a copy of `pins` with every tool in
 * `tools` that was not pinned yet added; tools already pinned keep their pin,
 * so a changed tool stays reported until you remove its entry.
 */
export function pinTools(
  tools: ToolDefinition[],
  pins: ToolPins = {}
): ToolPins {
  const out: ToolPins = {};
  for (const name of Object.keys(pins)) {
    Object.defineProperty(out, name, {
      value: pins[name],
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  for (const tool of tools) {
    const def = unwrap(tool);
    const name = String(def.name ?? "");
    if (!hasPin(out, name)) {
      Object.defineProperty(out, name, {
        value: fingerprint(def),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
  }
  return out;
}

/**
 * Collects the free text a model reads from a JSON schema: descriptions,
 * titles, examples, defaults, enum values, and parameter names, at any depth.
 */
function schemaText(
  schema: unknown,
  out: string[],
  depth = 0,
  inText = false
): void {
  if (depth > MAX_SCHEMA_DEPTH) {
    return;
  }
  if (typeof schema === "string") {
    out.push(schema);
    return;
  }
  if (Array.isArray(schema)) {
    for (const item of schema) {
      schemaText(item, out, depth + 1, inText);
    }
    return;
  }
  const record = asRecord(schema);
  if (!record) {
    return;
  }
  for (const [key, value] of Object.entries(record)) {
    entryText(key, value, out, depth, inText);
  }
}

/** Collects the text of one schema entry. */
function entryText(
  key: string,
  value: unknown,
  out: string[],
  depth: number,
  inText: boolean
): void {
  if (inText || TEXT_KEYS.has(key)) {
    if (inText) {
      out.push(key);
    }
    schemaText(value, out, depth + 1, true);
    return;
  }
  const names = NAMED_KEYS.has(key) ? asRecord(value) : undefined;
  if (names) {
    // Parameter names are read by the model too, so they can carry
    // instructions of their own.
    for (const name of Object.keys(names)) {
      out.push(identifierWords(name));
    }
  }
  if (value !== null && typeof value === "object") {
    schemaText(value, out, depth + 1, false);
  }
}

function toolText(tool: ToolDefinition): string {
  const def = unwrap(tool);
  const texts = [typeof def.description === "string" ? def.description : ""];
  schemaText(schemaOf(def), texts);
  return texts.filter(Boolean).join("\n");
}

/**
 * Checks tool descriptions and schemas locally, along with duplicate names,
 * hidden name characters, and changed definitions. For asynchronous detectors,
 * use scanToolsAsync.
 */
export function scanTools(
  tools: ToolDefinition[],
  options: ScanToolsOptions = {}
): ScanToolsResult {
  if (options.secondaryDetector || options.escalate) {
    throw new ShieldError(
      "Use scanToolsAsync for hosted or asynchronous detection.",
      "ASYNC_DETECTION_REQUIRES_AWAIT"
    );
  }
  const { maxDescriptionLength = 4000, pins, ...detectOptions } = options;
  const counts = new Map<string, number>();
  for (const tool of tools) {
    const name = String(unwrap(tool).name ?? "");
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }

  const results = tools.map((tool): ToolScanResult => {
    const def = unwrap(tool);
    const name = String(def.name ?? "");
    const description =
      typeof def.description === "string" ? def.description : "";
    const result = detect(toolText(tool), detectOptions);

    const issues: ToolScanResult["issues"] = [];
    if ((counts.get(name) ?? 0) > 1) {
      issues.push("duplicate_name");
    }
    if (RE_INVISIBLE_IN_NAME.test(name) || RE_NON_ASCII.test(name)) {
      issues.push("hidden_characters_in_name");
    }
    if (description.length > maxDescriptionLength) {
      issues.push("oversized_description");
    }
    if (pins && hasPin(pins, name) && pins[name] !== fingerprint(def)) {
      issues.push("changed_since_pinned");
    }
    return { name, result, issues };
  });

  return {
    flagged: results.some((r) => r.result.detected || r.issues.length > 0),
    tools: results,
  };
}

/** Checks tool definitions with hosted, model, or other asynchronous detectors. */
export async function scanToolsAsync(
  tools: ToolDefinition[],
  options: ScanToolsOptions = {}
): Promise<ScanToolsResult> {
  if (!(options.secondaryDetector || options.escalate)) {
    return scanTools(tools, options);
  }
  const scans = scanTools(tools, {
    ...options,
    secondaryDetector: undefined,
    escalate: undefined,
  });
  for (const [index, scan] of scans.tools.entries()) {
    const text = toolText(tools[index]);
    if (text) {
      const pending = slowDetection(text, scan.result, options);
      if (pending) {
        scan.result = await pending;
      }
    }
  }
  return {
    flagged: scans.tools.some(
      (scan) => scan.result.detected || scan.issues.length > 0
    ),
    tools: scans.tools,
  };
}
