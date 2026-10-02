/**
 * Wraps an MCP client (`@modelcontextprotocol/sdk`): the tools a server
 * lists are checked for tool poisoning, what its tools, resources, and
 * prompts return is checked for injection before it reaches a model, and
 * with a tool policy, each tool call is checked against it first.
 */

import type { DetectResult } from "../detect";
import {
  InjectionDetectedError,
  OutputBlockedError,
  ToolPolicyError,
} from "../errors";
import { type ScanOutputOptions, scanOutputText } from "../output/scan";
import { atLeast } from "../output/util";
import type { ToolPolicy } from "../policy";
import {
  pinTools,
  type ScanToolsOptions,
  scanToolsAsync,
  type ToolDefinition,
  type ToolPins,
  type ToolScanResult,
} from "../tools";
import { createShield, jsonText, type ShieldProviderOptions } from "./guard";
import { decodeTextBlob, isRecord, withOverrides } from "./shared";

export interface ShieldMcpOptions
  extends Pick<
    ShieldProviderOptions,
    "detect" | "scanToolResults" | "onDetection" | "onInjectionDetected"
  > {
  /**
   * Options for checking the tools `listTools` returns with `scanTools`, or
   * `false` to leave them unchecked. Default: the detect options tool
   * results use.
   */
  scanTools?: ScanToolsOptions | false;
  /**
   * What happens to a tool `scanTools` flags: `"drop"` (default) leaves it
   * out of the list, `"throw"` throws `InjectionDetectedError` with source
   * `"tool"`, and `"warn"` keeps it.
   */
  onFlaggedTools?: "drop" | "throw" | "warn";
  /** Called with each flagged tool and its scan result, in every mode. */
  onToolFlagged?: (tool: ToolDefinition, result: ToolScanResult) => void;
  /**
   * Pins each tool's definition the first time `listTools` returns it
   * unflagged, and flags the tool as `changed_since_pinned` when a later
   * list returns a different definition (a "rug pull"). Pass an object to
   * keep pins across sessions: the client adds new tools to it, so save it
   * with `JSON.stringify` and pass it back next time. To accept a changed
   * tool, delete its entry. `false` turns pinning off. Default: pins kept
   * for the life of the wrapped client.
   */
  pins?: ToolPins | false;
  /**
   * Refuse `callTool` for a tool the latest `listTools` flagged, with
   * `InjectionDetectedError`, before the server is called. Dropping a tool
   * only hides it from the list; this stops a call to it by name. Default
   * `true`, except with `onFlaggedTools: "warn"`.
   */
  blockFlaggedToolCalls?: boolean;
  /**
   * Checks the arguments of every `callTool` with `scanOutputText()` before
   * the server is called, and throws `OutputBlockedError` for any high or
   * critical finding, such as a credential or a link that carries data out.
   * `false` turns it off. Default: the `scanOutputText()` defaults, secrets
   * and exfiltration links.
   */
  scanArguments?: ScanOutputOptions | false;
  /**
   * A tool policy from `createToolPolicy()`, for one session. The tools
   * `listTools` returns are declared to it, as this client's own, `callTool`
   * runs `policy.checkAsync()` before the server is called and throws
   * `ToolPolicyError` when the policy refuses the call, and each tool result
   * is recorded with `policy.recordResult()`, flagged when detection found an
   * injection in it. A resource or prompt with an injection is recorded
   * with `policy.recordUntrusted()`. Default: none.
   */
  policy?: ToolPolicy;
}

/** Text of tool call arguments for the output detectors, up to 64KB. */
function argumentText(args: unknown): string {
  if (typeof args === "string") {
    return args.slice(0, 65_536);
  }
  try {
    return (JSON.stringify(args) ?? "").slice(0, 65_536);
  } catch {
    return "";
  }
}

const RISKS: DetectResult["risk"][] = [
  "none",
  "low",
  "medium",
  "high",
  "critical",
];

function isString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** Text of a resource's contents: its text, or a text blob decoded. */
function resourceText(resource: unknown): string {
  if (!isRecord(resource)) {
    return "";
  }
  return typeof resource.text === "string"
    ? resource.text
    : decodeTextBlob(resource.blob, resource.mimeType);
}

/** Text a model reads from a content block: text, an embedded resource, or a resource link's title and description. */
function blockText(block: unknown): string {
  if (!isRecord(block)) {
    return "";
  }
  switch (block.type) {
    case "text":
      return typeof block.text === "string" ? block.text : "";
    case "resource":
      return resourceText(block.resource);
    case "resource_link":
      return [block.title, block.description].filter(isString).join("\n");
    default:
      return "";
  }
}

function joined(texts: string[]): string {
  return texts.filter(Boolean).join("\n");
}

const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/**
 * Text of a tool call result: its content blocks, the strings in its
 * structured content, and a legacy `toolResult`.
 */
function toolResultText(result: unknown): string {
  if (!isRecord(result)) {
    return "";
  }
  const texts = list(result.content).map(blockText);
  if (result.structuredContent !== undefined) {
    texts.push(jsonText(result.structuredContent));
  }
  if (result.toolResult !== undefined) {
    texts.push(jsonText(result.toolResult));
  }
  return joined(texts);
}

function resourcesText(result: unknown): string {
  return isRecord(result)
    ? joined(list(result.contents).map(resourceText))
    : "";
}

/** Text of a prompt: its description and every message's content. */
function promptText(result: unknown): string {
  if (!isRecord(result)) {
    return "";
  }
  const texts = list(result.messages).map((message) =>
    isRecord(message) ? blockText(message.content) : ""
  );
  return joined([
    typeof result.description === "string" ? result.description : "",
    ...texts,
  ]);
}

function isFlagged(scan: ToolScanResult): boolean {
  return scan.result.detected || scan.issues.length > 0;
}

/**
 * One error for every flagged tool: the highest risk found, or `"low"` when
 * the tools were flagged only for issues, and every category and issue.
 */
function flaggedToolsError(flagged: ToolScanResult[]): InjectionDetectedError {
  let risk = 1;
  const categories = new Set<string>();
  for (const scan of flagged) {
    if (scan.result.detected) {
      risk = Math.max(risk, RISKS.indexOf(scan.result.risk));
    }
    for (const match of scan.result.matches) {
      categories.add(match.category);
    }
    for (const issue of scan.issues) {
      categories.add(issue);
    }
  }
  return new InjectionDetectedError(RISKS[risk], [...categories], "tool");
}

function toolScanOptions(options: ShieldMcpOptions): ScanToolsOptions | null {
  if (options.scanTools === false) {
    return null;
  }
  if (options.scanTools) {
    return options.scanTools;
  }
  if (typeof options.scanToolResults === "object") {
    return options.scanToolResults;
  }
  return options.detect || {};
}

type Method = (...args: unknown[]) => Promise<unknown>;

/** Tells apart the tools each wrapped client declares to a shared policy. */
let policySources = 0;

interface McpClient {
  listTools(...args: unknown[]): unknown;
  callTool(...args: unknown[]): unknown;
  readResource(...args: unknown[]): unknown;
  getPrompt(...args: unknown[]): unknown;
}

/**
 * Wraps an MCP `Client` so tool lists are checked for tool poisoning and
 * flagged tools are dropped, and tool results, resources, and prompts are
 * checked for injection like tool results in the other wrappers. With
 * `policy`, every tool call must pass a tool policy from
 * `createToolPolicy()` before the server is called.
 *
 * @example
 * ```ts
 * import { Client } from "@modelcontextprotocol/sdk/client/index.js";
 * import { shieldMcpClient } from "@zeroleaks/shield/mcp";
 *
 * const client = shieldMcpClient(new Client({ name: "agent", version: "1.0.0" }));
 * await client.connect(transport);
 * const { tools } = await client.listTools(); // flagged tools left out
 * ```
 */
export function shieldMcpClient<
  // Method syntax makes the parameter check bivariant, so the SDK's
  // `Client`, whose methods take specific param types, satisfies it.
  T extends McpClient,
>(client: T, options: ShieldMcpOptions = {}): T {
  const { input } = createShield(options);
  const scanOptions = toolScanOptions(options);
  const mode = options.onFlaggedTools ?? "drop";
  const pins: ToolPins | null =
    options.pins === false ? null : (options.pins ?? Object.create(null));
  const blockCalls =
    scanOptions !== null && (options.blockFlaggedToolCalls ?? mode !== "warn");
  const argumentOptions =
    options.scanArguments === false ? null : (options.scanArguments ?? {});
  /** Tools the latest list flagged, by name, with their scan results. */
  const flaggedByName = new Map<string, ToolScanResult>();
  const { policy } = options;
  policySources += 1;
  const policySource = `mcp:${policySources}`;
  /** The tools declared to the policy: every page of the latest list. */
  let declared: ToolDefinition[] = [];
  const blocking = (options.onDetection ?? "block") === "block";

  /** Declares the tools a list returned; a page fetched with a cursor adds to the pages before it. */
  const declare = (tools: unknown[], args: unknown[]): void => {
    if (!policy) {
      return;
    }
    const page = tools.filter(isRecord) as ToolDefinition[];
    const nextPage = isRecord(args[0]) && typeof args[0].cursor === "string";
    declared = nextPage ? [...declared, ...page] : page;
    policy.declareTools(declared, policySource);
  };

  /** Adds the pins `pinTools` made for `tools` to `pins` itself, which the caller may have passed in. */
  const pinNew = (tools: ToolDefinition[]): void => {
    if (!pins) {
      return;
    }
    const added = pinTools(tools, pins);
    for (const name of Object.keys(added)) {
      if (Object.getOwnPropertyDescriptor(pins, name) === undefined) {
        Object.defineProperty(pins, name, {
          value: added[name],
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
    }
  };

  /** Detection's result for the text of a result, reported to `onInjectionDetected`; `undefined` when tool results aren't checked. */
  const inspect = async (
    result: unknown,
    textOf: (result: unknown) => string
  ): Promise<DetectResult | undefined> =>
    input.tool ? await input.inspect(textOf(result), "tool") : undefined;

  const throwIfBlocking = (detection: DetectResult | undefined): void => {
    if (detection?.detected && blocking) {
      throw new InjectionDetectedError(
        detection.risk,
        detection.matches.map((m) => m.category),
        "tool"
      );
    }
  };

  /** Calls `method` and checks the text `textOf` finds in its result as a tool result. */
  const checked =
    (
      method: Method,
      textOf: (result: unknown) => string,
      source: string
    ): Method =>
    async (...args) => {
      const result = await method(...args);
      const detection = await inspect(result, textOf);
      if (detection?.detected) {
        policy?.recordUntrusted(source);
      }
      throwIfBlocking(detection);
      return result;
    };

  const listTools: Method = async (...args) => {
    const result = await client.listTools(...args);
    if (!(isRecord(result) && Array.isArray(result.tools))) {
      return result;
    }
    const tools: unknown[] = result.tools;
    if (!scanOptions) {
      declare(tools, args);
      return result;
    }
    const scans = (
      await scanToolsAsync(tools as ToolDefinition[], {
        ...scanOptions,
        pins: pins ?? undefined,
      })
    ).tools;
    const flagged = new Set<number>();
    const clean: ToolDefinition[] = [];
    for (const [i, scan] of scans.entries()) {
      if (isFlagged(scan)) {
        flagged.add(i);
        flaggedByName.set(scan.name, scan);
        options.onToolFlagged?.(tools[i] as ToolDefinition, scan);
      } else {
        flaggedByName.delete(scan.name);
        clean.push(tools[i] as ToolDefinition);
      }
    }
    pinNew(clean);
    declare(mode === "warn" ? tools : clean, args);
    if (flagged.size === 0 || mode === "warn") {
      return result;
    }
    if (mode === "throw") {
      throw flaggedToolsError(scans.filter((_, i) => flagged.has(i)));
    }
    return { ...result, tools: tools.filter((_, i) => !flagged.has(i)) };
  };

  const callTool: Method = async (...args) => {
    const params = isRecord(args[0]) ? args[0] : undefined;
    const name = typeof params?.name === "string" ? params.name : "";
    const flaggedScan = blockCalls ? flaggedByName.get(name) : undefined;
    if (flaggedScan) {
      throw flaggedToolsError([flaggedScan]);
    }
    if (argumentOptions && params && params.arguments !== undefined) {
      const scan = scanOutputText(
        argumentText(params.arguments),
        argumentOptions
      );
      const high = scan.findings.filter((f) => atLeast(f.severity, "high"));
      if (high.length > 0) {
        throw new OutputBlockedError(high);
      }
    }
    if (policy) {
      const decision = await policy.checkAsync({
        name,
        arguments: params?.arguments,
        source: policySource,
      });
      if (!decision.allowed) {
        throw new ToolPolicyError(decision);
      }
    }
    const result = await client.callTool(...args);
    const detection = await inspect(result, toolResultText);
    policy?.recordResult(name, { flagged: Boolean(detection?.detected) });
    throwIfBlocking(detection);
    return result;
  };

  return withOverrides(client, {
    listTools,
    callTool,
    readResource: checked(
      async (...args) => await client.readResource(...args),
      resourcesText,
      "readResource"
    ),
    getPrompt: checked(
      async (...args) => await client.getPrompt(...args),
      promptText,
      "getPrompt"
    ),
  });
}
