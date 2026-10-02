import type { OutputFinding } from "./output";
import type {
  SchemaViolation,
  ToolPolicyDecision,
  ToolPolicyReason,
} from "./policy";

export class ShieldError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "ShieldError";
    this.code = code;
  }
}

/** Where an injection was found: a user message, or a tool result or document the model reads. */
export type InjectionSource = "user" | "tool";

export class InjectionDetectedError extends ShieldError {
  readonly risk: string;
  readonly categories: string[];
  /** Set by the provider wrappers. */
  readonly source?: InjectionSource;

  constructor(risk: string, categories: string[], source?: InjectionSource) {
    super(
      `Prompt injection detected${source === "tool" ? " in a tool result" : ""} (${risk} risk): ${categories.join(", ")}`,
      "INJECTION_DETECTED"
    );
    this.name = "InjectionDetectedError";
    this.risk = risk;
    this.categories = categories;
    if (source) {
      this.source = source;
    }
  }
}

export class LeakDetectedError extends ShieldError {
  readonly confidence: number;
  readonly fragmentCount: number;

  constructor(confidence: number, fragmentCount: number) {
    super(
      `System prompt leak detected (confidence: ${Math.round(confidence * 100)}%, ${fragmentCount} fragment${fragmentCount === 1 ? "" : "s"})`,
      "LEAK_DETECTED"
    );
    this.name = "LeakDetectedError";
    this.confidence = confidence;
    this.fragmentCount = fragmentCount;
  }
}

/** What an `OutputBlockedError` keeps of each finding: never the matched text. */
export type BlockedFinding = Pick<OutputFinding, "type" | "kind" | "severity">;

const MAX_LISTED_FINDINGS = 5;

/** Thrown instead of redacting when model output has a high or critical finding. */
export class OutputBlockedError extends ShieldError {
  readonly findings: BlockedFinding[];

  constructor(findings: readonly BlockedFinding[]) {
    const kept = findings.map(({ type, kind, severity }) => ({
      type,
      kind,
      severity,
    }));
    const labels = [
      ...new Set(kept.map((f) => `${f.type}:${f.kind} (${f.severity})`)),
    ];
    const listed = labels.slice(0, MAX_LISTED_FINDINGS).join(", ");
    const more =
      labels.length > MAX_LISTED_FINDINGS
        ? ` and ${labels.length - MAX_LISTED_FINDINGS} more`
        : "";
    super(`Model output blocked: ${listed}${more}`, "OUTPUT_BLOCKED");
    this.name = "OutputBlockedError";
    this.findings = kept;
  }
}

/**
 * Thrown when a tool policy refuses a tool call, before the tool runs. It
 * carries the policy's decision: the tool, the reason, and for invalid
 * arguments where they are wrong, never the argument values.
 */
export class ToolPolicyError extends ShieldError {
  /** The tool's name, as the call gave it. */
  readonly tool: string;
  /** Why the call was refused, such as `"undeclared_tool"` or `"untrusted_to_sink"`. */
  readonly reason: ToolPolicyReason;
  /** With `invalid_arguments`: the first violations, by path and keyword. Otherwise empty. */
  readonly violations: SchemaViolation[];

  constructor(
    decision: Pick<
      ToolPolicyDecision,
      "tool" | "reason" | "message" | "violations"
    >
  ) {
    super(decision.message, "TOOL_POLICY_VIOLATION");
    this.name = "ToolPolicyError";
    this.tool = decision.tool;
    this.reason = decision.reason;
    this.violations = decision.violations ? [...decision.violations] : [];
  }
}
