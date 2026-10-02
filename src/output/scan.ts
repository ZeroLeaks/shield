import { findCanary } from "./canary";
import { detectExfiltration, type ExfiltrationOptions } from "./exfiltration";
import { detectInjection, type InjectionOptions } from "./injection";
import { detectPII, type PIIOptions } from "./pii";
import { type RedactionText, redactFindings } from "./redact";
import { detectSecrets, type SecretsOptions } from "./secrets";
import type { OutputFinding, Severity } from "./types";
import { atLeast, compareFindings } from "./util";

export interface ScanOutputOptions {
  /** Credential detection. Default on. */
  secrets?: boolean | SecretsOptions;
  /** Personal data detection. Default off. */
  pii?: boolean | PIIOptions;
  /** Rendering and link exfiltration detection. Default on. */
  exfiltration?: boolean | ExfiltrationOptions;
  /**
   * Improper-output-handling detection: XSS and dangerous HTML, SQL injection
   * shapes, shell metacharacters, template injection, spreadsheet formula
   * injection, and path traversal. Default off. `true` turns on every
   * category; an object turns on the categories set to `true`
   * (`{ html: true, sql: true }`). See `InjectionOptions`.
   */
  injection?: boolean | InjectionOptions;
  /** Canary token(s) planted in the system prompt (see `createCanary`). */
  canary?: string | readonly string[];
  /** Replacement text for redacted spans. Default "[REDACTED]". */
  redactionText?: RedactionText<OutputFinding>;
  /** Only redact findings at or above this severity. Default "low" (all findings). */
  redactMinSeverity?: Severity;
}

export interface ScanOutputResult {
  /** Every finding, ordered by start offset. */
  findings: OutputFinding[];
  /** The text with findings redacted. */
  redacted: string;
  /** True when any finding is high or critical. */
  blocked: boolean;
}

function enabled<T extends object>(
  option: boolean | T | undefined,
  byDefault: boolean
): T | null {
  if (option === undefined) {
    return byDefault ? ({} as T) : null;
  }
  if (typeof option === "boolean") {
    return option ? ({} as T) : null;
  }
  return option;
}

/**
 * Runs the output detectors over one piece of model output and returns the
 * findings, a redacted copy, and whether to block it. Secrets and
 * exfiltration are on by default; PII, injection, and canaries are opt-in.
 */
export function scanOutputText(
  text: string,
  options: ScanOutputOptions = {}
): ScanOutputResult {
  const findings: OutputFinding[] = [];
  const secrets = enabled(options.secrets, true);
  if (secrets) {
    findings.push(...detectSecrets(text, secrets));
  }
  const pii = enabled(options.pii, false);
  if (pii) {
    findings.push(...detectPII(text, pii));
  }
  const exfiltration = enabled(options.exfiltration, true);
  if (exfiltration) {
    findings.push(...detectExfiltration(text, exfiltration));
  }
  const injection = enabled(options.injection, false);
  if (injection) {
    findings.push(...detectInjection(text, injection));
  }
  const canaries =
    typeof options.canary === "string"
      ? [options.canary]
      : (options.canary ?? []);
  for (const canary of canaries) {
    findings.push(...findCanary(text, canary));
  }
  findings.sort(compareFindings);
  const floor = options.redactMinSeverity ?? "low";
  const redacted = redactFindings(
    text,
    findings.filter((f) => atLeast(f.severity, floor)),
    { redactionText: options.redactionText }
  );
  return {
    findings,
    redacted,
    blocked: findings.some((f) => atLeast(f.severity, "high")),
  };
}
