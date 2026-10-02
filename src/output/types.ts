export type Severity = "low" | "medium" | "high" | "critical";

export type OutputFindingType =
  | "secret"
  | "pii"
  | "exfiltration"
  | "injection"
  | "canary"
  | "prompt_leak";

export interface OutputFinding {
  type: OutputFindingType;
  /** Specific detector, e.g. "aws_access_key_id", "email", "markdown_image". */
  kind: string;
  /** [start, end) offsets into the scanned text (UTF-16 code units). */
  start: number;
  end: number;
  severity: Severity;
  /** 0..1 */
  confidence: number;
  /** Safe-to-log preview that never contains the full secret, e.g. "sk-proj-…9f2a" or "j***@example.com". */
  preview: string;
}
