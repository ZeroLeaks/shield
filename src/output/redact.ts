export interface RedactableFinding {
  start: number;
  end: number;
  kind?: string;
  type?: string;
}

export interface MergedRange<T extends RedactableFinding> {
  start: number;
  end: number;
  /** Findings covered by this range, in order of start offset (longest first). */
  findings: T[];
}

/**
 * Replacement for a merged range: a fixed string, or a function of the first
 * finding in the range (plus every finding merged into it).
 */
export type RedactionText<T extends RedactableFinding = RedactableFinding> =
  | string
  | ((finding: T, merged: readonly T[]) => string);

export interface RedactOptions<
  T extends RedactableFinding = RedactableFinding,
> {
  /** Default "[REDACTED]". Pass `redactionLabel` for "[REDACTED:email]"-style text. */
  redactionText?: RedactionText<T>;
}

export const DEFAULT_REDACTION_TEXT = "[REDACTED]";

/** Type-aware replacement text: "[REDACTED:<kind>]" (or the type when there is no kind). */
export function redactionLabel(finding: RedactableFinding): string {
  return `[REDACTED:${finding.kind ?? finding.type ?? "value"}]`;
}

/**
 * Sorts ranges and merges the ones that overlap or touch. Offsets are clamped
 * to `[0, textLength]`; empty and non-finite ranges are dropped.
 */
export function mergeRanges<T extends RedactableFinding>(
  ranges: readonly T[],
  textLength: number = Number.POSITIVE_INFINITY
): MergedRange<T>[] {
  const valid: { start: number; end: number; finding: T }[] = [];
  for (const finding of ranges) {
    const start = Math.max(0, Math.floor(finding.start));
    const end = Math.min(textLength, Math.ceil(finding.end));
    if (Number.isFinite(start) && Number.isFinite(end) && start < end) {
      valid.push({ start, end, finding });
    }
  }
  valid.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: MergedRange<T>[] = [];
  let current: MergedRange<T> | null = null;
  for (const range of valid) {
    if (current && range.start <= current.end) {
      current.end = Math.max(current.end, range.end);
      current.findings.push(range.finding);
    } else {
      current = {
        start: range.start,
        end: range.end,
        findings: [range.finding],
      };
      merged.push(current);
    }
  }
  return merged;
}

/**
 * Replaces every finding's `[start, end)` span with the redaction text.
 * Overlapping and adjacent spans are merged first, so each leaked region is
 * replaced once.
 */
export function redactFindings<T extends RedactableFinding>(
  text: string,
  findings: readonly T[],
  options: RedactOptions<T> = {}
): string {
  const merged = mergeRanges(findings, text.length);
  if (merged.length === 0) {
    return text;
  }
  const replacement = options.redactionText ?? DEFAULT_REDACTION_TEXT;
  const parts: string[] = [];
  let cursor = 0;
  for (const range of merged) {
    parts.push(text.slice(cursor, range.start));
    parts.push(
      typeof replacement === "function"
        ? replacement(range.findings[0], range.findings)
        : replacement
    );
    cursor = range.end;
  }
  parts.push(text.slice(cursor));
  return parts.join("");
}
