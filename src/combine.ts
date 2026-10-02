import type { DetectResult } from "./detect";

/** A detector for `escalate` or `secondaryDetector`: a detection, or `null` when the input is clean. */
export type AsyncDetector = (
  input: string,
  result: DetectResult
) => Promise<DetectResult | null>;

/**
 * Runs several detectors at once and reports a detection as soon as any of
 * them detects, without waiting for the others. Resolves to `null` when all
 * of them find the input clean. A detector that rejects rejects the whole
 * call, unless another one detected first.
 *
 * @example
 * ```ts
 * const result = await detectAsync(text, {
 *   escalate: { minScore: 0, detector: anyOf(modelDetector, llmDetector) },
 * });
 * ```
 */
export function anyOf(...detectors: AsyncDetector[]): AsyncDetector {
  return (input, result) =>
    new Promise((resolve, reject) => {
      let pending = detectors.length;
      let settled = false;
      if (pending === 0) {
        resolve(null);
        return;
      }
      for (const detector of detectors) {
        detector(input, result).then(
          (found) => {
            if (settled) {
              return;
            }
            if (found?.detected) {
              settled = true;
              resolve(found);
              return;
            }
            pending--;
            if (pending === 0) {
              settled = true;
              resolve(null);
            }
          },
          (error: unknown) => {
            if (!settled) {
              settled = true;
              reject(error);
            }
          }
        );
      }
    });
}
