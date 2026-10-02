import { vi } from "vitest";
import type { DetectResult } from "../detect";

/** What the slow detector reports: an injection the fast check missed. */
export const ESCALATED: DetectResult = {
  detected: true,
  risk: "high",
  matches: [{ category: "escalated", pattern: "llm", confidence: 0.9 }],
};

/**
 * An `escalate` detector for every text, with a verdict the test gives when
 * it is ready: `clean()` keeps Shield's result, `flag()` reports
 * `ESCALATED`, `clear()` overrules a detection (as a `secondaryDetector`),
 * and `fail(error)` throws. Every call waits for the same verdict.
 */
export function slowDetector() {
  let resolve: (result: DetectResult | null) => void = () => undefined;
  let reject: (error: Error) => void = () => undefined;
  const verdict = new Promise<DetectResult | null>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  const detector = vi.fn((_input: string, _result: DetectResult) => verdict);
  return {
    detector,
    detect: { escalate: { minScore: 0, detector } },
    clean: () => resolve(null),
    flag: () => resolve(ESCALATED),
    clear: () => resolve({ detected: false, risk: "none", matches: [] }),
    fail: (error: Error) => reject(error),
  };
}

/** Whether `promise` settles once everything already queued has run. */
export async function settlesNow(promise: Promise<unknown>): Promise<boolean> {
  let settled = false;
  promise.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    }
  );
  await new Promise((resolve) => setTimeout(resolve, 0));
  return settled;
}

/**
 * An SDK-style stream of `items` with an abort controller, like the OpenAI
 * and Anthropic SDKs' `Stream`. `read` counts the items taken from it.
 */
export function abortableStream<T>(items: T[]) {
  const controller = { abort: vi.fn() };
  const read = vi.fn();
  const stream = (async function* () {
    for await (const item of items) {
      read();
      yield item;
    }
  })();
  return Object.assign(stream, { controller, read });
}
