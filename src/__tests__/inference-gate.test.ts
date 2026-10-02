import { describe, expect, it } from "vitest";
import { InferenceGate } from "../server/inference-gate";

describe("native CPU execution slots", () => {
  it("gives a waiting short request a turn before the next long-request batch", async () => {
    const gate = new InferenceGate();
    const first = await gate.acquire();
    const order: string[] = [];
    const short = gate.acquire().then((release) => {
      order.push("short");
      release();
    });
    first();
    const next = gate.acquire().then((release) => {
      order.push("long-next-batch");
      release();
    });
    await Promise.all([short, next]);
    expect(order).toEqual(["short", "long-next-batch"]);
  });

  it("removes cancelled waiters without releasing an active native batch", async () => {
    const gate = new InferenceGate();
    const release = await gate.acquire();
    const abort = new AbortController();
    const reason = new Error("client cancelled");
    const cancelled = gate.acquire(abort.signal);
    abort.abort(reason);
    await expect(cancelled).rejects.toBe(reason);
    let granted = false;
    const next = gate.acquire().then((done) => {
      granted = true;
      done();
    });
    await Promise.resolve();
    expect(granted).toBe(false);
    release();
    release();
    await next;
    expect(granted).toBe(true);
  });

  it("reserves foreground capacity independently of an ensemble native call", async () => {
    const direct = new InferenceGate();
    const ensemble = new InferenceGate();
    const background = await ensemble.acquire();
    const foreground = await direct.acquire();
    foreground();
    background();
  });
});
