import { readFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ServingModel } from "../server/classifier";
import { InferenceGate } from "../server/inference-gate";
import { createModelProcess } from "../server/model-process";

const workers: ServingModel[] = [];
const worker = new URL("./fixtures/model-process.mjs", import.meta.url);

function create(gate?: InferenceGate, scenario?: string): ServingModel {
  const model = createModelProcess({
    model: { localPath: "/test/model", allowDownload: false, model: scenario },
    pythonPath: "/test/python",
    worker,
    gate,
  });
  workers.push(model);
  return model;
}

afterEach(async () => {
  await Promise.all(workers.splice(0).map((model) => model.dispose()));
});

describe("isolated native model processes", () => {
  it("preserves probabilities, full token counts, and bounded coverage", async () => {
    const model = create(new InferenceGate());
    await model.load();
    expect(model.ready?.()).toBe(true);
    await expect(model.scoreDetails("hello")).resolves.toEqual({
      score: 0.25,
      inputTokens: 7,
      coverage: { truncated: true, windows: 2, maxWindows: 32 },
    });
    await expect(model.score("hello")).resolves.toBe(0.25);
  });

  it("never becomes ready after a terminal startup failure", async () => {
    const model = create(undefined, "fatal-then-ready");
    await expect(model.load()).rejects.toThrow("unavailable");
    await delay(25);
    expect(model.ready?.()).toBe(false);
    await expect(model.score("hello")).rejects.toThrow("unavailable");
  });

  it("keeps the HTTP loop and foreground model responsive during a blocking native call", async () => {
    const slowGate = new InferenceGate();
    const acquire = vi.spyOn(slowGate, "acquire");
    const background = create(slowGate);
    const foreground = create(new InferenceGate());
    await Promise.all([background.load(), foreground.load()]);
    const slow = background.score("block");
    await vi.waitFor(() => expect(acquire).toHaveBeenCalledOnce());
    const started = performance.now();
    await expect(foreground.score("hello")).resolves.toBe(0.25);
    await delay(10);
    expect(performance.now() - started).toBeLessThan(250);
    await slow;
  });

  it("retains an active slot until native work returns after cancellation", async () => {
    const gate = new InferenceGate();
    const acquire = vi.spyOn(gate, "acquire");
    const model = create(gate);
    const abort = new AbortController();
    const reason = new Error("client cancelled");
    await model.load();
    const pending = model.score("block", abort.signal);
    const cancelled = expect(pending).rejects.toBe(reason);
    await vi.waitFor(() => expect(acquire).toHaveBeenCalledOnce());
    abort.abort(reason);
    let nextGranted = false;
    const next = gate.acquire().then((release) => {
      nextGranted = true;
      release();
    });
    await delay(20);
    expect(nextGranted).toBe(false);
    await cancelled;
    await next;
    expect(model.ready?.()).toBe(true);
    await expect(model.score("hello")).resolves.toBe(0.25);
  });

  it("fails closed on malformed model output and refuses subsequent work", async () => {
    const model = create(new InferenceGate());
    await model.load();
    await expect(model.score("invalid")).rejects.toThrow("unavailable");
    expect(model.ready?.()).toBe(false);
    await expect(model.score("hello")).rejects.toThrow("unavailable");
  });

  it("releases the shared CPU slot when a model process crashes", async () => {
    const gate = new InferenceGate();
    const crashed = create(gate);
    const other = create(gate);
    await Promise.all([crashed.load(), other.load()]);
    await expect(crashed.score("crash")).rejects.toThrow("unavailable");
    expect(crashed.ready?.()).toBe(false);
    await expect(other.score("hello")).resolves.toBe(0.25);
  });

  it.skipIf(process.platform !== "linux")(
    "kills worker descendants after an unexpected process exit",
    async () => {
      const model = create(new InferenceGate());
      await model.load();
      const { inputTokens: pid } = await model.scoreDetails("descendant");
      expect(pid).toBeGreaterThan(0);
      await expect(model.score("crash")).rejects.toThrow("unavailable");
      await vi.waitFor(() => {
        try {
          const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
          // A dead orphan can remain a zombie until the container's init reaps it.
          expect(stat.split(") ")[1][0]).toBe("Z");
        } catch (error) {
          if (
            !(
              error instanceof Error &&
              "code" in error &&
              error.code === "ENOENT"
            )
          ) {
            throw error;
          }
        }
      });
    }
  );
});
