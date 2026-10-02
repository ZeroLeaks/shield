import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { ModelScoreDetails } from "../model";
import type { ServingModel } from "./classifier";
import type { InferenceGate } from "./inference-gate";
import {
  isWorkerEvent,
  type WorkerCommand,
  type WorkerEvent,
  type WorkerModelOptions,
} from "./model-worker-protocol";

interface Pending {
  abort: AbortController;
  signal?: AbortSignal;
  cleanup(): void;
  resolve(value: ModelScoreDetails): void;
  reject(error: unknown): void;
}

interface Batch {
  requestId: number;
  release?: () => void;
}

export function createModelProcess(options: {
  model: WorkerModelOptions;
  pythonPath: string;
  worker: URL;
  gate?: InferenceGate;
  executable?: string;
}): ServingModel {
  const processGroup = process.platform !== "win32";
  const child = spawn(
    options.executable ?? process.execPath,
    [fileURLToPath(options.worker)],
    { stdio: ["ignore", "ignore", "ignore", "ipc"], detached: processGroup }
  );
  const pending = new Map<number, Pending>();
  const batches = new Map<number, Batch>();
  let nextId = 0;
  let available = false;
  let failed = false;
  let closing = false;
  let exited = false;
  let resolveReady: () => void;
  let rejectReady: (error: unknown) => void;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  // Startup failures are also observable through load(), scoreDetails(), and readiness.
  ready.catch(() => undefined);
  let resolveExit: () => void;
  const exit = new Promise<void>((resolve) => {
    resolveExit = resolve;
  });
  const startupTimer = setTimeout(() => fail(), 300_000);

  function killTree(): void {
    if (processGroup && child.pid !== undefined) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch (error) {
        if (
          !(error instanceof Error && "code" in error && error.code === "ESRCH")
        ) {
          throw error;
        }
      }
    } else {
      child.kill("SIGKILL");
    }
  }

  function fail(): void {
    failed = true;
    available = false;
    clearTimeout(startupTimer);
    rejectReady(new Error("Model worker unavailable"));
    if (!exited) {
      killTree();
    }
  }

  function send(message: WorkerCommand): void {
    if (!child.connected) {
      fail();
      return;
    }
    child.send(message, (error) => {
      if (error) {
        fail();
      }
    });
  }

  const finish = (): void => {
    if (exited) {
      return;
    }
    killTree();
    exited = true;
    available = false;
    clearTimeout(startupTimer);
    rejectReady(new Error("Model worker unavailable"));
    for (const batch of batches.values()) {
      batch.release?.();
    }
    batches.clear();
    for (const request of pending.values()) {
      request.abort.abort();
      request.cleanup();
      request.reject(new Error("Model worker unavailable"));
    }
    pending.clear();
    resolveExit();
  };
  child.once("exit", finish);
  child.once("error", () => {
    fail();
    if (child.pid === undefined) {
      finish();
    }
  });

  function deny(gateId: number): void {
    batches.delete(gateId);
    if (!exited) {
      send({ type: "deny", gateId });
    }
  }

  const acquire = async (id: number, gateId: number): Promise<void> => {
    const request = pending.get(id);
    if (!request || batches.has(gateId)) {
      fail();
      return;
    }
    const batch: Batch = { requestId: id };
    batches.set(gateId, batch);
    try {
      const release = await options.gate?.acquire(request.abort.signal);
      if (request.abort.signal.aborted || exited) {
        release?.();
        deny(gateId);
        return;
      }
      batch.release = release ?? (() => undefined);
      send({ type: "grant", gateId });
    } catch (error) {
      batches.delete(gateId);
      if (
        request.abort.signal.aborted &&
        error === request.abort.signal.reason
      ) {
        deny(gateId);
      } else {
        fail();
      }
    }
  };

  function settle(
    value: Extract<WorkerEvent, { type: "error" | "result" }>
  ): void {
    const request = pending.get(value.id);
    if (
      !request ||
      [...batches.values()].some((batch) => batch.requestId === value.id)
    ) {
      fail();
      return;
    }
    pending.delete(value.id);
    request.cleanup();
    if (value.type === "error") {
      if (value.cancelled && request.signal?.aborted) {
        request.reject(request.signal.reason);
      } else {
        request.reject(new Error("Model worker inference failed"));
        fail();
      }
    } else if (request.signal?.aborted) {
      request.reject(request.signal.reason);
    } else {
      request.resolve(value.result);
    }
  }

  function releaseBatch(gateId: number): void {
    const batch = batches.get(gateId);
    if (!batch?.release) {
      fail();
      return;
    }
    batch.release();
    batches.delete(gateId);
  }

  child.on("message", (value: unknown) => {
    if (failed) {
      return;
    }
    if (!isWorkerEvent(value)) {
      fail();
      return;
    }
    switch (value.type) {
      case "ready":
        if (available || closing) {
          fail();
          return;
        }
        clearTimeout(startupTimer);
        available = true;
        resolveReady();
        break;
      case "fatal":
        fail();
        break;
      case "acquire":
        acquire(value.id, value.gateId).catch(fail);
        break;
      case "release":
        releaseBatch(value.gateId);
        break;
      case "result":
      case "error":
        settle(value);
        break;
      default:
        break;
    }
  });

  send({
    type: "init",
    options: options.model,
    pythonPath: options.pythonPath,
  });

  const scoreDetails = async (
    input: string,
    signal?: AbortSignal
  ): Promise<ModelScoreDetails> => {
    signal?.throwIfAborted();
    await ready;
    signal?.throwIfAborted();
    if (!available || closing || failed) {
      throw new Error("Model worker unavailable");
    }
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      const abort = new AbortController();
      const cancel = (): void => {
        abort.abort(signal?.reason);
        send({ type: "cancel", id });
      };
      pending.set(id, {
        abort,
        signal,
        resolve,
        reject,
        cleanup: () => signal?.removeEventListener("abort", cancel),
      });
      signal?.addEventListener("abort", cancel, { once: true });
      send({ type: "score", id, input });
    });
  };

  return {
    load: () => ready,
    ready: () => available && !closing && !failed,
    scoreDetails,
    score: async (input, signal) => (await scoreDetails(input, signal)).score,
    async dispose() {
      if (!closing) {
        closing = true;
        available = false;
        for (const [id, request] of pending) {
          request.abort.abort();
          send({ type: "cancel", id });
        }
        if (!exited) {
          send({ type: "close" });
        }
      }
      const killTimer = setTimeout(killTree, 5000);
      try {
        await exit;
      } finally {
        clearTimeout(killTimer);
      }
    },
  };
}
