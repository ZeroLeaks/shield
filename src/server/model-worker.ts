import { createModelDetector, type DetailedModelDetector } from "../model";
import {
  isWorkerCommand,
  type WorkerEvent,
  type WorkerModelOptions,
} from "./model-worker-protocol";
import { createTokenCounter, type TokenCounter } from "./tokenizer";

interface Request {
  abort: AbortController;
  done: Promise<void>;
}

interface WaitingBatch {
  grant(): void;
  deny(): void;
}

let detector: DetailedModelDetector | undefined;
let counter: TokenCounter | undefined;
let initialized = false;
let closing = false;
let nextGateId = 0;
const requests = new Map<number, Request>();
const scopes = new WeakMap<AbortSignal, number>();
const batches = new Map<number, WaitingBatch>();

function send(event: WorkerEvent): void {
  if (process.connected) {
    process.send?.(event);
  }
}

function fatal(): void {
  send({ type: "fatal" });
}

async function initialize(
  options: WorkerModelOptions,
  pythonPath: string
): Promise<void> {
  counter = await createTokenCounter(
    pythonPath,
    `${options.localPath}/tokenizer.json`,
    () => {
      if (!closing) {
        fatal();
      }
    }
  );
  detector = createModelDetector({
    ...options,
    countTokens: counter.count,
    scheduler: {
      acquire(signal) {
        const id = signal && scopes.get(signal);
        if (id === undefined) {
          return Promise.reject(new Error("Missing model request"));
        }
        const gateId = ++nextGateId;
        return new Promise((resolve, reject) => {
          batches.set(gateId, {
            grant: () => {
              batches.delete(gateId);
              resolve(() => send({ type: "release", gateId }));
            },
            deny: () => {
              batches.delete(gateId);
              reject(signal?.reason ?? new Error("Model request cancelled"));
            },
          });
          send({ type: "acquire", id, gateId });
        });
      },
    },
  });
  await detector.load();
  if (!closing) {
    send({ type: "ready" });
  }
}

function score(id: number, input: string): void {
  const model = detector;
  if (!(model && counter?.ready()) || closing || requests.has(id)) {
    fatal();
    return;
  }
  const abort = new AbortController();
  scopes.set(abort.signal, id);
  const done = (async () => {
    try {
      const result = await model.scoreDetails(input, abort.signal);
      send({ type: "result", id, result });
    } catch (error) {
      send({
        type: "error",
        id,
        cancelled: abort.signal.aborted && error === abort.signal.reason,
      });
    } finally {
      requests.delete(id);
    }
  })();
  requests.set(id, { abort, done });
}

async function close(): Promise<void> {
  if (closing) {
    return;
  }
  closing = true;
  for (const request of requests.values()) {
    request.abort.abort();
  }
  if (!process.connected) {
    for (const batch of batches.values()) {
      batch.deny();
    }
  }
  await Promise.allSettled(
    [...requests.values()].map((request) => request.done)
  );
  counter?.close();
  await detector?.dispose();
  if (process.connected) {
    process.disconnect?.();
  }
}

process.on("message", (value: unknown) => {
  if (!isWorkerCommand(value)) {
    fatal();
    return;
  }
  switch (value.type) {
    case "init":
      if (initialized || closing) {
        fatal();
        return;
      }
      initialized = true;
      initialize(value.options, value.pythonPath).catch(fatal);
      break;
    case "score":
      score(value.id, value.input);
      break;
    case "cancel":
      requests.get(value.id)?.abort.abort();
      break;
    case "grant":
    case "deny": {
      const batch = batches.get(value.gateId);
      if (!batch) {
        fatal();
        return;
      }
      if (value.type === "grant") {
        batch.grant();
      } else {
        batch.deny();
      }
      break;
    }
    case "close":
      close().catch(fatal);
      break;
    default:
      break;
  }
});
process.once("disconnect", () => close().catch(fatal));
process.once("SIGTERM", () => close().catch(fatal));
