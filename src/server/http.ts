import { createHash, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { Capacity } from "./capacity";
import type {
  Classification,
  LocalClassifier,
  ShieldModel,
} from "./classifier";
import { parseRequest, readBody } from "./http-request";
import { cancellation, RequestError } from "./request-error";

export interface ShieldServerOptions {
  classifier: LocalClassifier;
  bearerToken: string;
  concurrency?: number;
  gpuConcurrency?: number;
  maxQueue?: number;
  queueTimeoutMs?: number;
  requestTimeoutMs?: number;
  uploadTimeoutMs?: number;
  maxUploads?: number;
  maxBodyBytes?: number;
  maxInputLength?: number;
  maxBatchSize?: number;
}

export interface ShieldHttpServer extends Server {
  readiness: Server;
  drain(): Promise<void>;
}

function json(response: ServerResponse, status: number, value: unknown): void {
  if (response.destroyed || response.writableEnded) {
    return;
  }
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...(status === 503 ? { "retry-after": "1" } : {}),
  });
  response.end(body);
}

function timeout(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error("Invalid server deadline");
  }
  return value;
}

function closeIncompleteRequest(
  request: IncomingMessage,
  response: ServerResponse
): void {
  if (request.complete) {
    return;
  }
  response.shouldKeepAlive = false;
  if (response.writableFinished) {
    request.destroy();
  } else {
    response.once("finish", () => request.destroy());
  }
}

async function classifyBatch(
  parsed: { model: ShieldModel; input: string[] },
  options: ShieldServerOptions,
  capacity: Capacity,
  signal: AbortSignal
): Promise<Classification[]> {
  const release = await capacity.acquire(signal);
  const started = performance.now();
  let success = false;
  try {
    const results: Classification[] = [];
    for (const input of parsed.input) {
      if (signal.aborted) {
        throw cancellation(signal);
      }
      results.push(
        await options.classifier.classify(parsed.model, input, signal)
      );
    }
    if (signal.aborted) {
      throw cancellation(signal);
    }
    success = true;
    return results;
  } finally {
    capacity.finish(success, performance.now() - started);
    release();
  }
}

export function createShieldServer(
  options: ShieldServerOptions
): ShieldHttpServer {
  if (options.bearerToken.length < 32) {
    throw new Error(
      "A private bearer token of at least 32 characters is required"
    );
  }
  const queueTimeout = timeout(options.queueTimeoutMs ?? 5000);
  const requestTimeout = timeout(options.requestTimeoutMs ?? 24_000);
  const uploadTimeout = timeout(options.uploadTimeoutMs ?? 5000);
  const cpu = new Capacity(
    options.concurrency ?? 1,
    options.maxQueue ?? 8,
    queueTimeout
  );
  const gpu = new Capacity(
    options.gpuConcurrency ?? 1,
    options.maxQueue ?? 8,
    queueTimeout
  );
  const uploads = new Capacity(options.maxUploads ?? 16, 0, uploadTimeout);
  let draining = false;
  const healthy = (): boolean => {
    try {
      return !draining && (options.classifier.ready?.() ?? true);
    } catch {
      return false;
    }
  };
  const digest = (token: string): Buffer =>
    createHash("sha256").update(token).digest();
  const expected = digest(`Bearer ${options.bearerToken}`);

  const classify = async (
    request: IncomingMessage,
    response: ServerResponse
  ): Promise<void> => {
    if (!healthy()) {
      throw new RequestError(503, "inference_unavailable");
    }
    const abort = new AbortController();
    const cancel = (): void => {
      if (!response.writableFinished) {
        abort.abort(new RequestError(499, "request_cancelled"));
      }
    };
    response.once("close", cancel);
    const deadline = setTimeout(() => {
      abort.abort(new RequestError(504, "inference_timeout"));
      closeIncompleteRequest(request, response);
      json(response, 504, { error: { code: "inference_timeout" } });
    }, requestTimeout);
    try {
      const releaseUpload = await uploads.acquire(abort.signal);
      let value: unknown;
      try {
        value = await readBody(
          request,
          options.maxBodyBytes ?? 2 * 1024 * 1024,
          uploadTimeout,
          abort.signal
        );
      } finally {
        releaseUpload();
      }
      const parsed = parseRequest(
        value,
        options.maxBatchSize ?? 32,
        options.maxInputLength ?? 200_000
      );
      if (!healthy()) {
        throw new RequestError(503, "inference_unavailable");
      }
      if (
        options.classifier.models &&
        !options.classifier.models.includes(parsed.model)
      ) {
        throw new RequestError(403, "model_not_available");
      }
      const capacity =
        parsed.model === "shield" || parsed.model === "shield-base" ? cpu : gpu;
      const results = await classifyBatch(
        parsed,
        options,
        capacity,
        abort.signal
      );
      json(response, 200, {
        model: parsed.model,
        model_revision: options.classifier.revision,
        results,
      });
    } finally {
      clearTimeout(deadline);
      response.off("close", cancel);
    }
  };

  const server = createServer((request, response) => {
    const run = async (): Promise<void> => {
      if (
        !timingSafeEqual(expected, digest(request.headers.authorization ?? ""))
      ) {
        throw new RequestError(401, "unauthorized");
      }
      switch (`${request.method} ${request.url}`) {
        case "GET /healthz": {
          const ready = healthy();
          json(response, ready ? 200 : 503, {
            status: ready ? "ok" : "unavailable",
            model_revision: options.classifier.revision,
          });
          return;
        }
        case "GET /metrics":
          json(response, 200, {
            ready: healthy(),
            pool: options.classifier.runtime?.pool ?? "paid",
            lanes: { cpu: cpu.snapshot(), gpu: gpu.snapshot() },
          });
          return;
        case "POST /classify":
          break;
        default:
          throw new RequestError(404, "not_found");
      }
      if (
        (request.headers["content-type"] ?? "")
          .split(";", 1)[0]
          ?.trim()
          .toLowerCase() !== "application/json"
      ) {
        throw new RequestError(415, "unsupported_media_type");
      }
      await classify(request, response);
    };
    run().catch((error: unknown) => {
      closeIncompleteRequest(request, response);
      json(response, error instanceof RequestError ? error.status : 503, {
        error: {
          code: error instanceof RequestError ? error.code : "inference_failed",
        },
      });
    });
  }) as ShieldHttpServer;
  server.readiness = createServer((request, response) => {
    if (request.method !== "GET" || request.url !== "/readyz") {
      json(response, 404, { error: { code: "not_found" } });
      return;
    }
    const ready = healthy();
    json(response, ready ? 200 : 503, { ready });
  });
  server.drain = async (): Promise<void> => {
    draining = true;
    await Promise.all([uploads.drain(), cpu.drain(), gpu.drain()]);
  };
  for (const listener of [server, server.readiness]) {
    listener.requestTimeout = requestTimeout;
    listener.headersTimeout = Math.min(10_000, requestTimeout);
    // The ALB closes idle upstream connections after 40 seconds.
    listener.keepAliveTimeout = 65_000;
  }
  return server;
}
