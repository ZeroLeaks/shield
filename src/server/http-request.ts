import type { IncomingMessage } from "node:http";
import { SHIELD_MODELS, type ShieldModel } from "./classifier";
import { cancellation, RequestError } from "./request-error";

const INVALID_UNICODE = /[\uD800-\uDFFF]/u;

export function readBody(
  request: IncomingMessage,
  maxBytes: number,
  timeoutMs: number,
  signal: AbortSignal
): Promise<unknown> {
  const length = Number(request.headers["content-length"] ?? 0);
  if (!Number.isFinite(length) || length < 0 || length > maxBytes) {
    return Promise.reject(new RequestError(413, "request_too_large"));
  }
  if (signal.aborted) {
    return Promise.reject(cancellation(signal));
  }
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    const cleanup = (): void => {
      clearTimeout(timer);
      request.off("data", data);
      request.off("end", end);
      request.off("aborted", failed);
      signal.removeEventListener("abort", abort);
    };
    const fail = (error: RequestError): void => {
      cleanup();
      request.pause();
      reject(error);
    };
    const data = (chunk: Buffer): void => {
      size += chunk.length;
      if (size > maxBytes) {
        fail(new RequestError(413, "request_too_large"));
      } else {
        chunks.push(chunk);
      }
    };
    const end = (): void => {
      cleanup();
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.concat(chunks)
        );
        resolve(JSON.parse(text));
      } catch {
        reject(new RequestError(400, "invalid_json"));
      }
    };
    const failed = (): void =>
      fail(new RequestError(400, "incomplete_request"));
    const abort = (): void => fail(cancellation(signal));
    const timer = setTimeout(
      () => fail(new RequestError(408, "upload_timeout")),
      timeoutMs
    );
    request.on("data", data);
    request.once("end", end);
    request.once("error", failed);
    request.once("aborted", failed);
    signal.addEventListener("abort", abort, { once: true });
  });
}

export function parseRequest(
  value: unknown,
  maxBatch: number,
  maxLength: number
): { model: ShieldModel; input: string[] } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RequestError(400, "invalid_request");
  }
  const item = value as Record<string, unknown>;
  if (Object.keys(item).some((key) => key !== "model" && key !== "input")) {
    throw new RequestError(400, "invalid_request");
  }
  if (
    typeof item.model !== "string" ||
    !SHIELD_MODELS.some((model) => model === item.model)
  ) {
    throw new RequestError(400, "invalid_model");
  }
  if (
    !Array.isArray(item.input) ||
    item.input.length === 0 ||
    item.input.length > maxBatch ||
    !item.input.every(
      (text): text is string =>
        typeof text === "string" &&
        text.trim().length > 0 &&
        text.length <= maxLength &&
        !INVALID_UNICODE.test(text)
    )
  ) {
    throw new RequestError(400, "invalid_input");
  }
  return { model: item.model as ShieldModel, input: item.input };
}
