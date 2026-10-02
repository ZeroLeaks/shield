import type { DetectOptions, DetectResult } from "./detect";
import { ShieldError } from "./errors";

export const SHIELD_API_BASE_URL = "https://api.zeroleaks.ai/v1";
export const SHIELD_MODELS = [
  "shield",
  "shield-base",
  "shield-large",
  "shield-tiered",
] as const;
export type ShieldModel = (typeof SHIELD_MODELS)[number];
const TRAILING_SLASHES = /\/+$/;
const WHITESPACE = /\s/;

export interface HostedRequestOptions {
  signal?: AbortSignal;
  /** Includes reading and validating the response. Default 30 seconds. */
  timeoutMs?: number;
}

export interface HostedDetectOptions extends HostedRequestOptions {
  /** Defaults to ZEROLEAKS_API_KEY in server environments. */
  apiKey?: string;
  /** Default `shield` (free). Other models require paid access. */
  model?: ShieldModel;
  /** OpenAI-compatible API base URL, including `/v1`. */
  baseURL?: string;
  /** Full moderation URL. Use either this or `baseURL`. */
  endpoint?: string;
  /** Reject partial-window coverage. Default false; inspect result.shield.coverage. */
  requireFullCoverage?: boolean;
  fetch?: typeof globalThis.fetch;
}

export interface HostedCoverage {
  truncated: boolean;
  windows: number;
  max_windows: number;
}

export interface HostedDetectResult extends DetectResult {
  model: ShieldModel;
  /** Effective binary score; rules may raise it to the classification threshold. */
  score: number;
  flagged: boolean;
  /** One binary category covers prompt injection and jailbreaks. */
  categories: { prompt_injection: boolean };
  category_scores: { prompt_injection: number };
  shield: {
    model_score: number;
    rules: boolean;
    coverage?: HostedCoverage;
  };
}

/** Request failures never become a clean detection result. */
export class ShieldAPIError extends ShieldError {
  readonly status?: number;

  constructor(message: string, code: string, status?: number) {
    super(message, code);
    this.name = "ShieldAPIError";
    this.status = status;
  }
}

export interface HostedDetector {
  readonly model: ShieldModel;
  detect(
    input: string,
    options?: HostedRequestOptions
  ): Promise<HostedDetectResult>;
  /** Runs the hosted detector for every input in existing provider wrappers. */
  options(): DetectOptions;
}

function configurationError(message: string): ShieldAPIError {
  return new ShieldAPIError(message, "SHIELD_INVALID_CONFIGURATION");
}

function moderationURL(options: HostedDetectOptions): URL {
  if (options.baseURL !== undefined && options.endpoint !== undefined) {
    throw configurationError("Use either baseURL or endpoint, not both.");
  }
  let url: URL;
  try {
    const base = (options.baseURL ?? SHIELD_API_BASE_URL).replace(
      TRAILING_SLASHES,
      ""
    );
    url = new URL(options.endpoint ?? `${base}/moderations`);
  } catch {
    throw configurationError("Shield requires an absolute API URL.");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw configurationError("Shield requires HTTPS, except on localhost.");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw configurationError(
      "Shield API URLs cannot contain credentials, queries, or fragments."
    );
  }
  return url;
}

function environmentKey(): string | undefined {
  return typeof process === "undefined"
    ? undefined
    : process.env?.ZEROLEAKS_API_KEY;
}

function requestKey(
  options: HostedDetectOptions,
  url: URL
): string | undefined {
  // An explicit self-hosted endpoint must not inherit the production key.
  const isDefault = url.origin === new URL(SHIELD_API_BASE_URL).origin;
  const key = options.apiKey ?? (isDefault ? environmentKey() : undefined);
  if (key !== undefined && (!key.trim() || WHITESPACE.test(key))) {
    throw configurationError(
      "Shield requires a nonempty API key without whitespace."
    );
  }
  if (isDefault && !key) {
    throw configurationError(
      "Set apiKey or ZEROLEAKS_API_KEY to a dashboard API key."
    );
  }
  return key;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function probability(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

function invalidResponse(): ShieldAPIError {
  return new ShieldAPIError(
    "Shield returned an invalid detection response.",
    "SHIELD_INVALID_RESPONSE"
  );
}

function parseCoverage(value: unknown): HostedCoverage | undefined {
  if (value === undefined) {
    return;
  }
  if (
    !record(value) ||
    typeof value.truncated !== "boolean" ||
    typeof value.windows !== "number" ||
    !Number.isSafeInteger(value.windows) ||
    value.windows < 1 ||
    typeof value.max_windows !== "number" ||
    !Number.isSafeInteger(value.max_windows) ||
    value.max_windows < 1 ||
    value.windows > value.max_windows
  ) {
    throw invalidResponse();
  }
  return {
    truncated: value.truncated,
    windows: value.windows,
    max_windows: value.max_windows,
  };
}

function parseResult(
  value: unknown,
  model: ShieldModel,
  requireFullCoverage: boolean
): HostedDetectResult {
  if (
    !record(value) ||
    value.model !== model ||
    !Array.isArray(value.results) ||
    value.results.length !== 1
  ) {
    throw invalidResponse();
  }
  const result: unknown = value.results[0];
  if (!record(result)) {
    throw invalidResponse();
  }
  const { flagged, categories, category_scores: scores, shield } = result;
  if (
    typeof flagged !== "boolean" ||
    !record(categories) ||
    categories.prompt_injection !== flagged ||
    !record(scores) ||
    !probability(scores.prompt_injection) ||
    !record(shield) ||
    !probability(shield.model_score) ||
    typeof shield.rules !== "boolean"
  ) {
    throw invalidResponse();
  }
  if (
    flagged !== scores.prompt_injection >= 0.5 ||
    (!flagged && (shield.rules || shield.model_score >= 0.5))
  ) {
    throw invalidResponse();
  }
  const coverage = parseCoverage(shield.coverage);
  if (requireFullCoverage && (!coverage || coverage.truncated)) {
    throw new ShieldAPIError(
      "Shield did not confirm full input coverage.",
      "SHIELD_INCOMPLETE_COVERAGE"
    );
  }
  const score = scores.prompt_injection;
  const flaggedRisk = score >= 0.85 ? "high" : "medium";
  return {
    model,
    detected: flagged,
    flagged,
    score,
    risk: flagged ? flaggedRisk : "none",
    matches: flagged
      ? [{ category: "prompt_injection", pattern: model, confidence: score }]
      : [],
    categories: { prompt_injection: flagged },
    category_scores: { prompt_injection: score },
    shield: {
      model_score: shield.model_score,
      rules: shield.rules,
      ...(coverage ? { coverage } : {}),
    },
  };
}

function httpError(status: number): ShieldAPIError {
  if (status === 401) {
    return new ShieldAPIError(
      "Shield rejected the API key.",
      "SHIELD_UNAUTHORIZED",
      status
    );
  }
  if (status === 403) {
    return new ShieldAPIError(
      "Shield access requires the appropriate plan and research consent.",
      "SHIELD_FORBIDDEN",
      status
    );
  }
  if (status === 413) {
    return new ShieldAPIError(
      "The input exceeds Shield's request limit.",
      "SHIELD_INPUT_TOO_LARGE",
      status
    );
  }
  if (status === 429) {
    return new ShieldAPIError(
      "Shield's request limit was reached.",
      "SHIELD_RATE_LIMITED",
      status
    );
  }
  return new ShieldAPIError(
    "Shield could not complete the detection request.",
    "SHIELD_HTTP_ERROR",
    status
  );
}

async function discardResponse(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Closing an error response cannot replace its sanitized public error.
  }
}

function validateRequest(input: string, options: HostedRequestOptions): number {
  if (typeof input !== "string" || input.length === 0) {
    throw configurationError("Shield requires a nonempty string input.");
  }
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (
    !Number.isFinite(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 2_147_483_647
  ) {
    throw configurationError(
      "Shield timeoutMs must be a positive duration below 2147483648 ms."
    );
  }
  return timeoutMs;
}

async function request(
  input: string,
  model: ShieldModel,
  url: URL,
  key: string | undefined,
  fetcher: typeof globalThis.fetch,
  options: HostedRequestOptions,
  requireFullCoverage: boolean
): Promise<HostedDetectResult> {
  const timeoutMs = validateRequest(input, options);
  const controller = new AbortController();
  const abort = (): void => controller.abort();
  let timedOut = false;
  if (options.signal?.aborted) {
    abort();
  } else {
    options.signal?.addEventListener("abort", abort, { once: true });
  }
  const timeout = setTimeout(() => {
    timedOut = true;
    abort();
  }, timeoutMs);
  try {
    if (controller.signal.aborted) {
      throw new ShieldAPIError(
        "Shield detection was canceled.",
        "SHIELD_ABORTED"
      );
    }
    const response = await fetcher(url.href, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(key ? { Authorization: `Bearer ${key}` } : {}),
      },
      body: JSON.stringify({ model, input }),
      signal: controller.signal,
      redirect: "manual",
      credentials: "omit",
    });
    if (!response.ok) {
      discardResponse(response);
      throw httpError(response.status);
    }
    let data: unknown;
    try {
      data = await response.json();
    } catch {
      throw invalidResponse();
    }
    if (controller.signal.aborted) {
      throw new ShieldAPIError(
        "Shield detection was canceled.",
        "SHIELD_ABORTED"
      );
    }
    return parseResult(data, model, requireFullCoverage);
  } catch (error) {
    if (controller.signal.aborted) {
      throw new ShieldAPIError(
        timedOut
          ? "Shield detection timed out."
          : "Shield detection was canceled.",
        timedOut ? "SHIELD_TIMEOUT" : "SHIELD_ABORTED"
      );
    }
    if (error instanceof ShieldAPIError) {
      throw error;
    }
    // Transport exceptions can include request headers or input text.
    throw new ShieldAPIError(
      "Shield could not reach the detection service.",
      "SHIELD_NETWORK_ERROR"
    );
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abort);
  }
}

/** Reuse a hosted detector across requests, including provider wrappers. */
export function createHostedDetector(
  options: HostedDetectOptions = {}
): HostedDetector {
  const url = moderationURL(options);
  const key = requestKey(options, url);
  const model = options.model ?? "shield";
  if (!SHIELD_MODELS.includes(model)) {
    throw configurationError(
      "Shield model must be shield, shield-base, shield-large, or shield-tiered."
    );
  }
  const fetcher = options.fetch ?? globalThis.fetch;
  if (typeof fetcher !== "function") {
    throw configurationError("Shield requires a fetch implementation.");
  }
  const detect = (
    input: string,
    overrides: HostedRequestOptions = {}
  ): Promise<HostedDetectResult> =>
    request(
      input,
      model,
      url,
      key,
      fetcher,
      {
        signal: overrides.signal ?? options.signal,
        timeoutMs: overrides.timeoutMs ?? options.timeoutMs,
      },
      options.requireFullCoverage ?? false
    );
  return {
    model,
    detect,
    options: (): DetectOptions => ({
      classifier: false,
      secondaryDetector: (input) => detect(input),
      escalate: { minScore: 0, detector: (input) => detect(input) },
    }),
  };
}

/** Detect prompt injection and jailbreaks with the hosted Shield API. */
export async function detect(
  input: string,
  options: HostedDetectOptions = {}
): Promise<HostedDetectResult> {
  return await createHostedDetector(options).detect(input);
}
