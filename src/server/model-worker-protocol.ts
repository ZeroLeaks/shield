import type { ModelDetectorOptions, ModelScoreDetails } from "../model";

export type WorkerModelOptions = Omit<
  ModelDetectorOptions,
  "countTokens" | "scheduler"
> & { localPath: string; allowDownload: false };

export type WorkerCommand =
  | { type: "init"; options: WorkerModelOptions; pythonPath: string }
  | { type: "score"; id: number; input: string }
  | { type: "cancel"; id: number }
  | { type: "grant"; gateId: number }
  | { type: "deny"; gateId: number }
  | { type: "close" };

export type WorkerEvent =
  | { type: "ready" }
  | { type: "result"; id: number; result: ModelScoreDetails }
  | { type: "error"; id: number; cancelled: boolean }
  | { type: "acquire"; id: number; gateId: number }
  | { type: "release"; gateId: number }
  | { type: "fatal" };

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function identifier(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === "number" && value > 0;
}

function scoreDetails(value: unknown): value is ModelScoreDetails {
  if (!(record(value) && record(value.coverage))) {
    return false;
  }
  return (
    typeof value.score === "number" &&
    Number.isFinite(value.score) &&
    value.score >= 0 &&
    value.score <= 1 &&
    Number.isSafeInteger(value.inputTokens) &&
    typeof value.inputTokens === "number" &&
    value.inputTokens >= 0 &&
    typeof value.coverage.truncated === "boolean" &&
    identifier(value.coverage.windows) &&
    identifier(value.coverage.maxWindows) &&
    value.coverage.windows <= value.coverage.maxWindows
  );
}

export function isWorkerEvent(value: unknown): value is WorkerEvent {
  if (!record(value)) {
    return false;
  }
  switch (value.type) {
    case "ready":
    case "fatal":
      return true;
    case "result":
      return identifier(value.id) && scoreDetails(value.result);
    case "error":
      return identifier(value.id) && typeof value.cancelled === "boolean";
    case "acquire":
      return identifier(value.id) && identifier(value.gateId);
    case "release":
      return identifier(value.gateId);
    default:
      return false;
  }
}

export function isWorkerCommand(value: unknown): value is WorkerCommand {
  if (!record(value)) {
    return false;
  }
  switch (value.type) {
    case "init":
      return (
        record(value.options) &&
        typeof value.options.localPath === "string" &&
        value.options.allowDownload === false &&
        typeof value.pythonPath === "string"
      );
    case "score":
      return identifier(value.id) && typeof value.input === "string";
    case "cancel":
      return identifier(value.id);
    case "grant":
    case "deny":
      return identifier(value.gateId);
    case "close":
      return true;
    default:
      return false;
  }
}
