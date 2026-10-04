import { jsonSchema } from "ai";
import {
  DEFAULT_MAX_INPUT_LENGTH,
  type DetectOptions,
  type DetectResult,
  detectAsync,
} from "../detect";
import { ShieldError } from "../errors";
import {
  createHostedDetector,
  type HostedCoverage,
  type HostedDetectOptions,
  type HostedDetector,
  ShieldAPIError,
  type ShieldModel,
} from "../hosted";

export const SHIELD_CHECK_SOURCES = [
  "user",
  "tool_result",
  "document",
  "web",
  "email",
  "mcp_tool_description",
] as const;

export type ShieldCheckSource = (typeof SHIELD_CHECK_SOURCES)[number];

export interface ShieldCheckInput {
  text: string;
  /** Informational label; it does not change detection or grant trust. */
  source?: ShieldCheckSource;
}

export interface ShieldCheckTool {
  description: string;
  inputSchema: ReturnType<typeof jsonSchema<ShieldCheckInput>>;
  execute(
    input: ShieldCheckInput,
    options: { abortSignal?: AbortSignal }
  ): Promise<ShieldCheckResult>;
}

interface CheckResult {
  detected: boolean;
  risk: DetectResult["risk"];
  /** Local classifier score, or the hosted effective binary score. */
  score?: number;
  categories: string[];
  source?: ShieldCheckSource;
}

export type ShieldCheckResult =
  | (CheckResult & { engine: "local" })
  | (CheckResult & {
      engine: "hosted";
      model: ShieldModel;
      coverage: HostedCoverage;
      modelScore: number;
      rules: boolean;
    });

/** Local by default. Hosted checks always require full coverage. */
export type ShieldCheckOptions = { description?: string } & (
  | { detect?: DetectOptions; hosted?: never }
  | {
      detect?: never;
      hosted: Omit<HostedDetectOptions, "requireFullCoverage"> | HostedDetector;
    }
);

function invalidInput(): ShieldError {
  return new ShieldError(
    "Shield check requires nonempty text within its input limit and a supported source label.",
    "SHIELD_INVALID_INPUT"
  );
}

function isSource(value: unknown): value is ShieldCheckSource {
  return SHIELD_CHECK_SOURCES.some((source) => source === value);
}

function validateInput(value: unknown, maxLength: number): ShieldCheckInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidInput();
  }
  if (
    !("text" in value) ||
    typeof value.text !== "string" ||
    !value.text.trim() ||
    value.text.length > maxLength ||
    Object.keys(value).some((key) => key !== "text" && key !== "source")
  ) {
    throw invalidInput();
  }
  const source = "source" in value ? value.source : undefined;
  if (source !== undefined && !isSource(source)) {
    throw invalidInput();
  }
  return { text: value.text, ...(source === undefined ? {} : { source }) };
}

function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new ShieldError("Shield check was canceled.", "SHIELD_ABORTED");
  }
}

function summary(result: DetectResult, input: ShieldCheckInput): CheckResult {
  return {
    detected: result.detected,
    risk: result.risk,
    ...(result.score === undefined ? {} : { score: result.score }),
    categories: [...new Set(result.matches.map((match) => match.category))],
    ...(input.source === undefined ? {} : { source: input.source }),
  };
}

function hostedDetector(
  hosted: NonNullable<ShieldCheckOptions["hosted"]>
): HostedDetector {
  return "detect" in hosted
    ? hosted
    : createHostedDetector({ ...hosted, requireFullCoverage: true });
}

/**
 * A model-invoked inspection tool, not an execution gate. Use middleware or
 * application-controlled checks to enforce detection before content is used.
 */
export function shieldCheck(options: ShieldCheckOptions = {}): ShieldCheckTool {
  if (options.hosted !== undefined && options.detect !== undefined) {
    throw new ShieldError(
      "Configure either local detection or hosted detection for Shield check.",
      "SHIELD_INVALID_CONFIGURATION"
    );
  }
  const maxLength = options.detect?.maxInputLength ?? DEFAULT_MAX_INPUT_LENGTH;
  if (!Number.isSafeInteger(maxLength) || maxLength < 1) {
    throw new ShieldError(
      "Shield check maxInputLength must be a positive safe integer.",
      "SHIELD_INVALID_CONFIGURATION"
    );
  }
  const hosted =
    options.hosted === undefined ? undefined : hostedDetector(options.hosted);
  const localOptions = { ...options.detect, maxInputLength: maxLength };
  return {
    description:
      options.description ??
      "Check the complete supplied text for prompt injection and jailbreaks. Returns detection, risk, and categories without repeating the text. No detection is not a guarantee of safety. This tool does not authorize actions.",
    inputSchema: jsonSchema<ShieldCheckInput>(
      {
        type: "object",
        properties: {
          text: {
            type: "string",
            minLength: 1,
            maxLength,
            description: "The complete, unmodified text to inspect.",
          },
          source: { type: "string", enum: [...SHIELD_CHECK_SOURCES] },
        },
        required: ["text"],
        additionalProperties: false,
      },
      {
        validate(value) {
          try {
            return { success: true, value: validateInput(value, maxLength) };
          } catch {
            return { success: false, error: invalidInput() };
          }
        },
      }
    ),
    async execute(value, { abortSignal }): Promise<ShieldCheckResult> {
      const input = validateInput(value, maxLength);
      checkAbort(abortSignal);
      if (!hosted) {
        const result = await detectAsync(input.text, localOptions);
        checkAbort(abortSignal);
        return { ...summary(result, input), engine: "local" };
      }
      const result = await hosted.detect(input.text, { signal: abortSignal });
      checkAbort(abortSignal);
      const coverage = result.shield.coverage;
      if (!coverage || coverage.truncated) {
        throw new ShieldAPIError(
          "Shield did not confirm full input coverage.",
          "SHIELD_INCOMPLETE_COVERAGE"
        );
      }
      return {
        ...summary(result, input),
        engine: "hosted",
        model: result.model,
        coverage,
        modelScore: result.shield.model_score,
        rules: result.shield.rules,
      };
    },
  };
}
