import { detect } from "../detect";
import {
  createModelDetector,
  type DetailedModelDetector,
  MODEL_EXCLUDED_CATEGORIES,
  MODEL_EXCLUDED_PATTERNS,
  type ModelScoreDetails,
  SHIELD_MODEL,
  SHIELD_MODEL_LARGE,
} from "../model";
import type { ArtifactManifest, ServingPool } from "./artifacts";
import type { WorkerModelOptions } from "./model-worker-protocol";
import { createTokenCounter, type TokenCounter } from "./tokenizer";

export const SHIELD_MODELS = [
  "shield",
  "shield-base",
  "shield-large",
  "shield-tiered",
] as const;
export type ShieldModel = (typeof SHIELD_MODELS)[number];
export interface AttackSpan {
  text: string;
  source: "rule";
  confidence: number;
}
export interface Classification {
  score: number;
  flagged: boolean;
  rules: boolean;
  input_tokens: number;
  coverage: { truncated: boolean; windows: number; max_windows: number };
  attack_spans?: AttackSpan[];
}
export interface LocalClassifier {
  revision: string;
  models?: readonly ShieldModel[];
  ready?(): boolean;
  runtime?: { pool: ServingPool; large_device: "cpu" | "cuda" };
  close?(): void | Promise<void>;
  classify(
    model: ShieldModel,
    input: string,
    signal?: AbortSignal
  ): Promise<Classification>;
}
export type ServingModel = Pick<
  DetailedModelDetector,
  "load" | "score" | "scoreDetails" | "dispose"
> & { ready?(): boolean };
const RULE_OPTIONS = {
  classifier: false as const,
  excludeCategories: [...MODEL_EXCLUDED_CATEGORIES],
  excludePatterns: [...MODEL_EXCLUDED_PATTERNS],
};

const WHITESPACE = /\s+/u;
const SENTENCES = /[^.!?\r\n]+[.!?]?/gu;

function minimizeSpan(excerpt: string, category: string): string {
  const words = excerpt.split(WHITESPACE);
  const stillFlags = (text: string): boolean =>
    detect(text, RULE_OPTIONS).matches.some(
      (match) => match.category === category && match.confidence >= 0.8
    );
  while (words.length > 2 && stillFlags(words.slice(1).join(" "))) {
    words.shift();
  }
  while (words.length > 2 && stillFlags(words.slice(0, -1).join(" "))) {
    words.pop();
  }
  return words.join(" ");
}

/** Keep only short, independently flagged sentences. Ambiguous or long spans are omitted. */
function attackSpans(
  input: string,
  matches: ReturnType<typeof detect>["matches"]
): AttackSpan[] {
  const categories = new Set(
    matches
      .filter((match) => match.confidence >= 0.8)
      .map((match) => match.category)
  );
  const spans: AttackSpan[] = [];
  let checked = 0;
  for (const candidate of input.matchAll(SENTENCES)) {
    if (++checked > 128 || spans.length >= 3) {
      break;
    }
    const excerpt = candidate[0].trim();
    if (
      excerpt.length < 16 ||
      excerpt.length > 512 ||
      spans.some((span) => span.text === excerpt)
    ) {
      continue;
    }
    const finding = detect(excerpt, RULE_OPTIONS).matches.find(
      (match) => match.confidence >= 0.8 && categories.has(match.category)
    );
    if (!finding) {
      continue;
    }
    const minimal = minimizeSpan(excerpt, finding.category);
    if (minimal.length >= 16) {
      spans.push({
        text: minimal,
        source: "rule",
        confidence: finding.confidence,
      });
    }
  }
  return spans;
}

export async function createLocalClassifier(
  manifest: ArtifactManifest,
  options: {
    threads?: number;
    pythonPath: string;
    pool?: ServingPool;
    largeDevice?: "cpu" | "cuda";
    warmup?: boolean;
    createModel?: (
      options: WorkerModelOptions,
      lane: "direct" | "ensemble"
    ) => ServingModel;
  }
): Promise<LocalClassifier> {
  const pool = options.pool ?? manifest.pool ?? "paid";
  const largeDevice = options.largeDevice ?? "cpu";
  const tokens: TokenCounter[] = [];
  const detectors: ServingModel[] = [];
  let healthy = true;
  let closed = false;
  const close = async (): Promise<void> => {
    if (closed) {
      return;
    }
    closed = true;
    for (const counter of tokens) {
      counter.close();
    }
    await Promise.allSettled(detectors.map((detector) => detector.dispose()));
  };
  const detectorFor = async (
    modelOptions: WorkerModelOptions,
    lane: "direct" | "ensemble"
  ): Promise<ServingModel> => {
    let detector: ServingModel;
    if (options.createModel) {
      detector = options.createModel(modelOptions, lane);
    } else {
      const counter = await createTokenCounter(
        options.pythonPath,
        `${modelOptions.localPath}/tokenizer.json`
      );
      tokens.push(counter);
      detector = createModelDetector({
        ...modelOptions,
        countTokens: counter.count,
      });
    }
    detectors.push(detector);
    await detector.load();
    return detector;
  };
  const common = {
    allowDownload: false as const,
    threads: options.threads ?? 2,
    device: "cpu" as const,
  };
  let small: ServingModel;
  let base: ServingModel | undefined;
  let ensembleSmall: ServingModel | undefined;
  let ensembleBase: ServingModel | undefined;
  let large: ServingModel | undefined;
  try {
    const smallOptions: WorkerModelOptions = {
      ...common,
      model: SHIELD_MODEL,
      localPath: manifest.artifacts.s15e.path,
      dtype: "q8",
    };
    small = await detectorFor(smallOptions, "direct");
    if (pool === "paid") {
      const baseArtifact = manifest.artifacts.sb1;
      const largeArtifact = manifest.artifacts["l7a-q4"];
      if (!(baseArtifact && largeArtifact)) {
        throw new Error(
          "Paid serving requires the approved Base and Large artifacts"
        );
      }
      const baseOptions: WorkerModelOptions = {
        ...common,
        model: "zeroleaks/shield-base",
        localPath: baseArtifact.path,
        dtype: "q8",
        maxTokens: 256,
        windows: { stride: 192, max: 32 },
      };
      base = await detectorFor(baseOptions, "direct");
      ensembleSmall = options.createModel
        ? await detectorFor(smallOptions, "ensemble")
        : small;
      ensembleBase = options.createModel
        ? await detectorFor(baseOptions, "ensemble")
        : base;
      large = await detectorFor(
        {
          ...common,
          device: largeDevice,
          model: SHIELD_MODEL_LARGE,
          localPath: largeArtifact.path,
          dtype: "q4",
        },
        "ensemble"
      );
    }
    if (options.warmup) {
      for (const detector of detectors) {
        const score = await detector.score("Summarize the meeting notes.");
        if (!Number.isFinite(score)) {
          throw new Error("Model warmup failed");
        }
      }
    }
  } catch (error) {
    await close();
    throw error;
  }

  const ensemble = async (
    input: string,
    signal?: AbortSignal
  ): Promise<ModelScoreDetails> => {
    if (!(large && ensembleBase)) {
      throw new Error("Model is not available in this serving pool");
    }
    const llm = await large.scoreDetails(input, signal);
    const encoder = await ensembleBase.scoreDetails(input, signal);
    return {
      score: 0.6 * llm.score + 0.4 * encoder.score,
      inputTokens: llm.inputTokens,
      coverage: {
        truncated: llm.coverage.truncated || encoder.coverage.truncated,
        windows: llm.coverage.windows + encoder.coverage.windows,
        maxWindows: llm.coverage.maxWindows + encoder.coverage.maxWindows,
      },
    };
  };

  const scoreFor = async (
    model: ShieldModel,
    input: string,
    signal?: AbortSignal
  ): Promise<ModelScoreDetails> => {
    if (model === "shield-base") {
      if (!base) {
        throw new Error("Model is not available in this serving pool");
      }
      return base.scoreDetails(input, signal);
    }
    if (model === "shield-large") {
      return ensemble(input, signal);
    }
    const detail = await (model === "shield-tiered" && ensembleSmall
      ? ensembleSmall
      : small
    ).scoreDetails(input, signal);
    if (
      model === "shield-tiered" &&
      detail.score >= 0.01 &&
      detail.score < 0.97
    ) {
      return ensemble(input, signal);
    }
    return detail;
  };

  return {
    revision: manifest.revision,
    models: pool === "free" ? ["shield"] : SHIELD_MODELS,
    runtime: { pool, large_device: largeDevice },
    ready: () =>
      healthy &&
      !closed &&
      tokens.every((counter) => counter.ready()) &&
      detectors.every((detector) => detector.ready?.() ?? true),
    close,
    async classify(model, input, signal) {
      if (!healthy || closed || (pool === "free" && model !== "shield")) {
        throw new Error("Model is not available in this serving pool");
      }
      try {
        signal?.throwIfAborted();
        const rules = detect(input, {
          ...RULE_OPTIONS,
          maxInputLength: input.length,
        });
        const detail = await scoreFor(model, input, signal);
        signal?.throwIfAborted();
        const spans = rules.detected ? attackSpans(input, rules.matches) : [];
        return {
          score: detail.score,
          flagged: rules.detected || detail.score >= 0.5,
          rules: rules.detected,
          input_tokens: detail.inputTokens,
          coverage: {
            truncated: detail.coverage.truncated,
            windows: detail.coverage.windows,
            max_windows: detail.coverage.maxWindows,
          },
          ...(spans.length > 0 ? { attack_spans: spans } : {}),
        };
      } catch (error) {
        if (!(signal?.aborted && error === signal.reason)) {
          healthy = false;
        }
        throw error;
      }
    },
  };
}
