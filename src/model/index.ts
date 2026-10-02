/**
 * An opt-in model tier: a transformer classifier run in-process with
 * transformers.js, for use as `detectAsync`'s `escalate` detector. Nothing
 * here loads until the detector is first called, and the root entry point
 * never imports this file.
 */

import type { DetectOptions, DetectResult } from "../detect";
import { ShieldError } from "../errors";
import { htmlText, looksLikeHtml } from "../html";
import { importPeer } from "./peer";

const PEER = "@huggingface/transformers";
/** Shield's own model: multilingual, 12 layers, 256-token windows. The default. */
export const SHIELD_MODEL = "zeroleaks/shield-small";
/**
 * Shield's large model: a small LLM fine-tuned as a classifier, more accurate
 * on instructions planted in documents and on agent attacks, and much slower.
 * Use it through `tiered()` so it only sees what the fast model is unsure about.
 */
export const SHIELD_MODEL_LARGE = "zeroleaks/shield-large";
const PROTECTAI_MODEL = "protectai/deberta-v3-base-prompt-injection-v2";
/** The commit of ProtectAI's model that Shield's benchmark ran. */
const PROTECTAI_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671";
const DEFAULT_LABEL = "INJECTION";

interface ModelProfile {
  maxTokens: number;
  windows: false | { stride: number; max: number };
  dtype: ModelDtype;
}

/**
 * How Shield's models were trained and benchmarked: 256-token windows, every
 * 192 tokens. `onnx/model.onnx` stores its weights at half precision and
 * computes at full precision.
 */
const SHIELD_PROFILE: ModelProfile = {
  maxTokens: 256,
  windows: { stride: 192, max: 32 },
  dtype: "fp32",
};
/** For any other model: its first 512 tokens, full precision. */
const OTHER_PROFILE: ModelProfile = {
  maxTokens: 512,
  windows: false,
  dtype: "fp32",
};

/** Shield's large model reads 512-token windows every 384 tokens, with 4-bit weights. */
const SHIELD_LARGE_PROFILE: ModelProfile = {
  maxTokens: 512,
  windows: { stride: 384, max: 16 },
  dtype: "q4",
};

function profileFor(model: string): ModelProfile {
  if (model === SHIELD_MODEL) {
    return SHIELD_PROFILE;
  }
  return model === SHIELD_MODEL_LARGE ? SHIELD_LARGE_PROFILE : OTHER_PROFILE;
}
const DEFAULT_THRESHOLD = 0.5;
const DEFAULT_MIN_SCORE = 0.05;
const HIGH_RISK_SCORE = 0.9;
/** Windows scored at most when `windows` is on. */
const MAX_WINDOWS = 32;
/**
 * A text too long for its windows is read at both ends: the first windows,
 * and this many windows ending where the text ends, so that an instruction
 * placed at the end of a long document is still read.
 */
const TAIL_WINDOWS = 4;
/** Characters taken from the end of the text for its last windows, per token they need. */
const TAIL_CHARS_PER_TOKEN = 8;
/**
 * Text is tokenized in pieces of about this many characters, each ending at
 * whitespace, until there are enough tokens: transformers.js tokenizes in
 * time quadratic in the length of what it is given.
 */
const CHUNK_CHARS = 256;
/** A word longer than this is cut, even though that can change its tokens. */
const MAX_WORD_CHARS = 1024;
/** Stop looking for tokens after this much text, for input that is mostly whitespace. */
const MAX_SCAN_CHARS = 64 * 1024;
/**
 * Characters every tokenizer normalization turns into a word boundary.
 * Others, such as a vertical tab, may be dropped instead, so text is not
 * split there.
 */
const RE_BOUNDARY = /[ \t\n\r]/;
const RE_LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;
/** A relative path transformers.js would take for a Hugging Face repo id. */
const RE_REPO_ID_LIKE = /^[\w.-]+(?:\/[\w.-]+)?$/;

export type ModelDtype =
  | "fp32"
  | "fp16"
  | "q8"
  | "int8"
  | "uint8"
  | "q4"
  | "bnb4"
  | "q4f16";

export interface ModelDetectorOptions {
  /** Optional exact tokenizer implementation for usage accounting on long inputs. */
  countTokens?: (input: string) => Promise<number>;
  /**
   * Hugging Face repo to download the model from, and the name reported in
   * `matches`. Default `zeroleaks/shield-small`, Shield's own model. Any
   * text-classification model with an ONNX export works, such as
   * `protectai/deberta-v3-base-prompt-injection-v2`.
   */
  model?: string;
  /**
   * Commit, branch, or tag of `model` to download. Default `"main"`, or for
   * ProtectAI's model the commit Shield's benchmark ran.
   */
  revision?: string;
  /** Probability of `label` at or above which the input is an injection. Default 0.5. */
  threshold?: number;
  /** Label in the model's `id2label` whose probability is the score. Default `"INJECTION"`. */
  label?: string;
  /**
   * Which ONNX weights to load, as named by transformers.js: `"fp32"` reads
   * `onnx/model.onnx`, `"q8"` reads `onnx/model_quantized.onnx`, and so on.
   * Default `"fp32"`. For Shield's models, `"q8"` loads a file half the size
   * that runs about a quarter faster and is slightly less accurate.
   */
  dtype?: ModelDtype;
  /**
   * A directory with the model files, laid out like the repo: `config.json`,
   * `tokenizer.json`, `tokenizer_config.json`, and `onnx/model.onnx`.
   * Nothing is downloaded.
   */
  localPath?: string;
  /** Where downloads are cached. Default: transformers.js's cache directory. */
  cacheDir?: string;
  /**
   * `false` loads only from `localPath` or files already in the cache, and
   * fails instead of downloading. Default true.
   */
  allowDownload?: boolean;
  /** ONNX Runtime threads for one inference. Default: ONNX Runtime's. */
  threads?: number;
  /** Coordinate native inference batches across models sharing a device. */
  scheduler?: {
    acquire(signal?: AbortSignal): Promise<() => void>;
  };
  /** Explicit native execution device. CUDA requires the matching ONNX GPU runtime. */
  device?: "cpu" | "cuda";
  /**
   * Tokens the model reads at once, counting the special tokens around the
   * text. Default 256 for Shield's models and 512 for others.
   */
  maxTokens?: number;
  /**
   * Score long input in overlapping windows of `maxTokens` and report the
   * highest window, so an instruction late in a long document is read too.
   * `stride` is how many tokens each window starts after the previous one
   * (default three quarters of a window) and `max` how many windows are
   * scored at most (default 32). Default for Shield's models
   * `{ stride: 192, max: 32 }`; for others `false`, only the first window.
   */
  windows?: false | { stride?: number; max?: number };
  /**
   * Read HTML input the way an agent reads the page (its text, comments, and
   * descriptive attributes, as `detect()` does) instead of scoring markup.
   * Default true.
   */
  html?: boolean;
}

export interface ModelDetector {
  /** The model's name, reported as `pattern` in matches. */
  readonly model: string;
  /**
   * Scores `input` with the model, loading it on the first call. Returns a
   * detection when the score is at or above `threshold`, else `null`, so it
   * can be `escalate.detector` directly.
   */
  (input: string): Promise<DetectResult | null>;
  /** The model's probability that `input` is an injection, 0 to 1. */
  score(input: string, signal?: AbortSignal): Promise<number>;
  /** Loads the model now instead of on the first call. */
  load(): Promise<void>;
  /**
   * The `escalate` option for `detectAsync` and the provider wrappers, with
   * this detector. `minScore` defaults to 0.05.
   */
  escalate(minScore?: number): NonNullable<DetectOptions["escalate"]>;
  /**
   * Detect options that use this model in place of the built-in classifier:
   * pattern matching still runs first, and every input it doesn't flag is
   * scored by the model. This is how Shield's benchmark runs its model.
   * `extra` holds any other detect options.
   */
  options(extra?: DetectOptions): DetectOptions;
}

export interface ModelScoreDetails {
  score: number;
  /** Actual tokenizer count of the submitted text, without special tokens. */
  inputTokens: number;
  coverage: { truncated: boolean; windows: number; maxWindows: number };
}

export interface DetailedModelDetector extends ModelDetector {
  /** Scores once and reports tokenizer usage and the bounded window coverage. */
  scoreDetails(input: string, signal?: AbortSignal): Promise<ModelScoreDetails>;
  /** Release native sessions after all requests have drained. */
  dispose(): Promise<void>;
}

/** The parts of transformers.js this module uses. */
interface Tokenizer {
  encode(text: string, options?: { add_special_tokens?: boolean }): number[];
  pad_token_id?: number;
}

interface Classifier {
  config: { id2label?: Record<string, string> };
  dispose?(): Promise<unknown>;
  (
    inputs: Record<string, unknown>
  ): Promise<{
    logits: { data: ArrayLike<number> };
  }>;
}

interface Transformers {
  AutoTokenizer: {
    from_pretrained(source: string, options?: object): Promise<Tokenizer>;
  };
  AutoModelForSequenceClassification: {
    from_pretrained(source: string, options?: object): Promise<Classifier>;
  };
  Tensor: new (type: "int64", data: BigInt64Array, dims: number[]) => unknown;
}

interface LoadedModel {
  transformers: Transformers;
  tokenizer: Tokenizer;
  classifier: Classifier;
  /** Special tokens the tokenizer puts before and after a text. */
  head: number[];
  tail: number[];
  labelIndex: number;
  batchWindows: number;
  scheduler?: ModelDetectorOptions["scheduler"];
}

function isMissingPeer(error: unknown): boolean {
  const { code, message } = (error ?? {}) as {
    code?: unknown;
    message?: unknown;
  };
  const notFound =
    code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND";
  return notFound && String(message).includes(PEER);
}

async function importTransformers(): Promise<Transformers> {
  try {
    return (await importPeer()) as Transformers;
  } catch (error) {
    if (isMissingPeer(error)) {
      throw new ShieldError(
        `@zeroleaks/shield/model needs the optional peer dependency ${PEER} (version 3). Install it with: npm install ${PEER}@3`,
        "MODEL_DEPENDENCY_MISSING"
      );
    }
    throw error;
  }
}

/** Where transformers.js should read the model: a local directory or a repo id. */
function modelSource(options: ModelDetectorOptions, model: string): string {
  const { localPath } = options;
  if (localPath === undefined) {
    return model;
  }
  // transformers.js looks a path shaped like "org/name" up in its own
  // models directory, so relative paths are made explicit.
  return RE_REPO_ID_LIKE.test(localPath) ? `./${localPath}` : localPath;
}

function findLabel(
  id2label: Record<string, string> | undefined,
  label: string
): number {
  const wanted = label.toUpperCase();
  for (const [index, name] of Object.entries(id2label ?? {})) {
    if (String(name).toUpperCase() === wanted) {
      return Number(index);
    }
  }
  throw new ShieldError(
    `The model has no label "${label}" (its labels: ${Object.values(id2label ?? {}).join(", ") || "none"})`,
    "MODEL_LABEL_MISSING"
  );
}

/**
 * The special tokens the tokenizer adds before and after a single text,
 * found by encoding a word with and without them.
 */
function specialTokens(tokenizer: Tokenizer): {
  head: number[];
  tail: number[];
} {
  const withSpecial = tokenizer.encode("a");
  const plain = tokenizer.encode("a", { add_special_tokens: false });
  for (let i = 0; i + plain.length <= withSpecial.length; i++) {
    if (plain.every((id, j) => withSpecial[i + j] === id)) {
      return {
        head: withSpecial.slice(0, i),
        tail: withSpecial.slice(i + plain.length),
      };
    }
  }
  return { head: [], tail: [] };
}

async function loadModel(
  options: ModelDetectorOptions,
  model: string
): Promise<LoadedModel> {
  const transformers = await importTransformers();
  const local = options.localPath !== undefined;
  const common = {
    revision:
      options.revision ??
      (model === PROTECTAI_MODEL ? PROTECTAI_REVISION : "main"),
    cache_dir: options.cacheDir,
    local_files_only: local || options.allowDownload === false,
  };
  const source = modelSource(options, model);
  const sessionOptions = {
    ...(options.threads === undefined
      ? {}
      : { intraOpNumThreads: options.threads, interOpNumThreads: 1 }),
    ...(options.device === undefined
      ? {}
      : { executionProviders: [options.device] }),
  };
  const [tokenizer, classifier] = await Promise.all([
    transformers.AutoTokenizer.from_pretrained(source, common),
    transformers.AutoModelForSequenceClassification.from_pretrained(source, {
      ...common,
      dtype: options.dtype ?? profileFor(model).dtype,
      ...(options.device === undefined ? {} : { device: options.device }),
      session_options: sessionOptions,
    }),
  ]);
  return {
    transformers,
    tokenizer,
    classifier,
    ...specialTokens(tokenizer),
    labelIndex: findLabel(
      classifier.config.id2label,
      options.label ?? DEFAULT_LABEL
    ),
    // Q4 CUDA kernels require unpadded, single-window calls for this artifact.
    batchWindows: options.device === "cuda" ? 1 : BATCH_WINDOWS,
    scheduler: options.scheduler,
  };
}

/**
 * Whether every tokenizer splits `text` between `i - 1` and `i`: before a
 * single space between two other characters, or before a newline that
 * follows a letter or digit. A cut elsewhere in whitespace can change the
 * tokens: byte-level BPE, the large model's, reads a run of spaces or
 * newlines, and punctuation with the newlines after it, as one piece.
 */
function cleanCut(text: string, i: number): boolean {
  if (RE_BOUNDARY.test(text[i - 1])) {
    return false;
  }
  if (text[i] === "\n") {
    return RE_LETTER_OR_DIGIT.test(text[i - 1]);
  }
  return (
    text[i] === " " && i + 1 < text.length && !RE_BOUNDARY.test(text[i + 1])
  );
}

/**
 * Where the piece of `text` starting at `start` ends, after `CHUNK_CHARS`:
 * at a clean cut, else at the end of the text if that is near, else at any
 * whitespace, else after `MAX_WORD_CHARS` more.
 */
function chunkEnd(text: string, start: number): number {
  const soft = start + CHUNK_CHARS;
  const hard = Math.min(text.length, soft + MAX_WORD_CHARS);
  let loose = -1;
  for (let i = soft; i < hard; i++) {
    if (cleanCut(text, i)) {
      return i;
    }
    if (loose < 0 && RE_BOUNDARY.test(text[i])) {
      loose = i;
    }
  }
  if (hard === text.length) {
    return hard;
  }
  if (loose >= 0) {
    return loose;
  }
  // Don't cut a surrogate pair in two.
  const code = text.charCodeAt(hard - 1);
  return code >= 0xd8_00 && code <= 0xdb_ff ? hard + 1 : hard;
}

/**
 * The token ids the model reads for `text`: its first tokens between the
 * special tokens, `maxTokens` in all, as a Python tokenizer called with
 * `truncation=True, max_length=512` gives. transformers.js's own truncation
 * would cut the closing special token instead.
 */
function tokenize(loaded: LoadedModel, text: string, room: number): number[] {
  const { tokenizer } = loaded;
  const ids: number[] = [];
  const end = Math.min(text.length, MAX_SCAN_CHARS);
  // Pieces end where every tokenizer splits (see cleanCut), so they
  // tokenize as they would in the whole text.
  for (let start = 0; start < end && ids.length < room; ) {
    const stop = chunkEnd(text, start);
    ids.push(
      ...tokenizer.encode(text.slice(start, stop), {
        add_special_tokens: false,
      })
    );
    start = stop;
  }
  return ids.slice(0, room);
}

/**
 * The windows of `ids` to score: one starting every `stride` tokens, `body`
 * long, at most `max`. As in training and in the benchmark, a window starts
 * at every stride inside the input, so the last ones can be short.
 */
function windowsOf(
  ids: number[],
  body: number,
  stride: number,
  max: number
): number[][] {
  if (ids.length <= body) {
    return [ids];
  }
  const out: number[][] = [];
  for (let start = 0; start < ids.length && out.length < max; start += stride) {
    out.push(ids.slice(start, start + body));
  }
  return out;
}

function prepareWindows(
  loaded: LoadedModel,
  input: string,
  options: ModelDetectorOptions,
  profile: ModelProfile
): { text: string; bodies: number[][]; room: number; max: number } {
  const text =
    options.html !== false && looksLikeHtml(input)
      ? htmlText(input).text
      : input;
  const maxTokens = options.maxTokens ?? profile.maxTokens;
  const body = maxTokens - loaded.head.length - loaded.tail.length;
  const windows =
    options.windows === undefined ? profile.windows : options.windows;
  if (!windows) {
    return { text, bodies: [tokenize(loaded, text, body)], room: body, max: 1 };
  }
  const stride = Math.max(1, windows.stride ?? Math.floor((body * 3) / 4));
  const max = Math.max(1, windows.max ?? MAX_WINDOWS);
  const room = stride * (max - 1) + body;
  const ids = tokenize(loaded, text, room + 1);
  if (ids.length <= room || max <= TAIL_WINDOWS) {
    return {
      text,
      bodies: windowsOf(ids.slice(0, room), body, stride, max),
      room,
      max,
    };
  }
  const tailRoom = stride * (TAIL_WINDOWS - 1) + body;
  const tail = tokenize(
    loaded,
    text.slice(tailStart(text, tailRoom * TAIL_CHARS_PER_TOKEN)),
    Number.POSITIVE_INFINITY
  ).slice(-tailRoom);
  const headMax = max - TAIL_WINDOWS;
  const head = windowsOf(
    ids.slice(0, stride * (headMax - 1) + body),
    body,
    stride,
    headMax
  );
  return {
    text,
    bodies: [...head, ...tailWindows(tail, body, stride, TAIL_WINDOWS)],
    room,
    max,
  };
}

/** Where the last `chars` characters of `text` start, moved forward to the next space or line break. */
function tailStart(text: string, chars: number): number {
  if (text.length <= chars) {
    return 0;
  }
  let i = text.length - chars;
  while (i < text.length && !" \t\n\r".includes(text[i] ?? "")) {
    i++;
  }
  return i;
}

/** `n` windows of `body` tokens, every `stride` tokens, the last one ending at the end of `ids`. */
function tailWindows(
  ids: number[],
  body: number,
  stride: number,
  n: number
): number[][] {
  const out: number[][] = [];
  for (let k = n - 1; k >= 0; k--) {
    const end = ids.length - k * stride;
    if (end > 0) {
      out.push(ids.slice(Math.max(0, end - body), end));
    }
  }
  return out;
}

/** Windows scored in one call to the model. */
const BATCH_WINDOWS = 8;

/**
 * The model's highest probability over windows of token ids, with the
 * special tokens added, scoring up to `BATCH_WINDOWS` windows per call.
 */
async function scoreBatch(
  loaded: LoadedModel,
  bodies: number[][],
  signal?: AbortSignal
): Promise<number> {
  let best = 0;
  for (let i = 0; i < bodies.length; i += loaded.batchWindows) {
    signal?.throwIfAborted();
    const batch = bodies
      .slice(i, i + loaded.batchWindows)
      .map((b) => [...loaded.head, ...b, ...loaded.tail])
      .filter((row) => row.length > 0);
    if (batch.length === 0) {
      continue;
    }
    const release = await loaded.scheduler?.acquire(signal);
    let scores: number[];
    try {
      signal?.throwIfAborted();
      scores = await scoreRows(loaded, batch);
    } finally {
      release?.();
    }
    signal?.throwIfAborted();
    for (const p of scores) {
      best = Math.max(best, p);
    }
  }
  return best;
}

async function scoreRows(
  loaded: LoadedModel,
  rows: number[][]
): Promise<number[]> {
  const width = Math.max(...rows.map((r) => r.length));
  const pad = BigInt(loaded.tokenizer.pad_token_id ?? 0);
  const ids = new BigInt64Array(rows.length * width).fill(pad);
  const mask = new BigInt64Array(rows.length * width);
  rows.forEach((row, r) => {
    for (let t = 0; t < row.length; t++) {
      ids[r * width + t] = BigInt(row[t]);
      mask[r * width + t] = BigInt(1);
    }
  });
  const { Tensor } = loaded.transformers;
  const dims = [rows.length, width];
  const output = await loaded.classifier({
    input_ids: new Tensor("int64", ids, dims),
    attention_mask: new Tensor("int64", mask, dims),
  });
  const logits = Array.from(output.logits.data);
  const labels = logits.length / rows.length;
  if (
    !Number.isInteger(labels) ||
    labels < 1 ||
    !Number.isInteger(loaded.labelIndex) ||
    loaded.labelIndex < 0 ||
    loaded.labelIndex >= labels ||
    logits.some((value) => !Number.isFinite(value))
  ) {
    throw new ShieldError(
      "Model returned invalid logits",
      "MODEL_INVALID_OUTPUT"
    );
  }
  const out: number[] = [];
  for (let r = 0; r < rows.length; r++) {
    const z = logits.slice(r * labels, (r + 1) * labels);
    const max = Math.max(...z);
    let sum = 0;
    for (const v of z) {
      sum += Math.exp(v - max);
    }
    out.push(Math.exp(z[loaded.labelIndex] - max) / sum);
  }
  return out;
}

function riskFor(score: number): DetectResult["risk"] {
  if (score >= HIGH_RISK_SCORE) {
    return "high";
  }
  return score >= DEFAULT_THRESHOLD ? "medium" : "low";
}

/**
 * Creates a detector that runs a transformer model, by default Shield's own
 * (`zeroleaks/shield-small`), through `@huggingface/transformers`. The model
 * is downloaded (about 235MB) and loaded on the first call, once. If loading
 * fails, that call rejects and the next one tries again.
 */
export function createModelDetector(
  options: ModelDetectorOptions = {}
): DetailedModelDetector {
  const model = options.model ?? SHIELD_MODEL;
  const profile = profileFor(model);
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  let loading: Promise<LoadedModel> | undefined;
  let disposed = false;

  const load = (): Promise<LoadedModel> => {
    if (disposed) {
      return Promise.reject(
        new ShieldError("Model detector was disposed", "MODEL_DISPOSED")
      );
    }
    if (!loading) {
      loading = loadModel(options, model).catch((error: unknown) => {
        loading = undefined;
        throw error;
      });
    }
    return loading;
  };

  const score = async (
    input: string,
    signal?: AbortSignal
  ): Promise<number> => {
    signal?.throwIfAborted();
    const loaded = await load();
    signal?.throwIfAborted();
    return scoreBatch(
      loaded,
      prepareWindows(loaded, input, options, profile).bodies,
      signal
    );
  };
  const scoreDetails = async (
    input: string,
    signal?: AbortSignal
  ): Promise<ModelScoreDetails> => {
    signal?.throwIfAborted();
    const loaded = await load();
    signal?.throwIfAborted();
    const prepared = prepareWindows(loaded, input, options, profile);
    const countTokens =
      options.countTokens ??
      (async (text: string): Promise<number> =>
        loaded.tokenizer.encode(text, { add_special_tokens: false }).length);
    const inputTokens = await countTokens(input);
    const textTokens =
      prepared.text === input ? inputTokens : await countTokens(prepared.text);
    signal?.throwIfAborted();
    return {
      score: await scoreBatch(loaded, prepared.bodies, signal),
      inputTokens,
      coverage: {
        truncated:
          textTokens > prepared.room || prepared.text.length > MAX_SCAN_CHARS,
        windows: prepared.bodies.length,
        maxWindows: prepared.max,
      },
    };
  };

  return Object.assign(
    detectorFrom(
      model,
      score,
      async () => {
        await load();
      },
      threshold
    ),
    {
      scoreDetails,
      async dispose(): Promise<void> {
        if (disposed) {
          return;
        }
        disposed = true;
        const current = loading;
        loading = undefined;
        if (current) {
          const loaded = await current;
          await loaded.classifier.dispose?.();
        }
      },
    }
  );
}

/** A `ModelDetector` from a scoring function. */
function detectorFrom(
  model: string,
  score: (input: string) => Promise<number>,
  load: () => Promise<void>,
  threshold: number
): ModelDetector {
  const detector = async (input: string): Promise<DetectResult | null> => {
    const probability = await score(input);
    if (probability < threshold) {
      return null;
    }
    return {
      detected: true,
      risk: riskFor(probability),
      matches: [{ category: "model", pattern: model, confidence: probability }],
      score: probability,
    };
  };

  return Object.assign(detector, {
    model,
    score,
    load,
    escalate: (minScore = DEFAULT_MIN_SCORE) => ({ minScore, detector }),
    options: (extra: DetectOptions = {}): DetectOptions => ({
      ...extra,
      excludeCategories: extra.excludeCategories ?? [
        ...MODEL_EXCLUDED_CATEGORIES,
      ],
      excludePatterns: extra.excludePatterns ?? [...MODEL_EXCLUDED_PATTERNS],
      classifier: false,
      escalate: { minScore: 0, detector },
    }),
  });
}

/**
 * Rule categories left out when a model runs with the rules. The models catch
 * instruction-override phrasings ("ignore previous instructions") on their own,
 * and on benign agent text (tool descriptions, skills, documentation) those
 * rules mostly add false alarms: without them, every model tier flagged fewer
 * benign texts and caught as many agent attacks. Pass `excludeCategories` to
 * `options()` to choose your own list; rules-only `detect()` is unchanged.
 */
export const MODEL_EXCLUDED_CATEGORIES: readonly string[] = [
  "instruction_override",
];

/**
 * Built-in patterns, by regex source, left out when a model runs with the
 * rules. Two match topics rather than attacks (the cloud metadata address in
 * SSRF advisories, compliance ticket numbers in business text); the third
 * gives way to a variant that skips quoted "You are DAN". None caught an
 * attack the models missed, and all flagged benign text. Pass
 * `excludePatterns` to `options()` to choose your own list.
 */
export const MODEL_EXCLUDED_PATTERNS: readonly string[] = [
  /169\.254\.169\.254/.source,
  /(?:compliance|security)\s+ticket\s+\w+-\d+/i.source,
  /you\s+are\s+(now\s+)?(DAN|DUDE|STAN|KEVIN|JAILBREAK)\b/i.source,
];

export interface TieredOptions {
  /**
   * Fast-model scores from `from` up to, but not including, `to` count as
   * unsure, and the large model decides those inputs. Defaults 0.01 and 0.97.
   */
  from?: number;
  to?: number;
  /** Probability at or above which the input is an injection. Default 0.5. */
  threshold?: number;
}

/**
 * Two models as one detector: `fast` scores every input, and the inputs it
 * is unsure about go to `large`, whose score is used instead. The large
 * model runs on a small share of inputs, so the detector costs about what the
 * fast model costs and is close to the large model's accuracy.
 *
 * @example
 * ```ts
 * const model = tiered(
 *   createModelDetector(),
 *   createModelDetector({ model: SHIELD_MODEL_LARGE })
 * );
 * const result = await detectAsync(text, model.options());
 * ```
 */
export function tiered(
  fast: ModelDetector,
  large: ModelDetector,
  options: TieredOptions = {}
): ModelDetector {
  const from = options.from ?? 0.01;
  const to = options.to ?? 0.97;
  const score = async (input: string): Promise<number> => {
    const first = await fast.score(input);
    return first >= from && first < to ? await large.score(input) : first;
  };
  return detectorFrom(
    `${fast.model}+${large.model}`,
    score,
    async () => {
      await Promise.all([fast.load(), large.load()]);
    },
    options.threshold ?? DEFAULT_THRESHOLD
  );
}
