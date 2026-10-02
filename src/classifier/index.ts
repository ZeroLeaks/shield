// biome-ignore-all lint/suspicious/noBitwiseOperators: feature hashing and 4-bit weight unpacking require bit manipulation.
import {
  BIGRAM_SEED,
  FEATURE_BITS,
  FNV_OFFSET,
  FNV_PRIME,
  hashString,
  isAsciiWordChar,
  MAX_NGRAM,
  MIN_NGRAM,
  mix,
  RE_NON_ASCII,
  RE_WORD,
  WORD_SEED,
} from "./features";
import { MODEL } from "./model";

/** Characters of normalized text scored together, unless the model sets its own. */
export const CLASSIFIER_WINDOW = 1024;
/** Beyond this many overlapping windows, long text is scored without overlap. */
const MAX_OVERLAPPING_WINDOWS = 32;

export interface ClassifierModel {
  version: string;
  /** The model has `2 ** bits` weights; feature indices are folded to fit. */
  bits: number;
  /** `int8`: one signed byte per weight. `int4`: two signed nibbles per byte, low first. */
  encoding: "int4" | "int8";
  /** Base64 of the quantized weights. */
  weights: string;
  scale: number;
  bias: number;
  /** Probability at or above which text is reported as an injection. */
  threshold: number;
  /** Probability at or above which a detection is reported as high risk. */
  highThreshold: number;
  /** Characters per scoring window the model was trained on. Default 1024. */
  window?: number;
}

let decoded: Int8Array | undefined;

function decodeWeights(model: ClassifierModel): Int8Array {
  const bytes = Uint8Array.from(atob(model.weights), (c) => c.charCodeAt(0));
  const size = 1 << model.bits;
  if (model.encoding === "int8") {
    return new Int8Array(bytes.buffer, 0, size);
  }
  const weights = new Int8Array(size);
  for (let i = 0; i < size / 2; i++) {
    const byte = bytes[i];
    weights[2 * i] = ((byte & 0x0f) << 28) >> 28;
    weights[2 * i + 1] = (byte << 24) >> 28;
  }
  return weights;
}

function getWeights(): Int8Array {
  decoded ??= decodeWeights(MODEL);
  return decoded;
}

function sigmoid(z: number): number {
  return 1 / (1 + Math.exp(-z));
}

// Marks which features a window has already counted: `marks[i] === generation`
// means feature i was seen in the current window. Cheaper than a Set, and a
// byte per feature keeps it small enough to stay in cache.
let marks: Uint8Array | undefined;
let generation = 0;
let codes = new Uint16Array(4096);

/**
 * Injection probability of one window of normalized text. This is
 * `visitFeatures` with the scoring inlined, since it runs on every window;
 * a test checks that both see the same features.
 */
// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: the hot loop is inlined on purpose; a test checks it against visitFeatures.
function scoreWindow(text: string, weights: Int8Array): number {
  if (marks === undefined) {
    marks = new Uint8Array(1 << FEATURE_BITS);
  }
  const mask = weights.length - 1;
  if (generation === 255) {
    marks.fill(0);
    generation = 0;
  }
  generation++;
  const seen = marks;
  const gen = generation;
  let sum = 0;
  let count = 0;

  // The window padded with a space on each side, as char codes: indexing a
  // typed array is faster than charCodeAt on a concatenated string.
  const n = text.length + 2;
  if (codes.length < n) {
    codes = new Uint16Array(n * 2);
  }
  const c = codes;
  c[0] = 32;
  for (let i = 0; i < text.length; i++) {
    c[i + 1] = text.charCodeAt(i);
  }
  c[n - 1] = 32;
  for (let i = 0; i + MIN_NGRAM <= n; i++) {
    let h = FNV_OFFSET;
    const end = n - i < MAX_NGRAM ? n - i : MAX_NGRAM;
    for (let k = 0; k < end; k++) {
      h = Math.imul(h ^ c[i + k], FNV_PRIME);
      if (k + 1 >= MIN_NGRAM) {
        const f = mix(h ^ (k + 1)) & mask;
        if (seen[f] !== gen) {
          seen[f] = gen;
          sum += weights[f];
          count++;
        }
      }
    }
  }

  // Word and word-pair features. Kept in this function, without a closure,
  // so the sums stay in registers.
  const words = wordHashes(text);
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const f = mix(w) & mask;
    if (seen[f] !== gen) {
      seen[f] = gen;
      sum += weights[f];
      count++;
    }
    if (i > 0) {
      const b =
        mix(Math.imul(words[i - 1] ^ BIGRAM_SEED, FNV_PRIME) ^ w) & mask;
      if (seen[b] !== gen) {
        seen[b] = gen;
        sum += weights[b];
        count++;
      }
    }
  }

  if (count === 0) {
    return 0;
  }
  return sigmoid(MODEL.bias + (MODEL.scale * sum) / Math.sqrt(count));
}

/** The hash of each word in `text`, as `visitFeatures` computes them. */
function wordHashes(text: string): number[] {
  const out: number[] = [];
  if (RE_NON_ASCII.test(text)) {
    RE_WORD.lastIndex = 0;
    let m = RE_WORD.exec(text);
    while (m) {
      out.push(hashString(m[0], WORD_SEED));
      m = RE_WORD.exec(text);
    }
    return out;
  }
  let h = WORD_SEED;
  let inWord = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (isAsciiWordChar(c)) {
      h = Math.imul(h ^ c, FNV_PRIME);
      inWord = true;
    } else if (inWord) {
      out.push(h >>> 0);
      h = WORD_SEED;
      inWord = false;
    }
  }
  if (inWord) {
    out.push(h >>> 0);
  }
  return out;
}

/** For tests: the probability computed from `visitFeatures`, not inlined. */
export function scoreWithVisitor(
  text: string,
  visit: (text: string, cb: (f: number) => void) => void
): number {
  const weights = getWeights();
  const mask = weights.length - 1;
  const features = new Set<number>();
  visit(text, (f) => features.add(f & mask));
  if (features.size === 0) {
    return 0;
  }
  let sum = 0;
  for (const f of features) {
    sum += weights[f];
  }
  return sigmoid(MODEL.bias + (MODEL.scale * sum) / Math.sqrt(features.size));
}

/** For tests: the inlined window score. */
export function scoreWindowForTest(text: string): number {
  return scoreWindow(text, getWeights());
}

/**
 * Injection probability of normalized text: the highest score of any window,
 * so an instruction buried in a long document isn't averaged away.
 */
export function classify(normalized: string): number {
  const weights = getWeights();
  const size = MODEL.window ?? CLASSIFIER_WINDOW;
  if (normalized.length <= size) {
    return scoreWindow(normalized, weights);
  }
  const overlapStep = (size * 3) / 4;
  const overlapping =
    normalized.length <= overlapStep * MAX_OVERLAPPING_WINDOWS;
  const step = overlapping ? overlapStep : size;
  let max = 0;
  for (let start = 0; start < normalized.length; start += step) {
    const window = normalized.slice(start, start + size);
    if (start > 0 && window.length < 64) {
      break;
    }
    max = Math.max(max, scoreWindow(window, weights));
    if (start + size >= normalized.length) {
      break;
    }
  }
  return max;
}

export const classifierThresholds = {
  get threshold(): number {
    return MODEL.threshold;
  },
  get highThreshold(): number {
    return MODEL.highThreshold;
  },
  get version(): string {
    return MODEL.version;
  },
};
