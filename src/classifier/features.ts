// biome-ignore-all lint/suspicious/noBitwiseOperators: FNV-1a and MurmurHash3 feature hashing requires bit manipulation.
/**
 * Feature extraction for the injection classifier. Training reads features
 * produced by this same code, so a model and the SDK that runs it always
 * agree on what each feature index means.
 */

export const FEATURE_BITS = 18;
export const FEATURE_MASK = (1 << FEATURE_BITS) - 1;

export const FNV_OFFSET = 0x81_1c_9d_c5;
export const FNV_PRIME = 0x01_00_01_93;
export const WORD_SEED = 0x9e_37_79_b9;
export const BIGRAM_SEED = 0x5b_d1_e9_95;
export const MIN_NGRAM = 3;
export const MAX_NGRAM = 5;

export const RE_WORD = /[\p{L}\p{N}]+/gu;

/**
 * MurmurHash3's 32-bit finalizer, to spread FNV output across buckets.
 * Returns a signed 32-bit integer; callers mask it, which gives the same
 * bucket as the unsigned value and keeps the math in small integers.
 */
export function mix(h: number): number {
  let x = h ^ (h >>> 16);
  x = Math.imul(x, 0x85_eb_ca_6b);
  x ^= x >>> 13;
  x = Math.imul(x, 0xc2_b2_ae_35);
  return x ^ (x >>> 16);
}

export function hashString(s: string, seed: number): number {
  let h = seed;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), FNV_PRIME);
  }
  return h >>> 0;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: matches any character outside ASCII.
export const RE_NON_ASCII = /[^\x00-\x7f]/;

export function isAsciiWordChar(c: number): boolean {
  return (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || (c >= 65 && c <= 90);
}

/**
 * Calls `visit` with the feature index of each character 3- to 5-gram of the
 * text padded with a space on each side, each word, and each pair of adjacent
 * words. Indices can repeat. `text` should already be normalized.
 */
export function visitFeatures(
  text: string,
  visit: (index: number) => void
): void {
  const s = ` ${text} `;
  const n = s.length;
  for (let i = 0; i + MIN_NGRAM <= n; i++) {
    let h = FNV_OFFSET;
    for (let k = 0; k < MAX_NGRAM && i + k < n; k++) {
      h = Math.imul(h ^ s.charCodeAt(i + k), FNV_PRIME);
      if (k + 1 >= MIN_NGRAM) {
        visit(mix(h ^ (k + 1)) & FEATURE_MASK);
      }
    }
  }

  let prev = -1;
  const word = (w: number) => {
    visit(mix(w) & FEATURE_MASK);
    if (prev >= 0) {
      visit(mix(Math.imul(prev ^ BIGRAM_SEED, FNV_PRIME) ^ w) & FEATURE_MASK);
    }
    prev = w;
  };
  if (RE_NON_ASCII.test(text)) {
    RE_WORD.lastIndex = 0;
    let m = RE_WORD.exec(text);
    while (m) {
      word(hashString(m[0], WORD_SEED));
      m = RE_WORD.exec(text);
    }
    return;
  }
  let h = WORD_SEED;
  let inWord = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (isAsciiWordChar(c)) {
      h = Math.imul(h ^ c, FNV_PRIME);
      inWord = true;
    } else if (inWord) {
      word(h >>> 0);
      h = WORD_SEED;
      inWord = false;
    }
  }
  if (inWord) {
    word(h >>> 0);
  }
}

/** The distinct feature indices of `text`. */
export function extractFeatures(text: string): Set<number> {
  const out = new Set<number>();
  visitFeatures(text, (index) => out.add(index));
  return out;
}
