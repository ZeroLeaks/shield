export interface SanitizeResult {
  leaked: boolean;
  confidence: number;
  fragments: string[];
  sanitized: string;
}

export interface SanitizeOptions {
  ngramSize?: number;
  threshold?: number;
  wordOverlapThreshold?: number;
  redactionText?: string;
  detectOnly?: boolean;
}

export function sanitizeObject<T extends Record<string, unknown>>(
  obj: T,
  systemPrompt: string,
  options: SanitizeOptions = {}
): { result: T; hadLeak: boolean } {
  if (!obj || typeof obj !== "object") return { result: obj, hadLeak: false };
  const result = (Array.isArray(obj) ? [...obj] : { ...obj }) as T;
  let hadLeak = false;
  for (const key of Object.keys(result)) {
    const val = result[key as keyof T];
    if (typeof val === "string") {
      const r = sanitize(val, systemPrompt, options);
      if (r.leaked) {
        hadLeak = true;
        (result as Record<string, unknown>)[key] = r.sanitized;
      }
    } else if (
      val !== null &&
      typeof val === "object" &&
      (Object.prototype.toString.call(val) === "[object Object]" ||
        Array.isArray(val))
    ) {
      const nested = sanitizeObject(
        val as Record<string, unknown>,
        systemPrompt,
        options
      );
      (result as Record<string, unknown>)[key] = nested.result;
      if (nested.hadLeak) hadLeak = true;
    }
  }
  return { result, hadLeak };
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^\w\s]/g, " ")
    .split(/\s+/)
    .filter(Boolean);
}

function generateNgrams(tokens: string[], n: number): Set<string> {
  const ngrams = new Set<string>();
  for (let i = 0; i <= tokens.length - n; i++) {
    ngrams.add(tokens.slice(i, i + n).join(" "));
  }
  return ngrams;
}

function wordOverlapRatio(
  outputTokens: string[],
  promptTokens: string[]
): number {
  const outSet = new Set(outputTokens);
  const promptSet = new Set(promptTokens);
  let intersection = 0;
  for (const w of outSet) {
    if (promptSet.has(w)) {
      intersection++;
    }
  }
  const union = outSet.size + promptSet.size - intersection;
  return union > 0 ? intersection / union : 0;
}

function findMatchingSubstrings(
  output: string,
  promptTokens: string[],
  ngramSize: number,
  threshold: number
): string[] {
  const outputTokens = tokenize(output);
  const promptNgrams = generateNgrams(promptTokens, ngramSize);

  const matches: string[] = [];
  const windowSize = ngramSize + 4;

  for (let i = 0; i <= outputTokens.length - ngramSize; i++) {
    const ngram = outputTokens.slice(i, i + ngramSize).join(" ");
    if (promptNgrams.has(ngram)) {
      const end = Math.min(i + windowSize, outputTokens.length);
      const fragment = outputTokens.slice(i, end).join(" ");
      if (!matches.some((m) => m.includes(ngram))) {
        matches.push(fragment);
      }
    }
  }

  return matches;
}

const SANITIZE_MAX_OUTPUT_LENGTH = 1024 * 1024;

export function sanitize(
  output: string,
  systemPrompt: string,
  options: SanitizeOptions = {}
): SanitizeResult {
  if (
    !output ||
    typeof output !== "string" ||
    !systemPrompt ||
    typeof systemPrompt !== "string"
  ) {
    return {
      leaked: false,
      confidence: 0,
      fragments: [],
      sanitized: output || "",
    };
  }

  const boundedOutput =
    output.length > SANITIZE_MAX_OUTPUT_LENGTH
      ? output.slice(0, SANITIZE_MAX_OUTPUT_LENGTH)
      : output;
  const ngramSize = options.ngramSize ?? 4;
  const threshold = options.threshold ?? 0.7;
  const wordOverlapThreshold = options.wordOverlapThreshold ?? 0.25;
  const redactionText = options.redactionText || "[REDACTED]";

  const promptTokens = tokenize(systemPrompt);
  const outputTokens = tokenize(boundedOutput);

  const effectiveNgram = Math.min(ngramSize, Math.max(2, promptTokens.length));
  if (promptTokens.length < 2) {
    return {
      leaked: false,
      confidence: 0,
      fragments: [],
      sanitized: boundedOutput,
    };
  }

  const promptNgrams = generateNgrams(promptTokens, effectiveNgram);
  const fragments = findMatchingSubstrings(
    boundedOutput,
    promptTokens,
    effectiveNgram,
    threshold
  );

  const smallNgramSize = Math.min(3, Math.max(1, effectiveNgram - 1));
  const smallFragments =
    smallNgramSize >= 2 && promptTokens.length >= smallNgramSize
      ? findMatchingSubstrings(
          boundedOutput,
          promptTokens,
          smallNgramSize,
          threshold
        )
      : [];

  const outputNgrams = generateNgrams(outputTokens, effectiveNgram);
  let ngramOverlap = 0;
  for (const ng of outputNgrams) {
    if (promptNgrams.has(ng)) {
      ngramOverlap++;
    }
  }
  const ngramOverlapRatio =
    promptNgrams.size > 0 ? ngramOverlap / promptNgrams.size : 0;
  const wordOverlap = wordOverlapRatio(outputTokens, promptTokens);

  const confidence =
    fragments.length > 0
      ? Math.min(1, ngramOverlapRatio * 2 + (fragments.length > 2 ? 0.2 : 0))
      : wordOverlap >= wordOverlapThreshold
        ? Math.min(1, wordOverlap * 2)
        : 0;

  const isLeak =
    (fragments.length > 0 && confidence >= threshold) ||
    fragments.length >= 2 ||
    (smallFragments.length >= 3 && wordOverlap >= wordOverlapThreshold) ||
    (wordOverlap >= wordOverlapThreshold * 1.5 && smallFragments.length >= 1);

  if (!isLeak) {
    return {
      leaked: false,
      confidence,
      fragments: [],
      sanitized: boundedOutput,
    };
  }

  const allFragments = [...new Set([...fragments, ...smallFragments])];

  let sanitized = boundedOutput;
  if (!options.detectOnly) {
    for (const fragment of allFragments) {
      const words = fragment.split(" ");
      for (let len = words.length; len >= effectiveNgram; len--) {
        const sub = words.slice(0, len).join(" ");
        const regex = new RegExp(
          sub.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+"),
          "gi"
        );
        sanitized = sanitized.replace(regex, redactionText);
      }
    }
  }

  return {
    leaked: true,
    confidence,
    fragments: allFragments,
    sanitized,
  };
}
