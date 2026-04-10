export interface DetectNormalizationOptions {
  enabled?: boolean;
  foldHomoglyphs?: boolean;
  stripInvisible?: boolean;
  collapseWhitespace?: boolean;
  joinSeparatedLetters?: boolean;
  normalizeCase?: boolean;
  decodeLeetspeak?: boolean;
  repairTypos?: boolean;
  repairPhonetics?: boolean;
}

export interface ResolvedDetectNormalizationOptions {
  enabled: boolean;
  foldHomoglyphs: boolean;
  stripInvisible: boolean;
  collapseWhitespace: boolean;
  joinSeparatedLetters: boolean;
  normalizeCase: boolean;
  decodeLeetspeak: boolean;
  repairTypos: boolean;
  repairPhonetics: boolean;
}

const RE_WHITESPACE = /\s+/g;
const RE_WHITESPACE_SPLIT = /\s+/;
const RE_WORD_CHAR = /\w/;
const RE_INVISIBLE = /[\u200B-\u200F\u2028-\u202F\uFEFF\u2060]/g;

const TYPO_MAP: Record<string, string> = {
  ingnore: "ignore",
  ignor: "ignore",
  ign0re: "ignore",
  previ0us: "previous",
  previus: "previous",
  instrucions: "instructions",
  instrucion: "instruction",
  overide: "override",
  overrride: "override",
  disreguard: "disregard",
  disrega: "disregard",
};

const HOMOGLYPH_MAP: [string, string][] = [
  ["\uFF21", "A"],
  ["\uFF22", "B"],
  ["\uFF23", "C"],
  ["\uFF24", "D"],
  ["\uFF25", "E"],
  ["\uFF26", "F"],
  ["\uFF27", "G"],
  ["\uFF28", "H"],
  ["\uFF29", "I"],
  ["\uFF2A", "J"],
  ["\uFF2B", "K"],
  ["\uFF2C", "L"],
  ["\uFF2D", "M"],
  ["\uFF2E", "N"],
  ["\uFF2F", "O"],
  ["\uFF30", "P"],
  ["\uFF31", "Q"],
  ["\uFF32", "R"],
  ["\uFF33", "S"],
  ["\uFF34", "T"],
  ["\uFF35", "U"],
  ["\uFF36", "V"],
  ["\uFF37", "W"],
  ["\uFF38", "X"],
  ["\uFF39", "Y"],
  ["\uFF3A", "Z"],
  ["\uFF41", "a"],
  ["\uFF42", "b"],
  ["\uFF43", "c"],
  ["\uFF44", "d"],
  ["\uFF45", "e"],
  ["\uFF46", "f"],
  ["\uFF47", "g"],
  ["\uFF48", "h"],
  ["\uFF49", "i"],
  ["\uFF4A", "j"],
  ["\uFF4B", "k"],
  ["\uFF4C", "l"],
  ["\uFF4D", "m"],
  ["\uFF4E", "n"],
  ["\uFF4F", "o"],
  ["\uFF50", "p"],
  ["\uFF51", "q"],
  ["\uFF52", "r"],
  ["\uFF53", "s"],
  ["\uFF54", "t"],
  ["\uFF55", "u"],
  ["\uFF56", "v"],
  ["\uFF57", "w"],
  ["\uFF58", "x"],
  ["\uFF59", "y"],
  ["\uFF5A", "z"],
  ["\u0430", "a"],
  ["\u043E", "o"],
  ["\u0435", "e"],
  ["\u0440", "p"],
  ["\u0441", "c"],
  ["\u0445", "x"],
  ["\u0456", "i"],
  ["\u04CF", "d"],
];

const LEET_SEQUENCE_MAP: Array<[RegExp, string]> = [
  [/\|\\\|/g, "n"],
  [/\|_\|/g, "u"],
  [/\|v\|/g, "m"],
  [/\|<|\|\{/g, "k"],
  [/\|2/g, "r"],
  [/\|\)/g, "d"],
  [/\|=/g, "f"],
  [/\|\*/g, "p"],
  [/\/\/\\\\/g, "m"],
  [/\\\/\\\//g, "w"],
  [/\\\//g, "v"],
  [/></g, "x"],
];

const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "6": "g",
  "7": "t",
  "8": "b",
  "9": "g",
  "@": "a",
  $: "s",
  "!": "i",
};

const PHONETIC_PATTERNS: Array<[RegExp, string]> = [
  [/\bignorre?\b/gi, "ignore"],
  [/\bign?r\b/gi, "ignore"],
  [/\bpr[3e]vious\b/gi, "previous"],
  [/\binstr(?:uk|uc)tions?\b/gi, "instructions"],
  [/\boverryde\b/gi, "override"],
  [/\bd[i1]sregard\b/gi, "disregard"],
  [/\bpromt\b/gi, "prompt"],
  [/\brulz\b/gi, "rules"],
];

export const DEFAULT_DETECT_NORMALIZATION: ResolvedDetectNormalizationOptions = {
  enabled: true,
  foldHomoglyphs: true,
  stripInvisible: true,
  collapseWhitespace: true,
  joinSeparatedLetters: true,
  normalizeCase: true,
  decodeLeetspeak: true,
  repairTypos: true,
  repairPhonetics: true,
};

function applyHomoglyphs(input: string): string {
  let result = input;
  for (const [from, to] of HOMOGLYPH_MAP) {
    result = result.split(from).join(to);
  }
  return result;
}

function collapseWhitespace(input: string): string {
  return input.replace(RE_WHITESPACE, " ");
}

function joinSeparatedLetters(input: string): string {
  return input.replace(/(?<!\w)(\w)(\s+\w)+(?!\w)/g, (match) => {
    const tokens = match.split(RE_WHITESPACE_SPLIT);
    if (tokens.every((token) => token.length === 1 && RE_WORD_CHAR.test(token))) {
      return tokens.join("");
    }
    return match;
  });
}

function decodeLeetspeak(input: string): string {
  let result = input;
  for (const [pattern, replacement] of LEET_SEQUENCE_MAP) {
    result = result.replace(pattern, replacement);
  }
  for (const [from, to] of Object.entries(LEET_MAP)) {
    result = result.replace(
      new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"),
      to
    );
  }
  return result;
}

function repairTypos(input: string): string {
  let result = input;
  for (const [typo, correct] of Object.entries(TYPO_MAP)) {
    const escaped = typo.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`\\b${escaped}\\b`, "gi");
    result = result.replace(re, correct);
  }
  return result;
}

function repairPhonetics(input: string): string {
  let result = input;
  for (const [pattern, replacement] of PHONETIC_PATTERNS) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

export function resolveDetectNormalization(
  options?: false | DetectNormalizationOptions
): ResolvedDetectNormalizationOptions {
  if (options === false) {
    return {
      ...DEFAULT_DETECT_NORMALIZATION,
      enabled: false,
    };
  }

  return {
    ...DEFAULT_DETECT_NORMALIZATION,
    ...options,
  };
}

export function normalizeForDetection(
  input: string,
  options?: false | DetectNormalizationOptions
): string {
  const config = resolveDetectNormalization(options);
  if (!config.enabled) {
    return input.trim();
  }

  let normalized = input.normalize("NFKC");

  if (config.foldHomoglyphs) {
    normalized = applyHomoglyphs(normalized);
  }
  if (config.stripInvisible) {
    normalized = normalized.replace(RE_INVISIBLE, "");
  }
  if (config.collapseWhitespace) {
    normalized = collapseWhitespace(normalized);
  }
  if (config.joinSeparatedLetters) {
    normalized = joinSeparatedLetters(normalized);
  }
  if (config.normalizeCase) {
    normalized = normalized.toLowerCase();
  }
  if (config.decodeLeetspeak) {
    normalized = decodeLeetspeak(normalized);
  }
  if (config.repairTypos) {
    normalized = repairTypos(normalized);
  }
  if (config.repairPhonetics) {
    normalized = repairPhonetics(normalized);
  }
  if (config.collapseWhitespace) {
    normalized = collapseWhitespace(normalized);
  }

  return normalized.trim();
}
