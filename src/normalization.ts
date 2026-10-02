export interface DetectNormalizationOptions {
  enabled?: boolean;
  foldHomoglyphs?: boolean;
  stripInvisible?: boolean;
  collapseWhitespace?: boolean;
  joinSeparatedLetters?: boolean;
  /**
   * Rules always match lowercased text, so this no longer changes what
   * `detect` sees. It only affects the string `normalizeForDetection`
   * returns.
   */
  normalizeCase?: boolean;
  decodeLeetspeak?: boolean;
  repairTypos?: boolean;
  repairPhonetics?: boolean;
  /**
   * Decode payloads hidden in base64, hex, binary, URL encoding, HTML
   * entities, escape sequences, Unicode tag characters, variation selectors,
   * ROT13, Morse, Braille, and reversed or upside-down text, and scan what
   * they decode to.
   */
  decodePayloads?: boolean;
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
  decodePayloads: boolean;
}

export const DEFAULT_DETECT_NORMALIZATION: ResolvedDetectNormalizationOptions =
  {
    enabled: true,
    foldHomoglyphs: true,
    stripInvisible: true,
    collapseWhitespace: true,
    joinSeparatedLetters: true,
    normalizeCase: true,
    decodeLeetspeak: true,
    repairTypos: true,
    repairPhonetics: true,
    decodePayloads: true,
  };

export function resolveDetectNormalization(
  options?: false | DetectNormalizationOptions
): ResolvedDetectNormalizationOptions {
  if (options === false) {
    return { ...DEFAULT_DETECT_NORMALIZATION, enabled: false };
  }
  return { ...DEFAULT_DETECT_NORMALIZATION, ...options };
}

/** Signs of deliberate obfuscation found while normalizing. */
export interface ObfuscationSignals {
  /** Invisible Unicode tag characters that spell out ASCII text. */
  unicodeTags: number;
  /** Variation selectors carrying bytes after a visible character. */
  variationSelectors: number;
  /** Zero-width and other invisible format characters. */
  invisible: number;
  /** Invisible characters between two Latin letters, splitting a word. */
  invisibleInWords: number;
  /** Right-to-left and left-to-right override controls (Trojan Source). */
  bidi: number;
  /** Words that mix Latin with Cyrillic, Greek, or Armenian letters. */
  mixedScriptWords: number;
  /** Letters carrying two or more stacked combining marks (Zalgo text). */
  stackedMarks: number;
}

export interface HiddenText {
  encoding: "unicode_tags" | "variation_selectors";
  text: string;
}

export interface NormalizedViews {
  /** NFKC, invisible characters removed, diacritics stripped, lowercased, whitespace collapsed. */
  text: string;
  /**
   * `text` with obfuscation undone: spaced-out letters joined, separators
   * inside words removed, leetspeak decoded, typos repaired. Equal to `text`
   * when there was nothing to undo.
   */
  deobfuscated: string;
  /** A second leetspeak reading with `1` as `l`, when the text has one. */
  deobfuscatedAlt?: string;
  /** Text smuggled in Unicode tags or variation selectors, decoded. */
  hidden: HiddenText[];
  signals: ObfuscationSignals;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: matches any character outside ASCII.
const RE_NON_ASCII = /[^\x00-\x7f]/;
// Runs of whitespace other than a lone space: any run that starts with
// another space character, or a space followed by more whitespace. A single
// space is left alone, so ordinary prose has nothing to replace.
const RE_WS_RUN =
  /(?:[\t\f\v\r\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]| (?=[ \t\f\v\r\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]))[ \t\f\v\r\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]*/g;
const RE_NEWLINE_RUN = / ?\n[\s]*/g;
const RE_BIDI = /[\u202a-\u202e\u2066-\u2069]/g;
const RE_BIDI_OVERRIDE = /[\u202d\u202e]/g;
const RE_INVISIBLE_IN_WORD =
  /[a-z][\u034f\u115f\u1160\u180e\u200b-\u200d\u2060-\u2064\ufeff]+(?=[a-z])/gi;
// Zero-width, soft hyphen, word joiners, fillers, and similar format
// characters. Tags and variation selectors are handled separately.
const RE_INVISIBLE =
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: the class lists combining and format characters on purpose, to find or strip them.
  /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2060-\u2065\u206a-\u206f\u3164\ufeff\uffa0\ufff0-\ufff8]/g;
const RE_TAG_RUN = /(?:\udb40[\udc00-\udc7f])+/g;
const RE_VS_RUN = /(?:[\ufe00-\ufe0f]|\udb40[\udd00-\uddef]){4,}/g;
const RE_VS_ANY = /[\ufe00-\ufe0f]|\udb40[\udd00-\uddef]/g;
const RE_TAG_ANY = /\udb40[\udc00-\udc7f]/g;
// Combining marks used on Latin, Greek, and Cyrillic, plus Arabic harakat
// and Hebrew points. Indic vowel signs and kana voicing marks stay.
const RE_COMBINING =
  // biome-ignore lint/suspicious/noMisleadingCharacterClass: the class lists combining and format characters on purpose, to find or strip them.
  /[\u0300-\u036f\u0483-\u0489\u0591-\u05c7\u064b-\u065f\u0670\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]/g;
const RE_STACKED_MARKS =
  /[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff]{2,}/g;
const RE_WORD = /[\p{L}\p{M}]+/gu;
const RE_LATIN_LETTER = /[a-z]/;
const RE_CONFUSABLE_SCRIPT =
  /[\u0370-\u03ff\u0400-\u04ff\u0500-\u052f\u0531-\u058f]/;

/** Letters from other scripts that render like Latin ones. Lowercase keys. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: "a",
  в: "b",
  г: "r",
  д: "d",
  е: "e",
  ё: "e",
  з: "3",
  и: "u",
  й: "u",
  к: "k",
  м: "m",
  н: "h",
  о: "o",
  п: "n",
  р: "p",
  с: "c",
  т: "t",
  у: "y",
  х: "x",
  ь: "b",
  ѕ: "s",
  і: "i",
  ї: "i",
  ј: "j",
  һ: "h",
  ԁ: "d",
  ԛ: "q",
  ԝ: "w",
  ӏ: "l",
  ү: "y",
  // Greek
  α: "a",
  β: "b",
  γ: "y",
  ε: "e",
  η: "n",
  ι: "i",
  κ: "k",
  ν: "v",
  ο: "o",
  ρ: "p",
  τ: "t",
  υ: "u",
  χ: "x",
  ω: "w",
  ϲ: "c",
  // Armenian
  օ: "o",
  ո: "n",
  ս: "u",
  հ: "h",
  ց: "g",
  զ: "q",
};

/**
 * Latin letters that NFKC leaves alone but that only style or spoof plain
 * letters (small capitals, IPA look-alikes), plus stroked letters NFD does
 * not decompose. Always folded.
 */
const LATIN_FOLDS: Record<string, string> = {
  ı: "i",
  ȷ: "j",
  ɑ: "a",
  ɡ: "g",
  ɩ: "i",
  ʟ: "l",
  ɴ: "n",
  ʀ: "r",
  ɢ: "g",
  ʜ: "h",
  ɪ: "i",
  ʏ: "y",
  ʙ: "b",
  ᴀ: "a",
  ᴄ: "c",
  ᴅ: "d",
  ᴇ: "e",
  ғ: "f",
  ᴊ: "j",
  ᴋ: "k",
  ᴍ: "m",
  ᴏ: "o",
  ᴘ: "p",
  ǫ: "q",
  ꜱ: "s",
  ᴛ: "t",
  ᴜ: "u",
  ᴠ: "v",
  ᴡ: "w",
  ᴢ: "z",
  ł: "l",
  đ: "d",
  ø: "o",
  ħ: "h",
  ŧ: "t",
  ƚ: "l",
  ƀ: "b",
  ß: "ss",
  æ: "ae",
  œ: "oe",
};
const RE_LATIN_FOLDS = new RegExp(
  `[${Object.keys(LATIN_FOLDS).join("")}]`,
  "g"
);

/** Upside-down letters, mapped back. The text is also reversed. */
const UPSIDE_DOWN: Record<string, string> = {
  ɐ: "a",
  q: "b",
  ɔ: "c",
  p: "d",
  ǝ: "e",
  ɟ: "f",
  ƃ: "g",
  ɥ: "h",
  ᴉ: "i",
  ɾ: "j",
  ʞ: "k",
  ɯ: "m",
  u: "n",
  d: "p",
  b: "q",
  ɹ: "r",
  ʇ: "t",
  n: "u",
  ʌ: "v",
  ʍ: "w",
  ʎ: "y",
  "˙": ".",
  "¡": "!",
  "¿": "?",
  "'": ",",
  ",": "'",
};
const RE_UPSIDE_DOWN_MARKERS =
  /[\u0250\u0254\u01dd\u025f\u0183\u0265\u1d09\u027e\u029e\u026f\u0279\u0287\u028c\u028d\u028e]/g;

// --- Deobfuscation (ASCII, lowercase input) ---

// Four or more single characters separated by one or two separator
// characters: "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e". The character and
// separator sets are disjoint, so matching is linear.
const RE_SPACED_CHARS =
  /(^|[^a-z0-9])((?:[a-z0-9@$!][ .\-_*~+|/\\]{1,2}){3,}[a-z0-9@$!])(?![a-z0-9])/g;
const RE_SPACED_SEPARATORS = /[ .\-_*~+|/\\]/g;
// Punctuation used to split a word: "ig.no.re", "in-struc-tions", "sys*tem".
const RE_INTRAWORD_PUNCT = /([a-z])[.\-_*~`'|]+(?=[a-z])/g;

const LEET_SEQUENCES: [RegExp, string][] = [
  [/\|\\\|/g, "n"],
  [/\|_\|/g, "u"],
  [/\|v\|/g, "m"],
  [/\/\\\/\\/g, "m"],
  [/\|\\\/\|/g, "m"],
  [/\\\/\\\//g, "w"],
  [/\\\//g, "v"],
  [/\|<|\|\{/g, "k"],
  [/\|2/g, "r"],
  [/\|\)/g, "d"],
  [/\|=/g, "f"],
  [/\|\*/g, "p"],
  [/></g, "x"],
];

const LEET: Record<string, string> = {
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
  "|": "l",
  "€": "e",
};

const TYPOS: Record<string, string> = {
  ingnore: "ignore",
  ignor: "ignore",
  ignroe: "ignore",
  igonre: "ignore",
  ingore: "ignore",
  ignoer: "ignore",
  ignorr: "ignore",
  ignorre: "ignore",
  inore: "ignore",
  previus: "previous",
  previos: "previous",
  prevous: "previous",
  preivous: "previous",
  pervious: "previous",
  privious: "previous",
  instrucions: "instructions",
  instrucion: "instruction",
  instuctions: "instructions",
  instructons: "instructions",
  intructions: "instructions",
  insturctions: "instructions",
  instrctions: "instructions",
  instructinos: "instructions",
  overide: "override",
  overrride: "override",
  ovveride: "override",
  disreguard: "disregard",
  disrega: "disregard",
  disregrad: "disregard",
  dissregard: "disregard",
  forgett: "forget",
  foget: "forget",
  frogett: "forget",
  sytem: "system",
  sysem: "system",
  systme: "system",
  sistem: "system",
  promt: "prompt",
  prompet: "prompt",
  propmt: "prompt",
  pormpt: "prompt",
  rulez: "rules",
  rulz: "rules",
  jailbrake: "jailbreak",
  jailbrek: "jailbreak",
  restrictons: "restrictions",
  restricitons: "restrictions",
  guidlines: "guidelines",
  guidelnes: "guidelines",
  revael: "reveal",
  reveel: "reveal",
};

const PHONETICS: [RegExp, string][] = [
  [/^ignr$/, "ignore"],
  [/^pre+vious$/, "previous"],
  [/^instr(?:uk|ukk|ooc|ook)tions?$/, "instructions"],
  [/^in?stroo?[ck]?shuns?$/, "instructions"],
  [/^over+[yi]de?$/, "override"],
  [/^promt$/, "prompt"],
  [/^rulz$/, "rules"],
  [/^sistum$/, "system"],
];
const RE_PHONETIC_HINT =
  /^(?:ignr|pre+vious|instr(?:uk|ukk|ooc|ook)tions?|in?stroo?[ck]?shuns?|over+[yi]de?|promt|rulz|sistum)$/;

function decodeTags(input: string): { text: string; decoded: string[] } {
  const decoded: string[] = [];
  const text = input.replace(RE_TAG_RUN, (run: string, offset: number) => {
    // A tag sequence after U+1F3F4 is a subdivision flag, not a message.
    const isFlag =
      offset >= 2 &&
      input.charCodeAt(offset - 1) === 0xdf_f4 &&
      input.charCodeAt(offset - 2) === 0xd8_3c;
    if (!isFlag) {
      let ascii = "";
      for (let i = 1; i < run.length; i += 2) {
        const code = run.charCodeAt(i) - 0xdc_00;
        if (code >= 0x20 && code < 0x7f) {
          ascii += String.fromCharCode(code);
        }
      }
      if (ascii.trim()) {
        decoded.push(ascii);
      }
    }
    return "";
  });
  return { text, decoded };
}

let utf8Decoder: TextDecoder | undefined;

function decodeVariationSelectors(input: string): string[] {
  const decoded: string[] = [];
  RE_VS_RUN.lastIndex = 0;
  let run = RE_VS_RUN.exec(input);
  while (run) {
    const bytes: number[] = [];
    const s = run[0];
    for (let i = 0; i < s.length; i++) {
      const code = s.charCodeAt(i);
      if (code >= 0xfe_00 && code <= 0xfe_0f) {
        bytes.push(code - 0xfe_00);
      } else if (code === 0xdb_40) {
        bytes.push(s.charCodeAt(i + 1) - 0xdd_00 + 16);
        i++;
      }
    }
    utf8Decoder ??= new TextDecoder("utf-8", { fatal: false });
    const text = utf8Decoder.decode(new Uint8Array(bytes));
    if (text.trim()) {
      decoded.push(text);
    }
    run = RE_VS_RUN.exec(input);
  }
  return decoded;
}

function countMatches(re: RegExp, input: string): number {
  re.lastIndex = 0;
  let count = 0;
  while (re.exec(input)) {
    count++;
  }
  return count;
}

function foldMixedScriptWords(
  input: string,
  signals: ObfuscationSignals
): string {
  if (!RE_CONFUSABLE_SCRIPT.test(input)) {
    return input;
  }
  return input.replace(RE_WORD, (word: string) => {
    if (!(RE_LATIN_LETTER.test(word) && RE_CONFUSABLE_SCRIPT.test(word))) {
      return word;
    }
    signals.mixedScriptWords++;
    let folded = "";
    for (const ch of word) {
      folded += CONFUSABLES[ch] ?? ch;
    }
    return folded;
  });
}

function collapseWhitespace(input: string): string {
  return input.replace(RE_WS_RUN, " ").replace(RE_NEWLINE_RUN, "\n").trim();
}

/** Undo the Unicode-level tricks: returns NFKC, lowercase, de-accented text. */
function normalizeUnicode(
  input: string,
  config: ResolvedDetectNormalizationOptions,
  signals: ObfuscationSignals,
  hidden: HiddenText[]
): string {
  let text = input;
  if (!RE_NON_ASCII.test(text)) {
    text = text.toLowerCase();
    return config.collapseWhitespace ? collapseWhitespace(text) : text;
  }

  if (config.stripInvisible) {
    signals.unicodeTags = countMatches(RE_TAG_ANY, text);
    if (signals.unicodeTags > 0) {
      const tags = decodeTags(text);
      text = tags.text;
      for (const decoded of tags.decoded) {
        hidden.push({ encoding: "unicode_tags", text: decoded });
      }
    }
    signals.variationSelectors = countMatches(RE_VS_ANY, text);
    if (signals.variationSelectors >= 4) {
      for (const decoded of decodeVariationSelectors(text)) {
        hidden.push({ encoding: "variation_selectors", text: decoded });
      }
    }
    text = text.replace(RE_VS_ANY, "");
    signals.bidi = countMatches(RE_BIDI_OVERRIDE, text);
    signals.invisible = countMatches(RE_INVISIBLE, text);
    signals.invisibleInWords = countMatches(RE_INVISIBLE_IN_WORD, text);
    text = text.replace(RE_BIDI, "").replace(RE_INVISIBLE, "");
  }

  const decomposed = text.normalize("NFKC").toLowerCase().normalize("NFD");
  signals.stackedMarks = countMatches(RE_STACKED_MARKS, decomposed);
  text = decomposed.replace(RE_COMBINING, "").normalize("NFC");

  if (config.foldHomoglyphs) {
    text = text.replace(RE_LATIN_FOLDS, (ch: string) => LATIN_FOLDS[ch] ?? ch);
    text = foldMixedScriptWords(text, signals);
  }
  return config.collapseWhitespace ? collapseWhitespace(text) : text;
}

function isLeetTokenChar(c: number): boolean {
  return (
    (c >= 97 && c <= 122) ||
    (c >= 48 && c <= 57) ||
    c === 64 || // @
    c === 36 || // $
    c === 33 || // !
    c === 124 || // |
    c === 0x20_ac // euro sign
  );
}

// Leet characters by char code, for tokens that mix them with letters.
const LEET_BY_CODE = new Map<number, string>(
  Object.entries(LEET).map(([ch, letter]) => [ch.charCodeAt(0), letter])
);

function decodeLeetToken(token: string, one: string): string {
  let out = "";
  for (let i = 0; i < token.length; i++) {
    const c = token.charCodeAt(i);
    out += c === 49 ? one : (LEET_BY_CODE.get(c) ?? token[i]);
  }
  return out;
}

// Multi-character leet letters such as `|\|` for n or `\/\/` for w. These
// span characters that end a token, so they're decoded across the whole text
// before tokens are.
const RE_LEET_SEQUENCE_TEXT_HINT = /\|[\\_v<{2)=*]|\/\\|\\\/|></;

function decodeLeetSequences(text: string): string {
  if (!RE_LEET_SEQUENCE_TEXT_HINT.test(text)) {
    return text;
  }
  let out = text;
  for (const [re, replacement] of LEET_SEQUENCES) {
    out = out.replace(re, replacement);
  }
  return out;
}

// Gates for each deobfuscation step, so text that needs none of them skips
// the work.
const RE_SPACED_HINT =
  /[a-z0-9@$!][ .\-_*~+|/\\]{1,2}[a-z0-9@$!][ .\-_*~+|/\\]{1,2}[a-z0-9@$!][ .\-_*~+|/\\]{1,2}[a-z0-9@$!](?![a-z0-9])/;
const RE_INTRAWORD_HINT = /[a-z][.\-_*~`'|]+[a-z]/;

const RE_DOUBLE_SPACE = / {2,}/g;

/** Typo and phonetic spellings of words attacks rely on, fixed word by word. */
function repairWord(
  word: string,
  config: ResolvedDetectNormalizationOptions
): string {
  if (config.repairTypos) {
    const fixed = TYPOS[word];
    if (fixed) {
      return fixed;
    }
  }
  if (
    config.repairPhonetics &&
    word.length >= 4 &&
    word.length <= 14 &&
    RE_PHONETIC_HINT.test(word)
  ) {
    for (const [re, replacement] of PHONETICS) {
      if (re.test(word)) {
        return replacement;
      }
    }
  }
  return word;
}

function isAsciiLetter(c: number): boolean {
  return c >= 97 && c <= 122;
}

// First two letters of every word `repairWord` can change, packed as
// `a * 32 + b` over letter codes 0-25, so words that can't need a repair are
// skipped without slicing them out of the text.
const REPAIR_PREFIXES = new Uint8Array(32 * 32);
for (const word of [
  ...Object.keys(TYPOS),
  "ignr",
  "preevious",
  "instruk",
  "istro",
  "overyde",
  "promt",
  "rulz",
  "sistum",
]) {
  REPAIR_PREFIXES[(word.charCodeAt(0) - 97) * 32 + (word.charCodeAt(1) - 97)] =
    1;
}

function mayNeedRepair(text: string, start: number): boolean {
  const a = text.charCodeAt(start) - 97;
  const b = text.charCodeAt(start + 1) - 97;
  return (
    a >= 0 && a < 26 && b >= 0 && b < 26 && REPAIR_PREFIXES[a * 32 + b] === 1
  );
}

interface Repaired {
  text: string;
  /** The same text with `1` read as `l` instead of `i`, if that differs. */
  alt?: string;
}

/**
 * One pass over the tokens of `text`: decodes leetspeak in tokens that mix
 * letters with leet characters, then repairs typos and phonetic spellings.
 * Tokens with a `1` are also decoded with `1` as `l`, into `alt`.
 */
// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one pass over the text on a hot path; splitting it would scan tokens twice.
function repairTokens(
  text: string,
  config: ResolvedDetectNormalizationOptions
): Repaired {
  const repair = config.repairTypos || config.repairPhonetics;
  let out = "";
  let alt = "";
  let hasAlt = false;
  let last = 0;
  let i = 0;
  while (i < text.length) {
    if (!isLeetTokenChar(text.charCodeAt(i))) {
      i++;
      continue;
    }
    const start = i;
    let letters = false;
    let leet = false;
    let one = false;
    while (i < text.length && isLeetTokenChar(text.charCodeAt(i))) {
      const c = text.charCodeAt(i);
      if (isAsciiLetter(c)) {
        letters = true;
      } else if (c === 49) {
        leet = true;
        one = true;
      } else if (c !== 50) {
        leet = true;
      }
      i++;
    }
    const decodeLeet = leet && config.decodeLeetspeak;
    const candidate =
      letters &&
      i - start >= 3 &&
      (decodeLeet || (repair && mayNeedRepair(text, start)));
    if (!candidate) {
      continue;
    }
    const token = text.slice(start, i);
    let fixed = decodeLeet ? decodeLeetToken(token, "i") : token;
    let fixedAlt = decodeLeet && one ? decodeLeetToken(token, "l") : fixed;
    if (repair) {
      fixed = repairWord(fixed, config);
      fixedAlt = fixedAlt === fixed ? fixed : repairWord(fixedAlt, config);
    }
    if (fixed !== token || fixedAlt !== token) {
      const between = text.slice(last, start);
      out += between + fixed;
      alt += between + fixedAlt;
      hasAlt ||= fixedAlt !== fixed;
      last = i;
    }
  }
  if (last === 0) {
    return { text };
  }
  const tail = text.slice(last);
  return { text: out + tail, alt: hasAlt ? alt + tail : undefined };
}

interface Deobfuscated {
  text: string;
  alt?: string;
}

function deobfuscate(
  text: string,
  config: ResolvedDetectNormalizationOptions
): Deobfuscated {
  let out = text;
  let joined = false;
  if (config.joinSeparatedLetters) {
    if (RE_SPACED_HINT.test(out)) {
      out = out.replace(
        RE_SPACED_CHARS,
        (run: string, before: string, chars: string) => {
          const letters = chars.replace(RE_SPACED_SEPARATORS, "");
          let count = 0;
          for (let i = 0; i < letters.length; i++) {
            if (isAsciiLetter(letters.charCodeAt(i))) {
              count++;
            }
          }
          if (count < 3) {
            return run;
          }
          joined = true;
          return `${before} ${letters} `;
        }
      );
    }
    if (RE_INTRAWORD_HINT.test(out)) {
      out = out.replace(RE_INTRAWORD_PUNCT, "$1");
    }
  }
  if (config.decodeLeetspeak) {
    out = decodeLeetSequences(out);
  }
  const repaired = repairTokens(out, config);
  const tidy = (s: string) =>
    joined ? s.replace(RE_DOUBLE_SPACE, " ").trim() : s;
  return {
    text: tidy(repaired.text),
    alt: repaired.alt === undefined ? undefined : tidy(repaired.alt),
  };
}

/** Maps upside-down text back and reverses it, or returns undefined. */
export function unflipText(text: string): string | undefined {
  const markers = new Set(text.match(RE_UPSIDE_DOWN_MARKERS) ?? []);
  if (markers.size < 3) {
    return;
  }
  let out = "";
  for (const ch of text) {
    out = (UPSIDE_DOWN[ch] ?? ch) + out;
  }
  return out;
}

function emptySignals(): ObfuscationSignals {
  return {
    unicodeTags: 0,
    variationSelectors: 0,
    invisible: 0,
    invisibleInWords: 0,
    bidi: 0,
    mixedScriptWords: 0,
    stackedMarks: 0,
  };
}

/** Builds the normalized views that detection rules and the classifier read. */
export function buildViews(
  input: string,
  options?: false | DetectNormalizationOptions
): NormalizedViews {
  const config = resolveDetectNormalization(options);
  const signals = emptySignals();
  if (!config.enabled) {
    const text = input.toLowerCase();
    return { text, deobfuscated: text, hidden: [], signals };
  }

  const hidden: HiddenText[] = [];
  const text = normalizeUnicode(input, config, signals, hidden);
  const anyDeobfuscation =
    config.joinSeparatedLetters ||
    config.decodeLeetspeak ||
    config.repairTypos ||
    config.repairPhonetics;
  if (!anyDeobfuscation) {
    return { text, deobfuscated: text, hidden, signals };
  }
  const { text: deobfuscated, alt: deobfuscatedAlt } = deobfuscate(
    text,
    config
  );
  return {
    text,
    deobfuscated,
    deobfuscatedAlt,
    hidden,
    signals,
  };
}

/**
 * The fully normalized form of `input` that detection matches against:
 * Unicode-normalized, lowercased, and deobfuscated.
 */
export function normalizeForDetection(
  input: string,
  options?: false | DetectNormalizationOptions
): string {
  const config = resolveDetectNormalization(options);
  if (!config.enabled) {
    return input.trim();
  }
  const views = buildViews(input, options);
  return config.normalizeCase ? views.deobfuscated : views.deobfuscated.trim();
}
