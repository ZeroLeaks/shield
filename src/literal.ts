const RE_LITERAL_CHAR = /[a-z0-9]/;
const MIN_LITERAL = 3;

/** Literals of which at least one appears in every match. */
type Requirement = string[];

/** Prefers the requirement whose shortest literal is longest, then the smallest set. */
function better(a: Requirement | undefined, b: Requirement): boolean {
  if (!a) {
    return true;
  }
  const minA = Math.min(...a.map((s) => s.length));
  const minB = Math.min(...b.map((s) => s.length));
  return minB > minA || (minB === minA && b.length < a.length);
}

/** Index just past the group that opens at `start`. */
function groupEnd(src: string, start: number): number {
  let depth = 0;
  for (let i = start; i < src.length; i++) {
    const ch = src[i];
    if (ch === "\\") {
      i++;
    } else if (ch === "[") {
      i++;
      while (i < src.length && src[i] !== "]") {
        if (src[i] === "\\") {
          i++;
        }
        i++;
      }
    } else if (ch === "(") {
      depth++;
    } else if (ch === ")") {
      depth--;
      if (depth === 0) {
        return i + 1;
      }
    }
  }
  return src.length;
}

/** Whether the item ending at `i` is followed by a quantifier allowing zero. */
function optionalAt(src: string, i: number): boolean {
  const ch = src[i];
  return ch === "?" || ch === "*" || (ch === "{" && src[i + 1] === "0");
}

function isQuantifier(ch: string | undefined): boolean {
  return ch === "?" || ch === "*" || ch === "+" || ch === "{";
}

/** Skips a quantifier (and its lazy `?`) starting at `i`. */
function skipQuantifier(src: string, i: number): number {
  let j = i;
  if (src[j] === "{") {
    while (j < src.length && src[j] !== "}") {
      j++;
    }
  }
  j++;
  if (src[j] === "?") {
    j++;
  }
  return j;
}

/** Splits `src` at its top-level `|`. */
function branches(src: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === "\\") {
      i++;
    } else if (ch === "[") {
      i++;
      while (i < src.length && src[i] !== "]") {
        if (src[i] === "\\") {
          i++;
        }
        i++;
      }
    } else if (ch === "(") {
      i = groupEnd(src, i) - 1;
    } else if (ch === "|") {
      out.push(src.slice(start, i));
      start = i + 1;
    }
  }
  out.push(src.slice(start));
  return out;
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: a small parser for regex source; each branch is one token kind.
function branchRequirement(
  src: string,
  ignoreCase: boolean
): Requirement | undefined {
  let best: Requirement | undefined;
  let run = "";
  const consider = (req: Requirement | undefined) => {
    if (req && better(best, req)) {
      best = req;
    }
  };
  const endRun = () => {
    if (run.length >= MIN_LITERAL) {
      consider([run]);
    }
    run = "";
  };

  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === "\\") {
      endRun();
      i += 2;
      if (isQuantifier(src[i])) {
        i = skipQuantifier(src, i);
      }
      continue;
    }
    if (ch === "[") {
      endRun();
      i++;
      while (i < src.length && src[i] !== "]") {
        if (src[i] === "\\") {
          i++;
        }
        i++;
      }
      i++;
      if (isQuantifier(src[i])) {
        i = skipQuantifier(src, i);
      }
      continue;
    }
    if (ch === "(") {
      endRun();
      const end = groupEnd(src, i);
      const optional = optionalAt(src, end);
      const lookaround =
        src.startsWith("(?=", i) ||
        src.startsWith("(?!", i) ||
        src.startsWith("(?<=", i) ||
        src.startsWith("(?<!", i);
      if (!(optional || lookaround)) {
        let inner = src.slice(i + 1, end - 1);
        if (inner.startsWith("?:")) {
          inner = inner.slice(2);
        } else if (inner.startsWith("?<")) {
          inner = inner.slice(inner.indexOf(">") + 1);
        }
        consider(requirement(inner, ignoreCase));
      }
      i = end;
      if (isQuantifier(src[i])) {
        i = skipQuantifier(src, i);
      }
      continue;
    }
    if (optionalAt(src, i)) {
      // The quantifier makes the preceding character optional.
      run = run.slice(0, -1);
      endRun();
      i = skipQuantifier(src, i);
      continue;
    }
    if (ch === "+" || ch === "{") {
      endRun();
      i = skipQuantifier(src, i);
      continue;
    }
    const lower = ignoreCase ? ch.toLowerCase() : ch;
    if (RE_LITERAL_CHAR.test(lower)) {
      run += lower;
    } else {
      endRun();
    }
    i++;
  }
  endRun();
  return best;
}

function requirement(
  src: string,
  ignoreCase: boolean
): Requirement | undefined {
  const parts = branches(src);
  const union: string[] = [];
  for (const part of parts) {
    const req = branchRequirement(part, ignoreCase);
    if (!req) {
      return;
    }
    union.push(...req);
  }
  return [...new Set(union)];
}

/**
 * Literals of which every match of `re` contains at least one, or undefined
 * if the pattern can match without any literal of three or more letters or
 * digits. Used to skip patterns that can't match a text.
 */
export function requiredLiterals(re: RegExp): string[] | undefined {
  return requirement(re.source, re.flags.includes("i"));
}

/** The single literal every match of `re` contains, if there is one. */
export function requiredLiteral(re: RegExp): string | undefined {
  const req = requiredLiterals(re);
  return req?.length === 1 ? req[0] : undefined;
}
