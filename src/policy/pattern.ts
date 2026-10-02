/**
 * JSON Schema `pattern` without ReDoS. A backtracking regex engine can take
 * time exponential in the input for some patterns, and polynomial for many
 * more, and tool arguments are written by a model that may be following an
 * attacker. So a pattern is first read, without running it, for the shapes
 * that backtrack:
 *
 * - A backreference, or a repeated group that holds a quantifier or an
 *   alternation, such as `(a+)+` or `(a|ab)*`, can take exponential time.
 *   These patterns are not run at all.
 * - Every other pattern's work grows at most with the length of the string
 *   to the power of its unbounded quantifiers (`*`, `+`, `{n,}`, or a range
 *   wider than 16), plus one when it is not anchored with a leading `^`. The
 *   pattern is run only on strings short enough to keep that under 2^20, and
 *   a longer string fails the check.
 */

import { lastItem } from "../output/util";

/** The most backtracking one pattern test may do, as length ** degree. */
export const PATTERN_WORK = 2 ** 20;
/** A bounded quantifier whose range is wider than this counts as unbounded. */
const WIDE_RANGE = 16;
const MAX_PLANS = 256;
const RE_BRACE_QUANTIFIER = /^\{(\d{1,9})(,(\d{0,9}))?\}/;

export interface PatternPlan {
  regex: RegExp;
  /** The longest string the pattern is run on. A longer one fails. */
  maxLength: number;
  /** How the work grows with the length: at most length ** degree. */
  degree: number;
}

interface Quantifier {
  length: number;
  /** Whether it can match its atom more than once. */
  repeats: boolean;
  unbounded: boolean;
}

interface Frame {
  quantified: boolean;
  unbounded: boolean;
  alternation: boolean;
}

interface Shape {
  safe: boolean;
  /** Unbounded quantifiers. */
  unbounded: number;
  /** Whether the pattern starts with `^` and has no top-level `|`. */
  anchored: boolean;
}

function quantifierAt(pattern: string, i: number): Quantifier | null {
  const c = pattern[i];
  let q: Quantifier | null = null;
  if (c === "*" || c === "+") {
    q = { length: 1, repeats: true, unbounded: true };
  } else if (c === "?") {
    q = { length: 1, repeats: false, unbounded: false };
  } else if (c === "{") {
    const m = RE_BRACE_QUANTIFIER.exec(pattern.slice(i, i + 24));
    if (m) {
      const min = Number(m[1]);
      let max = min;
      if (m[2] !== undefined) {
        max = m[3] === "" ? Number.POSITIVE_INFINITY : Number(m[3]);
      }
      q = {
        length: m[0].length,
        repeats: max >= 2,
        unbounded: max - min > WIDE_RANGE,
      };
    }
  }
  if (q && pattern[i + q.length] === "?") {
    q.length += 1;
  }
  return q;
}

/** Index after the character class that starts at `i`. */
function skipClass(pattern: string, i: number): number {
  let j = i + 1;
  if (pattern[j] === "^") {
    j += 1;
  }
  while (j < pattern.length && pattern[j] !== "]") {
    j += pattern[j] === "\\" ? 2 : 1;
  }
  return j + 1;
}

/** Length of a group's opening: `(`, `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!`, or `(?<name>`. */
function groupOpening(pattern: string, i: number): number {
  if (pattern[i + 1] !== "?") {
    return 1;
  }
  const kind = pattern[i + 2];
  if (kind === ":" || kind === "=" || kind === "!") {
    return 3;
  }
  if (kind === "<") {
    const next = pattern[i + 3];
    if (next === "=" || next === "!") {
      return 4;
    }
    const close = pattern.indexOf(">", i);
    return close === -1 ? pattern.length - i : close - i + 1;
  }
  return 2;
}

function isBackreference(pattern: string, i: number): boolean {
  const next = pattern[i + 1];
  return (next >= "1" && next <= "9") || next === "k";
}

/** Where `shapeOf` is in a pattern, and what it has found so far. */
interface Scan {
  pattern: string;
  i: number;
  /** Open groups, innermost last, above the pattern itself. */
  stack: Frame[];
  unbounded: number;
  topAlternation: boolean;
}

function newFrame(): Frame {
  return { quantified: false, unbounded: false, alternation: false };
}

function top(scan: Scan): Frame {
  return lastItem(scan.stack) as Frame;
}

/**
 * Applies the quantifier at the scan's position, if any, to the atom before
 * it: `group` when that atom is a group. `false` when a repeated group could
 * match the same text in more than one way.
 */
function quantify(scan: Scan, group?: Frame): boolean {
  const q = quantifierAt(scan.pattern, scan.i);
  if (!q) {
    return true;
  }
  scan.i += q.length;
  const frame = top(scan);
  frame.quantified = true;
  if (q.unbounded) {
    scan.unbounded += 1;
    frame.unbounded = true;
  }
  if (!(group && q.repeats)) {
    return true;
  }
  if (q.unbounded) {
    return !(group.quantified || group.alternation);
  }
  return !group.unbounded;
}

function closeGroup(scan: Scan): boolean {
  const group = scan.stack.pop() as Frame;
  if (scan.stack.length === 0) {
    return false;
  }
  scan.i += 1;
  const parent = top(scan);
  parent.quantified ||= group.quantified;
  parent.unbounded ||= group.unbounded;
  parent.alternation ||= group.alternation;
  return quantify(scan, group);
}

/** Reads the token at the scan's position. `false` when the pattern is unsafe. */
function step(scan: Scan): boolean {
  const { pattern, i } = scan;
  switch (pattern[i]) {
    case "\\":
      if (isBackreference(pattern, i)) {
        return false;
      }
      scan.i += 2;
      return quantify(scan);
    case "[":
      scan.i = skipClass(pattern, i);
      return quantify(scan);
    case "(":
      scan.stack.push(newFrame());
      scan.i += groupOpening(pattern, i);
      return true;
    case ")":
      return closeGroup(scan);
    case "|":
      top(scan).alternation = true;
      scan.topAlternation ||= scan.stack.length === 1;
      scan.i += 1;
      return true;
    default:
      scan.i += 1;
      return quantify(scan);
  }
}

/** Reads a pattern's shape without running it. */
function shapeOf(pattern: string): Shape {
  const scan: Scan = {
    pattern,
    i: 0,
    stack: [newFrame()],
    unbounded: 0,
    topAlternation: false,
  };
  while (scan.i < pattern.length) {
    if (!step(scan)) {
      return { safe: false, unbounded: 0, anchored: false };
    }
  }
  return {
    safe: scan.stack.length === 1,
    unbounded: scan.unbounded,
    anchored: pattern.startsWith("^") && !scan.topAlternation,
  };
}

function compile(pattern: string): RegExp | null {
  try {
    return new RegExp(pattern, "u");
  } catch {
    // Patterns written for the non-Unicode syntax, such as `\-` outside a class.
  }
  try {
    return new RegExp(pattern);
  } catch {
    return null;
  }
}

const plans = new Map<string, PatternPlan | null>();

/**
 * How to run `pattern`, or `null` when it is not run: it isn't a valid
 * regex, or it can backtrack exponentially.
 */
export function planPattern(pattern: string): PatternPlan | null {
  const cached = plans.get(pattern);
  if (cached !== undefined) {
    return cached;
  }
  const shape = shapeOf(pattern);
  const regex = shape.safe ? compile(pattern) : null;
  let plan: PatternPlan | null = null;
  if (regex) {
    const degree = shape.unbounded + (shape.anchored ? 0 : 1);
    plan = {
      regex,
      degree,
      maxLength: Math.floor(PATTERN_WORK ** (1 / Math.max(degree, 1))),
    };
  }
  if (plans.size >= MAX_PLANS) {
    plans.clear();
  }
  plans.set(pattern, plan);
  return plan;
}
