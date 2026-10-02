/**
 * A focused JSON Schema validator for tool call arguments. It knows `type`
 * (with OpenAPI's `nullable`), `required`, `properties`,
 * `additionalProperties`, `items`, `minItems`, `maxItems`, `enum`, `const`,
 * `minLength`, `maxLength`, `pattern`, `minimum`, `maximum`,
 * `exclusiveMinimum`, `exclusiveMaximum`, `anyOf`, `oneOf`, `allOf`, `not`,
 * and `$ref` to a JSON pointer in the same schema, such as `#/$defs/name`.
 * Every other keyword is ignored.
 *
 * Schemas can come from an MCP server, so validation is bounded: `$ref` is
 * followed at most 32 deep, arguments are read at most 64 levels deep, one
 * validation takes at most 100,000 steps, and patterns are run as
 * `planPattern()` allows. Violations say where and which keyword, never the
 * value.
 */

import { PATTERN_WORK, planPattern } from "./pattern";

export interface SchemaViolation {
  /**
   * Where in the arguments: `$` is the arguments themselves, `$.to` a
   * property, `$.items[0]` an array item. A key the schema doesn't declare
   * comes from the arguments, so it is written as `*`.
   */
  path: string;
  /** The keyword that failed, such as `type` or `required`. */
  keyword: string;
  /** What is wrong, without the value. */
  message: string;
}

const MAX_STEPS = 100_000;
const MAX_DEPTH = 64;
const MAX_REF_DEPTH = 32;
const MAX_KEY_IN_PATH = 64;
/** Pattern work, as length ** degree, that counts as one step. */
const PATTERN_WORK_PER_STEP = 1024;
const RE_IDENTIFIER = /^[A-Za-z_$][\w$]*$/;
const RE_INDEX = /^(0|[1-9]\d*)$/;
const RE_POINTER_SLASH = /~1/g;
const RE_POINTER_TILDE = /~0/g;

type JsonRecord = Record<string, unknown>;

interface Run {
  root: unknown;
  budget: { steps: number; exhausted: boolean };
  /** Violations found so far, or `null` in a quiet run, which only needs to know whether the value is valid. */
  out: SchemaViolation[] | null;
  max: number;
}

function asRecord(value: unknown): JsonRecord | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function hasOwn(record: object, key: string): boolean {
  return Object.getOwnPropertyDescriptor(record, key) !== undefined;
}

function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function propertyPath(path: string, key: string): string {
  const shown =
    key.length > MAX_KEY_IN_PATH ? `${key.slice(0, MAX_KEY_IN_PATH)}...` : key;
  return RE_IDENTIFIER.test(shown)
    ? `${path}.${shown}`
    : `${path}[${JSON.stringify(shown)}]`;
}

/** Stops collecting once `max` violations were found. */
function full(run: Run): boolean {
  return run.out === null || run.out.length >= run.max;
}

function report(
  run: Run,
  path: string,
  keyword: string,
  message: string
): void {
  if (full(run) || !run.out) {
    return;
  }
  const seen = run.out.some((v) => v.path === path && v.keyword === keyword);
  if (!seen) {
    run.out.push({ path, keyword, message });
  }
}

/** Counts `steps` against the budget, and says whether it is spent. */
function spend(run: Run, steps = 1): boolean {
  run.budget.steps += steps;
  if (run.budget.steps > MAX_STEPS) {
    run.budget.exhausted = true;
  }
  return run.budget.exhausted;
}

/** Code points, which JSON Schema lengths count, rather than UTF-16 units. */
function codePoints(text: string): number {
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd8_00 && unit <= 0xdb_ff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc_00 && next <= 0xdf_ff) {
        i += 1;
      }
    }
    count += 1;
  }
  return count;
}

function jsonEqual(a: unknown, b: unknown, depth = 0): boolean {
  if (a === b) {
    return true;
  }
  if (depth > MAX_DEPTH || typeof a !== "object" || typeof b !== "object") {
    return false;
  }
  if (a === null || b === null || Array.isArray(a) !== Array.isArray(b)) {
    return false;
  }
  if (Array.isArray(a)) {
    const other = b as unknown[];
    return (
      a.length === other.length &&
      a.every((item, i) => jsonEqual(item, other[i], depth + 1))
    );
  }
  const left = a as JsonRecord;
  const right = b as JsonRecord;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every(
      (key) => hasOwn(right, key) && jsonEqual(left[key], right[key], depth + 1)
    )
  );
}

/** Whether `value` has JSON type `type`, or `undefined` for a type name this validator doesn't know. */
function hasType(value: unknown, type: string): boolean | undefined {
  switch (type.toLowerCase()) {
    case "null":
      return value === null;
    case "boolean":
      return typeof value === "boolean";
    case "string":
      return typeof value === "string";
    case "number":
      return isNumber(value);
    case "integer":
      return isNumber(value) && Number.isInteger(value);
    case "array":
      return Array.isArray(value);
    case "object":
      return asRecord(value) !== undefined;
    default:
      return;
  }
}

/** The type names `value` doesn't match, or `null` when it matches or the keyword doesn't apply. */
function typeMismatch(schema: JsonRecord, value: unknown): string[] | null {
  let types: string[] = [];
  if (typeof schema.type === "string") {
    types = [schema.type];
  } else if (Array.isArray(schema.type)) {
    types = schema.type.filter((t): t is string => typeof t === "string");
  }
  let known = false;
  for (const type of types) {
    const match = hasType(value, type);
    if (match) {
      return null;
    }
    known ||= match === false;
  }
  if (!known || (value === null && schema.nullable === true)) {
    return null;
  }
  return types.map((t) => t.toLowerCase());
}

/** The schema a local JSON pointer (`#`, `#/$defs/name`) points to, or `undefined`. */
function resolveRef(root: unknown, ref: string): unknown {
  if (!ref.startsWith("#")) {
    return;
  }
  let pointer: string;
  try {
    pointer = decodeURIComponent(ref.slice(1));
  } catch {
    return;
  }
  if (pointer === "") {
    return root;
  }
  if (!pointer.startsWith("/")) {
    return;
  }
  let node: unknown = root;
  for (const raw of pointer.slice(1).split("/")) {
    const key = raw
      .replace(RE_POINTER_SLASH, "/")
      .replace(RE_POINTER_TILDE, "~");
    if (Array.isArray(node)) {
      node = RE_INDEX.test(key) ? node[Number(key)] : undefined;
    } else {
      const record = asRecord(node);
      node = record && hasOwn(record, key) ? record[key] : undefined;
    }
    if (node === undefined) {
      return;
    }
  }
  return node;
}

function checkString(
  run: Run,
  schema: JsonRecord,
  value: string,
  path: string
): boolean {
  let valid = true;
  const needsLength = isNumber(schema.minLength) || isNumber(schema.maxLength);
  const length = needsLength ? codePoints(value) : 0;
  if (isNumber(schema.minLength) && length < schema.minLength) {
    valid = false;
    report(
      run,
      path,
      "minLength",
      `must be at least ${schema.minLength} characters`
    );
  }
  if (isNumber(schema.maxLength) && length > schema.maxLength) {
    valid = false;
    report(
      run,
      path,
      "maxLength",
      `must be at most ${schema.maxLength} characters`
    );
  }
  if (typeof schema.pattern === "string") {
    valid = checkPattern(run, schema.pattern, value, path) && valid;
  }
  return valid;
}

function checkPattern(
  run: Run,
  pattern: string,
  value: string,
  path: string
): boolean {
  const plan = planPattern(pattern);
  if (!plan) {
    return true;
  }
  if (value.length > plan.maxLength) {
    report(
      run,
      path,
      "pattern",
      `is too long to check against its pattern (over ${plan.maxLength} characters)`
    );
    return false;
  }
  const work = Math.min(value.length ** Math.max(plan.degree, 1), PATTERN_WORK);
  if (spend(run, Math.ceil(work / PATTERN_WORK_PER_STEP))) {
    return false;
  }
  if (plan.regex.test(value)) {
    return true;
  }
  report(run, path, "pattern", "must match the pattern");
  return false;
}

/** The `minimum` and `exclusiveMinimum` that `value` is below, as keyword and message. */
function belowMinimum(schema: JsonRecord, value: number): [string, string][] {
  const out: [string, string][] = [];
  const { minimum, exclusiveMinimum } = schema;
  if (isNumber(minimum)) {
    const exclusive = exclusiveMinimum === true;
    if (exclusive ? value <= minimum : value < minimum) {
      out.push(["minimum", `must be ${exclusive ? ">" : ">="} ${minimum}`]);
    }
  }
  if (isNumber(exclusiveMinimum) && value <= exclusiveMinimum) {
    out.push(["exclusiveMinimum", `must be > ${exclusiveMinimum}`]);
  }
  return out;
}

/** The `maximum` and `exclusiveMaximum` that `value` is above, as keyword and message. */
function aboveMaximum(schema: JsonRecord, value: number): [string, string][] {
  const out: [string, string][] = [];
  const { maximum, exclusiveMaximum } = schema;
  if (isNumber(maximum)) {
    const exclusive = exclusiveMaximum === true;
    if (exclusive ? value >= maximum : value > maximum) {
      out.push(["maximum", `must be ${exclusive ? "<" : "<="} ${maximum}`]);
    }
  }
  if (isNumber(exclusiveMaximum) && value >= exclusiveMaximum) {
    out.push(["exclusiveMaximum", `must be < ${exclusiveMaximum}`]);
  }
  return out;
}

function checkNumber(
  run: Run,
  schema: JsonRecord,
  value: number,
  path: string
): boolean {
  const failed = [
    ...belowMinimum(schema, value),
    ...aboveMaximum(schema, value),
  ];
  for (const [keyword, message] of failed) {
    report(run, path, keyword, message);
  }
  return failed.length === 0;
}

function checkArray(
  run: Run,
  schema: JsonRecord,
  value: unknown[],
  path: string,
  depth: number,
  refs: number
): boolean {
  let valid = true;
  if (isNumber(schema.minItems) && value.length < schema.minItems) {
    valid = false;
    report(
      run,
      path,
      "minItems",
      `must have at least ${schema.minItems} items`
    );
  }
  if (isNumber(schema.maxItems) && value.length > schema.maxItems) {
    valid = false;
    report(run, path, "maxItems", `must have at most ${schema.maxItems} items`);
  }
  const { items } = schema;
  if (items === undefined) {
    return valid;
  }
  for (const [i, item] of value.entries()) {
    const itemSchema = Array.isArray(items) ? items[i] : items;
    if (itemSchema === undefined) {
      break;
    }
    valid =
      check(run, itemSchema, item, `${path}[${i}]`, depth + 1, refs) && valid;
    if (full(run) && !valid) {
      return false;
    }
  }
  return valid;
}

function checkRequired(
  run: Run,
  schema: JsonRecord,
  value: JsonRecord,
  path: string
): boolean {
  if (!Array.isArray(schema.required)) {
    return true;
  }
  let valid = true;
  for (const name of schema.required) {
    const present = hasOwn(value, name) && value[name] !== undefined;
    if (typeof name === "string" && !present) {
      valid = false;
      report(run, propertyPath(path, name), "required", "is required");
    }
  }
  return valid;
}

/** Checks one property against `properties` or `additionalProperties`. */
function checkProperty(
  run: Run,
  schema: JsonRecord,
  value: JsonRecord,
  key: string,
  path: string,
  depth: number,
  refs: number
): boolean {
  const properties = asRecord(schema.properties) ?? {};
  if (hasOwn(properties, key)) {
    const at = propertyPath(path, key);
    return check(run, properties[key], value[key], at, depth + 1, refs);
  }
  // Without patternProperties, which this validator doesn't read, it can't
  // tell which keys are additional.
  const additional =
    schema.patternProperties === undefined
      ? schema.additionalProperties
      : undefined;
  if (additional === false) {
    report(run, `${path}.*`, "additionalProperties", "is not allowed");
    return false;
  }
  if (additional === undefined || additional === true) {
    return true;
  }
  return check(run, additional, value[key], `${path}.*`, depth + 1, refs);
}

function checkObject(
  run: Run,
  schema: JsonRecord,
  value: JsonRecord,
  path: string,
  depth: number,
  refs: number
): boolean {
  let valid = checkRequired(run, schema, value, path);
  for (const key of Object.keys(value)) {
    if (value[key] === undefined) {
      continue;
    }
    valid = checkProperty(run, schema, value, key, path, depth, refs) && valid;
    if (full(run) && !valid) {
      return false;
    }
  }
  return valid;
}

/** Runs `check` without reporting, sharing the budget. */
function matches(
  run: Run,
  schema: unknown,
  value: unknown,
  depth: number,
  refs: number
): boolean {
  return check({ ...run, out: null }, schema, value, "$", depth, refs);
}

/** How many of `schemas` `value` matches, counting no further than `limit`. */
function countMatches(
  run: Run,
  schemas: unknown[],
  value: unknown,
  depth: number,
  refs: number,
  limit: number
): number {
  let count = 0;
  for (const schema of schemas) {
    if (count >= limit) {
      break;
    }
    if (matches(run, schema, value, depth, refs)) {
      count += 1;
    }
  }
  return count;
}

function checkAllOf(
  run: Run,
  schemas: unknown[],
  value: unknown,
  path: string,
  depth: number,
  refs: number
): boolean {
  let valid = true;
  for (const schema of schemas) {
    valid = check(run, schema, value, path, depth, refs) && valid;
    if (full(run) && !valid) {
      return false;
    }
  }
  return valid;
}

function checkCombinators(
  run: Run,
  schema: JsonRecord,
  value: unknown,
  path: string,
  depth: number,
  refs: number
): boolean {
  const { allOf, anyOf, oneOf, not } = schema;
  let valid = Array.isArray(allOf)
    ? checkAllOf(run, allOf, value, path, depth, refs)
    : true;
  if (
    Array.isArray(anyOf) &&
    countMatches(run, anyOf, value, depth, refs, 1) === 0
  ) {
    valid = false;
    report(run, path, "anyOf", "does not match any of the allowed schemas");
  }
  const oneOfMatches = Array.isArray(oneOf)
    ? countMatches(run, oneOf, value, depth, refs, 2)
    : 1;
  if (oneOfMatches !== 1) {
    valid = false;
    report(
      run,
      path,
      "oneOf",
      oneOfMatches === 0
        ? "does not match any of the allowed schemas"
        : "matches more than one of the schemas where exactly one must match"
    );
  }
  if (not !== undefined && matches(run, not, value, depth, refs)) {
    valid = false;
    report(run, path, "not", "matches a schema it must not match");
  }
  return valid;
}

function checkValue(
  run: Run,
  schema: JsonRecord,
  value: unknown,
  path: string,
  depth: number,
  refs: number
): boolean {
  let valid = true;
  const mismatch = typeMismatch(schema, value);
  if (mismatch) {
    report(run, path, "type", `must be ${mismatch.join(" or ")}`);
    return false;
  }
  if (Array.isArray(schema.enum)) {
    spend(run, schema.enum.length);
    if (!schema.enum.some((option) => jsonEqual(option, value))) {
      valid = false;
      report(run, path, "enum", "must be one of the allowed values");
    }
  }
  if (schema.const !== undefined && !jsonEqual(schema.const, value)) {
    valid = false;
    report(run, path, "const", "must be the allowed value");
  }
  if (typeof value === "string") {
    valid = checkString(run, schema, value, path) && valid;
  } else if (isNumber(value)) {
    valid = checkNumber(run, schema, value, path) && valid;
  } else if (Array.isArray(value)) {
    valid = checkArray(run, schema, value, path, depth, refs) && valid;
  } else if (asRecord(value)) {
    valid =
      checkObject(run, schema, value as JsonRecord, path, depth, refs) && valid;
  }
  return valid;
}

function check(
  run: Run,
  schema: unknown,
  value: unknown,
  path: string,
  depth: number,
  refs: number
): boolean {
  if (run.budget.exhausted || spend(run)) {
    return false;
  }
  if (schema === false) {
    report(run, path, "false", "is not allowed");
    return false;
  }
  const record = asRecord(schema);
  if (!record) {
    return true;
  }
  if (depth > MAX_DEPTH) {
    report(run, path, "depth", `is nested deeper than ${MAX_DEPTH} levels`);
    return false;
  }
  let valid = true;
  if (typeof record.$ref === "string") {
    if (refs >= MAX_REF_DEPTH) {
      report(run, path, "$ref", `follows $ref more than ${MAX_REF_DEPTH} deep`);
      return false;
    }
    const target = resolveRef(run.root, record.$ref);
    if (target !== undefined) {
      valid = check(run, target, value, path, depth, refs + 1);
      if (full(run) && !valid) {
        return false;
      }
    }
  }
  valid = checkValue(run, record, value, path, depth, refs) && valid;
  if (full(run) && !valid) {
    return false;
  }
  return checkCombinators(run, record, value, path, depth, refs) && valid;
}

/**
 * Validates `value` against a JSON schema and returns up to `max`
 * violations, none when it is valid. When validation runs out of steps, the
 * only violation is `{ path: "$", keyword: "budget" }`.
 */
export function validateSchema(
  schema: unknown,
  value: unknown,
  max = 5
): SchemaViolation[] {
  const run: Run = {
    root: schema,
    budget: { steps: 0, exhausted: false },
    out: [],
    max,
  };
  const valid = check(run, schema, value, "$", 0, 0);
  if (run.budget.exhausted) {
    return [
      { path: "$", keyword: "budget", message: "is too complex to validate" },
    ];
  }
  if (!valid && run.out?.length === 0) {
    return [
      { path: "$", keyword: "schema", message: "does not match the schema" },
    ];
  }
  return run.out ?? [];
}
