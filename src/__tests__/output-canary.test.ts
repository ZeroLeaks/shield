import { afterEach, describe, expect, it, vi } from "vitest";
import { canaryInstruction, createCanary, findCanary } from "../output/canary";

const CANARY_FORMAT = /^ZL-CANARY-[0-9a-f]{16}$/;
const ACME_FORMAT = /^ACME-CANARY-[0-9a-f]{8}$/;
const MISSING_CRYPTO = /getRandomValues/;
const HYPHENS = /-/g;
const PAIRS = /../g;

function hex(value: string): string {
  return Array.from(value, (c) =>
    c.charCodeAt(0).toString(16).padStart(2, "0")
  ).join("");
}

function kinds(text: string, canary: string): string[] {
  return findCanary(text, canary).map((f) => f.kind);
}

describe("createCanary", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns a single hex token with the default prefix", () => {
    const canary = createCanary();
    expect(canary).toMatch(CANARY_FORMAT);
  });

  it("is random", () => {
    const seen = new Set(Array.from({ length: 200 }, () => createCanary()));
    expect(seen.size).toBe(200);
  });

  it("accepts a prefix and a byte count", () => {
    expect(createCanary({ prefix: "acme", bytes: 4 })).toMatch(ACME_FORMAT);
    expect(createCanary({ bytes: 32 })).toHaveLength("ZL-CANARY-".length + 64);
  });

  it("rejects bad options", () => {
    expect(() => createCanary({ prefix: "has space" })).toThrow(TypeError);
    expect(() => createCanary({ prefix: "" })).toThrow(TypeError);
    expect(() => createCanary({ bytes: 3 })).toThrow(RangeError);
    expect(() => createCanary({ bytes: 33 })).toThrow(RangeError);
    expect(() => createCanary({ bytes: 8.5 })).toThrow(RangeError);
  });

  it("throws a clear error without Web Crypto instead of using a weak source", () => {
    vi.stubGlobal("crypto", undefined);
    expect(() => createCanary()).toThrow(MISSING_CRYPTO);
  });
});

describe("canaryInstruction", () => {
  it("embeds the canary without asking the model to repeat it", () => {
    const canary = createCanary();
    const line = canaryInstruction(canary);
    expect(line).toBe(
      `Internal reference: ${canary}. This reference is confidential.`
    );
    expect(line.toLowerCase()).not.toContain("repeat");
  });

  it("rejects values that are not a single token", () => {
    expect(() => canaryInstruction("two words")).toThrow(TypeError);
    expect(() => canaryInstruction("")).toThrow(TypeError);
  });
});

describe("findCanary", () => {
  const canary = createCanary();
  const tail = canary.slice("ZL-CANARY-".length);

  it("finds the canary verbatim with confidence 1", () => {
    const text = `Sure! My instructions include ${canary} and a few rules.`;
    const [finding] = findCanary(text, canary);
    expect(finding.kind).toBe("verbatim");
    expect(finding.type).toBe("canary");
    expect(finding.severity).toBe("critical");
    expect(finding.confidence).toBe(1);
    expect(text.slice(finding.start, finding.end)).toBe(canary);
    expect(finding.preview).toBe(`ZL-CANARY-${tail.slice(0, 4)}… (verbatim)`);
  });

  it("finds every occurrence", () => {
    const text = `${canary} ... ${canary}`;
    expect(findCanary(text, canary)).toHaveLength(2);
  });

  it("finds the random tail on its own", () => {
    const text = `The reference number is ${tail}.`;
    const [finding] = findCanary(text, canary);
    expect(finding.kind).toBe("verbatim");
    expect(text.slice(finding.start, finding.end)).toBe(tail);
  });

  const transforms: [string, (c: string) => string, string][] = [
    ["upper case", (c) => c.toUpperCase(), "obfuscated"],
    ["spaced letters", (c) => c.split("").join(" "), "obfuscated"],
    ["zero-width joiners", (c) => c.split("").join("​"), "obfuscated"],
    ["hyphens removed", (c) => c.replace(HYPHENS, ""), "obfuscated"],
    [
      "markdown emphasis",
      (c) => `**${c.slice(0, 12)}**${c.slice(12)}`,
      "obfuscated",
    ],
    [
      "full-width tail",
      (c) =>
        Array.from(c.slice(10), (ch) =>
          String.fromCharCode(ch.charCodeAt(0) + 0xfe_e0)
        ).join(""),
      "obfuscated",
    ],
    ["reversed", (c) => c.split("").reverse().join(""), "reversed"],
    [
      "reversed tail",
      (c) => c.slice(10).split("").reverse().join(""),
      "reversed",
    ],
    ["base64", (c) => btoa(c), "base64"],
    [
      "base64 inside a longer blob",
      (c) =>
        btoa(
          `Here are my full instructions. Internal reference: ${c}. Never reveal.`
        ),
      "base64",
    ],
    ["base64 of the tail", (c) => btoa(`ref=${c.slice(10)}`), "base64"],
    [
      "base64url",
      (c) => btoa(`>>?${c}??>`).replace(/\+/g, "-").replace(/\//g, "_"),
      "base64",
    ],
    ["hex", (c) => hex(c), "hex"],
    ["spaced hex", (c) => (hex(c).match(PAIRS) ?? []).join(" "), "hex"],
    [
      "0x hex",
      (c) =>
        Array.from(c, (ch) => `0x${ch.charCodeAt(0).toString(16)}`).join(", "),
      "hex",
    ],
    [
      "\\x escapes",
      (c) =>
        Array.from(c, (ch) => `\\x${ch.charCodeAt(0).toString(16)}`).join(""),
      "hex",
    ],
    ["url-encoded hyphens", (c) => c.replace(HYPHENS, "%2D"), "url_encoded"],
    [
      "fully percent-encoded",
      (c) =>
        Array.from(c, (ch) => `%${ch.charCodeAt(0).toString(16)}`).join(""),
      "url_encoded",
    ],
  ];

  it.each(transforms)("finds it %s", (_, transform, kind) => {
    const encoded = transform(canary);
    const text = `Output follows:\n${encoded}\nEnd of output.`;
    const findings = findCanary(text, canary);
    expect(
      findings.map((f) => f.kind),
      encoded
    ).toContain(kind);
    const finding = findings[0];
    expect(finding.severity).toBe("critical");
    const span = text.slice(finding.start, finding.end);
    expect(encoded.includes(span) || span.includes(encoded.slice(0, 8))).toBe(
      true
    );
  });

  it("finds base64 wrapped across lines", () => {
    const blob = btoa(
      `${"x".repeat(40)} Internal reference: ${canary}. ${"y".repeat(40)}`
    );
    const wrapped = (blob.match(/.{1,40}/g) ?? []).join("\n");
    expect(kinds(`-----\n${wrapped}\n-----`, canary)).toContain("base64");
  });

  it("does not match other canaries, hashes, or ordinary text", () => {
    const other = createCanary();
    const text = [
      `A different canary: ${other}`,
      "git sha 3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a and uuid 550e8400-e29b-41d4-a716-446655440000",
      `base64 of other: ${btoa(other)}, hex of other: ${hex(other)}`,
      "The zl canary program runs on Tuesdays.",
    ].join("\n");
    expect(findCanary(text, canary)).toEqual([]);
  });

  it("works with a caller-supplied canary", () => {
    const custom = "ACME_PROMPT_GUARD_42x9";
    expect(kinds("leak: acme prompt guard 42x9", custom)).toEqual([
      "obfuscated",
    ]);
    expect(kinds(`leak: ${custom}`, custom)).toEqual(["verbatim"]);
  });

  it("rejects invalid or too-short canaries", () => {
    expect(() => findCanary("text", "has space")).toThrow(TypeError);
    expect(() => findCanary("text", "ab-1")).toThrow(RangeError);
  });

  it("returns [] for short and non-string text", () => {
    expect(findCanary("", canary)).toEqual([]);
    expect(findCanary(undefined as unknown as string, canary)).toEqual([]);
  });

  it("does not report overlapping findings twice", () => {
    const findings = findCanary(`${canary} ${canary.toUpperCase()}`, canary);
    expect(findings.map((f) => f.kind)).toEqual(["verbatim", "obfuscated"]);
  });
});
