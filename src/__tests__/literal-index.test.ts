// biome-ignore-all lint/suspicious/noBitwiseOperators: the test text generator is a 32-bit LCG.
import { describe, expect, it } from "vitest";
import { buildLiteralIndex } from "../literal-index";

const LITERALS = [
  "ignore",
  "ignor",
  "gnore",
  "instruct",
  "instructions",
  "sys",
  "system",
  "prompt",
  "123",
  "a1b2",
  "he",
  "she",
  "his",
  "hers",
];

function randomText(seed: number, length: number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 .,-";
  let x = seed;
  let out = "";
  for (let i = 0; i < length; i++) {
    x = (Math.imul(x, 1_103_515_245) + 12_345) >>> 0;
    out += alphabet[x % alphabet.length];
  }
  return out;
}

describe("buildLiteralIndex", () => {
  const index = buildLiteralIndex(LITERALS);

  it("finds the same literals as includes()", () => {
    const texts = [
      "please ignore the system prompt",
      "ushers and his hers",
      "a1b2c3 123",
      ...Array.from({ length: 200 }, (_, i) => randomText(i + 1, 400)),
    ];
    for (const text of texts) {
      const found = new Uint8Array(index.size);
      index.scan(text, found);
      for (const literal of LITERALS) {
        expect(found[index.ids.get(literal) ?? -1] === 1).toBe(
          text.includes(literal)
        );
      }
    }
  });

  it("dedupes literals and rejects characters outside a-z0-9", () => {
    expect(buildLiteralIndex(["abc", "abc"]).size).toBe(1);
    expect(() => buildLiteralIndex(["a-b"])).toThrow();
  });
});
