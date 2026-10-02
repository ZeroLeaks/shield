// biome-ignore-all lint/suspicious/noBitwiseOperators: the test text generator is a 32-bit LCG.
import { describe, expect, it } from "vitest";
import { classify, scoreWindowForTest, scoreWithVisitor } from "../classifier";
import { extractFeatures, visitFeatures } from "../classifier/features";

function randomText(seed: number, length: number): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 .,!?'\né中р";
  let x = seed;
  let out = "";
  for (let i = 0; i < length; i++) {
    x = (Math.imul(x, 1_103_515_245) + 12_345) >>> 0;
    out += alphabet[x % alphabet.length];
  }
  return out;
}

describe("classifier", () => {
  it("scores the same features the training extractor emits", () => {
    for (let seed = 1; seed <= 200; seed++) {
      const text = randomText(seed, (seed * 37) % 900);
      expect(scoreWindowForTest(text)).toBeCloseTo(
        scoreWithVisitor(text, visitFeatures),
        12
      );
    }
  });

  it("extracts deterministic features", () => {
    expect([...extractFeatures("hello world")].sort()).toEqual(
      [...extractFeatures("hello world")].sort()
    );
    expect(extractFeatures("").size).toBe(0);
  });

  it("returns probabilities for empty, short, and long text", () => {
    for (const text of ["", "hi", randomText(7, 5000), randomText(9, 50_000)]) {
      const p = classify(text);
      expect(p).toBeGreaterThanOrEqual(0);
      expect(p).toBeLessThanOrEqual(1);
    }
  });
});
