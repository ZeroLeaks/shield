// biome-ignore-all lint/performance/useTopLevelRegex: each case is the regex under test.
import { describe, expect, it } from "vitest";
import { requiredLiteral, requiredLiterals } from "../literal";

describe("requiredLiteral", () => {
  it("finds the longest required run", () => {
    expect(requiredLiteral(/hello\s+(big\s+)?world/i)).toBe("hello");
    expect(requiredLiteral(/ab\s+wonderful/)).toBe("wonderful");
  });

  it("drops a character made optional by a quantifier", () => {
    expect(requiredLiteral(/colou?r/)).toBe("colo");
    expect(requiredLiteral(/abcd*/)).toBe("abc");
  });

  it("returns undefined for top-level alternation or short literals", () => {
    expect(requiredLiteral(/cat|dog/)).toBeUndefined();
    expect(requiredLiteral(/(?:cat|dog)s/)).toBeUndefined();
    expect(requiredLiteral(/[a-z]+/)).toBeUndefined();
  });

  it("ignores groups, classes, and escapes", () => {
    expect(requiredLiteral(/(?:alpha|beta)\s+gamma/)).toBe("gamma");
    expect(requiredLiteral(/\[report\]/)).toBe("report");
    expect(requiredLiteral(/\d+\.\d+ version/)).toBe("version");
  });

  it("keeps case for case-sensitive patterns", () => {
    expect(requiredLiteral(/Hello/)).toBe("ello");
    expect(requiredLiteral(/Hello/i)).toBe("hello");
  });

  it("returns alternatives from required groups", () => {
    expect(
      requiredLiterals(/\[?\s*(?:WHITE\s+TEXT|HIDDEN|NOT\s+VISIBLE)\s*/i)
    ).toEqual(["white", "hidden", "visible"]);
    expect(requiredLiterals(/cat|dog/)).toEqual(["cat", "dog"]);
    expect(requiredLiterals(/(?:big\s+)?(?:cat|dog)food/)).toEqual(["food"]);
  });

  it("skips optional groups and lookarounds", () => {
    expect(requiredLiterals(/(?:alpha)?beta/)).toEqual(["beta"]);
    expect(requiredLiterals(/(?!alpha)\w+/)).toBeUndefined();
    expect(requiredLiterals(/(?=alpha)\w+/)).toBeUndefined();
    expect(requiredLiterals(/(?:one|t)wo/)).toBeUndefined();
  });

  it("never claims a literal a match can lack", () => {
    const cases: [RegExp, string[]][] = [
      [
        /\[?\s*(?:WHITE\s+TEXT|HIDDEN|NOT\s+VISIBLE)\s*/i,
        ["[hidden", "not visible", "white text"],
      ],
      [
        /(?:repeat|print)\s+(?:your|the)\s+rules/i,
        ["print the rules", "repeat your rules"],
      ],
      [/colou?r(?:ful)?/, ["color", "colourful"]],
      [/a{0,3}bcd+e/, ["bcde", "abcdddde"]],
    ];
    for (const [re, samples] of cases) {
      const req = requiredLiterals(re);
      for (const sample of samples) {
        expect(re.test(sample)).toBe(true);
        if (req) {
          expect(req.some((lit) => sample.toLowerCase().includes(lit))).toBe(
            true
          );
        }
      }
    }
  });
});
