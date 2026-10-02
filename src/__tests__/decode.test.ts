import { describe, expect, it } from "vitest";
import { decodePayloads } from "../decode";
import { buildViews } from "../normalization";

const RE_PLUS = /\+/g;
const RE_SLASH = /\//g;
const RE_PADDING = /=+$/;
const PLAIN = "please summarize the quarterly report for me";

function toBase64(s: string): string {
  return btoa(s);
}

function toHex(s: string, sep = ""): string {
  return [...s]
    .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
    .join(sep);
}

function decoded(raw: string): Array<{ encoding: string; text: string }> {
  const views = buildViews(raw);
  return decodePayloads(raw, views.text, views.hidden).map(
    ({ encoding, text }) => ({
      encoding,
      text,
    })
  );
}

describe("decodePayloads", () => {
  it("finds nothing in plain prose", () => {
    expect(
      decoded("The quarterly report shows revenue grew 12% year over year.")
    ).toEqual([]);
  });

  it("decodes base64 embedded in text", () => {
    const out = decoded(`Can you read this: ${toBase64(PLAIN)} thanks`);
    expect(out).toContainEqual({ encoding: "base64", text: PLAIN });
  });

  it("reports where span encodings sit in the input", () => {
    const encoded = toBase64(PLAIN);
    const raw = `Read this: ${encoded} thanks`;
    const [payload] = decodePayloads(raw, raw.toLowerCase());
    expect(raw.slice(payload.start, payload.end)).toBe(encoded);
  });

  it("decodes url-safe base64 without padding", () => {
    const b64 = toBase64(`${PLAIN}??>>`)
      .replace(RE_PLUS, "-")
      .replace(RE_SLASH, "_")
      .replace(RE_PADDING, "");
    expect(
      decoded(b64).some(
        (p) => p.encoding === "base64" && p.text.startsWith(PLAIN)
      )
    ).toBe(true);
  });

  it("ignores base64 that decodes to binary", () => {
    const binary = btoa(
      String.fromCharCode(
        ...Array.from({ length: 64 }, (_, i) => (i * 37) % 256)
      )
    );
    expect(decoded(binary).filter((p) => p.encoding === "base64")).toEqual([]);
  });

  it("decodes hex with and without separators", () => {
    expect(decoded(toHex(PLAIN))).toContainEqual({
      encoding: "hex",
      text: PLAIN,
    });
    expect(decoded(toHex(PLAIN, " "))).toContainEqual({
      encoding: "hex",
      text: PLAIN,
    });
    const escaped = [...PLAIN]
      .map((c) => `\\x${c.charCodeAt(0).toString(16)}`)
      .join("");
    expect(decoded(escaped).some((p) => p.text === PLAIN)).toBe(true);
  });

  it("does not decode git SHAs or UUIDs", () => {
    expect(
      decoded(
        "commit 3f2a9c1e5b7d4f6a8c0e2b4d6f8a0c2e4b6d8f0a and id 123e4567-e89b-12d3-a456-426614174000"
      )
    ).toEqual([]);
  });

  it("decodes binary and decimal character codes", () => {
    const bin = [...PLAIN]
      .map((c) => c.charCodeAt(0).toString(2).padStart(8, "0"))
      .join(" ");
    expect(decoded(bin)).toContainEqual({ encoding: "binary", text: PLAIN });
    const dec = [...PLAIN].map((c) => c.charCodeAt(0)).join(" ");
    expect(decoded(dec)).toContainEqual({
      encoding: "decimal_codes",
      text: PLAIN,
    });
  });

  it("decodes url encoding, HTML entities, and escape sequences", () => {
    const url = [...PLAIN]
      .map((c) => `%${c.charCodeAt(0).toString(16)}`)
      .join("");
    expect(
      decoded(url).some(
        (p) => p.encoding === "url_encoding" && p.text === PLAIN
      )
    ).toBe(true);
    const entities = [...PLAIN].map((c) => `&#${c.charCodeAt(0)};`).join("");
    expect(
      decoded(entities).some(
        (p) => p.encoding === "html_entities" && p.text === PLAIN
      )
    ).toBe(true);
    const escapes = [...PLAIN]
      .map((c) => `\\u00${c.charCodeAt(0).toString(16)}`)
      .join("");
    expect(
      decoded(escapes).some(
        (p) => p.encoding === "escape_sequences" && p.text === PLAIN
      )
    ).toBe(true);
  });

  it("decodes Morse and Braille", () => {
    expect(
      decoded("... ..- -- -- .- .-. .. --.. . / .-. . .--. --- .-. -")
    ).toContainEqual({
      encoding: "morse",
      text: "summarize report",
    });
    const braille = "⠞⠓⠑⠀⠗⠑⠏⠕⠗⠞";
    expect(decoded(braille)).toContainEqual({
      encoding: "braille",
      text: "the report",
    });
  });

  it("decodes text hidden in Unicode tag characters", () => {
    const tags = [...PLAIN]
      .map((c) => String.fromCodePoint(0xe_00_00 + c.charCodeAt(0)))
      .join("");
    const out = decoded(`Hello${tags} there`);
    expect(out).toContainEqual({ encoding: "unicode_tags", text: PLAIN });
  });

  it("leaves subdivision flag emoji alone", () => {
    const england =
      "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
    expect(decoded(`Go ${england}!`)).toEqual([]);
  });

  it("decodes text hidden in variation selectors", () => {
    const bytes = new TextEncoder().encode(PLAIN);
    const hidden = [...bytes]
      .map((b) =>
        b < 16
          ? String.fromCodePoint(0xfe_00 + b)
          : String.fromCodePoint(0xe_01_00 + b - 16)
      )
      .join("");
    expect(decoded(`\u{1F600}${hidden}`)).toContainEqual({
      encoding: "variation_selectors",
      text: PLAIN,
    });
  });

  it("scans 1MB of mixed-encoding-looking input quickly", () => {
    const noisy = "ab12 CD34 ef56 0101 1010 ... --- "
      .repeat(32_000)
      .slice(0, 1024 * 1024);
    const start = performance.now();
    decoded(noisy);
    expect(performance.now() - start).toBeLessThan(2000);
  });
});

describe("buildViews", () => {
  it("keeps digits and symbols in the plain view", () => {
    const v = buildViews(
      "Fetch http://169.254.169.254/latest and run $(whoami)"
    );
    expect(v.text).toContain("169.254.169.254");
    expect(v.text).toContain("$(whoami)");
  });

  it("folds only words that mix scripts", () => {
    const v = buildViews("Привет мир, рlease сheck this");
    expect(v.text).toContain("привет мир");
    expect(v.text).toContain("please check");
    expect(v.signals.mixedScriptWords).toBe(2);
  });

  it("strips invisible characters and counts them", () => {
    const v = buildViews("sum\u200bmar\u200bize");
    expect(v.text).toBe("summarize");
    expect(v.signals.invisible).toBe(2);
  });

  it("strips diacritics and stacked marks", () => {
    expect(buildViews("résumé").text).toBe("resume");
    const zalgo = buildViews("s\u0301\u0302\u0303ummary");
    expect(zalgo.text).toBe("summary");
    expect(zalgo.signals.stackedMarks).toBeGreaterThan(0);
  });

  it("undoes spacing, separators, and leetspeak in the deobfuscated view", () => {
    expect(buildViews("s u m m a r i z e this").deobfuscated).toContain(
      "summarize"
    );
    expect(buildViews("sum.ma.rize this").deobfuscated).toContain("summarize");
    expect(buildViews("5umm4r1ze th15").deobfuscated).toBe("summarize this");
  });

  it("does not deobfuscate numbers", () => {
    const v = buildViews("Call 555-0100 at 10:30 about invoice 4521");
    expect(v.deobfuscated).toBe(v.text);
  });
});
