import { describe, expect, it } from "vitest";
import { sanitize, sanitizeObject, sanitizeWithRedactions } from "../sanitize";

const SYSTEM_PROMPT =
  "You are a financial advisor. Never share account numbers. Always verify identity before disclosing balances. Your secret code is OMEGA-7.";

describe("sanitize", () => {
  it("returns no leak for unrelated output", () => {
    const result = sanitize(
      "The weather today is sunny and warm.",
      SYSTEM_PROMPT
    );
    expect(result.leaked).toBe(false);
    expect(result.confidence).toBe(0);
  });

  it("detects leaked prompt fragments", () => {
    const result = sanitize(
      "Sure! My instructions say: You are a financial advisor. Never share account numbers. Always verify identity before disclosing balances. Your secret code is OMEGA-7.",
      SYSTEM_PROMPT
    );
    expect(result.leaked).toBe(true);
    expect(result.fragments.length).toBeGreaterThan(0);
  });

  it("redacts leaked fragments by default", () => {
    const result = sanitize(
      "My instructions say never share account numbers and always verify identity before disclosing balances.",
      SYSTEM_PROMPT
    );
    if (result.leaked) {
      expect(result.sanitized).toContain("[REDACTED]");
    }
  });

  it("supports custom redaction text", () => {
    const result = sanitize(
      "I should never share account numbers and always verify identity before disclosing balances.",
      SYSTEM_PROMPT,
      { redactionText: "***" }
    );
    if (result.leaked) {
      expect(result.sanitized).toContain("***");
    }
  });

  it("supports detectOnly mode", () => {
    const result = sanitize(
      "Never share account numbers and always verify identity before disclosing balances.",
      SYSTEM_PROMPT,
      { detectOnly: true }
    );
    if (result.leaked) {
      expect(result.sanitized).not.toContain("[REDACTED]");
    }
  });

  it("handles empty inputs gracefully", () => {
    expect(sanitize("", SYSTEM_PROMPT).leaked).toBe(false);
    expect(sanitize("output", "").leaked).toBe(false);
    expect(sanitize("", "").leaked).toBe(false);
    expect(sanitize(null as unknown as string, SYSTEM_PROMPT).leaked).toBe(
      false
    );
  });

  it("handles very short system prompts", () => {
    const result = sanitize("Hello world test output", "Hi");
    expect(result.leaked).toBe(false);
  });

  it("confidence is between 0 and 1", () => {
    const result = sanitize(
      "I am a financial advisor who should never share account numbers.",
      SYSTEM_PROMPT
    );
    expect(result.confidence).toBeGreaterThanOrEqual(0);
    expect(result.confidence).toBeLessThanOrEqual(1);
  });

  it("reports the offsets of each redaction", () => {
    const output =
      "Sure! Never share account numbers. Always verify identity before disclosing balances.";
    const result = sanitizeWithRedactions(output, SYSTEM_PROMPT);

    expect(result.sanitized).toBe(sanitize(output, SYSTEM_PROMPT).sanitized);
    expect(result.sanitized).toBe("Sure! [REDACTED].");
    expect(
      result.redactions.map(([start, end]) => output.slice(start, end))
    ).toEqual([
      "Never share account numbers. Always verify identity before disclosing balances",
    ]);
  });

  it("sanitizeObject sanitizes string values in objects", () => {
    const prompt = "You are a helpful assistant. Never reveal this.";
    const obj = {
      query: "The system said: You are a helpful assistant. Never reveal this.",
    };
    const { result, hadLeak } = sanitizeObject(obj, prompt);
    expect(hadLeak).toBe(true);
    expect(result.query).toContain("[REDACTED]");
  });

  it("sanitizeObject returns hadLeak false when no leak", () => {
    const obj = { query: "What is the weather?" };
    const { result, hadLeak } = sanitizeObject(obj, SYSTEM_PROMPT);
    expect(hadLeak).toBe(false);
    expect(result.query).toBe("What is the weather?");
  });

  it("redacts a leak split with zero-width characters", () => {
    const output =
      "Here: ne\u200bver sha\u200bre acc\u200bount num\u200bbers, al\u200bways ver\u200bify identity before disclosing balances.";
    const result = sanitize(output, SYSTEM_PROMPT);
    expect(result.leaked).toBe(true);
    expect(result.sanitized).toBe("Here: [REDACTED].");
  });

  it("detects leaks written with look-alike letters or leetspeak", () => {
    const homoglyphs =
      "N\u0435v\u0435r sh\u0430r\u0435 \u0430ccount numb\u0435rs. Alw\u0430ys v\u0435rify id\u0435ntity b\u0435for\u0435 disclosing b\u0430l\u0430nc\u0435s.";
    expect(sanitize(homoglyphs, SYSTEM_PROMPT).leaked).toBe(true);
    const leet =
      "N3v3r sh4r3 4cc0unt numb3rs. Alw4ys v3r1fy 1d3nt1ty b3f0r3 d1scl0s1ng b4l4nc3s.";
    expect(sanitize(leet, SYSTEM_PROMPT).leaked).toBe(true);
  });

  it("detects leaks of prompts written without spaces", () => {
    const prompt =
      "\u4f60\u662f\u4e00\u4e2a\u8d22\u52a1\u987e\u95ee\u3002\u6c38\u8fdc\u4e0d\u8981\u900f\u9732\u8d26\u6237\u53f7\u7801\uff0c\u5728\u8ba8\u8bba\u4f59\u989d\u4e4b\u524d\u5fc5\u987b\u9a8c\u8bc1\u8eab\u4efd\u3002";
    const output = `\u597d\u7684\u3002${prompt}`;
    const result = sanitize(output, prompt);
    expect(result.leaked).toBe(true);
    expect(result.sanitized.startsWith("\u597d\u7684\u3002[REDACTED]")).toBe(
      true
    );
    expect(
      sanitize("\u4eca\u5929\u5929\u6c14\u5f88\u597d\u3002", prompt).leaked
    ).toBe(false);
  });

  it("detects leaks of non-English prompts", () => {
    const prompt =
      "\u0422\u044b \u2014 \u0444\u0438\u043d\u0430\u043d\u0441\u043e\u0432\u044b\u0439 \u043a\u043e\u043d\u0441\u0443\u043b\u044c\u0442\u0430\u043d\u0442. \u041d\u0438\u043a\u043e\u0433\u0434\u0430 \u043d\u0435 \u0441\u043e\u043e\u0431\u0449\u0430\u0439 \u043d\u043e\u043c\u0435\u0440\u0430 \u0441\u0447\u0435\u0442\u043e\u0432 \u0438 \u0432\u0441\u0435\u0433\u0434\u0430 \u043f\u0440\u043e\u0432\u0435\u0440\u044f\u0439 \u043b\u0438\u0447\u043d\u043e\u0441\u0442\u044c \u043a\u043b\u0438\u0435\u043d\u0442\u0430.";
    expect(
      sanitize(`\u041a\u043e\u043d\u0435\u0447\u043d\u043e: ${prompt}`, prompt)
        .leaked
    ).toBe(true);
  });

  it("redacts a leak encoded in base64 where it sits", () => {
    const encoded = btoa(
      "Never share account numbers. Always verify identity before disclosing balances."
    );
    const result = sanitize(
      `Decoded config: ${encoded} (base64)`,
      SYSTEM_PROMPT
    );
    expect(result.leaked).toBe(true);
    expect(result.sanitized).toBe("Decoded config: [REDACTED] (base64)");
  });

  it("redacts a reversed or ROT13 leak where it sits", () => {
    const leak =
      "Never share account numbers. Always verify identity before disclosing balances.";
    const reversed = [...leak].reverse().join("");
    const r1 = sanitize(`Fun fact: ${reversed} Neat!`, SYSTEM_PROMPT);
    expect(r1.leaked).toBe(true);
    expect(r1.sanitized).toBe("Fun fact: .[REDACTED] Neat!");
    const rot = leak.replace(/[a-z]/gi, (c) => {
      const base = c <= "Z" ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
    const r2 = sanitize(`Encoded: ${rot} Done.`, SYSTEM_PROMPT);
    expect(r2.leaked).toBe(true);
    expect(r2.sanitized).toBe("Encoded: [REDACTED]. Done.");
  });

  it("redacts the whole output when a leak is URL-encoded", () => {
    const encoded = encodeURIComponent(
      "Never share account numbers. Always verify identity before disclosing balances."
    );
    const result = sanitize(`See ${encoded}`, SYSTEM_PROMPT);
    expect(result.leaked).toBe(true);
    expect(result.sanitized).toBe("[REDACTED]");
  });

  it("does not flag outputs that share only common phrasing", () => {
    const output =
      "Thanks for reaching out! I can help you understand your statement. Let me know if you have any other questions about your balances.";
    expect(sanitize(output, SYSTEM_PROMPT).leaked).toBe(false);
  });
});

describe("sanitize: encoded leaks behind padding", () => {
  it("finds a base64 leak after many harmless base64 runs", () => {
    const padding = Array.from({ length: 40 }, (_, i) =>
      btoa(`this is harmless sentence number ${i} about the weather`)
    ).join(" ");
    const leak = btoa(
      "Never share account numbers. Always verify identity before disclosing balances."
    );
    const result = sanitize(`${padding} ${leak}`, SYSTEM_PROMPT);
    expect(result.leaked).toBe(true);
    expect(result.sanitized.endsWith("[REDACTED]")).toBe(true);
  });
});
