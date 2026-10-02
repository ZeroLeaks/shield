import { describe, expect, it } from "vitest";
import {
  InjectionDetectedError,
  LeakDetectedError,
  OutputBlockedError,
  ShieldError,
} from "../errors";
import type { OutputFinding } from "../output";

describe("ShieldError", () => {
  it("has correct name and code", () => {
    const err = new ShieldError("test", "TEST_CODE");
    expect(err.name).toBe("ShieldError");
    expect(err.code).toBe("TEST_CODE");
    expect(err.message).toBe("test");
    expect(err instanceof Error).toBe(true);
  });
});

describe("InjectionDetectedError", () => {
  it("formats message from risk and categories", () => {
    const err = new InjectionDetectedError("critical", [
      "instruction_override",
      "role_hijack",
    ]);
    expect(err.name).toBe("InjectionDetectedError");
    expect(err.code).toBe("INJECTION_DETECTED");
    expect(err.risk).toBe("critical");
    expect(err.categories).toEqual(["instruction_override", "role_hijack"]);
    expect(err.message).toContain("critical");
    expect(err.source).toBeUndefined();
    expect(err instanceof ShieldError).toBe(true);
  });

  it("records whether the injection came from a user or a tool", () => {
    const fromUser = new InjectionDetectedError(
      "high",
      ["role_hijack"],
      "user"
    );
    const fromTool = new InjectionDetectedError(
      "high",
      ["indirect_injection"],
      "tool"
    );

    expect(fromUser.source).toBe("user");
    expect(fromUser.message).toBe(
      new InjectionDetectedError("high", ["role_hijack"]).message
    );
    expect(fromTool.source).toBe("tool");
    expect(fromTool.message).toContain("tool result");
  });
});

describe("LeakDetectedError", () => {
  it("formats message from confidence and fragment count", () => {
    const err = new LeakDetectedError(0.85, 3);
    expect(err.name).toBe("LeakDetectedError");
    expect(err.code).toBe("LEAK_DETECTED");
    expect(err.confidence).toBe(0.85);
    expect(err.fragmentCount).toBe(3);
    expect(err.message).toContain("85%");
    expect(err.message).toContain("3 fragments");
    expect(err instanceof ShieldError).toBe(true);
  });
});

describe("OutputBlockedError", () => {
  it("keeps the type, kind, and severity of each finding and nothing else", () => {
    const secret: OutputFinding = {
      type: "secret",
      kind: "github_pat",
      severity: "critical",
      start: 4,
      end: 44,
      confidence: 0.95,
      preview: "ghp_…abcd",
    };
    const err = new OutputBlockedError([
      secret,
      { type: "exfiltration", kind: "markdown_image", severity: "high" },
    ]);

    expect(err.name).toBe("OutputBlockedError");
    expect(err.code).toBe("OUTPUT_BLOCKED");
    expect(err.findings).toEqual([
      { type: "secret", kind: "github_pat", severity: "critical" },
      { type: "exfiltration", kind: "markdown_image", severity: "high" },
    ]);
    expect(err.message).toContain("secret:github_pat (critical)");
    expect(err.message).toContain("exfiltration:markdown_image (high)");
    expect(err.message).not.toContain("ghp_");
    expect(err instanceof ShieldError).toBe(true);
  });

  it("lists at most five kinds in its message", () => {
    const err = new OutputBlockedError(
      Array.from({ length: 7 }, (_, i) => ({
        type: "secret" as const,
        kind: `kind_${i}`,
        severity: "high" as const,
      }))
    );

    expect(err.message).toContain("kind_4");
    expect(err.message).not.toContain("kind_5");
    expect(err.message).toContain("and 2 more");
  });
});
