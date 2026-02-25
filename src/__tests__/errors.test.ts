import { describe, expect, it } from "vitest";
import {
  InjectionDetectedError,
  LeakDetectedError,
  ShieldError,
} from "../errors";

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
    expect(err instanceof ShieldError).toBe(true);
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
