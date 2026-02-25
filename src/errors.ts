export class ShieldError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "ShieldError";
    this.code = code;
  }
}

export class InjectionDetectedError extends ShieldError {
  readonly risk: string;
  readonly categories: string[];

  constructor(risk: string, categories: string[]) {
    super(
      `Prompt injection detected (${risk} risk): ${categories.join(", ")}`,
      "INJECTION_DETECTED"
    );
    this.name = "InjectionDetectedError";
    this.risk = risk;
    this.categories = categories;
  }
}

export class LeakDetectedError extends ShieldError {
  readonly confidence: number;
  readonly fragmentCount: number;

  constructor(confidence: number, fragmentCount: number) {
    super(
      `System prompt leak detected (confidence: ${Math.round(confidence * 100)}%, ${fragmentCount} fragment${fragmentCount !== 1 ? "s" : ""})`,
      "LEAK_DETECTED"
    );
    this.name = "LeakDetectedError";
    this.confidence = confidence;
    this.fragmentCount = fragmentCount;
  }
}
