// biome-ignore-all lint/performance/noBarrelFile: this is the public entry point for the output detectors.
export {
  type CanaryMatchKind,
  type CanaryOptions,
  canaryInstruction,
  createCanary,
  findCanary,
} from "./canary";
export {
  detectExfiltration,
  EXFILTRATION_KINDS,
  type ExfiltrationOptions,
  isAllowedHost,
} from "./exfiltration";
export {
  detectInjection,
  INJECTION_KINDS,
  type InjectionOptions,
} from "./injection";
export {
  DEFAULT_PII_KINDS,
  detectPII,
  ibanChecksumValid,
  luhnValid,
  PII_KINDS,
  type PIIKind,
  type PIIOptions,
} from "./pii";
export {
  DEFAULT_REDACTION_TEXT,
  type MergedRange,
  mergeRanges,
  type RedactableFinding,
  type RedactionText,
  type RedactOptions,
  redactFindings,
  redactionLabel,
} from "./redact";
export {
  type ScanOutputOptions,
  type ScanOutputResult,
  scanOutputText,
} from "./scan";
export { detectSecrets, SECRET_KINDS, type SecretsOptions } from "./secrets";
export type { OutputFinding, OutputFindingType, Severity } from "./types";
