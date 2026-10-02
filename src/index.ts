// biome-ignore-all lint/performance/noBarrelFile: this is the package's public entry point.

export { type AsyncDetector, anyOf } from "./combine";
export {
  type ConversationDetectOptions,
  type ConversationDetectResult,
  type ConversationMessage,
  type DetectNormalizationOptions,
  type DetectOptions as LocalDetectOptions,
  type DetectResult as LocalDetectResult,
  detect as detectLocal,
  detectAsync,
  detectConversation,
} from "./detect";
export {
  type BlockedFinding,
  InjectionDetectedError,
  type InjectionSource,
  LeakDetectedError,
  OutputBlockedError,
  ShieldError,
  ToolPolicyError,
} from "./errors";
export {
  type HardenOptions,
  harden,
  type SpotlightOptions,
  spotlight,
  spotlightInstruction,
} from "./harden";
export {
  createHostedDetector,
  detect,
  type HostedCoverage,
  type HostedDetectOptions,
  type HostedDetectOptions as DetectOptions,
  type HostedDetector,
  type HostedDetectResult,
  type HostedDetectResult as DetectResult,
  type HostedRequestOptions,
  SHIELD_API_BASE_URL,
  SHIELD_MODELS,
  ShieldAPIError,
  type ShieldModel,
} from "./hosted";
export {
  createLlmDetector,
  LLM_DETECTOR_PROMPT,
  type LlmDetector,
  type LlmDetectorOptions,
} from "./llm";
export {
  type CanaryMatchKind,
  type CanaryOptions,
  canaryInstruction,
  createCanary,
  DEFAULT_PII_KINDS,
  detectExfiltration,
  detectInjection,
  detectPII,
  detectSecrets,
  EXFILTRATION_KINDS,
  type ExfiltrationOptions,
  findCanary,
  INJECTION_KINDS,
  type InjectionOptions,
  ibanChecksumValid,
  isAllowedHost,
  luhnValid,
  type OutputFinding,
  type OutputFindingType,
  PII_KINDS,
  type PIIKind,
  type PIIOptions,
  type RedactOptions,
  redactFindings,
  redactionLabel,
  type ScanOutputOptions,
  type ScanOutputResult,
  SECRET_KINDS,
  type SecretsOptions,
  type Severity,
  scanOutputText,
} from "./output";
export {
  createToolPolicy,
  guessToolLabels,
  type SchemaViolation,
  type ToolLabel,
  type ToolPolicy,
  type ToolPolicyCall,
  type ToolPolicyDecision,
  type ToolPolicyOptions,
  type ToolPolicyReason,
  type ToolPolicyRefusal,
  type ToolPolicyRule,
  type ToolPolicyState,
  type ToolSet,
} from "./policy";
export {
  type ShieldAISdkOptions,
  type ShieldLanguageModelMiddleware,
  shieldLanguageModelMiddleware,
  shieldMiddleware,
} from "./providers/ai-sdk";
export {
  type ShieldAnthropicOptions,
  shieldAnthropic,
} from "./providers/anthropic";
export {
  type ShieldGoogleGenAIOptions,
  shieldGoogleGenAI,
} from "./providers/google";
export { type ShieldGroqOptions, shieldGroq } from "./providers/groq";
export type { ShieldProviderOptions } from "./providers/guard";
export { type ShieldMcpOptions, shieldMcpClient } from "./providers/mcp";
export { type ShieldMistralOptions, shieldMistral } from "./providers/mistral";
export { type ShieldOpenAIOptions, shieldOpenAI } from "./providers/openai";
export {
  type ShieldInjectionInfo,
  type ShieldInputGuardrail,
  type ShieldInputGuardrailOptions,
  type ShieldLeakInfo,
  type ShieldOutputGuardrail,
  type ShieldOutputGuardrailOptions,
  type ShieldPolicySource,
  type ShieldToolGuardrailBehavior,
  type ShieldToolInputGuardrail,
  type ShieldToolInputGuardrailOptions,
  type ShieldToolOutputGuardrail,
  type ShieldToolOutputGuardrailOptions,
  type ShieldToolPolicyGuardrail,
  type ShieldToolPolicyGuardrailOptions,
  shieldInputGuardrail,
  shieldOutputGuardrail,
  shieldToolInputGuardrail,
  shieldToolOutputGuardrail,
  shieldToolPolicyGuardrail,
} from "./providers/openai-agents";
export {
  type SanitizeOptions,
  type SanitizeResult,
  sanitize,
  sanitizeObject,
} from "./sanitize";
export {
  pinTools,
  type ScanToolsOptions,
  type ScanToolsResult,
  scanTools,
  scanToolsAsync,
  type ToolDefinition,
  type ToolPins,
  type ToolScanResult,
} from "./tools";
