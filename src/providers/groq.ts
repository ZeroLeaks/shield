import type { DetectOptions, DetectResult } from "../detect";
import type { HardenOptions } from "../harden";
import type { SanitizeOptions, SanitizeResult } from "../sanitize";
import { shieldOpenAI } from "./openai";

export interface ShieldGroqOptions {
  systemPrompt?: string;
  harden?: HardenOptions | false;
  detect?: DetectOptions | false;
  sanitize?: SanitizeOptions | false;
  /** `"buffer"`: full buffer then sanitize. `"chunked"`: 8KB chunks, lower memory. `"passthrough"`: skip sanitization. */
  streamingSanitize?: "buffer" | "chunked" | "passthrough";
  /** Chunk size for "chunked" mode (default 8192). */
  streamingChunkSize?: number;
  onDetection?: "block" | "warn";
  throwOnLeak?: boolean;
  onInjectionDetected?: (result: DetectResult) => void;
  onLeakDetected?: (result: SanitizeResult) => void;
}

export function shieldGroq<
  T extends { chat: { completions: { create(...args: unknown[]): unknown } } },
>(client: T, options: ShieldGroqOptions = {}): T {
  return shieldOpenAI(client, options);
}
