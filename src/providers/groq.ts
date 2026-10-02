import type { ShieldProviderOptions } from "./guard";
import { shieldOpenAI } from "./openai";

export interface ShieldGroqOptions extends ShieldProviderOptions {}

export function shieldGroq<
  T extends { chat: { completions: { create(...args: unknown[]): unknown } } },
>(client: T, options: ShieldGroqOptions = {}): T {
  return shieldOpenAI(client, options);
}
