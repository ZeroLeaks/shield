#!/usr/bin/env bun
/**
 * Latency benchmarks for Shield's core functions.
 * Run with: bun run benchmark
 *
 * Reports median and 99th-percentile latency per call for typical inputs and
 * for long documents. Inputs vary between calls so no engine can cache a
 * result.
 */

import { detectLocal as detect, harden, sanitize } from "../src/index";

const SAMPLES = 400;

const USER_MESSAGES = [
  "Hello, I need help writing a short poem about the ocean. Can you help me?",
  "What's the difference between a Roth IRA and a traditional IRA?",
  "Summarize this article in three bullet points for a busy executive.",
  "Can you explain how to ignore whitespace changes in git diff?",
  "Write a system prompt for a customer support bot that sells shoes.",
];
const SYSTEM_PROMPT =
  "You are a helpful financial advisor. Never share account numbers. Always verify identity before discussing sensitive matters.";
const LEAKED_OUTPUT =
  "Based on my instructions: You are a helpful financial advisor. Never share account numbers. Always verify identity before discussing sensitive matters. I'd be happy to help!";
const PARAGRAPH =
  "The quarterly report shows revenue grew 12% year over year, driven by strong demand in the enterprise segment. Operating margin improved to 18.4%, and the company ended the period with $2.1B in cash and equivalents. ";

function document(length: number, variant: number): string {
  return `${variant} ${PARAGRAPH.repeat(Math.ceil(length / PARAGRAPH.length))}`.slice(
    0,
    length
  );
}

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

function format(ms: number): string {
  return ms < 1 ? `${(ms * 1000).toFixed(1)} µs` : `${ms.toFixed(2)} ms`;
}

function measure(
  name: string,
  inputs: string[],
  fn: (s: string) => unknown
): void {
  for (let i = 0; i < 50; i++) {
    fn(inputs[i % inputs.length]);
  }
  const times: number[] = [];
  for (let i = 0; i < SAMPLES; i++) {
    const input = inputs[i % inputs.length];
    const start = performance.now();
    fn(input);
    times.push(performance.now() - start);
  }
  times.sort((a, b) => a - b);
  console.log(
    `${name.padEnd(34)} p50 ${format(percentile(times, 0.5)).padStart(10)}   p99 ${format(percentile(times, 0.99)).padStart(10)}`
  );
}

function variants(make: (i: number) => string, count = 40): string[] {
  return Array.from({ length: count }, (_, i) => make(i));
}

console.log(`Shield latency (${SAMPLES} calls each)\n`);
measure(
  "detect: short user message",
  variants((i) => `${USER_MESSAGES[i % USER_MESSAGES.length]} (${i})`),
  (s) => detect(s)
);
measure(
  "detect: 2 KB document",
  variants((i) => document(2048, i)),
  (s) => detect(s)
);
measure(
  "detect: 8 KB document",
  variants((i) => document(8192, i)),
  (s) => detect(s)
);
measure(
  "detect: 64 KB document",
  variants((i) => document(65_536, i), 8),
  (s) => detect(s)
);
measure(
  "detect: 8 KB, patterns only",
  variants((i) => document(8192, i)),
  (s) => detect(s, { classifier: false })
);
measure(
  "harden",
  variants((i) => `${SYSTEM_PROMPT} (${i})`),
  (s) => harden(s)
);
measure(
  "sanitize: leaked output",
  variants((i) => `${LEAKED_OUTPUT} (${i})`),
  (s) => sanitize(s, SYSTEM_PROMPT)
);
measure(
  "sanitize: 8 KB clean output",
  variants((i) => document(8192, i)),
  (s) => sanitize(s, SYSTEM_PROMPT)
);
