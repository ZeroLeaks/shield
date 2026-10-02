import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ArtifactManifest } from "../server/artifacts";
import { assertCudaValidation } from "../server/cuda-validation";

const roots: string[] = [];
const hash = "a".repeat(64);
const manifest: ArtifactManifest = {
  version: 1,
  revision: "reference",
  artifacts: {
    s15e: { path: "/models/s15e", files: {} },
    "l7a-q4": { path: "/models/l7a", files: { "onnx/model_q4.onnx": hash } },
  },
};
const report = {
  passed: true,
  onnxruntime_version: "1.21.0",
  model_sha256: hash,
  cuda_window_batch: 1,
  tf32_disabled: true,
  placement_policy: "cuda-arithmetic-cpu-reviewed-layout-v2",
  tolerance: 0.000_01,
  comparisons: Array.from({ length: 6 }, () => ({
    max_window_delta: 0.000_001,
    windows: 1,
  })),
  cpu_layout_nodes: [],
  operator_placement: [
    {
      provider: "CUDAExecutionProvider",
      operator: "MatMulNBits",
      executions: 18,
    },
    {
      provider: "CPUExecutionProvider",
      operator: "GatherBlockQuantized",
      executions: 6,
    },
  ],
  node_validation: {
    passed: true,
    onnxruntime_version: "1.21.0",
    model_sha256: hash,
    cuda_window_batch: 1,
    cpu_layout_nodes: [],
    comparisons: Array.from({ length: 6 }, () => ({
      absolute_delta: 0.000_001,
      verdict_match: true,
    })),
    operator_placement: [
      {
        provider: "CUDAExecutionProvider",
        operator: "MatMulNBits",
        executions: 18,
      },
      {
        provider: "CPUExecutionProvider",
        operator: "GatherBlockQuantized",
        executions: 6,
      },
    ],
  },
};

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function fixture(value: unknown): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "shield-cuda-check-"));
  roots.push(root);
  const path = join(root, "report.json");
  await writeFile(path, JSON.stringify(value));
  return path;
}

describe("CUDA startup evidence", () => {
  it("accepts bounded parity and observed GPU compute for the pinned file", async () => {
    await expect(
      assertCudaValidation(await fixture(report), manifest)
    ).resolves.toBeUndefined();
  });

  it.each([
    { model_sha256: "b".repeat(64) },
    { onnxruntime_version: "1.30.0" },
    { passed: false },
    { cuda_window_batch: 8 },
    { tf32_disabled: false },
    { placement_policy: "unspecified" },
    { tolerance: 0.1 },
    { comparisons: [{ max_window_delta: 0 }] },
    {
      comparisons: Array.from({ length: 6 }, () => ({
        max_window_delta: 0.001,
      })),
    },
    { operator_placement: [] },
    { node_validation: undefined },
    { node_validation: { ...report.node_validation, passed: false } },
    { node_validation: { ...report.node_validation, operator_placement: [] } },
    {
      node_validation: {
        ...report.node_validation,
        comparisons: Array.from({ length: 6 }, () => ({
          absolute_delta: 0.0001,
          verdict_match: true,
        })),
      },
    },
    {
      node_validation: {
        ...report.node_validation,
        comparisons: Array.from({ length: 6 }, () => ({
          absolute_delta: 0,
          verdict_match: false,
        })),
      },
    },
    {
      operator_placement: [
        ...report.operator_placement,
        {
          provider: "CPUExecutionProvider",
          operator: "MatMulNBits",
          executions: 1,
        },
      ],
    },
  ])("rejects incompatible or incomplete evidence %j", async (override) => {
    await expect(
      assertCudaValidation(await fixture({ ...report, ...override }), manifest)
    ).rejects.toThrow();
  });

  it("rejects missing and nonlocal reports", async () => {
    await expect(assertCudaValidation(undefined, manifest)).rejects.toThrow();
    await expect(
      assertCudaValidation("https://example.invalid/report", manifest)
    ).rejects.toThrow();
  });
});
