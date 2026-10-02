import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import type { ArtifactManifest } from "./artifacts";
import { assertCpuLayoutNodes } from "./cuda-layout";

const ALLOWED_CPU_OPERATORS = new Set([
  "GatherBlockQuantized",
  "Shape",
  "Size",
  "Gather",
  "Unsqueeze",
  "Squeeze",
  "Concat",
  "Cast",
  "Reshape",
  "Slice",
  "ConstantOfShape",
  "Range",
  "Expand",
  "Identity",
]);

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Require the boot-time kernel check for the exact Q4 file before accepting traffic. */
export async function assertCudaValidation(
  path: string | undefined,
  manifest: ArtifactManifest
): Promise<void> {
  if (!(path && isAbsolute(path))) {
    throw new Error("CUDA serving requires its local validation report");
  }
  const value: unknown = JSON.parse(await readFile(path, "utf8"));
  const hash = manifest.artifacts["l7a-q4"]?.files["onnx/model_q4.onnx"];
  if (
    !record(value) ||
    value.passed !== true ||
    value.onnxruntime_version !== "1.21.0" ||
    value.cuda_window_batch !== 1 ||
    value.tf32_disabled !== true ||
    value.placement_policy !== "cuda-arithmetic-cpu-reviewed-layout-v2" ||
    value.model_sha256 !== hash ||
    !hash ||
    typeof value.tolerance !== "number" ||
    value.tolerance <= 0 ||
    value.tolerance > 0.000_01 ||
    !Array.isArray(value.comparisons) ||
    value.comparisons.length < 6 ||
    !Array.isArray(value.operator_placement)
  ) {
    throw new Error(
      "CUDA validation does not match the approved runtime and artifact"
    );
  }
  let windows = 0;
  for (const comparison of value.comparisons) {
    if (
      !record(comparison) ||
      typeof comparison.max_window_delta !== "number" ||
      !Number.isFinite(comparison.max_window_delta) ||
      comparison.max_window_delta < 0 ||
      comparison.max_window_delta > value.tolerance ||
      typeof comparison.windows !== "number" ||
      !Number.isSafeInteger(comparison.windows) ||
      comparison.windows < 1 ||
      comparison.windows > 16
    ) {
      throw new Error("CUDA validation contains an invalid parity result");
    }
    windows += comparison.windows;
  }
  assertCudaPlacement(
    value.operator_placement,
    value.cpu_layout_nodes,
    windows
  );
  const node = value.node_validation;
  if (
    !record(node) ||
    node.passed !== true ||
    node.onnxruntime_version !== "1.21.0" ||
    node.model_sha256 !== hash ||
    node.cuda_window_batch !== 1 ||
    !Array.isArray(node.comparisons) ||
    node.comparisons.length !== value.comparisons.length
  ) {
    throw new Error("CUDA serving requires matching Node runtime evidence");
  }
  for (const comparison of node.comparisons) {
    if (
      !record(comparison) ||
      typeof comparison.absolute_delta !== "number" ||
      !Number.isFinite(comparison.absolute_delta) ||
      comparison.absolute_delta < 0 ||
      comparison.absolute_delta > value.tolerance ||
      comparison.verdict_match !== true
    ) {
      throw new Error("Node CUDA parity validation failed");
    }
  }
  assertCudaPlacement(node.operator_placement, node.cpu_layout_nodes, windows);
}

export function assertCudaPlacement(
  value: unknown,
  layout: unknown,
  windows: number
): void {
  if (!Array.isArray(value)) {
    throw new Error("CUDA operator placement evidence is missing");
  }
  const layoutCounts = assertCpuLayoutNodes(layout, windows);
  let gpuMatmul = false;
  for (const placement of value) {
    if (
      !record(placement) ||
      (placement.provider !== "CPUExecutionProvider" &&
        placement.provider !== "CUDAExecutionProvider") ||
      typeof placement.operator !== "string" ||
      typeof placement.executions !== "number" ||
      !Number.isSafeInteger(placement.executions) ||
      placement.executions <= 0
    ) {
      throw new Error("CUDA validation contains invalid operator evidence");
    }
    if (
      placement.provider === "CPUExecutionProvider" &&
      !ALLOWED_CPU_OPERATORS.has(placement.operator)
    ) {
      if (layoutCounts.get(placement.operator) !== placement.executions) {
        throw new Error(
          "CUDA validation recorded CPU fallback for model compute"
        );
      }
      layoutCounts.delete(placement.operator);
    }
    gpuMatmul ||=
      placement.provider === "CUDAExecutionProvider" &&
      placement.operator === "MatMulNBits";
  }
  if (!gpuMatmul) {
    throw new Error("CUDA validation did not observe quantized GPU compute");
  }
  if (layoutCounts.size > 0) {
    throw new Error("CPU layout evidence does not match operator totals");
  }
}
