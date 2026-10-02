import { describe, expect, it } from "vitest";
import {
  assertCpuLayoutNodes,
  type CpuLayoutNode,
} from "../server/cuda-layout";
import { assertCudaPlacement } from "../server/cuda-validation";

const query: CpuLayoutNode = {
  node: "node_transpose_1",
  operator: "Transpose",
  inputs: [{ float: [1, 512, 16, 128] }],
  outputs: [{ float: [1, 16, 512, 128] }],
};

describe("reviewed Q4 CPU layout nodes", () => {
  it("accepts only the measured attention, rotary and pooling shapes", () => {
    const nodes = [
      query,
      {
        ...query,
        node: "node_transpose_2",
        inputs: [{ float: [1, 7, 8, 128] }],
        outputs: [{ float: [1, 8, 7, 128] }],
      },
      {
        ...query,
        node: "node_transpose_140",
        inputs: [{ float: [1, 16, 7, 128] }],
        outputs: [{ float: [1, 7, 16, 128] }],
      },
      {
        ...query,
        node: "Transpose",
        inputs: [{ float: [1, 128, 7] }],
        outputs: [{ float: [1, 7, 128] }],
      },
      {
        node: "node_Equal_4623",
        operator: "Equal",
        inputs: [{ int64: [1, 7] }, { int64: [] }],
        outputs: [{ bool: [1, 7] }],
      },
      {
        node: "node_argmax",
        operator: "ArgMax",
        inputs: [{ int32: [1, 7] }],
        outputs: [{ int64: [1] }],
      },
    ];
    expect(assertCpuLayoutNodes(nodes, 1).get("Transpose")).toBe(4);
  });

  it.each([
    { node: "unknown_transpose" },
    { node: "node_transpose_4" },
    { node: "node_transpose_141" },
    { node: "node_transpose_01" },
    { operator: "MatMul" },
    { inputs: [{ float: [2, 512, 16, 128] }] },
    { inputs: [{ float: [true, 512, 16, 128] }] },
    { inputs: [{ float: [1, 513, 16, 128] }] },
    { inputs: [{ float: [1, 512, 32, 128] }] },
    { outputs: [{ float: [1, 16, 511, 128] }] },
    { inputs: [{ float16: [1, 512, 16, 128] }] },
  ])("rejects a changed node, operation or tensor role %j", (override) => {
    expect(() =>
      assertCpuLayoutNodes([{ ...query, ...override }], 1)
    ).toThrow();
  });

  it("limits each named CPU node to one execution per window", () => {
    expect(() => assertCpuLayoutNodes([query, query], 1)).toThrow();
    expect(assertCpuLayoutNodes([query, query], 2).get("Transpose")).toBe(2);
  });

  it("requires node evidence to account for every CPU transpose", () => {
    const placement = [
      {
        provider: "CUDAExecutionProvider",
        operator: "MatMulNBits",
        executions: 197,
      },
      {
        provider: "CPUExecutionProvider",
        operator: "Transpose",
        executions: 2,
      },
    ];
    expect(() => assertCudaPlacement(placement, [query], 1)).toThrow();
    placement[1].executions = 1;
    expect(() => assertCudaPlacement(placement, [query], 1)).not.toThrow();
  });
});
