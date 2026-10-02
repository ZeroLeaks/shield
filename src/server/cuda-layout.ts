export interface CpuLayoutNode {
  node: string;
  operator: string;
  inputs: unknown;
  outputs: unknown;
}

const TRANSPOSE_NODE = /^node_transpose_([1-9]\d*)$/;

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function shape(value: unknown, type: string): number[] | undefined {
  if (!(Array.isArray(value) && record(value[0]))) {
    return;
  }
  const dimensions = value[0][type];
  return Array.isArray(dimensions) && dimensions.every(Number.isSafeInteger)
    ? dimensions
    : undefined;
}

function matches(value: unknown, expected: unknown): boolean {
  return JSON.stringify(value) === JSON.stringify(expected);
}

function transposeShapes(
  node: string,
  inputs: unknown
): [number[], number[]] | undefined {
  const dimensions = shape(inputs, "float");
  if (!dimensions) {
    return;
  }
  if (node === "Transpose") {
    const width = dimensions[2];
    return [
      [1, 128, width],
      [1, width, 128],
    ];
  }
  const match = TRANSPOSE_NODE.exec(node);
  const index = match ? Number(match[1]) : 0;
  if (index < 1 || index > 140 || index % 5 === 4) {
    return;
  }
  if (index % 5 === 0) {
    const width = dimensions[2];
    return [
      [1, 16, width, 128],
      [1, width, 16, 128],
    ];
  }
  const width = dimensions[1];
  const heads = index % 5 === 1 ? 16 : 8;
  return [
    [1, width, heads, 128],
    [1, heads, width, 128],
  ];
}

/** Only the reviewed Q4 graph's bounded layout copies and token-pooling indices. */
function reviewedNode(value: CpuLayoutNode): boolean {
  if (value.operator === "Transpose") {
    const expected = transposeShapes(value.node, value.inputs);
    return Boolean(
      expected?.[0].every(
        (dimension) =>
          Number.isSafeInteger(dimension) && dimension >= 1 && dimension <= 512
      ) &&
        matches(value.inputs, [{ float: expected[0] }]) &&
        matches(value.outputs, [{ float: expected[1] }])
    );
  }
  const type = value.operator === "Equal" ? "int64" : "int32";
  const width = shape(value.inputs, type)?.[1];
  if (!(Number.isSafeInteger(width) && width) || width < 1 || width > 512) {
    return false;
  }
  if (value.operator === "Equal" && value.node === "node_Equal_4623") {
    return (
      matches(value.inputs, [{ int64: [1, width] }, { int64: [] }]) &&
      matches(value.outputs, [{ bool: [1, width] }])
    );
  }
  return (
    value.operator === "ArgMax" &&
    value.node === "node_argmax" &&
    matches(value.inputs, [{ int32: [1, width] }]) &&
    matches(value.outputs, [{ int64: [1] }])
  );
}

export function assertCpuLayoutNodes(
  value: unknown,
  windows: number
): Map<string, number> {
  if (
    !(Array.isArray(value) && Number.isSafeInteger(windows)) ||
    windows < 1 ||
    value.length > windows * 115
  ) {
    throw new Error("Missing or excessive CPU layout evidence");
  }
  const nodes = new Map<string, number>();
  const operators = new Map<string, number>();
  for (const item of value) {
    if (
      !record(item) ||
      typeof item.node !== "string" ||
      typeof item.operator !== "string" ||
      !reviewedNode({
        node: item.node,
        operator: item.operator,
        inputs: item.inputs,
        outputs: item.outputs,
      })
    ) {
      throw new Error("Unreviewed CPU layout node or tensor shape");
    }
    const executions = (nodes.get(item.node) ?? 0) + 1;
    if (executions > windows) {
      throw new Error("CPU layout node exceeded one execution per window");
    }
    nodes.set(item.node, executions);
    operators.set(item.operator, (operators.get(item.operator) ?? 0) + 1);
  }
  return operators;
}
