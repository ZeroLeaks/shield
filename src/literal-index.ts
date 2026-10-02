// biome-ignore-all lint/suspicious/noBitwiseOperators: automaton state indexing.

/**
 * Finds which of a fixed set of literals occur in a text, in one pass
 * (Aho-Corasick). Literals are lowercase letters and digits, so any other
 * character ends every match and the automaton restarts.
 */

const ALPHABET = 36;
const CHAR_INDEX = new Int8Array(128).fill(-1);
for (let c = 97; c <= 122; c++) {
  CHAR_INDEX[c] = c - 97;
}
for (let c = 48; c <= 57; c++) {
  CHAR_INDEX[c] = 26 + c - 48;
}

export interface LiteralIndex {
  /** Id of each literal, in insertion order. */
  ids: Map<string, number>;
  size: number;
  /** Sets `found[id]` to 1 for every literal that occurs in `text`. */
  scan(text: string, found: Uint8Array): void;
}

interface Trie {
  ids: Map<string, number>;
  goto: Int32Array[];
  outputs: number[][];
}

function buildTrie(literals: Iterable<string>): Trie {
  const ids = new Map<string, number>();
  const goto: Int32Array[] = [new Int32Array(ALPHABET).fill(-1)];
  const outputs: number[][] = [[]];
  for (const literal of literals) {
    if (ids.has(literal) || literal.length === 0) {
      continue;
    }
    const id = ids.size;
    ids.set(literal, id);
    let node = 0;
    for (let i = 0; i < literal.length; i++) {
      const a = CHAR_INDEX[literal.charCodeAt(i)] ?? -1;
      if (a < 0) {
        throw new Error(`literal index: unsupported character in ${literal}`);
      }
      if (goto[node][a] < 0) {
        goto[node][a] = goto.length;
        goto.push(new Int32Array(ALPHABET).fill(-1));
        outputs.push([]);
      }
      node = goto[node][a];
    }
    outputs[node].push(id);
  }
  return { ids, goto, outputs };
}

/**
 * Breadth-first over the trie: failure links, a full transition table, and
 * each node's outputs extended with those of its failure node.
 */
function buildTransitions({ goto, outputs }: Trie): Int32Array {
  const nodes = goto.length;
  const delta = new Int32Array(nodes * ALPHABET);
  const fail = new Int32Array(nodes);
  const queue: number[] = [];
  for (let a = 0; a < ALPHABET; a++) {
    const next = goto[0][a];
    delta[a] = next < 0 ? 0 : next;
    if (next > 0) {
      queue.push(next);
    }
  }
  for (const u of queue) {
    outputs[u].push(...outputs[fail[u]]);
    for (let a = 0; a < ALPHABET; a++) {
      const v = goto[u][a];
      if (v < 0) {
        delta[u * ALPHABET + a] = delta[fail[u] * ALPHABET + a];
      } else {
        fail[v] = delta[fail[u] * ALPHABET + a];
        delta[u * ALPHABET + a] = v;
        queue.push(v);
      }
    }
  }
  return delta;
}

export function buildLiteralIndex(literals: Iterable<string>): LiteralIndex {
  const trie = buildTrie(literals);
  const delta = buildTransitions(trie);

  // Outputs flattened into one array with per-node offsets.
  const nodes = trie.goto.length;
  const outStart = new Int32Array(nodes + 1);
  const flat: number[] = [];
  for (let n = 0; n < nodes; n++) {
    outStart[n] = flat.length;
    for (const id of new Set(trie.outputs[n])) {
      flat.push(id);
    }
  }
  outStart[nodes] = flat.length;
  const outIds = Int32Array.from(flat);

  return {
    ids: trie.ids,
    size: trie.ids.size,
    scan(text: string, found: Uint8Array): void {
      let state = 0;
      for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        const a = code < 128 ? CHAR_INDEX[code] : -1;
        if (a < 0) {
          state = 0;
          continue;
        }
        state = delta[state * ALPHABET + a];
        const end = outStart[state + 1];
        for (let k = outStart[state]; k < end; k++) {
          found[outIds[k]] = 1;
        }
      }
    },
  };
}
