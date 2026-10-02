import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

export const ARTIFACT_NAMES = ["s15e", "sb1", "l7a-q4"] as const;
export type ArtifactName = (typeof ARTIFACT_NAMES)[number];
export type ServingPool = "free" | "paid";
export interface Artifact {
  path: string;
  files: Record<string, string>;
}
export interface ArtifactManifest {
  version: 1;
  pool?: ServingPool;
  artifacts: {
    s15e: Artifact;
    sb1?: Artifact;
    "l7a-q4"?: Artifact;
  };
  revision: string;
}
const SHA256 = /^[a-f0-9]{64}$/;

function releaseRevision(value: Record<string, unknown>): string {
  const hashes = Object.entries(value)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, item]) => {
      if (!(record(item) && record(item.files))) {
        throw new Error("Invalid artifact metadata");
      }
      const files = Object.entries(item.files).sort(([a], [b]) =>
        a.localeCompare(b)
      );
      if (
        files.some(([, hash]) => typeof hash !== "string" || !SHA256.test(hash))
      ) {
        throw new Error("Invalid artifact checksum metadata");
      }
      return [name, files];
    });
  return createHash("sha256")
    .update(JSON.stringify({ version: 1, artifacts: hashes }))
    .digest("hex");
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function checksum(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

async function validateArtifact(
  name: ArtifactName,
  item: unknown
): Promise<Artifact> {
  if (
    !record(item) ||
    typeof item.path !== "string" ||
    !isAbsolute(item.path) ||
    !record(item.files)
  ) {
    throw new Error(`Invalid local artifact: ${name}`);
  }
  const required = [
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    name === "l7a-q4" ? "onnx/model_q4.onnx" : "onnx/model_quantized.onnx",
  ];
  const files: Record<string, string> = {};
  for (const filename of required) {
    const expected = item.files[filename];
    if (typeof expected !== "string" || !SHA256.test(expected)) {
      throw new Error(`Missing checksum for ${name}/${filename}`);
    }
    const file = join(item.path, filename);
    if (!(await stat(file)).isFile() || (await checksum(file)) !== expected) {
      throw new Error(`Artifact checksum mismatch: ${name}/${filename}`);
    }
    files[filename] = expected;
  }
  return { path: item.path, files };
}

/** Validates every required local artifact before loading any model. No remote fallback. */
export async function loadArtifactManifest(
  path: string,
  options: { pool?: ServingPool } = {}
): Promise<ArtifactManifest> {
  if (!isAbsolute(path)) {
    throw new Error("SHIELD_ARTIFACT_MANIFEST must be an absolute path");
  }
  const raw = await readFile(path, "utf8");
  const value: unknown = JSON.parse(raw);
  if (!record(value) || value.version !== 1 || !record(value.artifacts)) {
    throw new Error("Invalid Shield artifact manifest");
  }
  const artifacts: Partial<Record<ArtifactName, Artifact>> = {};
  const pool = options.pool ?? "paid";
  const required: readonly ArtifactName[] =
    pool === "free" ? ["s15e"] : ARTIFACT_NAMES;
  for (const name of required) {
    artifacts[name] = await validateArtifact(name, value.artifacts[name]);
  }
  const { s15e, sb1, "l7a-q4": l7a } = artifacts;
  if (!s15e || (pool === "paid" && !(sb1 && l7a))) {
    throw new Error("Incomplete Shield artifact manifest");
  }
  return {
    version: 1,
    pool,
    artifacts: {
      s15e,
      ...(sb1 ? { sb1 } : {}),
      ...(l7a ? { "l7a-q4": l7a } : {}),
    },
    revision: releaseRevision(value.artifacts),
  };
}
