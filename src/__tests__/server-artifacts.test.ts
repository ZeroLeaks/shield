import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ARTIFACT_NAMES, loadArtifactManifest } from "../server/artifacts";

const roots: string[] = [];
const SHA256 = /^[a-f0-9]{64}$/;
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))
  );
});

async function fixture(): Promise<{ manifest: string; root: string }> {
  const root = await mkdtemp(join(tmpdir(), "shield-artifacts-"));
  roots.push(root);
  const artifacts: Record<
    string,
    { path: string; files: Record<string, string> }
  > = {};
  for (const name of ARTIFACT_NAMES) {
    const path = join(root, name);
    await mkdir(join(path, "onnx"), { recursive: true });
    const files: Record<string, string> = {};
    for (const file of [
      "config.json",
      "tokenizer.json",
      "tokenizer_config.json",
      name === "l7a-q4" ? "onnx/model_q4.onnx" : "onnx/model_quantized.onnx",
    ]) {
      const content = `fixture-${name}-${file}`;
      await writeFile(join(path, file), content);
      files[file] = createHash("sha256").update(content).digest("hex");
    }
    artifacts[name] = { path, files };
  }
  const manifest = join(root, "manifest.json");
  await writeFile(manifest, JSON.stringify({ version: 1, artifacts }));
  return { manifest, root };
}

describe("local artifact manifest", () => {
  it("checks every model/tokenizer file before accepting the release", async () => {
    const files = await fixture();
    const manifest = await loadArtifactManifest(files.manifest);
    expect(manifest.revision).toMatch(SHA256);
    expect(Object.keys(manifest.artifacts)).toEqual(["s15e", "sb1", "l7a-q4"]);
    await writeFile(
      join(files.root, "sb1", "onnx/model_quantized.onnx"),
      "changed-weights"
    );
    await expect(loadArtifactManifest(files.manifest)).rejects.toThrow(
      "Artifact checksum mismatch"
    );
  });
  it("fails when an artifact is missing and rejects remote manifest paths", async () => {
    const files = await fixture();
    await rm(join(files.root, "l7a-q4", "tokenizer.json"));
    await expect(loadArtifactManifest(files.manifest)).rejects.toThrow();
    await expect(
      loadArtifactManifest("https://example.invalid/manifest.json")
    ).rejects.toThrow("absolute path");
  });
  it("free replicas neither read nor require paid artifact files", async () => {
    const files = await fixture();
    const paid = await loadArtifactManifest(files.manifest);
    await rm(join(files.root, "sb1"), { recursive: true });
    await rm(join(files.root, "l7a-q4"), { recursive: true });
    const free = await loadArtifactManifest(files.manifest, { pool: "free" });
    expect(Object.keys(free.artifacts)).toEqual(["s15e"]);
    expect(free.revision).toBe(paid.revision);
    await expect(loadArtifactManifest(files.manifest)).rejects.toThrow();
  });
  it("release identity ignores deployment paths and metadata order", async () => {
    const first = await fixture();
    const second = await fixture();
    const raw = JSON.parse(await readFile(second.manifest, "utf8"));
    raw.artifacts = Object.fromEntries(Object.entries(raw.artifacts).reverse());
    await writeFile(second.manifest, JSON.stringify(raw, null, 2));
    expect((await loadArtifactManifest(first.manifest)).revision).toBe(
      (await loadArtifactManifest(second.manifest)).revision
    );
  });
});
