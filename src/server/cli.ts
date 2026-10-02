import { assertCudaValidation } from "./cuda-validation";
import {
  createLocalClassifier,
  createShieldServer,
  loadArtifactManifest,
  type ShieldServerOptions,
} from "./index";
import { InferenceGate } from "./inference-gate";
import { createModelProcess } from "./model-process";

function positiveInteger(
  name: string,
  fallback: number,
  maximum: number
): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error("Invalid server configuration");
  }
  return value;
}

function capacityOptions(): Omit<
  ShieldServerOptions,
  "classifier" | "bearerToken"
> {
  return {
    concurrency: Number(process.env.SHIELD_CONCURRENCY ?? 1),
    gpuConcurrency: Number(process.env.SHIELD_GPU_CONCURRENCY ?? 1),
    maxQueue: Number(process.env.SHIELD_MAX_QUEUE ?? 8),
    queueTimeoutMs: Number(process.env.SHIELD_QUEUE_TIMEOUT_MS ?? 5000),
    requestTimeoutMs: Number(process.env.SHIELD_REQUEST_TIMEOUT_MS ?? 24_000),
    uploadTimeoutMs: Number(process.env.SHIELD_UPLOAD_TIMEOUT_MS ?? 5000),
    maxUploads: Number(process.env.SHIELD_MAX_UPLOADS ?? 16),
  };
}

async function main(): Promise<void> {
  const manifestPath = process.env.SHIELD_ARTIFACT_MANIFEST;
  const bearerToken = process.env.SHIELD_PRIVATE_TOKEN;
  const pythonPath = process.env.SHIELD_TOKENIZER_PYTHON;
  if (!(manifestPath && pythonPath && bearerToken) || bearerToken.length < 32) {
    throw new Error("Missing manifest or private token");
  }
  const pool = process.env.SHIELD_POOL ?? "paid";
  const largeDevice = process.env.SHIELD_LARGE_DEVICE ?? "cpu";
  if (
    (pool !== "free" && pool !== "paid") ||
    (largeDevice !== "cpu" && largeDevice !== "cuda") ||
    (pool === "free" && largeDevice !== "cpu")
  ) {
    throw new Error("Invalid serving pool or device");
  }
  const manifest = await loadArtifactManifest(manifestPath, { pool });
  if (largeDevice === "cuda") {
    if (process.env.NVIDIA_TF32_OVERRIDE !== "0") {
      throw new Error("CUDA serving requires full-precision matmul settings");
    }
    await assertCudaValidation(
      process.env.SHIELD_CUDA_VALIDATION_REPORT,
      manifest
    );
  }
  const threads = positiveInteger("SHIELD_THREADS", 2, 256);
  const port = positiveInteger("SHIELD_PORT", 8789, 65_535);
  const healthPort = positiveInteger("SHIELD_HEALTH_PORT", 8790, 65_535);
  if (healthPort === port) {
    throw new Error("The readiness listener requires its own port");
  }
  const cpuGates = {
    direct: new InferenceGate(),
    ensemble: new InferenceGate(),
  };
  const classifier = await createLocalClassifier(manifest, {
    threads,
    pythonPath,
    pool,
    largeDevice,
    warmup: true,
    createModel: (model, lane) =>
      createModelProcess({
        model,
        pythonPath,
        worker: new URL("./model-worker.ts", import.meta.url),
        gate: model.device === "cuda" ? undefined : cpuGates[lane],
      }),
  });
  const server = createShieldServer({
    classifier,
    bearerToken,
    ...capacityOptions(),
  });
  // The default binding cannot receive public traffic. Private network use is explicit.
  const bind = process.env.SHIELD_BIND ?? "127.0.0.1";
  server.listen(port, bind);
  server.readiness.listen(healthPort, bind);
  let stopping = false;
  const stop = async (): Promise<void> => {
    if (stopping) {
      return;
    }
    stopping = true;
    await server.drain();
    await classifier.close?.();
    server.close();
    server.readiness.close();
  };
  const onStop = (): void => {
    stop().catch(() => {
      process.exitCode = 1;
    });
  };
  process.once("SIGTERM", onStop);
  process.once("SIGINT", onStop);
}

main().catch(() => {
  process.stderr.write(
    "Shield private server failed to start; verify local artifacts and configuration.\n"
  );
  process.exitCode = 1;
});
