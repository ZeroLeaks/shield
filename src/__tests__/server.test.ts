import { once } from "node:events";
import { Agent, request as httpRequest, type Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { LocalClassifier } from "../server/classifier";
import {
  createShieldServer,
  type ShieldHttpServer,
  type ShieldServerOptions,
} from "../server/http";

const TOKEN = "private-test-token-with-at-least-32-characters";
const RESULT = {
  score: 0.25,
  flagged: false,
  rules: false,
  input_tokens: 3,
  coverage: { truncated: false, windows: 1, max_windows: 32 },
};
const servers: Server[] = [];

function deferred() {
  let resolve = (): void => undefined;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function latestServer(): ShieldHttpServer {
  const [server] = servers.slice(-1);
  return server as ShieldHttpServer;
}

async function metrics(url: string) {
  return await (
    await fetch(`${url}/metrics`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    })
  ).json();
}

async function serve(
  classifier: LocalClassifier,
  options: Omit<ShieldServerOptions, "classifier" | "bearerToken"> = {}
): Promise<string> {
  const server = createShieldServer({
    classifier,
    bearerToken: TOKEN,
    ...options,
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("No test server address");
  }
  return `http://127.0.0.1:${address.port}`;
}
function post(url: string, body: unknown, token = TOKEN): Promise<Response> {
  return fetch(`${url}/classify`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          server.closeAllConnections();
          server.close(() => resolve());
        })
    )
  );
});

describe("private inference HTTP boundary", () => {
  it("frames JSON with its UTF-8 byte length", async () => {
    const revision = "révision–東京";
    const url = await serve({
      revision,
      classify: async () => RESULT,
    });
    const response = await fetch(`${url}/healthz`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(Number(response.headers.get("content-length"))).toBe(
      Buffer.byteLength(body)
    );
    expect(response.headers.has("transfer-encoding")).toBe(false);
    expect(JSON.parse(body)).toEqual({
      status: "ok",
      model_revision: revision,
    });
  });

  it("keeps backend connections reusable beyond the former five-second idle limit", async () => {
    const url = await serve({
      revision: "revision",
      classify: async () => RESULT,
    });
    expect(latestServer().keepAliveTimeout).toBeGreaterThan(40_000);
    const agent = new Agent({ keepAlive: true, maxSockets: 1 });
    const read = () =>
      new Promise<boolean>((resolve, reject) => {
        const request = httpRequest(
          `${url}/healthz`,
          { agent, headers: { authorization: `Bearer ${TOKEN}` } },
          (response) => {
            response.on("error", reject);
            response.resume();
            response.once("end", () => resolve(request.reusedSocket));
          }
        );
        request.on("error", reject);
        request.end();
      });
    try {
      expect(await read()).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 7000));
      expect(await read()).toBe(true);
    } finally {
      agent.destroy();
    }
  }, 12_000);

  it("rejects malformed UTF-8 without passing replacement text to the model", async () => {
    const classify = vi.fn(async () => RESULT);
    const url = await serve({ revision: "revision", classify });
    const response = await fetch(`${url}/classify`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
      },
      body: Buffer.concat([
        Buffer.from('{"model":"shield","input":["'),
        Buffer.from([0xff]),
        Buffer.from('"]}'),
      ]),
    });
    expect(response.status).toBe(400);
    expect(classify).not.toHaveBeenCalled();
  });

  it("keeps CPU requests available while the GPU lane is busy", async () => {
    const held = deferred();
    const started = deferred();
    const url = await serve(
      {
        revision: "revision",
        classify: async (model) => {
          if (model === "shield-large") {
            started.resolve();
            await held.promise;
          }
          return RESULT;
        },
      },
      { maxQueue: 0 }
    );
    const large = post(url, {
      model: "shield-large",
      input: ["private marker"],
    });
    await started.promise;
    expect(
      (await post(url, { model: "shield-base", input: ["ordinary text"] }))
        .status
    ).toBe(200);
    const state = await metrics(url);
    expect(state.lanes.cpu.completed).toBe(1);
    expect(state.lanes.gpu.active).toBe(1);
    expect(JSON.stringify(state)).not.toContain("private marker");
    expect(JSON.stringify(state)).not.toContain(TOKEN);
    held.resolve();
    expect((await large).status).toBe(200);
  });

  it("a free-only process rejects paid models before invoking the classifier", async () => {
    const classify = vi.fn(async () => RESULT);
    const url = await serve({
      revision: "revision",
      models: ["shield"],
      classify,
    });
    expect(
      (await post(url, { model: "shield-base", input: ["text"] })).status
    ).toBe(403);
    expect(classify).not.toHaveBeenCalled();
  });

  it("expires slow uploads without occupying an execution slot", async () => {
    const classify = vi.fn(async () => RESULT);
    const url = await serve(
      { revision: "revision", classify },
      { uploadTimeoutMs: 80, maxUploads: 2 }
    );
    const uploading = deferred();
    const slowResponse = new Promise<number>((resolve, reject) => {
      const slow = httpRequest(
        `${url}/classify`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${TOKEN}`,
            "content-type": "application/json",
            "transfer-encoding": "chunked",
          },
        },
        (response) => {
          response.resume();
          resolve(response.statusCode ?? 0);
        }
      );
      slow.on("error", reject);
      slow.write('{"model":"shield","input":["', () => uploading.resolve());
    });
    await uploading.promise;
    expect(
      (await post(url, { model: "shield", input: ["complete request"] })).status
    ).toBe(200);
    expect(await slowResponse).toBe(408);
    expect(classify).toHaveBeenCalledTimes(1);
  });

  it("returns a deadline error while retaining capacity until native work finishes", async () => {
    const held = deferred();
    const started = deferred();
    const classify = vi.fn(async () => {
      started.resolve();
      await held.promise;
      return RESULT;
    });
    const url = await serve(
      { revision: "revision", classify },
      { requestTimeoutMs: 40, maxQueue: 0 }
    );
    const active = post(url, {
      model: "shield",
      input: ["first", "must not run"],
    });
    await started.promise;
    expect((await active).status).toBe(504);
    expect((await metrics(url)).lanes.cpu.active).toBe(1);
    expect(
      (await post(url, { model: "shield", input: ["rejected"] })).status
    ).toBe(503);
    held.resolve();
    await vi.waitFor(async () =>
      expect((await metrics(url)).lanes.cpu.active).toBe(0)
    );
    expect(classify).toHaveBeenCalledTimes(1);
  });

  it("drains queued work, waits for active inference, and removes readiness immediately", async () => {
    const held = deferred();
    const started = deferred();
    const classify = vi.fn(async () => {
      started.resolve();
      await held.promise;
      return RESULT;
    });
    const url = await serve({
      revision: "revision",
      ready: () => true,
      classify,
    });
    const server = latestServer();
    server.readiness.listen(0, "127.0.0.1");
    servers.push(server.readiness);
    await once(server.readiness, "listening");
    const address = server.readiness.address();
    if (!address || typeof address === "string") {
      throw new Error("Missing readiness address");
    }
    const readiness = `http://127.0.0.1:${address.port}/readyz`;
    expect((await fetch(readiness)).status).toBe(200);
    const active = post(url, { model: "shield", input: ["active"] });
    await started.promise;
    const queued = post(url, { model: "shield", input: ["queued"] });
    await vi.waitFor(async () =>
      expect((await metrics(url)).lanes.cpu.queued).toBe(1)
    );
    let drained = false;
    const draining = server.drain().then(() => {
      drained = true;
    });
    expect((await fetch(readiness)).status).toBe(503);
    expect((await queued).status).toBe(503);
    expect((await post(url, { model: "shield", input: ["new"] })).status).toBe(
      503
    );
    expect(drained).toBe(false);
    held.resolve();
    expect((await active).status).toBe(200);
    await draining;
    expect(drained).toBe(true);
    expect(classify).toHaveBeenCalledTimes(1);
  });

  it("unhealthy models fail health and classification without exposing runtime errors", async () => {
    const classify = vi.fn(async () => RESULT);
    const url = await serve({
      revision: "revision",
      ready: () => false,
      classify,
    });
    expect(
      (
        await fetch(`${url}/healthz`, {
          headers: { authorization: `Bearer ${TOKEN}` },
        })
      ).status
    ).toBe(503);
    expect((await post(url, { model: "shield", input: ["text"] })).status).toBe(
      503
    );
    expect(classify).not.toHaveBeenCalled();
  });

  it("requires private authentication for both inference and health", async () => {
    const classify = vi.fn(async () => RESULT);
    const url = await serve({ revision: "revision", classify });
    expect((await fetch(`${url}/healthz`)).status).toBe(401);
    expect(
      (await post(url, { model: "shield", input: ["hello"] }, "bad")).status
    ).toBe(401);
    expect(classify).not.toHaveBeenCalled();
    const health = await fetch(`${url}/healthz`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(await health.json()).toEqual({
      status: "ok",
      model_revision: "revision",
    });
  });

  it("validates batches, size, and model before inference", async () => {
    const classify = vi.fn(async () => RESULT);
    const url = await serve(
      { revision: "revision", classify },
      { maxBodyBytes: 256, maxInputLength: 10, maxBatchSize: 2 }
    );
    for (const body of [
      { model: "unknown", input: ["text"] },
      { model: "shield", input: [3] },
      { model: "shield", input: ["\ud800"] },
      { model: "shield", input: [] },
      { model: "shield", input: ["12345678901"] },
      { model: "shield", input: ["a", "b", "c"] },
    ]) {
      expect((await post(url, body)).status).toBe(400);
    }
    expect(
      (await post(url, { model: "shield", input: ["x".repeat(300)] })).status
    ).toBe(413);
    expect(classify).not.toHaveBeenCalled();
  });

  it("preserves batch order and separate model and rule scores", async () => {
    const classify = vi.fn(async (_model, text) => ({
      ...RESULT,
      score: text === "first" ? 0.1 : 0.8,
      flagged: true,
      rules: text === "first",
    }));
    const url = await serve({ revision: "revision", classify });
    const response = await post(url, {
      model: "shield-large",
      input: ["first", "second"],
    });
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.json();
    expect(
      body.results.map((result: { score: number }) => result.score)
    ).toEqual([0.1, 0.8]);
    expect(classify.mock.calls.map((call) => call[0])).toEqual([
      "shield-large",
      "shield-large",
    ]);
  });

  it("bounds the queue and releases capacity after a model failure", async () => {
    let finish: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      finish = resolve;
    });
    let signalStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const classify = vi.fn(async () => {
      if (classify.mock.calls.length === 1) {
        signalStarted?.();
        await held;
        throw new Error("private input must never appear in an error");
      }
      return RESULT;
    });
    const url = await serve(
      { revision: "revision", classify },
      { concurrency: 1, maxQueue: 0 }
    );
    const first = post(url, { model: "shield", input: ["private text"] });
    await started;
    expect(
      (await post(url, { model: "shield", input: ["queued"] })).status
    ).toBe(503);
    finish?.();
    const failed = await first;
    expect(await failed.json()).toEqual({
      error: { code: "inference_failed" },
    });
    expect((await post(url, { model: "shield", input: ["next"] })).status).toBe(
      200
    );
  });

  it("expires queued requests without running their inference", async () => {
    let release: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let signalStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const classify = vi.fn(async () => {
      signalStarted?.();
      await held;
      return RESULT;
    });
    const url = await serve(
      { revision: "revision", classify },
      { concurrency: 1, maxQueue: 1, queueTimeoutMs: 20 }
    );
    const active = post(url, { model: "shield", input: ["first"] });
    await started;
    const queued = await post(url, { model: "shield", input: ["second"] });
    expect(queued.status).toBe(503);
    expect(await queued.json()).toEqual({ error: { code: "queue_timeout" } });
    expect(classify).toHaveBeenCalledTimes(1);
    release?.();
    expect((await active).status).toBe(200);
  });

  it("removes disconnected queued requests without running inference", async () => {
    let release: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let signalStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const classify = vi.fn(async (_model, text) => {
      if (text === "first") {
        signalStarted?.();
        await held;
      }
      return RESULT;
    });
    const url = await serve(
      { revision: "revision", classify },
      { concurrency: 1, maxQueue: 1 }
    );
    const active = post(url, { model: "shield", input: ["first"] });
    await started;
    const [server] = servers.slice(-1);
    if (!server) {
      throw new Error("Missing test server");
    }
    const received = once(server, "request");
    const controller = new AbortController();
    const queued = fetch(`${url}/classify`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ model: "shield", input: ["cancelled"] }),
      signal: controller.signal,
    }).catch((error: unknown) => error);
    await received;
    controller.abort();
    await queued;
    // Observe the close event on the server before testing the recovered queue slot.
    await new Promise((resolve) => setTimeout(resolve, 20));
    const receivedNext = once(server, "request");
    const next = post(url, { model: "shield", input: ["next"] });
    await receivedNext;
    release?.();
    expect((await active).status).toBe(200);
    expect((await next).status).toBe(200);
    expect(classify.mock.calls.map((call) => call[1])).toEqual([
      "first",
      "next",
    ]);
  });

  it("finishes active native inference but skips remaining inputs after disconnect", async () => {
    let release: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    let signalStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    const classify = vi.fn(async () => {
      signalStarted?.();
      await held;
      return RESULT;
    });
    const url = await serve({ revision: "revision", classify });
    const controller = new AbortController();
    const active = fetch(`${url}/classify`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: "shield",
        input: ["first", "must not run"],
      }),
      signal: controller.signal,
    }).catch((error: unknown) => error);
    await started;
    controller.abort();
    await active;
    await new Promise((resolve) => setTimeout(resolve, 20));
    release?.();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(classify).toHaveBeenCalledTimes(1);
  });
});
