import { spawn } from "node:child_process";
import { setImmediate as immediate } from "node:timers/promises";

const requests = new Map();
const gates = new Map();
let nextGate = 0;
let descendant;

async function score(id, input) {
  const request = { cancelled: false };
  requests.set(id, request);
  const gateId = ++nextGate;
  const granted = await new Promise((resolve) => {
    gates.set(gateId, resolve);
    process.send({ type: "acquire", id, gateId });
  });
  if (!granted) {
    process.send({ type: "error", id, cancelled: true });
    requests.delete(id);
    return;
  }
  if (!request.cancelled) {
    if (input === "crash") {
      process.exit(1);
    }
    if (input === "block") {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 400);
    }
    if (input === "descendant") {
      descendant = spawn(
        process.execPath,
        ["-e", "setInterval(() => {}, 1000)"],
        {
          stdio: "ignore",
        }
      );
    }
  }
  process.send({ type: "release", gateId });
  await immediate();
  if (request.cancelled) {
    process.send({ type: "error", id, cancelled: true });
  } else {
    process.send({
      type: "result",
      id,
      result: {
        score: input === "invalid" ? 5 : 0.25,
        inputTokens: input === "descendant" ? descendant.pid : 7,
        coverage: { truncated: true, windows: 2, maxWindows: 32 },
      },
    });
  }
  requests.delete(id);
}

process.on("message", (message) => {
  switch (message.type) {
    case "init":
      if (message.options.model === "fatal-then-ready") {
        process.send({ type: "fatal" });
      }
      process.send({ type: "ready" });
      break;
    case "score":
      score(message.id, message.input);
      break;
    case "cancel":
      if (requests.has(message.id)) {
        requests.get(message.id).cancelled = true;
      }
      break;
    case "grant":
      gates.get(message.gateId)?.(true);
      gates.delete(message.gateId);
      break;
    case "deny":
      gates.get(message.gateId)?.(false);
      gates.delete(message.gateId);
      break;
    case "close":
      process.disconnect();
      break;
    default:
      process.exit(1);
  }
});
