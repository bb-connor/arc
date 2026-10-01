import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { generateText, streamText, stepCountIs } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { ChioProcessAgent } from "@chio-protocol/ai-sdk-process";
import { ProcessClient } from "@chio-protocol/process";

process.umask(0o077);
const bootstrap = JSON.parse(fs.readFileSync(0, "utf8"));
const settings = bootstrap.input, directory = settings.directory, attempt = bootstrap.attempt;
const receipts = [];
function persist(name, value) {
  const file = path.join(directory, name), temporary = file + ".tmp";
  const fd = fs.openSync(temporary, "w", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
  const parent = fs.openSync(directory, "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
persist(`started-${attempt}.json`, { pid: process.pid, attempt });
const client = new ProcessClient(bootstrap.connection.socket_path, bootstrap.connection.credential);
const checkpoint = client.checkpoint.bind(client);
const metricsFile = path.join(directory, "checkpoint-metrics.json");
const metrics = fs.existsSync(metricsFile) ? JSON.parse(fs.readFileSync(metricsFile, "utf8")) : { writes: 0, bytesWritten: 0, maxBytes: 0 };
client.checkpoint = async (revision, value) => {
  const result = await checkpoint(revision, value), size = Buffer.byteLength(JSON.stringify(value));
  metrics.writes++; metrics.bytesWritten += size; metrics.maxBytes = Math.max(metrics.maxBytes, size);
  persist("checkpoint-metrics.json", metrics);
  return result;
};
const model = createOpenAICompatible({ name: "http-pressure", baseURL: settings.endpoint }).chatModel("fixture");
try {
  const result = await new ChioProcessAgent({ client, model, tools: bootstrap.connection.tools,
    namespace: "http-pressure", threadId: "read-thread", turnId: "read-turn", modelKey: "32-files-v1",
    responseStorage: settings.mode === "pressure-inline" ? "checkpoint" : "blobs",
    maxConcurrency: 1, onReceipt: async event => {
      receipts.push(event);
      if (attempt === 1 && receipts.length === 16 && ["pressure-worker-death", "pressure-host-death"].includes(settings.mode)) {
        persist("first-result.json", event);
        if (settings.mode === "pressure-host-death") await new Promise(() => { setInterval(() => {}, 1000); });
        process.exit(77);
      }
    },
  }).run(async bindings => {
    const options = { ...bindings, prompt: "Read the 32 fixture files in order", stopWhen: stepCountIs(34), maxRetries: 0, experimental_include: { requestBody: true } };
    if (settings.mode !== "pressure-host-death") return generateText(options);
    const result = streamText(options);
    await result.consumeStream({ onError: error => { throw error; } });
    return { text: await result.text, steps: await result.steps };
  });
  assert.equal(result.text, "Read all 32 files.");
  assert.equal(result.steps.length, 33);
  assert.ok(JSON.stringify(result.steps[16].request.body).includes("a".repeat(8192)), "retain the provider request body through recovery");
  assert.equal(receipts.length, 32);
  persist("result.json", { attempt, receipts, steps: result.steps.length, metrics, storage: (await client.inspect()).storage });
} catch (error) {
  persist(`failure-${attempt}.json`, { code: error.code ?? error.name, receipts, metrics, storage: (await client.inspect()).storage });
  process.exitCode = 2;
}
