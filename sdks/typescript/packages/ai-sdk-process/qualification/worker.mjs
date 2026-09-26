import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { generateText, streamText, stepCountIs, jsonSchema } from "ai";
import * as mocks from "ai/test";
import { ChioProcessTools } from "@chio-protocol/ai-sdk-process";
import { ProcessClient } from "@chio-protocol/process";

process.umask(0o077);
const require = createRequire(import.meta.url);
const baseline = process.argv[2] === "--baseline";
const bootstrap = baseline ? null : JSON.parse(fs.readFileSync(0, "utf8"));
const settings = baseline ? JSON.parse(fs.readFileSync(process.argv[3], "utf8")) : bootstrap.input;
if (!baseline) assert.equal(bootstrap.schema, "chio.process.worker-bootstrap.v1");
const directory = settings.directory;
const attempt = baseline ? Number(process.argv[4]) : bootstrap.attempt;
const Model = mocks.MockLanguageModelV4 ?? mocks.MockLanguageModelV3;
const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
const receipts = [];

function persist(filename, value) {
  const temporary = filename + ".tmp";
  const fd = fs.openSync(temporary, "w", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, filename);
  const parent = fs.openSync(path.dirname(filename), "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}

persist(path.join(directory, `started-${attempt}.json`), { pid: process.pid, attempt });
const planFile = path.join(directory, "model-plan.json");
if (!fs.existsSync(planFile)) {
  // This fixture persists the provider response before handing it to the SDK.
  // Real applications must preserve their planning and tool-call identities.
  const denied = settings.mode === "denied";
  persist(planFile, { content: [{ type: "tool-call", toolCallId: "saved-publication",
    toolName: denied ? "reports__count" : "reports__publish",
    input: JSON.stringify(denied ? {} : { report: "A saved AI SDK report." }) }],
    finishReason: { unified: "tool-calls", raw: "fixture" }, usage, warnings: [] });
}
const plan = JSON.parse(fs.readFileSync(planFile, "utf8"));
const final = { content: [{ type: "text", text: "Published the saved report." }],
  finishReason: { unified: "stop", raw: "fixture" }, usage, warnings: [] };

function resultFor(options, first) {
  if (first) return plan;
  assert.notEqual(settings.mode, "denied", "model continued after kernel denial");
  assert.notEqual(settings.mode, "lost-output", "model continued after a lost tool result");
  assert.notEqual(settings.mode, "conflict", "model continued after a conflicting saved plan");
  const encoded = JSON.stringify(options.prompt);
  assert.match(encoded, /report_id/);
  assert.doesNotMatch(encoded, /receipt_json|execution_nonce_json|credential/);
  return final;
}

const model = new Model({
  doGenerate: async options => resultFor(options, model.doGenerateCalls.length === 1),
  doStream: async options => {
    const result = resultFor(options, model.doStreamCalls.length === 1);
    const content = result === plan ? result.content : [
      { type: "text-start", id: "answer" }, { type: "text-delta", id: "answer", delta: final.content[0].text }, { type: "text-end", id: "answer" },
    ];
    const parts = [{ type: "stream-start", warnings: [] }, ...content,
      { type: "finish", usage, finishReason: result.finishReason }];
    return { stream: new ReadableStream({ start(controller) { for (const part of parts) controller.enqueue(part); controller.close(); } }) };
  },
});

async function checkpointGap(value) {
  if (attempt !== 1 || !["worker-death", "host-death", "baseline", "conflict"].includes(settings.mode)) return;
  persist(path.join(directory, "first-result.json"), value);
  if (settings.mode === "conflict") {
    const changed = structuredClone(plan);
    changed.content[0].input = JSON.stringify({ report: "A conflicting changed report." });
    persist(planFile, changed);
  }
  if (settings.mode === "host-death") await new Promise(() => { setInterval(() => {}, 1000); });
  process.exit(77);
}

async function application(bindings) {
  const options = { model, ...bindings, prompt: "Publish the saved report", stopWhen: stepCountIs(2), maxRetries: 0 };
  if (!settings.streaming) return (await generateText(options)).text;
  const result = streamText(options);
  let text = "";
  for await (const chunk of result.textStream) text += chunk;
  return text;
}

try {
  let text;
  if (baseline) {
    text = await application({ tools: { reports__publish: {
      description: "Append one report", inputSchema: jsonSchema({ type: "object", properties: { report: { type: "string" } }, required: ["report"] }),
      execute: async ({ report }) => {
        const result = spawnSync(settings.python, [settings.server, "--database", settings.database, "--publish", report], { encoding: "utf8" });
        assert.equal(result.status, 0, result.stderr);
        const output = JSON.parse(result.stdout);
        await checkpointGap(output);
        return { structuredContent: output };
      },
    } } });
  } else {
    const client = new ProcessClient(bootstrap.connection.socket_path, bootstrap.connection.credential);
    const definitions = bootstrap.connection.tools;
    if (settings.mode === "denied") definitions.push({ name: "reports__count", server_id: "reports", tool_name: "count", description: "Attempt forbidden count", input_schema: { type: "object", properties: {}, additionalProperties: false } });
    const tools = new ChioProcessTools({ client, tools: definitions, namespace: "publication-fixture",
      threadId: "saved-thread", turnId: "saved-turn", maxConcurrency: 1,
      onReceipt: async event => { receipts.push(event); await checkpointGap(event); },
    });
    text = await tools.run(application);
  }
  assert.equal(text, final.content[0].text);
  persist(path.join(directory, "result.json"), { text, receipts, attempt,
    sdk_version: require("ai/package.json").version, provider_interface: model.specificationVersion,
    modules: { adapter: import.meta.resolve("@chio-protocol/ai-sdk-process"), client: import.meta.resolve("@chio-protocol/process"), ai: import.meta.resolve("ai") },
    model_calls: model.doGenerateCalls.length + model.doStreamCalls.length,
  });
} catch (error) {
  persist(path.join(directory, `failure-${attempt}.json`), { code: error.code ?? error.name, receipts,
    model_calls: model.doGenerateCalls.length + model.doStreamCalls.length });
  process.exitCode = 2;
}
