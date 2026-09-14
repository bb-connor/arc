import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { generateText, stepCountIs } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { ChioProcessAgent, ProcessSuspendedError } from "@chio-protocol/ai-sdk-process";
import { ProcessClient } from "@chio-protocol/process";

process.umask(0o077);
const bootstrap = JSON.parse(fs.readFileSync(0, "utf8"));
const root = bootstrap.connection.process_id === "root";
const settings = root ? bootstrap.input : bootstrap.input.configuration;
const task = root ? { role: "coordinator" } : bootstrap.input.task;
const role = root ? "coordinator" : `researcher-${task.index}`;
const directory = settings.directory, attempt = bootstrap.attempt, processId = bootstrap.connection.process_id;

function persist(name, value) {
  const target = path.join(directory, name), temporary = target + ".tmp";
  const fd = fs.openSync(temporary, "w", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, target);
  const parent = fs.openSync(directory, "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
function append(name, value) {
  const fd = fs.openSync(path.join(directory, name), "a", 0o600);
  try { fs.writeSync(fd, JSON.stringify(value) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

persist(`${processId}-started-${attempt}.json`, { pid: process.pid, role, attempt, at: Date.now() });
if (root) persist(`started-${attempt}.json`, { pid: process.pid, attempt });

const client = new ProcessClient(bootstrap.connection.socket_path, bootstrap.connection.credential);
const invoke = client.invoke.bind(client);
client.invoke = async (key, server, tool, args) => {
  const started = performance.now();
  try { return await invoke(key, server, tool, args); }
  finally { append(`${processId}-calls.ndjson`, { role, attempt, key, tool, ms: performance.now() - started, at: Date.now() }); }
};

const tools = [...bootstrap.connection.tools];
if (settings.mode === "conflict" && role === "researcher-1") {
  // The model is offered a publication it is not authorized to make.
  tools.push({ name: "report__publish", server_id: "report", tool_name: "publish", description: "Append one checked report",
    input_schema: { type: "object", properties: { report: { type: "string" } }, required: ["report"], additionalProperties: false } });
}

const seen = new Map();
let receipts = 0;
async function onReceipt(event) {
  receipts++;
  append(`${processId}-receipts.ndjson`, event);
  if (receipts === 1) persist(`${processId}-first-receipt-${attempt}.json`, { at: Date.now() });
  const tool = event.tool.tool_name;
  seen.set(tool, (seen.get(tool) ?? 0) + 1);
  const matches = spec => spec && spec.role === role && spec.attempt === attempt && spec.tool === tool && seen.get(tool) === (spec.ordinal ?? 1);
  if (matches(settings.kill)) {
    persist(`${processId}-killed-${attempt}.json`, { tool, ordinal: seen.get(tool) });
    process.exit(77);
  }
  if ((settings.hang ?? []).some(matches)) {
    // Hold this durable point open until the harness interrupts the host.
    persist(`hang-${role}.json`, { pid: process.pid, tool, ordinal: seen.get(tool) });
    await new Promise(() => { setInterval(() => {}, 1000); });
  }
}

const provider = createOpenAICompatible({ name: "research-swarm", baseURL: settings.endpoint });
const prompt = JSON.stringify({
  instruction: root ? "Delegate the sources to researchers, join them, collect their findings and publish one checked report."
    : "Read each assigned source and send your findings.",
  task,
});
try {
  const result = await new ChioProcessAgent({
    client, model: provider.chatModel(role), tools, namespace: "research-swarm", threadId: "checked-report", turnId: role,
    modelKey: "research-swarm-v1", cooperativeChildren: true, onReceipt,
  }).run(bindings => generateText({ ...bindings, prompt, maxRetries: 0, stopWhen: stepCountIs(root ? 12 : 10) }));
  assert.equal(result.text, root ? "Published the checked report." : "Findings sent.");
  persist(`${processId}-result.json`, { role, text: result.text, attempt });
} catch (error) {
  if (error instanceof ProcessSuspendedError) {
    persist(`${processId}-suspended-${attempt}.json`, { exitCode: error.exitCode });
    if ((settings.hang ?? []).some(spec => spec.role === role && spec.attempt === attempt && spec.tool === undefined)) {
      persist(`hang-${role}.json`, { pid: process.pid, suspended: true });
      await new Promise(() => { setInterval(() => {}, 1000); });
    }
    process.exitCode = error.exitCode;
  } else {
    persist(`${processId}-failure-${attempt}.json`, { role, code: error.code ?? error.name, message: String(error.message).slice(0, 200) });
    process.exitCode = 2;
  }
}
