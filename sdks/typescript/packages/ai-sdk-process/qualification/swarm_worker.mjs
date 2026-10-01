import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { generateText, stepCountIs } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { ChioProcessAgent, ProcessSuspendedError } from "@chio-protocol/ai-sdk-process";
import { ProcessClient } from "@chio-protocol/process";

process.umask(0o077);
const bootstrap = JSON.parse(fs.readFileSync(0, "utf8"));
const root = bootstrap.connection.process_id === "root";
const settings = root ? bootstrap.input : bootstrap.input.configuration;
const task = root ? { role: "coordinator" } : bootstrap.input.task;
const modelId = root ? "root" : `reader-${task.index}`;
const directory = settings.directory, attempt = bootstrap.attempt, processId = bootstrap.connection.process_id;
function persist(name, value) {
  const target = path.join(directory, name), temporary = target + ".tmp";
  const fd = fs.openSync(temporary, "w", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, target);
  const parent = fs.openSync(directory, "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}
persist(`${processId}-started-${attempt}.json`, { pid: process.pid, attempt });
if (root) persist(`started-${attempt}.json`, { pid: process.pid, attempt });
const client = new ProcessClient(bootstrap.connection.socket_path, bootstrap.connection.credential);
const provider = createOpenAICompatible({ name: "swarm-fixture", baseURL: settings.endpoint });
try {
  const result = await new ChioProcessAgent({ client, model: provider.chatModel(modelId), tools: bootstrap.connection.tools,
    namespace: "swarm", threadId: "read-and-publish", turnId: modelId, modelKey: "two-file-review-v1",
    cooperativeChildren: settings.mode !== "swarm-baseline",
    onReceipt: async event => {
      const fd = fs.openSync(path.join(directory, `${processId}-receipts.ndjson`), "a", 0o600);
      try { fs.writeSync(fd, JSON.stringify(event) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      if (root && settings.mode === "swarm-publication-death" && event.tool.server_id === "reports" && event.tool.tool_name === "publish" && attempt === 2) process.exit(77);
    },
  }).run(bindings => generateText({ ...bindings, prompt: JSON.stringify({ instruction: root ? "Delegate two file reviews, join them, collect their handoffs and publish one report." : "Read the assigned file and send its review.", task }), maxRetries: 0, stopWhen: stepCountIs(8) }));
  assert.equal(result.text, root ? "Published both reviews." : "Review sent.");
  persist(`${processId}-result.json`, { text: result.text, attempt });
} catch (error) {
  if (error instanceof ProcessSuspendedError) {
    persist(`${processId}-suspended-${attempt}.json`, { exitCode: error.exitCode });
    if (root && settings.mode === "swarm-host-death" && attempt === 1) {
      persist("first-result.json", { suspended: true });
      await new Promise(() => { setInterval(() => {}, 1000); });
    }
    process.exitCode = error.exitCode;
  } else {
    persist(`${processId}-failure-${attempt}.json`, { code: error.code ?? error.name });
    process.exitCode = 2;
  }
}
