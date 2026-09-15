import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { generateText, stepCountIs } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { ChioProcessAgent, ProcessSuspendedError } from "@chio-protocol/ai-sdk-process";
import { ProcessClient } from "@chio-protocol/process";

process.umask(0o077);
const bootstrap = JSON.parse(fs.readFileSync(0, "utf8")), id = bootstrap.connection.process_id;
const root = id === "root", settings = root ? bootstrap.input : bootstrap.input.configuration;
const role = root ? "supervisor" : bootstrap.input.task.role;
const persist = (name, value) => {
  const fd = fs.openSync(path.join(settings.directory, name), "w", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
};
persist(`${id}-started-${bootstrap.attempt}.json`, { pid: process.pid });
if (role === "primary") process.exit(1);
const client = new ProcessClient(bootstrap.connection.socket_path, bootstrap.connection.credential);
const provider = createOpenAICompatible({ name: "supervision-fixture", baseURL: settings.endpoint });
try {
  const result = await new ChioProcessAgent({ client, model: provider.chatModel(role), tools: bootstrap.connection.tools,
    namespace: "supervision", threadId: "fallback-task", turnId: role, modelKey: "supervised-fallback-v1", cooperativeChildren: true,
    onReceipt: async event => {
      const fd = fs.openSync(path.join(settings.directory, `${id}-receipts.ndjson`), "a", 0o600);
      try { fs.writeSync(fd, JSON.stringify(event) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
      if (role === "fallback" && event.tool.tool_name === "send_results" && bootstrap.attempt === 1) {
        if (settings.mode === "worker-death") process.exit(77);
        if (settings.mode === "host-death") {
          persist("started-1.json", { pid: process.pid });
          persist("first-result.json", event);
          await new Promise(() => { setInterval(() => {}, 1000); });
        }
      }
    },
  }).run(bindings => generateText({ ...bindings, prompt: root ? "Try the primary worker, observe its outcome and choose a fallback if needed. Publish the recovered answer." : "Send the fallback answer.", stopWhen: stepCountIs(8), maxRetries: 0 }));
  assert.equal(result.text, root ? "Recovered with fallback." : "Fallback sent.");
  persist(`${id}-result.json`, { text: result.text, attempt: bootstrap.attempt,
    modules: { adapter: import.meta.resolve("@chio-protocol/ai-sdk-process"), process: import.meta.resolve("@chio-protocol/process"), ai: import.meta.resolve("ai") } });
} catch (error) {
  persist(`${id}-end-${bootstrap.attempt}.json`, { code: error.code ?? error.name });
  process.exitCode = error instanceof ProcessSuspendedError ? error.exitCode : 2;
}
