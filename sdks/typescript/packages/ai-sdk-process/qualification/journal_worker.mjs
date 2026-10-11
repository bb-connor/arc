import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { generateText, streamText, stepCountIs, jsonSchema } from "ai";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { ChioProcessAgent, MODEL_JOURNAL_SLOT } from "@chio-protocol/ai-sdk-process";
import { ProcessClient } from "@chio-protocol/process";

process.umask(0o077);
const require = createRequire(import.meta.url);
const baseline = process.argv[2] === "--baseline";
const bootstrap = baseline ? null : JSON.parse(fs.readFileSync(0, "utf8"));
const settings = baseline ? JSON.parse(fs.readFileSync(process.argv[3], "utf8")) : bootstrap.input;
const attempt = baseline ? Number(process.argv[4]) : bootstrap.attempt;
const directory = settings.directory, receipts = [];
const persist = (name, value) => {
  const file = path.join(directory, name), temporary = file + ".tmp";
  const fd = fs.openSync(temporary, "w", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
  const parent = fs.openSync(directory, "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
};
persist(`started-${attempt}.json`, { pid: process.pid, attempt });
const provider = createOpenAICompatible({ name: "http-qualification", baseURL: settings.endpoint });
const model = provider.chatModel("fixture");
const client = baseline ? null : new ProcessClient(bootstrap.connection.socket_path, bootstrap.connection.credential);

async function gap(event) {
  if (attempt !== 1 || !["baseline", "worker-death", "host-death", "prompt-drift"].includes(settings.mode)) return;
  persist("first-result.json", event);
  if (settings.mode === "host-death") await new Promise(() => { setInterval(() => {}, 1000); });
  process.exit(77);
}

async function application(bindings) {
  const prompt = "Publish a report" + (settings.mode === "prompt-drift" && attempt > 1 ? " with a changed instruction" : "");
  const options = { ...bindings, prompt, stopWhen: stepCountIs(3), maxRetries: 0 };
  if (!settings.streaming) return (await generateText(options)).text;
  const result = streamText(options);
  let text = "";
  for await (const part of result.textStream) text += part;
  return text;
}

try {
  let text;
  if (baseline) {
    text = await application({ model, tools: { reports__publish: {
      description: "Append one report", inputSchema: jsonSchema({ type: "object", properties: { report: { type: "string" } }, required: ["report"] }),
      execute: async ({ report }) => {
        const result = spawnSync(settings.python, [settings.server, "--database", settings.database, "--publish", report], { encoding: "utf8" });
        assert.equal(result.status, 0, result.stderr);
        const value = JSON.parse(result.stdout); await gap(value);
        return { structuredContent: value };
      },
    } } });
  } else {
    if (settings.mode === "model-checkpoint-death" && attempt === 1) {
      const checkpoint = client.checkpoint.bind(client);
      client.checkpoint = async (revision, value) => {
        const result = await checkpoint(revision, value);
        const turns = value[MODEL_JOURNAL_SLOT]?.turns;
        if (turns && Object.values(turns)[0].entries[0]?.state === "completed") {
          persist("model-committed.json", { committed: true }); process.exit(76);
        }
        return result;
      };
    }
    text = await new ChioProcessAgent({ client, model, tools: bootstrap.connection.tools,
      namespace: "http-model-publication", threadId: "saved-thread", turnId: "saved-turn",
      modelKey: "http-qualification-v1", maxConcurrency: 1,
      onReceipt: async event => { receipts.push(event); await gap(event); },
    }).run(application);
  }
  assert.equal(text, settings.streaming ? "Planning. Published." : "Published.");
  persist("result.json", { text, attempt, receipts, sdk_version: require("ai/package.json").version,
    provider_version: require("@ai-sdk/openai-compatible/package.json").version,
    provider_interface: model.specificationVersion,
    modules: { adapter: import.meta.resolve("@chio-protocol/ai-sdk-process"), provider: import.meta.resolve("@ai-sdk/openai-compatible"), ai: import.meta.resolve("ai") } });
} catch (error) {
  persist(`failure-${attempt}.json`, { code: error.code ?? error.name, receipts });
  process.exitCode = 2;
}
