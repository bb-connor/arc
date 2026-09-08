import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Resolve real installed packages from an operator-selected consumer directory.
// The application adds no tool authority or model-response replay coordinator.
export async function installed(consumer) {
  assert.equal(fs.realpathSync(path.dirname(fileURLToPath(import.meta.url))), fs.realpathSync(consumer), "stage the application in the installed consumer first");
  const require = createRequire(path.join(fs.realpathSync(consumer), "package.json"));
  const names = ["ai", "@ai-sdk/openai-compatible", "@chio-protocol/ai-sdk-process", "@chio-protocol/process"];
  const locations = Object.fromEntries(names.map(name => [name, import.meta.resolve(name)]));
  const major = Number(require("ai/package.json").version.split(".")[0]);
  assert.ok(major === 6 || major === 7, "install the supported AI SDK 6 or 7 profile");
  const modules = await Promise.all(names.map(name => import(locations[name])));
  return { modules, locations, versions: {
    ai: require("ai/package.json").version,
    provider: require("@ai-sdk/openai-compatible/package.json").version,
  } };
}

function persist(directory, name, value) {
  const file = path.join(directory, name), temporary = `${file}.${process.pid}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
  const parent = fs.openSync(directory, "r");
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
}

export async function execute(bootstrap) {
  const settings = bootstrap.input;
  assert.equal(settings.worker_sha256, createHash("sha256").update(fs.readFileSync(fileURLToPath(import.meta.url))).digest("hex"), "worker source changed");
  assert.equal(settings.backend, "chio");
  assert.ok(Number.isInteger(settings.max_rounds) && settings.max_rounds >= 1 && settings.max_rounds <= 12);
  assert.ok(["openai", "openrouter"].includes(settings.provider));
  assert.ok(settings.services.length && settings.thread_id && settings.model && settings.instruction);
  const supplied = new Map(bootstrap.connection.tools.map(tool => [tool.name, tool]));
  for (const tool of settings.tools) assert.deepEqual(supplied.get(tool.name), tool, "host resource definition changed");
  const { modules: [sdk, providerModule, adapter, processModule], locations, versions } = await installed(settings.consumer);
  const directory = fs.realpathSync(settings.directory);
  const binding = path.join(directory, "input.json");
  if (fs.existsSync(binding)) assert.deepEqual(JSON.parse(fs.readFileSync(binding, "utf8")), settings, "worker input changed across recovery");
  else {
    // A partial initial binding fails closed on recovery. Kernel checkpoint CAS
    // owns concurrent model attempts and uncertain provider outcomes.
    const fd = fs.openSync(binding, "wx", 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(settings)); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
  }
  const key = process.env[settings.provider.toUpperCase() + "_API_KEY"];
  assert.ok(key, "provider credential is required in the worker environment");
  const provider = providerModule.createOpenAICompatible({
    name: settings.provider,
    baseURL: settings.provider === "openrouter" ? "https://openrouter.ai/api/v1" : "https://api.openai.com/v1",
    apiKey: key,
  });
  const client = new processModule.ProcessClient(bootstrap.connection.socket_path, bootstrap.connection.credential);
  const receipts = [];
  const modelKey = createHash("sha256").update(JSON.stringify({ schema: "shared-resource-ai-sdk-v1", settings, versions })).digest("hex");
  const started = performance.now();
  const result = await new adapter.ChioProcessAgent({
    client, model: provider.chatModel(settings.model), tools: settings.tools,
    namespace: settings.namespace, threadId: settings.thread_id, turnId: "assessment",
    modelKey, maxModelCalls: settings.max_rounds, maxConcurrency: 1, maxResponseBytes: 1048576,
    onReceipt: async event => {
      receipts.push(event);
      const fd = fs.openSync(path.join(directory, "receipt-events.ndjson"), "a", 0o600);
      try { fs.writeSync(fd, JSON.stringify(event) + "\n"); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      if (settings.crash_after_replace && event.tool.tool_name === "replace" && event.result.output?.value?.structuredContent?.status === "committed") {
        const marker = path.join(directory, "fault.json");
        if (!fs.existsSync(marker)) {
          persist(directory, "fault.json", { event: "worker_exit_after_effect", tool_call_id: event.toolCallId,
            artifact: { operation_key: event.operationKey, chio: { receipt_json: event.result.receipt_json } } });
          process.exit(77);
        }
      }
    },
  }).run(bindings => sdk.generateText({
    ...bindings,
    system: settings.instruction,
    prompt: "Assigned services: " + JSON.stringify(settings.services),
    maxRetries: 0,
    // AI SDK 7 omits raw response bodies from step results by default.
    experimental_include: { responseBody: true },
    maxOutputTokens: 2048,
    stopWhen: sdk.stepCountIs(settings.max_rounds),
    providerOptions: settings.provider === "openrouter"
      ? { openrouter: { provider: { allow_fallbacks: false, require_parameters: true } } }
      : undefined,
  }));
  assert.equal(result.finishReason, "stop", "worker reached its bound without finishing");
  const calls = result.steps.map((step, turn) => {
    const response = step.response.body;
    assert.ok(response?.id && Array.isArray(response.choices), "original provider response is missing");
    return { turn, kind: "live_" + settings.provider, complete: true, response };
  });
  const evidence = {
    graph_finished: true,
    framework: "ai-sdk",
    text: result.text,
    model_calls: calls,
    tools: receipts.map(event => ({ artifact: { chio: { receipt_json: event.result.receipt_json } } })),
    elapsed_seconds: (performance.now() - started) / 1000,
    versions,
    modules: locations,
  };
  persist(directory, "result.json", evidence);
  return evidence;
}

if (process.argv[2] === "--preflight") {
  const { versions } = await installed(process.argv[3]);
  console.log(JSON.stringify(versions));
} else if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.umask(0o077);
  const bootstrap = JSON.parse(fs.readFileSync(0, "utf8"));
  await execute(bootstrap);
  console.log(JSON.stringify({ graph_finished: true }));
}
