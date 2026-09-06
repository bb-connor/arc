import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { generateText, streamText, stepCountIs } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { WorkerError } from "@chio-protocol/process";
import { ChioProcessAgent, ModelJournalError, MODEL_JOURNAL_SLOT } from "../dist/index.js";
import { encode, restored } from "../dist/model-codec.js";

const scope = { namespace: "journal-test", threadId: "thread", turnId: "turn", modelKey: "model-and-application-v1" };
const definition = { name: "reports__publish", server_id: "reports", tool_name: "publish", description: "Publish report",
  input_schema: { type: "object", properties: { report: { type: "string" } }, required: ["report"], additionalProperties: false } };
const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
const response = content => ({ content, usage, warnings: [], finishReason: { unified: content.some(c => c.type === "tool-call") ? "tool-calls" : "stop", raw: "fixture" },
  response: { id: randomUUID(), timestamp: new Date("2026-09-05T12:00:00Z"), modelId: "fixture", headers: { "x-fixture": "retained" } } });
const toolCall = () => ({ type: "tool-call", toolCallId: randomUUID(), toolName: "reports__publish", input: '{"report":"Model-selected report"}' });
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
const code = expected => error => error instanceof ModelJournalError && error.code === expected;

function client() {
  let revision = 0, value = { application: { retained: true } }, publications = 0;
  const results = new Map();
  return {
    get value() { return structuredClone(value); },
    set value(next) { value = structuredClone(next); revision++; },
    get publications() { return publications; },
    inspect: async () => ({ process_id: "writer", state: "running", checkpoint: { revision: String(revision), value: structuredClone(value) } }),
    checkpoint: async (expected, next) => {
      if (expected !== String(revision)) throw new WorkerError("checkpoint_conflict");
      value = JSON.parse(JSON.stringify(next)); revision++;
      return { revision: String(revision), value: structuredClone(value) };
    },
    invoke: async (key, _server, _tool, args) => {
      const entries = Object.values(value[MODEL_JOURNAL_SLOT].turns)[0].entries;
      assert.equal(entries[0].state, "completed", "provider response must be durable before any tool effect");
      if (!results.has(key)) results.set(key, { request_id: key, verdict: "allow", reason: null, terminal_state: { state: "completed" },
        output: { kind: "value", value: { report_id: ++publications, report: args.report } }, receipt_json: '{"fixture":"original receipt"}', execution_nonce_json: null });
      return results.get(key);
    },
  };
}
const agent = (client, model, extra = {}) => new ChioProcessAgent({ ...scope, client, model, tools: [definition], ...extra });
const generate = bindings => generateText({ ...bindings, prompt: "Publish a report", stopWhen: stepCountIs(3), maxRetries: 0 });
const streaming = async bindings => {
  const result = streamText({ ...bindings, prompt: "Publish a report", stopWhen: stepCountIs(3), maxRetries: 0 });
  let text = "";
  for await (const part of result.textStream) text += part;
  return text;
};
function model(counter) {
  return new MockLanguageModelV4({ doGenerate: async options => {
    counter.calls++;
    return response(options.prompt.some(m => m.role === "tool") ? [{ type: "text", text: "Published." }] : [toolCall()]);
  } });
}

test("ordinary generateText resumes generated tool-call IDs without a caller-owned plan file", async () => {
  const host = client(), counter = { calls: 0 };
  await assert.rejects(agent(host, model(counter), { onReceipt: () => { throw new Error("worker stopped before application checkpoint"); } }).run(generate));
  assert.equal(host.publications, 1); assert.equal(counter.calls, 1);
  const recovered = await agent(host, model(counter)).run(generate);
  assert.equal(recovered.text, "Published."); assert.equal(host.publications, 1); assert.equal(counter.calls, 2);
  assert.ok(recovered.response.timestamp instanceof Date);
  assert.deepEqual(host.value.application, { retained: true });
  const original = JSON.stringify(host.value);
  const replay = await agent(host, new MockLanguageModelV4({ doGenerate: async () => { throw new Error("must not call provider"); } })).run(generate);
  assert.equal(replay.text, "Published."); assert.equal(host.publications, 1);
  assert.equal(JSON.stringify(host.value), original);
});

test("prompt, model configuration and sampling drift reject before provider or tool dispatch", async () => {
  const host = client(), counter = { calls: 0 };
  await agent(host, model(counter)).run(generate);
  const changes = [
    [{}, bindings => generate({ ...bindings, temperature: 0.5 })],
    [{}, bindings => generateText({ ...bindings, prompt: "Different instruction", maxRetries: 0 })],
    [{ modelKey: "new-model-configuration" }, generate],
  ];
  for (const [options, operation] of changes) await assert.rejects(agent(host, model(counter), options).run(operation), code("model_request_conflict"));
  assert.equal(counter.calls, 2); assert.equal(host.publications, 1);
});

test("an uncertain provider call stays reserved and cannot automatically produce a replacement plan", async () => {
  const host = client(); let calls = 0;
  const failed = new MockLanguageModelV4({ doGenerate: async () => { calls++; throw new Error("private provider error"); } });
  await assert.rejects(agent(host, failed).run(bindings => generateText({ ...bindings, prompt: "Publish a report", maxRetries: 3 })), code("model_outcome_unknown"));
  await assert.rejects(agent(host, failed).run(generate), code("model_outcome_unknown"));
  assert.equal(calls, 1); assert.equal(host.publications, 0);
});

test("text streams before completion, while tool inputs and calls wait for the durable response", async () => {
  const host = client(), release = deferred(), prefix = deferred(); let providerCalls = 0;
  const streamed = new MockLanguageModelV4({ doStream: async options => {
    providerCalls++;
    const next = options.prompt.some(m => m.role === "tool");
    return { stream: new ReadableStream({ async start(controller) {
      controller.enqueue({ type: "stream-start", warnings: [] });
      controller.enqueue({ type: "text-start", id: "text" });
      controller.enqueue({ type: "text-delta", id: "text", delta: next ? "Published." : "Planning. " });
      controller.enqueue({ type: "text-end", id: "text" });
      if (!next) { controller.enqueue(toolCall()); await release.promise; }
      controller.enqueue({ type: "finish", usage, finishReason: { unified: next ? "stop" : "tool-calls", raw: "fixture" } });
      controller.close();
    } }) };
  } });
  const running = agent(host, streamed).run(async bindings => {
    const result = streamText({ ...bindings, prompt: "Publish a report", stopWhen: stepCountIs(3), maxRetries: 0 });
    let text = "";
    for await (const part of result.textStream) { text += part; prefix.resolve(); }
    return text;
  });
  await prefix.promise;
  assert.equal(host.publications, 0); assert.equal(providerCalls, 1);
  release.resolve();
  assert.equal(await running, "Planning. Published."); assert.equal(host.publications, 1);
  assert.equal(await agent(host, streamed).run(streaming), "Planning. Published.");
  assert.equal(providerCalls, 2); assert.equal(host.publications, 1);
});

test("a truncated stream releases no tools, and a fresh run does not redispatch the provider", async () => {
  const host = client(); let calls = 0;
  const partial = new MockLanguageModelV4({ doStream: async () => {
    calls++;
    return { stream: new ReadableStream({ start(controller) {
      controller.enqueue({ type: "stream-start", warnings: [] }); controller.enqueue(toolCall()); controller.close();
    } }) };
  } });
  await assert.rejects(agent(host, partial).run(streaming), code("model_outcome_unknown"));
  await assert.rejects(agent(host, partial).run(streaming), code("model_outcome_unknown"));
  assert.equal(host.publications, 0); assert.equal(calls, 1);
});

test("checkpoint conflicts and oversized responses fail before tool execution", async () => {
  const host = client(), counter = { calls: 0 };
  host.checkpoint = async () => { throw new WorkerError("checkpoint_conflict"); };
  await assert.rejects(agent(host, model(counter)).run(generate), code("model_checkpoint_conflict"));
  assert.equal(counter.calls, 0);
  const full = client();
  const large = new MockLanguageModelV4({ doGenerate: async () => response([toolCall(), { type: "text", text: "x".repeat(6000) }]) });
  await assert.rejects(agent(full, large, { maxCheckpointBytes: 4096 }).run(generate), code("model_journal_full"));
  assert.equal(full.publications, 0);
});

test("corrupted checkpoints and shortened replay cannot silently replace existing history", async () => {
  const host = client(), counter = { calls: 0 };
  await agent(host, model(counter)).run(generate);
  await assert.rejects(agent(host, model(counter)).run(async () => "skipped replay"), code("model_replay_incomplete"));
  const valid = host.value;
  host.value = { ...valid, [MODEL_JOURNAL_SLOT]: null };
  await assert.rejects(agent(host, model(counter)).run(generate), code("model_checkpoint_invalid"));
  host.value = valid;
  const corrupted = host.value;
  Object.values(corrupted[MODEL_JOURNAL_SLOT].turns)[0].entries[0].responseHash = "corrupt";
  host.value = corrupted;
  await assert.rejects(agent(host, model(counter)).run(generate), code("model_checkpoint_invalid"));
  assert.equal(counter.calls, 2); assert.equal(host.publications, 1);
});

test("tagged codec preserves provider values and rejects unsupported coercion", () => {
  const value = { missing: undefined, timestamp: new Date("2026-09-05T12:00:00Z"), bytes: new Uint8Array([0, 255]),
    file: new URL("https://example.test/file"), raw: { tag: "date", value: "ordinary JSON" }, zero: -0 };
  assert.deepEqual(restored(encode(value)), value);
  let getters = 0;
  const getter = Object.defineProperty({}, "secret", { enumerable: true, get() { getters++; return 1; } });
  for (const invalid of [getter, { toJSON() { getters++; return {}; } }, NaN, 1n, "\ud800"]) assert.throws(() => encode(invalid), code("model_value_unsupported"));
  assert.equal(getters, 0);
});

test("a committed model response survives a lost checkpoint acknowledgement before any tool effect", async () => {
  const host = client(), counter = { calls: 0 }, checkpoint = host.checkpoint;
  let dropped = false;
  host.checkpoint = async (revision, value) => {
    const result = await checkpoint(revision, value);
    if (!dropped && Object.values(value[MODEL_JOURNAL_SLOT].turns)[0].entries[0].state === "completed") {
      dropped = true; throw new WorkerError("connection_closed");
    }
    return result;
  };
  await assert.rejects(agent(host, model(counter)).run(generate), code("model_checkpoint_unavailable"));
  assert.equal(host.publications, 0);
  assert.equal((await agent(host, model(counter)).run(generate)).text, "Published.");
  assert.equal(host.publications, 1); assert.equal(counter.calls, 2);
});

test("concurrent checkpoint claimants cannot both dispatch a provider request", async () => {
  const host = client(), release = deferred(), entered = deferred(); let calls = 0;
  const slow = () => new MockLanguageModelV4({ doGenerate: async () => {
    calls++; entered.resolve(); await release.promise; return response([{ type: "text", text: "Done." }]);
  } });
  const first = agent(host, slow()).run(generate);
  await entered.promise;
  await assert.rejects(agent(host, slow()).run(generate), code("model_outcome_unknown"));
  release.resolve(); await first;
  assert.equal(calls, 1);
});

test("duplicate provider tool-call IDs and absent terminal reasons cannot release a tool", async () => {
  const host = client();
  const duplicate = toolCall();
  await assert.rejects(agent(host, new MockLanguageModelV4({ doGenerate: async () => response([duplicate, duplicate]) })).run(generate), code("model_response_invalid"));
  assert.equal(host.publications, 0);
  const unknown = client();
  await assert.rejects(agent(unknown, new MockLanguageModelV4({ doGenerate: async () => ({ ...response([toolCall()]), finishReason: { unified: "other", raw: undefined } }) })).run(generate), code("model_response_invalid"));
  assert.equal(unknown.publications, 0);
});

test("provider responses are snapshotted before asynchronous checkpoint reads and coercion is rejected", async () => {
  const host = client(), inspect = host.inspect, entered = deferred(), release = deferred();
  let reads = 0;
  host.inspect = async () => { if (++reads === 2) { entered.resolve(); await release.promise; } return inspect(); };
  const selected = toolCall(), originalId = selected.toolCallId;
  const supplied = response([selected]);
  const provider = new MockLanguageModelV4({ doGenerate: async options => options.prompt.some(m => m.role === "tool") ? response([{ type: "text", text: "Published." }]) : supplied });
  const pending = agent(host, provider).run(generate);
  await entered.promise;
  selected.toolCallId = "changed-after-snapshot";
  selected.input = '{"report":"changed after snapshot"}';
  release.resolve();
  await pending;
  assert.deepEqual(Object.values(host.value[MODEL_JOURNAL_SLOT].turns)[0].entries[0].callIds, [originalId]);
  let getters = 0;
  const malformed = Object.defineProperty(response([]), "content", { enumerable: true, get() { getters++; return [toolCall()]; } });
  await assert.rejects(agent(client(), new MockLanguageModelV4({ doGenerate: async () => malformed })).run(generate), code("model_value_unsupported"));
  const streamed = Object.defineProperty({ stream: new ReadableStream({ start(controller) { controller.close(); } }) }, "response", { enumerable: true, get() { getters++; return {}; } });
  await assert.rejects(agent(client(), new MockLanguageModelV4({ doStream: async () => streamed })).run(streaming), code("model_value_unsupported"));
  assert.equal(getters, 0);
});

test("the provider receives the same parameter snapshot that was reserved in the journal", async () => {
  const host = client(), inspect = host.inspect, entered = deferred(), release = deferred();
  let reads = 0, received;
  host.inspect = async () => { if (++reads === 1) { entered.resolve(); await release.promise; } return inspect(); };
  const providerOptions = { fixture: { setting: "original" } };
  const provider = new MockLanguageModelV4({ doGenerate: async options => {
    received = options.providerOptions.fixture.setting;
    return response([{ type: "text", text: "Done." }]);
  } });
  const running = agent(host, provider).run(bindings => generateText({ ...bindings, prompt: "Test", providerOptions, maxRetries: 0 }));
  await entered.promise; providerOptions.fixture.setting = "changed"; release.resolve();
  await running;
  assert.equal(received, "original");
});

function blobClient() {
  const host = client(), blobs = new Map();
  const inspect = host.inspect;
  host.inspect = async () => ({ ...await inspect(), storage: { protocol: "chio.process.blobs.v1", max_blob_bytes: 1_048_576 } });
  host.blobs = blobs;
  host.putBlob = async value => {
    const { createHash } = await import("node:crypto");
    const bytes = Buffer.from(value), sha256 = createHash("sha256").update(bytes).digest("hex");
    blobs.set(sha256, bytes); return { sha256, bytes: bytes.length };
  };
  host.readBlob = async sha256 => { if (!blobs.has(sha256)) throw new WorkerError("blob_missing"); return new Uint8Array(blobs.get(sha256)); };
  return host;
}

test("large responses use bounded chunks and replay every provider field with a small checkpoint", async () => {
  const host = blobClient(); let calls = 0;
  const body = "x".repeat(2_100_000);
  const supplied = new MockLanguageModelV4({ doGenerate: async () => { calls++; return {
    ...response([{ type: "text", text: "Saved." }]), request: { body }, providerMetadata: { fixture: { body } },
  }; } });
  const run = bindings => generateText({ ...bindings, prompt: "Large response", maxRetries: 0 });
  const first = await agent(host, supplied).run(run);
  assert.equal(first.providerMetadata.fixture.body, body);
  assert.equal(calls, 1); assert.ok(host.blobs.size > 1);
  assert.ok([...host.blobs.values()].every(bytes => bytes.length <= 1_048_576));
  assert.ok(Buffer.byteLength(JSON.stringify(host.value)) < 4096);
  const replayed = await agent(host, supplied).run(run);
  assert.equal(replayed.providerMetadata.fixture.body, body); assert.equal(calls, 1);
  const missing = host.blobs.keys().next().value, saved = host.blobs.get(missing);
  host.blobs.delete(missing);
  await assert.rejects(agent(host, supplied).run(run), code("model_checkpoint_unavailable"));
  host.blobs.set(missing, Buffer.alloc(saved.length));
  await assert.rejects(agent(host, supplied).run(run), code("model_checkpoint_invalid"));
  assert.equal(calls, 1);
});

test("blob quota or checkpoint failure never releases a tool plan or regenerates it", async () => {
  for (const failAt of ["blob", "checkpoint"]) {
    const host = blobClient(), counter = { calls: 0 };
    if (failAt === "blob") host.putBlob = async () => { throw new WorkerError("limit_reached"); };
    else {
      const checkpoint = host.checkpoint;
      host.checkpoint = async (revision, value) => {
        if (Object.values(value[MODEL_JOURNAL_SLOT].turns)[0].entries[0].state === "completed") throw new WorkerError("transport_error");
        return checkpoint(revision, value);
      };
    }
    await assert.rejects(agent(host, model(counter)).run(generate), code("model_checkpoint_unavailable"));
    await assert.rejects(agent(host, model(counter)).run(generate), code("model_outcome_unknown"));
    assert.equal(host.publications, 0); assert.equal(counter.calls, 1);
    if (failAt === "checkpoint") assert.ok(host.blobs.size > 0, "orphaned chunks remain charged");
  }
});

test("explicit blob storage requires host support before a provider request", async () => {
  const counter = { calls: 0 };
  await assert.rejects(agent(client(), model(counter), { responseStorage: "blobs" }).run(generate), code("model_storage_unavailable"));
  assert.equal(counter.calls, 0);
  const host = blobClient();
  await agent(host, model(counter), { responseStorage: "checkpoint" }).run(generate);
  assert.equal(host.blobs.size, 0);
  await agent(host, model(counter)).run(generate);
  assert.equal(counter.calls, 2, "auto mode can replay existing inline entries");
});

test("32 reads retain growing provider request bodies without growing the checkpoint past its bound", async () => {
  const results = [];
  for (const responseStorage of ["checkpoint", "blobs"]) {
    const host = blobClient(), invoke = host.invoke;
    host.invoke = async (...args) => ({ ...await invoke(...args), output: { kind: "value", value: "source\n".repeat(1171) } });
    let calls = 0, maxCheckpointBytes = 0, checkpointBytesWritten = 0;
    const checkpoint = host.checkpoint;
    host.checkpoint = async (revision, value) => {
      const size = Buffer.byteLength(JSON.stringify(value));
      maxCheckpointBytes = Math.max(maxCheckpointBytes, size); checkpointBytesWritten += size;
      return checkpoint(revision, value);
    };
    const supplied = new MockLanguageModelV4({ doGenerate: async options => {
      calls++;
      const done = options.prompt.filter(item => item.role === "tool").length === 32;
      return { ...response(done ? [{ type: "text", text: "Read all 32 files." }] : [toolCall()]), request: { body: JSON.stringify(options.prompt) } };
    } });
    const run = bindings => generateText({ ...bindings, prompt: "Read 32 files", stopWhen: stepCountIs(34), maxRetries: 0 });
    if (responseStorage === "checkpoint") {
      await assert.rejects(agent(host, supplied, { responseStorage }).run(run), code("model_journal_full"));
      assert.ok(host.publications < 32);
    } else {
      assert.equal((await agent(host, supplied, { responseStorage }).run(run)).text, "Read all 32 files.");
      assert.equal(host.publications, 32); assert.equal(calls, 33);
      const before = checkpointBytesWritten;
      await agent(host, supplied, { responseStorage }).run(run);
      assert.equal(host.publications, 32); assert.equal(calls, 33); assert.equal(checkpointBytesWritten, before);
      assert.ok(maxCheckpointBytes < 32_768);
    }
    results.push({ responseStorage, calls, reads: host.publications, maxCheckpointBytes, checkpointBytesWritten,
      blobBytes: [...host.blobs.values()].reduce((sum, bytes) => sum + bytes.length, 0) });
  }
  assert.ok(results[1].checkpointBytesWritten < results[0].checkpointBytesWritten);
  console.log(JSON.stringify({ workload: "scripted-model, in-memory transport, 32 reads, 8197 bytes each", results }));
});

test("a client wrapper cannot mutate saved response bytes through a supplied chunk view", async () => {
  const host = blobClient(), counter = { calls: 0 }, put = host.putBlob;
  host.putBlob = async bytes => { const reference = await put(bytes); bytes.fill(0); return reference; };
  await agent(host, model(counter)).run(generate);
  await agent(host, model(counter)).run(generate);
  assert.equal(counter.calls, 2); assert.equal(host.publications, 1);
});
