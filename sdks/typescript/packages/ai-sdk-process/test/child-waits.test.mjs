import assert from "node:assert/strict";
import test from "node:test";
import { generateText, streamText, stepCountIs } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { WorkerError } from "@chio-protocol/process";
import { ChioProcessAgent, ChioProcessTools, ProcessSuspendedError, CHILD_WAITS_SLOT, MODEL_JOURNAL_SLOT } from "../dist/index.js";

const scope = { namespace: "swarm", threadId: "task", turnId: "coordinator", modelKey: "planner-v1" };
const wait = { name: "chio-process__wait_children", server_id: "chio-process", tool_name: "wait_children", description: "Join direct children",
  input_schema: { type: "object", properties: { children: { type: "array", items: { type: "string" } } }, required: ["children"] } };
const spawn = { name: "chio-process__spawn_reader", server_id: "chio-process", tool_name: "spawn_reader", description: "Start a reader",
  input_schema: { type: "object", properties: {} } };
const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
const response = content => ({ content, usage, warnings: [], finishReason: { unified: content[0].type === "tool-call" ? "tool-calls" : "stop", raw: "fixture" } });
const call = (id, tool, args) => ({ type: "tool-call", toolCallId: id, toolName: tool.name, input: JSON.stringify(args) });
function host() {
  let value = { application: { preserved: true } }, revision = 0, spawns = 0;
  const calls = new Map(), invocations = [];
  const client = {
    complete: false, calls, invocations,
    get spawns() { return spawns; },
    get value() { return structuredClone(value); },
    set value(next) { value = structuredClone(next); revision++; },
    inspect: async () => ({ process_id: "root", state: "running", checkpoint: { value: structuredClone(value), revision: String(revision) } }),
    checkpoint: async (expected, next) => {
      if (expected !== String(revision)) throw new WorkerError("checkpoint_conflict");
      value = JSON.parse(JSON.stringify(next)); revision++;
      return { value: structuredClone(value), revision: String(revision) };
    },
    invoke: async (key, server, tool, args) => {
      invocations.push({ key, server, tool, args });
      if (!calls.has(key)) {
        const output = tool === "spawn_reader" ? { process: `child-${++spawns}` } : { complete: client.complete, children: args.children };
        calls.set(key, { request_id: key, verdict: "allow", reason: null, terminal_state: { state: "completed" }, output: { kind: "value", value: output }, receipt_json: JSON.stringify({ original: key }), execution_nonce_json: null });
      }
      return calls.get(key);
    },
  };
  return client;
}
const options = client => ({ ...scope, client, cooperativeChildren: true, tools: [spawn, wait] });
function model(counter) {
  return new MockLanguageModelV4({ doGenerate: async () => {
    counter.calls++;
    return response(counter.calls === 1 ? [call("spawn-generated", spawn, {})] : counter.calls === 2 ? [call("join-generated", wait, { children: ["child-1"] })] : [{ type: "text", text: "Children completed." }]);
  } });
}
const generate = bindings => generateText({ ...bindings, prompt: "Delegate the task and join its children", stopWhen: stepCountIs(5), maxRetries: 0 });
const suspend = error => error instanceof ProcessSuspendedError && error.exitCode === 75;

test("an ordinary model loop suspends then replays the original spawn and advances only the join observation", async () => {
  const client = host(), counter = { calls: 0 }, events = [];
  const create = () => new ChioProcessAgent({ ...options(client), model: model(counter), onReceipt: event => { events.push(event); } });
  await assert.rejects(create().run(generate), suspend);
  assert.equal(counter.calls, 2); assert.equal(client.spawns, 1);
  const originalWait = events[1];
  assert.equal(Object.values(client.value[CHILD_WAITS_SLOT].waits)[0].poll, 1);
  assert.equal(Object.values(client.value[MODEL_JOURNAL_SLOT].turns)[0].entries.length, 2);
  client.complete = true;
  assert.equal((await create().run(generate)).text, "Children completed.");
  assert.equal(counter.calls, 3); assert.equal(client.spawns, 1);
  assert.equal(events[0].operationKey, events[2].operationKey);
  assert.notEqual(originalWait.operationKey, events[3].operationKey);
  assert.equal(originalWait.toolCallId, events[3].toolCallId);
  assert.equal(originalWait.result.output.value.complete, false);
  assert.equal(events[3].result.output.value.complete, true);
  const state = JSON.stringify(client.value);
  await create().run(generate);
  assert.equal(counter.calls, 3); assert.equal(client.spawns, 1);
  assert.equal(JSON.stringify(client.value), state);
  assert.deepEqual(client.value.application, { preserved: true });
});

test("a lost acknowledgement of join advancement recovers its committed poll without a new spawn", async () => {
  const client = host(), checkpoint = client.checkpoint, counter = { calls: 0 };
  let interrupted = false;
  client.checkpoint = async (revision, value) => {
    const result = await checkpoint(revision, value);
    if (!interrupted && Object.values(value[CHILD_WAITS_SLOT]?.waits ?? {}).some(item => item.poll === 1)) {
      interrupted = true; throw new WorkerError("transport_error");
    }
    return result;
  };
  const create = () => new ChioProcessAgent({ ...options(client), model: model(counter) });
  await assert.rejects(create().run(generate), error => !suspend(error));
  assert.equal(counter.calls, 2);
  client.complete = true;
  await create().run(generate);
  assert.equal(client.spawns, 1); assert.equal(counter.calls, 3);
});

test("parallel joins preserve both advancement records before suspension", async () => {
  const client = host();
  await assert.rejects(new ChioProcessTools(options(client)).run(async ({ tools }) => Promise.all([
    tools[wait.name].execute({ children: ["one"] }, { toolCallId: "join-one" }),
    tools[wait.name].execute({ children: ["two"] }, { toolCallId: "join-two" }),
  ])), suspend);
  assert.equal(client.calls.size, 2);
  assert.deepEqual(Object.values(client.value[CHILD_WAITS_SLOT].waits).map(item => item.poll), [1, 1]);
});

test("changed child sets, corrupt poll state and failed receipt persistence cannot invent a new observation", async () => {
  const client = host();
  const run = (children, extra = {}) => new ChioProcessTools({ ...options(client), ...extra }).run(({ tools }) => tools[wait.name].execute({ children }, { toolCallId: "join-one" }));
  await assert.rejects(run(["one"], { onReceipt: () => { throw new Error("sink failed"); } }), error => error.code === "receipt_sink_failed");
  assert.equal(Object.values(client.value[CHILD_WAITS_SLOT].waits)[0].poll, 0);
  const before = client.invocations.length;
  await assert.rejects(run(["two"]), error => error.code === "child_wait_conflict");
  assert.equal(client.invocations.length, before);
  const state = client.value;
  Object.values(state[CHILD_WAITS_SLOT].waits)[0].poll = -1; client.value = state;
  await assert.rejects(run(["one"]), error => error.code === "child_wait_invalid");
  assert.equal(client.invocations.length, before);
});

test("a failure from an admitted sibling overrides cooperative suspension while all calls drain", async () => {
  const client = host(), invoke = client.invoke;
  let finish;
  const pending = new Promise(resolve => { finish = resolve; });
  client.invoke = async (...args) => {
    if (args[2] === "spawn_reader") { await pending; throw new WorkerError("runtime_error"); }
    return invoke(...args);
  };
  const originalCheckpoint = client.checkpoint;
  client.checkpoint = async (...args) => {
    const result = await originalCheckpoint(...args);
    if (Object.values(args[1][CHILD_WAITS_SLOT]?.waits ?? {}).some(item => item.poll === 1)) setTimeout(finish, 20);
    return result;
  };
  await assert.rejects(new ChioProcessTools(options(client)).run(async ({ tools }) => Promise.all([
    tools[spawn.name].execute({}, { toolCallId: "spawn" }),
    tools[wait.name].execute({ children: ["one"] }, { toolCallId: "join" }),
  ])), error => error.code === "runtime_error");
});


test("streaming model loops preserve suspension and resume the same generated join", async () => {
  const client = host(); let calls = 0;
  const supplied = () => new MockLanguageModelV4({ doStream: async () => {
    calls++;
    const content = calls === 1 ? call("stream-spawn", spawn, {}) : calls === 2 ? call("stream-join", wait, { children: ["child-1"] }) : null;
    const chunks = [{ type: "stream-start", warnings: [] }, ...(content ? [content] : [
      { type: "text-start", id: "answer" }, { type: "text-delta", id: "answer", delta: "Joined." }, { type: "text-end", id: "answer" },
    ]), { type: "finish", finishReason: { unified: content ? "tool-calls" : "stop", raw: "fixture" }, usage }];
    return { stream: new ReadableStream({ start(controller) { chunks.forEach(chunk => controller.enqueue(chunk)); controller.close(); } }) };
  } });
  const run = () => new ChioProcessAgent({ ...options(client), model: supplied() }).run(async bindings => {
    const result = streamText({ ...bindings, prompt: "Delegate and join", stopWhen: stepCountIs(5), maxRetries: 0 });
    await result.consumeStream();
    return result.text;
  });
  await assert.rejects(run(), suspend);
  assert.equal(calls, 2); client.complete = true;
  assert.equal(await run(), "Joined."); assert.equal(calls, 3); assert.equal(client.spawns, 1);
});

test("a failed advancement write repeats the original pending observation before advancing", async () => {
  const client = host(), checkpoint = client.checkpoint, counter = { calls: 0 };
  let failed = false;
  client.checkpoint = async (revision, value) => {
    if (!failed && Object.values(value[CHILD_WAITS_SLOT]?.waits ?? {}).some(item => item.poll === 1)) {
      failed = true; throw new WorkerError("transport_error");
    }
    return checkpoint(revision, value);
  };
  const run = () => new ChioProcessAgent({ ...options(client), model: model(counter) }).run(generate);
  await assert.rejects(run(), error => !suspend(error));
  assert.equal(Object.values(client.value[CHILD_WAITS_SLOT].waits)[0].poll, 0);
  client.complete = true;
  await assert.rejects(run(), suspend);
  assert.equal(counter.calls, 2); assert.equal(client.spawns, 1);
  assert.equal((await run()).text, "Children completed.");
  assert.equal(counter.calls, 3); assert.equal(client.calls.size, 3);
});
