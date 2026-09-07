import assert from "node:assert/strict";
import test from "node:test";
import { generateText, streamText, stepCountIs } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { WorkerError } from "@chio-protocol/process";
import { ChioProcessTools, ProcessToolError, processOperationKey } from "../dist/index.js";

const scope = { namespace: "review", threadId: "thread", turnId: "persisted-turn" };
const definition = () => ({
  name: "repo__publish", server_id: "repo", tool_name: "publish", description: "Publish report",
  input_schema: { type: "object", properties: { report: { type: "string" } }, required: ["report"], additionalProperties: false },
});
const response = (changes = {}) => ({
  request_id: "request", verdict: "allow", reason: null,
  terminal_state: { state: "completed" }, output: { kind: "value", value: { report_id: 1 } },
  receipt_json: '{"signature":"private-audit-marker"}', execution_nonce_json: "audit-nonce", ...changes,
});
const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
const generated = (content, reason = "tool-calls") => ({ content, finishReason: { unified: reason, raw: reason }, usage, warnings: [] });
const call = { type: "tool-call", toolCallId: "saved-call", toolName: "repo__publish", input: '{"report":"saved plan"}' };
const bridge = (invoke, extra = {}) => new ChioProcessTools({ ...scope, tools: [definition()], client: { invoke }, ...extra });
const execute = (tools, id = "saved-call", input = { report: "saved plan" }) => tools.repo__publish.execute(input, { toolCallId: id, messages: [] });
const code = expected => error => error instanceof ProcessToolError && error.code === expected;
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

test("identity excludes attempts, arguments and route aliases while binding the saved turn", () => {
  const key = processOperationKey(scope, "saved-call");
  assert.equal(key, processOperationKey({ ...scope, attempt: 9, credential: "rotated" }, "saved-call"));
  assert.notEqual(key, processOperationKey({ ...scope, turnId: "next-turn" }, "saved-call"));
  assert.notEqual(key, processOperationKey(scope, "next-call"));
  assert.throws(() => processOperationKey(scope, " "), code("invalid_identity"));
  assert.throws(() => processOperationKey(scope, "\ud800"), code("invalid_identity"));
});

test("generateText executes through the selected host and keeps receipts out of model messages", async () => {
  const requests = [], receipts = [];
  const model = new MockLanguageModelV4({ doGenerate: async options => {
    if (model.doGenerateCalls.length === 1) return generated([call]);
    const prompt = JSON.stringify(options.prompt);
    assert.match(prompt, /report_id/);
    assert.doesNotMatch(prompt, /private-audit-marker|audit-nonce|receipt_json/);
    return generated([{ type: "text", text: "Published." }], "stop");
  } });
  const tools = bridge(async (...args) => { requests.push(args); return response(); }, { onReceipt: event => receipts.push(event) });
  const result = await tools.run(bindings => generateText({ model, ...bindings, prompt: "Publish", stopWhen: stepCountIs(2), maxRetries: 0 }));
  assert.equal(result.text, "Published.");
  assert.equal(requests.length, 1);
  assert.equal(requests[0][0], processOperationKey(scope, call.toolCallId));
  assert.deepEqual(requests[0].slice(1, 3), ["repo", "publish"]);
  assert.equal(receipts[0].result.receipt_json, response().receipt_json);
});

test("streamText retains SDK text streaming and awaits the guarded tool result", async () => {
  const receipts = [];
  const model = new MockLanguageModelV4({ doStream: async () => {
    const first = model.doStreamCalls.length === 1;
    const chunks = [{ type: "stream-start", warnings: [] }, ...(first ? [call] : [
      { type: "text-start", id: "answer" }, { type: "text-delta", id: "answer", delta: "Published." }, { type: "text-end", id: "answer" },
    ]), { type: "finish", usage, finishReason: { unified: first ? "tool-calls" : "stop", raw: "fixture" } }];
    return { stream: new ReadableStream({ start(controller) { for (const chunk of chunks) controller.enqueue(chunk); controller.close(); } }) };
  } });
  const text = await bridge(async () => response(), { onReceipt: event => receipts.push(event) }).run(async bindings => {
    const result = streamText({ model, ...bindings, prompt: "Publish", stopWhen: stepCountIs(2), maxRetries: 0 });
    let text = "";
    for await (const part of result.textStream) text += part;
    return text;
  });
  assert.equal(text, "Published.");
  assert.equal(receipts.length, 1);
});

for (const [name, value, expected] of [
  ["denial", response({ verdict: "deny" }), "kernel_denied"],
  ["unknown", response({ terminal_state: { state: "incomplete", reason: "unknown outcome" } }), "incomplete"],
  ["MCP error", response({ output: { kind: "value", value: { isError: true, content: [] } } }), "tool_error"],
]) test(`a ${name} cannot become AI SDK success or dispatch a queued replacement`, async () => {
  let calls = 0;
  const tools = bridge(async () => { calls++; return value; }, { maxConcurrency: 1 });
  await assert.rejects(tools.run(async ({ tools }) => {
    await Promise.allSettled([execute(tools), execute(tools, "replacement")]);
    return "framework swallowed the tool errors";
  }), code(expected));
  assert.equal(calls, 1);
});

test("generateText tool-error handling cannot swallow a kernel denial", async () => {
  const model = new MockLanguageModelV4({ doGenerate: generated([call]) });
  await assert.rejects(bridge(async () => response({ verdict: "deny" })).run(bindings =>
    generateText({ model, ...bindings, prompt: "Publish", stopWhen: stepCountIs(5), maxRetries: 0 })), code("kernel_denied"));
  assert.equal(model.doGenerateCalls.length, 1);
});

test("run waits for already admitted calls on abort, preserves receipts, and never starts queued calls", async () => {
  const hold = deferred(), entered = deferred(), aborted = new AbortController();
  let calls = 0, receipts = 0, finished = false;
  const tools = bridge(async () => { calls++; entered.resolve(); await hold.promise; return response(); }, {
    abortSignal: aborted.signal, maxConcurrency: 1, onReceipt: () => { receipts++; },
  });
  const running = tools.run(async ({ tools }) => {
    await Promise.allSettled([execute(tools), execute(tools, "queued")]);
  }).finally(() => { finished = true; });
  const rejected = assert.rejects(running, code("aborted"));
  await entered.promise;
  aborted.abort();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(finished, false);
  hold.resolve();
  await rejected;
  assert.equal(calls, 1);
  assert.equal(receipts, 1);
});

test("concurrency is bounded and receipt sink failure stops later admissions", async () => {
  let active = 0, maximum = 0, calls = 0;
  await bridge(async () => {
    calls++; maximum = Math.max(maximum, ++active);
    await new Promise(resolve => setImmediate(resolve)); active--; return response();
  }, { maxConcurrency: 2 }).run(async ({ tools }) => Promise.all(Array.from({ length: 8 }, (_, i) => execute(tools, `call-${i}`))));
  assert.equal(calls, 8); assert.equal(maximum, 2);
  calls = 0;
  await assert.rejects(bridge(async () => { calls++; return response(); }, {
    maxConcurrency: 1, onReceipt: () => { throw new Error("private sink details"); },
  }).run(async ({ tools }) => { await Promise.allSettled([execute(tools), execute(tools, "later")]); }), code("receipt_sink_failed"));
  assert.equal(calls, 1);
});

test("arguments, definitions and receipt outputs cannot mutate across asynchronous execution", async () => {
  const definitionValue = definition(), hold = deferred(), entered = deferred();
  let received;
  const tools = bridge(async (_key, server, tool, args) => {
    received = { server, tool, args }; entered.resolve(); await hold.promise; return response();
  }, { tools: [definitionValue], onReceipt: event => {
    assert.throws(() => { event.result.output.value.report_id = 9; }, TypeError);
  } });
  definitionValue.server_id = "forged";
  const input = { report: "original" };
  const pending = tools.run(({ tools }) => execute(tools, "saved-call", input));
  await entered.promise; input.report = "changed"; hold.resolve();
  assert.equal((await pending).report_id, 1);
  assert.equal(received.server, "repo"); assert.equal(received.args.report, "original");
});

test("non-JSON inputs reject before dispatch without invoking coercion hooks", async () => {
  let hooks = 0, calls = 0;
  const getter = Object.defineProperty({}, "x", { enumerable: true, get() { hooks++; return 1; } });
  const sparse = new Array(1); sparse.extra = 1;
  const cycle = {}; cycle.self = cycle;
  class ArraySubclass extends Array { map() { hooks++; return []; } }
  for (const value of [undefined, NaN, 2 ** 53, 1n, { x: undefined }, sparse, cycle, getter, new ArraySubclass(1), "\ud800", { toJSON() { hooks++; return {}; } }]) {
    await assert.rejects(bridge(async () => { calls++; return response(); }).run(({ tools }) =>
      tools.repo__publish.execute(value, { toolCallId: "saved-call", messages: [] })), code("invalid_json"));
  }
  assert.equal(calls, 0); assert.equal(hooks, 0);
});

test("queue overflow and missing identities stop the run; a closed bridge cannot dispatch", async () => {
  const hold = deferred(); let calls = 0;
  const tools = bridge(async () => { calls++; await hold.promise; return response(); }, { maxConcurrency: 1, maxPending: 1 });
  await assert.rejects(tools.run(async ({ tools }) => {
    const first = execute(tools); const second = execute(tools, "overflow"); hold.resolve();
    await Promise.allSettled([first, second]);
  }), code("queue_full"));
  assert.equal(calls, 1);
  await assert.rejects(bridge(async () => { throw new Error("must not dispatch"); }).run(({ tools }) => execute(tools, "")), code("invalid_identity"));
  let retained;
  const closed = bridge(async () => { throw new Error("must not dispatch"); });
  await closed.run(async bindings => { retained = bindings.tools; });
  await assert.rejects(execute(retained), code("closed"));
  await assert.rejects(closed.run(async () => null), code("closed"));
});

test("host errors retain only public protocol codes and cannot leak private error details", async () => {
  for (const [error, expected] of [
    [Object.assign(new WorkerError("conflict"), { message: "private operation details" }), "conflict"],
    [new WorkerError("private-code-marker"), "transport_error"],
    [new Error("private socket details"), "transport_error"],
  ]) {
    await assert.rejects(bridge(async () => { throw error; }).run(({ tools }) => execute(tools)), failure => {
      assert.equal(failure.code, expected);
      assert.doesNotMatch(String(failure), /private/);
      return true;
    });
  }
});

test("missing receipts and malformed outputs stop the run while buffered streams remain JSON", async () => {
  for (const [result, expected] of [
    [response({ receipt_json: "" }), "missing_receipt"],
    [response({ output: null }), "invalid_output"],
    [response({ output: { kind: "value" } }), "invalid_output"],
  ]) await assert.rejects(bridge(async () => result).run(({ tools }) => execute(tools)), code(expected));
  const result = await bridge(async () => response({ output: { kind: "stream", chunks: ["a", { b: 2 }] } }))
    .run(({ tools }) => execute(tools));
  assert.equal(JSON.stringify(result), '{"chunks":["a",{"b":2}]}');
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.chunks));
});

test("invalid input latches before a synchronously submitted sibling can dispatch", async () => {
  let calls = 0;
  await assert.rejects(bridge(async () => { calls++; return response(); }).run(async ({ tools }) => {
    await Promise.allSettled([execute(tools, "invalid", NaN), execute(tools, "sibling")]);
  }), code("invalid_json"));
  assert.equal(calls, 0);
});
