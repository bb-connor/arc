import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerProcessClient, decodeBrokerOutput, PROTOCOL } from "../index.mjs";

/** Answer each connection's request with the next queued result or error. */
async function withHost(replies, run) {
  const directory = await mkdtemp(join(tmpdir(), "chio-js-"));
  const path = join(directory, "s");
  const requests = [];
  const server = createServer(socket => {
    let input = "";
    socket.on("error", () => {});
    socket.on("data", chunk => {
      input += chunk.toString();
      if (!input.includes("\n")) return;
      requests.push(JSON.parse(input).operation);
      const reply = replies.shift();
      socket.end(JSON.stringify({ protocol: PROTOCOL, ...reply }) + "\n");
    });
  });
  await new Promise(resolve => server.listen(path, resolve));
  try {
    await run(new BrokerProcessClient(path, "test-secret", { timeoutMs: 1000 }));
  } finally {
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
  return requests;
}

test("invoke sends the host-prepared envelope and never dispatches after a failed preparation", async () => {
  const prepared = { schema: "chio.broker-execute.v1", proof: { nonce: "original" } };
  const original = { receipt_json: '{ "unchanged" : true }', output: {} };
  const requests = await withHost([
    { ok: true, result: prepared },
    { ok: true, result: original },
    { ok: false, error: { code: "conflict" } },
  ], async client => {
    assert.deepEqual(await client.invoke("key", "server", "tool", { a: 1 }, { knownOutcomeOnly: true }), original);
    await assert.rejects(client.invoke("key", "other", "tool", { a: 2 }), error => error.code === "conflict");
  });
  assert.deepEqual(requests.map(request => request.op), ["prepare_invocation", "invoke", "prepare_invocation"]);
  assert.deepEqual(requests[0], { op: "prepare_invocation", operation_key: "key", server_id: "server", tool_name: "tool", arguments: { a: 1 } });
  assert.deepEqual(requests[1].arguments, prepared);
  assert.equal(requests[1].known_outcome_only, true);
});

test("invoke refuses a preparation that is not a broker execute envelope", async () => {
  const requests = await withHost([{ ok: true, result: { schema: "other" } }], async client => {
    await assert.rejects(client.invoke("key", "server", "tool", {}), error => error.code === "invalid_preparation");
  });
  assert.deepEqual(requests.map(request => request.op), ["prepare_invocation"]);
});

test("decodeBrokerOutput rejects ambiguous or incomplete bodies", () => {
  const response = body => ({
    status: 200, headers: [], body: [...Buffer.from(body)],
    evidence: { schema: "chio.broker-execution-evidence.v2" }, receiptReference: {}, receipt: {},
  });
  const value = { output: "native", returncode: 0, nested: [{ a: "x,\"a\":" }, { a: 1 }] };
  assert.deepEqual(decodeBrokerOutput(response(JSON.stringify(value))), value);
  for (const body of ['{"x":1,"x":2}', '{"y":{"x":1,"\\u0078":2}}', '{"x":NaN}', Buffer.from([0xff]),
    "{", Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), Buffer.from([0x22, 0xed, 0xa0, 0x80, 0x22])]) {
    assert.throws(() => decodeBrokerOutput(response(body)), error => error.code === "invalid_broker_body");
  }
  for (const [field, value, code] of [
    ["status", 500, "incomplete_broker_response"],
    ["extra", 1, "incomplete_broker_response"],
    ["evidence", {}, "invalid_broker_evidence"],
    ["body", [true], "invalid_broker_body"],
    ["body", [256], "invalid_broker_body"],
  ]) {
    const invalid = { ...response("{}"), [field]: value };
    assert.throws(() => decodeBrokerOutput(invalid), error => error.code === code);
  }
});
