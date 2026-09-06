import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import test from "node:test";
import { ProcessClient, PROTOCOL, MAX_RESPONSE_BYTES } from "../index.mjs";

async function fixture(handler, run) {
  const directory = await mkdtemp(join(tmpdir(), "chio-js-"));
  const path = join(directory, "s");
  const sockets = new Set();
  let calls = 0;
  const server = createServer(socket => {
    sockets.add(socket);
    let input = "";
    socket.on("error", () => {});
    socket.on("data", chunk => {
      input += chunk.toString();
      if (!input.includes("\n")) return;
      calls += 1;
      handler(socket, JSON.parse(input));
    });
  });
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(path, resolve); });
  try { await run(new ProcessClient(path, "test-secret", { timeoutMs: 1000 })); }
  finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
  return calls;
}

test("preserves receipt bytes, decimal revisions and fragmented UTF-8", async () => {
  const receipt = '{"counter":18446744073709551615,"text":"λ"}';
  const calls = await fixture((socket, request) => {
    assert.equal(request.operation.expected_revision, "9007199254740993");
    const bytes = Buffer.from(JSON.stringify({ protocol: PROTOCOL, ok: true,
      result: { receipt_json: receipt, revision: "9007199254740994" } }) + "\n");
    const split = bytes.indexOf(Buffer.from("λ")) + 1;
    socket.write(bytes.subarray(0, split));
    setImmediate(() => socket.end(bytes.subarray(split)));
  }, async client => {
    assert(!inspect(client).includes("test-secret"));
    const result = await client.checkpoint("9007199254740993", {});
    assert.equal(result.receipt_json, receipt);
    assert.equal(result.revision, "9007199254740994");
  });
  assert.equal(calls, 1);
});

test("rejects invalid and oversized responses without an automatic retry", async () => {
  for (const [payload, code] of [
    ['{"protocol":"other","ok":true,"result":{}}\n', "invalid_response"],
    ['{"protocol":"chio.process.v1","ok":true}\n', "invalid_response"],
    [Buffer.from([0xff, 10]), "invalid_response"],
    ['{"protocol":', "truncated_response"],
    ["x".repeat(MAX_RESPONSE_BYTES + 1), "response_too_large"],
    [JSON.stringify({ protocol: PROTOCOL, ok: false, error: { code: "unauthenticated" } }) + "\n", "unauthenticated"],
  ]) {
    const calls = await fixture(socket => socket.end(payload), async client => {
      await assert.rejects(client.invoke("publish", "tools", "append", {}), error => error.code === code);
    });
    assert.equal(calls, 1);
  }
});

test("unsafe numeric inputs fail before connecting", async () => {
  const client = new ProcessClient("/absent", "test-secret");
  for (const value of [NaN, Infinity, 9007199254740992]) {
    await assert.rejects(client.invoke("one", "tools", "read", { value }), TypeError);
  }
});

test("absolute response deadline closes a stalled connection", async () => {
  const directory = await mkdtemp(join(tmpdir(), "chio-js-"));
  const path = join(directory, "s");
  const sockets = [];
  const server = createServer(socket => sockets.push(socket));
  await new Promise(resolve => server.listen(path, resolve));
  try {
    await assert.rejects(new ProcessClient(path, "secret", { timeoutMs: 30 }).inspect(), error => error.code === "transport_error");
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test("state blobs snapshot input and verify canonical bytes and digest on read", async () => {
  const { createHash } = await import("node:crypto");
  const data = Buffer.from([0, 255, 128]), sha256 = createHash("sha256").update(data).digest("hex");
  await fixture((socket, request) => {
    const op = request.operation;
    assert.equal(op.sha256, sha256);
    if (op.op === "blob_put") assert.equal(op.data_base64, data.toString("base64"));
    socket.end(JSON.stringify({ protocol: PROTOCOL, ok: true, result: {
      sha256, bytes: data.length, ...(op.op === "blob_read" ? { data_base64: data.toString("base64") } : {}),
    } }) + "\n");
  }, async client => {
    const mutable = new Uint8Array(data), pending = client.putBlob(mutable);
    mutable.fill(1);
    assert.deepEqual(await pending, { sha256, bytes: 3 });
    assert.deepEqual(await client.readBlob(sha256), new Uint8Array(data));
  });
  for (const data_base64 of ["AP+A\n", "AP+B", "AP+A="]) {
    const calls = await fixture(socket => socket.end(JSON.stringify({ protocol: PROTOCOL, ok: true,
      result: { sha256, bytes: 3, data_base64 } }) + "\n"), async client => {
      await assert.rejects(client.readBlob(sha256), error => error.code === "invalid_response");
    });
    assert.equal(calls, 1);
  }
  const disconnected = new ProcessClient("/absent", "secret");
  await assert.rejects(disconnected.putBlob(new Uint8Array(1_048_577)), TypeError);
  await assert.rejects(disconnected.readBlob("A".repeat(64)), TypeError);
});
