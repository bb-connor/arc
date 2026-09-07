import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ProcessClient } from "@chio-protocol/process";

const bootstrap = JSON.parse(readFileSync(0, "utf8"));
assert.equal(bootstrap.schema, "chio.process.worker-bootstrap.v1");
const { socket_path: socketPath, credential } = bootstrap.connection;
const client = new ProcessClient(socketPath, credential);
const denied = await client.invoke("check-send-scope", "chio-ipc", "send_jobs", {
  message_key: "forbidden", payload: { items: [] },
});
assert.equal(denied.verdict, "deny");
assert.equal(denied.output, null);

const received = await client.invoke("receive-order", "chio-ipc", "receive_jobs", {
  after_sequence: "0", limit: 1,
});
assert.equal(received.verdict, "allow");
const messages = received.output.value.messages;
assert.equal(messages.length, 1);
const items = messages[0].payload.items;
assert.ok(Array.isArray(items) && items.length <= 16);
assert.ok(items.every(item => Number.isSafeInteger(item) && item >= 0));
const result = { item_count: items.length, total: items.reduce((sum, item) => sum + item, 0) };
assert.ok(Number.isSafeInteger(result.total));
const snapshot = await client.inspect();
// A repeat after checkpoint commit retains the original revision and value.
if (snapshot.checkpoint.revision === "0") {
  await client.checkpoint("0", result);
} else {
  assert.deepEqual(snapshot.checkpoint.value, result);
}
const ack = await client.invoke("ack-order", "chio-ipc", "ack_jobs", {
  through_sequence: messages[0].sequence,
});
assert.equal(ack.verdict, "allow");
writeFileSync(join(bootstrap.input.directory, "consumer.json"), JSON.stringify({
  result,
  receipts: [denied.receipt_json, received.receipt_json, ack.receipt_json],
  module_path: import.meta.resolve("@chio-protocol/process"),
}), { mode: 0o600, flush: true });
