import assert from "node:assert/strict";
import test from "node:test";
import { decodePreparedOutput } from "./ai_sdk_worker.mjs";

test("prepared application output is bounded and does not change original evidence", () => {
  const value = { isError: false, structuredContent: { status: "superseded" } };
  const body = { status: 200, headers: [], body: [...Buffer.from(JSON.stringify(value))],
    evidence: { schema: "chio.broker-execution-evidence.v2" }, receiptReference: {}, receipt: {} };
  const original = { isError: false, structuredContent: body };
  const copy = structuredClone(original);
  assert.deepEqual(decodePreparedOutput(original), value);
  assert.deepEqual(original, copy);
  for (const change of [{ status: 500 }, { body: [256] }, { evidence: {} }, { body: [255] }]) {
    assert.throws(() => decodePreparedOutput({ ...original, structuredContent: { ...body, ...change } }));
  }
});
