import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ChioInvariantError,
  parseReceiptJson,
  verifyReceipt,
  verifyReceiptJson,
  verifyReceiptWithTrustedSigners,
} from "../src/index.ts";
import type { ChioReceipt, ReceiptVerification } from "../src/index.ts";

const testDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testDir, "../../../../");

interface ReceiptVector {
  id: string;
  receipt: ChioReceipt;
  expected: ReceiptVerification;
}

async function readJson<T>(relativePath: string): Promise<T> {
  return JSON.parse(await readFile(resolve(repoRoot, relativePath), "utf8")) as T;
}

async function receiptVectors(): Promise<ReceiptVector[]> {
  return (await readJson<{ cases: ReceiptVector[] }>("tests/bindings/vectors/receipt/v1.json")).cases;
}

function injectOnce(text: string, anchor: string, inserted: string): string {
  assert.equal(text.split(anchor).length, 2, anchor);
  return text.replace(anchor, `${anchor}${inserted}`);
}

function forgeries(compact: string): Array<[string, string]> {
  return [
    ["nested action.parameters", injectOnce(compact, '"parameters":{', '"path":"/etc/shadow",')],
    ["nested metadata", injectOnce(compact, '"metadata":{', '"surface":"forged",')],
    ["nested evidence entry", injectOnce(compact, '"evidence":[{', '"details":"forged",')],
    ["top-level tool_name", compact.replace("{", '{"tool_name":"shell_exec",')],
  ];
}

function assertRejected(text: string, label: string): void {
  const trusted = [(JSON.parse(text) as ChioReceipt).kernel_key];
  let verification: ReceiptVerification | undefined;
  try {
    verification = verifyReceiptWithTrustedSigners(parseReceiptJson(text), trusted);
  } catch (error) {
    assert.ok(error instanceof ChioInvariantError, label);
    assert.equal(error.code, "json", label);
    assert.throws(() => verifyReceiptJson(text), ChioInvariantError, label);
    return;
  }
  assert.fail(`duplicate keys in ${label} were accepted: ${JSON.stringify(verification)}`);
}

test("signed receipt with duplicate keys rejects at the original text", async () => {
  const vector = (await receiptVectors()).find((item) => item.id === "allow_receipt");
  assert.ok(vector);
  const compact = JSON.stringify(vector.receipt);
  const verification = verifyReceiptWithTrustedSigners(parseReceiptJson(compact), [
    vector.receipt.kernel_key,
  ]);
  assert.ok(verification.ok && verification.authorized);
  for (const [label, forged] of forgeries(compact)) {
    assert.deepEqual(JSON.parse(forged), vector.receipt, `${label} collapses last-wins`);
    assertRejected(forged, label);
  }
});

test("protocol-primitives raw receipt cases reject at the original text", async () => {
  const corpus = await readJson<{
    raw_cases: Array<{ name: string; schema_file: string; instance_text: string }>;
  }>("tests/bindings/fixtures/protocol-primitives-v1.json");
  const names: string[] = [];
  for (const rawCase of corpus.raw_cases) {
    if (rawCase.schema_file !== "receipt/record.schema.json") continue;
    assertRejected(rawCase.instance_text, rawCase.name);
    names.push(rawCase.name);
  }
  assert.deepEqual(names, ["receipt-duplicate-id", "receipt-duplicate-parameter"]);
});

test("receipt vectors verify identically from compact and pretty text", async () => {
  for (const vector of await receiptVectors()) {
    for (const text of [JSON.stringify(vector.receipt), JSON.stringify(vector.receipt, null, 2)]) {
      assert.deepEqual(verifyReceipt(parseReceiptJson(text)), vector.expected, vector.id);
    }
  }
});

test("receipt parsing keeps JSON.parse number and string results", () => {
  for (const text of [
    '{"max":18446744073709551615,"min":-9223372036854775808,"wide":1180591620717411303424}',
    '{"zero":-0,"float_zero":-0.0,"exp":1e2,"padded":0.10,"small":1.5e-7,"big":1E+21}',
    '{"nested":[{"a":1.0},[2,[3.25]],{"b":{"c":null,"d":true}}]}',
    '{"text":"caf\\u00e9 \\u2028 \\ud83d\\ude00 tab\\t","raw":"café"}',
    ' \n{"spaced" : [ 1 , 2 ] }\t',
  ]) {
    assert.deepStrictEqual(parseReceiptJson(text), JSON.parse(text), text);
  }
  assert.throws(() => parseReceiptJson("{not json"), ChioInvariantError);
});
