import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ChioInvariantError, verifyReceipt, verifyReceiptWithTrustedSigners } from "../src/index.ts";
import type { ChioReceipt } from "../src/index.ts";

const testDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(testDir, "../../../../");

async function readJson<T>(relativePath: string): Promise<T> {
  return JSON.parse(await readFile(resolve(repoRoot, relativePath), "utf8")) as T;
}

async function receipt(caseId: string): Promise<Record<string, unknown>> {
  const vectors = await readJson<{ cases: Array<{ id: string; receipt: ChioReceipt }> }>(
    "tests/bindings/vectors/receipt/v1.json",
  );
  const found = vectors.cases.find((item) => item.id === caseId);
  assert.ok(found, caseId);
  return structuredClone(found.receipt) as unknown as Record<string, unknown>;
}

async function padded(caseId: string, pointer: string): Promise<Record<string, unknown>> {
  const value = await receipt(caseId);
  if (pointer === "/actor_chain/0") {
    value.actor_chain = [{ actor_id: "agent-1", pad: 0 }];
    return value;
  }
  if (pointer === "/bbs_signature") {
    value.bbs_signature = { pad: 0 };
    return value;
  }
  let target: Record<string, unknown> = value;
  for (const part of pointer.split("/").slice(1)) {
    target = (Array.isArray(target) ? target[Number(part)] : target[part]) as Record<string, unknown>;
  }
  target.pad = 0;
  return value;
}

function assertRefused(value: Record<string, unknown>, member: string): void {
  const candidate = value as unknown as ChioReceipt;
  assert.throws(
    () => verifyReceiptWithTrustedSigners(candidate, [candidate.kernel_key]),
    (error: unknown) =>
      error instanceof ChioInvariantError &&
      error.code === "json" &&
      error.message === `unknown receipt member: ${member}`,
    member,
  );
}

test("every receipt record refuses an unknown member", async () => {
  for (const [caseId, pointer] of [
    ["allow_receipt", ""],
    ["allow_receipt", "/action"],
    ["allow_receipt", "/decision"],
    ["deny_receipt", "/decision"],
    ["allow_receipt", "/evidence/0"],
    ["allow_receipt", "/actor_chain/0"],
    ["allow_receipt", "/bbs_signature"],
  ] as const) {
    assertRefused(await padded(caseId, pointer), `${pointer}/pad`);
  }
});

test("an unsigned schema member is refused", async () => {
  const value = await receipt("allow_receipt");
  value.schema = "chio.receipt.v1";
  assertRefused(value, "/schema");
});

test("the protocol-primitives unknown-field case is refused", async () => {
  const corpus = await readJson<{
    cases: Array<{ name: string; valid: boolean; instance: ChioReceipt }>;
  }>("tests/bindings/fixtures/protocol-primitives-v1.json");
  const found = corpus.cases.find((item) => item.name === "receipt-unknown-field");
  assert.ok(found);
  assert.equal(found.valid, false);
  assert.throws(
    () => verifyReceipt(found.instance),
    (error: unknown) =>
      error instanceof ChioInvariantError && error.message === "unknown receipt member: /unsigned_extension",
  );
});
