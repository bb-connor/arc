import test from "node:test";
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ChioInvariantError,
  decodeSalt,
  openCommitments,
  parseReceiptDisclosure,
  parseReceiptDisclosureJson,
} from "../src/index.ts";
import type { OpeningReport } from "../src/index.ts";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../");
const examples = resolve(repoRoot, "spec/schemas/chio-wire/v1/root_authority/examples");

interface CommittedCase {
  id: string;
  receipt: { id: string; action: { parameter_commitment: unknown }; content_commitment: unknown };
  disclosure: unknown;
  delegation_context?: unknown;
  expected: OpeningReport;
  preimages: { parameters_canonical: string; content_preimage_hex: string };
}

test("openCommitments reproduces the committed-receipt vectors", async () => {
  const text = await readFile(resolve(repoRoot, "tests/bindings/vectors/receipt/committed/v1.json"), "utf8");
  const cases = (JSON.parse(text) as { cases: CommittedCase[] }).cases;
  assert.ok(cases.some((entry) => entry.id === "salt_noncanonical_tail"));
  for (const entry of cases) {
    let report: OpeningReport;
    try {
      report = openCommitments(
        entry.receipt.id,
        entry.receipt.action.parameter_commitment,
        entry.receipt.content_commitment,
        parseReceiptDisclosure(entry.disclosure),
        JSON.parse(entry.preimages.parameters_canonical),
        Buffer.from(entry.preimages.content_preimage_hex, "hex"),
      );
    } catch (error) {
      assert.ok(error instanceof ChioInvariantError, entry.id);
      report = { parameters: "rejected", content: "rejected", disclosure_valid: false };
    }
    assert.equal(report.parameters, entry.expected.parameters, entry.id);
    assert.equal(report.content, entry.expected.content, entry.id);
    if (entry.delegation_context === undefined) {
      assert.equal(report.disclosure_valid, entry.expected.disclosure_valid, entry.id);
    }
  }
});

test("disclosure decoding follows the schema examples", async () => {
  parseReceiptDisclosureJson(await readFile(resolve(examples, "valid/disclosure.json"), "utf8"));
  const invalid = (await readdir(resolve(examples, "invalid"))).filter((name) => name.startsWith("disclosure."));
  assert.equal(invalid.length, 7);
  for (const name of invalid) {
    const text = await readFile(resolve(examples, "invalid", name), "utf8");
    assert.throws(() => parseReceiptDisclosureJson(text), ChioInvariantError, name);
  }
});

test("disclosure decoding refuses duplicate keys", async () => {
  const text = await readFile(resolve(examples, "valid/disclosure.json"), "utf8");
  const receiptId = (JSON.parse(text) as { receipt_id: string }).receipt_id;
  const duplicated = text.replace('"receipt_id"', `"receipt_id": "${receiptId}", "receipt_id"`);
  assert.throws(() => parseReceiptDisclosureJson(duplicated), ChioInvariantError);
});

test("salt wire form is strict", () => {
  const canonical = "b64u:EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBA";
  assert.deepEqual(decodeSalt(canonical), Buffer.alloc(32, 0x10));
  for (const encoded of [`${canonical}=`, `b64u:${"A".repeat(42)}B`, canonical.slice(0, -1), 16]) {
    assert.throws(() => decodeSalt(encoded), ChioInvariantError, String(encoded));
  }
});
