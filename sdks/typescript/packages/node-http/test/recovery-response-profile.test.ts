import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { RecoveryClient } from "../src/recovery.js";
import { RecoveryError } from "../src/recovery-errors.js";
import { LosslessJsonNumber } from "../src/lossless-json.js";

const vectorRoot = resolve(import.meta.dirname, "../../../../../spec/vectors/recovery/v1");
const native = JSON.parse(readFileSync(resolve(vectorRoot, "authority-positive.json"), "utf8"));
const products = JSON.parse(readFileSync(resolve(vectorRoot, "product-contracts.json"), "utf8")).cases;
const command = { schema: "chio.recovery.command.v1", version: 1, command_id: "command",
  command: { kind: "inspect_workflow", workflow_id: "workflow" } } as const;

function receiptResponse(metadata: unknown, result: unknown = null): string {
  const response = structuredClone(native.command_result);
  response.original_response.receipt.metadata = metadata;
  response.original_response.result = result;
  return JSON.stringify(response);
}

describe("native recovery response resource profiles", () => {
  it.each([
    ["container entries", new Array(257).fill(null)],
    ["encoded strings", "a".repeat(32769)],
    ["nesting", Array.from({ length: 17 }).reduce<unknown>((value) => [value], true)],
    ["nodes", Array.from({ length: 16 }, () => new Array(256).fill(null))],
    ["wire bytes", Array.from({ length: 14 }, () => new Array(256).fill(-9007199254740991))],
  ])("refuses excessive foundation %s in signed metadata", async (_name, metadata) => {
    let calls = 0;
    const client = new RecoveryClient("https://host.example", async () => {
      calls++;
      return new Response(receiptResponse(metadata));
    });
    await expect(client.execute("capability", command)).rejects.toThrow(/^recovery.invalid_response$/);
    expect(calls).toBe(1);
  });

  it("charges raw escaped strings before typed metadata validation", async () => {
    const wire = receiptResponse("encoded-marker").replace('"encoded-marker"',
      '"' + "\\u0061".repeat(6000) + '"');
    const client = new RecoveryClient("https://host.example", async () => new Response(wire));
    await expect(client.execute("capability", command)).rejects.toThrow(/^recovery.invalid_response$/);
  });

  it("keeps the opaque result outside foundation quotas while charging signed fractions", async () => {
    const result = { text: "😀".repeat(18000), collection: new Array(300).fill(0),
      nested: Array.from({ length: 40 }).reduce<unknown>((value) => [value], "payload") };
    const metadata = { confidence: 0.5, delta: -1, nested: [1e-7, -9007199254740991] };
    const wire = receiptResponse(metadata, result);
    expect(new TextEncoder().encode(wire).length).toBeGreaterThan(65536);
    const client = new RecoveryClient("https://host.example", async () => new Response(wire));
    const response = await client.execute("capability", command);
    expect(response.original_response?.result).toEqual(result);
    expect(response.original_response?.receipt.metadata).toEqual(metadata);
    expect(response.original_response?.result_json).toBe(JSON.stringify(result));
  });

  it.each(["decision-report-view.schema.json", "policy-maintenance-view.schema.json"])(
    "retains the larger native product response profile for %s", async (schema) => {
      const view = structuredClone(products.find((row: { name: string }) => row.name === schema).body);
      const owners: Record<string, string[]> = {};
      for (let owner = 0; owner < 2; owner++) {
        const principal = `owner-${owner}`;
        owners[principal] = [principal, ...Array.from({ length: 191 }, (_value, index) =>
          `reader-${owner}-${index}`.padEnd(200, "r"))];
      }
      view.label = { kind: "known", owners, compartments: [] };
      const wire = JSON.stringify(view);
      expect(new TextEncoder().encode(wire).length).toBeGreaterThan(65536);
      expect(new TextEncoder().encode(wire).length).toBeLessThanOrEqual(262144);
      const client = new RecoveryClient("https://host.example", async () => new Response(wire));
      const result = schema.startsWith("decision")
        ? await client.readReport("capability", "report")
        : await client.proposePolicy("capability", view.proposal);
      expect(result).toEqual(view);
    });
});

describe("public lossless numeric token contract", () => {
  it.each([0, 1, ["1"], { length: 1, toString: () => "1" }])(
    "refuses a nonstring JavaScript token %s", (value) => {
      expect(() => LosslessJsonNumber.fromToken(value as unknown as string)).toThrow();
    });
});

describe("typed recovery transport failures", () => {
  it("keeps the closed unavailable category when the response body fails", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.error(new Error("stream-diagnostic-canary")); },
    });
    const client = new RecoveryClient("https://host.example", async () => new Response(stream));
    try {
      await client.execute("capability", command);
      throw new Error("expected body failure");
    } catch (error) {
      expect(error).toBeInstanceOf(RecoveryError);
      expect((error as RecoveryError).code).toBe("recovery.unavailable");
      expect((error as Error).message).not.toContain("canary");
    }
  });
});
