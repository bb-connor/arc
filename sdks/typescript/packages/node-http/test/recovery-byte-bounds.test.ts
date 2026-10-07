import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createWireSchemaValidator } from "../src/wire-schema.js";
import { RecoveryClient } from "../src/recovery.js";

const schema = JSON.parse(readFileSync(resolve(import.meta.dirname,
  "../../../../../spec/schemas/chio-wire/v1/recovery/support-issue-input.schema.json"), "utf8"));
const validate = createWireSchemaValidator([schema]);

describe("protected recovery text byte bounds", () => {
  it.each(["\ud800", "\udfff"])("refuses text that cannot be encoded as UTF-8", (title) => {
    expect(validate(schema.$id, { title, body: "body" })).toBe(false);
    expect(validate(schema.$id, { title: "😀", body: "body" })).toBe(true);
  });
  it.each([0, -1, 1.5, true, "unbounded", Number.MAX_SAFE_INTEGER + 1])(
    "refuses an invalid UTF-8 byte ceiling %s", (maximum) => {
      expect(() => createWireSchemaValidator([{
        $id: "https://chio.computer/schemas/test/utf8-byte-bound",
        type: "string", "x-maxUtf8Bytes": maximum,
      }])).toThrow();
    });
  it.each([["title", 256], ["body", 16384]] as const)("charges decoded UTF-8 for %s", (member, limit) => {
    const input = { title: "title", body: "body" };
    input[member] = "é".repeat(limit / 2 + 1);
    expect(validate(schema.$id, input)).toBe(false);
    input[member] = "é".repeat(limit / 2);
    expect(validate(schema.$id, input)).toBe(true);
    input[member] = "x".repeat(limit);
    expect(validate(schema.$id, input)).toBe(true);
    input[member] += "x";
    expect(validate(schema.$id, input)).toBe(false);
  });

  it("charges escaped command strings before invoking a transport", async () => {
    let calls = 0;
    const client = new RecoveryClient("https://host.example", async () => {
      calls++;
      return new Response("recovery.unavailable", { status: 503 });
    });
    const command = { schema: "chio.recovery.command.v1", version: 1, command_id: "command",
      command: { kind: "create_workflow", creation_key: "key", template: "support_ticket_public_issue",
        request_seed: "\0".repeat(6000) } } as const;
    await expect(async () => client.execute("capability", command)).rejects.toThrow(/^recovery.invalid_command$/);
    expect(calls).toBe(0);
  });
});
