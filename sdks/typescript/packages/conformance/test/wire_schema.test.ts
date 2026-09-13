import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import { createWireSchemaValidator } from "@chio-protocol/node-http";

const commonJs = createRequire(import.meta.url)("@chio-protocol/node-http") as
  typeof import("@chio-protocol/node-http");

const schema = {
  $id: "urn:chio:test:exact-json",
  type: "object",
  required: ["value"],
  additionalProperties: false,
  properties: { value: { type: "integer", minimum: 0 } },
};

describe("public wire schema validator", () => {
  it("accepts representable bounds without modifying input", () => {
    for (const factory of [createWireSchemaValidator, commonJs.createWireSchemaValidator]) {
      const validate = factory([schema]);
      for (const value of [0, 4294967295, Number.MAX_SAFE_INTEGER]) {
        const input = Object.freeze({ value });
        expect(validate(schema.$id, input)).toBe(true);
        expect(input.value).toBe(value);
      }
      expect(validate(schema.$id, { value: "1" })).toBe(false);
    }
  });

  it("rejects unsafe numbers, unknown authority, coercion and unknown domains", () => {
    const validate = createWireSchemaValidator([schema]);
    for (const value of [Number.MAX_SAFE_INTEGER + 1, Infinity, NaN, "1", true, 1n, undefined]) {
      expect(validate(schema.$id, { value })).toBe(false);
    }
    expect(validate(schema.$id, { value: 1, caller_quota: 2 })).toBe(false);
    expect(validate("urn:chio:test:unknown", { value: 1 })).toBe(false);
    expect(validate(schema.$id, null)).toBe(false);
  });

  it("compiles references at setup and rejects cycles in input", () => {
    expect(() => createWireSchemaValidator([{ $id: "urn:chio:test:bad", $ref: "urn:missing" }])).toThrow();
    expect(() => createWireSchemaValidator([{ type: "object" }])).toThrow();
    expect(() => createWireSchemaValidator([{ $id: "urn:chio:test:async", $async: true, type: "object" }])).toThrow("must be synchronous");
    const input: Record<string, unknown> = {};
    input.self = input;
    expect(createWireSchemaValidator([schema])(schema.$id, input)).toBe(false);
  });
});
