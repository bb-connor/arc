import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { RecoveryClient } from "../src/recovery.js";
import { LosslessJsonNumber, parseLosslessJson } from "../src/lossless-json.js";
import { canonicalJsonString } from "../src/canonical.js";

const native = JSON.parse(readFileSync(resolve(import.meta.dirname,
  "../../../../../spec/vectors/recovery/v1/authority-positive.json"), "utf8"));
const command = { schema: "chio.recovery.command.v1", version: 1, command_id: "command",
  command: { kind: "inspect_workflow", workflow_id: "workflow" } } as const;

function responseWire(result: string, status = native.command_result.status): string {
  return `{"status":${JSON.stringify(status)},"original_response":{"receipt":${JSON.stringify(native.command_result.original_response.receipt)},"result":${result}}}`;
}

async function resultFrom(source: string) {
  let calls = 0;
  const client = new RecoveryClient("https://host.example", async () => {
    calls++;
    return new Response(responseWire(source));
  });
  const response = await client.execute("capability", command);
  expect(calls).toBe(1);
  return response.original_response as unknown as {
    result: Record<string, unknown>;
    result_json: string;
  };
}

describe("lossless opaque native tool results", () => {
  it("retains unsafe integer lexemes without relaxing signed metadata", async () => {
    const source = '{"safe":42,"wide":9007199254740993,"negative":-9007199254740993,"nested":[18446744073709551615]}';
    const response = await resultFrom(source);
    expect(response.result_json).toBe(source);
    expect(response.result.safe).toBe(42);
    const wide = response.result.wide as { source: string; toBigInt(): bigint; toNumber(): number };
    expect(wide.source).toBe("9007199254740993");
    expect(wide.toBigInt()).toBe(9007199254740993n);
    expect(() => wide.toNumber()).toThrow();
    expect((response.result.negative as { source: string }).source).toBe("-9007199254740993");
    expect(((response.result.nested as unknown[])[0] as { source: string }).source).toBe("18446744073709551615");
  });

  it("preserves decimal, exponent, negative zero and Unicode representations", async () => {
    const source = '{ "exact":0.5, "decimal":0.10000000000000001,"exponent":1e+100,"integral":1e0,"negative_zero":-0,"unicode":"😀\\u0058" }';
    const response = await resultFrom(source);
    expect(response.result_json).toBe(source);
    expect(response.result.exact).toBe(0.5);
    expect(response.result.unicode).toBe("😀X");
    expect((response.result.decimal as { source: string }).source).toBe("0.10000000000000001");
    expect((response.result.exponent as { source: string }).source).toBe("1e+100");
    expect((response.result.integral as { source: string }).source).toBe("1e0");
    expect((response.result.negative_zero as { source: string }).source).toBe("-0");
  });

  it("refuses unsafe or noninteger numeric tokens in the signed status", async () => {
    for (const token of ["9007199254740993", "1.0", "1e0", "-0"]) {
      const wire = responseWire("null").replace('"revision":' + native.command_result.status.revision,
        '"revision":' + token);
      const client = new RecoveryClient("https://host.example", async () => new Response(wire));
      await expect(client.execute("capability", command)).rejects.toThrow(/^recovery.invalid_response$/);
    }
  });

  it.each(['{"n":1,"n":2}', '{"n":1,"\\u006e":2}', 'NaN', 'Infinity', '01', '1e+', '"\\ud800"', 'null true'])(
    "refuses malformed or ambiguous result %s", async (source) => {
      const client = new RecoveryClient("https://host.example", async () => new Response(responseWire(source)));
      await expect(client.execute("capability", command)).rejects.toThrow(/^recovery.invalid_response$/);
    });

  it("keeps prototype-looking result keys as ordinary own properties", async () => {
    const response = await resultFrom('{"__proto__":{"polluted":true},"constructor":7}');
    expect(Object.getPrototypeOf(response.result)).toBe(Object.prototype);
    expect(Object.hasOwn(response.result, "__proto__")).toBe(true);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("requires an explicit exact conversion or the retained JSON when forwarding numbers", () => {
    const wide = LosslessJsonNumber.fromToken("9007199254740993");
    expect(() => JSON.stringify({ wide })).toThrow();
    expect(() => canonicalJsonString({ wide })).toThrow();
    expect(LosslessJsonNumber.fromToken("1e0").toNumber()).toBe(1);
    expect(LosslessJsonNumber.fromToken("1.20").toNumber()).toBe(1.2);
    expect(() => LosslessJsonNumber.fromToken("0.10000000000000001").toNumber()).toThrow();
    expect(() => LosslessJsonNumber.fromToken("1e10000").toNumber()).toThrow();
  });

  it("counts empty containers at the nesting boundary", () => {
    expect(() => parseLosslessJson("[".repeat(64) + "]".repeat(64))).not.toThrow();
    expect(() => parseLosslessJson("[".repeat(65) + "]".repeat(65))).toThrow(/nesting bound/);
  });

  it("charges UTF-8 bytes while allowing bounded opaque collections", () => {
    const exact = '"' + "😀".repeat(65535) + "xx" + '"';
    expect(new TextEncoder().encode(exact).length).toBe(262144);
    expect(parseLosslessJson(exact).value).toBe("😀".repeat(65535) + "xx");
    expect(() => parseLosslessJson(exact.slice(0, -1) + 'x"')).toThrow(/response bound/);
    expect((parseLosslessJson("[" + "0,".repeat(5000) + "0]").value as unknown[]).length).toBe(5001);
  });
});
