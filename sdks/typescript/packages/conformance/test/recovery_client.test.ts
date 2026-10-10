import { describe, expect, it } from "vitest";
import { RecoveryClient } from "../src/recovery.js";
import { canonicalJsonString } from "../src/canonical.js";
import type { Recovery_Command } from "../src/_generated/index.js";

const reply = {status:{command_id:"original-command",workflow_id:"workflow",revision:1,control:"active",effect:{kind:"never_admitted"},release:{kind:"not_available"}}};
const command: Recovery_Command.RecoveryCommandV1 = { schema: "chio.recovery.command.v1", version: 1,
  command_id: "original-command", command: { kind: "inspect_workflow", workflow_id: "workflow" } };

describe("Rust-owned recovery transport", () => {
  it("preserves exactly the same semantic bytes and identity across lost acknowledgements", async () => {
    const requests: string[] = [];
    const transport: typeof fetch = async (_url, options) => {
      expect(options?.redirect).toBe("error");
      requests.push(new TextDecoder().decode(options?.body as Uint8Array));
      return new Response(JSON.stringify(reply), { status: requests.length === 1 ? 503 : 200 });
    };
    const client = new RecoveryClient("https://host.example", transport);
    await expect(client.execute("protected-capability", command)).rejects.toThrow("recovery.refused_or_unavailable");
    expect(requests).toHaveLength(1);
    const result = await client.execute("protected-capability", command);
    expect(result.status.effect.kind).toBe("never_admitted");
    expect(requests).toHaveLength(2);
    expect(requests[0]).toBe(requests[1]);
    for (const request of requests) {
      expect(JSON.parse(request).command).toBe(canonicalJsonString(command));
    }
  });
  it("refuses redirect and oversized replies without retry or secret-bearing errors", async () => {
    for (const response of [new Response("private-canary", {status:302}),new Response("x".repeat(262145)),new Response("{private-canary"),new Response("{}")]) {
      let calls = 0;
      const client = new RecoveryClient("https://host.example", async () => { calls++; return response; });
      await expect(client.execute("private-canary", command)).rejects.toThrow(/^recovery\./);
      expect(calls).toBe(1);
    }
  });
  it("bounds intake before a transport is called", async () => {
    let calls = 0;
    const client = new RecoveryClient("https://host.example", async () => {calls++;return new Response("{}");});
    await expect(client.execute("x".repeat(65536), command)).rejects.toThrow("recovery.resource_exhausted");
    expect(calls).toBe(0);
  });
  it("refuses unsafe control endpoints", () => {
    for (const url of ["http://foreign.example", "https://token@host.example", "https://host.example?credential=canary"]) {
      expect(() => new RecoveryClient(url)).toThrow("recovery.invalid_endpoint");
    }
  });
  it("bounds fetch and stream failures and keeps the original command", async () => {
    for (const transport of [
      async () => { throw new Error("private-canary"); },
      async () => new Response(new ReadableStream({ pull() { throw new Error("private-canary"); } })),
    ]) {
      let calls = 0;
      const client = new RecoveryClient("https://host.example", async () => { calls++; return transport(); });
      await expect(client.execute("private-canary", command)).rejects.toThrow(/^recovery.unavailable$/);
      expect(calls).toBe(1);
    }
    expect(() => new RecoveryClient("private-canary")).toThrow(/^recovery.invalid_endpoint$/);
  });
});
