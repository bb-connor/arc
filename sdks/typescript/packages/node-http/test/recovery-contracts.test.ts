import { describe, expect, it, vi } from "vitest";
import { canonicalJsonString } from "../src/canonical.js";
import { RecoveryClient } from "../src/recovery.js";

const command = { schema: "chio.recovery.command.v1", version: 1, command_id: "command",
  command: { kind: "inspect_workflow", workflow_id: "workflow" } } as const;

describe("native recovery transport contracts", () => {
  it.each([
    ["https://host.example", "/v1/recovery/commands"],
    ["https://host.example/gateway", "/gateway/v1/recovery/commands"],
    ["https://host.example/gateway/", "/gateway/v1/recovery/commands"],
    ["https://host.example/gateway/encoded%2Fsegment", "/gateway/encoded%2Fsegment/v1/recovery/commands"],
  ])("preserves the service mount path for %s", async (endpoint, path) => {
    const urls: string[] = [];
    const client = new RecoveryClient(endpoint, async (url) => {
      urls.push(String(url));
      return new Response("recovery.unavailable", { status: 503 });
    });
    await expect(client.execute("capability", command)).rejects.toThrow(/^recovery.unavailable$/);
    expect(new URL(urls[0] ?? "").pathname).toBe(path);
  });
  it.each([[400, "invalid_command"], [403, "authority_denied"], [409, "conflict"],
    [409, "unsupported_profile"], [409, "uncovered_mediation"], [409, "restart_required"],
    [409, "unknown_effect"], [503, "unavailable"], [409, "probe_expired"], [409, "origin_refused"],
    [503, "busy"], [413, "projection_too_large"]] as const)(
    "retains the exact public native error for HTTP %s: %s", async (status, code) => {
      let calls = 0;
      const client = new RecoveryClient("http://localhost:1", async () => {
        calls++;
        return new Response(`recovery.${code}`, { status });
      });
      await expect(client.execute("private-capability", command)).rejects.toThrow(`recovery.${code}`);
      expect(calls).toBe(1);
    });

  it("rejects arbitrary upstream diagnostics and status/category mismatches", async () => {
    for (const body of ["private-capability", "recovery.restart_required\n", "recovery.authority_denied"]) {
      const client = new RecoveryClient("http://localhost:1", async () => new Response(body, { status: 503 }));
      await expect(client.execute("private-capability", command)).rejects.toThrow(/^recovery.refused_or_unavailable$/);
    }
  });

  it("uses bounded route-specific deadlines", async () => {
    const timeout = vi.spyOn(AbortSignal, "timeout");
    try {
      const client = new RecoveryClient("http://localhost:1", async () => new Response("recovery.unavailable", { status: 503 }));
      await expect(client.execute("capability", command)).rejects.toThrow();
      await expect(client.setupProbe("capability", "workflow")).rejects.toThrow();
      expect(timeout.mock.calls).toEqual([[20000], [120000]]);
    } finally { timeout.mockRestore(); }
  });

  it.each([0, 121, 1.5, Number.NaN, Number.POSITIVE_INFINITY])("rejects invalid wait budget %s", (timeoutSeconds) => {
    expect(() => new RecoveryClient("http://localhost:1", fetch, { timeoutSeconds })).toThrow("recovery.invalid_budget");
  });

  it.each(["request", "body"])("bounds a stalled %s even when an injected transport ignores abort", async (phase) => {
    let calls = 0;
    let cancelled = false;
    const client = new RecoveryClient("http://localhost:1", async () => {
      calls++;
      if (phase === "request") return new Promise<Response>(() => {});
      return new Response(new ReadableStream({ cancel() { cancelled = true; } }));
    }, { timeoutSeconds: 1 });
    let safetyTimer: ReturnType<typeof setTimeout> | undefined;
    const safety = new Promise<never>((_, reject) => {
      safetyTimer = setTimeout(() => reject(new Error("test safety deadline exceeded")), 3000);
    });
    try {
      await expect(Promise.race([client.execute("capability", command), safety])).rejects.toThrow(/^recovery.unavailable$/);
      expect(calls).toBe(1);
      if (phase === "body") expect(cancelled).toBe(true);
    } finally { clearTimeout(safetyTimer); }
  });
});

describe("raw setup authorization inputs", () => {
  const { cases } = JSON.parse(readFileSync(new URL(
    "../../../../../spec/vectors/recovery/v1/product-contracts.json", import.meta.url,
  ), "utf8")) as { cases: { name: string; body: { body: unknown } }[] };
  const probe = cases.find((item) => item.name === "signed-recovery-setup-probe.schema.json");
  if (!probe) throw new Error("native signed setup probe fixture missing");

  it.each(["duplicate_body", "fractional_version", "exponent_version", "negative_zero"])(
    "refuses %s before invoking the transport", async (mutation) => {
      const baseline = JSON.stringify(probe.body);
      const wire = mutation === "duplicate_body"
        ? `{"body":${JSON.stringify(probe.body.body)},${baseline.slice(1)}`
        : mutation === "negative_zero"
          ? baseline.replace('"issued_at_unix_ms":1000', '"issued_at_unix_ms":-0')
          : baseline.replace('"domain_version":1',
            `"domain_version":${mutation === "fractional_version" ? "1.0" : "1e0"}`);
      expect(wire).not.toBe(baseline);
      let calls = 0;
      const client = new RecoveryClient("http://localhost:1", async () => {
        calls++;
        return new Response("recovery.unavailable", { status: 503 });
      });
      await expect(async () => client.setupQualify("private-capability", wire))
        .rejects.toThrow(/^recovery.invalid_command$/);
      expect(calls).toBe(0);
    });
});

describe("I-JSON canonical values", () => {
  it.each([Number.MAX_SAFE_INTEGER + 1, -Number.MAX_SAFE_INTEGER - 1, 1e21])("refuses an unsafe integer %s", (value) => {
    expect(() => canonicalJsonString({ authorization: value })).toThrow();
  });
  it.each(["\ud800", "\udfff", "valid\ud800invalid"])("refuses an unpaired surrogate", (value) => {
    expect(() => canonicalJsonString({ value })).toThrow();
    expect(() => canonicalJsonString({ [value]: "field" })).toThrow();
  });
  it("preserves a valid surrogate pair and UTF-16 key order", () => {
    expect(canonicalJsonString({ "\ue000": 2, "😀": 1, a: 3 })).toBe('{"a":3,"😀":1,"":2}');
  });
});
import { readFileSync } from "node:fs";
