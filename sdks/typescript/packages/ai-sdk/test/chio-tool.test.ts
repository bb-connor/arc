import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  ChioClient,
  ChioToolError,
  chioTool,
  type ChioReceipt,
} from "../src/index.js";

// -- Helpers ---------------------------------------------------------------

interface FetchCall {
  url: string;
  body: unknown;
  headers: Record<string, string>;
}

/**
 * Build a fake `fetch` that records each call and returns a sequence of
 * pre-baked `Response` objects. Uses `Response` from the global Node
 * environment (Node >= 18).
 */
function fakeFetch(
  receipts: Array<ChioReceipt | Record<string, unknown> | { error: string; status: number }>,
): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  let i = 0;
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const body = init?.body != null ? JSON.parse(init.body as string) : null;
    const headers: Record<string, string> = {};
    const rawHeaders = init?.headers;
    if (rawHeaders != null && typeof rawHeaders === "object" && !Array.isArray(rawHeaders)) {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
    }
    calls.push({ url, body, headers });
    const next = receipts[i++];
    if (next == null) {
      throw new Error("fakeFetch: no more responses queued");
    }
    if ("error" in next) {
      return new Response(next.error, { status: next.status });
    }
    return new Response(JSON.stringify(next), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { fetch: impl, calls };
}

function throwingFetch(error: Error): { fetch: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const body = init?.body != null ? JSON.parse(init.body as string) : null;
    const headers: Record<string, string> = {};
    const rawHeaders = init?.headers;
    if (rawHeaders != null && typeof rawHeaders === "object" && !Array.isArray(rawHeaders)) {
      for (const [k, v] of Object.entries(rawHeaders as Record<string, string>)) {
        headers[k.toLowerCase()] = v;
      }
    }
    calls.push({ url, body, headers });
    throw error;
  }) as typeof fetch;
  return { fetch: impl, calls };
}

function allowReceipt(id = "r-allow"): ChioReceipt {
  return {
    id,
    decision: { verdict: "allow" },
  };
}

function denyReceipt(reason = "no permission", guard = "TestGuard", id = "r-deny"): ChioReceipt {
  return {
    id,
    decision: { verdict: "deny", reason, guard },
  };
}

function lambdaAllowReceipt(id = "r-allow"): Record<string, unknown> {
  return {
    receipt_id: id,
    decision: "allow",
    capability_id: "cap-1",
    tool_server: "math",
    tool_name: "double",
    timestamp: 1_700_000_000,
  };
}

function sidecarAllowEvaluateResponse(id = "r-allow"): Record<string, unknown> {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id,
      verdict: { verdict: "allow" },
      route_pattern: "/arc/tools/math/double",
      method: "POST",
    },
    evidence: [],
  };
}

const CAPABILITY_TOKEN = JSON.stringify({
  id: "cap-1",
  issuer: "issuer-placeholder",
  subject: "subject-placeholder",
});

// -- chioTool: basic shape --------------------------------------------------

describe("chioTool: shape and type preservation", () => {
  it("returns a tool object with the same top-level fields", () => {
    const params = z.object({ q: z.string() });
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      description: "Search",
      parameters: params,
      execute: async ({ q }: { q: string }) => ({ q }),
      scope: { toolServer: "srv", toolName: "search" },
      clientOptions: { sidecarUrl: "http://127.0.0.1:9090", fetch },
    });

    expect(wrapped.description).toBe("Search");
    expect(wrapped.parameters).toBe(params);
    expect(typeof wrapped.execute).toBe("function");
  });

  it("preserves zod parameter schema reference (no re-wrapping)", () => {
    const schema = z.object({ q: z.string().min(1) });
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      parameters: schema,
      execute: async ({ q }: { q: string }) => q,
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });
    expect(wrapped.parameters).toBe(schema);
  });

  it("preserves the `inputSchema` field used by Vercel AI SDK v5", () => {
    const schema = z.object({ q: z.string() });
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      inputSchema: schema,
      execute: async ({ q }: { q: string }) => q,
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });
    expect(wrapped.inputSchema).toBe(schema);
  });

  it("strips Chio-only config fields from the wrapper's public surface", () => {
    const { fetch } = fakeFetch([]);
    const wrapped = chioTool({
      description: "d",
      parameters: z.object({}),
      execute: async () => "ok",
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
      onSidecarError: "deny",
    });
    expect("scope" in wrapped).toBe(false);
    expect("clientOptions" in wrapped).toBe(false);
    expect("onSidecarError" in wrapped).toBe(false);
  });
});

// -- chioTool: allow/deny path ---------------------------------------------

describe("chioTool: allow path invokes underlying execute", () => {
  it("delegates to the original execute on allow and returns its value", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("http://127.0.0.1:9090/arc/evaluate");
    expect(calls[0]!.body).toMatchObject({
      request_id: expect.any(String),
      method: "POST",
      route_pattern: "/arc/tools/math/double",
      path: "/arc/tools/math/double",
      query: {},
      headers: {
        "content-type": "application/json",
        "content-length": String(JSON.stringify({ n: 21 }).length),
      },
      caller: {
        subject: "anonymous",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      body_hash: expect.any(String),
      body_length: JSON.stringify({ n: 21 }).length,
      timestamp: expect.any(Number),
      tool_server: "math",
      tool_name: "double",
      capability_id: "cap-1",
      arguments: { n: 21 },
    });
    expect(calls[0]!.headers["x-chio-capability"]).toBe(CAPABILITY_TOKEN);
  });

  it("forwards capability token in X-Chio-Capability header when provided", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => "ok",
      scope: {
        toolServer: "s",
        toolName: "t",
        capabilityToken: '{"id":"cap-xyz"}',
      },
      clientOptions: { fetch },
    });

    await wrapped.execute!({});
    expect(calls[0]!.headers["x-chio-capability"]).toBe('{"id":"cap-xyz"}');
    expect(calls[0]!.body).toMatchObject({
      capability_id: "cap-xyz",
      capability: { id: "cap-xyz" },
      arguments: {},
    });
  });

  it("forwards scope metadata into the evaluation request", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => "ok",
      scope: {
        toolServer: "s",
        toolName: "t",
        metadata: { trace_id: "trace-1" },
      },
      clientOptions: { fetch },
    });

    await wrapped.execute!({});
    expect(calls[0]!.body).toMatchObject({
      metadata: { trace_id: "trace-1" },
    });
  });

  it("normalizes the Lambda evaluator response contract", async () => {
    const { fetch } = fakeFetch([lambdaAllowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });

  it("normalizes the sidecar EvaluateResponse contract", async () => {
    const { fetch } = fakeFetch([sidecarAllowEvaluateResponse()]);
    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: {
        toolServer: "math",
        toolName: "double",
        capabilityId: "cap-1",
        capabilityToken: CAPABILITY_TOKEN,
      },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });

  it("forwards ToolExecuteOptions (abortSignal, toolCallId) to underlying execute", async () => {
    const { fetch } = fakeFetch([allowReceipt()]);
    let capturedOpts: unknown;
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async (_params: unknown, options) => {
        capturedOpts = options;
        return "ok";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    const controller = new AbortController();
    await wrapped.execute!({}, {
      toolCallId: "call-1",
      abortSignal: controller.signal,
      messages: [],
    });
    expect(capturedOpts).toMatchObject({ toolCallId: "call-1" });
    expect((capturedOpts as { abortSignal?: AbortSignal }).abortSignal).toBe(controller.signal);
  });

  it("resolves a capability token when only capabilityId is configured", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: { toolServer: "math", toolName: "double", capabilityId: "cap-1" },
      resolveCapabilityToken: async (capabilityId) =>
        capabilityId === "cap-1" ? CAPABILITY_TOKEN : undefined,
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
    expect(calls[0]!.headers["x-chio-capability"]).toBe(CAPABILITY_TOKEN);
  });

  it("fails fast when capabilityId is configured without a presented token", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: { toolServer: "math", toolName: "double", capabilityId: "cap-1" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ n: 21 })).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "incomplete",
    });
    expect(calls).toHaveLength(0);
  });
});

describe("chioTool: deny path throws ChioToolError", () => {
  it("throws ChioToolError with verdict/guard/reason on deny", async () => {
    const { fetch } = fakeFetch([denyReceipt("not allowed", "FsDenylist", "r-42")]);
    const wrapped = chioTool({
      parameters: z.object({ path: z.string() }),
      execute: async () => "should not run",
      scope: { toolServer: "fs", toolName: "read" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ path: "/etc/passwd" })).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "deny",
      guard: "FsDenylist",
      reason: "not allowed",
      receiptId: "r-42",
    });
  });

  it("never calls underlying execute on deny", async () => {
    const { fetch } = fakeFetch([denyReceipt()]);
    let called = false;
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => {
        called = true;
        return "ran";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({})).rejects.toBeInstanceOf(ChioToolError);
    expect(called).toBe(false);
  });

  it("fails closed on sidecar error by default", async () => {
    const { fetch } = fakeFetch([{ error: "boom", status: 500 }]);
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => "ran",
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({})).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "sidecar_unreachable",
    });
  });

  it("fails open only for transport outages when onSidecarError=allow", async () => {
    const { fetch } = throwingFetch(new Error("connect ECONNREFUSED"));
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => "ran",
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
      onSidecarError: "allow",
    });

    const result = await wrapped.execute!({});
    expect(result).toBe("ran");
  });

  it("keeps sidecar control responses blocking even when onSidecarError=allow", async () => {
    const { fetch } = fakeFetch([{ error: "approval required", status: 409 }]);
    let called = false;
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => {
        called = true;
        return "ran";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
      onSidecarError: "allow",
    });

    await expect(wrapped.execute!({})).rejects.toMatchObject({
      name: "ChioToolError",
      verdict: "sidecar_unreachable",
    });
    expect(called).toBe(false);
  });
});

// -- Streaming preservation ------------------------------------------------

describe("chioTool: streaming preservation", () => {
  it("passes ReadableStream return value through unchanged (no buffering)", async () => {
    const stream = new ReadableStream<string>({
      start(controller) {
        controller.enqueue("a");
        controller.enqueue("b");
        controller.enqueue("c");
        controller.close();
      },
    });

    const { fetch } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => stream,
      scope: { toolServer: "s", toolName: "stream" },
      clientOptions: { fetch },
    });

    const returned = await wrapped.execute!({});
    // Critical: the wrapper must return the exact same ReadableStream
    // instance -- no tee, no clone, no buffering.
    expect(returned).toBe(stream);
    expect(returned instanceof ReadableStream).toBe(true);

    // The stream must still be uncollected and readable end-to-end.
    const reader = (returned as ReadableStream<string>).getReader();
    const chunks: string[] = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    expect(chunks).toEqual(["a", "b", "c"]);
  });

  it("preserves async generator return type (lazy iteration)", async () => {
    let yielded = 0;
    async function* gen(): AsyncGenerator<number> {
      for (let i = 0; i < 3; i++) {
        yielded++;
        yield i;
      }
    }

    const { fetch } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => gen(),
      scope: { toolServer: "s", toolName: "gen" },
      clientOptions: { fetch },
    });

    const returned = await wrapped.execute!({});
    // Wrapper must not have iterated the generator -- `yielded` stays 0
    // until the caller drives the iterator.
    expect(yielded).toBe(0);
    expect(typeof (returned as AsyncGenerator<number>)[Symbol.asyncIterator]).toBe("function");

    const collected: number[] = [];
    for await (const n of returned as AsyncGenerator<number>) {
      collected.push(n);
    }
    expect(collected).toEqual([0, 1, 2]);
    expect(yielded).toBe(3);
  });

  it("returns the same reference identity for ReadableStream (object identity check)", async () => {
    const stream = new ReadableStream<Uint8Array>();
    const { fetch } = fakeFetch([allowReceipt()]);
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => stream,
      scope: { toolServer: "s", toolName: "stream" },
      clientOptions: { fetch },
    });

    const a = await wrapped.execute!({});
    expect(Object.is(a, stream)).toBe(true);
  });
});

// -- Shared client reuse --------------------------------------------------

describe("chioTool: client reuse", () => {
  it("reuses a caller-provided ChioClient across invocations", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt(), allowReceipt()]);
    const client = new ChioClient({ fetch });
    const wrapped = chioTool({
      parameters: z.object({}),
      execute: async () => "ok",
      scope: { toolServer: "s", toolName: "t" },
      client,
    });

    await wrapped.execute!({});
    await wrapped.execute!({});
    expect(calls).toHaveLength(2);
    expect(calls[0]!.url).toBe(calls[1]!.url);
  });
});
