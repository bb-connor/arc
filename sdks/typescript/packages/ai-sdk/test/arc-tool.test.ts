import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  ArcClient,
  ArcToolError,
  arcTool,
  type ArcReceipt,
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
  receipts: Array<ArcReceipt | Record<string, unknown> | { error: string; status: number }>,
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

function allowReceipt(id = "r-allow"): ArcReceipt {
  return {
    id,
    decision: { verdict: "allow" },
  };
}

function denyReceipt(reason = "no permission", guard = "TestGuard", id = "r-deny"): ArcReceipt {
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

// -- arcTool: basic shape --------------------------------------------------

describe("arcTool: shape and type preservation", () => {
  it("returns a tool object with the same top-level fields", () => {
    const params = z.object({ q: z.string() });
    const { fetch } = fakeFetch([]);
    const wrapped = arcTool({
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
    const wrapped = arcTool({
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
    const wrapped = arcTool({
      inputSchema: schema,
      execute: async ({ q }: { q: string }) => q,
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });
    expect(wrapped.inputSchema).toBe(schema);
  });

  it("strips ARC-only config fields from the wrapper's public surface", () => {
    const { fetch } = fakeFetch([]);
    const wrapped = arcTool({
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

// -- arcTool: allow/deny path ---------------------------------------------

describe("arcTool: allow path invokes underlying execute", () => {
  it("delegates to the original execute on allow and returns its value", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = arcTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: { toolServer: "math", toolName: "double", capabilityId: "cap-1" },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("http://127.0.0.1:9090/v1/evaluate");
    expect(calls[0]!.body).toMatchObject({
      tool_server: "math",
      tool_name: "double",
      capability_id: "cap-1",
      arguments: { n: 21 },
    });
  });

  it("forwards capability token in X-Arc-Capability header when provided", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt()]);
    const wrapped = arcTool({
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
    expect(calls[0]!.headers["x-arc-capability"]).toBe('{"id":"cap-xyz"}');
    expect(calls[0]!.body).toMatchObject({
      capability_id: "cap-xyz",
      capability: { id: "cap-xyz" },
      arguments: {},
    });
  });

  it("normalizes the Lambda evaluator response contract", async () => {
    const { fetch } = fakeFetch([lambdaAllowReceipt()]);
    const wrapped = arcTool({
      parameters: z.object({ n: z.number() }),
      execute: async ({ n }: { n: number }) => ({ doubled: n * 2 }),
      scope: { toolServer: "math", toolName: "double", capabilityId: "cap-1" },
      clientOptions: { fetch },
    });

    const result = await wrapped.execute!({ n: 21 });
    expect(result).toEqual({ doubled: 42 });
  });

  it("forwards ToolExecuteOptions (abortSignal, toolCallId) to underlying execute", async () => {
    const { fetch } = fakeFetch([allowReceipt()]);
    let capturedOpts: unknown;
    const wrapped = arcTool({
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
});

describe("arcTool: deny path throws ArcToolError", () => {
  it("throws ArcToolError with verdict/guard/reason on deny", async () => {
    const { fetch } = fakeFetch([denyReceipt("not allowed", "FsDenylist", "r-42")]);
    const wrapped = arcTool({
      parameters: z.object({ path: z.string() }),
      execute: async () => "should not run",
      scope: { toolServer: "fs", toolName: "read" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({ path: "/etc/passwd" })).rejects.toMatchObject({
      name: "ArcToolError",
      verdict: "deny",
      guard: "FsDenylist",
      reason: "not allowed",
      receiptId: "r-42",
    });
  });

  it("never calls underlying execute on deny", async () => {
    const { fetch } = fakeFetch([denyReceipt()]);
    let called = false;
    const wrapped = arcTool({
      parameters: z.object({}),
      execute: async () => {
        called = true;
        return "ran";
      },
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({})).rejects.toBeInstanceOf(ArcToolError);
    expect(called).toBe(false);
  });

  it("fails closed on sidecar error by default", async () => {
    const { fetch } = fakeFetch([{ error: "boom", status: 500 }]);
    const wrapped = arcTool({
      parameters: z.object({}),
      execute: async () => "ran",
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
    });

    await expect(wrapped.execute!({})).rejects.toMatchObject({
      name: "ArcToolError",
      verdict: "sidecar_unreachable",
    });
  });

  it("fails open (forwards to execute) when onSidecarError=allow", async () => {
    const { fetch } = fakeFetch([{ error: "boom", status: 500 }]);
    const wrapped = arcTool({
      parameters: z.object({}),
      execute: async () => "ran",
      scope: { toolServer: "s", toolName: "t" },
      clientOptions: { fetch },
      onSidecarError: "allow",
    });

    const result = await wrapped.execute!({});
    expect(result).toBe("ran");
  });
});

// -- Streaming preservation ------------------------------------------------

describe("arcTool: streaming preservation", () => {
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
    const wrapped = arcTool({
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
    const wrapped = arcTool({
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
    const wrapped = arcTool({
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

describe("arcTool: client reuse", () => {
  it("reuses a caller-provided ArcClient across invocations", async () => {
    const { fetch, calls } = fakeFetch([allowReceipt(), allowReceipt()]);
    const client = new ArcClient({ fetch });
    const wrapped = arcTool({
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
