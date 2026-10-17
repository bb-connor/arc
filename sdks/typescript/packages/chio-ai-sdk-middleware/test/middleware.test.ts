import { describe, expect, it, mock } from "bun:test";
import { generateText, jsonSchema, simulateReadableStream, streamText, tool, wrapLanguageModel } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import {
  ChioMiddlewareDeniedError,
  createChioMiddleware,
  isAsyncIterable,
  isReadableStreamLike,
  wrapWithChio,
  type ChioReceiptAuthority,
} from "../src/index.js";

function authorizedAllow() {
  return {
    verdict: "allow" as const,
    decision: "allow" as const,
    receipt_kind: "mediated_decision" as const,
    boundary_class: "prevent" as const,
    trust_level: "mediated" as const,
    result: "allow",
    authorized: true,
    ok: true,
    signer_trusted: true,
    signature_valid: true,
    receipt_id_valid: true,
    parameter_hash_valid: true,
  };
}

const USAGE = {
  inputTokens: { total: 1, noCache: 1, cacheRead: undefined, cacheWrite: undefined },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};

const GENERATE_RESULT = {
  content: [{ type: "text" as const, text: "ok" }],
  finishReason: { unified: "stop" as const, raw: undefined },
  usage: USAGE,
  warnings: [],
};

/// Mock V4 model whose doGenerate/doStream report each invocation.
function mockModel(onCall: () => void = () => {}) {
  return new MockLanguageModelV4({
    doGenerate: async () => {
      onCall();
      return GENERATE_RESULT;
    },
    doStream: async () => {
      onCall();
      return {
        stream: simulateReadableStream({
          chunks: [
            { type: "text-start" as const, id: "t1" },
            { type: "text-delta" as const, id: "t1", delta: "ok" },
            { type: "text-end" as const, id: "t1" },
            { type: "finish" as const, finishReason: { unified: "stop" as const, raw: undefined }, usage: USAGE },
          ],
        }),
      };
    },
  });
}

/// V4 call options declaring the named function tools.
function callOptions(...names: string[]) {
  return {
    prompt: [{ role: "user" as const, content: [{ type: "text" as const, text: "hi" }] }],
    tools: names.map(name => ({
      type: "function" as const,
      name,
      inputSchema: { type: "object" as const, properties: {} },
    })),
  };
}

/// AI SDK tool set declaring one executable function tool.
function sdkTools(name: string) {
  return {
    [name]: tool({
      description: name,
      inputSchema: jsonSchema({ type: "object", properties: {} }),
      execute: async () => "unused",
    }),
  };
}

describe("wrapWithChio", () => {
  it("runs verdict evaluation before generation when tools are present", async () => {
    const calls: string[] = [];
    const wrapped = wrapWithChio(mockModel(() => calls.push("model")), {
      evaluate: ({ toolUse }) => {
        calls.push(`verdict:${toolUse?.name}`);
        return authorizedAllow();
      },
    });

    const result = await wrapped.doGenerate(callOptions("search"));

    expect(result).toEqual(GENERATE_RESULT);
    expect(calls).toEqual(["verdict:search", "model"]);
  });

  it("keeps the wrapped model's identity", () => {
    const base = mockModel();
    const wrapped = wrapWithChio(base, { evaluate: () => authorizedAllow() });

    expect(wrapped.specificationVersion).toBe("v4");
    expect(wrapped.provider).toBe(base.provider);
    expect(wrapped.modelId).toBe(base.modelId);
  });

  it("denies before invoking the underlying model", async () => {
    let invoked = false;
    const wrapped = wrapWithChio(mockModel(() => { invoked = true; }), {
      evaluate: () => ({ verdict: "deny", reason: "blocked", receiptId: "r-deny" }),
    });

    await expect(wrapped.doGenerate(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("denies a streaming call before invoking the underlying model", async () => {
    let invoked = false;
    const wrapped = wrapWithChio(mockModel(() => { invoked = true; }), {
      evaluate: () => ({ verdict: "deny", reason: "blocked", receiptId: "r-deny" }),
    });

    await expect(wrapped.doStream(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("passes the stream result through without buffering", async () => {
    const stream = new ReadableStream();
    const base = new MockLanguageModelV4({ doStream: async () => ({ stream }) });
    const wrapped = wrapWithChio(base, { evaluate: () => authorizedAllow() });

    const result = await wrapped.doStream(callOptions("search"));

    expect(result.stream).toBe(stream);
    expect(isReadableStreamLike(result.stream)).toBe(true);
    expect(isAsyncIterable({
      async *[Symbol.asyncIterator]() {
        yield "chunk";
      },
    })).toBe(true);
  });

  it("skips evaluation when the request declares no tools", async () => {
    let evaluations = 0;
    let modelCalls = 0;
    const wrapped = wrapWithChio(mockModel(() => { modelCalls += 1; }), {
      evaluate: () => {
        evaluations += 1;
        return authorizedAllow();
      },
    });

    const result = await wrapped.doGenerate(callOptions());

    expect(result).toEqual(GENERATE_RESULT);
    expect(evaluations).toBe(0);
    expect(modelCalls).toBe(1);
  });

  it("evaluates each declared tool once, sorted by name", async () => {
    const seen: string[] = [];
    const wrapped = wrapWithChio(mockModel(), {
      evaluate: ({ toolUse }) => {
        seen.push(toolUse?.name ?? "<missing>");
        return authorizedAllow();
      },
    });

    await wrapped.doGenerate(callOptions("search", "fetch_url"));

    // Names are sorted to stabilize evaluation order across runtimes.
    expect(seen).toEqual(["fetch_url", "search"]);
  });

  it("evaluates provider-defined tools by name", async () => {
    const seen: string[] = [];
    const wrapped = wrapWithChio(mockModel(), {
      evaluate: ({ toolUse }) => {
        seen.push(toolUse?.name ?? "<missing>");
        return authorizedAllow();
      },
    });

    await wrapped.doGenerate({
      ...callOptions(),
      tools: [{ type: "provider", id: "openai.web_search", name: "web_search", args: {} }],
    });

    expect(seen).toEqual(["web_search"]);
  });

  it("denies on the first denying tool and stops invoking the model", async () => {
    let modelCalls = 0;
    const seen: string[] = [];
    const wrapped = wrapWithChio(mockModel(() => { modelCalls += 1; }), {
      evaluate: ({ toolUse }) => {
        seen.push(toolUse?.name ?? "<missing>");
        if (toolUse?.name === "fetch_url") {
          return { verdict: "deny", reason: "domain not on allowlist" };
        }
        return authorizedAllow();
      },
    });

    await expect(wrapped.doGenerate(callOptions("search", "fetch_url", "execute")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);

    expect(seen).toEqual(["execute", "fetch_url"]);
    expect(modelCalls).toBe(0);
  });

  it("rejects bare allow responses without verified receipt authority", async () => {
    let invoked = false;
    const wrapped = wrapWithChio(mockModel(() => { invoked = true; }), {
      evaluate: () => ({ verdict: "allow" }),
    });

    await expect(wrapped.doGenerate(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("denies non-canonical authorized result strings", async () => {
    let invoked = false;
    const wrapped = wrapWithChio(mockModel(() => { invoked = true; }), {
      evaluate: () => ({ ...authorizedAllow(), result: "authorized" }),
    });

    await expect(wrapped.doGenerate(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });
});

describe("tool declaration validation", () => {
  const allow = { evaluate: () => authorizedAllow() };

  it.each([
    ["an unknown type", { type: "other", name: "x", inputSchema: {} }],
    ["a missing type", { name: "x", inputSchema: {} }],
    ["an empty name", { type: "function", name: "", inputSchema: {} }],
    ["a non-string name", { type: "function", name: 7, inputSchema: {} }],
    ["a provider tool without an id", { type: "provider", name: "bash", args: {} }],
    ["a non-object entry", "search"],
  ])("denies %s before invoking the model", async (_label, entry) => {
    let invoked = false;
    const wrapped = wrapWithChio(mockModel(() => { invoked = true; }), allow);

    await expect(wrapped.doGenerate({ ...callOptions(), tools: [entry] } as never))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("reports the tool type and provider id so policy can tell a provider tool from a function", async () => {
    const seen: Array<{ name: string; type: string; id?: string | undefined }> = [];
    const wrapped = wrapWithChio(mockModel(), {
      evaluate: ({ toolUse }) => {
        seen.push({ name: toolUse!.name, type: toolUse!.type, id: toolUse!.id });
        return authorizedAllow();
      },
    });

    await wrapped.doGenerate({
      ...callOptions("bash"),
      tools: [
        ...callOptions("bash").tools,
        { type: "provider", id: "anthropic.bash_20250124", name: "bash", args: {} },
      ],
    });

    expect(seen).toEqual([
      { name: "bash", type: "function", id: undefined },
      { name: "bash", type: "provider", id: "anthropic.bash_20250124" },
    ]);
  });
});

describe("middleware ordering", () => {
  const injectTool = {
    specificationVersion: "v4" as const,
    transformParams: async ({ params }: { params: ReturnType<typeof callOptions> }) => ({
      ...params,
      tools: [
        ...(params.tools ?? []),
        { type: "function" as const, name: "injected", inputSchema: { type: "object" as const, properties: {} } },
      ],
    }),
  };

  it("denies a tool added by middleware placed before Chio in the array", async () => {
    let invoked = false;
    const model = wrapLanguageModel({
      model: mockModel(() => { invoked = true; }),
      middleware: [
        injectTool as never,
        createChioMiddleware({
          evaluate: ({ toolUse }) =>
            toolUse?.name === "injected" ? { verdict: "deny", reason: "injected" } : authorizedAllow(),
        }),
      ],
    });

    await expect(model.doGenerate(callOptions("search"))).rejects.toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });

  it("denies a tool added by middleware that wraps a Chio-wrapped model", async () => {
    let invoked = false;
    const inner = wrapWithChio(mockModel(() => { invoked = true; }), {
      evaluate: ({ toolUse }) =>
        toolUse?.name === "injected" ? { verdict: "deny", reason: "injected" } : authorizedAllow(),
    });
    const model = wrapLanguageModel({ model: inner, middleware: injectTool as never });

    await expect(model.doGenerate(callOptions("search"))).rejects.toThrow(ChioMiddlewareDeniedError);
    expect(invoked).toBe(false);
  });
});

describe("createChioMiddleware", () => {
  it("declares the v4 middleware specification with generate and stream hooks", () => {
    const middleware = createChioMiddleware({ evaluate: () => authorizedAllow() });

    expect(middleware.specificationVersion).toBe("v4");
    expect(typeof middleware.wrapGenerate).toBe("function");
    expect(typeof middleware.wrapStream).toBe("function");
  });

  it("gates generateText through the AI SDK before the model runs", async () => {
    let modelCalls = 0;
    const model = wrapWithChio(mockModel(() => { modelCalls += 1; }), {
      evaluate: ({ toolUse }) =>
        toolUse?.name === "blocked"
          ? { verdict: "deny", reason: "blocked tool" }
          : authorizedAllow(),
    });
    const allowed = await generateText({ model, prompt: "hi", tools: sdkTools("search") });
    expect(allowed.text).toBe("ok");
    expect(modelCalls).toBe(1);

    await expect(generateText({ model, prompt: "hi", tools: sdkTools("blocked") }))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(1);
  });

  it("gates streamText through the AI SDK before the model runs", async () => {
    let modelCalls = 0;
    const model = wrapWithChio(mockModel(() => { modelCalls += 1; }), {
      evaluate: () => ({ verdict: "deny", reason: "blocked tool" }),
    });

    const errors: unknown[] = [];
    const result = streamText({
      model,
      prompt: "hi",
      tools: sdkTools("search"),
      onError: ({ error }) => { errors.push(error); },
    });
    await result.consumeStream();

    expect(errors.some(error => error instanceof ChioMiddlewareDeniedError)).toBe(true);
    expect(modelCalls).toBe(0);
  });
});

/// Minimal `/chio/evaluate` response carrying just the verdict and receipt
/// body. Authority fields are deliberately omitted because the raw wire
/// response does not produce them; they are the output of verification.
function evaluateResponseBody(receiptId = "r-1") {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id: receiptId,
      verdict: { verdict: "allow" },
      signed_body: "stub",
    },
  };
}

function authorityAllow(): ChioReceiptAuthority {
  return {
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    trust_level: "mediated",
    result: "allow",
    authorized: true,
    ok: true,
    signer_trusted: true,
    signature_valid: true,
    receipt_id_valid: true,
    parameter_hash_valid: true,
  };
}

/// Matches the wire shape produced by `VerifyReceiptResponse` in
/// `crates/platform/chio-http-core/src/evaluation.rs`: `result` is `"allow"` not
/// `"authorized"`. The middleware must accept this value.
function sidecarVerifyAllow(): Record<string, unknown> {
  return {
    receipt_kind: "mediated_decision",
    boundary_class: "prevent",
    trust_level: "mediated",
    result: "allow",
    authorized: true,
    ok: true,
    signer_trusted: true,
    signature_valid: true,
    receipt_id_valid: true,
    parameter_hash_valid: true,
    signer_key_hex: "deadbeef",
  };
}

interface MockResponseInit {
  status?: number;
  body?: unknown;
}

function jsonResponse(init: MockResponseInit = {}): Response {
  const status = init.status ?? 200;
  return new Response(JSON.stringify(init.body ?? {}), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("receipt authority verification", () => {
  it("populates authority fields from explicit verifyReceipt and authorizes the call", async () => {
    const seenReceipts: Array<Record<string, unknown>> = [];
    let modelCalls = 0;
    let evaluateCalls = 0;

    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        evaluateCalls += 1;
        return jsonResponse({ body: evaluateResponseBody("r-explicit") });
      }
      throw new Error(`unexpected fetch in explicit-verifier test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
      verifyReceipt: (receipt) => {
        seenReceipts.push(receipt);
        return authorityAllow();
      },
    });

    const result = await wrapped.doGenerate(callOptions("search"));

    expect(result).toEqual(GENERATE_RESULT);
    expect(evaluateCalls).toBe(1);
    expect(modelCalls).toBe(1);
    expect(seenReceipts).toHaveLength(1);
    expect(seenReceipts[0]?.["id"]).toBe("r-explicit");
  });

  it("evaluates through the sidecar even when an EdgeRuntime global is present", async () => {
    const globals = globalThis as Record<string, unknown>;
    globals["EdgeRuntime"] = "edge-runtime";
    const seenPaths: string[] = [];
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      seenPaths.push(url);
      return jsonResponse({ body: evaluateResponseBody("r-edge-global") });
    };

    try {
      const wrapped = wrapWithChio(mockModel(() => {
          modelCalls += 1;
        }), {
        sidecarUrl: "http://sidecar.test",
        fetch: fetchMock as typeof fetch,
        verifyReceipt: () => authorityAllow(),
      });
      await wrapped.doGenerate(callOptions("search"));
    } finally {
      delete globals["EdgeRuntime"];
    }

    expect(seenPaths).toEqual(["http://sidecar.test/chio/evaluate"]);
    expect(modelCalls).toBe(1);
  });

  it("defaults to /chio/verify when no verifyReceipt is configured", async () => {
    const seenPaths: string[] = [];
    const verifyBodies: string[] = [];
    let modelCalls = 0;

    const fetchMock = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      seenPaths.push(url);
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-verify") });
      }
      if (url.endsWith("/chio/verify")) {
        // Confirm the receipt body was forwarded.
        const body = init?.body == null ? "" : String(init.body);
        verifyBodies.push(body);
        expect(body).toContain("r-verify");
        return jsonResponse({ body: authorityAllow() });
      }
      throw new Error(`unexpected fetch in default-verify test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate(callOptions("search"));

    expect(result).toEqual(GENERATE_RESULT);
    expect(modelCalls).toBe(1);
    expect(seenPaths.some(path => path.endsWith("/chio/evaluate"))).toBe(true);
    expect(seenPaths.some(path => path.endsWith("/chio/verify"))).toBe(true);
    // The Rust `/chio/verify` handler deserializes the request body
    // directly as an `HttpReceipt`. Wrapping the payload as
    // `{ receipt: ... }` would cause the real sidecar to return 400, so
    // the middleware must POST the raw receipt body. We assert the
    // top-level body matches the receipt body verbatim.
    expect(verifyBodies).toHaveLength(1);
    const parsed = JSON.parse(verifyBodies[0]!);
    expect(parsed).toEqual({
      id: "r-verify",
      verdict: { verdict: "allow" },
      signed_body: "stub",
    });
    expect(parsed.receipt).toBeUndefined();
  });

  it("verifies via the default localhost sidecar when sidecarUrl is omitted", async () => {
    // Mirrors the default-configured node path: no explicit `sidecarUrl`
    // and no `verifyReceipt`. The middleware should still call
    // `/chio/verify` against the default `http://127.0.0.1:9090`
    // (matching `resolveSidecarUrl(undefined)` on the evaluate path).
    const seenPaths: string[] = [];
    let modelCalls = 0;

    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      seenPaths.push(url);
      if (url === "http://127.0.0.1:9090/chio/evaluate") {
        return jsonResponse({ body: evaluateResponseBody("r-default-host") });
      }
      if (url === "http://127.0.0.1:9090/chio/verify") {
        return jsonResponse({ body: authorityAllow() });
      }
      throw new Error(`unexpected fetch in default-host-verify test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      // sidecarUrl deliberately omitted to exercise the documented default.
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate(callOptions("search"));

    expect(result).toEqual(GENERATE_RESULT);
    expect(modelCalls).toBe(1);
    expect(seenPaths).toEqual([
      "http://127.0.0.1:9090/chio/evaluate",
      "http://127.0.0.1:9090/chio/verify",
    ]);
  });

  it("accepts the sidecar's result: \"allow\" response shape from /chio/verify", async () => {
    // The Rust `/chio/verify` route returns `result: "allow"` (see
    // `VerifyReceiptResponse::from_http_receipt` in
    // `crates/platform/chio-http-core/src/evaluation.rs`); the middleware must
    // accept that shape and authorize when every authority field is true.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-allow") });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({ body: sidecarVerifyAllow() });
      }
      throw new Error(`unexpected fetch in result-allow test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate(callOptions("search"));
    expect(result).toEqual(GENERATE_RESULT);
    expect(modelCalls).toBe(1);
  });

  it("verifies via the resolved default URL on otherwise-allowed tool use without sidecarUrl or verifyReceipt", async () => {
    // Guards: applyReceiptAuthority must not deny tool use when callers rely on
    // the default sidecar URL (no explicit sidecarUrl / verifyReceipt).
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url === "http://127.0.0.1:9090/chio/evaluate") {
        return jsonResponse({ body: evaluateResponseBody("r-no-config") });
      }
      if (url === "http://127.0.0.1:9090/chio/verify") {
        return jsonResponse({ body: authorityAllow() });
      }
      throw new Error(`unexpected fetch in no-config test: ${url}`);
    };

    let modelCalls = 0;
    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      // Neither `sidecarUrl` nor `verifyReceipt` is configured. The
      // middleware must still authorize because both default to the
      // local sidecar and the authority response says allow.
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate(callOptions("search"));
    expect(result).toEqual(GENERATE_RESULT);
    expect(modelCalls).toBe(1);
  });

  it("fails closed when the sidecar /chio/verify route is unreachable", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-unreachable") });
      }
      if (url.endsWith("/chio/verify")) {
        throw new TypeError("connection refused");
      }
      throw new Error(`unexpected fetch in unreachable-verify test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });

  it("fails closed when verifyReceipt reports a partial authority", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-partial") });
      }
      throw new Error(`unexpected fetch in partial-authority test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
      verifyReceipt: () => ({
        // Authority result is intentionally partial: it carries the descriptive
        // fields but omits parameter_hash_valid, so the middleware must deny.
        receipt_kind: "mediated_decision",
        boundary_class: "prevent",
        trust_level: "mediated",
        result: "allow",
        authorized: true,
        ok: true,
        signer_trusted: true,
        signature_valid: true,
        receipt_id_valid: true,
      }),
    });

    await expect(wrapped.doGenerate(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });

  it("fails closed when /chio/verify response omits required authority fields", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: evaluateResponseBody("r-omit") });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({
          body: {
            // Descriptive fields are present, but authority booleans are
            // omitted. The middleware must not authorize.
            receipt_kind: "mediated_decision",
            boundary_class: "prevent",
            trust_level: "mediated",
            result: "allow",
            authorized: true,
            ok: true,
          },
        });
      }
      throw new Error(`unexpected fetch in omit-authority test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });
});

/**
 * Mirror the canonical Rust `EvaluateResponse` wire shape: the top-level
 * `verdict` is a tagged-enum object (`{verdict:"allow"}`) and the inner
 * `HttpReceipt` carries `verdict: {verdict:"allow"}` with NO sibling
 * `decision` field. These tests deliberately omit any top-level
 * `decision` string so the verdict must be lifted from the tagged-enum
 * shape alone.
 */
function httpReceiptOnlyAllowResponse(receiptId = "r-canonical"): Record<string, unknown> {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id: receiptId,
      verdict: { verdict: "allow" },
      receipt_kind: "mediated_decision",
      boundary_class: "prevent",
      tool_origin: "caller_executed",
      redaction_mode: "none",
      trust_level: "mediated",
      route_pattern: "/chio/tools/search/run",
      method: "POST",
      signed_body: "stub",
    },
    evidence: [],
  };
}

describe("receipt verdict lifting", () => {
  it("lifts nested receipt.verdict.verdict into decision when sidecar response uses the Verdict-tagged shape", async () => {
    // The Rust `Verdict` enum is `#[serde(tag = "verdict")]`, so the
    // real `HttpReceipt.verdict` is `{verdict:"allow"}` rather than a
    // plain string. The middleware must lift this nested shape: if it
    // only reads a string `record.decision` or `receipt.decision.verdict`,
    // `evaluation.decision` stays undefined and every otherwise-authorized
    // tool use is denied because `isAuthorizedEvaluation` requires
    // `decision === "allow"`. This test deliberately omits the
    // exercises the nested `receipt.verdict.verdict` lifting path.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({ body: httpReceiptOnlyAllowResponse("r-nested") });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({ body: sidecarVerifyAllow() });
      }
      throw new Error(`unexpected fetch in nested-verdict test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    const result = await wrapped.doGenerate(callOptions("search"));
    expect(result).toEqual(GENERATE_RESULT);
    expect(modelCalls).toBe(1);
  });

  it("denies when the receipt carries no parseable verdict tag", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({
          body: {
            verdict: { verdict: "allow" },
            receipt: {
              id: "r-no-tag",
              receipt_kind: "mediated_decision",
              boundary_class: "prevent",
              tool_origin: "caller_executed",
              redaction_mode: "none",
              trust_level: "mediated",
              signed_body: "stub",
            },
            evidence: [],
          },
        });
      }
      if (url.endsWith("/chio/verify")) {
        return jsonResponse({ body: sidecarVerifyAllow() });
      }
      throw new Error(`unexpected fetch in missing-tag test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate(callOptions("search"))).rejects.toThrow();
    expect(modelCalls).toBe(0);
  });

  it("rejects a plain-string verdict", async () => {
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({
          body: {
            verdict: "allow",
            receipt: {
              id: "r-plain-verdict",
              verdict: "allow",
              signed_body: "stub",
            },
            evidence: [],
          },
        });
      }
      throw new Error(`unexpected fetch in plain-string-verdict test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate(callOptions("search"))).rejects.toThrow(
      "did not include an allow or deny verdict",
    );
    expect(modelCalls).toBe(0);
  });

  it("surfaces a tagged deny verdict on the receipt as a deny evaluation", async () => {
    // The deny path must mirror the allow path: a Rust-tagged
    // `{verdict:"deny",...}` on `receipt.verdict` should lift into the
    // decision so the middleware fails closed with a deny rather than
    // an "no allow or deny verdict" parse error.
    let modelCalls = 0;
    const fetchMock = async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/chio/evaluate")) {
        return jsonResponse({
          body: {
            verdict: { verdict: "deny", reason: "not allowed", guard: "FsDenylist", http_status: 403 },
            receipt: {
              id: "r-tagged-deny",
              verdict: {
                verdict: "deny",
                reason: "not allowed",
                guard: "FsDenylist",
                http_status: 403,
              },
              receipt_kind: "mediated_decision",
              boundary_class: "prevent",
              tool_origin: "caller_executed",
              redaction_mode: "none",
              trust_level: "mediated",
              signed_body: "stub",
            },
            evidence: [],
          },
        });
      }
      throw new Error(`unexpected fetch in tagged-deny test: ${url}`);
    };

    const wrapped = wrapWithChio(mockModel(() => {
        modelCalls += 1;
      }), {
      sidecarUrl: "http://sidecar.test",
      fetch: fetchMock as typeof fetch,
    });

    await expect(wrapped.doGenerate(callOptions("search")))
      .rejects
      .toThrow(ChioMiddlewareDeniedError);
    expect(modelCalls).toBe(0);
  });
});
