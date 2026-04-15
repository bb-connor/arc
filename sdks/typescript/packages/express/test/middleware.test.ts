import { describe, it, expect } from "vitest";
import express from "express";
import http from "node:http";
import { arc, arcErrorHandler } from "../src/index.js";
import type { EvaluateResponse } from "@arc-protocol/node-http";

// Helper to make HTTP requests to a test server
async function request(
  server: http.Server,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const addr = server.address();
    if (addr == null || typeof addr === "string") {
      reject(new Error("server not listening"));
      return;
    }
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: addr.port,
        path,
        method,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf-8"),
            headers: res.headers,
          });
        });
      },
    );
    req.on("error", reject);
    if (body != null) {
      req.write(body);
    }
    req.end();
  });
}

function allowResponse(): EvaluateResponse {
  return {
    verdict: { verdict: "allow" },
    receipt: {
      id: "rcpt-1",
      request_id: "req-1",
      route_pattern: "/echo",
      method: "POST",
      caller_identity_hash: "a".repeat(64),
      verdict: { verdict: "allow" },
      evidence: [],
      response_status: 200,
      timestamp: 1_700_000_000,
      content_hash: "b".repeat(64),
      policy_hash: "c".repeat(64),
      kernel_key: "d".repeat(64),
      signature: "e".repeat(128),
    },
    evidence: [],
  };
}

async function startMockSidecar(): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/arc/evaluate") {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(allowResponse()));
      });
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const addr = server.address();
  if (addr == null || typeof addr === "string") {
    throw new Error("sidecar not listening");
  }

  return {
    server,
    url: `http://127.0.0.1:${addr.port}`,
  };
}

describe("arc() middleware", () => {
  it("exports arc as a function", () => {
    expect(typeof arc).toBe("function");
  });

  it("returns Express middleware (a function)", () => {
    const middleware = arc({});
    expect(typeof middleware).toBe("function");
  });

  it("skip patterns bypass evaluation", async () => {
    const app = express();
    app.use(
      arc({
        skip: ["/health", /^\/internal\//],
        sidecarUrl: "http://127.0.0.1:1", // Unreachable on purpose
      }),
    );
    app.get("/health", (_req, res) => {
      res.json({ ok: true });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const resp = await request(server, "GET", "/health");
      expect(resp.status).toBe(200);
      expect(JSON.parse(resp.body)).toEqual({ ok: true });
    } finally {
      server.close();
    }
  });

  it("denies requests when sidecar is unreachable (fail-closed)", async () => {
    const app = express();
    app.use(
      arc({
        sidecarUrl: "http://127.0.0.1:1", // Unreachable
        timeoutMs: 500,
      }),
    );
    app.get("/test", (_req, res) => {
      res.json({ data: "should not reach here" });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const resp = await request(server, "GET", "/test");
      expect(resp.status).toBe(502);
      const body = JSON.parse(resp.body);
      expect(body.error).toBe("arc_sidecar_unreachable");
    } finally {
      server.close();
    }
  });

  it("fail-open passthroughs do not synthesize ARC receipts", async () => {
    const app = express();
    app.use(
      arc({
        sidecarUrl: "http://127.0.0.1:1", // Unreachable
        onSidecarError: "allow",
        timeoutMs: 500,
      }),
    );
    app.get("/test", (req, res) => {
      const arcReq = req as import("../src/index.js").ArcRequest;
      res.json({
        hasArcResult: arcReq.arcResult != null,
        arcPassthrough: arcReq.arcPassthrough,
      });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const resp = await request(server, "GET", "/test");
      expect(resp.status).toBe(200);
      expect(resp.headers["x-arc-receipt-id"]).toBeUndefined();
      expect(JSON.parse(resp.body)).toEqual({
        hasArcResult: false,
        arcPassthrough: {
          mode: "allow_without_receipt",
          error: "arc_sidecar_unreachable",
          message: expect.stringContaining("sidecar"),
        },
      });
    } finally {
      server.close();
    }
  });

  it("preserves request bodies for downstream Express parsers", async () => {
    const sidecar = await startMockSidecar();
    const app = express();
    app.use(arc({ sidecarUrl: sidecar.url }));
    app.use(express.json());
    app.post("/echo", (req, res) => {
      res.json({
        parsed: req.body,
        hasRawBody: Buffer.isBuffer((req as { rawBody?: unknown }).rawBody),
      });
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, resolve));

    try {
      const payload = JSON.stringify({ hello: "world", count: 2 });
      const resp = await request(
        server,
        "POST",
        "/echo",
        {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload).toString(),
        },
        payload,
      );
      expect(resp.status).toBe(200);
      expect(JSON.parse(resp.body)).toEqual({
        parsed: { hello: "world", count: 2 },
        hasRawBody: true,
      });
    } finally {
      server.close();
      sidecar.server.close();
    }
  });
});

describe("arcErrorHandler", () => {
  it("exports arcErrorHandler as a function", () => {
    expect(typeof arcErrorHandler).toBe("function");
  });
});
