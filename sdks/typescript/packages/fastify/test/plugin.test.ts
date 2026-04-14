import { describe, it, expect } from "vitest";
import Fastify from "fastify";
import { arc } from "../src/index.js";

describe("arc fastify plugin", () => {
  it("exports arc as a function", () => {
    expect(typeof arc).toBe("function");
  });

  it("registers without error", async () => {
    const fastify = Fastify();
    await fastify.register(arc, {
      sidecarUrl: "http://127.0.0.1:1",
      skip: ["/health"],
    });

    fastify.get("/health", async () => {
      return { ok: true };
    });

    // Verify the plugin registered successfully
    await fastify.ready();
    await fastify.close();
  });

  it("skipped routes bypass ARC evaluation", async () => {
    const fastify = Fastify();
    await fastify.register(arc, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      skip: ["/health"],
    });

    fastify.get("/health", async () => {
      return { ok: true };
    });

    const response = await fastify.inject({
      method: "GET",
      url: "/health",
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ ok: true });
    await fastify.close();
  });

  it("denies requests when sidecar is unreachable (fail-closed)", async () => {
    const fastify = Fastify();

    // Register ARC plugin
    await fastify.register(arc, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      timeoutMs: 1000,
    });

    fastify.get("/test", async (_request, _reply) => {
      return { data: "should not reach here" };
    });

    await fastify.ready();

    const response = await fastify.inject({
      method: "GET",
      url: "/test",
    });

    // When the sidecar is unreachable and onSidecarError is "deny" (default),
    // the plugin should return 502.
    expect(response.statusCode).toBe(502);
    const body = JSON.parse(response.body);
    expect(body.error).toBe("arc_sidecar_unreachable");
    await fastify.close();
  });

  it("allows requests when onSidecarError is allow", async () => {
    const fastify = Fastify();
    await fastify.register(arc, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      onSidecarError: "allow",
      timeoutMs: 500,
    });

    fastify.get("/test", async () => {
      return { data: "reached handler" };
    });

    const response = await fastify.inject({
      method: "GET",
      url: "/test",
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ data: "reached handler" });
    await fastify.close();
  });

  it("skip patterns with regex work", async () => {
    const fastify = Fastify();
    await fastify.register(arc, {
      sidecarUrl: "http://127.0.0.1:1", // Unreachable
      skip: [/^\/internal\//],
    });

    fastify.get("/internal/status", async () => {
      return { status: "ok" };
    });

    const response = await fastify.inject({
      method: "GET",
      url: "/internal/status",
    });

    expect(response.statusCode).toBe(200);
    await fastify.close();
  });
});
