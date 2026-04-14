import { describe, it, expect } from "vitest";
import { buildArcHttpRequest, resolveConfig } from "../src/interceptor.js";
import type { BuildRequestOptions } from "../src/interceptor.js";

describe("buildArcHttpRequest", () => {
  it("creates a valid ArcHttpRequest", () => {
    const opts: BuildRequestOptions = {
      method: "GET",
      path: "/pets/42",
      query: { verbose: "true" },
      headers: {
        "content-type": "application/json",
        authorization: "Bearer token",
        "x-custom": "value",
      },
      caller: {
        subject: "test-user",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      bodyHash: undefined,
      bodyLength: 0,
      routePattern: "/pets/{petId}",
      capabilityId: undefined,
    };

    const req = buildArcHttpRequest(opts);

    expect(req.method).toBe("GET");
    expect(req.path).toBe("/pets/42");
    expect(req.route_pattern).toBe("/pets/{petId}");
    expect(req.query).toEqual({ verbose: "true" });
    expect(req.caller.subject).toBe("test-user");
    expect(req.body_hash).toBeUndefined();
    expect(req.body_length).toBe(0);
    expect(req.request_id).toBeTruthy();
    expect(req.timestamp).toBeGreaterThan(0);
  });

  it("filters headers to only allowed set", () => {
    const opts: BuildRequestOptions = {
      method: "POST",
      path: "/pets",
      query: {},
      headers: {
        "content-type": "application/json",
        authorization: "Bearer secret",
        "x-arc-capability": "cap-123",
        "x-custom-header": "should-not-appear",
      },
      caller: {
        subject: "anonymous",
        auth_method: { method: "anonymous" },
        verified: false,
      },
      bodyHash: "abc123",
      bodyLength: 42,
      routePattern: "/pets",
      capabilityId: "cap-123",
    };

    const req = buildArcHttpRequest(opts);

    expect(req.headers["content-type"]).toBe("application/json");
    expect(req.headers["x-arc-capability"]).toBe("cap-123");
    // Authorization should NOT be forwarded (not in allowed set)
    expect(req.headers["authorization"]).toBeUndefined();
    // Custom headers should NOT be forwarded
    expect(req.headers["x-custom-header"]).toBeUndefined();
    expect(req.body_hash).toBe("abc123");
    expect(req.body_length).toBe(42);
    expect(req.capability_id).toBe("cap-123");
  });
});

describe("resolveConfig", () => {
  it("applies defaults when no config provided", () => {
    const resolved = resolveConfig({});

    expect(resolved.onSidecarError).toBe("deny");
    expect(resolved.timeoutMs).toBe(5000);
    expect(resolved.forwardHeaders).toEqual([
      "content-type",
      "content-length",
      "x-arc-capability",
    ]);
    expect(resolved.identityExtractor).toBeDefined();
    expect(resolved.routePatternResolver).toBeDefined();
    expect(resolved.client).toBeDefined();
  });

  it("uses custom onSidecarError", () => {
    const resolved = resolveConfig({ onSidecarError: "allow" });
    expect(resolved.onSidecarError).toBe("allow");
  });

  it("uses custom timeout", () => {
    const resolved = resolveConfig({ timeoutMs: 10000 });
    expect(resolved.timeoutMs).toBe(10000);
  });
});
