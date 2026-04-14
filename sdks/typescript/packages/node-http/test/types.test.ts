import { describe, it, expect } from "vitest";
import { isMethodSafe, isAllowed, isDenied } from "../src/types.js";
import type { Verdict } from "../src/types.js";

describe("isMethodSafe", () => {
  it("returns true for safe methods", () => {
    expect(isMethodSafe("GET")).toBe(true);
    expect(isMethodSafe("HEAD")).toBe(true);
    expect(isMethodSafe("OPTIONS")).toBe(true);
  });

  it("returns false for side-effect methods", () => {
    expect(isMethodSafe("POST")).toBe(false);
    expect(isMethodSafe("PUT")).toBe(false);
    expect(isMethodSafe("PATCH")).toBe(false);
    expect(isMethodSafe("DELETE")).toBe(false);
  });
});

describe("verdict helpers", () => {
  it("isAllowed returns true for allow verdict", () => {
    const v: Verdict = { verdict: "allow" };
    expect(isAllowed(v)).toBe(true);
    expect(isDenied(v)).toBe(false);
  });

  it("isDenied returns true for deny verdict", () => {
    const v: Verdict = {
      verdict: "deny",
      reason: "no capability",
      guard: "CapabilityGuard",
      http_status: 403,
    };
    expect(isDenied(v)).toBe(true);
    expect(isAllowed(v)).toBe(false);
  });

  it("isDenied narrows type to access reason and guard", () => {
    const v: Verdict = {
      verdict: "deny",
      reason: "rate limited",
      guard: "RateGuard",
      http_status: 429,
    };
    if (isDenied(v)) {
      expect(v.reason).toBe("rate limited");
      expect(v.guard).toBe("RateGuard");
      expect(v.http_status).toBe(429);
    }
  });

  it("handles cancel verdict", () => {
    const v: Verdict = { verdict: "cancel", reason: "timeout" };
    expect(isAllowed(v)).toBe(false);
    expect(isDenied(v)).toBe(false);
  });

  it("handles incomplete verdict", () => {
    const v: Verdict = { verdict: "incomplete", reason: "pending" };
    expect(isAllowed(v)).toBe(false);
    expect(isDenied(v)).toBe(false);
  });
});
