import { describe, it, expect } from "vitest";
import { resolveSidecarUrl, SidecarError } from "../src/sidecar-client.js";

describe("resolveSidecarUrl", () => {
  it("uses config sidecarUrl when provided", () => {
    expect(resolveSidecarUrl({ sidecarUrl: "http://localhost:8080" })).toBe(
      "http://localhost:8080",
    );
  });

  it("strips trailing slashes", () => {
    expect(resolveSidecarUrl({ sidecarUrl: "http://localhost:8080/" })).toBe(
      "http://localhost:8080",
    );
  });

  it("defaults to 127.0.0.1:9090 when no config or env", () => {
    const original = process.env["ARC_SIDECAR_URL"];
    delete process.env["ARC_SIDECAR_URL"];
    try {
      expect(resolveSidecarUrl({})).toBe("http://127.0.0.1:9090");
    } finally {
      if (original != null) {
        process.env["ARC_SIDECAR_URL"] = original;
      }
    }
  });
});

describe("SidecarError", () => {
  it("sets code and message", () => {
    const err = new SidecarError("arc_timeout", "timed out");
    expect(err.code).toBe("arc_timeout");
    expect(err.message).toBe("timed out");
    expect(err.name).toBe("SidecarError");
    expect(err.statusCode).toBeUndefined();
  });

  it("sets status code when provided", () => {
    const err = new SidecarError("arc_evaluation_failed", "bad", 500);
    expect(err.statusCode).toBe(500);
  });

  it("is an instance of Error", () => {
    const err = new SidecarError("arc_timeout", "timed out");
    expect(err).toBeInstanceOf(Error);
  });
});
