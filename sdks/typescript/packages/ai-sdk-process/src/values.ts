import { createHash } from "node:crypto";
import type { Json } from "@chio-protocol/process";
import { ProcessToolError, type ProcessIdentity } from "./types.js";

export function identity(value: unknown): string {
  if (typeof value !== "string" || !value || value.trim() !== value ||
      /[\ud800-\udfff]/u.test(value) || Buffer.byteLength(value) > 1024 || /[\u0000-\u001f]/.test(value)) {
    throw new ProcessToolError("invalid_identity");
  }
  return value;
}

/** Payload and route changes conflict under the same operation identity. */
export function processOperationKey(scope: ProcessIdentity, toolCallId: string): string {
  const parts = ["chio.ai-sdk.tool.v1", identity(scope.namespace), identity(scope.threadId),
    identity(scope.turnId), identity(toolCallId)];
  return "ai-sdk:" + createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

/** Snapshot JSON without invoking getters, toJSON, or coercing unsupported values. */
export function json(value: unknown, seen = new Set<object>(), depth = 0): Json {
  if (depth > 64) throw new ProcessToolError("invalid_json");
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    // JSON strings must contain complete Unicode scalar values.
    for (let i = 0; i < value.length; i++) {
      const code = value.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = value.charCodeAt(++i);
        if (!(next >= 0xdc00 && next <= 0xdfff)) throw new ProcessToolError("invalid_json");
      } else if (code >= 0xdc00 && code <= 0xdfff) throw new ProcessToolError("invalid_json");
    }
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value) &&
      (!Number.isInteger(value) || Number.isSafeInteger(value))) return value;
  if (typeof value !== "object" || seen.has(value)) throw new ProcessToolError("invalid_json");
  const prototype = Object.getPrototypeOf(value);
  if ((Array.isArray(value) && prototype !== Array.prototype) ||
      (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null)) {
    throw new ProcessToolError("invalid_json");
  }
  seen.add(value);
  try {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Object.getOwnPropertySymbols(value).length ||
        Object.values(descriptors).some(d => d.get || d.set)) throw new ProcessToolError("invalid_json");
    if (Array.isArray(value)) {
      const keys = Object.keys(value);
      if (keys.length !== value.length || keys.some((key, i) => key !== String(i)) ||
          Object.getOwnPropertyNames(value).length !== value.length + 1) throw new ProcessToolError("invalid_json");
      return Object.freeze(value.map(item => json(item, seen, depth + 1))) as Json[];
    }
    const copy: { [key: string]: Json } = Object.create(null);
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (!descriptor.enumerable) throw new ProcessToolError("invalid_json");
      json(key);
      copy[key] = json(descriptor.value, seen, depth + 1);
    }
    return Object.freeze(copy);
  } finally {
    seen.delete(value);
  }
}
