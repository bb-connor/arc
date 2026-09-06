import { createHash } from "node:crypto";
import type { Json } from "@chio-protocol/process";

export type ModelJournalErrorCode = "model_value_unsupported" | "model_checkpoint_conflict"
  | "model_storage_unavailable" | "model_checkpoint_invalid" | "model_journal_full" | "model_request_conflict"
  | "model_outcome_unknown" | "model_response_invalid" | "model_concurrent"
  | "model_closed" | "model_aborted" | "model_replay_incomplete" | "model_checkpoint_unavailable";

export class ModelJournalError extends Error {
  constructor(readonly code: ModelJournalErrorCode) {
    super(`Chio model journal failed: ${code}`);
    this.name = "ModelJournalError";
  }
}

/** Tagged values preserve provider dates, bytes, URLs and undefined without JSON coercion. */
export function encode(value: unknown, seen = new Set<object>(), depth = 0): Json[] {
  const invalid = () => { throw new ModelJournalError("model_value_unsupported"); };
  if (depth > 64) return invalid();
  if (value === null) return ["null"];
  if (value === undefined) return ["undefined"];
  if (typeof value === "boolean") return ["boolean", value];
  if (typeof value === "string") {
    if (/[\ud800-\udfff]/u.test(value)) return invalid();
    return ["string", value];
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) return invalid();
    return Object.is(value, -0) ? ["negative-zero"] : ["number", value];
  }
  if (typeof value !== "object" || seen.has(value)) return invalid();
  const prototype = Object.getPrototypeOf(value);
  if (prototype === Date.prototype) {
    if (Reflect.ownKeys(value).length || !Number.isFinite(Date.prototype.getTime.call(value))) return invalid();
    return ["date", Date.prototype.toISOString.call(value)];
  }
  if (prototype === URL.prototype) return ["url", URL.prototype.toString.call(value)];
  if (prototype === Uint8Array.prototype || Buffer.isBuffer(value)) {
    const bytes = value as Uint8Array;
    if (Object.getOwnPropertyNames(value).length !== bytes.length || Object.getOwnPropertySymbols(value).length) return invalid();
    return ["bytes", Buffer.from(bytes).toString("base64")];
  }
  if (prototype === ArrayBuffer.prototype) {
    if (Reflect.ownKeys(value).length) return invalid();
    return ["array-buffer", Buffer.from(value as ArrayBuffer).toString("base64")];
  }
  if (prototype !== Object.prototype && prototype !== null && prototype !== Array.prototype) return invalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length || Object.values(descriptors).some(d => d.get || d.set)) return invalid();
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.keys(value).some((key, index) => key !== String(index)) ||
          Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) return invalid();
      return ["array", value.map(item => encode(item, seen, depth + 1))];
    }
    const fields: Json[] = [];
    for (const key of Object.keys(descriptors).sort()) {
      const descriptor = descriptors[key]!;
      if (!descriptor.enumerable) return invalid();
      encode(key);
      fields.push([key, encode(descriptor.value, seen, depth + 1)]);
    }
    return ["object", prototype === null, fields];
  } finally { seen.delete(value); }
}

export function decode(wire: Json, depth = 0): unknown {
  const invalid = () => { throw new ModelJournalError("model_checkpoint_invalid"); };
  if (depth > 64 || !Array.isArray(wire)) return invalid();
  const [tag, data] = wire;
  switch (tag) {
    case "null": if (wire.length === 1) return null; break;
    case "undefined": if (wire.length === 1) return undefined; break;
    case "negative-zero": if (wire.length === 1) return -0; break;
    case "boolean": if (wire.length === 2 && typeof data === "boolean") return data; break;
    case "number": if (wire.length === 2 && typeof data === "number" && Number.isFinite(data)) return data; break;
    case "string": if (wire.length === 2 && typeof data === "string") return data; break;
    case "date": if (wire.length === 2 && typeof data === "string") return new Date(data); break;
    case "url": if (wire.length === 2 && typeof data === "string") return new URL(data); break;
    case "bytes": case "array-buffer": {
      if (wire.length !== 2 || typeof data !== "string") break;
      const bytes = Uint8Array.from(Buffer.from(data, "base64"));
      if (Buffer.from(bytes).toString("base64") !== data) break;
      return tag === "bytes" ? bytes : bytes.buffer;
    }
    case "array":
      if (wire.length === 2 && Array.isArray(data)) return data.map(item => decode(item, depth + 1));
      break;
    case "object": {
      if (wire.length !== 3 || typeof data !== "boolean" || !Array.isArray(wire[2])) break;
      const result: Record<string, unknown> = data ? Object.create(null) : {};
      let previous: string | undefined;
      for (const field of wire[2]) {
        if (!Array.isArray(field) || field.length !== 2 || typeof field[0] !== "string" ||
            (previous !== undefined && previous >= field[0])) return invalid();
        previous = field[0];
        Object.defineProperty(result, field[0], { enumerable: true, configurable: true, writable: true, value: decode(field[1]!, depth + 1) });
      }
      return result;
    }
  }
  return invalid();
}

export function digest(value: Json): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

export function restored<T>(wire: Json): T {
  try {
    const result = decode(wire);
    if (digest(encode(result)) !== digest(wire)) throw new ModelJournalError("model_checkpoint_invalid");
    return result as T;
  } catch { throw new ModelJournalError("model_checkpoint_invalid"); }
}
