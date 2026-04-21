export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

import { ChioInvariantError, parseJsonText } from "./errors.ts";

function compareUtf16(a: string, b: string): number {
  if (a < b) {
    return -1;
  }
  if (a > b) {
    return 1;
  }
  return 0;
}

export function canonicalizeJson(value: unknown): string {
  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new ChioInvariantError("canonical_json", "canonical JSON does not support non-finite numbers");
      }
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object":
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
      }

      return `{${Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => compareUtf16(left, right))
        .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalizeJson(entryValue)}`)
        .join(",")}}`;
    default:
      throw new ChioInvariantError(
        "canonical_json",
        `canonical JSON does not support values of type ${typeof value}`,
      );
  }
}

export function canonicalizeJsonString(input: string): string {
  return canonicalizeJson(parseJsonText(input));
}
