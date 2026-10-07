/** Foundation allocation accounting, not signature or execution authority. */
import { parseLosslessJson, type LosslessJsonValue } from "./lossless-json.js";

/** Check the conjunctive native byte, structure, string and numeric budgets. */
export function assertFoundationRecoveryWire(source: string): void {
  readFoundationRecoveryWire(source);
}

/** Preserve original tokens until the owning metadata profile has refused them. */
export function readFoundationRecoveryWire(source: string): LosslessJsonValue {
  checkFoundationResources(source, true);
  // Resource accounting deliberately does not replace the syntax reader.
  return parseLosslessJson(source).value;
}

/** Charge exact response metadata bytes while retaining signed JSON numbers. */
export function assertFoundationRecoveryResponseResources(source: string): void {
  checkFoundationResources(source, false);
}

function checkFoundationResources(source: string, unsignedNumbers: boolean): void {
  const bytes = new TextEncoder().encode(source);
  if (bytes.length === 0 || bytes.length > 65536) throw new Error("recovery foundation byte bound");
  const entries: number[] = [];
  let cursor = 0;
  let nodes = 0;
  let strings = 0;
  while (cursor < bytes.length) {
    const byte = bytes[cursor];
    if (byte === undefined) throw new Error("incomplete recovery JSON");
    if ([32, 10, 13, 9, 58].includes(byte)) { cursor++; continue; }
    if (byte === 123 || byte === 91) {
      nodes++;
      if (entries.length >= 16) throw new Error("recovery foundation depth bound");
      entries.push(1);
      cursor++;
    } else if (byte === 125 || byte === 93) {
      if (entries.length === 0) throw new Error("malformed recovery container");
      entries.pop();
      cursor++;
    } else if (byte === 44) {
      const index = entries.length - 1;
      const count = entries[index];
      if (count === undefined) throw new Error("malformed recovery separator");
      entries[index] = count + 1;
      if (count >= 256) throw new Error("recovery foundation container bound");
      cursor++;
    } else if (byte === 34) {
      nodes++;
      const start = ++cursor;
      while (cursor < bytes.length && bytes[cursor] !== 34) {
        cursor += bytes[cursor] === 92 ? 2 : 1;
        if (strings + cursor - start > 32768) throw new Error("recovery foundation encoded-string bound");
      }
      if (cursor >= bytes.length) throw new Error("unterminated recovery string");
      strings += cursor - start;
      cursor++;
    } else {
      nodes++;
      const start = cursor;
      while (cursor < bytes.length && ![44, 125, 93, 32, 10, 13, 9].includes(bytes[cursor] ?? -1)) cursor++;
      const token = new TextDecoder().decode(bytes.subarray(start, cursor));
      if (unsignedNumbers && !["true", "false", "null"].includes(token)) {
        if (!/^[0-9]+$/.test(token) || !Number.isSafeInteger(Number(token))) {
          throw new Error("recovery metadata requires an unsigned safe integer token");
        }
      }
    }
    if (nodes > 4096) throw new Error("recovery foundation node bound");
  }
  if (entries.length !== 0) throw new Error("incomplete recovery container");
}
