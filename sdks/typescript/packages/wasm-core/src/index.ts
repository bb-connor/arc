// Shared pure helpers for the Chio runtime SDKs (workers, edge, deno, browser).
//
// This module is intentionally dependency-free and side-effect-free so it can be
// consumed from every runtime target (Cloudflare Workers, Vercel Edge, Deno, and
// the browser) without pulling in any runtime-specific machinery.

/**
 * Decodes a hex-encoded receipt envelope to its canonical JSON text.
 *
 * Accepts an optional `0x` prefix. Rejects odd-length input, any non
 * hexadecimal characters and bytes that are not valid UTF-8, so malformed
 * receipts fail fast before they reach the wasm `verify_receipt` boundary.
 */
export function receiptHexToJson(hex: string): string {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error('receipt hex must have an even number of characters');
  }
  if (!/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new Error('receipt hex must contain only hexadecimal characters');
  }

  const pairs = normalized.match(/.{2}/g) ?? [];
  const bytes = Uint8Array.from(pairs.map(byte => Number.parseInt(byte, 16)));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
