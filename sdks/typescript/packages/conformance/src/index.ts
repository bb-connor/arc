/**
 * @arc-protocol/conformance
 *
 * Conformance test utilities for the ARC TypeScript SDK.
 * Verifies that TS SDK behavior matches the Rust kernel.
 */

export { canonicalJsonString, canonicalJsonBytes } from "./canonical.js";
export {
  validateReceiptStructure,
  verifyContentHash,
  assertVerdictMatch,
} from "./verify.js";
