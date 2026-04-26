// chio-deprecation: this hand-typed surface will be replaced by
// generated bindings in milestone M01 P3 (json-schema-to-typescript).
// Mirror schemas under spec/schemas/chio-wire/v1/.
/**
 * @chio-protocol/conformance
 *
 * Conformance test utilities for the Chio TypeScript SDK.
 * Verifies that TS SDK behavior matches the Rust kernel.
 */

export { canonicalJsonString, canonicalJsonBytes } from "./canonical.js";
export {
  validateReceiptStructure,
  verifyContentHash,
  assertVerdictMatch,
} from "./verify.js";
