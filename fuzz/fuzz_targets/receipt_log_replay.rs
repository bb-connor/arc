// owned-by: M02 (fuzz lane); target authored under M02.P1.T8.
//
//! libFuzzer harness for the `chio-kernel-core` receipt-log replay trust
//! boundary.
//!
//! The trust boundary is the moment at which Chio re-reads a previously
//! emitted NDJSON receipt log (one canonical-JSON `ChioReceipt` per line,
//! per `tests/replay/src/golden_writer.rs`) during the M04 deterministic
//! replay path. The verifier drives, in order:
//!
//! 1. NDJSON line-splitting on `\n`.
//! 2. Per-line `serde_json::from_slice::<ChioReceipt>` decode.
//! 3. `ChioReceipt::verify_signature` (canonical-JSON re-canonicalize plus
//!    Ed25519 / multi-algorithm signature verify against the receipt's
//!    embedded `kernel_key`).
//! 4. Cross-receipt chain invariants: timestamp monotonicity and
//!    `kernel_key` consistency across the verified sequence.
//!
//! The contract is that arbitrary bytes either ingest cleanly (and verify
//! to true / false) or surface as `Err(_)`. A panic / abort anywhere along
//! the chain would crash the M04 replay gate every time the malformed
//! bytes are seen, so this target exists to keep the
//! decode-then-verify-then-check-chain path panic-free as `serde_json`,
//! the canonical-JSON pipeline, and the signature-verify backends evolve.
//!
//! Round-2 rationale (per `.planning/trajectory/02-fuzzing-post-pr13.md`
//! Phase 1 lines 379-385): catches reordered / corrupted-chain bugs that
//! `merkle_checkpoint` cannot, because the merkle root only commits to the
//! set of leaf hashes; it cannot detect a re-encoded receipt whose
//! canonical bytes still hash to the same leaf, nor a chain whose
//! timestamps move backwards while every individual signature still
//! verifies.
//!
//! Reference: `.planning/trajectory/02-fuzzing-post-pr13.md` Phase 1
//! (Round-2 trust-boundary fuzz target #12).

#![no_main]

use chio_kernel_core::fuzz::fuzz_receipt_log_replay;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_receipt_log_replay(data);
});
