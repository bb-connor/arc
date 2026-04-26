// owned-by: M02 (fuzz lane); target authored under M02.P1.T2.
//
//! libFuzzer harness for the `chio-anchor` proof-bundle / checkpoint
//! publication trust boundary.
//!
//! The anchor bundle surface is fail-closed by construction (see
//! `crates/chio-anchor/src/bundle.rs`): every arbitrary byte string must
//! surface as an `Err(AnchorError::*)`, an `Err(serde_json::Error)`, or be
//! silently ignored, rather than a panic, abort, or `Ok(_)` that would let
//! a malformed bundle escape into the rest of the system. This target
//! exists to catch parse-path regressions (unwrap/expect/UB) in:
//!
//! - The `AnchorProofBundle` JSON deserializer (`serde_json` decode plus
//!   the `deny_unknown_fields` schema-shape derives across
//!   `primary_proof`, `secondary_lanes`, `solana_anchor`, `note`).
//! - `chio_core::web3::verify_anchor_inclusion_proof` (Merkle proof and
//!   inclusion-shape checks reached via `verify_proof_bundle`).
//! - The Bitcoin OTS linkage check
//!   (`chio_anchor::verify_bitcoin_anchor_for_proof`).
//! - The Solana memo verifier (`chio_anchor::verify_solana_anchor`).
//! - The `CheckpointTransparencySummary` JSON deserializer plus
//!   `verify_checkpoint_publication_records`, including the trust-anchor
//!   binding validator and the successor-witness pairing logic.
//!
//! Input layout: bytes are forwarded to the anchor-side fuzz entry point
//! `chio_anchor::fuzz::fuzz_anchor_bundle_verify`, which exercises both
//! surfaces concurrently. The seed corpus under
//! `corpus/anchor_bundle_verify/` mixes empty input, deterministic
//! 64-byte garbage, a minimal proof-bundle JSON shape, a truncated
//! bundle JSON, a bundle with deliberately bogus Merkle-proof bytes, and
//! a checkpoint-publication-records summary so libFuzzer has a head
//! start on every parse path.

#![no_main]

use chio_anchor::fuzz::fuzz_anchor_bundle_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_anchor_bundle_verify(data);
});
