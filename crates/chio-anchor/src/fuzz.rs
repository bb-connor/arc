// owned-by: M02 (fuzz lane); module authored under M02.P1.T2.
//
//! libFuzzer entry-point module for `chio-anchor`.
//!
//! Authored under M02.P1.T2 (`.planning/trajectory/02-fuzzing-post-pr13.md`
//! Phase 1, trust-boundary fuzz target #4). This module is gated behind the
//! `fuzz` Cargo feature so it only compiles into the standalone `chio-fuzz`
//! workspace at `../../fuzz`. The production build of `chio-anchor` never
//! pulls in `arbitrary`, never exposes these symbols, and never gets
//! recompiled with libFuzzer instrumentation.
//!
//! The single entry point [`fuzz_anchor_bundle_verify`] consumes arbitrary
//! bytes and drives them through the two trust-boundary surfaces in
//! `chio-anchor`'s `bundle` module:
//!
//! 1. [`crate::verify_proof_bundle`] - fail-closed multi-lane proof bundle
//!    verifier (EVM primary plus Bitcoin OTS / Solana memo secondaries).
//!    Bytes are interpreted as a JSON-encoded
//!    [`crate::AnchorProofBundle`]. Every malformed input must surface as
//!    `Err(AnchorError::*)` or `Err(serde_json::Error)`, never a panic.
//! 2. [`crate::verify_checkpoint_publication_records`] - the publication
//!    record / equivocation / witness consistency check. Bytes are
//!    interpreted as a JSON-encoded
//!    [`chio_kernel::checkpoint::CheckpointTransparencySummary`].
//!
//! Both interpretations run on every iteration so libFuzzer covers both
//! parsers concurrently from the same byte stream. No setup state is
//! required: both verifiers operate purely over their input arguments
//! (no anchor backends, no registries, no clock), so we can drive them
//! without a `OnceLock` fixture.

use chio_kernel::checkpoint::CheckpointTransparencySummary;

use crate::{verify_checkpoint_publication_records, verify_proof_bundle, AnchorProofBundle};

/// Drive arbitrary bytes through the `chio-anchor` trust-boundary surface.
///
/// Bytes are interpreted in two independent ways and each interpretation
/// is forwarded to the corresponding verifier. Errors at every step are
/// silently consumed: the trust-boundary contract guarantees the only
/// outcomes are `Err(AnchorError::*)` (good), `Err(serde_json::Error)`
/// (good), or a panic / abort (which libFuzzer surfaces as a crash). An
/// arbitrary byte stream may rarely produce a useful `Ok(_)` from
/// [`verify_proof_bundle`] (the inclusion-proof checks reject all but a
/// vanishingly small surface), but we discard it; the goal is exercising
/// the parse plus validation paths, not asserting any post-condition on
/// the success branch.
///
/// 1. As a JSON byte slice, the input is fed to `serde_json::from_slice`
///    with target type [`AnchorProofBundle`]; on success the bundle is
///    forwarded to [`verify_proof_bundle`]. This exercises the bundle
///    deserializer (deny-unknown-fields shape check across
///    `primary_proof`, `secondary_lanes`, `solana_anchor`, `note`),
///    `chio_core::web3::verify_anchor_inclusion_proof`, the Bitcoin OTS
///    linkage check (`verify_bitcoin_anchor_for_proof`), and the Solana
///    memo verifier (`verify_solana_anchor`).
/// 2. As a JSON byte slice, the input is also fed to
///    `serde_json::from_slice` with target type
///    [`CheckpointTransparencySummary`]; on success the summary is
///    forwarded to [`verify_checkpoint_publication_records`]. This
///    exercises the publication-record deserializer (publications,
///    witnesses, consistency proofs, equivocations) plus the
///    trust-anchor-binding validator and the successor-witness pairing
///    check.
pub fn fuzz_anchor_bundle_verify(data: &[u8]) {
    if let Ok(bundle) = serde_json::from_slice::<AnchorProofBundle>(data) {
        let _ = verify_proof_bundle(&bundle);
    }
    if let Ok(transparency) = serde_json::from_slice::<CheckpointTransparencySummary>(data) {
        let _ = verify_checkpoint_publication_records(&transparency);
    }
}
