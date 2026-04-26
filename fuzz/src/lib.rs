// owned-by: M02 (fuzz lane); shared library authored under M02.P2.T6.
//
//! Shared library for the chio fuzz crate. Currently only exposes the
//! structure-aware canonical-JSON mutator wired into the four
//! canonical-JSON-decoding fuzz targets via
//! [`libfuzzer_sys::fuzz_mutator!`].
//!
//! The mutator source lives at `fuzz/mutators/canonical_json.rs` (path
//! demanded by the M02.P2.T6 gate `grep`). This crate re-exposes it via
//! `#[path = ...]` so the four `fuzz_targets/*.rs` binaries can import
//! it as `chio_fuzz::canonical_json::canonical_json_mutate`.

#[path = "../mutators/canonical_json.rs"]
pub mod canonical_json;
