// owned-by: M02 (fuzz lane); target authored under M02.P2.T6.
//
//! libFuzzer self-driver for the structure-aware canonical-JSON mutator.
//!
//! The fuzz target body is intentionally minimal: it round-trips bytes
//! through `serde_json::from_slice::<serde_json::Value>` so the only
//! interesting work happens inside
//! [`chio_fuzz::canonical_json::canonical_json_mutate`], wired in below
//! via [`libfuzzer_sys::fuzz_mutator!`]. This target's purpose is two-fold:
//!
//! 1. Exercise the mutator itself end-to-end (parse, mutate, serialize,
//!    re-parse). Any panic inside the mutator surfaces here.
//! 2. Provide cargo-fuzz with a buildable target that proves the
//!    mutator-plus-target wiring compiles (gate-required).
//!
//! Source: `.planning/trajectory/02-fuzzing-post-pr13.md` Round-2 P2.T6.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    // Round-trip through serde_json::Value. We do not unwrap because
    // the mutator deliberately returns garbage bytes when it cannot
    // produce a valid canonical-JSON output (libFuzzer's contract
    // permits invalid candidates; the SUT here is the mutator, not the
    // parser). This call exists to give the harness a coverage-bearing
    // body so libFuzzer schedules iterations.
    let _ = serde_json::from_slice::<serde_json::Value>(data);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
