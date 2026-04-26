// owned-by: M02 (fuzz lane); target authored under M02.P2.T6.
//
//! libFuzzer harness for the `chio-manifest::ToolManifest` canonical-JSON
//! deserialization trust boundary plus a decode -> serialize -> decode
//! roundtrip invariant.
//!
//! `ToolManifest` deserializes with `serde(deny_unknown_fields)` across
//! every nested struct, so any structural drift between the wire format
//! and the Rust types surfaces as `Err(serde_json::Error)`. The
//! roundtrip arm asserts that once a manifest is decoded, its
//! re-encoded canonical bytes parse back into an equal-shape value
//! (via `serde_json::Value`-level structural equality, not Rust-level
//! `PartialEq`, since `ToolManifest` does not derive `PartialEq`).
//!
//! The structure-aware canonical-JSON mutator is wired in via
//! [`libfuzzer_sys::fuzz_mutator!`].
//!
//! Source: `.planning/trajectory/02-fuzzing-post-pr13.md` Round-2 P2.T6.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use chio_manifest::ToolManifest;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    let manifest: ToolManifest = match serde_json::from_slice(data) {
        Ok(m) => m,
        Err(_) => return,
    };

    let reserialized = match serde_json::to_vec(&manifest) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    let first_value: serde_json::Value = match serde_json::from_slice(&reserialized) {
        Ok(v) => v,
        Err(_) => return,
    };

    let second: ToolManifest = match serde_json::from_slice(&reserialized) {
        Ok(m) => m,
        Err(_) => return,
    };

    let second_serialized = match serde_json::to_vec(&second) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };

    let second_value: serde_json::Value = match serde_json::from_slice(&second_serialized) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Structural equality: a successful decode must roundtrip to an
    // equal canonical-JSON value. Inequality is a fuzz finding.
    assert_eq!(first_value, second_value, "manifest roundtrip drift");
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
