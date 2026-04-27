// owned-by: M02 (fuzz lane); target authored under M02.P2.T6.
//
//! libFuzzer harness for the `chio-manifest::ToolManifest` canonical-JSON
//! deserialization trust boundary plus a decode -> serialize -> decode
//! roundtrip invariant.
//!
//! `ToolManifest` deserializes with `serde(deny_unknown_fields)` across
//! every nested struct, so any structural drift between the wire format
//! and the Rust types surfaces as `Err(serde_json::Error)`. The
//! roundtrip arm asserts a BYTE-level invariant on the second-pass
//! re-serialization: once a manifest is decoded and re-encoded, the
//! `decode -> encode` cycle on those bytes MUST emit the exact same
//! bytes a second time. That catches nondeterministic serialization
//! (object-key reorderings, whitespace drift, optional-field round-trip
//! anomalies) that a `serde_json::Value`-level structural compare
//! would silently mask.
//!
//! Cleanup C6: previously the assertion compared two reparsed
//! `serde_json::Value`s, which forgives wire-format drift as long as
//! the abstract object-set is equal. The new assertion is on raw
//! bytes; structural equality is kept as a pre-check so a benign
//! `serde_json` fmt drift surfaces with a clear panic message rather
//! than a raw byte diff.
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

    // Structural equality is a pre-check: catches the easy class of
    // fuzz finding (a re-encode that drops or rewires fields) with a
    // diagnostic that names the offending shape.
    assert_eq!(
        first_value, second_value,
        "manifest roundtrip drift (structural)"
    );

    // Byte-level equality is the actual stated invariant: two
    // back-to-back `to_vec` passes over the same `ToolManifest` must
    // emit byte-identical output. Drift here is the canonical-shape
    // bug this target was authored to catch (object-key reordering,
    // whitespace drift, optional-field flip-flop). We compare the raw
    // byte strings, not their parses, so a re-encode that produces
    // structurally-equal-but-not-byte-equal output FAILS this assert.
    assert_eq!(
        reserialized, second_serialized,
        "manifest roundtrip drift (byte-level): repeated to_vec emitted different bytes"
    );
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
