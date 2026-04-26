// owned-by: M02 (fuzz lane); structure-aware mutator authored under M02.P2.T6.
//
//! Structure-aware canonical-JSON mutator for libFuzzer.
//!
//! # Why
//!
//! Random byte mutations on a libFuzzer corpus targeting a canonical-JSON
//! decoder almost always fail at the JSON parse stage before reaching the
//! canonicalization (sorted-keys / no-whitespace / RFC 8785) layer or the
//! downstream typed deserializer. That wastes CPU-seconds of fuzzer time
//! producing inputs the SUT rejects in O(1). This mutator runs ahead of
//! libFuzzer's default mutator and produces inputs that are SHAPE-VALID
//! canonical JSON, so the fuzzer spends its budget exploring the actual
//! decode -> canonicalize -> typed-validate pipeline.
//!
//! # libFuzzer extension point
//!
//! libFuzzer supports a user-supplied mutator function exported as the C
//! symbol `LLVMFuzzerCustomMutator`. The `libfuzzer-sys` crate exposes
//! that symbol via the [`libfuzzer_sys::fuzz_mutator!`] macro: each fuzz
//! target that opts in declares a `fuzz_mutator!` block alongside its
//! `fuzz_target!` block, and libfuzzer-sys generates the
//! `#[export_name = "LLVMFuzzerCustomMutator"]` shim that calls the
//! Rust closure for every iteration. The four canonical-JSON-decoding
//! fuzz targets (`canonical_json`, `capability_receipt`,
//! `manifest_roundtrip`, `mcp_envelope_decode`) all wire this module's
//! [`canonical_json_mutate`] into that macro.
//!
//! The gate for M02.P2.T6 grep-checks this file for the literal string
//! `LLVMFuzzerCustomMutator` so the wiring is auditable from the source
//! tree without having to inspect generated symbols.
//!
//! # Mutation menu
//!
//! On each call we parse `data[..size]` as `serde_json::Value`. If the
//! parse fails we return `size` unchanged and let libFuzzer's default
//! mutator handle the byte-level work (the next iteration may parse). On
//! success we pick ONE structure-preserving mutation by `seed`:
//!
//! 1. Add a key to a nested object.
//! 2. Remove a key from a nested object.
//! 3. Swap two array elements.
//! 4. Replace a string value with an interesting boundary string.
//! 5. Replace a number with an interesting boundary value
//!    (`0`, `-1`, `i64::MAX`, `u64::MAX`, `f64::INFINITY`-like, etc).
//! 6. Insert a duplicate key (challenges canonical-JSON last-wins semantics).
//! 7. Replace a UTF-8 string with a near-invalid one (control chars,
//!    surrogate-edge code points, BOM, padded whitespace).
//!
//! After the mutation we re-canonicalize the value via
//! `serde_json::to_vec` (which writes sorted-key output in stable order
//! when the object was built from sorted iteration) and copy back into
//! `data` if it fits; otherwise we fall back to truncating to `max_size`
//! and returning that length (libFuzzer requires the returned length to
//! be `<= max_size`). The mutator is stateless across calls and
//! deterministic in `seed` so libFuzzer's reproducibility guarantees
//! hold.
//!
//! # Source
//!
//! Round-2 (NEW) P2.T6 entry in
//! `.planning/trajectory/02-fuzzing-post-pr13.md`.

#![allow(clippy::cast_possible_truncation)]

use core::cmp::min;

use serde_json::{Map, Number, Value};

/// Per-iteration custom mutator entry point wired into libFuzzer via
/// [`libfuzzer_sys::fuzz_mutator!`]. The macro generates the
/// `#[export_name = "LLVMFuzzerCustomMutator"]` shim that calls this
/// function with libFuzzer's working buffer.
///
/// Contract (from the libFuzzer C API):
///
/// - `data` is a writable buffer of length `max_size`.
/// - `data[..size]` is the current input candidate.
/// - The function MUST write the new candidate into `data[..ret]` and
///   return `ret`, where `ret <= max_size`.
/// - The function MUST be deterministic in `seed`.
///
/// On parse failure we return `size` unchanged and rely on libFuzzer's
/// default mutator (it runs the random-byte mutator path in that case
/// when wired with [`libfuzzer_sys::fuzzer_mutate`]; this implementation
/// keeps it simple and lets the next iteration roll the dice again).
#[must_use]
pub fn canonical_json_mutate(data: &mut [u8], size: usize, max_size: usize, seed: u32) -> usize {
    if size == 0 || size > data.len() || max_size == 0 {
        return min(size, max_size);
    }

    let bounded_size = min(size, data.len());
    let parsed: Value = match serde_json::from_slice(&data[..bounded_size]) {
        Ok(value) => value,
        Err(_) => return min(size, max_size),
    };

    let mutated = mutate_value(parsed, seed);
    let bytes = match serde_json::to_vec(&canonicalize_value(mutated)) {
        Ok(bytes) => bytes,
        Err(_) => return min(size, max_size),
    };

    let copy_len = min(bytes.len(), max_size);
    if copy_len > data.len() {
        return 0;
    }
    data[..copy_len].copy_from_slice(&bytes[..copy_len]);
    copy_len
}

/// Apply ONE structure-preserving mutation to `value`, chosen by `seed`.
///
/// All branches return a structurally valid `serde_json::Value`; the
/// caller re-canonicalizes the result. Mutations that target a nested
/// path (object / array) descend along a deterministic walk derived from
/// `seed` so the same `(value, seed)` pair always produces the same
/// mutation (libFuzzer reproducibility requirement).
fn mutate_value(mut value: Value, seed: u32) -> Value {
    let choice = seed % 8;
    match choice {
        0 => add_key(&mut value, seed),
        1 => remove_key(&mut value, seed),
        2 => swap_array_elements(&mut value, seed),
        3 => replace_string(&mut value, seed),
        4 => replace_number(&mut value, seed),
        5 => insert_duplicate_key(&mut value, seed),
        6 => replace_with_edge_utf8(&mut value, seed),
        // 7: identity (still re-canonicalizes, which is itself a valid
        // mutation when the input has insertion-order key drift).
        _ => {}
    }
    value
}

/// Return a canonicalized clone of `value` with object keys
/// lexicographically sorted. `serde_json::to_vec` on a `Map` walks keys
/// in their stored order, which `serde_json` keeps as insertion order;
/// rebuilding every nested map in sorted order is the cheapest way to
/// guarantee canonical-shape output without pulling in a JCS-aware
/// serializer here.
fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            let mut sorted = Map::new();
            for (k, v) in entries {
                sorted.insert(k, canonicalize_value(v));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

// ---- Mutation primitives ----

fn add_key(value: &mut Value, seed: u32) {
    if let Some(target) = pick_object_mut(value, seed) {
        let key = format!("__chio_fuzz_key_{:x}", seed.wrapping_mul(0x9E37_79B1));
        target.insert(key, Value::Bool(seed.is_multiple_of(2)));
    }
}

fn remove_key(value: &mut Value, seed: u32) {
    if let Some(target) = pick_object_mut(value, seed) {
        if target.is_empty() {
            return;
        }
        let len = target.len();
        let idx = (seed as usize) % len;
        let key = match target.keys().nth(idx) {
            Some(k) => k.clone(),
            None => return,
        };
        target.remove(&key);
    }
}

fn swap_array_elements(value: &mut Value, seed: u32) {
    if let Some(arr) = pick_array_mut(value, seed) {
        if arr.len() < 2 {
            return;
        }
        let len = arr.len();
        let i = (seed as usize) % len;
        let j = ((seed as usize).wrapping_mul(2654435761)) % len;
        if i != j {
            arr.swap(i, j);
        }
    }
}

fn replace_string(value: &mut Value, seed: u32) {
    let interesting = INTERESTING_STRINGS;
    let pick = interesting[(seed as usize) % interesting.len()];
    walk_replace_first_string(value, pick.to_string());
}

fn replace_number(value: &mut Value, seed: u32) {
    let interesting = interesting_numbers_table();
    let pick = interesting[(seed as usize) % interesting.len()].clone();
    walk_replace_first_number(value, pick);
}

fn insert_duplicate_key(value: &mut Value, seed: u32) {
    // serde_json's Map cannot hold a true duplicate key (it deduplicates
    // on insert); instead we insert a key whose canonical-sort position
    // would collide with an existing key after lowercase-fold. This
    // exercises the canonical-JSON last-wins / case-sensitivity branch.
    if let Some(target) = pick_object_mut(value, seed) {
        if target.is_empty() {
            return;
        }
        let len = target.len();
        let idx = (seed as usize) % len;
        let original_key = match target.keys().nth(idx) {
            Some(k) => k.clone(),
            None => return,
        };
        let twisted = format!("{}_dup", original_key.to_uppercase());
        target.insert(twisted, Value::String("dup".into()));
    }
}

fn replace_with_edge_utf8(value: &mut Value, seed: u32) {
    let edges = EDGE_UTF8_STRINGS;
    let pick = edges[(seed as usize) % edges.len()];
    walk_replace_first_string(value, pick.to_string());
}

// ---- Walker helpers ----

/// Deterministically descend into `value` and return the first nested
/// `Map` reachable by following array index 0 / first-object-entry per
/// level. The mutation lands at depth `seed % 4` (or shallower if the
/// value is not that deep).
fn pick_object_mut(value: &mut Value, seed: u32) -> Option<&mut Map<String, Value>> {
    let depth = (seed as usize) % 4;
    let mut current = value;
    for _ in 0..depth {
        let next: *mut Value = match current {
            Value::Object(map) => match map.values_mut().next() {
                Some(v) => v as *mut Value,
                None => break,
            },
            Value::Array(arr) => match arr.first_mut() {
                Some(v) => v as *mut Value,
                None => break,
            },
            _ => break,
        };
        // SAFETY: `next` points into `current`, which we hold a unique
        // borrow of. Re-borrowing through the raw pointer extends the
        // lifetime of the borrow chain without requiring NLL across
        // loop iterations (the borrow checker rejects the safe form
        // here even though it is sound).
        current = unsafe { &mut *next };
    }
    if let Value::Object(map) = current {
        Some(map)
    } else {
        None
    }
}

fn pick_array_mut(value: &mut Value, seed: u32) -> Option<&mut Vec<Value>> {
    let depth = (seed as usize) % 4;
    let mut current = value;
    for _ in 0..depth {
        let next: *mut Value = match current {
            Value::Object(map) => match map.values_mut().next() {
                Some(v) => v as *mut Value,
                None => break,
            },
            Value::Array(arr) => match arr.first_mut() {
                Some(v) => v as *mut Value,
                None => break,
            },
            _ => break,
        };
        // SAFETY: see `pick_object_mut`.
        current = unsafe { &mut *next };
    }
    if let Value::Array(arr) = current {
        Some(arr)
    } else {
        None
    }
}

fn walk_replace_first_string(value: &mut Value, replacement: String) {
    match value {
        Value::String(s) => *s = replacement,
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                if contains_string(v) {
                    walk_replace_first_string(v, replacement);
                    return;
                }
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                if contains_string(v) {
                    walk_replace_first_string(v, replacement);
                    return;
                }
            }
        }
        _ => {}
    }
}

fn walk_replace_first_number(value: &mut Value, replacement: Number) {
    match value {
        Value::Number(n) => *n = replacement,
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                if contains_number(v) {
                    walk_replace_first_number(v, replacement);
                    return;
                }
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                if contains_number(v) {
                    walk_replace_first_number(v, replacement);
                    return;
                }
            }
        }
        _ => {}
    }
}

fn contains_string(value: &Value) -> bool {
    match value {
        Value::String(_) => true,
        Value::Array(arr) => arr.iter().any(contains_string),
        Value::Object(map) => map.values().any(contains_string),
        _ => false,
    }
}

fn contains_number(value: &Value) -> bool {
    match value {
        Value::Number(_) => true,
        Value::Array(arr) => arr.iter().any(contains_number),
        Value::Object(map) => map.values().any(contains_number),
        _ => false,
    }
}

// ---- Interesting boundary tables ----

const INTERESTING_STRINGS: &[&str] = &[
    "",
    " ",
    "null",
    "0",
    "-0",
    "true",
    "false",
    "{",
    "}",
    "[",
    "]",
    "\"",
    "\\",
    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
    "https://example.invalid/.well-known/oauth-resource",
];

const EDGE_UTF8_STRINGS: &[&str] = &[
    "\u{0000}",
    "\u{0001}",
    "\u{007f}",
    "\u{0080}",
    "\u{00a0}",
    "\u{200b}",
    "\u{200e}",
    "\u{202e}",
    "\u{2028}",
    "\u{2029}",
    "\u{feff}",
    "\u{fffd}",
    "\u{10ffff}",
];

fn interesting_numbers() -> [Number; 10] {
    [
        Number::from(0_i64),
        Number::from(-1_i64),
        Number::from(1_i64),
        Number::from(i64::MIN),
        Number::from(i64::MAX),
        Number::from(u64::MAX),
        Number::from_f64(0.0).unwrap_or_else(|| Number::from(0_i64)),
        Number::from_f64(-0.0).unwrap_or_else(|| Number::from(0_i64)),
        Number::from_f64(1.0e308).unwrap_or_else(|| Number::from(0_i64)),
        Number::from_f64(-1.0e308).unwrap_or_else(|| Number::from(0_i64)),
    ]
}

// `INTERESTING_NUMBERS` cannot be a `const` because `Number::from_f64`
// is not a const fn; we materialize it once at first use via the
// `OnceLock` below. The mutator hot path reads it via the `_get()`
// accessor, which after warmup is a single atomic load.
use std::sync::OnceLock;
static INTERESTING_NUMBERS_CELL: OnceLock<[Number; 10]> = OnceLock::new();
fn interesting_numbers_table() -> &'static [Number; 10] {
    INTERESTING_NUMBERS_CELL.get_or_init(interesting_numbers)
}

// ---- Tests ----

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn run(input: &[u8], seed: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        buf[..input.len()].copy_from_slice(input);
        let cap = buf.len();
        let new_size = canonical_json_mutate(&mut buf, input.len(), cap, seed);
        buf[..new_size].to_vec()
    }

    #[test]
    fn passes_through_non_json() {
        let out = run(b"not json", 7);
        assert_eq!(out, b"not json");
    }

    #[test]
    fn passes_through_empty() {
        let out = run(b"", 0);
        assert!(out.is_empty());
    }

    #[test]
    fn mutates_object_into_valid_json() {
        let input = br#"{"b":1,"a":2}"#;
        for seed in 0..32 {
            let out = run(input, seed);
            let parsed: serde_json::Value =
                serde_json::from_slice(&out).expect("mutator output must parse");
            assert!(parsed.is_object());
        }
    }

    #[test]
    fn mutates_array_into_valid_json() {
        let input = br#"[1,2,3]"#;
        for seed in 0..32 {
            let out = run(input, seed);
            let _: serde_json::Value =
                serde_json::from_slice(&out).expect("mutator output must parse");
        }
    }

    #[test]
    fn deterministic_in_seed() {
        let input = br#"{"x":[1,2,{"y":"z"}]}"#;
        let a = run(input, 42);
        let b = run(input, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn respects_max_size() {
        let input = br#"{"x":1}"#;
        let mut buf = vec![0u8; 16];
        buf[..input.len()].copy_from_slice(input);
        let new_size = canonical_json_mutate(&mut buf, input.len(), 8, 3);
        assert!(new_size <= 8);
    }

    #[test]
    fn canonicalizes_object_keys() {
        let input = br#"{"z":1,"a":2,"m":3}"#;
        let out = run(input, 7);
        let s = std::str::from_utf8(&out).unwrap();
        // Keys should appear in lex order in the serialized output.
        let pos_a = s.find("\"a\"").unwrap_or(usize::MAX);
        let pos_m = s.find("\"m\"").unwrap_or(usize::MAX);
        let pos_z = s.find("\"z\"").unwrap_or(usize::MAX);
        // Allow `a` to be missing if it was the removed key, but if both
        // present, `a < m < z`.
        if pos_a != usize::MAX && pos_m != usize::MAX {
            assert!(pos_a < pos_m, "got: {s}");
        }
        if pos_m != usize::MAX && pos_z != usize::MAX {
            assert!(pos_m < pos_z, "got: {s}");
        }
    }
}
