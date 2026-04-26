// owned-by: M02 (fuzz lane); target authored under M02.P1.T1.c.
//
//! libFuzzer harness for the `chio-did` resolve trust boundary.
//!
//! The DID surface is fail-closed by construction (see
//! `crates/chio-did/src/lib.rs`): every arbitrary byte string must surface
//! as an `Err(DidError::*)`, an `Err(serde_json::Error)`, or be silently
//! ignored, rather than a panic, abort, or `Ok(_)` that would let
//! malformed identifiers escape into the rest of the system. This target
//! exists to catch parse-path regressions (unwrap/expect/UB) in:
//!
//! - The `did:chio:<hex>` URI parser (hex-decoding loop, length check).
//! - The `DidDocument` JSON deserializer (`serde_json` decode plus the
//!   schema-shape derive on `DidVerificationMethod` / `DidService`).
//! - The multibase encoder used by the resolver convenience.
//! - The `url::Url`-backed service-endpoint validator.
//!
//! Input layout: bytes are forwarded to the credentials-side fuzz entry
//! point `chio_did::fuzz::fuzz_did_resolve`, which exercises all four
//! surfaces concurrently. The seed corpus under `corpus/did_resolve/`
//! mixes empty input, random bytes, real-looking `did:chio` /
//! `did:web` / `did:key` URIs, and a minimal `DidDocument` JSON blob so
//! libFuzzer has a head start on every parse path.
//!
//! `id-token: write` is not relevant here; this is a local fuzz target,
//! not a release workflow.

#![no_main]

use chio_did::fuzz::fuzz_did_resolve;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_did_resolve(data);
});
