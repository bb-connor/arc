// owned-by: M02 (fuzz lane); target authored under M02.P2.T6.
//
//! libFuzzer harness for the `chio-core-types` `CapabilityToken` and
//! `ChioReceipt` canonical-JSON deserialization trust boundary.
//!
//! Both surfaces are fail-closed by construction: invalid bytes must
//! surface as `Err(serde_json::Error)`, and `verify_signature` must
//! surface forged or malformed signatures as `Ok(false)` or `Err(_)`,
//! never `Ok(true)`. This target exists to catch parse-path regressions
//! (unwrap/expect/UB) and signature-verify regressions in:
//!
//! - `serde_json::from_slice::<CapabilityToken>` and the downstream
//!   `CapabilityToken::verify_signature` chain (delegation_chain
//!   walker, attestation-trust policy, signing-algorithm dispatch).
//! - `serde_json::from_slice::<ChioReceipt>` and `ChioReceipt::verify_signature`.
//!
//! The structure-aware canonical-JSON mutator is wired in via
//! [`libfuzzer_sys::fuzz_mutator!`]: random byte mutations on these
//! shape-heavy types almost always fail at the parse stage, while
//! shape-valid mutations exercise the typed deserializer's branches
//! (delegation_chain length, optional algorithm, evidence array, etc).
//!
//! Source: `.planning/trajectory/02-fuzzing-post-pr13.md` Round-2 P2.T6.

#![no_main]

use chio_core_types::{CapabilityToken, ChioReceipt};
use chio_fuzz::canonical_json::canonical_json_mutate;
use libfuzzer_sys::{fuzz_mutator, fuzz_target};

fuzz_target!(|data: &[u8]| {
    // Try CapabilityToken first; on success, drive the verify path.
    if let Ok(token) = serde_json::from_slice::<CapabilityToken>(data) {
        // Signature verification is fail-closed: we accept Ok(false) /
        // Err(_) as expected outcomes. The point is that the call must
        // not panic on any structurally valid CapabilityToken.
        let _ = token.verify_signature();
    }

    // Try ChioReceipt independently. Same byte stream, different typed
    // deserializer, different fail-closed surface.
    if let Ok(receipt) = serde_json::from_slice::<ChioReceipt>(data) {
        let _ = receipt.verify_signature();
    }
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    canonical_json_mutate(data, size, max_size, seed)
});
