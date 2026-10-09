//! Unproved SHA-256 noncollision research obligation.
//!
//! Preserved with its original symbolic domain and assertions. Strict runs
//! timed out; no successful proof is claimed. This opt-in module is excluded
//! from the production gate. See formal/rust-verification/crypto-proof-scope.toml.

use super::kani_public_harnesses::public_key;
use crate::quote::{expect_report_data, QuoteVerificationContext};

#[kani::proof]
#[kani::unwind(136)]
pub fn public_expect_report_data_determinism_under_input_change() {
    // Preserve both symbolic axes: kernel-key seed and receipt-root index.
    let kernel_seed = kani::any::<u8>();
    let mut receipt_root = [0u8; 32];
    let flip_index = kani::any::<u8>();
    // Restrict the flip index into the slot. `assume` is bounded but
    // non-vacuous (the slot has 32 distinct positions) and lets Kani
    // enumerate every byte position in the receipt root.
    kani::assume((flip_index as usize) < receipt_root.len());
    receipt_root[flip_index as usize] = 1;

    let kernel_pk = public_key(kernel_seed);

    let first = expect_report_data(&kernel_pk, &receipt_root);
    let second = expect_report_data(&kernel_pk, &receipt_root);
    assert_eq!(first, second);

    // (2) Right-pad invariant. Bytes 32..64 of the slot MUST be zero
    // by construction (the function right-pads with `0x00` to fill
    // the 64-byte slot). A backend that committed unrelated bytes in
    // the upper half of the slot would defeat the binding; we pin
    // the layout the runtime relies on.
    for byte in &first[32..] {
        assert_eq!(*byte, 0);
    }

    // (3) Tampering. Flipping a single byte in the receipt root MUST
    // change the digest half (bytes 0..32) of the slot. We compare
    // against a tampered receipt-root and assert byte-array
    // inequality on the digest range.
    let mut tampered_root = receipt_root;
    tampered_root[flip_index as usize] ^= 0x01;
    let tampered = expect_report_data(&kernel_pk, &tampered_root);
    assert_ne!(first[..32], tampered[..32]);

    // (4) `QuoteVerificationContext::expected_report_data` is a real
    // `pub fn` thin wrapper around `expect_report_data`. Pin the
    // invariant that the wrapper agrees with the free function so a
    // future regression that diverged the two paths is caught here.
    let context = QuoteVerificationContext::new(&kernel_pk, &receipt_root);
    let via_context = context.expected_report_data();
    assert_eq!(via_context, first);
    core::mem::forget(kernel_pk);
    kani::cover!(
        true,
        "public_expect_report_data_determinism_under_input_change"
    );
}
