//! Unproved SHA-256 noncollision research obligation.
//!
//! Preserved with its original symbolic domain and assertions. Strict runs
//! timed out; no successful proof is claimed. This opt-in module is excluded
//! from the production gate. See formal/rust-verification/crypto-proof-scope.toml.

use crate::card::weights_hash_of;

#[kani::proof]
#[kani::unwind(66)]
pub fn public_weights_hash_of_determinism_and_tampering() {
    // A 4-byte message plus the 0x80 delimiter and the 8-byte length
    // fits one 64-byte SHA-256 block. The tampered position ranges over
    // every byte of the message.
    let bytes: [u8; 4] = kani::any();
    let flip_index: u8 = kani::any();
    kani::assume((flip_index as usize) < bytes.len());

    // (1) Determinism. Two calls with identical inputs MUST agree
    // byte-for-byte. The kernel binding refusal path relies on this
    // when it recomputes `weights_hash_of(loaded_bytes)` and
    // byte-compares against the card's `weights_hash`.
    let first = weights_hash_of(&bytes);
    let second = weights_hash_of(&bytes);
    assert_eq!(first, second);

    // (2) Output shape. The output is always a 64-character lowercase
    // hex string. The card's `validate()` predicate refuses any
    // candidate that does not match this shape, so a `weights_hash_of`
    // implementation that drifted to uppercase or shortened the
    // digest would silently break every binding.
    assert_eq!(first.len(), 64);
    for byte in first.as_bytes() {
        assert!(matches!(*byte, b'0'..=b'9' | b'a'..=b'f'));
    }

    // (3) Tampering. Flipping a single bit in the input MUST change
    // the digest. The kernel binding refusal path therefore cannot
    // be tricked by a runtime that loads tampered weights and hopes
    // the digest collides.
    let mut tampered = bytes;
    tampered[flip_index as usize] ^= 0x01;
    let tampered_digest = weights_hash_of(&tampered);
    assert_ne!(first, tampered_digest);
    kani::cover!(true, "public_weights_hash_of_determinism_and_tampering");
}
