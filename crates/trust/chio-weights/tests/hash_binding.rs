//! Concrete tamper controls supplement ASSUME-SHA256; they do not prove it.

use chio_weights::weights_hash_of;

#[test]
fn four_byte_weight_digest_detects_each_bit_zero_flip_in_seeded_cases() {
    for seed in u8::MIN..=u8::MAX {
        let original = [seed, seed.wrapping_add(1), !seed, seed.rotate_left(1)];
        let expected = weights_hash_of(&original);
        for index in 0..original.len() {
            let mut tampered = original;
            tampered[index] ^= 1;
            assert_ne!(
                expected,
                weights_hash_of(&tampered),
                "seed={seed}, index={index}"
            );
        }
    }
}
