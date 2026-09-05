//! Strict JSON parser and canonicalization, with raw and structured candidates.

#![no_main]

use chio_fuzz::canonical_json::canonical_json_mutate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Keep libFuzzer's raw byte mutations: converting every candidate to a
    // Value first would erase duplicate keys and original number spellings.
    chio_fuzz::canonical_input::check(data);
    if data.len() <= 4096 {
        let mut buffer = [0_u8; 4096];
        buffer[..data.len()].copy_from_slice(data);
        let seed = data.iter().take(4).fold(0_u32, |seed, byte| {
            seed.wrapping_mul(257).wrapping_add(u32::from(*byte))
        });
        let size = canonical_json_mutate(&mut buffer, data.len(), 4096, seed);
        chio_fuzz::canonical_input::check(&buffer[..size]);
    }
});
