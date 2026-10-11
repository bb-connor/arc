//! Fuzz target for the conformance peers lockfile: arbitrary TOML images
//! must decode, validate and answer every query without panicking, since
//! the lockfile gates which release artifacts fetch-peers downloads.

#![no_main]

use chio_conformance::fuzz::peers_lock_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    peers_lock_decode(data);
});
