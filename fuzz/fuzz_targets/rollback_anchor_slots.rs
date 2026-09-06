//! Trust-boundary fuzz target for the SQLite serving owner's rollback anchor
//! slot decoder: arbitrary two-slot images must never panic, and every
//! accepted slot must validate and re-encode to the bytes it was read from.

#![no_main]

use chio_store_sqlite::fuzz::rollback_anchor_slots;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rollback_anchor_slots(data);
});
