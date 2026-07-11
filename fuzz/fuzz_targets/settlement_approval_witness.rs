//! Trust-boundary fuzz target for the `chio-settle` approval witness:
//! settlement-binding parse, CAIP-2 chain-id parse, the
//! `verify_governed_approval` gate, and the EIP-3009 lane wrapper.

#![no_main]

use chio_settle::fuzz::fuzz_settlement_approval_witness;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_settlement_approval_witness(data);
});
