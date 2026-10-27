//! Trust-boundary fuzz target for commerce authority receipts: arbitrary
//! receipt bytes routed through order replay and settlement verification must
//! never panic, and an action hash mismatch and an action hash encoding fault
//! must each surface as their own error class.

#![no_main]

use chio_commerce_order::fuzz::commerce_receipt_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    commerce_receipt_verify(data);
});
