#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    chio_quarantine::fuzz::response_lifecycle(data);
});
