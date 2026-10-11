#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    chio_control_plane::security::response_authority_protocol(data);
});
