//! Untrusted model responses can propose work but cannot execute tools here.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    chio_workbench::provider::fuzz_model_response(data);
});
