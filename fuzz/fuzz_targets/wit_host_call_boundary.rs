// owned-by: M02 (fuzz lane); target authored under M02.P1.T4.b.
//
//! libFuzzer harness for the WIT host-call boundary serde surface in
//! `chio_wasm_guards`.
//!
//! The trust boundary is the moment at which the host accepts bytes that
//! crossed the WIT marshaller from a guest WASM module and invokes serde
//! to materialize them into typed Rust structs. The contract is that
//! arbitrary guest-controlled bytes either deserialize cleanly or surface
//! as `Err(serde_json::Error)` -- a panic / abort in the serde chain would
//! let a malicious guest crash the host process.
//!
//! Two ABI types are exercised on every iteration (see
//! `chio_wasm_guards::fuzz::fuzz_wit_host_call_boundary` for the
//! per-surface rationale):
//!
//! 1. `GuardRequest` -- host-to-guest WIT-marshalled request envelope.
//! 2. `GuestDenyResponse` -- the canonical guest-to-host
//!    `chio_deny_reason` deser site (runtime.rs `read_structured_deny_reason`).
//!
//! `GuardVerdict` is intentionally not exercised because it crosses the WIT
//! boundary as an `i32` return code, not as a serialized struct, and adding
//! `Deserialize` to it would widen the production ABI for no defensive gain.
//!
//! Reference: `.planning/trajectory/02-fuzzing-post-pr13.md` Phase 1
//! (trust-boundary fuzz target #9).

#![no_main]

use chio_wasm_guards::fuzz::fuzz_wit_host_call_boundary;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_wit_host_call_boundary(data);
});
