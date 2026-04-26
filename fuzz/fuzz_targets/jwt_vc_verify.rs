// owned-by: M02 (fuzz lane); target authored under M02.P1.T1.a.
//
//! libFuzzer harness for `chio_credentials::verify_chio_passport_jwt_vc_json`.
//!
//! The verifier is fail-closed by construction (see
//! `crates/chio-credentials/src/portable_jwt_vc.rs`): every arbitrary byte
//! string must surface as an `Err(CredentialError::*)` rather than a panic,
//! abort, or `Ok(_)`. This target exists to catch parse-path regressions
//! (unwrap/expect/UB) in the compact-JWT decoder path, including base64url
//! decoding of the three segments, `serde_json` parsing of header and
//! payload, and the schema-shape checks that follow signature verification.
//!
//! Input layout: bytes are interpreted as a UTF-8 compact-JWT string and
//! forwarded to the credentials-side fuzz entry point
//! `chio_credentials::fuzz::fuzz_jwt_vc_verify`. The seed corpus under
//! `corpus/jwt_vc_verify/` mixes empty input, random bytes, JWT-prefix
//! garbage, and a near-valid JWT with a bogus signature so libFuzzer has a
//! head start on both the decode and the post-decode validation paths.
//!
//! `id-token: write` is not relevant here; this is a local fuzz target,
//! not a release workflow.

#![no_main]

use chio_credentials::fuzz::fuzz_jwt_vc_verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_jwt_vc_verify(data);
});
