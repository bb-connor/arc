// owned-by: M02 (fuzz lane); target authored under M09.P3.T5.
//
//! libFuzzer harness for `chio_attest_verify::SigstoreVerifier::verify_bundle`.
//!
//! The verifier is fail-closed by construction (see
//! `crates/chio-attest-verify/src/lib.rs` trust-boundary docs): every
//! arbitrary byte string must surface as an `Err(AttestError::*)` rather
//! than a panic, abort, or `Ok(_)`. This target exists to catch parse-path
//! regressions (unwrap/expect/UB) in the bundle decoder pulled in by
//! `sigstore-rs`, including its transitive `serde_json`, `x509-cert`,
//! `pem`, and `webpki` chains.
//!
//! Input layout: the first half of `data` is treated as the artifact bytes
//! (which the verifier hashes via SHA-256 to produce the subject digest);
//! the second half is treated as the bundle JSON. Splitting on a
//! deterministic midpoint keeps the corpus stable across libFuzzer runs
//! while still exercising both arguments. The seed `corpus/attest_verify/
//! empty.bin` is a 0-byte file that mutates outward into both fields.
//!
//! `id-token: write` is not relevant here; this is a local fuzz target,
//! not a release workflow.

#![no_main]

use std::sync::OnceLock;

use chio_attest_verify::{AttestVerifier, ExpectedIdentity, SigstoreVerifier};
use libfuzzer_sys::fuzz_target;

/// Build the verifier once per process. The embedded TUF trust root is
/// validated at compile time by `chio-attest-verify`'s `build.rs`, so a
/// successful link guarantees the constructor's only runtime failure mode
/// is corruption of the bundled bytes; if that happens at startup we have
/// no fuzz signal to give and falling through to `return` keeps libFuzzer
/// happy without aborting.
static VERIFIER: OnceLock<Option<SigstoreVerifier>> = OnceLock::new();

fn verifier() -> Option<&'static SigstoreVerifier> {
    VERIFIER
        .get_or_init(|| SigstoreVerifier::with_embedded_root().ok())
        .as_ref()
}

/// Identity expectation kept constant across the campaign. The regex and
/// issuer match the GitHub release-binaries workflow shape that M09 P3
/// signs against; varying these would mask parse-path failures behind
/// regex/issuer-mismatch errors that the verifier surfaces before it
/// touches the bundle bytes.
fn expected_identity() -> ExpectedIdentity {
    ExpectedIdentity {
        certificate_identity_regexp:
            r"https://github\.com/backbay/chio/\.github/workflows/release-binaries\.yml@refs/tags/v.*"
                .to_owned(),
        certificate_oidc_issuer: "https://token.actions.githubusercontent.com".to_owned(),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(verifier) = verifier() else {
        return;
    };

    let split = data.len() / 2;
    let (artifact, bundle_json) = data.split_at(split);
    let expected = expected_identity();

    // The trust-boundary contract guarantees this is fail-closed; the only
    // outcomes we care about are `Err(_)` (good) or a panic/abort (which
    // libFuzzer reports as a crash). We deliberately ignore the `Ok(_)`
    // branch because no arbitrary input can satisfy the keyless flow.
    let _ = verifier.verify_bundle(artifact, bundle_json, &expected);
});
