#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::verify_wrapped;
use chio_core_types::Error;
use chio_runtime_core::{
    SignedRuntimeVerifierTrustBundle, CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
};

const FIXTURE: &str = include_str!(
    "../../../../examples/chio-3vendor/fixtures/runtime-spine/runtime-trust-schema-only.json"
);

#[test]
fn committed_placeholder_verifier_trust_bundle_is_refused() {
    let bundle: SignedRuntimeVerifierTrustBundle = serde_json::from_str(FIXTURE).unwrap();
    assert!(matches!(
        verify_wrapped(
            &bundle.signer_key,
            CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
            &bundle.body,
            &bundle.signature,
        ),
        Err(Error::SignatureRejected)
    ));
    assert!(!bundle.verify_signature(&bundle.signer_key).unwrap());
}
