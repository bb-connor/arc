use chio_credit::obligation::{SignedCreditFacilityBindV1, SignedObligationStatusProofV1};
use chio_credit::SignedIouEnvelopeV2;
use std::error::Error;

fn require_error<T, E: Error + 'static>(result: Result<T, E>) -> E {
    match result {
        Err(error) => error,
        Ok(_) => panic!("malformed original input must reject"),
    }
}

fn assert_native_cause(error: &(dyn Error + 'static)) {
    assert!(
        error.source().is_some(),
        "native parser cause was discarded: {error}"
    );
    assert!(!error.to_string().contains("private-marker"));
}

#[test]
fn original_credit_readers_preserve_native_causes() {
    let bytes = br#"{"private-marker":1,"private-marker":2}"#;
    assert_native_cause(&require_error(SignedIouEnvelopeV2::from_canonical_bytes(
        bytes,
    )));
    assert_native_cause(&require_error(
        SignedCreditFacilityBindV1::from_canonical_bytes(bytes),
    ));
    assert_native_cause(&require_error(
        SignedObligationStatusProofV1::from_canonical_bytes(bytes),
    ));
}

#[test]
fn original_credit_input_is_bounded_before_typed_projection() {
    let bytes = vec![b' '; 4 * 1024 * 1024 + 1];
    let error = require_error(SignedIouEnvelopeV2::from_canonical_bytes(&bytes));
    let mut source: &(dyn Error + 'static) = &error;
    loop {
        if let Some(input) = source.downcast_ref::<chio_core_types::canonical::UntrustedJsonError>()
        {
            assert_eq!(input.code(), "urn:chio:error:attest:signed-json-too-large");
            break;
        }
        source = source
            .source()
            .unwrap_or_else(|| panic!("bounded input cause was discarded"));
    }
}
