use chio_fiscal::{FiscalRuntimeAdapterRegistry, VerifiedFiscalCharter};
use std::error::Error;

#[test]
fn original_fiscal_readers_preserve_native_causes() {
    let bytes = br#"{"private-marker":1,"private-marker":2}"#;
    let errors: Vec<Box<dyn Error>> = vec![
        match VerifiedFiscalCharter::from_canonical_bytes(bytes) {
            Err(error) => Box::new(error),
            Ok(_) => panic!("ambiguous charter accepted"),
        },
        match FiscalRuntimeAdapterRegistry::from_canonical_bytes(bytes) {
            Err(error) => Box::new(error),
            Ok(_) => panic!("ambiguous registry accepted"),
        },
    ];
    for error in errors {
        assert!(
            error.source().is_some(),
            "native parser cause was discarded: {error}"
        );
        assert!(!format!("{error:?} {error}").contains("private-marker"));
    }
}
