use super::*;

#[test]
fn original_bundle_artifact_count_is_bounded_before_verification() {
    let mut bundle = trust_market_bundle(TrustMarketCase::Valid);
    verify_trust_market_context(&bundle).test_expect("positive control verifies");
    for index in 0..4096 {
        bundle
            .artifacts
            .insert(format!("unused-{index}"), Vec::new());
    }
    let error =
        verify_trust_market_context(&bundle).test_expect_err("total input count must be bounded");
    assert!(matches!(
        error,
        chio_transaction_passport::TransactionPassportError::EvidenceLimit
    ));
}

#[test]
fn original_auxiliary_risk_receipt_preserves_parser_cause() {
    let mut bundle = trust_market_bundle(TrustMarketCase::RiskReserveLedgerReceiptUntrustedSigner);
    let path = "receipt-market-hold.json";
    update_trust_market_artifact_bytes(
        &mut bundle,
        path,
        signed_receipt_artifact_bytes("receipt-market-hold", true),
    );
    verify_trust_market_context(&bundle).test_expect("positive auxiliary receipt control");
    let mut original =
        String::from_utf8(bundle.artifacts[path].clone()).test_expect("receipt JSON");
    let end = original.rfind('}').test_expect("receipt is object");
    original.insert_str(end, ",\"private-marker\":1,\"private-marker\":2");
    update_trust_market_artifact_bytes(&mut bundle, path, original.into_bytes());
    let error = verify_trust_market_context(&bundle)
        .test_expect_err("ambiguous auxiliary evidence rejects");
    assert!(matches!(
        &error,
        chio_transaction_passport::TransactionPassportError::Input(_)
    ));
    assert!(std::error::Error::source(&error).is_some());
    assert!(!format!("{error:?} {error}").contains("private-marker"));
}
