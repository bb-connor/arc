use super::*;

#[test]
fn original_bundle_limit_precedes_consuming_replay_admission() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    let store = Arc::new(CapturingReplayStore::default());
    let trust = agent_web_fixture_trust().with_standard_webhooks_replay_store(store.clone());
    for index in 0..4096 {
        bundle
            .artifacts
            .insert(format!("unused-{index}"), Vec::new());
    }
    let error = verify_agent_web_interop_with_trust_and_consume_replays(&bundle, &trust)
        .test_expect_err("collection must be bounded before replay admission");
    assert!(matches!(
        error,
        chio_transaction_passport::TransactionPassportError::EvidenceLimit
    ));
    assert_eq!(
        store.entries.lock().test_expect("capture store lock").len(),
        0
    );
}

#[test]
fn agent_web_interop_rejects_unsigned_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptUnsigned);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external projection must bind a signed Chio receipt");

    assert!(matches!(
        &error,
        chio_transaction_passport::TransactionPassportError::Input(_)
    ));
    assert!(std::error::Error::source(&error).is_some());
}
