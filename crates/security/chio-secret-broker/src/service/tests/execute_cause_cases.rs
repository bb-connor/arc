//! Public-service native cause and prepared-material custody after a fresh refusal.
use super::*;

#[test]
fn f011_public_execute_retains_unavailable_cause_and_drops_prepared_material() {
    for delete in [false, true] {
        let fixture = fixture(2, false, false);
        let (request, trusted) = execution(&fixture, 196, 1);
        let ids = register_prepared_execution(&fixture, &request, &trusted, 20);
        assert_eq!(
            fixture
                .service
                .retained_prepared_dispatch_keys()
                .test_expect("prepared secret custody")
                .len(),
            1
        );
        let credential = &request.capability.body.credential;
        if delete {
            fixture
                .backend
                .delete(credential)
                .test_expect("delete after Prepare");
        } else {
            fixture
                .backend
                .disable(credential)
                .test_expect("disable after Prepare");
        }
        let error = fixture
            .service
            .execute(&request, &trusted, 21)
            .test_expect_err("public execute refuses unavailable prepared credential");
        assert!(matches!(&error, BrokerError::CredentialUnavailable(_)));
        assert_eq!(error.diagnostic_code(), "authorization_denied");
        let assert_native_source = |cause: &BrokerError| {
            let store = std::error::Error::source(cause)
                .and_then(|source| source.downcast_ref::<crate::CredentialStoreError>())
                .test_expect("opaque native credential source");
            assert!(matches!(
                std::error::Error::source(store)
                    .and_then(|source| source.downcast_ref::<chio_store_sqlite::BlobStoreError>()),
                Some(chio_store_sqlite::BlobStoreError::NotFound)
            ));
        };
        assert_native_source(&error);
        let redacted = error.redacted();
        assert_native_source(&redacted);
        assert!(fixture
            .service
            .retained_prepared_dispatch_keys()
            .test_expect("terminal secret custody")
            .is_empty());
        assert_eq!(fixture.authority.captured_count(), 1);
        let terminal = fixture
            .attempts
            .load_attempt(&ids.attempt_id)
            .test_expect("terminal attempt")
            .test_expect("present");
        assert_eq!(terminal.state, AttemptState::Failed);
        assert!(terminal.dispatch_claim_id.is_none());
        assert!(fixture
            .observed_authorizations
            .lock()
            .test_expect("transport observations")
            .is_empty());
        let failure = fixture
            .service
            .replay_failure(&request, 21)
            .test_expect("retained signed terminal")
            .test_expect("present");
        assert_eq!(failure.diagnostic_code, "chio.broker.authorization_denied");
        assert_eq!(failure.receipt.body.stage, BrokerFailureStage::Capture);
        assert_eq!(failure.receipt.body.outcome, BrokerFailureOutcome::Denied);
        assert_eq!(
            failure.receipt.body.dispatch_knowledge,
            BrokerDispatchKnowledge::NotCommitted
        );
        assert_eq!(
            fixture
                .service
                .execute_evidenced(&request, &trusted, 21)
                .test_expect("historical exact signed replay"),
            BrokerExecuteOutcome::Failure(Box::new(failure))
        );
        assert_eq!(fixture.authority.captured_count(), 1);
    }
}
