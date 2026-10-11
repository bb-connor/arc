//! The actual issuer transaction must not bypass native preflight custody.
use super::*;

#[test]
fn native_issuance_requires_preflight_taint_before_budget_preflight() -> TestResult {
    for joined in [false, true] {
        let fixture = fixture();
        let key = Keypair::generate();
        let (operation, original) =
            super::super::security_participant_state::prepare_issuance_fixture(
                &fixture, &key, joined,
            )?;
        let operation = preflight::own_and_clean(&fixture, &operation, &key)?;
        let issuance = AdmissionExecutionNonceReservationV1::mint_for_operation(
            &operation,
            &original,
            &key,
            &ExecutionNonceConfig::default(),
            now_ms(),
        )?;
        let command = nonce_command(
            &fixture.store,
            &fixture.fence,
            &operation,
            &key,
            vec![AdmissionAttachment::ExecutionNonceIssuanceDigest(
                AdmissionDigest::try_new("issuance", sha256_hex(issuance.canonical_bytes()))?,
            )],
            AdmissionOperationState::Prepared,
        )?;
        let result =
            fixture
                .store
                .issue_execution_nonce_and_commit_admission(&command, &issuance, now_ms());
        assert_eq!(
            result.is_ok(),
            joined,
            "native preflight present: {joined}; result: {result:?}"
        );
        if let Err(error) = result {
            assert!(
                error
                    .to_string()
                    .contains("native nonce issuance requires original preflight taint"),
                "denial must come from the physical native preflight prerequisite: {error}"
            );
        }
        let stored = fixture.store.load_execution_nonce_issuance(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?;
        assert_eq!(stored.is_some(), joined);
        if let Some(stored) = stored {
            assert_eq!(stored.canonical_bytes(), issuance.canonical_bytes());
        }
    }
    Ok(())
}
