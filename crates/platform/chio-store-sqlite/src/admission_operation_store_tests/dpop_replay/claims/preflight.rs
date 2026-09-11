use super::*;
use chio_kernel::admission_operation::{
    AdmissionNoncePreflightHoldDisposition, AdmissionNoncePreflightIdentityV1,
};
use chio_kernel::budget_store::BudgetReverseHoldRequest;
use chio_kernel::BudgetStore;

#[test]
fn real_nonce_preflight_requires_fresh_claim_but_recovers_and_cleans_expired_history(
) -> AnchoredTestResult {
    for already_authorized in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let domain = activate(&fixture, &source)?;
        let (operation, lease, credential) = setup(
            &fixture,
            &domain,
            "dpop-preflight",
            "nonce",
            DpopReplayClaimPhase::NoncePreflight,
        )?;
        let expires = credential.valid_through_unix_secs()? + 1;
        let intent = candidate(
            &operation,
            "preflight",
            credential,
            DpopReplayClaimPhase::NoncePreflight,
        )?;
        let (mut operation, reference) =
            fixture
                .store
                .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
        let identity = AdmissionNoncePreflightIdentityV1::for_operation(&operation, 0)?;
        let mut request = super::budget::authorization(&fixture, &operation)?;
        request
            .admission_binding
            .as_mut()
            .ok_or("binding absent")?
            .operation_id = identity.budget_operation_id().as_str().into();
        request.hold_id = Some(identity.hold_id().as_str().into());
        request.event_id = Some(identity.authorization_event_id().as_str().into());
        if already_authorized {
            let (decision, updated) = fixture.store.authorize_execution_nonce_preflight(
                &operation,
                &renew(&fixture, &operation, &lease, now_ms())?,
                request.clone(),
                now_ms(),
            )?;
            assert!(matches!(
                decision,
                BudgetAuthorizeHoldDecision::Authorized(_)
            ));
            operation = updated;
        }
        let lease = renew(&fixture, &operation, &lease, now_ms())?;
        let count = global_count(&fixture);
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
        let result = fixture.store.authorize_execution_nonce_preflight(
            &operation,
            &lease,
            request.clone(),
            expires * 1000,
        );
        if already_authorized {
            let (decision, restored) = result?;
            assert!(matches!(
                decision,
                BudgetAuthorizeHoldDecision::Authorized(_)
            ));
            assert_eq!(restored, operation);
        } else {
            let error = result.expect_err("expired proof cannot introduce preflight authority");
            assert!(error.to_string().contains("fresh"), "{error}");
        }
        assert_eq!(global_count(&fixture), count);
        assert_eq!(
            fixture.store.connection()?.query_row(
                "SELECT COUNT(*) FROM budget_authorization_holds",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            i64::from(already_authorized)
        );
        if already_authorized {
            fixture
                .authority
                .budget_store()
                .reverse_budget_hold(BudgetReverseHoldRequest {
                    capability_id: request.capability_id,
                    grant_index: request.grant_index,
                    reversed_exposure_units: 0,
                    hold_id: request.hold_id,
                    event_id: Some(format!("{}:reverse", identity.hold_id().as_str())),
                    expected_cumulative_approval_state: None,
                    authority: request.authority,
                })?;
            let recovery = fixture
                .store
                .load_execution_nonce_preflight(
                    operation.binding().operation_id(),
                    &fixture.fence,
                    expires * 1000,
                )?
                .ok_or("preflight recovery absent")?;
            assert_eq!(
                recovery.hold(),
                AdmissionNoncePreflightHoldDisposition::Reversed
            );
        }
        fixture
            .store
            .release_dpop_replay(&operation, &lease, &reference, expires * 1000)?;
        let (_, history) = fixture
            .store
            .load_dpop_replay_claim_history(
                operation.binding().operation_id(),
                &fixture.fence,
                expires * 1000,
            )?
            .ok_or("claim history absent")?;
        assert_eq!(
            history[0].disposition,
            DpopReplayClaimDisposition::ReleasedBeforeDispatch
        );
        verify_admission_operation_invariants(&*fixture.store.connection()?)?;
    }
    Ok(())
}

#[test]
fn generic_command_cannot_create_dpop_custody_from_an_attachment() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let domain = activate(&fixture, &source)?;
    let (operation, lease, _) = setup(
        &fixture,
        &domain,
        "forged-dpop",
        "nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let count = global_count(&fixture);
    let error = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease,
                vec![AdmissionAttachment::DpopReplayLedgerDigest(digest(
                    "fake-ledger",
                    'f',
                ))],
                operation.state(),
                None,
            ),
            now_ms(),
        )
        .expect_err("attachment is not physical custody");
    assert!(error.to_string().contains("atomic reservation"), "{error}");
    assert_eq!(global_count(&fixture), count);
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}
