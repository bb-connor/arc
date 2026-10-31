use super::*;
#[path = "lifecycle/dispatch_snapshot.rs"]
mod dispatch_snapshot;

fn capture_pending(
    fixture: &Fixture,
    mut operation: AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
) -> AnchoredTestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    // This state-machine fixture proves replay custody, not executable budget settlement.
    for (state, attachments) in [
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "hold",
                "approval-test-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, vec![]),
        (AdmissionOperationState::CapturePending, vec![]),
    ] {
        let current = renew(fixture, &operation, lease, now_ms())?;
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, current, attachments, state, None),
                now_ms(),
            )?
            .into_operation();
    }
    let lease = renew(fixture, &operation, lease, now_ms())?;
    Ok((operation, lease))
}

#[test]
fn expired_or_released_claim_cannot_cross_dispatch_commit() -> AnchoredTestResult {
    for released in [false, true] {
        let fixture = fixture();
        let binding = install(&fixture)?;
        let (operation, lease, mut credential) = setup(&fixture, "dispatch-guard")?;
        let expires = now_ms() / 1000 + 60;
        credential.expires_at_unix_secs = expires;
        let intent = candidate(&operation, &binding, "dispatch", credential)?;
        let (operation, reference) =
            fixture
                .store
                .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
        let lease = renew(&fixture, &operation, &lease, now_ms())?;
        let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
        if released {
            fixture
                .store
                .release_governed_approval(&operation, &lease, &reference, now_ms())?;
        }
        let _clock = chio_test_support::clock::scope_unix_secs(expires);
        let now = expires * 1000;
        let lease = renew(&fixture, &operation, &lease, now)?;
        let count = global_count(&fixture);
        assert!(fixture
            .store
            .compare_and_swap(
                &command(
                    &operation,
                    lease,
                    vec![],
                    AdmissionOperationState::DispatchCommitted,
                    None
                ),
                now
            )
            .is_err());
        assert_eq!(global_count(&fixture), count);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation)
        );
    }
    Ok(())
}

#[test]
fn committed_approval_survives_expiry_and_restart_without_release_authority() -> AnchoredTestResult
{
    let fixture = fixture();
    let binding = install(&fixture)?;
    let (operation, lease, mut credential) = setup(&fixture, "committed-approval")?;
    let expires = now_ms() / 1000 + 60;
    credential.expires_at_unix_secs = expires;
    let intent = candidate(&operation, &binding, "dispatch", credential)?;
    let (operation, reference) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
    let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
    let committed = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease,
                vec![],
                AdmissionOperationState::DispatchCommitted,
                None,
            ),
            now_ms(),
        )?
        .into_operation();
    let Closed {
        _temp,
        database,
        lock_root,
        fence,
        _clock,
    } = fixture.close();
    let _clock = chio_test_support::clock::scope_unix_secs(expires + 1);
    let now = (expires + 1) * 1000;
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert!(store
        .load_governed_approval_claim_history(committed.binding().operation_id(), &fence, now)
        .is_err());
    let fence = authority.mutation_fence();
    let (restored, history) = store
        .load_governed_approval_claim_history(committed.binding().operation_id(), &fence, now)?
        .ok_or("history missing")?;
    assert_eq!(restored, committed);
    assert_eq!(history[0].reference, reference);
    assert_eq!(
        history[0].disposition,
        GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
    );
    let lease = store.claim_recovery(
        committed.binding().operation_id(),
        committed.version(),
        &identifier("worker", "recovered"),
        now,
        now + 10000,
        &fence,
    )?;
    assert!(store
        .release_governed_approval(&committed, &lease, &reference, now)
        .is_err());
    let mut connection = store.connection()?;
    let tx = connection.transaction()?;
    crate::admission_operation_store::verify_approval_budget_selection_tx(
        &tx,
        &committed,
        0,
        GovernedApprovalClaimPhase::Dispatch,
    )?;
    Ok(())
}

#[test]
fn live_capacity_refuses_until_expiry_reclaims_it() -> AnchoredTestResult {
    let fixture = fixture();
    let binding = install_with_capacity(&fixture, 1)?;
    let (first, first_lease, mut first_credential) = setup(&fixture, "capacity-first")?;
    let expires = now_ms() / 1000 + 60;
    first_credential.expires_at_unix_secs = expires;
    let held = candidate(&first, &binding, "held", first_credential)?;
    fixture
        .store
        .claim_governed_approval(&first, &first_lease, &held, now_ms())?;
    let (operation, lease, credential) = setup(&fixture, "capacity-next")?;
    let intent = candidate(&operation, &binding, "claim", credential)?;
    let count = global_count(&fixture);
    let error = fixture
        .store
        .claim_governed_approval(&operation, &lease, &intent, now_ms())
        .expect_err("live capacity must deny");
    assert!(error.to_string().contains("live capacity"), "{error}");
    assert_eq!(global_count(&fixture), count);
    let _clock = chio_test_support::clock::scope_unix_secs(expires);
    let now = expires * 1000;
    let lease = renew(&fixture, &operation, &lease, now)?;
    fixture
        .store
        .claim_governed_approval(&operation, &lease, &intent, now)?;
    Ok(())
}
