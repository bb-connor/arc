//! Fenced reads of the original physical hold never acquire or reverse custody.
use super::*;
use chio_kernel::budget_store::BudgetInvocationState;

#[test]
fn native_capture_readback_authenticates_physical_members_inside_its_snapshot() -> AnchoredTestResult
{
    let fixture = fixture();
    let owner = pending(&fixture, "native-capture-custody")?;
    let capture = authorize(&fixture, owner.binding().operation_id().as_str())?;
    let lease = claim(&fixture, &owner, "native-capture-custody", now_ms());
    let (_, committed) = fixture.store.capture_invocation_and_commit_dispatch(
        &owner,
        &lease,
        capture,
        &fixture.fence,
        now_ms(),
    )?;
    // This transaction-level port consumes the caller's already authenticated
    // matching-grant inventory. Both fixtures select grant zero.
    let (_, retained) = super::super::super::retained_request::original(&fixture.fence)?;
    let budget = fixture.authority.budget_store();
    let before = counts(&fixture)?;
    for mutation in [
        "UPDATE budget_hold_quota_members SET max_invocations = max_invocations + 1 WHERE hold_id = 'shared-hold'",
        "DELETE FROM budget_hold_quota_members WHERE hold_id = 'shared-hold'",
    ] {
        let mut connection = fixture.store.connection()?;
        let transaction = connection.transaction()?;
        budget.load_native_capture_decision_tx(&transaction, &committed, &retained)?;
        transaction.execute_batch("PRAGMA defer_foreign_keys = ON")?;
        assert_eq!(transaction.execute(mutation, [])?, 1);
        assert!(
            budget
                .load_native_capture_decision_tx(&transaction, &committed, &retained)
                .is_err(),
            "native capture accepted changed physical custody: {mutation}",
        );
        transaction.rollback()?;
    }
    assert_eq!(counts(&fixture)?, before);
    Ok(())
}

#[test]
fn budget_custody_readback_distinguishes_absent_unheld_and_reversed_operations(
) -> AnchoredTestResult {
    use chio_kernel::budget_store::BudgetReverseHoldRequest;
    let fixture = fixture();
    let prepared = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "custody-unheld",
        "shared-capability",
    );
    assert!(fixture
        .store
        .load_admission_budget_custody(prepared.binding().operation_id(), &fixture.fence, now_ms())?
        .is_none());
    fixture.store.begin(&prepared, &fixture.fence, now_ms())?;
    assert!(fixture
        .store
        .load_admission_budget_custody(prepared.binding().operation_id(), &fixture.fence, now_ms())?
        .is_none());
    let owner = pending(&fixture, "custody-reversed")?;
    let capture = authorize(&fixture, owner.binding().operation_id().as_str())?;
    fixture
        .authority
        .budget_store()
        .reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: "shared-capability".into(),
            grant_index: 0,
            reversed_exposure_units: 0,
            hold_id: Some(capture.hold_id),
            event_id: Some("reverse-shared-hold".into()),
            expected_cumulative_approval_state: None,
            authority: capture.authority,
        })?;
    let before = counts(&fixture)?;
    let reversed = fixture
        .store
        .load_admission_budget_custody(owner.binding().operation_id(), &fixture.fence, now_ms())?
        .ok_or("reversed custody")?;
    assert_eq!(reversed.invocation_state, BudgetInvocationState::Reversed);
    assert!(matches!(
        reversed.monetary_state,
        chio_kernel::budget_store::BudgetMonetaryState::None
            | chio_kernel::budget_store::BudgetMonetaryState::Reversed
    ));
    assert_eq!(counts(&fixture)?, before);
    Ok(())
}

#[test]
fn budget_custody_readback_rejects_deleted_and_substituted_physical_quota_members(
) -> AnchoredTestResult {
    for mutation in [
        "UPDATE budget_hold_quota_members SET max_invocations = max_invocations + 1 WHERE hold_id = 'shared-hold'",
        "DELETE FROM budget_hold_quota_members WHERE hold_id = 'shared-hold'",
    ] {
        let fixture = fixture();
        let owner = pending(&fixture, "custody-corruption")?;
        authorize(&fixture, owner.binding().operation_id().as_str())?;
        // Use the owned connection so this exercises projection integrity
        // independently of the external-writer data-version check.
        {
            let connection = fixture.store.connection()?;
            connection.execute_batch("PRAGMA foreign_keys = OFF")?;
            assert_eq!(connection.execute(mutation, [])?, 1);
            connection.execute_batch("PRAGMA foreign_keys = ON")?;
        }
        assert!(fixture.store.load_admission_budget_custody(owner.binding().operation_id(), &fixture.fence, now_ms()).is_err(), "{mutation}");
    }
    Ok(())
}

#[test]
fn original_budget_custody_readback_binds_hold_owner_and_preserves_accounting() -> AnchoredTestResult
{
    let fixture = fixture();
    let owner = pending(&fixture, "custody-readback-owner")?;
    // A named but physically missing hold is corruption, not an unheld result.
    assert!(fixture
        .store
        .load_admission_budget_custody(owner.binding().operation_id(), &fixture.fence, now_ms(),)
        .is_err());
    let capture = authorize(&fixture, owner.binding().operation_id().as_str())?;
    let substitute = pending(&fixture, "custody-readback-substitute")?;
    assert!(fixture
        .store
        .load_admission_budget_custody(
            substitute.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )
        .is_err());
    let before = counts(&fixture)?;
    let held = fixture
        .store
        .load_admission_budget_custody(owner.binding().operation_id(), &fixture.fence, now_ms())?
        .ok_or("original held custody")?;
    assert_eq!(held.hold_id, capture.hold_id);
    assert_eq!(
        held.admission.operation_id,
        owner.binding().operation_id().as_str()
    );
    assert_eq!(held.capability_id, owner.binding().capability_id().as_str());
    assert_eq!(held.invocation_state, BudgetInvocationState::Authorized);
    assert_eq!(held.invocation_quotas.len(), 1);
    assert_eq!(held.invocation_quotas[0].max_invocations, 1);
    assert_eq!(counts(&fixture)?, before);
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert!(fixture
        .store
        .load_admission_budget_custody(owner.binding().operation_id(), &stale, now_ms(),)
        .is_err());
    assert!(fixture
        .store
        .load_admission_budget_custody(owner.binding().operation_id(), &fixture.fence, 0,)
        .is_err());
    let lease = claim(&fixture, &owner, "custody-readback-owner", now_ms());
    fixture.store.capture_invocation_and_commit_dispatch(
        &owner,
        &lease,
        capture,
        &fixture.fence,
        now_ms(),
    )?;
    let before = counts(&fixture)?;
    let captured = fixture
        .store
        .load_admission_budget_custody(owner.binding().operation_id(), &fixture.fence, now_ms())?
        .ok_or("captured custody")?;
    assert_eq!(captured.invocation_state, BudgetInvocationState::Captured);
    assert_eq!(captured.hold_id, held.hold_id);
    assert_eq!(captured.admission, held.admission);
    assert_eq!(captured.invocation_quotas, held.invocation_quotas);
    assert_eq!(counts(&fixture)?, before);
    Ok(())
}
