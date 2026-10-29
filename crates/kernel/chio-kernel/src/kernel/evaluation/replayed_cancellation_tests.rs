use super::*;
use crate::admission_operation::AdmissionOperationState;
use crate::budget_store::{BudgetHoldCleanupCustody, BudgetHoldDispositionView};
use crate::kernel::tests::durable_admission_fixture;

#[test]
fn cancelled_replayed_invocation_preserves_original_saga() -> Result<(), Box<dyn std::error::Error>>
{
    let (kernel, mut request, store, invocations) =
        durable_admission_fixture("cancelled-replayed-invocation");
    let mut body = request.capability.body();
    body.scope.grants[0].max_invocations = Some(3);
    request.capability = CapabilityToken::sign(body, &kernel.config.keypair)?;
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    let now = kernel.read_authority_time()?.get();
    let mut admission = kernel
        .begin_durable_tool_admission(&request, &matching, now)?
        .ok_or("durable admission missing")?;
    let (_, first) = kernel
        .check_and_increment_budget(
            &request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    assert_eq!(
        first
            .durable_hold_result()
            .ok_or("first invocation hold missing")?
            .cleanup_custody,
        BudgetHoldCleanupCustody::Fresh
    );
    let (grant_index, replayed) = kernel
        .check_and_increment_budget(
            &request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    let PreExecutionBudgetMutation::InvocationHold(charge) = &replayed else {
        return Err("replayed authorization must retain an invocation hold".into());
    };
    assert_eq!(charge.cleanup_custody, BudgetHoldCleanupCustody::Replayed);
    assert!(charge.invocation_capture.is_none());
    let operation_before = store.operation();
    assert_eq!(operation_before, *admission.operation());
    assert_eq!(
        operation_before.state(),
        AdmissionOperationState::BudgetAuthorized
    );
    assert_eq!(
        operation_before.binding().request_id().as_str(),
        request.request_id
    );
    assert_eq!(
        operation_before.binding().capability_id().as_str(),
        request.capability.id
    );
    assert_eq!(
        operation_before.budget_hold_id().map(|hold| hold.as_str()),
        Some(charge.budget_hold_id.as_str())
    );
    let budget = store.budget_store();
    let hold_before = budget
        .get_budget_hold(&charge.budget_hold_id)?
        .ok_or("original invocation hold missing")?;
    assert_eq!(hold_before.disposition, BudgetHoldDispositionView::Open);
    let usage_before = budget
        .get_usage(&request.capability.id, grant_index)?
        .ok_or("invocation usage missing")?;
    assert_eq!(usage_before.invocation_count, 1);

    let receipts_before = kernel.receipt_log().len();
    assert_eq!(receipts_before, 0);
    let response = kernel.build_session_dispatch_refusal_response(
        PreDispatchCleanupDeny {
            request: &request,
            denial: &Denial::new(
                ClientDenialCode::Denied,
                "session request cancelled before dispatch",
            ),
            timestamp: now / 1_000,
            matched_grant_index: grant_index,
            cap: &request.capability,
            budget_mutation: &replayed,
            payment_authorization: None,
            durable_operation: Some(&operation_before),
            runtime_admission_metadata: None,
            verified_payee_binding: None,
            budget_lease_acquired: false,
        },
        true,
    );

    assert_eq!(store.operation(), operation_before);
    assert_eq!(
        budget.get_budget_hold(&charge.budget_hold_id)?,
        Some(hold_before)
    );
    assert_eq!(
        budget.get_usage(&request.capability.id, grant_index)?,
        Some(usage_before)
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        response,
        Err(KernelError::BudgetStore(crate::budget_store::BudgetStoreError::Invariant(reason)))
            if reason == "budget hold cleanup requires fresh custody; current call custody is replayed"
    ));
    assert_eq!(kernel.receipt_log().len(), receipts_before);
    Ok(())
}
