//! A host cancellation that wins the pre-dispatch boundary is a cancelled outcome.

use super::*;

const PRE_DISPATCH_CANCELLATION: &str = "session request cancelled before dispatch";

fn reserve_unrelated_hold(
    fixture: &Fixture,
) -> TestResult<crate::budget_store::BudgetHoldSnapshot> {
    let budget = fixture.store.budget_store();
    let capability_id = fixture.request.capability.id.clone();
    let hold_id = "unrelated-earlier-session-hold";
    let decision = budget.authorize_budget_hold(BudgetAuthorizeHoldRequest {
        capability_id: capability_id.clone(),
        grant_index: 0,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: Some(crate::budget_store::BudgetAdmissionBinding {
            operation_id: "unrelated-earlier-session-operation".into(),
            revocation_set: crate::supplemental_quota::CanonicalRevocationSet::canonicalize(vec![
                capability_id,
            ])?,
            authorization_artifact_digests: Vec::new(),
            last_observed_revocation: None,
            supplemental_verifier_id: None,
            supplemental_verifier_config_digest: None,
            supplemental_authorization_artifact_digest: None,
            supplemental_authorization_expires_at: None,
        }),
        requested_exposure_units: 17,
        max_cost_per_invocation: Some(17),
        max_total_cost_units: Some(1_000),
        hold_id: Some(hold_id.into()),
        event_id: Some(format!("{hold_id}:authorize")),
        authority: None,
    })?;
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    budget
        .get_budget_hold(hold_id)?
        .ok_or_else(|| "unrelated earlier hold missing".into())
}

/// Parks the approved retry at its first threshold policy lookup. The retry has
/// already claimed the wait there and has not reached the dispatch-start boundary.
fn hold_policy_lookup(fixture: &mut Fixture) -> TestResult<CheckpointControl> {
    let resolver = fixture
        .kernel
        .threshold_approval_requirement_resolver
        .clone()
        .ok_or("policy resolver missing")?;
    let (checkpoint, control) = checkpoint();
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(
            move |policy: &str, server: &str, tool: &str| {
                checkpoint.hold()?;
                resolver.resolve_requirement(policy, server, tool)
            },
        ));
    Ok(control)
}

fn host_cancel_before_dispatch(entry: EntryPoint) -> TestResult {
    let mut fixture = Fixture::new()?;
    let unrelated_hold = reserve_unrelated_hold(&fixture)?;
    let (context, proposal) = pending_session_using(&fixture, entry)?;
    let original_hold_id = fixture
        .store
        .operation()
        .budget_hold_id()
        .ok_or("original approval hold missing")?
        .as_str()
        .to_owned();
    fixture.approve(proposal)?;
    let control = hold_policy_lookup(&mut fixture)?;
    let fixture = &fixture;
    let context = &context;
    let response = std::thread::scope(|scope| -> TestResult<ToolCallResponse> {
        let retry =
            scope.spawn(move || evaluate(fixture, context, entry).map_err(|e| e.to_string()));
        control.entered.recv_timeout(HOLD_TIMEOUT)?;
        assert_eq!(
            RequestState::read(fixture, context)?,
            RequestState::claimed()
        );
        fixture
            .kernel
            .request_session_cancellation(&context.session_id, &context.request_id)?;
        assert_eq!(
            RequestState::read(fixture, context)?,
            RequestState {
                cancellation_requested: true,
                ..RequestState::claimed()
            }
        );
        control.release.send(())?;
        Ok(retry.join().map_err(|_| "retry thread panicked")??)
    })?;

    // The dispatch-start boundary observed the host cancellation before any effect.
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(response.verdict, Verdict::Deny);
    let observed = KernelError::RequestCancelled {
        request_id: context.request_id.clone(),
        reason: PRE_DISPATCH_CANCELLATION.into(),
    }
    .to_string();
    assert!(
        matches!(
            response.reason.as_deref(),
            Some(reason) if reason == PRE_DISPATCH_CANCELLATION || reason == observed
        ),
        "{:?}",
        response.reason
    );

    let cancelled = OperationTerminalState::Cancelled {
        reason: PRE_DISPATCH_CANCELLATION.into(),
    };
    assert_eq!(response.terminal_state, cancelled);
    assert_eq!(
        response.receipt.decision,
        Some(Decision::Cancelled {
            reason: PRE_DISPATCH_CANCELLATION.into(),
        })
    );
    assert!(response.receipt.verify_integrity_embedded_key()?);
    assert_eq!(
        response.receipt.metadata.as_ref().and_then(|metadata| {
            metadata
                .pointer("/chio_runtime/identity_disposition")
                .and_then(serde_json::Value::as_str)
        }),
        Some("terminal"),
        "the original saga committed compensation before signing cancellation"
    );
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let budget = fixture.store.budget_store();
    assert_eq!(
        budget
            .get_budget_hold(&original_hold_id)?
            .ok_or("original compensated hold missing")?
            .disposition,
        crate::budget_store::BudgetHoldDispositionView::Reversed
    );
    assert_eq!(
        budget.get_budget_hold(&unrelated_hold.hold_id)?,
        Some(unrelated_hold),
        "original-saga cleanup must retain an unrelated earlier hold"
    );
    assert_eq!(
        budget
            .get_usage(&fixture.request.capability.id, 0)?
            .ok_or("budget usage missing")?
            .committed_cost_units()?,
        17
    );
    assert_eq!(
        RequestState::read(fixture, context)?,
        RequestState::finished(cancelled, 0)
    );
    Ok(())
}

#[test]
fn session_host_cancel_before_dispatch_records_cancelled_outcome() -> TestResult {
    host_cancel_before_dispatch(EntryPoint::Session)
}

#[test]
fn nested_sync_host_cancel_before_dispatch_records_cancelled_outcome() -> TestResult {
    host_cancel_before_dispatch(EntryPoint::NestedSync)
}

#[test]
fn nested_async_host_cancel_before_dispatch_records_cancelled_outcome() -> TestResult {
    host_cancel_before_dispatch(EntryPoint::NestedAsync)
}
