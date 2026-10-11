//! Scoped threshold artifacts retain current session authority and private arguments.

use super::*;

fn unbound_session_fixture() -> TestResult<Fixture> {
    let mut fixture = Fixture::new()?;
    let intent = fixture
        .request
        .governed_intent
        .as_mut()
        .ok_or("fixture intent missing")?;
    // Exercise trusted host binding of a legacy wire request. The direct-tool
    // fixture is already bound for its separate admission tests.
    intent.body = Default::default();
    intent.context = None;
    Ok(fixture)
}

#[test]
fn ap23_session_bound_threshold_artifact_cannot_cross_sessions() -> TestResult {
    let mut fixture = unbound_session_fixture()?;
    let original_intent = fixture.request.governed_intent.clone();
    let (context, proposal) = pending_session(&fixture)?;
    let bound_intent = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("original session missing")?
        .inflight()
        .get(&context.request_id)
        .ok_or("pending request missing")?
        .pending_threshold_approval
        .as_ref()
        .and_then(|pending| pending.bound_intent())
        .cloned()
        .ok_or("held intent missing")?;
    assert_eq!(
        bound_intent.binding_hash()?,
        proposal.body.governed_intent_hash
    );
    fixture.approve(proposal)?;
    fixture.request.governed_intent = Some(bound_intent);
    let other_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.request.capability.clone()],
    )?;
    fixture.kernel.activate_session(&other_id)?;
    let other_context = OperationContext::new(
        other_id,
        context.request_id.clone(),
        fixture.request.agent_id.clone(),
    );
    assert!(matches!(
        fixture.kernel.evaluate_session_operation(
            &other_context,
            &operation(&fixture.request)
        ),
        Err(KernelError::GovernedTransactionDenied(reason))
            if reason == "tool approval policy, tenant, capability or request binding changed"
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_pending_session(&fixture, &context)?;
    fixture.request.governed_intent = original_intent;
    assert_approved(&fixture, &context)
}

#[test]
fn ap23_session_pending_threshold_debug_omits_original_arguments() -> TestResult {
    let mut fixture = unbound_session_fixture()?;
    fixture.request.arguments = serde_json::json!({"secret": "ap23-session-argument-secret"});
    let (context, _) = pending_session(&fixture)?;
    let session = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    let request = session
        .inflight()
        .get(&context.request_id)
        .ok_or("pending request missing")?;
    let binding = request
        .pending_threshold_approval
        .as_ref()
        .ok_or("held approval missing")?;
    let diagnostic = format!("{binding:?}");
    assert!(
        !diagnostic.contains("ap23-session-argument-secret"),
        "retained arguments leaked through Debug"
    );
    assert!(diagnostic.contains("proposal_digest"));
    assert!(diagnostic.contains("operation_digest"));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn ap23_session_bound_threshold_artifact_requires_owned_context_on_raw_entry() -> TestResult {
    let mut fixture = unbound_session_fixture()?;
    let original_intent = fixture.request.governed_intent.clone();
    let (context, proposal) = pending_session(&fixture)?;
    let held = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?
        .inflight()
        .get(&context.request_id)
        .ok_or("pending request missing")?
        .pending_threshold_approval
        .as_ref()
        .and_then(|pending| pending.bound_intent())
        .cloned()
        .ok_or("held intent missing")?;
    fixture.approve(proposal)?;
    fixture.request.governed_intent = Some(held);
    assert!(matches!(
        fixture.kernel.evaluate_tool_call_blocking(&fixture.request),
        Err(KernelError::GovernedTransactionDenied(reason))
            if reason == "session-bound tool approval requires its owned session context"
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_pending_session(&fixture, &context)?;
    fixture.request.governed_intent = original_intent;
    assert_approved(&fixture, &context)
}

#[test]
fn ap23_session_below_threshold_needs_no_approval_resolver() -> TestResult {
    let mut fixture = unbound_session_fixture()?;
    fixture
        .request
        .governed_intent
        .as_mut()
        .ok_or("fixture intent missing")?
        .max_amount = Some(MonetaryAmount {
        units: 50,
        currency: "USD".into(),
    });
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(
            |_: &str, _: &str, _: &str| -> Result<Option<ThresholdApprovalRequirement>, String> {
                Ok(None)
            },
        ));
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.request.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let context = OperationContext::new(
        session_id,
        RequestId::new(fixture.request.request_id.clone()),
        fixture.request.agent_id.clone(),
    );
    let response = evaluate(&fixture, &context, EntryPoint::Session)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert!(fixture.store.operation().threshold_proposal().is_none());
    Ok(())
}

fn oauth_session_context(fixture: &Fixture, tenant: &str) -> TestResult<OperationContext> {
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.request.capability.clone()],
    )?;
    fixture.kernel.set_session_auth_context(
        &session_id,
        crate::kernel::tests::multi_tenant_receipt::oauth_auth_with_enterprise_tenant(tenant),
    )?;
    fixture.kernel.activate_session(&session_id)?;
    Ok(OperationContext::new(
        session_id,
        RequestId::new(fixture.request.request_id.clone()),
        fixture.request.agent_id.clone(),
    ))
}

#[test]
fn ap23_session_bound_threshold_artifact_cannot_cross_same_tenant_sessions() -> TestResult {
    let mut fixture = unbound_session_fixture()?;
    let original_intent = fixture.request.governed_intent.clone();
    let context = oauth_session_context(&fixture, "shared-enterprise-tenant")?;
    let pending = evaluate(&fixture, &context, EntryPoint::Session)?;
    assert_eq!(
        pending.verdict,
        Verdict::PendingApproval,
        "{:?}",
        pending.reason
    );
    let Some(ToolCallOutput::Value(value)) = pending.output else {
        return Err("pending proposal missing".into());
    };
    let proposal: ThresholdApprovalProposal = serde_json::from_value(value)?;
    let held = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?
        .inflight()
        .get(&context.request_id)
        .ok_or("pending request missing")?
        .pending_threshold_approval
        .as_ref()
        .and_then(|pending| pending.bound_intent())
        .cloned()
        .ok_or("held intent missing")?;
    let serialized_context = held.context.as_ref().ok_or("bound context missing")?;
    assert_eq!(
        serialized_context["chio_tool_approval"]["schema"],
        "chio.tool-approval-context.v1"
    );
    assert_eq!(
        serialized_context["chio_session_threshold"],
        "chio.session-threshold-approval.v1"
    );
    fixture.approve(proposal)?;
    fixture.request.governed_intent = Some(held);
    let other_context = oauth_session_context(&fixture, "shared-enterprise-tenant")?;
    assert_ne!(context.session_id, other_context.session_id);
    assert_eq!(
        fixture
            .kernel
            .resolve_tenant_id_for_session(Some(&context.session_id)),
        fixture
            .kernel
            .resolve_tenant_id_for_session(Some(&other_context.session_id))
    );
    assert!(matches!(
        fixture.kernel.evaluate_session_operation(&other_context, &operation(&fixture.request)),
        Err(KernelError::GovernedTransactionDenied(reason))
            if reason == "tool approval policy, tenant, capability or request binding changed"
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_pending_session(&fixture, &context)?;
    fixture.request.governed_intent = original_intent;
    assert_approved(&fixture, &context)
}
