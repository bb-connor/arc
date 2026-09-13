//! Reports must not consume approval continuation or durable operation authority.

use super::*;

fn conflict_preserves_wait(entry: EntryPoint) -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session_using(&fixture, entry)?;
    fixture.approve(proposal.clone())?;
    fixture.request.threshold_approval_proposal = None;
    let response = evaluate(&fixture, &context, entry)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        matches!(response.receipt.decision.as_ref(), Some(Decision::Deny { guard, .. }) if guard == "session_authorization")
    );
    assert_eq!(
        response.receipt.kernel_key,
        fixture.kernel.receipt_signing_public_key()
    );
    assert!(response.receipt.verify_signature()?);
    assert_pending_session(&fixture, &context)?;
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::ApprovalRequired
    );
    assert_eq!(
        fixture.store.operation().threshold_proposal(),
        Some(&proposal)
    );
    fixture.request.threshold_approval_proposal = Some(proposal);
    assert_approved(&fixture, &context)
}

#[test]
fn normalized_conflict_preserves_threshold_wait() -> TestResult {
    conflict_preserves_wait(EntryPoint::Session)
}

#[test]
fn nested_sync_conflict_preserves_threshold_wait() -> TestResult {
    conflict_preserves_wait(EntryPoint::NestedSync)
}

#[test]
fn nested_async_conflict_preserves_threshold_wait() -> TestResult {
    conflict_preserves_wait(EntryPoint::NestedAsync)
}

#[test]
fn failure_observation_preserves_pending_operation_and_approval_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    let SessionOperation::ToolCall(tool_call) = operation(&fixture.request) else {
        return Err("tool operation missing".into());
    };
    let receipt = fixture
        .kernel
        .record_session_tool_failure(&context, &tool_call)?;
    assert!(receipt.decision.is_none());
    assert!(receipt.financial_budget_authority_metadata().is_none());
    assert_pending_session(&fixture, &context)?;
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::ApprovalRequired
    );
    assert_eq!(
        fixture.store.operation().threshold_proposal(),
        Some(&proposal)
    );
    fixture.approve(proposal)?;
    assert_approved(&fixture, &context)
}

#[test]
fn wire_and_normalized_approval_shape_checks_agree_for_all_combinations() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (_, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal.clone())?;
    let vote = fixture
        .request
        .approval_tokens
        .first()
        .ok_or("vote missing")?
        .clone();
    for singular in [false, true] {
        for plural in [false, true] {
            for proposed in [false, true] {
                let SessionOperation::ToolCall(mut normalized) = operation(&fixture.request) else {
                    return Err("tool operation missing".into());
                };
                normalized.approval_token = singular.then(|| vote.clone());
                normalized.approval_tokens = if plural {
                    vec![vote.clone()]
                } else {
                    Vec::new()
                };
                normalized.threshold_approval_proposal = proposed.then(|| proposal.clone());
                let wire = chio_core::message::AgentMessage::ToolCallRequest {
                    id: fixture.request.request_id.clone(),
                    capability_token: Box::new(normalized.capability.clone()),
                    server_id: normalized.server_id.clone(),
                    tool: normalized.tool_name.clone(),
                    params: Box::new(normalized.arguments.clone()),
                    governed_intent: None,
                    approval_token: normalized.approval_token.clone().map(Box::new),
                    approval_tokens: normalized.approval_tokens.clone(),
                    threshold_approval_proposal: normalized
                        .threshold_approval_proposal
                        .clone()
                        .map(Box::new),
                    supplemental_authorization: None,
                    execution_nonce: None,
                };
                let expected = if singular && plural {
                    Some("approval_token and approval_tokens are mutually exclusive")
                } else if proposed && !plural {
                    Some("threshold_approval_proposal requires at least one approval token")
                } else if plural && !proposed {
                    Some("approval_tokens require a threshold_approval_proposal")
                } else {
                    None
                };
                assert_eq!(normalized.authorization_conflict(), expected);
                assert_eq!(wire.authorization_conflict(), expected);
            }
        }
    }
    Ok(())
}
