use super::*;

#[test]
fn cumulative_admission_retains_the_original_request_and_capability() -> TestResult {
    let mut fixture = Fixture::new()?;
    let proposal = fixture.pending()?;
    let original = {
        let state = fixture
            .store
            .state
            .lock()
            .map_err(|_| "test state poisoned")?;
        let retained = state
            .retained_request
            .as_ref()
            .ok_or("missing original request")?;
        retained.validate_binding(
            state
                .operation
                .as_ref()
                .ok_or("missing operation")?
                .binding(),
        )?;
        let restored = retained.request_for_revalidation();
        assert_eq!(
            canonical_json_bytes(&restored.capability)?,
            canonical_json_bytes(&fixture.request.capability)?
        );
        assert_eq!(restored.arguments, fixture.request.arguments);
        assert_eq!(restored.agent_id, fixture.request.agent_id);
        assert!(restored.dpop_proof.is_none());
        assert!(restored.execution_nonce.is_none());
        assert!(restored.approval_tokens.is_empty());
        retained.canonical_bytes().to_vec()
    };
    fixture.approve(proposal)?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let state = fixture
        .store
        .state
        .lock()
        .map_err(|_| "test state poisoned")?;
    assert_eq!(
        state
            .retained_request
            .as_ref()
            .ok_or("missing original")?
            .canonical_bytes(),
        original
    );
    Ok(())
}

#[test]
fn rejected_capability_does_not_retain_original_request_material() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.request.capability.id.push_str("-unsigned-change");
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    let state = fixture
        .store
        .state
        .lock()
        .map_err(|_| "test state poisoned")?;
    assert!(state.retained_request.is_none());
    assert!(state.operation.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn cumulative_retry_cannot_backfill_missing_original_authority() -> TestResult {
    let mut fixture = Fixture::new()?;
    let proposal = fixture.pending()?;
    fixture
        .store
        .state
        .lock()
        .map_err(|_| "test state poisoned")?
        .retained_request = None;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("original request")));
    assert_eq!(
        fixture.store.operation().threshold_proposal(),
        Some(&proposal)
    );
    assert!(fixture
        .store
        .state
        .lock()
        .map_err(|_| "test state poisoned")?
        .retained_request
        .is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
