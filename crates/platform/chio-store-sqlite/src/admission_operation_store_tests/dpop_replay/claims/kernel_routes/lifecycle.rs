use super::*;

#[test]
fn grant_fallback_releases_the_first_dpop_episode_before_claiming_the_next() -> AnchoredTestResult {
    let route = Route::new()?;
    let request = route.request("fallback-dpop", &[0, 1])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let (_, history) = route.history(&request)?;
    assert_eq!(history.len(), 2);
    for claim in &history {
        assert_eq!(
            claim.disposition,
            if claim.intent.grant_index() == 0 {
                DpopReplayClaimDisposition::ReleasedBeforeDispatch
            } else {
                DpopReplayClaimDisposition::RetainedAfterDispatchCommit
            }
        );
    }
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn budget_denial_releases_dpop_and_terminalizes_without_execution() -> AnchoredTestResult {
    let route = Route::new()?;
    let request = route.request("unfunded-dpop", &[0])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    let (operation, history) = route.history(&request)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn nonce_preflight_releases_dpop_before_issuance_then_dispatch_claims_a_new_episode(
) -> AnchoredTestResult {
    let mut route = Route::new()?;
    let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 60,
        nonce_store_capacity: 16,
        require_nonce: true,
    };
    route.kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
    );
    let mut request = route.request("nonce-dpop", &[1])?;
    let preflight = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    let (operation, history) = route.history(&request)?;
    assert!(operation.execution_nonce_issuance_digest().is_some());
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].intent.phase(),
        DpopReplayClaimPhase::NoncePreflight
    );
    assert_eq!(
        history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
    request.execution_nonce = preflight.execution_nonce.map(|nonce| *nonce);
    assert!(request.execution_nonce.is_some());
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let (_, history) = route.history(&request)?;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history
            .iter()
            .filter(|claim| claim.disposition
                == DpopReplayClaimDisposition::RetainedAfterDispatchCommit
                && claim.intent.phase() == DpopReplayClaimPhase::Dispatch)
            .count(),
        1
    );
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
