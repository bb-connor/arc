//! Both replay participants share one operation but acquire separate exact-version leases.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent,
};
use chio_kernel::admission_operation::governed_approval_claim::{
    GovernedApprovalAuthorityBindingV1, GovernedApprovalClaimDisposition,
};

fn add_approval(route: &mut Route, request: &mut ToolCallRequest) -> AnchoredTestResult {
    let path = route.fixture._temp.path().join("composed-approval.db");
    drop(crate::SqliteGovernedApprovalReplayStore::open_with_capacity(&path, 16)?);
    let source = Arc::new(crate::SqliteGovernedApprovalReplaySource::open(&path)?);
    let authority = identifier("authority", "composed-approval");
    let expected = route.fixture.store.expect_governed_approval_replay_source(
        &identifier("source", "composed-approval-source"),
        &authority,
        source.as_ref(),
        &route.fixture.fence,
        now_ms(),
    )?;
    let imported = route.fixture.store.import_governed_approval_replay_source(
        &authority,
        expected.expectation_id(),
        source.as_ref(),
        &route.fixture.fence,
        now_ms(),
    )?;
    let binding =
        GovernedApprovalAuthorityBindingV1::new(authority, imported.expectation_id().clone());
    route
        .fixture
        .store
        .activate_governed_approval_replay_source(
            &binding,
            source.as_ref(),
            &route.fixture.fence,
            now_ms(),
        )?;
    route
        .kernel
        .set_operation_owned_governed_approval_source(binding, source)?;
    let mut body = request.capability.body();
    for grant in &mut body.scope.grants {
        grant
            .constraints
            .push(chio_core::capability::scope::Constraint::GovernedIntentRequired);
    }
    request.capability = chio_core::capability::token::CapabilityToken::sign(body, &route.signer)?;
    let intent = GovernedTransactionIntent {
        id: request.request_id.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "composed credential custody".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    };
    request.approval_token = Some(GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{}", request.request_id),
            approver: route.signer.public_key(),
            subject: request.capability.subject.clone(),
            governed_intent_hash: intent.binding_hash()?,
            request_id: request.request_id.clone(),
            threshold_proposal_hash: None,
            issued_at: now_ms() / 1000 - 1,
            expires_at: now_ms() / 1000 + 120,
            decision: GovernedApprovalDecision::Approved,
        },
        &route.signer,
    )?);
    request.governed_intent = Some(intent);
    Ok(())
}

#[test]
fn composed_dpop_and_approval_preserve_each_grant_episode_across_preflight() -> AnchoredTestResult {
    for nonce_preflight in [false, true] {
        let mut route = Route::new()?;
        let mut request = route.request("composed-custody", &[0, 1])?;
        add_approval(&mut route, &mut request)?;
        if nonce_preflight {
            let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
                nonce_ttl_secs: 60,
                nonce_store_capacity: 16,
                require_nonce: true,
            };
            route.kernel.set_execution_nonce_store(
                config.clone(),
                Box::new(
                    chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config),
                ),
            );
            let preflight = route.kernel.evaluate_tool_call_blocking(&request)?;
            assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
            assert_eq!(route.calls.load(Ordering::SeqCst), 0);
            assert!(route.history(&request)?.1.iter().all(
                |claim| claim.disposition == DpopReplayClaimDisposition::ReleasedBeforeDispatch
            ));
            request.execution_nonce = preflight.execution_nonce.map(|nonce| *nonce);
            assert!(request.execution_nonce.is_some());
        }
        let response = route.kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(route.calls.load(Ordering::SeqCst), 1);
        let (operation, dpop) = route.history(&request)?;
        let (approval_operation, approval) = route
            .fixture
            .store
            .load_governed_approval_claim_history(
                operation.binding().operation_id(),
                &route.fixture.fence,
                now_ms(),
            )?
            .ok_or("approval missing")?;
        assert_eq!(approval_operation, operation);
        // Issuance pins the successful preflight grant. Dispatch does not
        // revisit the rejected grant or acquire a fourth episode.
        let grants = if nonce_preflight {
            vec![0, 1, 1]
        } else {
            vec![0, 1]
        };
        assert_eq!(
            dpop.iter()
                .map(|claim| claim.intent.grant_index())
                .collect::<Vec<_>>(),
            grants
        );
        assert_eq!(dpop.len(), if nonce_preflight { 3 } else { 2 });
        assert_eq!(approval.len(), dpop.len());
        let last_episode = dpop.len() - 1;
        for (index, (dpop, approval)) in dpop.iter().zip(&approval).enumerate() {
            assert_eq!(dpop.intent.grant_index(), approval.intent.grant_index());
            let committed = index == last_episode;
            assert_eq!(
                dpop.intent.phase(),
                if nonce_preflight && !committed {
                    DpopReplayClaimPhase::NoncePreflight
                } else {
                    DpopReplayClaimPhase::Dispatch
                }
            );
            assert_eq!(
                dpop.disposition,
                if committed {
                    DpopReplayClaimDisposition::RetainedAfterDispatchCommit
                } else {
                    DpopReplayClaimDisposition::ReleasedBeforeDispatch
                }
            );
            assert_eq!(
                approval.disposition,
                if committed {
                    GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
                } else {
                    GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
                }
            );
        }
    }
    Ok(())
}

#[test]
fn invalid_approval_prevents_the_first_dpop_claim_in_a_composed_request() -> AnchoredTestResult {
    let mut route = Route::new()?;
    let mut request = route.request("invalid-composition", &[1])?;
    add_approval(&mut route, &mut request)?;
    let mut body = request.approval_token.take().ok_or("approval")?.body();
    body.request_id = "another-request".into();
    request.approval_token = Some(GovernedApprovalToken::sign(body, &route.signer)?);
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(route.counts()?, (0, 0));
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn caller_reservation_rejects_unrecoverable_composed_credentials_before_acquisition(
) -> AnchoredTestResult {
    let mut route = Route::new()?;
    let mut request = route.request("unsupported-caller-composition", &[1])?;
    add_approval(&mut route, &mut request)?;
    let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 60,
        nonce_store_capacity: 16,
        require_nonce: true,
    };
    route.kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
    );
    let response = route.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(response.execution_nonce.is_none());
    assert_eq!(route.counts()?, (0, 0));
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    let (operations, approvals): (i64, i64) = route.fixture.store.connection()?.query_row(
        "SELECT (SELECT COUNT(*) FROM admission_operations), (SELECT COUNT(*) FROM governed_approval_replay_claim_episodes)",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!((operations, approvals), (0, 0));
    Ok(())
}

#[test]
fn unsupported_caller_retry_keeps_issued_nonce_and_composed_history_usable_by_kernel(
) -> AnchoredTestResult {
    let mut route = Route::new()?;
    let mut request = route.request("unsupported-caller-retry", &[0, 1])?;
    add_approval(&mut route, &mut request)?;
    let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 60,
        nonce_store_capacity: 16,
        require_nonce: true,
    };
    route.kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
    );
    let preflight = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
    request.execution_nonce = preflight.execution_nonce.map(|nonce| *nonce);
    assert!(request.execution_nonce.is_some());
    let before = route.history(&request)?;
    let counts = route.counts()?;
    let denied = route.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert!(denied.execution_nonce.is_none());
    assert_eq!(route.history(&request)?, before);
    assert_eq!(route.counts()?, counts);
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    let dispatched = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(
        dispatched.verdict,
        Verdict::Allow,
        "{:?}",
        dispatched.reason
    );
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
