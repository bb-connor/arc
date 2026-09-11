//! Normal kernel routes against the real SQLite authority and sealed source.
use super::*;
use chio_core::capability::scope::{ChioScope, Constraint, Operation, ToolGrant};
use chio_kernel::governed_approval_replay::GovernedApprovalReplayStore;
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection, Verdict,
};
use std::sync::atomic::{AtomicUsize, Ordering};
#[path = "kernel_routes/boundaries.rs"]
mod boundaries;

struct Server(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "approval-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["tool".into()]
    }
    fn tool_is_read_only(&self, _: &str) -> bool {
        true
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"ok": true}))
    }
}

struct RefuseLegacy(Arc<AtomicUsize>);
impl GovernedApprovalReplayStore for RefuseLegacy {
    fn reserve_for_dispatch(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: u64,
        _: &str,
    ) -> Result<bool, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal(
            "legacy approval route must not be used".into(),
        ))
    }
    fn commit_dispatch_reservation(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<bool, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal(
            "legacy approval commit must not be used".into(),
        ))
    }
    fn rollback_dispatch_reservation(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<bool, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal(
            "legacy approval rollback must not be used".into(),
        ))
    }
}

struct Route {
    fixture: Fixture,
    source: Arc<Source>,
    binding: GovernedApprovalAuthorityBindingV1,
    signer: Keypair,
    kernel: ChioKernel,
    calls: Arc<AtomicUsize>,
    legacy: Arc<AtomicUsize>,
}
impl Route {
    fn new() -> AnchoredTestResult<Self> {
        let fixture = fixture();
        let source = Arc::new(Source::new(&fixture, true)?);
        let binding = activate(&fixture, source.as_ref())?;
        let signer = Keypair::generate();
        let mut kernel = kernel_recovery::kernel_with_signer(&fixture, signer.clone())?;
        kernel.set_operation_owned_governed_approval_source(binding.clone(), source.clone())?;
        let calls = Arc::new(AtomicUsize::new(0));
        let legacy = Arc::new(AtomicUsize::new(0));
        kernel.set_governed_approval_replay_store(Box::new(RefuseLegacy(legacy.clone())));
        kernel.register_tool_server(Box::new(Server(calls.clone())));
        Ok(Self {
            fixture,
            source,
            binding,
            signer,
            kernel,
            calls,
            legacy,
        })
    }

    fn request(&self, id: &str, limits: &[u32]) -> AnchoredTestResult<ToolCallRequest> {
        let agent = Keypair::generate();
        let capability = self.kernel.issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: limits
                    .iter()
                    .map(|limit| ToolGrant {
                        server_id: "approval-server".into(),
                        tool_name: "tool".into(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![Constraint::GovernedIntentRequired],
                        max_invocations: Some(*limit),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    })
                    .collect(),
                ..Default::default()
            },
            300,
        )?;
        let intent = GovernedTransactionIntent {
            id: id.into(),
            server_id: "approval-server".into(),
            tool_name: "tool".into(),
            purpose: "kernel custody qualification".into(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        };
        let token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("approval-{id}"),
                approver: self.signer.public_key(),
                subject: capability.subject.clone(),
                governed_intent_hash: intent.binding_hash()?,
                request_id: id.into(),
                threshold_proposal_hash: None,
                issued_at: now_ms() / 1000 - 1,
                expires_at: now_ms() / 1000 + 120,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.signer,
        )?;
        Ok(serde_json::from_value(serde_json::json!({
            "request_id": id, "capability": capability, "agent_id": agent.public_key().to_hex(),
            "server_id": "approval-server", "tool_name": "tool", "arguments": {"record": id},
            "governed_intent": intent, "approval_token": token,
        }))?)
    }

    fn history(&self, request: &ToolCallRequest) -> AnchoredTestResult<(AdmissionOperationV1, Vec<chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalClaimHistoryV1>)>{
        let id: String = self.fixture.store.connection()?.query_row(
            "SELECT operation_id FROM admission_operations WHERE request_id = ?1",
            [&request.request_id],
            |row| row.get(0),
        )?;
        Ok(self
            .fixture
            .store
            .load_governed_approval_claim_history(
                &AdmissionOperationId::from_persisted(id)?,
                &self.fixture.fence,
                now_ms(),
            )?
            .ok_or("operation missing")?)
    }

    fn counts(&self) -> AnchoredTestResult<(i64, i64)> {
        Ok(self.fixture.store.connection()?.query_row("SELECT (SELECT COUNT(*) FROM governed_approval_replay_claim_episodes), (SELECT COUNT(*) FROM budget_authorization_holds)", [], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }
}

#[test]
fn normal_approval_dispatch_claims_before_budget_without_legacy_consumption() -> AnchoredTestResult
{
    let route = Route::new()?;
    let request = route.request("normal-owned", &[1])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    let (operation, history) = route.history(&request)?;
    assert!(operation.state().is_terminal());
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].disposition,
        GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
    );
    assert!(
        history[0].intent.credential()
            == &GovernedApprovalCredentialV1::from_token(
                request.approval_token.as_ref().ok_or("token")?
            )?
    );
    let (claim_sequence, budget_sequence): (i64, i64) = route.fixture.store.connection()?.query_row(
        "SELECT (SELECT MIN(commit_sequence) FROM admission_operation_commits WHERE mutation_kind = 'governed_approval_claim'), (SELECT MIN(commit_sequence) FROM admission_operation_commits WHERE mutation_kind = 'participant_update')", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
    assert!(claim_sequence < budget_sequence);
    let _ = route.kernel.evaluate_tool_call_blocking(&request);
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    assert_eq!(route.history(&request)?.1.len(), 1);
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn invalid_signed_approval_does_not_acquire_claim_or_budget() -> AnchoredTestResult {
    for invalid in ["issuer", "request", "signature", "expiry"] {
        let route = Route::new()?;
        let mut request = route.request(invalid, &[1])?;
        let token = request.approval_token.take().ok_or("token")?;
        let mut body = token.body();
        let signer = if invalid == "issuer" {
            Keypair::generate()
        } else {
            route.signer.clone()
        };
        body.approver = signer.public_key();
        if invalid == "request" {
            body.request_id = "other-request".into();
        }
        if invalid == "expiry" {
            body.issued_at = now_ms() / 1000 - 10;
            body.expires_at = now_ms() / 1000 - 1;
        }
        let mut token = GovernedApprovalToken::sign(body, &signer)?;
        if invalid == "signature" {
            token.request_id.push_str("-unsigned");
        }
        request.approval_token = Some(token);
        let response = route.kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{invalid}");
        assert_eq!(route.counts()?, (0, 0), "{invalid}");
        assert_eq!(route.calls.load(Ordering::SeqCst), 0);
        assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn grant_fallback_releases_only_the_preceding_approval_episode() -> AnchoredTestResult {
    let route = Route::new()?;
    let request = route.request("fallback", &[0, 1])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let (_, history) = route.history(&request)?;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].intent.grant_index(), 0);
    assert_eq!(
        history[0].disposition,
        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(history[1].intent.grant_index(), 1);
    assert_eq!(
        history[1].disposition,
        GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
    );
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn source_verification_failure_precedes_claim_and_budget() -> AnchoredTestResult {
    let route = Route::new()?;
    let request = route.request("source-failed", &[1])?;
    route.source.state.lock().expect("state").panic_on = Some("verify");
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(route.counts()?, (0, 0));
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn budget_denial_compensates_approval_without_legacy_rollback() -> AnchoredTestResult {
    let route = Route::new()?;
    let request = route.request("unfunded", &[0])?;
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
        GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn rejected_source_reconfiguration_preserves_the_installed_authority() -> AnchoredTestResult {
    let mut route = Route::new()?;
    let wrong = GovernedApprovalAuthorityBindingV1::new(
        route.binding.approval_authority_id().clone(),
        identifier("expectation", "not-activated"),
    );
    assert!(route
        .kernel
        .set_operation_owned_governed_approval_source(wrong, route.source.clone())
        .is_err());
    let request = route.request("retained-config", &[1])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(
        route.history(&request)?.1[0].intent.expectation_id(),
        route.binding.expectation_id()
    );
    assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn imported_inactive_approval_source_cannot_configure_kernel_acquisition() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Arc::new(Source::new(&fixture, true)?);
    let pinned = pin(&fixture, source.as_ref())?;
    let imported = import(&fixture, source.as_ref(), &pinned)?;
    let binding = GovernedApprovalAuthorityBindingV1::new(
        identifier("authority", AUTHORITY_ID),
        imported.expectation_id().clone(),
    );
    let mut kernel = kernel_recovery::kernel_with_signer(&fixture, Keypair::generate())?;
    let before = global_count(&fixture);
    assert!(kernel
        .set_operation_owned_governed_approval_source(binding, source)
        .is_err());
    assert_eq!(global_count(&fixture), before);
    Ok(())
}

#[test]
fn nonce_preflight_releases_approval_then_execution_claims_a_new_episode() -> AnchoredTestResult {
    for session_route in [false, true] {
        let mut route = Route::new()?;
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
        let mut request = route.request("nonce-route", &[1])?;
        let context = if session_route {
            let session = route
                .kernel
                .open_session(request.agent_id.clone(), vec![request.capability.clone()])?;
            route.kernel.activate_session(&session)?;
            Some(chio_core::session::OperationContext::new(
                session,
                chio_core::session::RequestId::new(request.request_id.clone()),
                request.agent_id.clone(),
            ))
        } else {
            None
        };
        let evaluate =
            |request: &ToolCallRequest| -> AnchoredTestResult<chio_kernel::ToolCallResponse> {
                let Some(context) = context.as_ref() else {
                    return Ok(route.kernel.evaluate_tool_call_blocking(request)?);
                };
                let operation = chio_core::session::SessionOperation::ToolCall(Box::new(
                    chio_core::session::ToolCallOperation {
                        capability: request.capability.clone(),
                        server_id: request.server_id.clone(),
                        tool_name: request.tool_name.clone(),
                        arguments: request.arguments.clone(),
                        governed_intent: request.governed_intent.clone(),
                        approval_token: request.approval_token.clone(),
                        approval_tokens: vec![],
                        threshold_approval_proposal: None,
                        supplemental_authorization: None,
                        execution_nonce: request
                            .execution_nonce
                            .as_ref()
                            .map(serde_json::to_value)
                            .transpose()?,
                        model_metadata: None,
                        extra_metadata: None,
                    },
                ));
                match route
                    .kernel
                    .evaluate_session_operation(context, &operation)?
                {
                    chio_kernel::SessionOperationResponse::ToolCall(response) => Ok(response),
                    _ => Err("tool call response missing".into()),
                }
            };
        let preflight = evaluate(&request)?;
        assert_eq!(
            preflight.verdict,
            Verdict::Allow,
            "session={session_route}: {:?}",
            preflight.reason
        );
        assert_eq!(route.calls.load(Ordering::SeqCst), 0);
        let (_, history) = route.history(&request)?;
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].intent.phase(),
            GovernedApprovalClaimPhase::NoncePreflight
        );
        assert_eq!(
            history[0].disposition,
            GovernedApprovalClaimDisposition::ReleasedBeforeDispatch
        );
        request.execution_nonce = preflight.execution_nonce.map(|nonce| *nonce);
        assert!(request.execution_nonce.is_some());
        let response = evaluate(&request)?;
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "session={session_route}: {:?}",
            response.reason
        );
        let (_, history) = route.history(&request)?;
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[1].intent.phase(),
            GovernedApprovalClaimPhase::Dispatch
        );
        assert_eq!(
            history[1].disposition,
            GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
        );
        assert_eq!(route.calls.load(Ordering::SeqCst), 1);
        assert_eq!(route.legacy.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
