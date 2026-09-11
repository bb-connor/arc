//! Stable trusted identity must be checked before durable terminal recovery.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "security_binding/retention.rs"]
mod retention;
#[path = "security_binding/native_authority.rs"]
mod native_authority;

pub(super) fn matching(request: &ToolCallRequest) -> Result<Vec<MatchingGrant<'_>>, KernelError> {
    resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .map_err(|error| KernelError::Internal(error.to_string()))
}

pub(super) fn context(
    request: &ToolCallRequest,
    generation: u64,
) -> Result<SecurityInvocationContext, Box<dyn std::error::Error>> {
    Ok(SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("admission-tenant")?,
            chio_security_types::ports::SessionId::new("admission-session")?,
            chio_security_types::PrincipalId::new(request.agent_id.clone())?,
            chio_security_types::ports::IsolationEpochId::new("admission-epoch")?,
            chio_security_types::ports::LineageId::new(request.capability.id.clone())?,
            generation,
        ),
    ))
}

#[test]
fn changed_security_identity_cannot_recover_a_completed_operation() -> TestResult {
    let (kernel, request, store, invocations) = durable_admission_fixture("security-replay");
    let first = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request, 1)?)?;
    assert_eq!(first.verdict, Verdict::Allow, "{first:?}");
    let operation = store.operation();
    let replay = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request, 2)?)?;
    assert_eq!(
        replay.verdict,
        Verdict::Deny,
        "changed identity recovered the old output: {replay:?}"
    );
    assert_eq!(store.operation(), operation);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn security_bound_raw_return_recovers_without_a_live_request_or_redispatch() -> TestResult {
    let (kernel, request, store, invocations) = durable_admission_fixture("security-finalization");
    store.fail_next_evaluation_begin();
    assert!(kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request, 1)?)
        .is_err());
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    let _clock = crate::scope_fixed_runtime_for_current_thread(current_unix_timestamp() + 61, []);
    assert_eq!(kernel.reconcile_recoverable_admissions()?, 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    let replay = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request, 1)?)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{replay:?}");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

fn evaluate(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    context: Option<&SecurityInvocationContext>,
    parent: Option<&OperationContext>,
) -> Result<ToolCallResponse, KernelError> {
    if let Some(parent) = parent {
        kernel.evaluate_tool_call_with_nested_flow_client_and_security_context(
            parent,
            request,
            &mut NoopNestedFlowClient,
            None,
            context,
        )
    } else if let Some(context) = context {
        kernel.evaluate_tool_call_blocking_with_security_context(request, context)
    } else {
        kernel.evaluate_tool_call_blocking(request)
    }
}

fn replay_matrix(nested: bool) -> TestResult {
    let (kernel, request, store, invocations) = durable_admission_fixture("security-matrix");
    let session = kernel.open_session(request.agent_id.clone(), vec![])?;
    kernel.activate_session(&session)?;
    let parent = make_operation_context(&session, "security-parent", &request.agent_id);
    kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
    let mut original = serde_json::to_value(context(&request, 1)?)?;
    original["context"]["sessionId"] = serde_json::json!(session.as_str());
    let original: SecurityInvocationContext = serde_json::from_value(original)?;
    let parent = nested.then_some(&parent);
    let first = evaluate(&kernel, &request, Some(&original), parent)?;
    assert_eq!(first.verdict, Verdict::Allow, "{first:?}");
    let operation = store.operation();

    for (field, value) in [
        ("tenantId", serde_json::json!("another-tenant")),
        ("sessionId", serde_json::json!("another-session")),
        ("isolationEpochId", serde_json::json!("another-epoch")),
        ("contextGeneration", serde_json::json!(2)),
        ("principalId", serde_json::json!("another-principal")),
        ("lineageRootId", serde_json::json!("another-lineage")),
    ] {
        let mut changed = serde_json::to_value(&original)?;
        changed["context"][field] = value;
        let changed = serde_json::from_value(changed)?;
        match evaluate(&kernel, &request, Some(&changed), parent) {
            Ok(response) => {
                assert_eq!(response.verdict, Verdict::Deny, "{field}: {response:?}");
                assert!(response.output.is_none());
                assert!(response
                    .reason
                    .as_deref()
                    .is_some_and(|r| r.contains("conflicts with retained operation")));
            }
            Err(KernelError::GuardDenied(_)) => {
                assert!(
                    field == "principalId"
                        || field == "lineageRootId"
                        || (nested && field == "sessionId")
                );
            }
            Err(error) => return Err(error.into()),
        }
        assert_eq!(store.operation(), operation, "{field}");
    }
    let removed = evaluate(&kernel, &request, None, parent)?;
    assert_eq!(removed.verdict, Verdict::Deny);
    assert!(removed.output.is_none());
    let advanced =
        SecurityInvocationContext::v1(original.as_v1().clone().with_flow_state_generation(7));
    let replay = evaluate(&kernel, &request, Some(&advanced), parent)?;
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, first.receipt.id);
    assert_eq!(replay.output, first.output);
    assert_eq!(store.operation(), operation);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn ordinary_security_replay_checks_every_identity_field_and_preserves_flow_observations(
) -> TestResult {
    replay_matrix(false)
}

#[test]
fn nested_security_replay_checks_every_identity_field_and_preserves_flow_observations() -> TestResult
{
    replay_matrix(true)
}

struct NoopHook;
impl SecurityPreDispatchHook for NoopHook {
    fn name(&self) -> &str {
        "admission-binding-test"
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(None)
    }
}

#[test]
fn changed_security_requirements_cannot_recover_an_unbound_terminal() -> TestResult {
    for hook in [false, true] {
        let (mut kernel, request, store, invocations) =
            durable_admission_fixture("security-requirements");
        assert_eq!(
            kernel.evaluate_tool_call_blocking(&request)?.verdict,
            Verdict::Allow
        );
        let operation = store.operation();
        if hook {
            kernel.set_security_pre_dispatch_hook(Arc::new(NoopHook));
        } else {
            kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        }
        let retry = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(retry.verdict, Verdict::Deny, "{retry:?}");
        assert!(retry.output.is_none());
        assert_eq!(store.operation(), operation);
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn adding_security_context_cannot_recover_an_unbound_terminal() -> TestResult {
    let (kernel, request, store, invocations) = durable_admission_fixture("security-added");
    assert_eq!(
        kernel.evaluate_tool_call_blocking(&request)?.verdict,
        Verdict::Allow
    );
    let operation = store.operation();
    let replay = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request, 1)?)?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay.output.is_none());
    assert_eq!(store.operation(), operation);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn security_binding_preserves_large_ordinary_requests() -> TestResult {
    let (kernel, mut request, _, invocations) = durable_admission_fixture("security-large");
    request.arguments["payload"] = serde_json::json!("x".repeat(262_145));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &context(&request, 1)?)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn changed_security_identity_is_rejected_before_dispatch_capture() -> TestResult {
    use crate::kernel::admission_coordinator::DispatchTransport;
    let (kernel, request, store, invocations) = durable_admission_fixture("security-freeze");
    let now = current_unix_timestamp_ms();
    let matching = matching(&request)?;
    let original = context(&request, 1)?;
    let changed = context(&request, 2)?;
    let mut admission = kernel
        .begin_durable_tool_admission_for_transport(
            &request,
            &matching,
            Some(&original),
            now,
            DispatchTransport::KernelToolServer,
        )?
        .ok_or("durable admission")?;
    let (_, mut budget) = kernel
        .check_and_increment_budget(
            &request,
            &request.capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )?
        .into_authorized()?;
    kernel.mark_durable_capture_pending(&mut admission, now)?;
    let operation = store.operation();
    let result = kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut budget,
        DurableToolReturnContextInput {
            request: &request,
            matched_grant_index: 0,
            extra_receipt_metadata: None,
            pre_invocation_guard_evidence: &[],
            verified_payee_binding: None,
            verified_purchase: None,
            verified_recovery: None,
            trusted_now_unix_ms: now,
            security_invocation_context: Some(&changed),
            security_release_required: false,
        },
    );
    assert!(matches!(
        result,
        Err(DurableDispatchCommitError::RejectedBeforeCommit(_))
    ));
    assert_eq!(store.operation(), operation);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
