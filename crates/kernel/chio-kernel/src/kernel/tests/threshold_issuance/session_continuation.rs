//! Threshold approval round trips through the production session entrypoints.

use super::*;

fn operation(request: &ToolCallRequest) -> SessionOperation {
    SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: request.governed_intent.clone(),
        approval_token: request.approval_token.clone(),
        approval_tokens: request.approval_tokens.clone(),
        threshold_approval_proposal: request.threshold_approval_proposal.clone(),
        supplemental_authorization: request.supplemental_authorization.clone(),
        execution_nonce: None,
        model_metadata: request.model_metadata.clone(),
        extra_metadata: None,
    }))
}

fn pending_session(fixture: &Fixture) -> TestResult<(OperationContext, ThresholdApprovalProposal)> {
    pending_session_using(fixture, EntryPoint::Session)
}

#[derive(Clone, Copy)]
enum EntryPoint {
    Session,
    NestedSync,
    NestedAsync,
}

fn evaluate(
    fixture: &Fixture,
    context: &OperationContext,
    entry: EntryPoint,
) -> TestResult<ToolCallResponse> {
    let operation = operation(&fixture.request);
    if matches!(entry, EntryPoint::Session) {
        return session_tool_call(
            fixture
                .kernel
                .evaluate_session_operation(context, &operation)?,
        )
        .ok_or_else(|| "tool response missing".into());
    }
    let SessionOperation::ToolCall(tool_call) = operation else {
        return Err("tool operation missing".into());
    };
    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".into(),
            content: serde_json::json!({"text": "unused"}),
            model: "unused".into(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    match entry {
        EntryPoint::Session => Err("unexpected session entry".into()),
        EntryPoint::NestedSync => Ok(fixture
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                context,
                &tool_call,
                &mut client,
            )?),
        EntryPoint::NestedAsync => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            Ok(runtime.block_on(
                fixture
                    .kernel
                    .evaluate_tool_call_operation_with_nested_flow_client_async(
                        context,
                        &tool_call,
                        &mut client,
                    ),
            )?)
        }
    }
}

fn pending_session_using(
    fixture: &Fixture,
    entry: EntryPoint,
) -> TestResult<(OperationContext, ThresholdApprovalProposal)> {
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
    let response = evaluate(fixture, &context, entry)?;
    assert_eq!(
        response.verdict,
        Verdict::PendingApproval,
        "{:?}",
        response.reason
    );
    let Some(ToolCallOutput::Value(value)) = response.output else {
        return Err("pending proposal missing".into());
    };
    assert_pending_session(fixture, &context)?;
    Ok((context, serde_json::from_value(value)?))
}

fn assert_pending_session(fixture: &Fixture, context: &OperationContext) -> TestResult {
    let session = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    let pending = session
        .inflight()
        .get(&context.request_id)
        .ok_or("pending request missing")?;
    assert!(pending.pending_threshold_approval.is_some());
    assert!(pending.pending_execution_nonce_id.is_none());
    assert!(session.terminal().get(&context.request_id).is_none());
    assert!(session
        .request_lineage(&context.request_id)
        .ok_or("lineage missing")?
        .terminal_state
        .is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn assert_approved(fixture: &Fixture, context: &OperationContext) -> TestResult {
    let response = session_tool_call(
        fixture
            .kernel
            .evaluate_session_operation(context, &operation(&fixture.request))?,
    )
    .ok_or("approved response missing")?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let session = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Completed)
    );
    assert_eq!(
        session
            .request_lineage(&context.request_id)
            .ok_or("lineage missing")?
            .terminal_state,
        Some(OperationTerminalState::Completed)
    );
    Ok(())
}

#[test]
fn approved_session_retry_resumes_original_threshold_request() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    assert_approved(&fixture, &context)?;
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request)),
        Err(KernelError::Session(
            crate::session::SessionError::DuplicateRequestLineage { .. }
        ))
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn altered_session_operation_cannot_consume_threshold_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    for field in [
        "capability",
        "server",
        "tool",
        "arguments",
        "intent",
        "metadata",
    ] {
        let SessionOperation::ToolCall(mut changed) = operation(&fixture.request) else {
            return Err("tool operation missing".into());
        };
        match field {
            "capability" => changed.capability.id.push_str("-changed"),
            "server" => changed.server_id.push_str("-changed"),
            "tool" => changed.tool_name.push_str("-changed"),
            "arguments" => changed.arguments = serde_json::json!({"record": "other"}),
            "intent" => changed.governed_intent = None,
            "metadata" => changed.extra_metadata = Some(serde_json::json!({"different": true})),
            _ => return Err("unexpected mutation".into()),
        }
        assert!(
            matches!(
                fixture
                    .kernel
                    .evaluate_session_operation(&context, &SessionOperation::ToolCall(changed)),
                Err(KernelError::Session(
                    crate::session::SessionError::ThresholdApprovalRetryMismatch { .. }
                ))
            ),
            "{field}"
        );
        assert_pending_session(&fixture, &context)?;
    }
    assert_approved(&fixture, &context)
}

#[test]
fn replacement_signed_proposal_cannot_take_over_session_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    let mut body = proposal.body.clone();
    body.proposal_id.push_str("-replacement");
    let replacement = ThresholdApprovalProposal::sign(body, &fixture.kernel.config.keypair)?;
    assert!(replacement.verify_signature()?);
    fixture.approve(replacement)?;
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request)),
        Err(KernelError::Session(
            crate::session::SessionError::ThresholdApprovalRetryMismatch { .. }
        ))
    ));
    assert_pending_session(&fixture, &context)?;
    fixture.approve(proposal)?;
    assert_approved(&fixture, &context)
}

#[test]
fn missing_proposal_cannot_restart_pending_session_request() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request)),
        Err(KernelError::Session(
            crate::session::SessionError::ThresholdApprovalRetryMismatch { .. }
        ))
    ));
    assert_pending_session(&fixture, &context)?;
    fixture.approve(proposal)?;
    assert_approved(&fixture, &context)
}

#[test]
fn changed_session_lineage_cannot_consume_threshold_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    let mut contexts = [context.clone(), context.clone(), context.clone()];
    contexts[0].agent_id.push_str("-changed");
    contexts[1].parent_request_id = Some(RequestId::new("different-parent"));
    contexts[2].progress_token = Some(chio_core::session::ProgressToken::String(
        "different-progress".into(),
    ));
    for changed in contexts {
        assert!(matches!(
            fixture
                .kernel
                .evaluate_session_operation(&changed, &operation(&fixture.request)),
            Err(KernelError::Session(_))
        ));
        assert_pending_session(&fixture, &context)?;
    }
    assert_approved(&fixture, &context)
}

#[test]
fn rotated_session_authentication_cannot_resume_threshold_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    fixture.kernel.set_session_auth_context(
        &context.session_id,
        SessionAuthContext::streamable_http_static_bearer(
            "rotated-principal",
            "rotated-fingerprint",
            None,
        ),
    )?;
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request)),
        Err(KernelError::Session(
            crate::session::SessionError::ThresholdApprovalRetryMismatch { .. }
        ))
    ));
    assert_pending_session(&fixture, &context)
}

#[test]
fn cancelled_session_cannot_resume_threshold_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    fixture
        .kernel
        .request_session_cancellation(&context.session_id, &context.request_id)?;
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request)),
        Err(KernelError::Session(
            crate::session::SessionError::ThresholdApprovalRetryMismatch { .. }
        ))
    ));
    assert_pending_session(&fixture, &context)
}

#[test]
fn draining_session_cannot_resume_threshold_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    fixture.kernel.begin_draining_session(&context.session_id)?;
    assert!(matches!(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request)),
        Err(KernelError::Session(
            crate::session::SessionError::OperationNotAllowed { .. }
        ))
    ));
    assert_pending_session(&fixture, &context)
}

#[test]
fn resumed_session_revalidates_revoked_capability() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    fixture
        .kernel
        .revoke_capability(&fixture.request.capability.id)?;
    let response = session_tool_call(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request))?,
    )
    .ok_or("denial response missing")?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn resumed_session_revalidates_current_threshold_policy() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal.clone())?;
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(
            |_: &str, _: &str, _: &str| -> Result<Option<ThresholdApprovalRequirement>, String> {
                Ok(None)
            },
        ));
    let response = session_tool_call(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request))?,
    )
    .ok_or("denial response missing")?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    fixture.assert_pending_unchanged(&proposal)
}

#[test]
fn resumed_session_revalidates_approval_votes() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    fixture.request.approval_tokens[0]
        .request_id
        .push_str("-changed");
    let response = session_tool_call(
        fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request))?,
    )
    .ok_or("denial response missing")?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

fn nested_round_trip(entry: EntryPoint) -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session_using(&fixture, entry)?;
    fixture.approve(proposal)?;
    let response = evaluate(&fixture, &context, entry)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let session = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Completed)
    );
    Ok(())
}

#[test]
fn nested_sync_session_resumes_threshold_request() -> TestResult {
    nested_round_trip(EntryPoint::NestedSync)
}

#[test]
fn nested_async_session_resumes_threshold_request() -> TestResult {
    nested_round_trip(EntryPoint::NestedAsync)
}

#[test]
fn threshold_session_rejects_unsupported_durable_nonce_profile() -> TestResult {
    let mut fixture = Fixture::new()?;
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 64,
        require_nonce: true,
    };
    fixture.kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );
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
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| reason
        .contains("durable execution nonces require an atomic admission participant")));
    assert!(response.execution_nonce.is_none());
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let session = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Completed)
    );
    Ok(())
}

#[test]
fn concurrent_threshold_retry_cannot_claim_same_session_wait() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    let resolver = fixture
        .kernel
        .threshold_approval_requirement_resolver
        .clone()
        .ok_or("policy resolver missing")?;
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    let first = std::sync::atomic::AtomicBool::new(true);
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(
            move |policy: &str, server: &str, tool: &str| {
                if first.swap(false, Ordering::SeqCst) {
                    entered_tx
                        .send(())
                        .map_err(|_| "test entry signal unavailable".to_string())?;
                    release_rx
                        .lock()
                        .map_err(|_| "test release lock poisoned".to_string())?
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .map_err(|_| "test release timed out".to_string())?;
                }
                resolver.resolve_requirement(policy, server, tool)
            },
        ));
    std::thread::scope(|scope| -> TestResult {
        let first_retry = scope.spawn(|| {
            fixture
                .kernel
                .evaluate_session_operation(&context, &operation(&fixture.request))
        });
        entered_rx.recv_timeout(std::time::Duration::from_secs(5))?;
        let competing = fixture
            .kernel
            .evaluate_session_operation(&context, &operation(&fixture.request));
        release_tx.send(())?;
        let response = session_tool_call(first_retry.join().map_err(|_| "retry thread panicked")??)
            .ok_or("first retry response missing")?;
        assert!(matches!(
            competing,
            Err(KernelError::Session(
                crate::session::SessionError::DuplicateInflightRequest { .. }
            ))
        ));
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
        Ok(())
    })
}
