struct SessionSecurityContextAuthority;

impl SecurityInvocationContextAuthority for SessionSecurityContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        Ok(SecurityInvocationContext::v1(
            SecurityInvocationContextV1::new(
                chio_security_types::ports::TenantId::new("tenant-session-test").unwrap(),
                chio_security_types::ports::SessionId::new(context.session_id.as_str()).unwrap(),
                chio_security_types::PrincipalId::new(context.agent_id.as_str()).unwrap(),
                chio_security_types::ports::IsolationEpochId::new("isolation-session-test")
                    .unwrap(),
                chio_security_types::ports::LineageId::new(operation.capability.id.as_str())
                    .unwrap(),
                1,
            ),
        ))
    }
}

struct RejectingSessionSecurityPreDispatch;

impl SecurityPreDispatchHook for RejectingSessionSecurityPreDispatch {
    fn name(&self) -> &str {
        "rejecting-session-security-pre-dispatch"
    }

    fn commit(
        &self,
        _context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::GuardDenied(
            "session security fence rejected".to_string(),
        ))
    }
}

#[test]
fn session_tool_call_uses_context_authority_and_final_security_fence() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    kernel.set_security_invocation_context_authority(Arc::new(SessionSecurityContextAuthority));
    kernel.set_security_pre_dispatch_hook(Arc::new(RejectingSessionSecurityPreDispatch));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "req-session-security-fence",
        &agent_kp.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    }));

    let response = session_tool_call(
        kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap(),
    )
    .expect("expected signed tool-call denial");

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("security pre-dispatch hook rejected dispatch")
    );
}
