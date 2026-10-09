use super::*;

#[test]
fn non_durable_monetary_kernel_denies_before_ambiguous_dispatch() {
    // A non-durable monetary kernel must reverse the provisional budget hold and
    // deny before dispatch. It therefore cannot reach RequestIncomplete or add
    // an unrecoverable retained-hold sample.
    let mut kernel =
        ChioKernel::new_with_clock(make_monetary_config(), chio_test_support::clock::clock());
    assert!(kernel.durable_admission_runtime.is_none());
    kernel.register_tool_server(Box::new(IncompleteServer {
        id: "broken".to_string(),
    }));
    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("broken", "drop_stream", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let before = ambiguous_retained_hold_none_sample();
    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-ambiguous-incomplete".to_string(),
            capability: cap,
            tool_name: "drop_stream".to_string(),
            server_id: "broken".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        })
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("requires durable admission coverage")),
        "the denial must identify the missing financial durability boundary: {:?}",
        response.reason
    );

    let after = ambiguous_retained_hold_none_sample();
    assert_eq!(
        after, before,
        "pre-dispatch denial must not record an ambiguous retained hold"
    );
    let usage = kernel
        .budget_store
        .get_usage(&response.receipt.capability_id, 0)
        .unwrap()
        .expect("the reversible mutation history retains a zeroed usage projection");
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 0);
}

/// Fails the next authority clock read after the tool server has run.
struct ClockOutageAfterDispatch {
    inner: Arc<dyn chio_security_types::clock::Clock>,
    unavailable: Arc<AtomicBool>,
}

impl chio_security_types::clock::Clock for ClockOutageAfterDispatch {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        if self.unavailable.swap(false, Ordering::SeqCst) {
            Err(chio_security_types::clock::ClockError::Unavailable)
        } else {
            self.inner.read()
        }
    }
}

struct ClockOutageServer {
    unavailable: Arc<AtomicBool>,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for ClockOutageServer {
    fn server_id(&self) -> &str {
        "cost-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.unavailable.store(true, Ordering::SeqCst);
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((
            value,
            Some(ToolInvocationCost {
                units: 75,
                currency: "USD".to_string(),
                breakdown: None,
            }),
        ))
    }
}

#[test]
fn non_durable_tool_keeps_its_signed_receipt_when_the_post_dispatch_clock_sample_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let mut kernel = make_kernel(make_monetary_config());
        assert!(kernel.durable_admission_runtime.is_none());
        let unavailable = Arc::new(AtomicBool::new(false));
        kernel.clock = Arc::new(ClockOutageAfterDispatch {
            inner: chio_test_support::clock::clock(),
            unavailable: unavailable.clone(),
        });
        let invocations = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(ClockOutageServer {
            unavailable,
            invocations: invocations.clone(),
        }));
        let agent_kp = Keypair::generate();
        let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
        let request = make_request("req-post-dispatch-clock", &cap, "compute", "cost-srv");
        let response = if nested {
            let session = kernel.open_session(request.agent_id.clone(), Vec::new())?;
            kernel.activate_session(&session)?;
            let parent =
                make_operation_context(&session, "post-dispatch-clock-parent", &request.agent_id);
            kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
            kernel.evaluate_tool_call_with_nested_flow_client(
                &parent,
                &request,
                &mut NoopNestedFlowClient,
                None,
            )
        } else {
            kernel.evaluate_tool_call_blocking(&request)
        };
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        let response = response?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.receipt.verify_signature()?);
        let financial = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .ok_or("financial receipt metadata")?;
        assert_eq!(financial["cost_charged"].as_u64(), Some(75));
        let usage = kernel
            .budget_store
            .get_usage(&cap.id, 0)?
            .ok_or("budget usage")?;
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.committed_cost_units()?, 75);
    }
    Ok(())
}
