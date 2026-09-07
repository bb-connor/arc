struct CallerContextProbe {
    observations: std::sync::Arc<Mutex<Vec<(String, crate::ToolInvocationContext, bool)>>>,
    stream: bool,
}

impl CallerContextProbe {
    fn observe(
        &self,
        route: &str,
        context: &crate::ToolInvocationContext,
        nested: bool,
    ) -> Result<(), KernelError> {
        self.observations
            .lock()
            .map_err(|_| KernelError::Internal("probe poisoned".to_owned()))?
            .push((route.to_owned(), context.clone(), nested));
        Ok(())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CallerContextProbe {
    fn server_id(&self) -> &str {
        "caller-context"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["work".to_owned(), "forbidden".to_owned()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolServerError(
            "native invocation requires caller context".to_owned(),
        ))
    }
    async fn invoke_with_context(
        &self,
        context: &crate::ToolInvocationContext,
        _: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.observe("value", context, bridge.is_some())?;
        Ok(serde_json::json!({"done": true}))
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &crate::ToolInvocationContext,
        _: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        self.observe("cost", context, bridge.is_some())?;
        Ok((
            serde_json::json!({"done": true}),
            Some(ToolInvocationCost {
                units: 3,
                currency: "USD".to_owned(),
                breakdown: None,
            }),
        ))
    }
    async fn invoke_stream_with_context(
        &self,
        context: &crate::ToolInvocationContext,
        _: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.observe("stream", context, bridge.is_some())?;
        Ok(self.stream.then(|| {
            ToolServerStreamResult::Complete(ToolCallStream {
                chunks: vec![ToolCallChunk {
                    data: serde_json::json!({"done": true}),
                }],
            })
        }))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invocation_context_binds_capability_and_route_on_value_cost_and_stream_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    for stream in [false, true] {
        let mut config = make_config();
        config.deadlines.dispatch_budget_ms = 1000;
        let mut kernel = make_kernel(config);
        let observations = std::sync::Arc::new(Mutex::new(Vec::new()));
        kernel.register_tool_server(Box::new(CallerContextProbe {
            observations: observations.clone(),
            stream,
        }));
        let agent = make_keypair();
        let cap = make_capability(
            &kernel,
            &agent,
            make_scope(vec![make_grant("caller-context", "work")]),
            300,
        );
        let request = make_request_with_arguments(
            "context-call",
            &cap,
            "work",
            "caller-context",
            serde_json::json!({
                "parent_id": "someone-else", "capability_id": "forged", "subject_key": "forged", "request_id": "forged",
            }),
        );
        let response = kernel.evaluate_tool_call(&request).await?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        let expected_hash = chio_core_types::crypto::sha256_hex(
            &chio_core_types::crypto::canonical_json_bytes(&cap)?,
        );
        {
            let seen = observations.lock().map_err(|_| "probe poisoned")?;
            assert_eq!(seen.len(), if stream { 1 } else { 2 });
            for (_, context, nested) in seen.iter() {
                assert_eq!(context.request_id(), request.request_id);
                assert_eq!(context.server_id(), "caller-context");
                assert_eq!(context.tool_name(), "work");
                assert_eq!(context.capability_id(), cap.id);
                assert_eq!(context.subject_key(), agent.public_key().to_hex());
                assert_eq!(context.capability_hash(), expected_hash);
                assert!(!nested);
            }
        }
        let before = observations.lock().map_err(|_| "probe poisoned")?.len();
        let denied = kernel
            .evaluate_tool_call(&make_request(
                "context-denied",
                &cap,
                "forbidden",
                "caller-context",
            ))
            .await?;
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(
            observations.lock().map_err(|_| "probe poisoned")?.len(),
            before
        );

        // Exercise the resolved connector's monetary branch directly; the
        // existing budget suite independently checks admission and settlement.
        if !stream {
            let server = std::sync::Arc::new(CallerContextProbe {
                observations: observations.clone(),
                stream: false,
            });
            let (_, cost) = kernel
                .dispatch_resolved_server_within_budget(server, &request, true)
                .await?;
            assert_eq!(cost.ok_or("missing cost")?.units, 3);
            assert_eq!(
                observations
                    .lock()
                    .map_err(|_| "probe poisoned")?
                    .last()
                    .ok_or("missing observation")?
                    .0,
                "cost"
            );
        }
    }
    Ok(())
}

#[test]
fn invocation_context_reaches_nested_flow_dispatch_without_a_wire_capability(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let observations = std::sync::Arc::new(Mutex::new(Vec::new()));
    kernel.register_tool_server(Box::new(CallerContextProbe {
        observations: observations.clone(),
        stream: false,
    }));
    let agent = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("caller-context", "work")]),
        300,
    );
    let session = kernel.open_session(agent.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session)?;
    let context = make_operation_context(&session, "nested-context", &agent.public_key().to_hex());
    let operation = ToolCallOperation {
        capability: cap.clone(),
        server_id: "caller-context".to_owned(),
        tool_name: "work".to_owned(),
        arguments: serde_json::json!({"parent_id":"forged"}),
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    let response = kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut NoopNestedFlowClient,
    )?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let seen = observations.lock().map_err(|_| "probe poisoned")?;
    assert_eq!(seen.len(), 2);
    for (_, binding, nested) in seen.iter() {
        assert!(*nested);
        assert_eq!(binding.request_id(), "nested-context");
        assert_eq!(binding.capability_id(), cap.id);
        assert_eq!(binding.subject_key(), agent.public_key().to_hex());
    }
    Ok(())
}
