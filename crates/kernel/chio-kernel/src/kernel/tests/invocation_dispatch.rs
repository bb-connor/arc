use super::*;

fn durable_context(request: &ToolCallRequest) -> crate::ToolDispatchContext {
    crate::ToolDispatchContext::new(
        request.request_id.clone(),
        chio_core_types::provider_attempt::ProviderAttemptBindingV1 {
            operation_id: "a".repeat(64),
            attempt_id: "retained-attempt".into(),
            transport_id: "native".into(),
            transport_key_epoch: 1,
        },
    )
}

struct DispatchProbe {
    seen: Arc<Mutex<Vec<(String, crate::ToolDispatchContext)>>>,
    stream: bool,
}

impl DispatchProbe {
    fn observe(&self, route: &str, context: &crate::ToolDispatchContext) {
        self.seen
            .lock()
            .unwrap()
            .push((route.into(), context.clone()));
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for DispatchProbe {
    fn server_id(&self) -> &str {
        "caller-context"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["work".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal("dispatch identity was lost".into()))
    }
    async fn invoke_in_context(
        &self,
        context: &crate::ToolDispatchContext,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.observe("value", context);
        Ok(serde_json::json!({"done": true}))
    }
    async fn invoke_with_cost_in_context(
        &self,
        context: &crate::ToolDispatchContext,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        self.observe("cost", context);
        Ok((
            serde_json::json!({"done": true}),
            Some(ToolInvocationCost {
                units: 3,
                currency: "USD".into(),
                breakdown: None,
            }),
        ))
    }
    async fn invoke_stream_in_context(
        &self,
        context: &crate::ToolDispatchContext,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.observe("stream", context);
        Ok(self
            .stream
            .then(|| ToolServerStreamResult::Complete(ToolCallStream { chunks: vec![] })))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invocation_and_dispatch_identities_survive_every_resolved_delivery_route() {
    for budget in [0, 1000] {
        let mut config = make_config();
        config.deadlines.dispatch_budget_ms = budget;
        let kernel = make_kernel(config);
        let agent = make_keypair();
        let cap = make_capability(
            &kernel,
            &agent,
            make_scope(vec![make_grant("caller-context", "work")]),
            300,
        );
        let mut request = make_request("context-both", &cap, "work", "caller-context");
        request.arguments = serde_json::json!({"chioCallerCapabilitySha256": "forged"});
        let dispatch = durable_context(&request);
        assert_eq!(dispatch.caller_capability_sha256(), None);
        let expected =
            dispatch
                .clone()
                .bind_caller_capability(chio_core_types::crypto::sha256_hex(
                    &chio_core_types::crypto::canonical_json_bytes(&cap).unwrap(),
                ));
        for (stream, monetary) in [(false, false), (false, true), (true, false)] {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let server = Arc::new(CallerContextProbe {
                observations: seen.clone(),
                stream,
            });
            kernel
                .dispatch_resolved_server_within_budget(
                    server,
                    &request,
                    monetary,
                    Some(dispatch.clone()),
                )
                .await
                .unwrap();
            for (_, context, _) in seen.lock().unwrap().iter() {
                assert_eq!(context.capability_id(), cap.id);
                assert_eq!(context.subject_key(), agent.public_key().to_hex());
                assert_eq!(context.dispatch(), Some(&expected));
            }
            assert_eq!(seen.lock().unwrap().len(), if stream { 1 } else { 2 });

            // Existing dispatch-aware transports receive the same identity
            // through the default caller-context adapter, including cost and stream.
            let seen = Arc::new(Mutex::new(Vec::new()));
            let server = Arc::new(DispatchProbe {
                seen: seen.clone(),
                stream,
            });
            let (_, cost) = kernel
                .dispatch_resolved_server_within_budget(
                    server,
                    &request,
                    monetary,
                    Some(dispatch.clone()),
                )
                .await
                .unwrap();
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), if stream { 1 } else { 2 });
            for (_, context) in seen.iter() {
                assert_eq!(context, &expected);
            }
            assert_eq!(seen[0].0, "stream");
            if !stream {
                assert_eq!(seen[1].0, if monetary { "cost" } else { "value" });
            }
            if monetary {
                assert_eq!(cost.unwrap().units, 3);
            }
        }
    }
}

struct BlockingDispatchProbe(Arc<Mutex<Vec<crate::ToolDispatchContext>>>);

impl crate::BlockingToolServerConnection for BlockingDispatchProbe {
    fn server_id(&self) -> &str {
        "caller-context"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["work".into()]
    }
    fn invoke_blocking(
        &self,
        _: &str,
        _: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "blocking dispatch identity was lost".into(),
        ))
    }
    fn invoke_blocking_in_context(
        &self,
        context: &crate::ToolDispatchContext,
        _: &str,
        _: serde_json::Value,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.lock().unwrap().push(context.clone());
        Ok(serde_json::json!({"done": true}))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_cost_delivery_preserves_the_durable_idempotency_key() {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("caller-context", "work")]),
        300,
    );
    let request = make_request("blocking-context", &cap, "work", "caller-context");
    let dispatch = durable_context(&request);
    assert_eq!(dispatch.caller_capability_sha256(), None);
    let expected = dispatch
        .clone()
        .bind_caller_capability(chio_core_types::crypto::sha256_hex(
            &chio_core_types::crypto::canonical_json_bytes(&cap).unwrap(),
        ));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let server =
        crate::BlockingToolServerAdapter::new(Arc::new(BlockingDispatchProbe(seen.clone())))
            .unwrap();
    let (_, cost) = kernel
        .dispatch_resolved_server_within_budget(
            Arc::new(server),
            &request,
            true,
            Some(dispatch.clone()),
        )
        .await
        .unwrap();
    assert!(cost.is_none());
    assert_eq!(*seen.lock().unwrap(), vec![expected]);
}
