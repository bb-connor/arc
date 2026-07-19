// Chio runtime admission hook tests.
//
// These cover the generic pre-dispatch hook that Chio 7.0 uses to deny
// cross-vendor workflow steps before tool execution or federation side effects.

struct DenyingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct AllowingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct MetadataInspectingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct LiveReceiptAllowingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct ReleaseTrackingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
    expected_request_id: &'static str,
    admission_id: &'static str,
    lease_id: &'static str,
    continuation_id: Option<&'static str>,
}

struct FailingReleaseRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
    expected_request_id: &'static str,
    admission_id: &'static str,
    lease_id: &'static str,
}

struct FailingAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    invocations: std::sync::Arc<AtomicU64>,
}

struct UrlElicitationBeforeSideEffectServer {
    id: String,
    tools: Vec<String>,
    stream_attempts: std::sync::Arc<AtomicU64>,
}

struct CancellationAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

struct IncompleteAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

// A registered tool server whose dispatch succeeds but returns a
// successful-yet-incomplete stream (e.g. stream-limit truncation). Unlike
// `IncompleteAfterSideEffectServer` (which returns `Err(RequestIncomplete)`
// and lands in the RequestIncomplete error arm), this drives the
// `Ok(ToolServerStreamResult::Incomplete)` finalize path, where the
// runtime-admission lease is still consumed after the side effect.
struct IncompleteStreamAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

// A registered server whose connector returns ToolNotRegistered after entry.
struct ToolNotRegisteredDispatchServer {
    id: String,
    tools: Vec<String>,
    stream_attempts: std::sync::Arc<AtomicU64>,
}

struct NoopNestedFlowClient;

impl RuntimeAdmissionHook for DenyingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, "req-chio-runtime-deny");
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::deny(
            "chio runtime admission denied",
            Some(serde_json::json!({
                "chio_runtime": {
                    "admission_id": "adm-denied",
                    "accepted": false,
                    "failure_code": "test_runtime_deny"
                }
            })),
        ))
    }
}

impl RuntimeAdmissionHook for AllowingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, "req-chio-runtime-allow");
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": "adm-allowed",
                "accepted": true,
                "failure_code": null,
                "observe_only": true
            }
        }))))
    }
}

impl RuntimeAdmissionHook for MetadataInspectingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-metadata-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let bridge = context
            .extra_metadata
            .and_then(|metadata| metadata.get("route"))
            .and_then(|route| route.get("bridge"))
            .and_then(serde_json::Value::as_str);
        if bridge == Some("mcp") {
            Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
                "chio_runtime": {
                    "admission_id": "adm-route-metadata",
                    "accepted": true,
                    "failure_code": null
                }
            }))))
        } else {
            Ok(RuntimeAdmissionDecision::deny(
                "route metadata missing from runtime admission context",
                Some(serde_json::json!({
                    "chio_runtime": {
                        "admission_id": "adm-route-metadata",
                        "accepted": false,
                        "failure_code": "route_metadata_missing"
                    }
                })),
            ))
        }
    }
}

impl RuntimeAdmissionHook for LiveReceiptAllowingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-live-receipt-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(context.matched_grant_index.is_some());
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": context.request.request_id,
                "accepted": true,
                "failure_code": null,
                "live_receipt_capture": true
            }
        }))))
    }
}

impl RuntimeAdmissionHook for ReleaseTrackingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-release-tracking-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, self.expected_request_id);
        assert_eq!(context.matched_grant_index, Some(0));
        let mut metadata = serde_json::json!({
            "chio_runtime": {
                "admission_id": self.admission_id,
                "accepted": true,
                "reserved_destructive_lease_id": self.lease_id,
                "failure_code": null
            }
        });
        if let Some(continuation_id) = self.continuation_id {
            metadata["chio_runtime"]["reserved_treaty_continuation_id"] =
                serde_json::json!(continuation_id);
        }
        Ok(RuntimeAdmissionDecision::allow(Some(metadata)))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            self.lease_id
        );
        if let Some(continuation_id) = self.continuation_id {
            assert_eq!(
                metadata["chio_runtime"]["reserved_treaty_continuation_id"],
                continuation_id
            );
        }
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl RuntimeAdmissionHook for FailingReleaseRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chio-failing-release-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, self.expected_request_id);
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": self.admission_id,
                "accepted": true,
                "reserved_destructive_lease_id": self.lease_id,
                "failure_code": null
            }
        }))))
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            self.lease_id
        );
        self.releases.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal(
            "runtime reservation release failed".to_string(),
        ))
    }
}

impl NestedFlowClient for NoopNestedFlowClient {
    fn list_roots(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Ok(Vec::new())
    }

    fn create_message(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested createMessage request".to_string(),
        ))
    }

    fn create_elicitation(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested elicitation request".to_string(),
        ))
    }

    fn notify_elicitation_completed(
        &mut self,
        _parent_context: &OperationContext,
        _elicitation_id: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn notify_resource_updated(
        &mut self,
        _parent_context: &OperationContext,
        _uri: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn notify_resources_list_changed(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        Ok(())
    }
}

impl FailingAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, invocations: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            invocations,
        }
    }
}

impl UrlElicitationBeforeSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, stream_attempts: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            stream_attempts,
        }
    }
}

impl CancellationAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

impl IncompleteAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FailingAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::Internal(
            "destructive side effect committed before transport failure".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for UrlElicitationBeforeSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.stream_attempts.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation required before dispatch side effect".to_string(),
            elicitations: Vec::new(),
        })
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after URL elicitation".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for CancellationAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::RequestCancelled {
            request_id: "req-chio-runtime-cancelled".to_string().into(),
            reason: "cancelled after possible dispatch side effect".to_string(),
        })
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after cancellation".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::RequestIncomplete(
            "incomplete after possible dispatch side effect".to_string(),
        ))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after incomplete request".to_string(),
        ))
    }
}

impl IncompleteStreamAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteStreamAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        // The destructive side effect committed, then the stream was
        // truncated. Dispatch returns Ok(Incomplete), so finalization (not
        // the RequestIncomplete error arm) builds the incomplete receipt.
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Ok(Some(ToolServerStreamResult::Incomplete {
            stream: ToolCallStream {
                chunks: vec![ToolCallChunk {
                    data: serde_json::json!({"partial": "vendor-ledger-7"}),
                }],
            },
            reason: "stream truncated after possible dispatch side effect".to_string(),
        }))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected non-stream invoke on incomplete-stream server".to_string(),
        ))
    }
}

impl ToolNotRegisteredDispatchServer {
    fn new(id: &str, tools: Vec<&str>, stream_attempts: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            stream_attempts,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for ToolNotRegisteredDispatchServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke_stream(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        self.stream_attempts.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::ToolNotRegistered(format!(
            "tool \"{tool_name}\" withdrawn from server roster before dispatch"
        )))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "unexpected invoke after tool-not-registered dispatch error".to_string(),
        ))
    }
}

// A registered tool server whose dispatch SUCCEEDS (returns Ok(Value)) after
// committing a destructive side effect. Used to exercise the post-invocation
// Block deny path: the tool has already run and its runtime-admission lease is
// retained (not released) when a POST-invocation output guard blocks the
// returned value.
struct SucceedingAfterSideEffectServer {
    id: String,
    tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

impl SucceedingAfterSideEffectServer {
    fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for SucceedingAfterSideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        // The destructive side effect commits, then the tool returns a
        // successful value. A post-invocation output guard blocks this value
        // AFTER the fact, but the side effect is already durable.
        self.side_effects.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"record": "vendor-ledger-7", "status": "closed"}))
    }
}

// A post-invocation output guard that always blocks the returned value.
// Simulates an output guard that denies a tool response AFTER the tool has
// already executed (and committed a side effect).
struct BlockingPostInvocationHook;

impl crate::post_invocation::PostInvocationHook for BlockingPostInvocationHook {
    fn name(&self) -> &str {
        "test-post-invocation-block"
    }

    fn inspect(
        &self,
        _ctx: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Block(
            "post-invocation output guard blocked destructive tool output".to_string(),
        )
    }
}

fn assert_package_valid_allow_receipt(
    response: &ToolCallResponse,
    request: &ToolCallRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.receipt.is_allowed());
    assert_eq!(response.receipt.capability_id, request.capability.id);
    assert_eq!(response.receipt.tool_server, request.server_id);
    assert_eq!(response.receipt.tool_name, request.tool_name);
    assert!(
        response.receipt.verify_signature()?,
        "response receipt signature must verify"
    );

    let package = serde_json::to_vec(&response.receipt)?;
    let unpacked: ChioReceipt = serde_json::from_slice(&package)?;
    assert_eq!(unpacked.id, response.receipt.id);
    assert!(
        unpacked.verify_signature()?,
        "serialized receipt package must verify"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_denies_before_tool_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("chio runtime admission denied")
    );
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-denied");
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "test_runtime_deny"
    );
    Ok(())
}

#[test]
fn chio_governed_request_without_runtime_hook_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-runtime-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: "intent:chio:no-hook".to_string(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: "verify Chio admission fails closed without a hook".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioAdmission": {
                    "admissionId": "adm-no-hook",
                    "bundleSha256": "a".repeat(64)
                }
            })),
        },
    ));

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_treaty_request_without_runtime_hook_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-treaty-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: "intent:chio:treaty-no-hook".to_string(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: "verify Chio treaty context fails closed without a hook".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioTreaty": {
                    "treatyScopeId": "treaty-buyer-vendor",
                    "treatyScopeSha256": "b".repeat(64),
                    "ladderIntersectionId": "intersection-live-1",
                    "ladderIntersectionSha256": "c".repeat(64),
                    "actionClassId": "workflow.destructive.vendor_call"
                }
            })),
        },
    ));

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_denies_federated_call_before_dispatch_or_cosign(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.chio-buyer";
    let tool_host_kernel_id = "kernel.chio-vendor";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("chio-runtime-deny-no-cosign");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())?;
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);

    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        response.reason.as_deref(),
        Some("chio runtime admission denied")
    );
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        cosigner_calls.load(Ordering::SeqCst),
        0,
        "runtime admission denial must not request federation cosign"
    );
    assert!(
        response.receipt.verify_signature()?,
        "deny response receipt signature must verify"
    );
    assert!(response.receipt.is_denied());
    assert_eq!(kernel.receipt_log().len(), 1);
    assert_eq!(kernel.receipt_log().receipts()[0].id, response.receipt.id);
    Ok(())
}

#[test]
fn federated_origin_without_runtime_hook_or_context_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.chio-buyer";
    let tool_host_kernel_id = "kernel.chio-vendor";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federated-no-hook-no-context");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?))?;

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())?;
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let kernel = kernel.with_federation_peers(vec![peer]);

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-federated-no-hook-no-context",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "missing_chio_treaty_context"
    );
    Ok(())
}

#[test]
fn chio_swarm_request_without_runtime_hook_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chio-swarm-no-hook",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.governed_intent = Some(GovernedTransactionIntent::tool_invocation(
        chio_core::capability::governance::GovernedToolInvocationIntentBody {
            id: "intent:chio:swarm-no-hook".to_string(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: "verify swarm authority fails closed without a runtime hook".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioSwarm": {
                    "taskGraph": {
                        "id": "swarm-task-graph-runtime",
                        "sha256": "a".repeat(64)
                    },
                    "continuationToken": {
                        "id": "swarm-continuation-runtime",
                        "sha256": "b".repeat(64)
                    }
                }
            })),
        },
    ));

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn session_tool_call_preserves_chio_swarm_runtime_context() -> Result<(), Box<dyn std::error::Error>>
{
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-swarm-session-no-hook",
        &agent_kp.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: cap,
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: Some(GovernedTransactionIntent::tool_invocation(
            chio_core::capability::governance::GovernedToolInvocationIntentBody {
                id: "intent:chio:swarm-session-no-hook".to_string(),
                server_id: "srv-chio-runtime".to_string(),
                tool_name: "destructive_update".to_string(),
                purpose: "verify session swarm authority fails closed without a runtime hook"
                    .to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    "chioSwarm": {
                        "taskGraph": {
                            "id": "swarm-task-graph-runtime",
                            "sha256": "a".repeat(64)
                        },
                        "continuationToken": {
                            "id": "swarm-continuation-runtime",
                            "sha256": "b".repeat(64)
                        }
                    }
                })),
            },
        )),
        supplemental_authorization: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
        declassification_grant: None,
    }));

    let response = session_tool_call(kernel.evaluate_session_operation(&context, &operation)?)
        .ok_or_else(|| std::io::Error::other("tool call response missing"))?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_admission_hook_missing"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_allows_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(AllowingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-allow",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let output = tool_call_value_output(response.output)
        .ok_or_else(|| std::io::Error::other("tool output missing"))?;
    assert_eq!(output["tool"], "destructive_update");
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("allow metadata missing"))?;
    assert_eq!(metadata["chio_runtime"]["admission_id"], "adm-allowed");
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert_eq!(metadata["chio_runtime"]["observe_only"], true);
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_receives_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        MetadataInspectingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-route-metadata",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    let metadata = serde_json::json!({
        "route": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-a"
        }
    });

    let response = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(metadata))?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn chio_runtime_admission_hook_receives_nested_flow_route_metadata_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        MetadataInspectingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-chio-runtime-nested-route-metadata",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: cap,
        server_id: "srv-chio-runtime".to_string(),
        tool_name: "destructive_update".to_string(),
        arguments: serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
        governed_intent: None,
        supplemental_authorization: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: Some(serde_json::json!({
            "route": {
                "bridge": "mcp",
                "protocolTarget": "mcp://provider-a"
            }
        })),
        declassification_grant: None,
    };
    let mut client = NoopNestedFlowClient;

    let response = kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    )?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| "allow metadata missing".to_string())?;
    assert_eq!(metadata["route"]["bridge"], "mcp");
    assert_eq!(metadata["route"]["protocolTarget"], "mcp://provider-a");
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-route-metadata"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_does_not_release_destructive_lease_after_dispatch_failure(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(FailingAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-dispatch-error",
        admission_id: "adm-dispatch-error",
        lease_id: "lease-dispatch-error",
        continuation_id: None,
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-dispatch-error",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "destructive runtime leases must remain consumed after tool dispatch starts"
    );
    assert_eq!(
        response.reason.as_deref(),
        Some("internal error: destructive side effect committed before transport failure")
    );
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(
        metadata["chio_runtime"]["admission_id"],
        "adm-dispatch-error"
    );
    assert_eq!(metadata["chio_runtime"]["accepted"], true);
    assert_eq!(
        metadata["chio_runtime"]["reserved_destructive_lease_id"],
        "lease-dispatch-error"
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_retains_reservations_on_url_elicitation_connector_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-url-elicitation",
        admission_id: "adm-url-elicitation",
        lease_id: "lease-url-elicitation",
        continuation_id: Some("continuation-url-elicitation"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-url-elicitation",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("URL elicitation must surface to the caller");

    assert!(matches!(error, KernelError::UrlElicitationsRequired { .. }));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(stream_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "connector-returned URL elicitation cannot prove that no side effect occurred"
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log.get(0).unwrap();
    assert!(receipt.is_incomplete());
    assert_eq!(
        receipt.metadata.as_ref().unwrap()["chio_runtime"]["reservations_retained_fail_closed"],
        true
    );
    Ok(())
}

#[test]
fn chio_runtime_admission_retains_reservations_on_ambiguous_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(CancellationAfterSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&side_effects),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ReleaseTrackingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-chio-runtime-cancelled",
        admission_id: "adm-cancelled",
        lease_id: "lease-cancelled",
        continuation_id: Some("continuation-cancelled"),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-chio-runtime", "destructive_update")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chio-runtime-cancelled",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        releases.load(Ordering::SeqCst),
        0,
        "runtime reservations must stay consumed when cancellation does not prove absence of side effects"
    );
    Ok(())
}
