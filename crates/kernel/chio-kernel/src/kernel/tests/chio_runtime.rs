use super::*;

#[path = "chio_runtime/admission_gates.rs"]
mod admission_gates;
#[path = "chio_runtime/child_receipts.rs"]
mod child_receipts;
#[path = "chio_runtime/post_dispatch_retention.rs"]
mod post_dispatch_retention;
#[path = "chio_runtime/pre_dispatch_cleanup.rs"]
mod pre_dispatch_cleanup;
// Chio runtime admission hook tests.
//
// These cover the generic pre-dispatch hook that Chio 7.0 uses to deny
// cross-vendor workflow steps before tool execution or federation side effects.

struct DenyingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

pub(super) struct AllowingRuntimeAdmissionHook {
    pub(super) calls: std::sync::Arc<AtomicU64>,
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

pub(super) struct FailingReleaseRuntimeAdmissionHook {
    pub(super) calls: std::sync::Arc<AtomicU64>,
    pub(super) releases: std::sync::Arc<AtomicU64>,
    pub(super) expected_request_id: &'static str,
    pub(super) admission_id: &'static str,
    pub(super) lease_id: &'static str,
}

pub(super) struct FailingAfterSideEffectServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
    pub(super) invocations: std::sync::Arc<AtomicU64>,
}

pub(super) struct UrlElicitationBeforeSideEffectServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
    stream_attempts: std::sync::Arc<AtomicU64>,
}

pub(super) struct CancellationAfterSideEffectServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

pub(super) struct IncompleteAfterSideEffectServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
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

// A registered server passes pre-dispatch validation, performs a side effect,
// then returns ToolNotRegistered from dispatch. An unregistered server would be
// denied before runtime admission and never reach the generic dispatch-error arm.
pub(super) struct ToolNotRegisteredDispatchServer {
    pub(super) id: String,
    pub(super) tools: Vec<String>,
    side_effects: std::sync::Arc<AtomicU64>,
}

pub(super) struct NoopNestedFlowClient;

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
    pub(super) fn new(id: &str, tools: Vec<&str>, invocations: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            invocations,
        }
    }
}

impl UrlElicitationBeforeSideEffectServer {
    pub(super) fn new(
        id: &str,
        tools: Vec<&str>,
        stream_attempts: std::sync::Arc<AtomicU64>,
    ) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            stream_attempts,
        }
    }
}

impl CancellationAfterSideEffectServer {
    pub(super) fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
        }
    }
}

impl IncompleteAfterSideEffectServer {
    pub(super) fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
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
    pub(super) fn new(id: &str, tools: Vec<&str>, side_effects: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            side_effects,
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
        self.side_effects.fetch_add(1, Ordering::SeqCst);
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

// --- RFC-0002 drop-guard unwind tests ---

pub(super) fn make_fabricated_drop_charge() -> BudgetChargeResult {
    BudgetChargeResult {
        grant_index: 0,
        cost_charged: 5,
        currency: "USD".to_string(),
        budget_total: Some(100),
        new_committed_cost_units: 5,
        budget_hold_id: "hold-drop-guard-tests".to_string(),
        authorize_metadata: BudgetCommitMetadata {
            authority: None,
            guarantee_level: crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic,
            budget_profile: crate::budget_store::BudgetAuthorityProfile::AuthoritativeHoldEvent,
            metering_profile:
                crate::budget_store::BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
            budget_commit_index: None,
            event_id: None,
            recorded_at_unix_seconds: None,
        },
        invocation_capture: None,
    }
}

/// Authorize a real, open budget hold that exactly matches the fabricated drop
/// charge (see `make_fabricated_drop_charge`). The drop-guard tests build a
/// fabricated `BudgetChargeResult`; without a matching open hold in the store,
/// the monetary reversal fails and records a fault receipt. Authorizing the hold
/// first models the real admission so the pre-dispatch monetary unwind is a
/// genuine, clean, receipt-free reversal.
pub(super) fn authorize_fabricated_drop_hold(
    kernel: &ChioKernel,
    capability_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    kernel
        .with_budget_store(|store| {
            let decision =
                store.authorize_budget_hold(crate::budget_store::BudgetAuthorizeHoldRequest {
                    capability_id: capability_id.to_string(),
                    grant_index: 0,
                    max_invocations: None,
                    invocation_quotas: Vec::new(),
                    cumulative_approval: None,
                    admission_binding: None,
                    requested_exposure_units: 5,
                    max_cost_per_invocation: Some(100),
                    max_total_cost_units: Some(1_000),
                    hold_id: Some("hold-drop-guard-tests".to_string()),
                    event_id: Some("hold-drop-guard-tests:authorize".to_string()),
                    authority: None,
                })?;
            assert!(
                matches!(
                    decision,
                    crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)
                ),
                "fabricated drop hold must authorize"
            );
            Ok(())
        })
        .map_err(|error| -> Box<dyn std::error::Error> {
            format!("authorize fabricated drop hold: {error}").into()
        })?;
    Ok(())
}

struct ParkingServer {
    id: String,
    tools: Vec<String>,
    started: std::sync::Arc<tokio::sync::Notify>,
    invocations: std::sync::Arc<AtomicU64>,
}

impl ParkingServer {
    fn new(
        id: &str,
        tools: Vec<&str>,
        started: std::sync::Arc<tokio::sync::Notify>,
        invocations: std::sync::Arc<AtomicU64>,
    ) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            started,
            invocations,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for ParkingServer {
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
        // notify_one() stores a permit if the waiter has not yet called
        // .notified().await, avoiding the lost-wakeup race that
        // notify_waiters() has when the waiter has not yet polled.
        self.started.notify_one();
        std::future::pending::<Result<serde_json::Value, KernelError>>().await
    }
}

// A registered tool server whose dispatch first performs a nested CHILD
// operation through the bridge (which buffers a signed child receipt into the
// parent evaluation's `child_receipts` sink) and then either parks forever or
// returns normally. Exercises receipt completeness for buffered child receipts
// across a post-dispatch parent drop, and the no-double-record property on the
// normal exit.
struct NestedChildOpServer {
    id: String,
    tools: Vec<String>,
    child_ops: std::sync::Arc<AtomicU64>,
    park: bool,
}

impl NestedChildOpServer {
    fn new(id: &str, tools: Vec<&str>, child_ops: std::sync::Arc<AtomicU64>, park: bool) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            child_ops,
            park,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NestedChildOpServer {
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
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        // Perform a nested child operation so a signed child receipt is
        // buffered. The child op's own result is irrelevant: completing it
        // (success or failure) is what records the signed receipt.
        if let Some(bridge) = nested_flow_bridge {
            let _ = bridge.list_roots();
            self.child_ops.fetch_add(1, Ordering::SeqCst);
        }
        if self.park {
            std::future::pending::<Result<serde_json::Value, KernelError>>().await
        } else {
            Ok(serde_json::json!({"status": "ok"}))
        }
    }
}

/// A durable store whose bounded child-receipt append always times out, to
/// drive the child-receipt persistence timeout that follows nested dispatch.
/// Parent (chio) receipt appends succeed so the fail-closed cancellation
/// receipt can still be persisted.
struct ChildAppendTimeoutStore;

impl ReceiptStore for ChildAppendTimeoutStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt_with_timeout(
        &self,
        _receipt: &ChildRequestReceipt,
        _budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        Err(ReceiptStoreError::Timeout {
            operation: "append_child_receipt".to_string(),
            timeout_ms: 0,
        })
    }
}

/// A durable store whose bounded child-receipt append fails closed on its first
/// call and succeeds afterward, modeling a commit writer that is momentarily
/// saturated during the normal record path but has drained before the drop-path
/// flush retries. Parent (chio) receipt appends always succeed.
struct ChildAppendFailsOnceStore {
    child_appends: std::sync::Arc<AtomicU64>,
}

impl ReceiptStore for ChildAppendFailsOnceStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt_with_timeout(
        &self,
        _receipt: &ChildRequestReceipt,
        _budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        if self.child_appends.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(ReceiptStoreError::Timeout {
                operation: "append_child_receipt".to_string(),
                timeout_ms: 0,
            });
        }
        Ok(Some(1))
    }
}

// A tool server whose dispatch performs TWO nested child operations (buffering
// two already-signed child receipts) and then parks forever. Dropping the
// parked parent future exercises the drop-path flush with more than one
// buffered receipt, so a failure on the first append must not discard the
// second.
struct TwoChildOpParkingServer {
    id: String,
    tools: Vec<String>,
    child_ops: std::sync::Arc<AtomicU64>,
}

impl TwoChildOpParkingServer {
    fn new(id: &str, tools: Vec<&str>, child_ops: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            child_ops,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for TwoChildOpParkingServer {
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
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        // Two nested child ops buffer two distinct signed child receipts (each
        // list_roots mints a fresh nonce-suffixed child request id).
        if let Some(bridge) = nested_flow_bridge {
            let _ = bridge.list_roots();
            let _ = bridge.list_roots();
            self.child_ops.fetch_add(2, Ordering::SeqCst);
        }
        std::future::pending::<Result<serde_json::Value, KernelError>>().await
    }
}
