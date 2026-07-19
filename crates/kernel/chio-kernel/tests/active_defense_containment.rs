use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_guards::InternalNetworkGuard;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, MemoryBudgetConfig, NestedFlowBridge,
    SecurityInvocationContext, SecurityInvocationContextV1, ToolCallRequest, ToolServerConnection,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_security_kernel::{ContainmentGuard, MissingContextPolicy};
use chio_security_types::ports::{
    ContainmentOverlayStore, IsolationEpochId, LineageId, SessionId, TenantId,
};
use chio_security_types::PrincipalId;
use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

struct CountingServer {
    invocations: Arc<AtomicUsize>,
}

#[async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "active-defense-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["http_request".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"ok": true}))
    }
}

fn kernel_with_request(
    arguments: serde_json::Value,
) -> (ChioKernel, ToolCallRequest, Arc<AtomicUsize>) {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "active-defense-posture-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::defaults(),
    });
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingServer {
        invocations: Arc::clone(&invocations),
    }));
    let subject = Keypair::generate();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "active-defense-server".to_string(),
            tool_name: "http_request".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let capability = kernel
        .issue_capability(&subject.public_key(), scope, 300)
        .unwrap_or_else(|error| panic!("issue capability: {error}"));
    let request = ToolCallRequest {
        request_id: "active-defense-posture-request".to_string(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "http_request".to_string(),
        server_id: "active-defense-server".to_string(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    (kernel, request, invocations)
}

fn security_context(request: &ToolCallRequest) -> SecurityInvocationContext {
    let lineage_root_id = request
        .capability
        .delegation_chain
        .first()
        .map_or(request.capability.id.as_str(), |link| {
            link.capability_id.as_str()
        });
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant-active-defense-posture")
            .unwrap_or_else(|error| panic!("tenant id: {error}")),
        SessionId::new("session-active-defense-posture")
            .unwrap_or_else(|error| panic!("session id: {error}")),
        PrincipalId::new(request.agent_id.clone())
            .unwrap_or_else(|error| panic!("principal id: {error}")),
        IsolationEpochId::new("epoch-active-defense-posture")
            .unwrap_or_else(|error| panic!("isolation epoch: {error}")),
        LineageId::new(lineage_root_id).unwrap_or_else(|error| panic!("lineage id: {error}")),
        1,
    ))
}

#[test]
fn overlay_store_outage_while_contribution_may_be_active_denies_before_dispatch() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
    let database_path = directory.path().join("containment-outage.db");
    let store = Arc::new(
        SqliteSecurityStateStore::open(&database_path)
            .unwrap_or_else(|error| panic!("open security state store: {error}")),
    );
    store
        .ensure_containment_overlays_ready()
        .unwrap_or_else(|error| panic!("initial overlay readiness: {error}"));

    let tamper = rusqlite::Connection::open(&database_path)
        .unwrap_or_else(|error| panic!("open outage connection: {error}"));
    tamper
        .execute("DROP TABLE security_overlay_state", [])
        .unwrap_or_else(|error| panic!("simulate overlay store outage: {error}"));

    let (mut kernel, request, invocations) =
        kernel_with_request(serde_json::json!({"url": "https://example.com"}));
    let overlays: Arc<dyn ContainmentOverlayStore> = store;
    kernel.add_guard(Box::new(ContainmentGuard::new(
        overlays,
        MissingContextPolicy::Deny,
    )));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .unwrap_or_else(|error| panic!("evaluate contained request: {error}"));

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(response.receipt.evidence.len(), 1);
    assert!(response.receipt.evidence[0]
        .details
        .as_deref()
        .is_some_and(|details| details.contains("overlay lookup failed")));
}

#[test]
fn planner_outage_with_no_active_overlay_leaves_preventive_guards_functional() {
    let directory = tempdir().unwrap_or_else(|error| panic!("temporary directory: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("planner-outage.db"))
            .unwrap_or_else(|error| panic!("open security state store: {error}")),
    );
    store
        .ensure_containment_overlays_ready()
        .unwrap_or_else(|error| panic!("overlay readiness without planner: {error}"));

    let (mut kernel, request, invocations) = kernel_with_request(serde_json::json!({
        "url": "http://169.254.169.254/latest/meta-data"
    }));
    let overlays: Arc<dyn ContainmentOverlayStore> = store;
    kernel.add_guard(Box::new(ContainmentGuard::new(
        overlays,
        MissingContextPolicy::Deny,
    )));
    let preventive_guard = InternalNetworkGuard::new();
    assert!(preventive_guard.check_host("169.254.169.254").is_some());
    kernel.add_guard(Box::new(preventive_guard));
    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context(&request))
        .unwrap_or_else(|error| panic!("evaluate preventive guard request: {error}"));

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(response
        .receipt
        .evidence
        .iter()
        .all(|evidence| evidence.guard_name != "chio-containment-overlay"));
}
