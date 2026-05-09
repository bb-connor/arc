//! Federation co-signing must not create an external remote side effect
//! until the local receipt state needed to recover the exchange is durable.
//!
//! This fixture drives the public hosted dispatch path with a v2-capable
//! federated peer. The tool invocation succeeds, v2 receipt persistence
//! succeeds, v1 fallback persistence fails, and the installed in-process
//! cosigner would succeed if called. The required behavior is to fail before
//! calling the cosigner.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chio_core::capability::{CapabilityNegotiation, ChioScope, Operation, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::receipt::{ChildRequestReceipt, ChioReceipt, ChioReceiptV2};
use chio_federation::{
    BilateralCoSigningError, BilateralCoSigningProtocol, CoSigningRequest, CoSigningResponse,
    ConformanceTier, FederationPeer, InProcessCoSigner,
};
use chio_kernel::runtime::{NestedFlowBridge, ToolCallRequest, ToolServerConnection};
use chio_kernel::{
    ChioKernel, KernelConfig, ReceiptStore, ReceiptStoreError, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

const SERVER_ID: &str = "srv-b2-durability";
const TOOL_NAME: &str = "persist-then-cosign";

struct CountingSucceedingCosigner {
    calls: Arc<AtomicU64>,
    inner: InProcessCoSigner,
}

impl BilateralCoSigningProtocol for CountingSucceedingCosigner {
    fn request_cosignature(
        &self,
        request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.request_cosignature(request)
    }
}

struct V2SucceedsV1FailsStore {
    v1_calls: Arc<AtomicU64>,
    v2_called: Arc<AtomicBool>,
}

impl ReceiptStore for V2SucceedsV1FailsStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.v1_calls.fetch_add(1, Ordering::SeqCst);
        Err(ReceiptStoreError::Conflict(
            "conformance v1 receipt persistence failed".to_string(),
        ))
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn supports_chio_receipt_v2(&self) -> bool {
        true
    }

    fn append_chio_receipt_v2(
        &self,
        _receipt: &ChioReceiptV2,
        _legacy_receipt_id_alias: Option<&str>,
    ) -> Result<u64, ReceiptStoreError> {
        self.v2_called.store(true, Ordering::SeqCst);
        Ok(1)
    }
}

struct SideEffectingTool {
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for SideEffectingTool {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        assert_eq!(tool_name, TOOL_NAME);
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({ "accepted": arguments }))
    }
}

fn make_kernel() -> ChioKernel {
    ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "b2-federation-local-durability".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    })
}

fn make_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: SERVER_ID.to_string(),
            tool_name: TOOL_NAME.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn make_request(
    capability: &chio_core::capability::CapabilityToken,
    origin: &str,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "req-b2-local-durability-before-cosign".to_string(),
        capability: capability.clone(),
        tool_name: TOOL_NAME.to_string(),
        server_id: SERVER_ID.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({ "path": "/data/federated.txt" }),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: Some(origin.to_string()),
    }
}

fn v2_peer(origin_kernel_id: &str, origin_keypair: &Keypair, now: u64) -> FederationPeer {
    FederationPeer {
        kernel_id: origin_kernel_id.to_string(),
        public_key: origin_keypair.public_key(),
        conformance_tier: ConformanceTier::Bronze,
        established_at: now,
        rotation_due: now.saturating_add(3_600),
        capabilities: CapabilityNegotiation::t1_default(),
    }
}

#[test]
fn remote_cosign_is_not_called_when_local_v1_persistence_fails_after_v2() {
    let mut kernel = make_kernel();
    let tool_host_kernel_id = "kernel.local-durability.tool-host";
    let origin_kernel_id = "kernel.local-durability.origin";
    let origin_keypair = Keypair::generate();
    let tool_host_public_key = kernel.public_key();
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    kernel.set_receipt_v2_default(true);

    let v1_calls = Arc::new(AtomicU64::new(0));
    let v2_called = Arc::new(AtomicBool::new(false));
    kernel.set_receipt_store(Box::new(V2SucceedsV1FailsStore {
        v1_calls: Arc::clone(&v1_calls),
        v2_called: Arc::clone(&v2_called),
    }));

    let tool_invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectingTool {
        invocations: Arc::clone(&tool_invocations),
    }));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let mut kernel =
        kernel.with_federation_peers(vec![v2_peer(origin_kernel_id, &origin_keypair, now)]);

    let cosigner_calls = Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(Arc::new(CountingSucceedingCosigner {
        calls: Arc::clone(&cosigner_calls),
        inner: InProcessCoSigner::new(origin_kernel_id, origin_keypair, tool_host_public_key),
    }));

    let agent_keypair = Keypair::generate();
    let capability = kernel
        .issue_capability(&agent_keypair.public_key(), make_scope(), 300)
        .unwrap();
    let request = make_request(&capability, origin_kernel_id);

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        result.is_err(),
        "local v1 persistence failure must abort the federated response path"
    );
    assert_eq!(
        tool_invocations.load(Ordering::SeqCst),
        1,
        "fixture must reach the post-dispatch receipt path"
    );
    assert!(
        v2_called.load(Ordering::SeqCst),
        "v2 receipt persistence must be attempted before the v1 fallback"
    );
    assert_eq!(
        v1_calls.load(Ordering::SeqCst),
        1,
        "v1 receipt persistence must be attempted exactly once"
    );
    assert_eq!(
        cosigner_calls.load(Ordering::SeqCst),
        0,
        "remote co-sign must not run before local receipt persistence succeeds"
    );
}
