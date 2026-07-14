use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityToken,
};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_kernel::admission_operation::{
    AdmissionOperationState, AdmissionOperationStore, AdmissionReceiptMetadataV1,
    ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ReceiptStore, ToolCallRequest,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteAuthorityStore;

struct MutationServer {
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for MutationServer {
    fn server_id(&self) -> &str {
        "sqlite-durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"sqlite-durable-admission-test-policy"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "sqlite-durable-server".to_owned(),
            tool_name: "mutate".to_owned(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn request(capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: "sqlite-durable-terminal".to_owned(),
        capability: capability.clone(),
        tool_name: "mutate".to_owned(),
        server_id: "sqlite-durable-server".to_owned(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"record": "ledger-11", "value": "committed"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

#[test]
fn sqlite_durable_admission_atomically_publishes_receipt_and_terminal_outcome(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    std::fs::create_dir(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fence = authority.mutation_fence();
    let operations = Arc::new(authority.admission_operation_store());
    let outcomes = Arc::new(authority.tool_outcome_store());

    let mut kernel = ChioKernel::new(kernel_config());
    kernel.set_durable_admission_store(operations.clone(), outcomes.clone(), fence)?;
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(MutationServer {
        invocations: invocations.clone(),
    }));
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(&agent.public_key(), scope(), 300)?;
    let request = request(&capability);

    let response = kernel.evaluate_tool_call_blocking(&request)?;
    let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .ok_or_else(|| std::io::Error::other("admission receipt metadata is absent"))?,
    )?;
    let operation = operations
        .load_by_operation_id(&metadata.operation_id)?
        .ok_or_else(|| std::io::Error::other("completed admission operation is absent"))?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let stored_receipt = operations
        .load_chio_receipt(&response.receipt.id)?
        .ok_or_else(|| std::io::Error::other("projected receipt is absent"))?;
    assert_eq!(
        canonical_json_bytes(&stored_receipt)?,
        canonical_json_bytes(&response.receipt)?
    );
    let resolved = outcomes
        .load_resolved_output_by_operation(&metadata.operation_id)?
        .ok_or_else(|| std::io::Error::other("resolved output blob is absent"))?;
    assert_eq!(sha256_hex(resolved.bytes()), response.receipt.content_hash);

    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
