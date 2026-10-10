//! Actual kernel dispatch and signed terminal projection on the joint store.
use super::*;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::Keypair;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallChunk, ToolCallRequest,
    ToolCallStream, ToolServerConnection, ToolServerStreamResult, Verdict,
};

struct FixtureTool {
    stream: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for FixtureTool {
    fn server_id(&self) -> &str {
        "compaction-fixture-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["complete".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(arguments)
    }
    async fn invoke_stream(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Ok(self
            .stream
            .then_some(ToolServerStreamResult::Complete(ToolCallStream {
                chunks: vec![ToolCallChunk { data: arguments }],
            })))
    }
}

pub(super) fn completed_return(
    fixture: &Fixture,
    name: &str,
    stream: bool,
) -> Result<(AdmissionOperationV1, ToolOutcomeRecordV1), Box<dyn std::error::Error>> {
    completed_return_with_value(
        fixture,
        name,
        stream,
        serde_json::json!({"completed": true}),
    )
}

pub(super) fn completed_return_with_value(
    fixture: &Fixture,
    name: &str,
    stream: bool,
    value: serde_json::Value,
) -> Result<(AdmissionOperationV1, ToolOutcomeRecordV1), Box<dyn std::error::Error>> {
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: Keypair::from_seed(&[42; 32]),
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: sha256_hex(b"compaction-qualified-fixture"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        },
        chio_test_support::clock::clock(),
    );
    kernel.set_durable_admission_store(
        Arc::new(fixture.operations.clone()),
        Arc::new(fixture.outcomes.clone()),
        fixture.fence.clone(),
    )?;
    kernel.set_budget_store_handle(Arc::new(fixture.authority.budget_store()));
    kernel.set_revocation_store_handle(Arc::new(fixture.authority.revocation_store()));
    kernel.register_tool_server(Box::new(FixtureTool { stream }));
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "compaction-fixture-server".into(),
                tool_name: "complete".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        300,
    )?;
    let request = ToolCallRequest {
        request_id: name.into(),
        capability,
        tool_name: "complete".into(),
        server_id: "compaction-fixture-server".into(),
        agent_id: agent.public_key().to_hex(),
        arguments: value,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: vec![],
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let metadata: chio_kernel::admission_operation::AdmissionReceiptMetadataV1 =
        serde_json::from_value(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata.get(chio_kernel::admission_operation::ADMISSION_RECEIPT_METADATA_KEY)
                })
                .cloned()
                .ok_or("missing signed admission metadata")?,
        )?;
    let operation = fixture
        .operations
        .load_by_operation_id(&metadata.operation_id)?
        .ok_or("missing completed operation")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    let outcome = fixture
        .outcomes
        .lookup_by_operation(&metadata.operation_id)?
        .ok_or("missing completed outcome")?;
    Ok((operation, outcome))
}
