#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::Keypair;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolInvocationCost,
    ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use std::sync::Arc;

pub struct MonetaryCostServer {
    id: String,
    reported_cost: Option<ToolInvocationCost>,
}

impl MonetaryCostServer {
    pub fn new(id: &str, cost_units: u64, currency: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: Some(ToolInvocationCost {
                units: cost_units,
                currency: currency.to_string(),
                breakdown: None,
            }),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MonetaryCostServer {
    fn server_id(&self) -> &str {
        &self.id
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
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, self.reported_cost.clone()))
    }
}

pub fn mediation_kernel(
    signer: &Keypair,
    budget: Arc<dyn BudgetStore>,
    require_nonce: bool,
) -> ChioKernel {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer.clone(),
        ca_public_keys: vec![signer.public_key()],
        max_delegation_depth: 5,
        policy_hash: "chio_api_protect_mediation_v1".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    });
    kernel.set_budget_store_handle(budget);
    let nonce_cfg = ExecutionNonceConfig {
        require_nonce,
        ..ExecutionNonceConfig::default()
    };
    kernel.set_execution_nonce_store(
        nonce_cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_cfg)),
    );
    kernel
}

pub fn issue_cost_bearing_capability(
    kernel: &ChioKernel,
    agent: &Keypair,
    server: &str,
    tool: &str,
    max_per: u64,
    max_total: u64,
    currency: &str,
) -> CapabilityToken {
    let grant = ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_per,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![grant],
        ..ChioScope::default()
    };
    kernel
        .issue_capability(&agent.public_key(), scope, 3600)
        .unwrap()
}

/// Build a sidecar-style advisory receipt from the fields of a mediated receipt.
/// The returned receipt carries `AdvisoryEvaluation` / `AdvisoryOnly` / `Advisory`
/// markers so `is_authoritative_spend_receipt` rejects it (mirroring
/// sidecar.rs:1091-1123 `ReceiptKind::AdvisoryEvaluation` path).
pub fn advisory_receipt(signer: &Keypair, mediated: &ChioReceipt) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp: mediated.timestamp,
        capability_id: mediated.capability_id.clone(),
        tool_server: mediated.tool_server.clone(),
        tool_name: mediated.tool_name.clone(),
        action: mediated.action.clone(),
        decision: None,
        receipt_kind: ReceiptKind::AdvisoryEvaluation,
        boundary_class: BoundaryClass::AdvisoryOnly,
        observation_outcome: Some(ObservationOutcome::Evaluated),
        tool_origin: ToolOrigin::HostExecutedUnmediated,
        redaction_mode: RedactionMode::None,
        actor_chain: Vec::new(),
        content_hash: mediated.content_hash.clone(),
        policy_hash: mediated.policy_hash.clone(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::Advisory,
        tenant_id: None,
        kernel_key: signer.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, signer).unwrap()
}
