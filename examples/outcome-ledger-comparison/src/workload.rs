use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolCallResponse,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde_json::{json, Value};

use crate::gates::Prepared;
use crate::{append_effect, count, fixture, scope, Gate, Result, BACKENDS, NOW};

fn error(error: impl std::fmt::Display) -> KernelError {
    KernelError::ToolServerError(error.to_string())
}

struct Publisher {
    gate: Arc<Gate>,
    directory: PathBuf,
}

#[async_trait::async_trait]
impl ToolServerConnection for Publisher {
    fn server_id(&self) -> &str {
        "artifact-registry"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["publish".into()]
    }
    async fn invoke(
        &self,
        tool: &str,
        arguments: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let prepared: Prepared = serde_json::from_value(arguments).map_err(error)?;
        let (_, _, artifact) = fixture().map_err(error)?;
        if prepared.arguments().artifact_sha256 != sha256_hex(&artifact) {
            return Err(error(
                "selected artifact bytes differ from the publication request",
            ));
        }
        let permit = self
            .gate
            .claim(&prepared, self.server_id(), tool, NOW)
            .map_err(error)?;
        let result = append_effect(&self.directory).map_err(error)?;
        self.gate.complete(permit, &result).map_err(error)?;
        Ok(result)
    }
}

pub(crate) fn configured_kernel(directory: &Path, keypair: Keypair) -> Result<ChioKernel> {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"identical-comparison-policy"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
    });
    let receipts =
        chio_store_sqlite::SqliteReceiptStore::open(directory.join("kernel-receipts.sqlite"))?;
    receipts.wait_for_writer_ready(std::time::Duration::from_secs(5))?;
    kernel.set_receipt_store_handle(Arc::new(receipts))?;
    Ok(kernel)
}

fn host(directory: &Path, gate: Arc<Gate>) -> Result<ChioKernel> {
    let mut kernel = configured_kernel(directory, Keypair::from_seed(&[41; 32]))?;
    kernel.register_tool_server(Box::new(Publisher {
        gate,
        directory: directory.into(),
    }));
    Ok(kernel)
}

fn invoke(kernel: &ChioKernel, prepared: &Prepared, id: &str) -> Result<ToolCallResponse> {
    invoke_authorized(
        kernel,
        &Keypair::from_seed(&[41; 32]),
        "artifact-registry",
        "publish",
        serde_json::to_value(prepared)?,
        id,
    )
}

pub(crate) fn invoke_authorized(
    kernel: &ChioKernel,
    issuer: &Keypair,
    server: &str,
    tool: &str,
    arguments: Value,
    id: &str,
) -> Result<ToolCallResponse> {
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, [format!("receipt-{id}")]);
    let agent = Keypair::generate();
    // The whole comparison uses one fixed logical clock, including the
    // receiver-issued capability. `issue_capability` uses wall-clock time.
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("comparison-capability-{}", agent.public_key().to_hex()),
            issuer: issuer.public_key(),
            subject: agent.public_key(),
            scope: scope(server, tool),
            issued_at: NOW / 1000,
            expires_at: NOW / 1000 + 300,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )?;
    Ok(kernel.evaluate_tool_call_blocking(&ToolCallRequest {
        request_id: id.into(),
        agent_id: agent.public_key().to_hex(),
        capability,
        server_id: server.into(),
        tool_name: tool.into(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        declassification_grant: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    })?)
}

pub fn compare(root: &Path) -> Result<Value> {
    let mut observations = Vec::new();
    for backend in BACKENDS {
        let directory = root.join("kernel-workflow").join(backend);
        let (rule, request, artifact) = fixture()?;
        let gate = Arc::new(Gate::open(backend, &directory, &rule)?);
        let prepared = gate.prepare(&request, &rule.server_id, &rule.tool_name, NOW)?;
        let kernel = host(&directory, gate.clone())?;
        let accepted = invoke(&kernel, &prepared, "initial-agent")?;
        assert_eq!(
            accepted.verdict,
            Verdict::Allow,
            "{backend}: {:?}",
            accepted.reason
        );
        assert_eq!(count(&directory)?, 1);
        assert!(accepted.receipt.verify_signature()?);
        let Some(chio_kernel::ToolCallOutput::Value(result)) = accepted.output.as_ref() else {
            return Err("kernel output missing".into());
        };
        assert_eq!(
            accepted.receipt.content_hash,
            sha256_hex(&canonical_json_bytes(result)?)
        );
        std::fs::write(
            directory.join("publication-receipt.json"),
            serde_json::to_vec_pretty(&accepted.receipt)?,
        )?;
        std::fs::write(
            directory.join("publication-result.json"),
            serde_json::to_vec_pretty(result)?,
        )?;
        drop(kernel);
        drop(gate);
        let reopened = Arc::new(Gate::open(backend, &directory, &rule)?);
        let replacement = host(&directory, reopened.clone())?;
        let replay = invoke(
            &replacement,
            &prepared,
            "replacement-agent-fresh-capability",
        )?;
        assert_ne!(replay.verdict, Verdict::Allow);
        assert_eq!(count(&directory)?, 1);
        assert_eq!(
            std::fs::read(directory.join("approved.scope.json"))?,
            artifact
        );
        assert!(replay.receipt.verify_signature()?);
        std::fs::write(
            directory.join("replacement-receipt.json"),
            serde_json::to_vec_pretty(&replay.receipt)?,
        )?;
        observations.push(json!({"admitted":true,"publicationCount":1,"replacementAdmitted":false,"state":reopened.status(&rule)?.0,"artifactSha256":sha256_hex(&artifact),"receiptsVerified":true}));
    }
    assert_eq!(observations[0], observations[1]);
    Ok(json!({"chio":observations[0],"ledger":observations[1]}))
}
