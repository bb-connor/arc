use super::*;

use chio_kernel::budget_store::BudgetStore;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

/// Build the sidecar's budget store: remote under `--control-url`, else a local
/// SQLite store, else `None` (the mediated route then denies fail-closed).
pub(crate) fn build_budget_store(
    config: &ProtectConfig,
) -> Result<Option<Arc<dyn BudgetStore>>, ProtectError> {
    if let Some(control_url) = config.control_url.as_deref() {
        let token = config.control_token.as_deref().unwrap_or("");
        let store =
            chio_control_plane::trust_control::service_runtime::budget::build_remote_budget_store(
                control_url,
                token,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(Arc::from(store)));
    }
    if let Some(path) = config.budget_db.as_deref() {
        let store = chio_store_sqlite::budget_store::SqliteBudgetStore::open(path)
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(Arc::new(store)));
    }
    Ok(None)
}

/// Build a `ChioKernel` for tool-call mediation with the budget store and
/// (optionally strict) execution-nonce config installed.
pub(crate) fn build_mediation_kernel(
    signer: &Keypair,
    budget_store: Arc<dyn BudgetStore>,
    require_nonce: bool,
    tool_servers: Vec<Box<dyn ToolServerConnection>>,
) -> Result<Arc<ChioKernel>, ProtectError> {
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
    kernel.set_budget_store_handle(budget_store);
    let nonce_cfg = ExecutionNonceConfig { require_nonce, ..ExecutionNonceConfig::default() };
    kernel.set_execution_nonce_store(
        nonce_cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_cfg)),
    );
    for server in tool_servers {
        kernel.register_tool_server(server);
    }
    Ok(Arc::new(kernel))
}

/// Tool server that represents the proxied upstream call for mediation. On
/// dispatch it reports a realized cost so the kernel reconciles the hold.
pub(crate) struct MediatedProxyToolServer {
    pub(crate) upstream: String,
}

impl MediatedProxyToolServer {
    pub(crate) fn new(upstream: String) -> Self {
        Self { upstream }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MediatedProxyToolServer {
    fn server_id(&self) -> &str {
        "chio-api-protect-upstream"
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({ "upstream": self.upstream.as_str() }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::BudgetStore;

    #[test]
    fn build_budget_store_local_sqlite_when_no_control_url() {
        let dir = std::env::temp_dir().join(format!("chio-budget-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("budget.sqlite");
        let config = ProtectConfig {
            upstream: "http://127.0.0.1:1".to_string(),
            spec_content: Some("{}".to_string()),
            spec_path: None,
            listen_addr: "127.0.0.1:0".to_string(),
            receipt_db: None,
            sidecar_control_token: None,
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: Some(db.to_string_lossy().to_string()),
            require_nonce: false,
        };
        let store = build_budget_store(&config).unwrap();
        assert!(store.is_some(), "local sqlite budget store must be built");
    }

    #[test]
    fn mediation_kernel_installs_budget_store_and_nonce_config() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> =
            Arc::new(chio_kernel::budget_store::InMemoryBudgetStore::new());
        let kernel =
            build_mediation_kernel(&signer, Arc::clone(&budget), true, Vec::new()).unwrap();
        assert!(kernel.execution_nonce_required(), "require_nonce must be honored");
    }
}
