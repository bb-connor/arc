use super::*;

use chio_kernel::budget_store::BudgetStore;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
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
    let nonce_cfg = ExecutionNonceConfig {
        require_nonce,
        ..ExecutionNonceConfig::default()
    };
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

#[derive(Debug, serde::Deserialize)]
pub(crate) struct SidecarEvaluateToolCallMediatedRequest {
    capability: chio_core_types::capability::token::CapabilityToken,
    tool_server: String,
    tool_name: String,
    #[serde(default)]
    parameters: serde_json::Value,
    #[serde(default)]
    agent_id: Option<String>,
}

pub(crate) async fn sidecar_evaluate_tool_call_mediated_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read mediated evaluate body: {error}");
            return sidecar_bad_request("failed to read evaluate body").into_response();
        }
    };
    let parsed: SidecarEvaluateToolCallMediatedRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return sidecar_bad_request(&format!("invalid mediated payload: {error}"))
                .into_response();
        }
    };
    let Some(kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "mediated tool-call route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    let agent_id = parsed
        .agent_id
        .unwrap_or_else(|| parsed.capability.subject.to_hex());
    let kernel_request = ToolCallRequest {
        request_id: uuid::Uuid::now_v7().to_string(),
        capability: parsed.capability,
        tool_name: parsed.tool_name,
        server_id: parsed.tool_server,
        agent_id,
        arguments: parsed.parameters,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let response = match kernel.evaluate_tool_call_blocking_with_metadata(&kernel_request, None) {
        Ok(response) => response,
        Err(error) => {
            warn!("mediated evaluation error: {error}");
            return internal_json_error_response("chio_mediation_failed", &error.to_string());
        }
    };
    if let Err(error) = record_tool_receipt(&state, &response.receipt).await {
        warn!("failed to persist mediated receipt: {error}");
        return internal_json_error_response("chio_receipt_persistence_failed", &error.to_string());
    }
    let verdict_str = match response.verdict {
        chio_kernel::Verdict::Allow => "allow",
        chio_kernel::Verdict::Deny => "deny",
        chio_kernel::Verdict::PendingApproval => "pending_approval",
    };
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "verdict": verdict_str,
            "receipt": response.receipt,
            "execution_nonce": response.execution_nonce,
        })),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
    use chio_kernel::ToolInvocationCost;
    use chio_test_support::prelude::*;
    use tower::ServiceExt;

    struct TestCostServer {
        id: String,
        tool: String,
        cost_units: u64,
        currency: String,
    }

    fn test_cost_server(id: &str, tool: &str, cost_units: u64, currency: &str) -> TestCostServer {
        TestCostServer {
            id: id.to_string(),
            tool: tool.to_string(),
            cost_units,
            currency: currency.to_string(),
        }
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for TestCostServer {
        fn server_id(&self) -> &str {
            &self.id
        }

        fn tool_names(&self) -> Vec<String> {
            vec![self.tool.clone()]
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
            Ok((
                value,
                Some(ToolInvocationCost {
                    units: self.cost_units,
                    currency: self.currency.clone(),
                    breakdown: None,
                }),
            ))
        }
    }

    fn issue_cost_bearing_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        max_total: u64,
        currency: &str,
    ) -> CapabilityToken {
        use chio_core_types::capability::scope::MonetaryAmount;
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
            .test_unwrap()
    }

    fn mediated_test_state(
        kernel: Arc<ChioKernel>,
        budget: Arc<dyn BudgetStore>,
    ) -> Arc<ProxyState> {
        let keypair = Keypair::generate();
        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let signer_public_key = keypair.public_key();
        let trusted_capability_issuers = vec![signer_public_key.clone()];
        let trusted_receipt_signers = vec![signer_public_key];
        let evaluator = RequestEvaluator::new_with_approval_store(
            Vec::new(),
            keypair.clone(),
            "test-policy".to_string(),
            Arc::clone(&approval_store),
        );
        let egress_contract = default_upstream_egress_contract("http://127.0.0.1:1").test_unwrap();
        let http_client = client_builder_with_contract(&egress_contract)
            .build()
            .test_unwrap();
        Arc::new(ProxyState {
            evaluator,
            signer_keypair: keypair,
            upstream: "http://127.0.0.1:1".to_string(),
            http_client,
            egress_contract,
            approval_admin: ApprovalAdmin::new(approval_store),
            receipt_log: Mutex::new(ReceiptLog {
                receipts: Vec::new(),
            }),
            tool_receipt_log: Mutex::new(ToolReceiptLog {
                receipts: Vec::new(),
            }),
            receipt_store: None,
            revoked_capability_ids: Mutex::new(std::collections::HashSet::new()),
            trusted_capability_issuers,
            trusted_receipt_signers,
            sidecar_control_token: None,
            budget_store: Some(budget),
            mediation_kernel: Some(kernel),
            allow_advisory: false,
        })
    }

    fn with_loopback_peer(request: axum::http::Request<Body>) -> axum::http::Request<Body> {
        use axum::extract::ConnectInfo;
        let mut request = request;
        request
            .extensions_mut()
            .insert(ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                4100,
            ))));
        request
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_route_moves_committed_cost_against_agent_capability() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = build_mediation_kernel(
            &signer,
            Arc::clone(&budget),
            false,
            vec![Box::new(test_cost_server("cost-srv", "compute", 50, "USD"))],
        )
        .test_unwrap();
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(Arc::clone(&kernel), Arc::clone(&budget));

        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        );
        let response = build_app(Arc::clone(&state))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(json["receipt"]["trust_level"], "mediated");
        assert_eq!(json["receipt"]["decision"]["verdict"], "allow");
        assert!(
            json["execution_nonce"].is_object(),
            "mediated route must return a nonce"
        );

        let usage = budget.get_usage(&cap_id, 0).unwrap().unwrap();
        assert_eq!(usage.committed_cost_units().unwrap(), 50);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_deny_leaves_committed_cost_zero() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let kernel = build_mediation_kernel(
            &signer,
            Arc::clone(&budget),
            false,
            vec![Box::new(test_cost_server("cost-srv", "compute", 50, "USD"))],
        )
        .test_unwrap();
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(Arc::clone(&kernel), Arc::clone(&budget));
        let body = serde_json::json!({ "capability": cap, "tool_server": "cost-srv",
            "tool_name": "compute", "parameters": {} });
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        );
        let response = build_app(Arc::clone(&state))
            .oneshot(request)
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_ne!(json["receipt"]["decision"]["verdict"], "allow");
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

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
            allow_advisory: false,
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
        assert!(
            kernel.execution_nonce_required(),
            "require_nonce must be honored"
        );
    }
}
