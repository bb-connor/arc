use super::*;

use chio_kernel::budget_store::BudgetStore;
use chio_kernel::execution_nonce::{
    ExecutionNonceConfig, ExecutionNonceStore, InMemoryExecutionNonceStore, SignedExecutionNonce,
};
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

/// Build the shared execution-nonce replay store for the mediated route.
///
/// The store is shared across every per-request mediation kernel so a minted
/// nonce is consumable exactly once globally; a per-request store would let a
/// caller replay a nonce across requests and double-charge the budget.
pub(crate) fn build_mediation_nonce_store() -> Arc<dyn ExecutionNonceStore> {
    Arc::new(InMemoryExecutionNonceStore::from_config(
        &ExecutionNonceConfig::default(),
    ))
}

/// Adapter that lets a single [`ExecutionNonceStore`] be shared (by `Arc`)
/// across the per-request mediation kernels, which each take ownership of a
/// boxed store. All calls delegate to the shared store so replay protection
/// stays global.
struct SharedExecutionNonceStore(Arc<dyn ExecutionNonceStore>);

impl ExecutionNonceStore for SharedExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.0.reserve(nonce_id)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.0.reserve_until(nonce_id, nonce_expires_at)
    }
}

/// Build a `ChioKernel` for tool-call mediation with the budget store and a
/// strict execution-nonce config installed.
///
/// The mediation kernel always runs execution-nonce strict mode because the
/// mediated route is a pre-execution authorization gate: a request that does
/// not present a nonce receives a preflight allow with a freshly minted nonce
/// and never dispatches a tool server, reconciles budget, or signs a completed
/// spend receipt. The caller executes the real tool afterwards presenting that
/// nonce, and realized-cost reconciliation happens outside this route.
///
/// A fresh kernel is built per mediated request so the pass-through tool server
/// can be registered under the caller's requested `server_id`: the kernel's
/// pre-dispatch registration check runs before the preflight return, so an
/// unregistered target would otherwise deny an ordinary preflight. The budget
/// store and `nonce_store` are shared across those per-request kernels so holds
/// and replay protection remain global.
///
/// `trusted_capability_issuers` are trusted as capability authorities in
/// addition to the sidecar signer, so an externally minted capability that the
/// sidecar's other endpoints accept is not rejected here as untrusted.
pub(crate) fn build_mediation_kernel(
    signer: &Keypair,
    budget_store: Arc<dyn BudgetStore>,
    nonce_store: Arc<dyn ExecutionNonceStore>,
    trusted_capability_issuers: &[PublicKey],
    tool_servers: Vec<Box<dyn ToolServerConnection>>,
) -> Result<Arc<ChioKernel>, ProtectError> {
    let mut ca_public_keys = vec![signer.public_key()];
    for issuer in trusted_capability_issuers {
        if !ca_public_keys.contains(issuer) {
            ca_public_keys.push(issuer.clone());
        }
    }
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer.clone(),
        ca_public_keys,
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
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel.set_execution_nonce_store(nonce_cfg, Box::new(SharedExecutionNonceStore(nonce_store)));
    for server in tool_servers {
        kernel.register_tool_server(server);
    }
    Ok(Arc::new(kernel))
}

/// Tool server registered under the caller's requested `server_id` so the
/// kernel's pre-dispatch registration check admits an ordinary preflight. The
/// mediated route does not execute the real tool (the caller does), so this
/// reports `measures_realized_cost() == false`: on a presented-nonce dispatch
/// the kernel reverses the pre-execution hold and signs a provisional,
/// unreconciled receipt rather than a settled authoritative spend. Realized-cost
/// reconciliation happens at the execution site outside this route.
pub(crate) struct MediatedProxyToolServer {
    server_id: String,
    upstream: String,
}

impl MediatedProxyToolServer {
    pub(crate) fn new(server_id: String, upstream: String) -> Self {
        Self {
            server_id,
            upstream,
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for MediatedProxyToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// The mediated route does not execute the real tool (the caller does), so
    /// this pass-through measures no realized cost. Reporting `false` keeps the
    /// kernel from signing a settled, reconciled authoritative spend for a
    /// dispatch that never ran: it reverses the pre-execution hold and emits a
    /// provisional receipt instead. Realized-cost reconciliation happens at the
    /// execution site.
    fn measures_realized_cost(&self) -> bool {
        false
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
    /// Signed execution nonce presented on a follow-up request so strict
    /// deployments can proceed past the preflight authorization and dispatch
    /// the tool. This is the `SignedExecutionNonce` object the preflight
    /// response returns verbatim under `execution_nonce`; the caller copies it
    /// back unchanged with no re-encoding. A malformed nonce fails the
    /// enclosing deserialization, which is rejected fail-closed with a 400.
    #[serde(default)]
    execution_nonce: Option<SignedExecutionNonce>,
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
    let (Some(budget_store), Some(nonce_store)) = (
        state.budget_store.as_ref(),
        state.mediation_nonce_store.as_ref(),
    ) else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "mediated tool-call route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    // Fail-closed: a capability released via `/v1/capabilities/release` is
    // recorded in the sidecar revocation set, which the per-request mediation
    // kernel does not carry. Reject a revoked capability here, mirroring the
    // validate, proxy, and advisory paths, so a revoked token cannot keep
    // earning mediated allows until expiry.
    let revoked = state
        .revoked_capability_ids
        .lock()
        .await
        .contains(&parsed.capability.id);
    if revoked {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": "chio_capability_revoked",
                "message": "capability has been revoked",
            })),
        )
            .into_response();
    }
    // Build a fresh kernel that registers the pass-through under the caller's
    // requested server id so the kernel's pre-dispatch registration check
    // admits the preflight. Budget store and nonce store are shared so holds
    // and replay protection stay global.
    let kernel = match build_mediation_kernel(
        &state.signer_keypair,
        Arc::clone(budget_store),
        Arc::clone(nonce_store),
        &state.trusted_capability_issuers,
        vec![Box::new(MediatedProxyToolServer::new(
            parsed.tool_server.clone(),
            state.upstream.clone(),
        ))],
    ) {
        Ok(kernel) => kernel,
        Err(error) => {
            warn!("failed to build mediation kernel: {error}");
            return internal_json_error_response("chio_mediation_failed", &error.to_string());
        }
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
        execution_nonce: parsed.execution_nonce,
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
    // Derive the top-level wire status from the terminal lifecycle state, not
    // the raw verdict. A nonce-less preflight returns `Verdict::Allow` with an
    // `Incomplete` terminal state and an incomplete-decision receipt: nothing
    // was authorized to execute yet. Surfacing "allow" there would let a caller
    // that gates on the top-level status execute the tool before retrying with
    // the minted nonce. Only a genuinely completed authorization surfaces
    // "allow".
    let verdict_str = match (&response.verdict, &response.terminal_state) {
        (chio_kernel::Verdict::Allow, chio_core_types::OperationTerminalState::Completed) => {
            "allow"
        }
        (chio_kernel::Verdict::Allow, _) => "pending_nonce",
        (chio_kernel::Verdict::Deny, _) => "deny",
        (chio_kernel::Verdict::PendingApproval, _) => "pending_approval",
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
    use chio_test_support::prelude::*;
    use tower::ServiceExt;

    /// Build an ephemeral kernel used only to mint capabilities in tests. The
    /// mediated handler builds its own per-request kernel, so cost is never
    /// resolved through an injected tool server; capabilities carry their own
    /// monetary constraints.
    fn issuing_kernel(
        signer: &Keypair,
        budget: Arc<dyn BudgetStore>,
        nonce_store: Arc<dyn ExecutionNonceStore>,
        trusted_capability_issuers: &[PublicKey],
    ) -> Arc<ChioKernel> {
        build_mediation_kernel(
            signer,
            budget,
            nonce_store,
            trusted_capability_issuers,
            Vec::new(),
        )
        .test_unwrap()
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

    /// Build proxy state for the mediated route. `signer` is the sidecar signer
    /// the per-request mediation kernels are built from (so capabilities minted
    /// by it are trusted), and `trusted_capability_issuers` are additional
    /// external issuers to trust.
    fn mediated_test_state(
        signer: Keypair,
        nonce_store: Arc<dyn ExecutionNonceStore>,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Arc<ProxyState> {
        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let signer_public_key = signer.public_key();
        let mut trusted_capability_issuers = trusted_capability_issuers;
        if !trusted_capability_issuers.contains(&signer_public_key) {
            trusted_capability_issuers.push(signer_public_key.clone());
        }
        let trusted_receipt_signers = vec![signer_public_key];
        let evaluator = RequestEvaluator::new_with_approval_store(
            Vec::new(),
            signer.clone(),
            "test-policy".to_string(),
            Arc::clone(&approval_store),
        );
        let egress_contract = default_upstream_egress_contract("http://127.0.0.1:1").test_unwrap();
        let http_client = client_builder_with_contract(&egress_contract)
            .build()
            .test_unwrap();
        Arc::new(ProxyState {
            evaluator,
            signer_keypair: signer,
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
            mediation_nonce_store: Some(nonce_store),
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
    async fn mediated_nonce_less_request_is_preflight_allow_without_completed_spend() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let nonce_store = build_mediation_nonce_store();
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), Arc::clone(&nonce_store), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(
            signer,
            Arc::clone(&nonce_store),
            Arc::clone(&budget),
            Vec::new(),
        );

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

        // A nonce-less mediated request is a pre-execution authorization gate:
        // it returns a distinct non-authorizing status ("pending_nonce") with a
        // freshly minted execution nonce, does not dispatch the tool, and does
        // not sign a completed spend. The top-level status must not be "allow",
        // so a caller gating on it cannot execute before retrying with the
        // minted nonce.
        assert_eq!(json["verdict"], "pending_nonce");
        assert_ne!(json["verdict"], "allow");
        assert!(
            json["execution_nonce"].is_object(),
            "preflight must mint an execution nonce"
        );
        assert_eq!(
            json["receipt"]["decision"]["verdict"], "incomplete",
            "preflight receipt must not be a completed-spend decision"
        );

        // The tool has not run, so no realized cost is reconciled against the
        // capability: the hold is not moved into committed spend.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(
            usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0,
            "nonce-less preflight must not move committed cost"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_revoked_capability_is_rejected() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let nonce_store = build_mediation_nonce_store();
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), Arc::clone(&nonce_store), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(
            signer,
            Arc::clone(&nonce_store),
            Arc::clone(&budget),
            Vec::new(),
        );
        // Record the capability id as revoked, mirroring a prior
        // `/v1/capabilities/release`.
        state
            .revoked_capability_ids
            .lock()
            .await
            .insert(cap_id.clone());

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
        // A revoked capability is rejected fail-closed rather than returning a
        // preflight allow.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_ne!(json["verdict"], "allow");
        assert_eq!(json["error"], "chio_capability_revoked");

        // The revoked capability never reaches the kernel, so no hold is placed.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_preflight_admits_caller_named_server_id() {
        // The operator does not pre-register tool servers; the mediated route
        // registers a pass-through under whatever server id the caller names,
        // so a nonce-less preflight for an arbitrary server is authorized
        // ("pending_nonce" + minted nonce) rather than denied `ToolNotRegistered`
        // by the kernel's pre-dispatch registration check.
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let nonce_store = build_mediation_nonce_store();
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), Arc::clone(&nonce_store), &[]);
        let cap = issue_cost_bearing_capability(
            &kernel,
            &agent,
            "arbitrary-srv",
            "invoke",
            100,
            1000,
            "USD",
        );
        let state = mediated_test_state(
            signer,
            Arc::clone(&nonce_store),
            Arc::clone(&budget),
            Vec::new(),
        );
        let body = serde_json::json!({
            "capability": cap,
            "tool_server": "arbitrary-srv",
            "tool_name": "invoke",
            "parameters": {}
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
        assert_eq!(json["verdict"], "pending_nonce");
        assert!(json["execution_nonce"].is_object());
        assert_eq!(json["receipt"]["decision"]["verdict"], "incomplete");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_presented_nonce_proceeds_past_preflight() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let nonce_store = build_mediation_nonce_store();
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), Arc::clone(&nonce_store), &[]);
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_id = cap.id.clone();
        let cap_value = serde_json::to_value(&cap).unwrap();
        let state = mediated_test_state(
            signer,
            Arc::clone(&nonce_store),
            Arc::clone(&budget),
            Vec::new(),
        );
        let signer_pub = state.signer_keypair.public_key();

        // Step 1: nonce-less preflight mints the execution nonce and does not
        // move committed cost.
        let preflight_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" }
        });
        let preflight_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&preflight_body).unwrap()))
                .unwrap(),
        );
        let preflight_response = build_app(Arc::clone(&state))
            .oneshot(preflight_request)
            .await
            .unwrap();
        let preflight_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(preflight_response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(preflight_json["verdict"], "pending_nonce");
        assert_eq!(
            preflight_json["receipt"]["decision"]["verdict"],
            "incomplete"
        );
        assert!(preflight_json["execution_nonce"].is_object());
        let usage_after_preflight = budget.get_usage(&cap_id, 0).unwrap();
        assert!(
            usage_after_preflight.is_none()
                || usage_after_preflight
                    .unwrap()
                    .committed_cost_units()
                    .unwrap()
                    == 0
        );
        // The caller copies the exact nonce object the preflight returned back
        // into the retry body with no re-encoding.
        let minted_nonce = preflight_json["execution_nonce"].clone();
        assert!(minted_nonce.is_object());

        // Step 2: presenting the minted nonce proceeds past preflight to a
        // completed authorization confirmation. The mediated route does not
        // execute the real tool, so the pass-through measures no realized cost:
        // the kernel reverses the pre-execution hold and signs a provisional,
        // unreconciled receipt rather than a settled authoritative spend.
        let execute_body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": { "invoice": "inv-1" },
            "execution_nonce": minted_nonce
        });
        let execute_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&execute_body).unwrap()))
                .unwrap(),
        );
        let execute_response = build_app(Arc::clone(&state))
            .oneshot(execute_request)
            .await
            .unwrap();
        assert_eq!(execute_response.status(), StatusCode::OK);
        let execute_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(execute_response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        // A completed authorization confirmation surfaces the top-level "allow"
        // and a completed-decision receipt, so the caller may execute the real
        // tool.
        assert_eq!(execute_json["verdict"], "allow");
        assert_eq!(execute_json["receipt"]["decision"]["verdict"], "allow");
        assert_eq!(execute_json["receipt"]["trust_level"], "mediated");

        // The stub measured no realized cost, so the receipt is truthfully
        // provisional: the budget hold is reversed (not reconciled) and
        // settlement stays pending.
        let budget_authority = &execute_json["receipt"]["metadata"]["budget_authority"];
        assert_eq!(budget_authority["terminal"]["disposition"], "reversed");
        assert_ne!(budget_authority["terminal"]["disposition"], "reconciled");
        assert_eq!(
            execute_json["receipt"]["metadata"]["financial"]["settlement_status"],
            "pending"
        );

        // The pre-execution hold is reversed: no committed spend was moved by
        // the stub dispatch. Realized-cost reconciliation happens at the real
        // execution site outside this route.
        let usage = budget.get_usage(&cap_id, 0).unwrap();
        assert!(
            usage.is_none() || usage.unwrap().committed_cost_units().unwrap() == 0,
            "unmeasured stub dispatch must not move committed cost"
        );

        // The invariant: a receipt minted by the stub dispatch must never be
        // accepted as a final settled/reconciled authoritative spend. It is
        // rejected because the hold was not reconciled.
        use chio_core_types::receipt::authoritative_spend::{
            is_authoritative_spend_receipt, NotAuthoritativeReason,
        };
        let signed_receipt: ChioReceipt =
            serde_json::from_value(execute_json["receipt"].clone()).unwrap();
        let presented_nonce: SignedExecutionNonce =
            serde_json::from_value(minted_nonce.clone()).unwrap();
        assert_eq!(
            is_authoritative_spend_receipt(&signed_receipt, &[signer_pub], &presented_nonce),
            Err(NotAuthoritativeReason::HoldNotReconciled),
            "the stub dispatch must not mint an authoritative spend receipt"
        );

        // Replaying the same nonce is rejected: the shared replay store consumed
        // it on the first execute, so a second presentation fails closed.
        let replay_request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&execute_body).unwrap()))
                .unwrap(),
        );
        let replay_response = build_app(Arc::clone(&state))
            .oneshot(replay_request)
            .await
            .unwrap();
        let replay_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(replay_response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_ne!(replay_json["verdict"], "allow");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_trusts_configured_external_capability_issuers() {
        let signer = Keypair::generate();
        let external_signer = Keypair::generate();
        let agent = Keypair::generate();

        // A capability minted by an operator-configured external issuer.
        let issuer_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let issuer_nonce_store = build_mediation_nonce_store();
        let issuer = issuing_kernel(&external_signer, issuer_budget, issuer_nonce_store, &[]);
        let cap =
            issue_cost_bearing_capability(&issuer, &agent, "cost-srv", "compute", 100, 1000, "USD");
        let cap_value = serde_json::to_value(&cap).unwrap();

        // Trusting the external issuer: the mediated route authorizes the
        // preflight rather than rejecting the capability as untrusted.
        let trusting_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let trusting_state = mediated_test_state(
            signer.clone(),
            build_mediation_nonce_store(),
            trusting_budget,
            vec![external_signer.public_key()],
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": {}
        });
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        );
        let response = build_app(trusting_state).oneshot(request).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        // A trusted issuer's nonce-less request is authorized to the preflight
        // stage: a distinct "pending_nonce" status with a minted nonce, not a
        // completed "allow".
        assert_eq!(json["verdict"], "pending_nonce");
        assert!(json["execution_nonce"].is_object());

        // Control: without the configured issuer the same capability is denied,
        // proving the trust set is load-bearing.
        let untrusting_budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let untrusting_state = mediated_test_state(
            signer,
            build_mediation_nonce_store(),
            untrusting_budget,
            Vec::new(),
        );
        let body = serde_json::json!({
            "capability": cap_value,
            "tool_server": "cost-srv",
            "tool_name": "compute",
            "parameters": {}
        });
        let request = with_loopback_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/evaluate")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        );
        let response = build_app(untrusting_state).oneshot(request).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(json["verdict"], "deny");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mediated_deny_leaves_committed_cost_zero() {
        let signer = Keypair::generate();
        let agent = Keypair::generate();
        let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());
        let nonce_store = build_mediation_nonce_store();
        let kernel = issuing_kernel(&signer, Arc::clone(&budget), Arc::clone(&nonce_store), &[]);
        // max_cost_per_invocation (100) exceeds max_total_cost (40), so the
        // pre-execution hold is refused before the preflight check.
        let cap =
            issue_cost_bearing_capability(&kernel, &agent, "cost-srv", "compute", 100, 40, "USD");
        let cap_id = cap.id.clone();
        let state = mediated_test_state(
            signer,
            Arc::clone(&nonce_store),
            Arc::clone(&budget),
            Vec::new(),
        );
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
    fn mediation_kernel_installs_budget_store_and_strict_nonce_config() {
        let signer = Keypair::generate();
        let budget: Arc<dyn BudgetStore> =
            Arc::new(chio_kernel::budget_store::InMemoryBudgetStore::new());
        let kernel = build_mediation_kernel(
            &signer,
            Arc::clone(&budget),
            build_mediation_nonce_store(),
            &[],
            Vec::new(),
        )
        .unwrap();
        assert!(
            kernel.execution_nonce_required(),
            "mediation kernel must always run execution-nonce strict mode"
        );
    }
}
