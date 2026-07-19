use super::*;

use chio_core_types::capability::governance::GovernedTransactionIntent;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::dpop::{DpopConfig, DpopNonceStore, DpopProof};
use chio_kernel::execution_nonce::{
    ExecutionNonceConfig, InMemoryExecutionNonceStore, SignedExecutionNonce,
};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, ToolCallRequest, ToolInvocationCost,
    ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

/// A configured budget store together with whether it supports the pre-execution
/// hold APIs the mediated reservation path depends on.
///
/// The local SQLite store implements `get_budget_hold`, `mark_hold_reserved`, and
/// `reap_expired_reserved_holds`, so a reserved hold can be resolved by nonce on
/// `/v1/reconcile` and reclaimed by the TTL reaper. The remote control-plane
/// store forwards only charge/reverse/reconcile and falls back to the no-op trait
/// defaults for those hold APIs, so a reservation minted against it could never
/// be reconciled by nonce or reaped. Tracking hold-capability at the point of
/// construction lets the mediated routes fail closed rather than mint an
/// unreconcilable reserved nonce.
pub(crate) struct ConfiguredBudgetStore {
    pub(crate) store: Arc<dyn BudgetStore>,
    pub(crate) hold_capable: bool,
}

/// Build the sidecar's budget store, preferring the hold-capable local SQLite
/// store (`--budget-db`) over the remote control-plane store (`--control-url`)
/// when both are configured; falling back to the remote store; else `None` (the
/// mediated route then denies fail-closed).
///
/// Only the local SQLite store is hold-capable. The mediated authorization and
/// reconcile routes need a hold-capable store to persist and resolve a durable
/// reserved hold, so when both are configured the local store is chosen and
/// mediation keeps working; a remote-only deployment stays not hold-capable and
/// those routes reject fail-closed rather than mint an unreconcilable reserved
/// nonce.
pub(crate) fn build_budget_store(
    config: &ProtectConfig,
) -> Result<Option<ConfiguredBudgetStore>, ProtectError> {
    if let Some(path) = config.budget_db.as_deref() {
        let store = chio_store_sqlite::budget_store::SqliteBudgetStore::open(path)
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(ConfiguredBudgetStore {
            store: Arc::new(store),
            hold_capable: true,
        }));
    }
    if let Some(control_url) = config.control_url.as_deref() {
        let token = config.control_token.as_deref().unwrap_or("");
        let store =
            chio_control_plane::trust_control::service_runtime::budget::build_remote_budget_store(
                control_url,
                token,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(ConfiguredBudgetStore {
            store: Arc::from(store),
            hold_capable: false,
        }));
    }
    Ok(None)
}

/// Load the durable revocation store's revoked capability ids so operator
/// revocations recorded through `chio trust revoke --revocation-db <path>` are
/// enforced on `/v1/evaluate` and every other path that consults the sidecar's
/// revoked set. Returns an empty set when no revocation-db is configured.
///
/// Opening or reading a configured store that fails is fatal (fail-closed): the
/// caller must not start the sidecar advertising revocation enforcement it
/// cannot provide. The whole table is paged into memory once at startup;
/// revocations recorded after startup require a sidecar restart or the
/// in-process `/v1/capabilities/release` (or `--control-url`) channel.
pub(crate) fn load_revocation_db_ids(
    config: &ProtectConfig,
) -> Result<std::collections::HashSet<String>, ProtectError> {
    let Some(path) = config.revocation_db.as_deref() else {
        return Ok(std::collections::HashSet::new());
    };
    let store = chio_store_sqlite::SqliteRevocationStore::open(path).map_err(|error| {
        ProtectError::Config(format!("cannot open revocation-db `{path}`: {error}"))
    })?;

    const PAGE_SIZE: usize = 1024;
    let mut ids = std::collections::HashSet::new();
    let mut cursor: Option<(i64, String)> = None;
    loop {
        let (after_revoked_at, after_capability_id) = match &cursor {
            Some((revoked_at, capability_id)) => (Some(*revoked_at), Some(capability_id.as_str())),
            None => (None, None),
        };
        let page = store
            .list_revocations_after(PAGE_SIZE, after_revoked_at, after_capability_id)
            .map_err(|error| {
                ProtectError::Config(format!("cannot read revocation-db `{path}`: {error}"))
            })?;
        let page_len = page.len();
        for record in page {
            cursor = Some((record.revoked_at, record.capability_id.clone()));
            ids.insert(record.capability_id);
        }
        if page_len < PAGE_SIZE {
            break;
        }
    }
    Ok(ids)
}

/// Build a `ChioKernel` for tool-call mediation with the budget store, a strict
/// execution-nonce config, and DPoP verification state installed.
///
/// The mediated `/v1/evaluate` route is a PURE pre-execution authorization gate.
/// Strict execution-nonce mode is always on, so every request reaches the
/// authorization preflight: the kernel verifies the capability (plus any DPoP
/// proof, governed intent, and approval token), reserves the pre-execution
/// budget hold and KEEPS IT OPEN, and mints a fresh execution nonce. It never
/// dispatches a tool server, never consumes a presented nonce, and never signs
/// a completed or settled spend. The caller presents the minted nonce to the
/// real tool server, which verifies and consumes it and reconciles the reserved
/// hold at the execution site.
///
/// A SINGLE kernel is built once at sidecar startup and reused for the process
/// lifetime (held behind a `Mutex` in `ProxyState`). Reuse is load-bearing for
/// security: the kernel's approval-token replay store and DPoP-nonce store live
/// on the instance, so a per-request kernel would reset them every call and let
/// an approval token or DPoP proof be replayed within its TTL. One instance
/// keeps both replay stores authoritative across `/v1/evaluate` requests, and it
/// is the same nonce store that mints on `/v1/evaluate` and verifies+consumes on
/// `/v1/reconcile`, so a reconciled nonce cannot be replayed. The route never
/// registers the caller-named `server_id`: the reserve-for-caller authorization
/// path never dispatches a tool on this kernel and so no longer requires the
/// target to be registered, which keeps the kernel's tool-server map from
/// growing on every caller-arbitrary request.
///
/// `trusted_capability_issuers` are trusted as capability authorities in
/// addition to the sidecar signer, so an externally minted capability that the
/// sidecar's other endpoints accept is not rejected here as untrusted.
///
/// `payment_adapter` is the operator-configured payment rail. When present it is
/// installed on the kernel so a governed `MustPrepay` (x402/ACP) quote is
/// authorized and captured before the reserve-for-caller path mints a nonce.
/// When `None` the kernel carries no adapter, so the governed prepayment gate
/// denies `MustPrepay` fail-closed: only a configured adapter enables it.
pub(crate) fn build_mediation_kernel(
    signer: &Keypair,
    budget_store: Arc<dyn BudgetStore>,
    trusted_capability_issuers: &[PublicKey],
    tool_servers: Vec<Box<dyn ToolServerConnection>>,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
) -> Result<ChioKernel, ProtectError> {
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
        // Revocation is enforced sidecar-side over the durable revoked set (the
        // revoked-ancestor walk below); this kernel's internal store is
        // intentionally empty, so its durability gate must not deny mediation.
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        // The dispatch-intent payment journal is off on this reserve-only kernel.
        // Its money-path durability is the reserved-hold TTL reaper plus settle
        // by reconcile-by-nonce, not the in-process HoldPlaced -> Authorized ->
        // Settled journal that the dispatching kernels (`chio mcp serve`, `chio
        // run`) use: this kernel reserves a hold and mints a nonce but never
        // dispatches or settles in-process, so it never writes the HoldPlaced row
        // an Authorized advance would require. A MustPrepay prepayment is still
        // authorized through the adapter before a nonce is minted.
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    });
    kernel.set_budget_store_handle(budget_store);
    let nonce_cfg = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel.set_execution_nonce_store(
        nonce_cfg,
        Box::new(InMemoryExecutionNonceStore::from_config(
            &ExecutionNonceConfig::default(),
        )),
    );
    // Install DPoP verification state so a grant with `dpop_required` can verify
    // a presented proof. Without it every dpop_required capability denies
    // fail-closed with no way to present a proof.
    kernel.set_dpop_store(
        DpopNonceStore::new(
            DpopConfig::default().nonce_store_capacity,
            std::time::Duration::from_secs(DpopConfig::default().proof_ttl_secs),
        ),
        DpopConfig::default(),
    );
    // Install the operator's payment rail so the governed prepayment gate can
    // authorize and capture a MustPrepay (x402/ACP) quote before the
    // reserve-for-caller path mints a nonce. Absent an adapter the gate denies
    // MustPrepay fail-closed, so only a configured adapter enables prepayment.
    if let Some(payment_adapter) = payment_adapter {
        kernel
            .set_payment_adapter(payment_adapter)
            .map_err(|error| {
                ProtectError::Config(format!(
                    "failed to install payment adapter on the mediation kernel: {error}"
                ))
            })?;
    }
    for server in tool_servers {
        kernel.register_tool_server(server);
    }
    // Rebuild the delegated reserve-for-caller accounting from the durable budget
    // store. A delegated reservation keeps its child's sibling-sum share admitted
    // against the parent while its hold stays open, but that admission is
    // in-memory only, so a kernel built fresh over a populated store (a restart)
    // would otherwise admit a sibling against the parent as if the still-open
    // reservation consumed nothing. Since the durable hold record does not carry
    // the parent capability id or the shares needed to rebuild the reservation,
    // this arms a fail-closed gate that denies delegated admission while any such
    // hold from a prior process remains open. Fail-closed: a store read error here
    // aborts startup so the sidecar refuses to mediate over a store it could not
    // inspect.
    kernel
        .arm_restart_reserved_hold_gate()
        .map_err(|error| ProtectError::Config(error.to_string()))?;
    Ok(kernel)
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
    /// Optional caller-chosen request identifier. When present it is forwarded
    /// verbatim so the caller can bind a governed approval token to this exact
    /// request (the kernel requires `approval_token.request_id == request_id`).
    /// When absent the sidecar mints one; that is fine for capabilities that do
    /// not carry an approval-gated governed intent.
    #[serde(default)]
    request_id: Option<String>,
    /// Optional governed transaction intent bound to this invocation. Forwarded
    /// so a grant carrying `GovernedIntentRequired` (or an approval threshold)
    /// can be authorized instead of denied.
    #[serde(default)]
    governed_intent: Option<GovernedTransactionIntent>,
    /// Optional approval token authorizing this governed invocation, forwarded
    /// alongside `governed_intent` so an approval-gated grant can be authorized.
    #[serde(default)]
    approval_token: Option<GovernedApprovalToken>,
    /// Optional DPoP proof-of-possession. Forwarded so a grant carrying
    /// `dpop_required` can verify the proof instead of denying fail-closed.
    #[serde(default)]
    dpop_proof: Option<DpopProof>,
    /// A signed execution nonce. This endpoint MINTS nonces; it does not settle
    /// presented ones. The field is parsed only so a caller that mistakenly
    /// presents a nonce here is rejected explicitly (fail-closed) rather than
    /// having the nonce silently ignored.
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
    // This endpoint is a pre-execution authorization gate: it mints an execution
    // nonce for the caller to present downstream. It does not consume or settle a
    // presented nonce. Reject one fail-closed so a caller cannot mistake this for
    // a completion endpoint (and so the sidecar never consumes the downstream
    // nonce, which would make the real tool server reject the caller as a
    // replay).
    if parsed.execution_nonce.is_some() {
        return sidecar_bad_request(
            "/v1/evaluate issues execution nonces; it does not accept a presented nonce. \
             Present the minted nonce to the tool server, not to this endpoint",
        )
        .into_response();
    }
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "mediated tool-call route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    // A mediated reservation requires a hold-capable budget store. The remote
    // control-plane store forwards only charge/reverse/reconcile and falls back to
    // the no-op hold-API defaults, so a reservation minted against it could never
    // be reconciled by nonce or reclaimed by the TTL reaper. Reject fail-closed
    // rather than mint an unreconcilable reserved nonce.
    if !state.mediation_hold_capable {
        return internal_json_error_response(
            "chio_mediation_requires_local_budget_store",
            "mediated authorization requires a hold-capable local budget store (--budget-db); \
             a remote control-plane budget store (--control-url) cannot persist a reserved hold",
        );
    }
    // A reserved hold is settled only through `/v1/reconcile`, which the
    // reconcile control gate restricts to the trusted tool server presenting the
    // sidecar-control token. Without a configured token every reconcile is
    // rejected, so a reservation minted here could only expire and forfeit
    // budget. The reconcile gate trims the configured token and treats a
    // whitespace-only value as unconfigured, so an unconfigured OR blank token
    // is rejected here identically. Reject fail-closed before reserving budget or
    // minting a nonce, mirroring the reconcile gate's own configured-token
    // requirement.
    if state
        .sidecar_control_token
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return internal_json_error_response(
            "chio_mediation_requires_reconcile_token",
            "mediated authorization requires a configured sidecar-control token so the reserved \
             hold can be settled on /v1/reconcile; without one the reservation could only expire \
             and forfeit budget",
        );
    }
    // Fail-closed: reject the presented capability when its own id OR any ancestor
    // in its delegation chain is revoked, so a delegated child of a revoked root
    // cannot keep earning mediated reservations until expiry. `capability_is_revoked`
    // consults the in-memory release set first (no I/O for a known-revoked id) and
    // then the durable revocation store, failing closed if that store cannot be
    // read, so a revocation a sibling replica or `chio trust revoke --revocation-db`
    // recorded after this process booted is honored here exactly as it is on the
    // proxy and validate paths. The kernel's own revocation store starts empty, so
    // this sidecar-side walk is the authority.
    //
    // Bound the chain before the per-ancestor durable walk: the capability
    // signature is not verified until the kernel below, so cap the ancestors
    // consulted to keep an unverified, caller-supplied token from forcing one
    // durable store read per fabricated ancestor. A legitimate chain never
    // approaches this bound (the kernel caps delegation depth far under it) and a
    // longer one is rejected by the kernel regardless.
    const MAX_MEDIATED_DELEGATION_CHAIN: usize = 32;
    if parsed.capability.delegation_chain.len() > MAX_MEDIATED_DELEGATION_CHAIN {
        return sidecar_bad_request("capability delegation chain is too long").into_response();
    }
    let mut revoked = state.capability_is_revoked(&parsed.capability.id).await;
    if !revoked {
        for ancestor in &parsed.capability.delegation_chain {
            if state.capability_is_revoked(&ancestor.capability_id).await {
                revoked = true;
                break;
            }
        }
    }
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
    let agent_id = parsed
        .agent_id
        .unwrap_or_else(|| parsed.capability.subject.to_hex());
    let request_id = parsed
        .request_id
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    // Durable reuse guard that survives a restart, which the in-memory window
    // below cannot: after a restart the window is empty, but a reservation opened
    // before it persists as a budget hold. Rejecting the reuse fail-closed (409)
    // is load-bearing because a reused id would either collapse into an idempotent
    // authorize that mints a second nonce against one reservation without
    // reserving more budget, or (for a closed, settled-or-reaped hold) make the
    // kernel reject the duplicate hold id on creation and turn an otherwise valid
    // later authorization into a 500 instead of the documented bounded-reuse 409.
    let Some(budget_store) = state.budget_store.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_requires_local_budget_store",
            "mediated authorization requires a configured hold-capable budget store",
        );
    };
    // Bound the pre-verification durable lookup: the capability signature is
    // verified inside the kernel below, so cap the number of grants scanned to a
    // sane maximum and reject an oversized scope fail-closed, rather than fan out
    // one store read per grant for an unverified, caller-supplied capability.
    const MAX_MEDIATED_SCOPE_GRANTS: usize = 64;
    if parsed.capability.scope.grants.len() > MAX_MEDIATED_SCOPE_GRANTS {
        return sidecar_bad_request("capability scope carries too many grants").into_response();
    }
    // Prefer the capability-agnostic durable probe. The kernel derives each hold
    // id from (request_id, capability id, grant index), so the per-grant exact-id
    // lookup below only sees a reuse under the SAME capability: a caller that
    // replays this request_id under a DIFFERENT capability token would miss the
    // existing `budget-hold:{request_id}:{other_cap}:..` row and win a second
    // reservation once a restart cleared the in-memory window. When the store can
    // enumerate holds by the `budget-hold:{request_id}:` prefix it rejects the
    // reuse regardless of which capability opened the hold; when it cannot
    // (`Ok(None)`), fall back to the per-grant exact-id probe.
    match budget_store.request_id_has_reserved_hold(&request_id) {
        Ok(Some(true)) => {
            return (
                StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "error": "chio_request_id_reused",
                    "message": "request_id already backs a reservation; choose a fresh request_id",
                })),
            )
                .into_response();
        }
        Ok(Some(false)) => {}
        Ok(None) => {
            for grant_index in 0..parsed.capability.scope.grants.len() {
                let hold_id = format!(
                    "budget-hold:{}:{}:{}",
                    request_id, parsed.capability.id, grant_index
                );
                match budget_store.get_budget_hold(&hold_id) {
                    Ok(Some(_)) => {
                        return (
                            StatusCode::CONFLICT,
                            axum::Json(serde_json::json!({
                                "error": "chio_request_id_reused",
                                "message": "request_id already backs a reservation; choose a fresh request_id",
                            })),
                        )
                            .into_response();
                    }
                    Ok(None) => {}
                    Err(error) => {
                        warn!("durable hold lookup failed: {error}");
                        return internal_json_error_response(
                            "chio_mediation_failed",
                            &error.to_string(),
                        );
                    }
                }
            }
        }
        Err(error) => {
            warn!("durable hold lookup failed: {error}");
            return internal_json_error_response("chio_mediation_failed", &error.to_string());
        }
    }
    // Fail-closed over-subscription guard: the kernel derives the durable budget
    // hold identity from `request_id`, so a reused id inside a live reservation
    // window would collapse into an idempotent authorize with no fresh
    // reservation. Claim the id for this window before authorizing and reject a
    // reuse with 409. The claim is released below when the authorization places
    // no durable hold, so a denied or failed attempt does not permanently burn
    // the id; claimed ids expire with the reservation TTL, keeping the set
    // bounded.
    let now_unix = chrono::Utc::now().timestamp();
    if !state
        .minted_request_ids
        .lock()
        .await
        .claim(&request_id, now_unix)
    {
        return (
            StatusCode::CONFLICT,
            axum::Json(serde_json::json!({
                "error": "chio_request_id_reused",
                "message":
                    "request_id has already been used for a reservation; choose a fresh request_id",
            })),
        )
            .into_response();
    }
    let kernel_request = ToolCallRequest {
        request_id: request_id.clone(),
        capability: parsed.capability,
        tool_name: parsed.tool_name,
        server_id: parsed.tool_server,
        agent_id,
        arguments: parsed.parameters,
        dpop_proof: parsed.dpop_proof,
        // The route mints the nonce; it never forwards a presented one (rejected
        // above), so the kernel always takes the authorization-reserve path.
        execution_nonce: None,
        governed_intent: parsed.governed_intent,
        approval_token: parsed.approval_token,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    // Single-phase authorization on the shared, process-lifetime kernel: verify +
    // reserve the budget hold (kept open) + mint a fresh execution nonce. The
    // reserve-for-caller path never dispatches, so it does not require the
    // caller-named server to be registered; the route therefore never registers
    // it and holds the kernel behind a shared (non-mut) lock. No dispatch, no
    // reconcile, no settlement. The lock is released at the end of the block,
    // before any await, so authorizations serialize without holding the kernel
    // across receipt-persistence I/O.
    let response = {
        let kernel = mediation_kernel.lock().await;
        match kernel.authorize_tool_call_reserving_blocking_with_metadata(&kernel_request, None) {
            Ok(response) => response,
            Err(error) => {
                // The reservation did not open; release the claimed id so a
                // failed authorization does not permanently burn it.
                state.minted_request_ids.lock().await.release(&request_id);
                warn!("mediated authorization error: {error}");
                return internal_json_error_response("chio_mediation_failed", &error.to_string());
            }
        }
    };
    // Only a successful reservation (Verdict::Allow) keeps its request-id claim: a
    // denied or pending verdict placed no durable hold, so release the id to let
    // the caller retry it without a spurious 409.
    if !matches!(response.verdict, chio_kernel::Verdict::Allow) {
        state.minted_request_ids.lock().await.release(&request_id);
    }
    if let Err(error) = record_tool_receipt(&state, &response.receipt).await {
        // The reserve receipt persisted here is a local audit entry, not the
        // authoritative record. When the reserve SUCCEEDED (Verdict::Allow with a
        // minted nonce) the reservation is durable in the budget store and the
        // caller holds the signed nonce, which reconciles at /v1/reconcile (that
        // route persists its own authoritative receipt). Any governed MustPrepay
        // prepayment was already captured to back this exact reservation. Tearing
        // the reservation down here would refund nothing on the prepaid path (direct
        // financial loss) and strand the caller without the nonce it paid for, so
        // return the nonce and log the persistence failure, mirroring the accepted
        // /v1/reconcile behavior. A denied or pending verdict placed no hold and
        // minted no nonce, so its unpersisted receipt still fails closed.
        if !matches!(
            (&response.verdict, response.execution_nonce.as_deref()),
            (chio_kernel::Verdict::Allow, Some(_))
        ) {
            warn!("failed to persist mediated receipt: {error}");
            return internal_json_error_response(
                "chio_receipt_persistence_failed",
                &error.to_string(),
            );
        }
        warn!(
            "mediated reserve receipt persistence failed; returning minted nonce to caller: {error}"
        );
    }
    // A successful authorization is `Verdict::Allow` with an incomplete terminal
    // state (the tool has not run) and a minted nonce. It maps to the wire
    // status "authorized": the reserved hold enforces budget and the caller
    // presents the minted nonce to the real tool server. This route never
    // completes or settles a spend, so no wire status implies a completed spend.
    let status_str = match &response.verdict {
        chio_kernel::Verdict::Allow => "authorized",
        chio_kernel::Verdict::Deny => "deny",
        chio_kernel::Verdict::PendingApproval => "pending_approval",
    };
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": status_str,
            "receipt": response.receipt,
            "execution_nonce": response.execution_nonce,
        })),
    )
        .into_response()
}

/// `POST /v1/reconcile` request shape. The caller presents the execution nonce
/// minted by `/v1/evaluate`, the exact `arguments` that nonce authorized, and
/// the measured `realized_cost`. The kernel settles the reserved hold the nonce
/// names at `min(realized, reserved)` and returns an authoritative
/// mediated-spend receipt.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct SidecarReconcileRequest {
    execution_nonce: SignedExecutionNonce,
    #[serde(default)]
    arguments: serde_json::Value,
    realized_cost: ToolInvocationCost,
}

/// Settle a reserved authorization by the execution nonce that names its hold.
///
/// This route is gated by the reconcile control middleware: only the trusted
/// tool server, presenting the sidecar-control token, reconciles. The controlled
/// agent that called `/v1/evaluate` must not reach this endpoint, or it could
/// settle its own reservation at cost zero and defeat the cumulative spend cap.
///
/// The presented nonce is the credential: the shared kernel that minted it
/// verifies it (signature under the sidecar key, expiry, single-use replay),
/// settles the exact reserved hold at `min(realized, reserved)`, releases the
/// difference back to the grant, and signs a completed authoritative receipt.
/// The `realized_cost` is the tool server's own report of what the call cost;
/// binding it to an attested oracle cost is a later concern. Fail-closed: a
/// forged, tampered, replayed, or argument-mismatched nonce, or a hold that is
/// already closed, is rejected with a 4xx and never settles.
pub(crate) async fn sidecar_reconcile_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read reconcile body: {error}");
            return sidecar_bad_request("failed to read reconcile body").into_response();
        }
    };
    let parsed: SidecarReconcileRequest = match serde_json::from_slice(&body_bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            return sidecar_bad_request(&format!("invalid reconcile payload: {error}"))
                .into_response();
        }
    };
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "reconcile route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    // A reserved hold can only be resolved by nonce when the budget store
    // implements the hold APIs. The remote control-plane store cannot, so a
    // reconcile against it could never settle the reserved hold the nonce names.
    // Reject fail-closed rather than attempt a settle that cannot succeed.
    if !state.mediation_hold_capable {
        return internal_json_error_response(
            "chio_mediation_requires_local_budget_store",
            "mediated reconcile requires a hold-capable local budget store (--budget-db); \
             a remote control-plane budget store (--control-url) cannot resolve a reserved hold",
        );
    }
    // Settle on the shared kernel. The same instance minted the nonce, so its
    // execution-nonce store is the single-use authority here: a forged, tampered,
    // or already-reconciled nonce is rejected. The lock releases at the end of
    // the block, before receipt-persistence I/O.
    let reconciled = {
        let kernel = mediation_kernel.lock().await;
        kernel.reconcile_reserved_authorization_by_nonce(
            &parsed.execution_nonce,
            &parsed.arguments,
            &parsed.realized_cost,
        )
    };
    let reconciled = match reconciled {
        Ok(response) => response,
        Err(error) => {
            warn!("reconcile rejected: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "chio_reconcile_rejected",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    // The settle already consumed the nonce and closed the reserved hold, and that
    // is irreversible: a retry cannot recreate this authoritative receipt. If
    // durable persistence then fails, returning 500 would discard the only proof
    // of a settled spend, leaving the tool server and operator audit with nothing
    // to reconcile against. Log the failure and return the signed receipt so the
    // caller can persist or retry it. This is the opposite of /v1/evaluate, whose
    // reservation is still open and reversible when persistence fails; here the
    // spend is done, so the receipt must reach the caller.
    if let Err(error) = record_tool_receipt(&state, &reconciled.receipt).await {
        warn!("reconcile settled but receipt persistence failed; returning authoritative receipt to caller: {error}");
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": "reconciled",
            "receipt": reconciled.receipt,
        })),
    )
        .into_response()
}

/// Release expired, unreconciled reserved budget holds on the shared kernel so a
/// caller that authorizes but never reconciles cannot permanently burn budget.
/// Returns the number of holds released; a sidecar without a configured budget
/// store (no mediation kernel) releases nothing. Factored out of the startup
/// interval task so it is directly unit-testable with a controlled clock.
pub(crate) async fn reap_expired_reserved_holds_once(
    state: &Arc<ProxyState>,
    now_unix_secs: i64,
) -> Result<usize, KernelError> {
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return Ok(0);
    };
    let kernel = mediation_kernel.lock().await;
    kernel.reap_expired_reserved_budget_holds(now_unix_secs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{BudgetStore, InMemoryBudgetStore};
    use chio_test_support::prelude::*;
    use tower::ServiceExt;

    /// Build an ephemeral kernel used only to mint capabilities in tests. It
    /// shares the budget store with the state's mediation kernel; cost is never
    /// resolved through an injected tool server, so capabilities carry their own
    /// monetary constraints.
    fn issuing_kernel(
        signer: &Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: &[PublicKey],
    ) -> Arc<ChioKernel> {
        Arc::new(
            build_mediation_kernel(signer, budget, trusted_capability_issuers, Vec::new(), None)
                .test_unwrap(),
        )
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

    /// Issue a capability whose single grant caps invocations only, with no
    /// monetary ceiling. The mediated reserve path debits an invocation but
    /// authorizes no monetary hold, so its reversal on tear-down and TTL reap is
    /// exercised separately from the monetary reserve.
    fn issue_invocation_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_invocations: u32,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(max_invocations),
            max_cost_per_invocation: None,
            max_total_cost: None,
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

    /// Control token the mediated test state configures so `/v1/reconcile`, now
    /// behind the reconcile control gate, admits the trusted tool server that
    /// presents it. `/v1/evaluate` is not gated, so evaluate tests are unaffected.
    const MEDIATED_CONTROL_TOKEN: &str = "tool-server-control-token";

    /// Build proxy state for the mediated route with the standard reconcile
    /// control token configured.
    fn mediated_test_state(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Arc<ProxyState> {
        mediated_test_state_with_control_token(
            signer,
            budget,
            trusted_capability_issuers,
            Some(MEDIATED_CONTROL_TOKEN.to_string()),
        )
    }

    /// Build proxy state for the mediated route. `signer` is the sidecar signer
    /// the shared mediation kernel is built from (so capabilities minted by it
    /// are trusted), and `trusted_capability_issuers` are additional external
    /// issuers to trust. `sidecar_control_token` gates `/v1/reconcile`; `None`
    /// leaves the sidecar with no configured token, so reconcile fails closed.
    fn mediated_test_state_with_control_token(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
    ) -> Arc<ProxyState> {
        // The default in-memory budget store implements the hold APIs, so it is
        // treated as hold-capable (matching a local `--budget-db` deployment).
        mediated_test_state_inner(
            signer,
            budget,
            trusted_capability_issuers,
            sidecar_control_token,
            None,
            true,
        )
    }

    /// Build proxy state for the mediated route with an explicit hold-capability
    /// flag. `hold_capable == false` models a remote `--control-url` budget store
    /// whose hold APIs fall back to the no-op trait defaults, so the mediated
    /// routes must fail closed rather than mint an unreconcilable reserved nonce.
    fn mediated_test_state_inner(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
        receipt_store: Option<SqliteReceiptStore>,
        hold_capable: bool,
    ) -> Arc<ProxyState> {
        // No payment adapter by default, so governed MustPrepay stays denied
        // fail-closed; the prepayment tests build the mediation kernel with one.
        mediated_test_state_core(
            signer,
            budget,
            trusted_capability_issuers,
            sidecar_control_token,
            receipt_store,
            hold_capable,
            None,
            None,
        )
    }

    /// Build proxy state for the mediated route with an explicit payment adapter
    /// for the shared mediation kernel. A configured adapter lets an approved
    /// governed `MustPrepay` request authorize (the quote is prepaid before a
    /// reserved nonce is minted); `None` keeps it denied fail-closed.
    #[allow(clippy::too_many_arguments)]
    fn mediated_test_state_core(
        signer: Keypair,
        budget: Arc<dyn BudgetStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        sidecar_control_token: Option<String>,
        receipt_store: Option<SqliteReceiptStore>,
        hold_capable: bool,
        payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
        revocation_store: Option<Arc<dyn chio_kernel::RevocationStore>>,
    ) -> Arc<ProxyState> {
        let approval_store: Arc<dyn ApprovalStore> = Arc::new(InMemoryApprovalStore::new());
        let signer_public_key = signer.public_key();
        let mut trusted_capability_issuers = trusted_capability_issuers;
        if !trusted_capability_issuers.contains(&signer_public_key) {
            trusted_capability_issuers.push(signer_public_key.clone());
        }
        let trusted_receipt_signers = vec![signer_public_key];
        let evaluator = RequestEvaluator::new_ephemeral_with_approval_store(
            Vec::new(),
            signer.clone(),
            "test-policy".to_string(),
            Arc::clone(&approval_store),
        );
        let egress_contract = default_upstream_egress_contract("http://127.0.0.1:1").test_unwrap();
        let http_client = client_builder_with_contract(&egress_contract)
            .build()
            .test_unwrap();
        // One shared mediation kernel for the process, matching production wiring:
        // reuse keeps the approval-token and DPoP replay stores authoritative and
        // makes the nonce minted on `/v1/evaluate` the one settled on
        // `/v1/reconcile`.
        let mediation_kernel = Mutex::new(
            build_mediation_kernel(
                &signer,
                Arc::clone(&budget),
                &trusted_capability_issuers,
                Vec::new(),
                payment_adapter,
            )
            .test_unwrap(),
        );
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
            receipt_store: receipt_store.map(Mutex::new),
            revocation_store,
            revoked_capability_ids: Mutex::new(std::collections::HashSet::new()),
            trusted_capability_issuers,
            trusted_receipt_signers,
            sidecar_control_token,
            budget_store: Some(budget),
            mediation_hold_capable: hold_capable,
            mediation_kernel: Some(mediation_kernel),
            minted_request_ids: Mutex::new(MintedRequestIdWindow::new(
                chio_kernel::DEFAULT_EXECUTION_NONCE_TTL_SECS,
            )),
            reaper_handle: Mutex::new(None),
            allow_advisory: false,
            receipt_backend: "ephemeral",
            revocation_backend: "ephemeral",
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

    // --- Scaffolding for governed and DPoP authorization tests ---

    use chio_core_types::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedTransactionIntent, MeteredBillingContext, MeteredBillingQuote,
        MeteredSettlementMode,
    };
    use chio_core_types::capability::scope::{Constraint, MonetaryAmount};
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;
    use chio_kernel::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};

    fn issue_governed_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        currency: &str,
        approval_threshold_units: u64,
    ) -> CapabilityToken {
        let grant = ToolGrant {
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![
                Constraint::GovernedIntentRequired,
                Constraint::RequireApprovalAbove {
                    threshold_units: approval_threshold_units,
                },
            ],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: max_per,
                currency: currency.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: max_per,
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

    fn issue_dpop_capability(
        kernel: &Arc<ChioKernel>,
        agent: &Keypair,
        server: &str,
        tool: &str,
        max_per: u64,
        currency: &str,
    ) -> CapabilityToken {
        issue_dpop_capability_with_total(kernel, agent, server, tool, max_per, max_per, currency)
    }

    fn issue_dpop_capability_with_total(
        kernel: &Arc<ChioKernel>,
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
            dpop_required: Some(true),
        };
        let scope = ChioScope {
            grants: vec![grant],
            ..ChioScope::default()
        };
        kernel
            .issue_capability(&agent.public_key(), scope, 3600)
            .test_unwrap()
    }

    fn governed_intent(
        id: &str,
        server: &str,
        tool: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: id.to_string(),
            server_id: server.to_string(),
            tool_name: tool.to_string(),
            purpose: "invoice-settlement".to_string(),
            max_amount: Some(MonetaryAmount {
                units,
                currency: currency.to_string(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
        }
    }

    /// A governed intent that mandates prepayment: it carries a metered-billing
    /// context in `MustPrepay` settlement mode with a quote for `units`. The
    /// kernel denies it unless a payment adapter is configured to prepay the
    /// quote before the reserve-for-caller path mints a nonce.
    fn governed_mustprepay_intent(
        id: &str,
        server: &str,
        tool: &str,
        units: u64,
        currency: &str,
    ) -> GovernedTransactionIntent {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        let mut intent = governed_intent(id, server, tool, units, currency);
        intent.metered_billing = Some(MeteredBillingContext {
            settlement_mode: MeteredSettlementMode::MustPrepay,
            quote: MeteredBillingQuote {
                quote_id: format!("quote-{id}"),
                provider: "billing.chio".to_string(),
                billing_unit: "call".to_string(),
                quoted_units: 1,
                quoted_cost: MonetaryAmount {
                    units,
                    currency: currency.to_string(),
                },
                issued_at: now.saturating_sub(5),
                expires_at: Some(now + 300),
            },
            max_billed_units: Some(2),
        });
        intent
    }

    fn governed_approval_token(
        approver: &Keypair,
        subject: &PublicKey,
        intent: &GovernedTransactionIntent,
        request_id: &str,
    ) -> GovernedApprovalToken {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: format!("approval-{request_id}"),
                approver: approver.public_key(),
                subject: subject.clone(),
                governed_intent_hash: intent.binding_hash().test_unwrap(),
                request_id: request_id.to_string(),
                issued_at: now.saturating_sub(1),
                expires_at: now + 300,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .test_unwrap()
    }

    fn dpop_proof_for(
        agent: &Keypair,
        cap: &CapabilityToken,
        server: &str,
        tool: &str,
        parameters: &serde_json::Value,
    ) -> DpopProof {
        // Match the kernel's action-hash computation exactly: SHA-256 hex over
        // the canonical JSON of the tool arguments.
        let args_bytes = chio_core_types::canonical::canonical_json_bytes(parameters).test_unwrap();
        let action_hash = chio_core_types::crypto::sha256_hex(&args_bytes);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .test_unwrap()
            .as_secs();
        DpopProof::sign(
            DpopProofBody {
                schema: DPOP_SCHEMA.to_string(),
                capability_id: cap.id.clone(),
                tool_server: server.to_string(),
                tool_name: tool.to_string(),
                action_hash,
                nonce: uuid::Uuid::now_v7().to_string(),
                issued_at: now,
                agent_key: agent.public_key(),
            },
            agent,
        )
        .test_unwrap()
    }

    /// POST a body to `/v1/evaluate` and return the status and parsed JSON.
    async fn post_evaluate(
        state: Arc<ProxyState>,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json(state, "/v1/evaluate", body).await
    }

    /// POST a body to `/v1/reconcile` presenting the standard control token, so
    /// the reconcile control gate admits it, and return the status and JSON.
    async fn post_reconcile(
        state: Arc<ProxyState>,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json_with_bearer(state, "/v1/reconcile", body, Some(MEDIATED_CONTROL_TOKEN)).await
    }

    async fn post_json(
        state: Arc<ProxyState>,
        uri: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        post_json_with_bearer(state, uri, body, None).await
    }

    async fn post_json_with_bearer(
        state: Arc<ProxyState>,
        uri: &str,
        body: &serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header("authorization", format!("Bearer {bearer}"));
        }
        let request = with_loopback_peer(
            builder
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        );
        let response = build_app(state).oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    include!("mediated_authorization_tests.rs");
    include!("mediated_persistence_tests.rs");
}
