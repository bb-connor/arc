use super::*;

use chio_core_types::capability::governance::{
    GovernedTransactionIntent, ThresholdApprovalProposal,
};
use chio_core_types::capability::supplemental_authorization::OpaqueSupplementalAuthorization;
use chio_kernel::budget_store::BudgetStore;
use chio_kernel::dpop::{DpopConfig, DpopNonceStore, DpopProof};
use chio_kernel::execution_nonce::{
    ExecutionNonceConfig, InMemoryExecutionNonceStore, SignedExecutionNonce,
};
use chio_kernel::{
    CallerExecutionReport, ChioKernel, KernelConfig, KernelError, ToolCallRequest,
    ToolInvocationCost, ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

#[path = "mediated/budget_configuration.rs"]
mod budget_configuration;
pub(crate) use budget_configuration::build_budget_store;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "mediated/tests.rs"]
mod tests;

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
    durable_admission: Option<DurableAdmissionStores>,
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
        // Durable admission binds every operation to a canonical SHA-256 policy
        // digest, so the mediation policy is named by its digest.
        policy_hash: chio_core_types::sha256_hex(b"chio_api_protect_mediation_v1"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        // A money-bearing mediated deployment should enable durable admission (the
        // durable receipt db path wired through evaluator.rs and proxy/state.rs) so
        // that an ambiguous post-dispatch outcome has its retained budget or payment
        // hold reconciled by the recovery sweep. The ephemeral log has no sweep, so
        // any hold retained on this non-durable kernel is surfaced instead by
        // chio_ambiguous_dispatch_retained_hold_total{reconciliation="none"}.
        allow_ephemeral_receipt_log: true,
        // Revocation is enforced sidecar-side over the durable revoked set (the
        // revoked-ancestor walk below); this kernel's internal store is
        // intentionally empty, so its durability gate must not deny mediation.
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    match durable_admission {
        Some(durable) => {
            // Durable operations, their preflight holds and their executable
            // holds share the authority's budget store; a separately configured
            // budget store cannot back a reservation the admission authority
            // owns.
            kernel.set_budget_store_handle(durable.budget_store);
            kernel
                .set_durable_admission_store(durable.store, durable.outcome_store, durable.fence)
                .map_err(|error| {
                    ProtectError::Config(format!(
                        "failed to install durable admission stores on the mediation kernel: {error}"
                    ))
                })?;
        }
        None => kernel.set_budget_store_handle(budget_store),
    }
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
        kernel.set_payment_adapter(payment_adapter);
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
    /// Reserved threshold approval fields. The mediated product does not yet
    /// configure a threshold policy resolver, so either field is rejected at the
    /// HTTP boundary instead of being advertised as an unusable kernel feature.
    #[serde(default)]
    approval_tokens: Vec<GovernedApprovalToken>,
    #[serde(default)]
    threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    /// Optional DPoP proof-of-possession. Forwarded so a grant carrying
    /// `dpop_required` can verify the proof instead of denying fail-closed.
    #[serde(default)]
    dpop_proof: Option<DpopProof>,
    /// Reserved opaque extension. The mediated product has no configured
    /// supplemental verifier, so presenting this field is rejected at the HTTP
    /// boundary.
    #[serde(default)]
    supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
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
    let mut parsed: SidecarEvaluateToolCallMediatedRequest =
        match serde_json::from_slice(&body_bytes) {
            Ok(parsed) => parsed,
            Err(error) => {
                return sidecar_bad_request(&format!("invalid mediated payload: {error}"))
                    .into_response();
            }
        };
    if parsed.supplemental_authorization.is_some() {
        return sidecar_bad_request(
            "supplemental_authorization is unavailable: no supplemental verifier is configured",
        )
        .into_response();
    }
    if !parsed.approval_tokens.is_empty() || parsed.threshold_approval_proposal.is_some() {
        return sidecar_bad_request(
            "threshold approvals are unavailable on the mediated endpoint: no threshold policy resolver is configured",
        )
        .into_response();
    }
    // This endpoint is a pre-execution authorization gate: it mints an execution
    // nonce for the caller to present downstream. It does not consume or settle a
    // presented nonce. Reject one fail-closed so a caller cannot mistake this for
    // a completion endpoint (and so the sidecar never consumes the downstream
    // nonce, which would make the real tool server reject the caller as a
    // replay).
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "mediated tool-call route requires a configured budget store (--control-url or --budget-db)",
        );
    };
    // Under durable admission the reservation is the operation's own and an
    // approved retry presents the nonce the strict preflight issued. The
    // legacy reservation mints nonces and never accepts one: a presented nonce
    // would be consumed here instead of by the tool server that expects it.
    let durable_reservation = mediation_kernel.lock().await.has_durable_admission_store();
    let presented_nonce = parsed.execution_nonce.take();
    if presented_nonce.is_some() && !durable_reservation {
        return sidecar_bad_request(
            "/v1/evaluate issues execution nonces; it does not accept a presented nonce. \
             Present the minted nonce to the tool server, not to this endpoint",
        )
        .into_response();
    }
    // A mediated reservation requires a hold-capable budget store. The remote
    // control-plane store forwards only charge/reverse/reconcile and rejects the
    // unsupported hold APIs, so a reservation minted against it could never
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
        // Only a durable approved retry presents a nonce; the legacy route
        // rejected one above, so it always takes the authorization-reserve path.
        execution_nonce: presented_nonce,
        governed_intent: parsed.governed_intent,
        approval_token: parsed.approval_token,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
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
        // Under durable admission the reservation is the operation's own: the
        // strict preflight issues the operation-bound nonce and the execution's
        // first half reserves the executable hold and the nonce until the
        // caller reconciles.
        let reserved = if durable_reservation {
            kernel.reserve_caller_execution_blocking(&kernel_request)
        } else {
            kernel.authorize_tool_call_reserving_blocking_with_metadata(&kernel_request, None)
        };
        match reserved {
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
        if kernel.has_durable_admission_store() {
            kernel.reconcile_caller_execution_blocking(
                &parsed.execution_nonce,
                &parsed.arguments,
                CallerExecutionReport {
                    output: serde_json::json!({
                        "caller_report": { "realized_cost": parsed.realized_cost }
                    }),
                    realized_cost: Some(parsed.realized_cost.clone()),
                },
            )
        } else {
            kernel.reconcile_reserved_authorization_by_nonce(
                &parsed.execution_nonce,
                &parsed.arguments,
                &parsed.realized_cost,
            )
        }
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
