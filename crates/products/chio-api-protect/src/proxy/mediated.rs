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
    ChioKernel, KernelConfig, ToolCallRequest, ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};

#[path = "mediated/authenticated.rs"]
pub(crate) mod authenticated;
#[path = "mediated/budget_configuration.rs"]
mod budget_configuration;
pub(crate) use budget_configuration::{build_budget_store, MediationBudget};
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

/// Capability authorities, policy identity, and receipt storage for mediation.
pub(crate) struct MediationPolicy<'a> {
    pub issuers: &'a [PublicKey],
    pub hash: Option<&'a str>,
    pub receipt_store: Option<Arc<dyn chio_kernel::ReceiptStore>>,
}

pub(crate) fn build_mediation_kernel(
    signer: &Keypair,
    budget: MediationBudget,
    policy: MediationPolicy<'_>,
    tool_servers: Vec<Box<dyn ToolServerConnection>>,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    clock: Arc<dyn chio_security_types::clock::Clock>,
) -> Result<ChioKernel, ProtectError> {
    let mut ca_public_keys = vec![signer.public_key()];
    for issuer in policy.issuers {
        if !ca_public_keys.contains(issuer) {
            ca_public_keys.push(issuer.clone());
        }
    }
    // HTTP mediation and durable admission share one policy identity.
    let policy_hash = match policy.hash {
        Some(hash) => hash.to_owned(),
        None => {
            let material = chio_core_types::canonical::canonical_json_bytes(&(
                "chio-api-protect-mediation-v2",
                chio_guards::default_runtime_guard_profile_identity()?,
            ))?;
            chio_core_types::sha256_hex(&material)
        }
    };
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: signer.clone(),
            ca_public_keys,
            max_delegation_depth: 5,
            // Durable admission binds every operation to a canonical SHA-256 policy
            // digest, so the mediation policy is named by its digest.
            policy_hash,
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            // Signed caller delivery requires a separate durable admission authority.
            allow_ephemeral_receipt_log: policy.receipt_store.is_none(),
            // The sidecar checks the durable revocation store before admission.
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        },
        clock.clone(),
    );
    let default_guard_profile = chio_guards::default_runtime_guard_profile();
    for guard in default_guard_profile.pre_invocation_guards {
        kernel.add_guard(guard);
    }
    kernel.set_post_invocation_pipeline(default_guard_profile.post_invocation_pipeline);
    if let Some(store) = policy.receipt_store {
        kernel
            .set_receipt_store_handle(store)
            .map_err(|error| ProtectError::Config(error.to_string()))?;
    }
    match budget {
        MediationBudget::Durable(durable) => {
            kernel.set_budget_store_handle(durable.budget_store);
            kernel
                .set_durable_admission_store(durable.store, durable.outcome_store, durable.fence)
                .map_err(|error| {
                    ProtectError::Config(format!(
                        "failed to install durable admission stores on the mediation kernel: {error}"
                    ))
                })?;
        }
        MediationBudget::Configured(store) => kernel.set_budget_store_handle(store),
    }
    let nonce_cfg = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel.set_execution_nonce_store(
        nonce_cfg,
        Box::new(InMemoryExecutionNonceStore::with_clock(
            ExecutionNonceConfig::default().nonce_store_capacity,
            clock.clone(),
        )),
    );
    // Credential-bearing caller execution also requires operation-owned custody.
    kernel
        .set_dpop_store(
            DpopNonceStore::with_clock(
                DpopConfig::default().nonce_store_capacity,
                DpopConfig::default().nonce_store_capacity,
                chio_kernel::dpop::DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
                std::time::Duration::from_secs(DpopConfig::default().proof_ttl_secs),
                clock,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?,
            DpopConfig::default(),
        )
        .map_err(|error| ProtectError::Config(error.to_string()))?;
    // The configured rail settles only after the caller commits a signed start.
    if let Some(payment_adapter) = payment_adapter {
        kernel.set_payment_adapter(payment_adapter);
    }
    for server in tool_servers {
        kernel.register_tool_server(server);
    }
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
    /// Optional caller request identity. With approval_id it must equal that
    /// server-owned identity; otherwise the sidecar generates one when omitted.
    #[serde(default)]
    request_id: Option<String>,
    /// Governed transaction intent bound to this invocation.
    #[serde(default)]
    governed_intent: Option<GovernedTransactionIntent>,
    /// Direct token presentations are rejected; `approval_id` selects retained authority.
    #[serde(default)]
    approval_token: Option<GovernedApprovalToken>,
    /// Server-assigned identifier of a retained, signed approval.
    #[serde(default)]
    approval_id: Option<String>,
    /// Threshold credentials are rejected without a configured policy resolver.
    #[serde(default)]
    approval_tokens: Vec<GovernedApprovalToken>,
    #[serde(default)]
    threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    /// DPoP proof; caller execution requires operation-owned proof custody.
    #[serde(default)]
    dpop_proof: Option<DpopProof>,
    /// Reserved opaque extension. The mediated product has no configured
    /// supplemental verifier, so presenting this field is rejected at the HTTP
    /// boundary.
    #[serde(default)]
    supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
    /// Signed nonce identifying the retained operation for an approved retry.
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
        match input::decode_arguments(&body_bytes, input::MAX_BODY_BYTES) {
            Ok(parsed) => parsed,
            Err(error) => return input::rejected(error),
        };
    if parsed.approval_token.is_some()
        || (parsed.approval_id.is_some() && parsed.governed_intent.is_some())
    {
        return sidecar_bad_request("use approval_id to redeem the retained server-built approval")
            .into_response();
    }
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
    let Some(mediation_kernel) = state.mediation_kernel.as_ref() else {
        return internal_json_error_response(
            "chio_mediation_unavailable",
            "mediated tool-call route requires a durable admission store",
        );
    };
    // The kernel mutex serializes request binding, reservation, and claim cleanup.
    let kernel = mediation_kernel.lock().await;
    if !kernel.has_durable_admission_store() {
        return internal_json_error_response(
            "chio_mediation_requires_durable_admission",
            "mediated authorization requires a durable admission store",
        );
    }
    let presented_nonce = parsed.execution_nonce.take();
    // A reservation requires access to the authenticated start and report routes.
    if state
        .sidecar_control_token
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return internal_json_error_response(
            "chio_mediation_requires_control_token",
            "mediated authorization requires a configured sidecar-control token for signed caller delivery",
        );
    }
    // Cap unverified ancestry before durable revocation reads.
    // Revocation of any ancestor invalidates the delegated capability.
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
        .clone()
        .or_else(|| parsed.approval_id.clone())
        .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
    // Bound the unverified capability before admission.
    const MAX_MEDIATED_SCOPE_GRANTS: usize = 64;
    if parsed.capability.scope.grants.len() > MAX_MEDIATED_SCOPE_GRANTS {
        return sidecar_bad_request("capability scope carries too many grants").into_response();
    }
    // The bounded window limits outstanding request identities. Presented nonces
    // borrow existing entries until durable admission verifies their exact binding.
    let now_unix = match state.clock.signed_seconds() {
        Ok(now) => now,
        Err(error) => return clock::rejection(error),
    };
    let request_claim = match state.minted_request_ids.lock().await.claim(
        &request_id,
        now_unix,
        presented_nonce.is_some(),
    ) {
        Ok(claim) => claim,
        Err(error) => {
            let status = match error {
                RequestIdClaimError::Reused => StatusCode::CONFLICT,
                RequestIdClaimError::Shape => StatusCode::BAD_REQUEST,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            return input::with_source(
                (
                    status,
                    axum::Json(serde_json::json!({"error": error.to_string()})),
                )
                    .into_response(),
                error,
            );
        }
    };
    let mut kernel_request = ToolCallRequest {
        request_id: request_id.clone(),
        capability: parsed.capability,
        tool_name: parsed.tool_name,
        server_id: parsed.tool_server,
        agent_id,
        arguments: parsed.parameters,
        dpop_proof: parsed.dpop_proof,
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
    if let Some(approval_id) = parsed.approval_id.as_deref() {
        if let Err(error) =
            super::approval::redeem_approval(&state, &kernel, &mut kernel_request, approval_id)
        {
            state
                .minted_request_ids
                .lock()
                .await
                .release(&request_claim);
            return approval_error_response(error);
        }
    }
    // Reservation binds the nonce and budget to one retained operation.
    let response = {
        let reserved = kernel.reserve_caller_execution_blocking(&kernel_request);
        match reserved {
            Ok(response) => response,
            Err(error) => {
                // The reservation did not open; release the claimed id so a
                // failed authorization does not permanently burn it.
                state
                    .minted_request_ids
                    .lock()
                    .await
                    .release(&request_claim);
                warn!("mediated authorization error: {error}");
                return internal_json_error_response("chio_mediation_failed", &error.to_string());
            }
        }
    };
    // Failed candidates cannot release borrowed custody or extend its horizon.
    if matches!(response.verdict, chio_kernel::Verdict::Allow) {
        if let Some(nonce) = response.execution_nonce.as_deref() {
            state
                .minted_request_ids
                .lock()
                .await
                .retain_until(&request_claim, nonce.nonce.expires_at);
        }
    } else {
        state
            .minted_request_ids
            .lock()
            .await
            .release(&request_claim);
    }
    drop(kernel);
    // Kernel delivery is idempotent on the shared sink. An irreversible reserve
    // may return its signed nonce after an append failure; retry persistence and
    // report that outcome without discarding the caller's only recovery evidence.
    let persistence = record_kernel_receipt(&state, &response.receipt).await;
    let evidence_persisted = state.receipt_store.is_some() && persistence.is_ok();
    if let Err(error) = persistence {
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
    // Execution requires a committed statement and a durable executor claim.
    let status_str = match &response.verdict {
        chio_kernel::Verdict::Allow => "reserved",
        chio_kernel::Verdict::Deny => "deny",
        chio_kernel::Verdict::PendingApproval => "pending_approval",
    };
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": status_str,
            "evidence_persisted": evidence_persisted,
            "protocol": "chio.caller-delivery.v1",
            "execution_authorized": false,
            "start_required": matches!(response.verdict, chio_kernel::Verdict::Allow),
            "receipt": response.receipt,
            "execution_nonce": response.execution_nonce,
        })),
    )
        .into_response()
}
