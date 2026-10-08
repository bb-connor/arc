use super::*;

pub(crate) async fn list_pending_approvals_handler(
    State(state): State<Arc<ProxyState>>,
    Query(query): Query<PendingQuery>,
) -> Response {
    match approval_blocking(&state, move |state| {
        handle_list_pending(&state.approval_admin, query)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn get_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
) -> Response {
    match approval_blocking(&state, move |state| {
        handle_get_approval(&state.approval_admin, &approval_id)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn respond_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
    request: Request<Body>,
) -> Response {
    let body: RespondRequest = match read_body(request, input::decode).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    if let Err(error) = require_current_approver(&state, &approval_id, &body.approver).await {
        return approval_error_response(error);
    }
    match approval_blocking(&state, move |state| {
        handle_respond(&state.approval_admin, &approval_id, body, now)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn batch_respond_approvals_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let body: BatchRespondRequest = match read_body(request, input::decode).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    for entry in &body.decisions {
        if let Err(error) =
            require_current_approver(&state, &entry.approval_id, &entry.approver).await
        {
            return approval_error_response(error);
        }
    }
    match approval_blocking(&state, move |state| {
        handle_batch_respond(&state.approval_admin, body, now)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn create_threshold_proposal_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let body: CreateThresholdProposalRequest = match read_body(request, input::decode).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    match approval_blocking(&state, move |state| {
        handle_create_threshold_proposal(&state.approval_admin, body, now)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::CREATED, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn get_threshold_proposal_handler(
    State(state): State<Arc<ProxyState>>,
    Path(proposal_id): Path<String>,
) -> Response {
    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    match approval_blocking(&state, move |state| {
        handle_get_threshold_proposal(&state.approval_admin, &proposal_id, now)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn submit_threshold_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(proposal_id): Path<String>,
    request: Request<Body>,
) -> Response {
    let body: SubmitThresholdApprovalRequest = match read_body(request, input::decode).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    match approval_blocking(&state, move |state| {
        handle_submit_threshold_approval(&state.approval_admin, &proposal_id, body, now)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn deliver_threshold_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(proposal_id): Path<String>,
) -> Response {
    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    match approval_blocking(&state, move |state| {
        handle_deliver_threshold_approval(&state.approval_admin, &proposal_id, now)
    })
    .await
    {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

/// The server owns request identity and computes the complete intent binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitApprovalRequest {
    capability: CapabilityToken,
    tool_server: String,
    tool_name: String,
    parameters: serde_json::Value,
    requested_by: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    ttl_seconds: u64,
    #[serde(default)]
    triggered_by: Vec<String>,
    #[serde(default)]
    governed_intent: Option<chio_core_types::capability::governance::GovernedTransactionIntent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SubmitApprovalResponse {
    approval_id: String,
    expires_at: u64,
    created_at: u64,
    trusted_approvers: Vec<String>,
}

#[allow(clippy::result_large_err)]
pub(crate) async fn submit_approval_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let body: SubmitApprovalRequest = match read_body(request, input::decode_arguments).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let subject = match PublicKey::from_hex(&body.requested_by) {
        Ok(subject) if subject == body.capability.subject => subject,
        _ => {
            return approval_error_response(ApprovalHandlerError::BadRequest(
                "requested_by must be the capability subject public key".into(),
            ))
        }
    };
    let Some(config) = &state.approval_config else {
        return approval_error_response(ApprovalHandlerError::Rejected(
            "approval authority is not configured".into(),
        ));
    };
    let Some(kernel) = &state.mediation_kernel else {
        return approval_error_response(ApprovalHandlerError::Rejected(
            "approval admission is unavailable".into(),
        ));
    };
    if state.capability_is_revoked(&body.capability.id).await {
        return approval_error_response(ApprovalHandlerError::Rejected(
            "approval capability is revoked".into(),
        ));
    }
    let approval_id = format!("ap-{}", uuid::Uuid::now_v7());
    let approvers = config.approvers.clone();
    let kernel = Arc::clone(kernel);
    let submitted = blocking(move || {
        retain_submitted_approval(&state, &kernel, body, subject, approval_id, approvers)
    })
    .await;
    match submitted {
        Ok(Ok(response)) => approval_json(StatusCode::CREATED, response),
        Ok(Err(rejection)) => rejection,
        Err(WorkerFailed) => approval_error_response(ApprovalHandlerError::Internal(
            "approval worker did not complete".into(),
        )),
    }
}

/// Bind the exact invocation intent on the shared kernel and retain the pending
/// approval. Runs on the blocking pool.
#[allow(clippy::result_large_err)]
fn retain_submitted_approval(
    state: &ProxyState,
    kernel: &chio_kernel::ChioKernel,
    body: SubmitApprovalRequest,
    subject: PublicKey,
    approval_id: String,
    approvers: Vec<PublicKey>,
) -> Result<SubmitApprovalResponse, Response> {
    let request = chio_kernel::ToolCallRequest {
        request_id: approval_id.clone(),
        capability: body.capability,
        server_id: body.tool_server,
        tool_name: body.tool_name,
        arguments: body.parameters,
        agent_id: subject.to_hex(),
        governed_intent: body.governed_intent,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        dpop_proof: None,
        execution_nonce: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let intent = kernel
        .bind_tool_approval_intent(&request)
        .map_err(|error| {
            approval_error_response(ApprovalHandlerError::Rejected(error.to_string()))
        })?;
    let now = state.clock.seconds().map_err(clock::rejection)?;
    let ttl = if body.ttl_seconds == 0 {
        3600
    } else {
        body.ttl_seconds.min(3600)
    };
    let expires_at = now.saturating_add(ttl).min(request.capability.expires_at);
    let parameter_hash = intent.binding_hash().map_err(|error| {
        approval_error_response(ApprovalHandlerError::Rejected(error.to_string()))
    })?;
    let approval = ApprovalRequest {
        approval_id: approval_id.clone(),
        policy_id: kernel.policy_hash().to_owned(),
        subject_id: request.agent_id,
        capability_id: request.capability.id,
        subject_public_key: Some(subject),
        tool_server: request.server_id,
        tool_name: request.tool_name,
        action: "invoke".into(),
        parameter_hash,
        expires_at,
        created_at: now,
        callback_hint: None,
        summary: body
            .summary
            .unwrap_or_else(|| "exact tool invocation".into()),
        governed_intent: Some(intent),
        trusted_approvers: approvers.clone(),
        triggered_by: body.triggered_by,
    };
    state
        .approval_admin
        .store()
        .store_pending(&approval)
        .map_err(|error| approval_error_response(error.into()))?;
    Ok(SubmitApprovalResponse {
        approval_id,
        expires_at,
        created_at: now,
        trusted_approvers: approvers.iter().map(PublicKey::to_hex).collect(),
    })
}

/// The compatibility route requires the same signer-authenticated response.
/// A bearer credential alone never authorizes the sidecar to mint approval.
pub(crate) async fn operator_respond_approval_handler(
    state: State<Arc<ProxyState>>,
    path: Path<String>,
    request: Request<Body>,
) -> Response {
    respond_approval_handler(state, path, request).await
}

async fn require_current_approver(
    state: &Arc<ProxyState>,
    approval_id: &str,
    approver: &PublicKey,
) -> Result<(), ApprovalHandlerError> {
    let config = state.approval_config.as_ref().ok_or_else(|| {
        ApprovalHandlerError::Rejected("approval authority is not configured".into())
    })?;
    if !config.approvers.contains(approver) {
        return Err(ApprovalHandlerError::Rejected(
            "approval signer is not in configured roster".into(),
        ));
    }
    let pending = {
        let approval_id = approval_id.to_owned();
        approval_blocking(state, move |state| {
            Ok(state.approval_admin.store().get_pending(&approval_id)?)
        })
        .await?
    }
    .ok_or_else(|| ApprovalHandlerError::NotFound(approval_id.into()))?;
    let kernel = state.mediation_kernel.as_ref().ok_or_else(|| {
        ApprovalHandlerError::Rejected("approval admission is unavailable".into())
    })?;
    let context = pending
        .governed_intent
        .as_ref()
        .and_then(|intent| intent.context.as_ref())
        .and_then(|value| value.get("chio_tool_approval"))
        .ok_or_else(|| {
            ApprovalHandlerError::Rejected("approval is missing its authority context".into())
        })?;
    if pending.policy_id != kernel.policy_hash()
        || context["tenant_id"] != config.tenant_id
        || context["policy_hash"] != kernel.policy_hash()
    {
        return Err(ApprovalHandlerError::Rejected(
            "approval policy or tenant changed".into(),
        ));
    }
    if state.capability_is_revoked(&pending.capability_id).await {
        return Err(ApprovalHandlerError::Rejected(
            "approval capability is revoked".into(),
        ));
    }
    Ok(())
}

/// Run approval-store work on the blocking pool with an owned state handle. A
/// worker that does not complete is an internal approval failure.
async fn approval_blocking<T, F>(
    state: &Arc<ProxyState>,
    operation: F,
) -> Result<T, ApprovalHandlerError>
where
    T: Send + 'static,
    F: FnOnce(&ProxyState) -> Result<T, ApprovalHandlerError> + Send + 'static,
{
    let state = Arc::clone(state);
    blocking(move || operation(&state))
        .await
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))?
}

pub(super) fn redeem_approval(
    state: &ProxyState,
    kernel: &chio_kernel::ChioKernel,
    request: &mut chio_kernel::ToolCallRequest,
    approval_id: &str,
) -> Result<(), ApprovalHandlerError> {
    let resolved = state
        .approval_admin
        .store()
        .get_resolution(approval_id)?
        .ok_or_else(|| ApprovalHandlerError::Rejected("approval is not resolved".into()))?;
    if resolved.outcome != ApprovalOutcome::Approved {
        return Err(ApprovalHandlerError::Rejected("approval was denied".into()));
    }
    let pending = resolved.request.ok_or_else(|| {
        ApprovalHandlerError::Rejected("legacy approval has no retained intent".into())
    })?;
    let token = resolved.token.ok_or_else(|| {
        ApprovalHandlerError::Rejected("approval has no retained signed decision".into())
    })?;
    if request.request_id != pending.approval_id
        || request.capability.id != pending.capability_id
        || request.server_id != pending.tool_server
        || request.tool_name != pending.tool_name
        || request.agent_id != pending.subject_id
        || pending.policy_id != kernel.policy_hash()
    {
        return Err(ApprovalHandlerError::Rejected(
            "approval does not bind this request, capability, route or policy".into(),
        ));
    }
    let now = state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))?;
    chio_kernel::ApprovalToken {
        approval_id: pending.approval_id.clone(),
        approver: token.approver.clone(),
        governed_token: token.clone(),
    }
    .verify_against(&pending, now)?;
    request.governed_intent = pending.governed_intent.clone();
    let current = kernel
        .bind_tool_approval_intent(request)
        .map_err(|error| ApprovalHandlerError::Rejected(error.to_string()))?;
    if Some(&current) != pending.governed_intent.as_ref() {
        return Err(ApprovalHandlerError::Rejected(
            "approval arguments, tenant, policy or capability changed".into(),
        ));
    }
    request.governed_intent = Some(current);
    request.approval_token = Some(token);
    Ok(())
}

async fn read_body<T: serde::de::DeserializeOwned>(
    request: Request<Body>,
    decode: impl FnOnce(&[u8], usize) -> Result<T, chio_core_types::canonical::UntrustedJsonError>,
) -> Result<T, Response> {
    const LIMIT: usize = 1024 * 1024;
    let bytes = axum::body::to_bytes(request.into_body(), LIMIT)
        .await
        .map_err(|error| {
            input::with_source(
                approval_error_response(ApprovalHandlerError::BadRequest(
                    "approval request exceeds its input bound".into(),
                )),
                error,
            )
        })?;
    decode(&bytes, LIMIT).map_err(|error| {
        input::with_source(
            approval_error_response(ApprovalHandlerError::BadRequest(error.code().into())),
            error,
        )
    })
}
