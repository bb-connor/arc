use super::*;

pub(crate) async fn list_pending_approvals_handler(
    State(state): State<Arc<ProxyState>>,
    Query(query): Query<PendingQuery>,
) -> Response {
    match handle_list_pending(&state.approval_admin, query) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn get_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(approval_id): Path<String>,
) -> Response {
    match handle_get_approval(&state.approval_admin, &approval_id) {
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
    match handle_respond(&state.approval_admin, &approval_id, body, now) {
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
    match handle_batch_respond(&state.approval_admin, body, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn create_threshold_proposal_handler(
    State(state): State<Arc<ProxyState>>,
    body: Result<Json<CreateThresholdProposalRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid threshold approval proposal payload: {error}"
            )));
        }
    };
    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    match handle_create_threshold_proposal(&state.approval_admin, body, now) {
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
    match handle_get_threshold_proposal(&state.approval_admin, &proposal_id, now) {
        Ok(response) => approval_json(StatusCode::OK, response),
        Err(error) => approval_error_response(error),
    }
}

pub(crate) async fn submit_threshold_approval_handler(
    State(state): State<Arc<ProxyState>>,
    Path(proposal_id): Path<String>,
    body: Result<Json<SubmitThresholdApprovalRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::BadRequest(format!(
                "invalid threshold approval token payload: {error}"
            )));
        }
    };
    let now = match state
        .clock
        .seconds()
        .map_err(|error| ApprovalHandlerError::Internal(error.to_string()))
    {
        Ok(now) => now,
        Err(error) => return approval_error_response(error),
    };
    match handle_submit_threshold_approval(&state.approval_admin, &proposal_id, body, now) {
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
    match handle_deliver_threshold_approval(&state.approval_admin, &proposal_id, now) {
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
    let kernel = kernel.lock().await;
    let intent = match kernel.bind_tool_approval_intent(&request) {
        Ok(intent) => intent,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::Rejected(error.to_string()))
        }
    };
    let now = match state.clock.seconds() {
        Ok(now) => now,
        Err(error) => return clock::rejection(error),
    };
    let ttl = if body.ttl_seconds == 0 {
        3600
    } else {
        body.ttl_seconds.min(3600)
    };
    let expires_at = now.saturating_add(ttl).min(request.capability.expires_at);
    let parameter_hash = match intent.binding_hash() {
        Ok(hash) => hash,
        Err(error) => {
            return approval_error_response(ApprovalHandlerError::Rejected(error.to_string()))
        }
    };
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
        trusted_approvers: config.approvers.clone(),
        triggered_by: body.triggered_by,
    };
    if let Err(error) = state.approval_admin.store().store_pending(&approval) {
        return approval_error_response(error.into());
    }
    approval_json(
        StatusCode::CREATED,
        SubmitApprovalResponse {
            approval_id,
            expires_at,
            created_at: now,
            trusted_approvers: config.approvers.iter().map(PublicKey::to_hex).collect(),
        },
    )
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
    state: &ProxyState,
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
    let pending = state
        .approval_admin
        .store()
        .get_pending(approval_id)?
        .ok_or_else(|| ApprovalHandlerError::NotFound(approval_id.into()))?;
    let kernel = state
        .mediation_kernel
        .as_ref()
        .ok_or_else(|| ApprovalHandlerError::Rejected("approval admission is unavailable".into()))?
        .lock()
        .await;
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
