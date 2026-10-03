//! Revalidation of externally signed decisions before recording them.
use super::*;

pub(super) fn invocation(
    session: &RemoteSession,
    capability: &CapabilityToken,
    request_id: &str,
    arguments: &Value,
    intent: GovernedTransactionIntent,
) -> chio_kernel::ToolCallRequest {
    chio_kernel::ToolCallRequest {
        request_id: request_id.to_owned(),
        capability: capability.clone(),
        tool_name: intent.tool_name.clone(),
        server_id: intent.server_id.clone(),
        agent_id: session.agent_id.clone(),
        arguments: arguments.clone(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

pub(super) fn decision(
    state: &RemoteAppState,
    session: &RemoteSession,
    record: &ApprovalRecord,
    token: &GovernedApprovalToken,
    now: u64,
) -> Result<(), Response> {
    validate_session_lifecycle(session)?;
    let approval = state.factory.config.approval.as_ref().ok_or_else(|| {
        failure(
            StatusCode::CONFLICT,
            "explicit approval authority is required",
        )
    })?;
    if record.schema != RECORD_SCHEMA
        || record.session_id != session.session_id
        || record.policy_fingerprint != session.policy_fingerprint
        || record.runtime_contract_fingerprint != session.runtime_contract_fingerprint
        || now < record.created_at
        || now >= record.expires_at
    {
        return Err(failure(
            StatusCode::CONFLICT,
            "approval authority changed or expired",
        ));
    }
    let capability = session
        .issued_capabilities
        .iter()
        .find(|cap| cap.id == record.capability_id && cap.subject == record.subject)
        .ok_or_else(|| failure(StatusCode::CONFLICT, "approval capability changed"))?;
    let request = invocation(
        session,
        capability,
        &record.request_id,
        &record.arguments,
        record.intent.clone(),
    );
    let rebound = state
        .factory
        .bind_approval_intent(session, &request)
        .map_err(|error| failure(StatusCode::CONFLICT, error))?;
    let intent_hash = record.intent.binding_hash().map_err(internal)?;
    if rebound.binding_hash().map_err(internal)? != intent_hash
        || record.expires_at > capability.expires_at
        || token.id != format!("{}-decision", record.id)
        || token.request_id != record.request_id
        || token.subject != record.subject
        || token.governed_intent_hash != intent_hash
        || token.threshold_proposal_hash.is_some()
        || token.issued_at < record.created_at
        || token.expires_at > record.expires_at
        || !token.is_valid_at(now)
        || !approval.approvers.contains(&token.approver)
    {
        return Err(failure(
            StatusCode::CONFLICT,
            "approval token does not authorize this record",
        ));
    }
    if !token
        .approver
        .verify_canonical_strict(&token.body(), &token.signature)
        .map_err(|error| failure(StatusCode::BAD_REQUEST, error))?
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "approval signature is invalid",
        ));
    }
    Ok(())
}
