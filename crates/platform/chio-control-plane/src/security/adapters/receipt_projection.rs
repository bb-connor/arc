use super::*;


pub(super) fn canonical_body(value: &serde_json::Value) -> Result<CanonicalBody, FlowDenial> {
    let bytes =
        chio_core::canonical_json_bytes(value).map_err(|_| FlowDenial::ClassifierFailure)?;
    CanonicalBody::new(bytes).map_err(|_| FlowDenial::ClassifierFailure)
}

pub(super) fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

pub(super) fn declassification_grant_hash<T: serde::Serialize>(grant: &T) -> Result<Digest32, FlowDenial> {
    let canonical = chio_core::canonical_json_bytes(grant)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    Ok(digest(&canonical))
}

pub(super) fn active_defense_header(
    occurred_at_unix_ms: u64,
    tenant_id: TenantId,
    transition_id: RecordId,
    prior_receipt_ids: Vec<OpaqueReceiptRef>,
) -> Result<ActiveDefenseReceiptHeader, FlowDenial> {
    ActiveDefenseReceiptHeader::new(
        occurred_at_unix_ms,
        tenant_id,
        transition_id,
        prior_receipt_ids,
    )
    .map_err(|_| FlowDenial::DeclassificationStoreFailure)
}

pub(super) fn append_active_defense_body(
    sink: &dyn SecurityReceiptSink,
    body: &ActiveDefenseReceiptBody,
) -> Result<OpaqueReceiptRef, FlowDenial> {
    let request = active_defense_receipt_request(body)?;
    let appended = sink
        .sign_and_append(&request)
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    if appended != request.evidence_id {
        return Err(FlowDenial::DeclassificationStoreFailure);
    }
    Ok(request.evidence_id)
}

pub(super) fn active_defense_receipt_request(
    body: &ActiveDefenseReceiptBody,
) -> Result<ReceiptAppendRequest, FlowDenial> {
    body.validate()
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    let canonical = chio_core::canonical_json_bytes(body)
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    let evidence_id = body
        .evidence_id()
        .map_err(|_| FlowDenial::DeclassificationStoreFailure)?;
    Ok(ReceiptAppendRequest {
        tenant_id: body.header().tenant_id.clone(),
        evidence_type: RecordId::new(body.kind().as_str())
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?,
        evidence_id: evidence_id.clone(),
        canonical_body: CanonicalBody::new(canonical)
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?,
        body_hash: body
            .body_digest()
            .map_err(|_| FlowDenial::DeclassificationStoreFailure)?,
        transition_id: body.header().transition_id.clone(),
        occurred_at_unix_ms: body.header().occurred_at_unix_ms,
    })
}

pub(super) fn append_exact_receipt(
    sink: &dyn ExactSecurityReceiptSink,
    request: &ReceiptAppendRequest,
) -> PortResult<ExactReceiptRecord> {
    if let Some(exact) = sink.load_exact(&request.evidence_id)? {
        if exact.receipt != *request {
            return Err(PortError::conflict());
        }
        if exact
            .durable_record_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(PortError::integrity_failure());
        }
        return Ok(exact);
    }
    let appended = sink.sign_and_append(request)?;
    if appended != request.evidence_id {
        return Err(PortError::integrity_failure());
    }
    let exact = sink
        .load_exact(&request.evidence_id)?
        .ok_or_else(PortError::integrity_failure)?;
    if exact.receipt != *request
        || exact
            .durable_record_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(exact)
}

pub(super) fn declassification_consumption_body(
    tenant_id: TenantId,
    policy: ActiveDefensePolicyBinding,
    grant_id: GrantId,
    grant_hash: Digest32,
    request_hash: Digest32,
    occurred_at_unix_ms: u64,
    transition_binding: &DeclassificationTransitionBinding,
) -> Result<ActiveDefenseReceiptBody, FlowDenial> {
    if !transition_binding.is_consumption()
        || transition_binding.tenant_id() != &tenant_id
        || transition_binding.grant_id() != &grant_id
        || transition_binding.request_hash() != request_hash
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    let transition_id = derive_declassification_transition_id(transition_binding)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    let event_id = derive_declassification_event_id(transition_binding)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    Ok(ActiveDefenseReceiptBody::DeclassificationConsumption(
        DeclassificationConsumptionReceiptBody {
            header: active_defense_header(
                occurred_at_unix_ms,
                tenant_id,
                transition_id,
                Vec::new(),
            )?,
            policy,
            grant_id,
            grant_hash,
            request_hash,
            event_id,
            state: DeclassificationUseState::ConsumedPendingDispatch,
        },
    ))
}

pub(super) fn declassification_outcome_body(
    input: DeclassificationOutcomeBodyInput,
    transition_binding: &DeclassificationTransitionBinding,
) -> Result<ActiveDefenseReceiptBody, FlowDenial> {
    let DeclassificationOutcomeBodyInput {
        tenant_id,
        prior_receipt_id,
        policy,
        grant_id,
        grant_hash,
        request_hash,
        occurred_at_unix_ms,
        to_state,
    } = input;
    if transition_binding.is_consumption()
        || transition_binding.tenant_id() != &tenant_id
        || transition_binding.grant_id() != &grant_id
        || transition_binding.request_hash() != request_hash
        || transition_binding.terminal_state() != Some(to_state)
    {
        return Err(FlowDenial::DeclassificationBindingMismatch);
    }
    let transition_id = derive_declassification_transition_id(transition_binding)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    let event_id = derive_declassification_event_id(transition_binding)
        .map_err(|_| FlowDenial::DeclassificationBindingMismatch)?;
    Ok(ActiveDefenseReceiptBody::DeclassificationOutcome(
        DeclassificationOutcomeReceiptBody {
            header: active_defense_header(
                occurred_at_unix_ms,
                tenant_id,
                transition_id,
                vec![prior_receipt_id],
            )?,
            policy,
            grant_id,
            grant_hash,
            request_hash,
            event_id,
            from_state: DeclassificationUseState::ConsumedPendingDispatch,
            to_state,
        },
    ))
}

pub(super) fn event_id(domain: &str, binding: &[u8]) -> Result<EventId, FlowDenial> {
    let transition = transition_id(domain, binding)?;
    EventId::new(transition.as_str().to_string()).map_err(|_| FlowDenial::StateOverflow)
}

pub(super) fn transition_id(domain: &str, binding: &[u8]) -> Result<RecordId, FlowDenial> {
    let mut material = Vec::with_capacity(domain.len() + 1 + binding.len());
    material.extend_from_slice(domain.as_bytes());
    material.push(0);
    material.extend_from_slice(binding);
    RecordId::new(format!(
        "{domain}:{}",
        hex::encode(chio_core::sha256(&material).as_bytes())
    ))
    .map_err(|_| FlowDenial::StateOverflow)
}

