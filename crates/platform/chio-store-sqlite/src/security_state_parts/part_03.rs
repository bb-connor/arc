
fn declassification_state_name(state: DeclassificationUseState) -> &'static str {
    match state {
        DeclassificationUseState::ConsumedPendingDispatch => "consumed_pending_dispatch",
        DeclassificationUseState::Released => "released",
        DeclassificationUseState::DispatchFailed => "dispatch_failed",
        DeclassificationUseState::OutcomeUnknown => "outcome_unknown",
    }
}

fn parse_declassification_state(value: &str) -> PortResult<DeclassificationUseState> {
    match value {
        "consumed_pending_dispatch" => Ok(DeclassificationUseState::ConsumedPendingDispatch),
        "released" => Ok(DeclassificationUseState::Released),
        "dispatch_failed" => Ok(DeclassificationUseState::DispatchFailed),
        "outcome_unknown" => Ok(DeclassificationUseState::OutcomeUnknown),
        _ => Err(PortError::integrity_failure()),
    }
}

fn encode_declassification_binding(
    binding: &DeclassificationTransitionBinding,
) -> PortResult<Vec<u8>> {
    let canonical = canonical_json_bytes(binding).map_err(|_| PortError::invalid_data())?;
    if canonical.len() > 4_096 {
        return Err(PortError::invalid_data());
    }
    Ok(canonical)
}

fn decode_declassification_binding(bytes: &[u8]) -> PortResult<DeclassificationTransitionBinding> {
    if bytes.len() > 4_096 {
        return Err(PortError::integrity_failure());
    }
    let binding = serde_json::from_slice::<DeclassificationTransitionBinding>(bytes)
        .map_err(|_| PortError::integrity_failure())?;
    let canonical = canonical_json_bytes(&binding).map_err(|_| PortError::integrity_failure())?;
    if canonical != bytes {
        return Err(PortError::integrity_failure());
    }
    Ok(binding)
}

fn validate_declassification_binding_identity(
    binding: &DeclassificationTransitionBinding,
    tenant_id: &TenantId,
    grant_id: &GrantId,
    request_hash: Digest32,
    receipt: &ReceiptAppendRequest,
    event_id: &EventId,
) -> PortResult<()> {
    let transition_id = derive_declassification_transition_id(binding)?;
    let expected_event_id = derive_declassification_event_id(binding)?;
    if binding.tenant_id() != tenant_id
        || binding.grant_id() != grant_id
        || binding.request_hash() != request_hash
        || receipt.transition_id != transition_id
        || *event_id != expected_event_id
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn declassification_phase_name(phase: DeclassificationEvidencePhase) -> &'static str {
    match phase {
        DeclassificationEvidencePhase::Consumption => "consumption",
        DeclassificationEvidencePhase::Outcome => "outcome",
    }
}

fn parse_declassification_phase(value: &str) -> PortResult<DeclassificationEvidencePhase> {
    match value {
        "consumption" => Ok(DeclassificationEvidencePhase::Consumption),
        "outcome" => Ok(DeclassificationEvidencePhase::Outcome),
        _ => Err(PortError::integrity_failure()),
    }
}

fn decode_declassification_receipt(
    receipt: &ReceiptAppendRequest,
) -> Result<ActiveDefenseReceiptBody, ()> {
    let body =
        serde_json::from_slice::<ActiveDefenseReceiptBody>(receipt.canonical_body.as_bytes())
            .map_err(|_| ())?;
    body.validate().map_err(|_| ())?;
    let canonical = canonical_json_bytes(&body).map_err(|_| ())?;
    let body_hash = body.body_digest().map_err(|_| ())?;
    let evidence_id = body.evidence_id().map_err(|_| ())?;
    if canonical.as_slice() != receipt.canonical_body.as_bytes()
        || body_hash != receipt.body_hash
        || evidence_id != receipt.evidence_id
        || body.header().tenant_id != receipt.tenant_id
        || body.header().transition_id != receipt.transition_id
        || body.header().occurred_at_unix_ms != receipt.occurred_at_unix_ms
        || body.kind().as_str() != receipt.evidence_type.as_str()
    {
        return Err(());
    }
    Ok(body)
}

fn validate_declassification_consumption_evidence(
    request: &DeclassificationConsumptionEvidenceCommit,
) -> PortResult<()> {
    let body = decode_declassification_receipt(&request.receipt)
        .map_err(|()| PortError::invalid_data())?;
    let ActiveDefenseReceiptBody::DeclassificationConsumption(body) = body else {
        return Err(PortError::invalid_data());
    };
    validate_declassification_binding_identity(
        &request.transition_binding,
        &request.consumption.tenant_id,
        &request.consumption.grant_id,
        request.consumption.request_hash,
        &request.receipt,
        &body.event_id,
    )?;
    if !request.transition_binding.is_consumption()
        || request.consumption.consumed_at_unix_ms == 0
        || request.consumption.grant_expires_at_unix_ms <= request.consumption.consumed_at_unix_ms
        || request.receipt.tenant_id != request.consumption.tenant_id
        || request.receipt.occurred_at_unix_ms != request.consumption.consumed_at_unix_ms
        || body.grant_id != request.consumption.grant_id
        || body.request_hash != request.consumption.request_hash
        || body.state != DeclassificationUseState::ConsumedPendingDispatch
        || !body.header.prior_receipt_ids.is_empty()
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_declassification_outcome_evidence(
    request: &DeclassificationOutcomeEvidenceCommit,
) -> PortResult<()> {
    let body = decode_declassification_receipt(&request.receipt)
        .map_err(|()| PortError::invalid_data())?;
    let ActiveDefenseReceiptBody::DeclassificationOutcome(body) = body else {
        return Err(PortError::invalid_data());
    };
    validate_declassification_binding_identity(
        &request.transition_binding,
        &request.outcome.tenant_id,
        &request.outcome.grant_id,
        request.outcome.request_hash,
        &request.receipt,
        &body.event_id,
    )?;
    if request.outcome.expected_state != DeclassificationUseState::ConsumedPendingDispatch
        || request.transition_binding.terminal_state() != Some(request.outcome.new_state)
        || request.outcome.transition_id != request.receipt.transition_id
        || request.receipt.tenant_id != request.outcome.tenant_id
        || request.predecessor_evidence_id == request.receipt.evidence_id
        || body.grant_id != request.outcome.grant_id
        || body.request_hash != request.outcome.request_hash
        || body.from_state != request.outcome.expected_state
        || body.to_state != request.outcome.new_state
        || body.header.prior_receipt_ids.as_slice()
            != core::slice::from_ref(&request.predecessor_evidence_id)
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}



type DeclassificationEvidenceRow = (
    String,
    String,
    String,
    i64,
    Vec<u8>,
    String,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    Option<String>,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
    i64,
    i64,
    Option<String>,
);

fn decode_declassification_evidence_row(
    row: DeclassificationEvidenceRow,
) -> PortResult<DeclassificationEvidenceRecord> {
    let (
        tenant_id,
        grant_id,
        phase,
        phase_ordinal,
        request_hash,
        state,
        transition_binding,
        evidence_type,
        evidence_id,
        canonical_body,
        body_hash,
        transition_id,
        occurred_at,
        predecessor_evidence_id,
        acknowledged,
        acknowledged_at,
        durable_sink_record_hash,
        attempts,
        next_attempt_at,
        last_error_code,
    ) = row;
    let phase = parse_declassification_phase(&phase)?;
    if from_i64(phase_ordinal)? != u64::from(phase.ordinal()) {
        return Err(PortError::integrity_failure());
    }
    let tenant_id = TenantId::new(tenant_id).map_err(|_| PortError::integrity_failure())?;
    let grant_id = GrantId::new(grant_id).map_err(|_| PortError::integrity_failure())?;
    let request_hash = decode_digest(request_hash)?;
    let state = parse_declassification_state(&state)?;
    let transition_binding = decode_declassification_binding(&transition_binding)?;
    let canonical_body =
        CanonicalBody::new(canonical_body).map_err(|_| PortError::integrity_failure())?;
    let body_hash = decode_digest(body_hash)?;
    let predecessor_evidence_id = predecessor_evidence_id
        .map(OpaqueReceiptRef::new)
        .transpose()
        .map_err(|_| PortError::integrity_failure())?;
    let (acknowledged, durable_sink_record_hash) =
        match (acknowledged, acknowledged_at, durable_sink_record_hash) {
            (0, None, None) => (false, None),
            (1, Some(value), Some(hash)) if value >= occurred_at => {
                (true, Some(decode_digest(hash)?))
            }
            _ => return Err(PortError::integrity_failure()),
        };
    let attempts =
        u32::try_from(from_i64(attempts)?).map_err(|_| PortError::integrity_failure())?;
    let next_attempt_at_unix_ms = from_i64(next_attempt_at)?;
    let last_error_code = last_error_code
        .map(ErrorCode::new)
        .transpose()
        .map_err(|_| PortError::integrity_failure())?;
    if (attempts == 0) != last_error_code.is_none()
        || next_attempt_at_unix_ms < from_i64(occurred_at)?
    {
        return Err(PortError::integrity_failure());
    }
    let receipt = ReceiptAppendRequest {
        tenant_id: tenant_id.clone(),
        evidence_type: RecordId::new(evidence_type).map_err(|_| PortError::integrity_failure())?,
        evidence_id: OpaqueReceiptRef::new(evidence_id)
            .map_err(|_| PortError::integrity_failure())?,
        canonical_body,
        body_hash,
        transition_id: RecordId::new(transition_id).map_err(|_| PortError::integrity_failure())?,
        occurred_at_unix_ms: from_i64(occurred_at)?,
    };
    let body =
        decode_declassification_receipt(&receipt).map_err(|()| PortError::integrity_failure())?;
    let body_event_id = match &body {
        ActiveDefenseReceiptBody::DeclassificationConsumption(consumption) => &consumption.event_id,
        ActiveDefenseReceiptBody::DeclassificationOutcome(outcome) => &outcome.event_id,
        _ => return Err(PortError::integrity_failure()),
    };
    validate_declassification_binding_identity(
        &transition_binding,
        &tenant_id,
        &grant_id,
        request_hash,
        &receipt,
        body_event_id,
    )
    .map_err(|_| PortError::integrity_failure())?;
    if (phase == DeclassificationEvidencePhase::Consumption
        && (state != DeclassificationUseState::ConsumedPendingDispatch
            || predecessor_evidence_id.is_some()
            || !matches!(
                &body,
                ActiveDefenseReceiptBody::DeclassificationConsumption(consumption)
                    if consumption.grant_id == grant_id
                        && consumption.request_hash == request_hash
                        && consumption.state == state
                        && consumption.header.prior_receipt_ids.is_empty()
            )))
        || (phase == DeclassificationEvidencePhase::Outcome
            && (!matches!(
                state,
                DeclassificationUseState::Released
                    | DeclassificationUseState::DispatchFailed
                    | DeclassificationUseState::OutcomeUnknown
            ) || predecessor_evidence_id.is_none()
                || !matches!(
                    &body,
                    ActiveDefenseReceiptBody::DeclassificationOutcome(outcome)
                        if outcome.grant_id == grant_id
                            && outcome.request_hash == request_hash
                            && outcome.from_state
                                == DeclassificationUseState::ConsumedPendingDispatch
                            && outcome.to_state == state
                            && predecessor_evidence_id.as_ref().is_some_and(|predecessor| {
                                outcome.header.prior_receipt_ids.as_slice()
                                    == core::slice::from_ref(predecessor)
                            })
                )))
    {
        return Err(PortError::integrity_failure());
    }
    Ok(DeclassificationEvidenceRecord {
        tenant_id,
        grant_id,
        phase,
        request_hash,
        state,
        transition_binding,
        predecessor_evidence_id,
        receipt,
        acknowledged,
        durable_sink_record_hash,
        attempts,
        next_attempt_at_unix_ms,
        last_error_code,
    })
}

fn declassification_evidence_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<DeclassificationEvidenceRow> {
    Ok((
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, String>(2)?,
        row.get::<_, i64>(3)?,
        row.get::<_, Vec<u8>>(4)?,
        row.get::<_, String>(5)?,
        row.get::<_, Vec<u8>>(6)?,
        row.get::<_, String>(7)?,
        row.get::<_, String>(8)?,
        row.get::<_, Vec<u8>>(9)?,
        row.get::<_, Vec<u8>>(10)?,
        row.get::<_, String>(11)?,
        row.get::<_, i64>(12)?,
        row.get::<_, Option<String>>(13)?,
        row.get::<_, i64>(14)?,
        row.get::<_, Option<i64>>(15)?,
        row.get::<_, Option<Vec<u8>>>(16)?,
        row.get::<_, i64>(17)?,
        row.get::<_, i64>(18)?,
        row.get::<_, Option<String>>(19)?,
    ))
}

struct DeclassificationEvidenceCommit<'a> {
    tenant_id: &'a TenantId,
    grant_id: &'a GrantId,
    phase: DeclassificationEvidencePhase,
    request_hash: Digest32,
    state: DeclassificationUseState,
    transition_binding: &'a DeclassificationTransitionBinding,
    predecessor_evidence_id: Option<&'a OpaqueReceiptRef>,
    receipt: &'a ReceiptAppendRequest,
}



fn declassification_evidence_matches(
    record: &DeclassificationEvidenceRecord,
    expected: &DeclassificationEvidenceCommit<'_>,
) -> bool {
    record.tenant_id == *expected.tenant_id
        && record.grant_id == *expected.grant_id
        && record.phase == expected.phase
        && record.request_hash == expected.request_hash
        && record.state == expected.state
        && record.transition_binding == *expected.transition_binding
        && record.predecessor_evidence_id.as_ref() == expected.predecessor_evidence_id
        && record.receipt == *expected.receipt
}



fn normalize_sql(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    let mut quote_terminator = None;
    let mut pending_space = false;
    while let Some(character) = characters.next() {
        if let Some(terminator) = quote_terminator {
            normalized.push(character);
            if character == terminator {
                if characters.peek() == Some(&terminator) {
                    if let Some(escaped_terminator) = characters.next() {
                        normalized.push(escaped_terminator);
                    }
                } else {
                    quote_terminator = None;
                }
            }
            continue;
        }
        if character.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        pending_space = false;
        normalized.push(character);
        quote_terminator = match character {
            '\'' | '"' | '`' => Some(character),
            '[' => Some(']'),
            _ => None,
        };
    }
    normalized
}

#[cfg(test)]
fn load_declassification_use_record(connection: &Connection, query: &DeclassificationUseQuery) -> PortResult<Option<DeclassificationUseRecord>> {
    declassification::load_legacy_use(connection, query)
}

#[cfg(test)]
fn load_declassification_evidence_record(connection: &Connection, query: &DeclassificationEvidenceQuery) -> PortResult<Option<DeclassificationEvidenceRecord>> {
    declassification::load_legacy_evidence(connection, query)
}
