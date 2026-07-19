fn declassification_consumption_body(
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

struct DeclassificationOutcomeBodyInput {
    tenant_id: TenantId,
    prior_receipt_id: OpaqueReceiptRef,
    policy: ActiveDefensePolicyBinding,
    grant_id: GrantId,
    grant_hash: Digest32,
    request_hash: Digest32,
    occurred_at_unix_ms: u64,
    to_state: DeclassificationUseState,
}

fn declassification_outcome_body(
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

fn flow_denial_code(denial: FlowDenial) -> Result<ErrorCode, FlowDenial> {
    let suffix = match denial {
        FlowDenial::StateOverflow => "state_overflow",
        FlowDenial::StateChanged => "state_changed",
        FlowDenial::InvalidManifest => "invalid_manifest",
        FlowDenial::DeclassificationBindingMismatch => "declassification_binding_mismatch",
        FlowDenial::DeclassificationPurposeDenied => "declassification_purpose_denied",
        FlowDenial::DeclassificationNotYetValid => "declassification_not_yet_valid",
        FlowDenial::DeclassificationExpired => "declassification_expired",
        FlowDenial::DeclassificationUntrustedAuthority => "declassification_untrusted_authority",
        FlowDenial::UnexpectedDeclassification => "unexpected_declassification",
        FlowDenial::DeclassificationReplay => "declassification_replay",
        FlowDenial::DeclassificationStoreFailure => "declassification_store_failure",
        FlowDenial::ClassifierFailure => "classifier_failure",
        FlowDenial::ClassifierBindingMismatch => "classifier_binding_mismatch",
        FlowDenial::MissingPolicyClearance => "missing_policy_clearance",
        FlowDenial::MissingManifestClearance => "missing_manifest_clearance",
        FlowDenial::TopSource => "top_source",
        FlowDenial::TopClearance => "top_clearance",
        FlowDenial::PolicyFlowViolation => "policy_flow_violation",
        FlowDenial::ManifestFlowViolation => "manifest_flow_violation",
    };
    ErrorCode::new(format!("flow.{suffix}")).map_err(|_| FlowDenial::StateOverflow)
}

fn event_id(domain: &str, binding: &[u8]) -> Result<EventId, FlowDenial> {
    let transition = transition_id(domain, binding)?;
    EventId::new(transition.as_str().to_string()).map_err(|_| FlowDenial::StateOverflow)
}

fn transition_id(domain: &str, binding: &[u8]) -> Result<RecordId, FlowDenial> {
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

fn flow_transition_id(
    domain: &str,
    key: &FlowStateKey,
    context_generation: u64,
    request_id: &RequestId,
    payload_digest: Digest32,
) -> Result<RecordId, FlowDenial> {
    let fields = [
        key.tenant_id.as_str().as_bytes(),
        key.principal_id.as_str().as_bytes(),
        key.lineage_id.as_str().as_bytes(),
        key.session_id.as_str().as_bytes(),
        key.isolation_epoch_id.as_str().as_bytes(),
        request_id.as_str().as_bytes(),
        payload_digest.as_bytes(),
    ];
    let mut binding = Vec::new();
    for field in fields {
        let length = u64::try_from(field.len()).map_err(|_| FlowDenial::StateOverflow)?;
        binding.extend_from_slice(&length.to_be_bytes());
        binding.extend_from_slice(field);
    }
    binding.extend_from_slice(&context_generation.to_be_bytes());
    transition_id(domain, &binding)
}

fn non_egress_declaration() -> chio_manifest::ToolFlowDeclaration {
    chio_manifest::ToolFlowDeclaration {
        output_label: None,
        input_clearance: None,
        egress: false,
        declassification_purposes: BTreeSet::new(),
    }
}

fn map_declassification_error(error: DeclassificationError) -> FlowDenial {
    match error {
        DeclassificationError::PurposeDenied => FlowDenial::DeclassificationPurposeDenied,
        DeclassificationError::NotYetValid => FlowDenial::DeclassificationNotYetValid,
        DeclassificationError::Expired => FlowDenial::DeclassificationExpired,
        DeclassificationError::UntrustedAuthority => FlowDenial::DeclassificationUntrustedAuthority,
        DeclassificationError::AlreadyConsumed => FlowDenial::DeclassificationReplay,
        DeclassificationError::StoreFailure => FlowDenial::DeclassificationStoreFailure,
        DeclassificationError::InvalidGrant
        | DeclassificationError::InvalidRequestRepresentation
        | DeclassificationError::BindingMismatch
        | DeclassificationError::InvalidSignature
        | DeclassificationError::TopSource
        | DeclassificationError::InvalidTarget
        | DeclassificationError::NoOpTarget => FlowDenial::DeclassificationBindingMismatch,
    }
}
