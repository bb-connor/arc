#[derive(Serialize)]
struct RequestCommitment<'a> {
    tenant_id: &'a str,
    action_id: &'a str,
    plan_hash: Digest32,
    created_at_unix_ms: u64,
}

fn request_id(plan: &ResponsePlan) -> Result<RecordId, StateMachineError> {
    let digest = domain_hash(
        REQUEST_ID_DOMAIN,
        &RequestCommitment {
            tenant_id: plan.tenant_id.as_str(),
            action_id: plan.action_id.as_str(),
            plan_hash: plan.plan_hash,
            created_at_unix_ms: plan.created_at_unix_ms,
        },
    )?;
    RecordId::new(format!("response_request_{}", hex_bytes(digest.as_bytes())))
        .map_err(|_| StateMachineError::Canonical)
}

fn latest_evidence_id(snapshot: &ResponseSnapshot) -> Result<OpaqueReceiptRef, StateMachineError> {
    let mutation_index = snapshot
        .mutations
        .len()
        .checked_sub(1)
        .ok_or(StateMachineError::InvalidRecord)?;
    response_receipt_for_mutation(snapshot, mutation_index)
        .and_then(|body| body.evidence_id())
        .map_err(|_| StateMachineError::Canonical)
}

#[derive(Serialize)]
struct TransitionCommitment<'a, T> {
    kind: &'a str,
    tenant_id: &'a str,
    action_id: &'a str,
    plan_hash: Digest32,
    expected_generation: u64,
    mutation: &'a T,
}

fn transition_id<T: Serialize>(
    kind: &str,
    plan: &ResponsePlan,
    expected_generation: u64,
    mutation: &T,
) -> Result<RecordId, StateMachineError> {
    let digest = domain_hash(
        TRANSITION_ID_DOMAIN,
        &TransitionCommitment {
            kind,
            tenant_id: plan.tenant_id.as_str(),
            action_id: plan.action_id.as_str(),
            plan_hash: plan.plan_hash,
            expected_generation,
            mutation,
        },
    )?;
    RecordId::new(format!(
        "response_transition_{}",
        hex_bytes(digest.as_bytes())
    ))
    .map_err(|_| StateMachineError::Canonical)
}

#[derive(Serialize)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum CanonicalMutationBody {
    Transition {
        generation: u64,
        from_state: ResponseState,
        to_state: ResponseState,
        cause: ResponseTransitionCause,
        applying_lease_expires_at_unix_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: Option<LeaseOwnerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_fencing_token: Option<u64>,
        prior_receipt_id: OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    EffectRequested {
        generation: u64,
        effect_id: EffectId,
        effect_generation: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        prior_receipt_id: OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    EffectApplied {
        generation: u64,
        effect_id: EffectId,
        effect_generation: u64,
        resulting_version_hash: Digest32,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        effect_transition_id: Option<RecordId>,
        prior_receipt_id: OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    EffectFailed {
        generation: u64,
        effect_id: EffectId,
        effect_generation: u64,
        error_code: ErrorCode,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        effect_transition_id: Option<RecordId>,
        prior_receipt_id: OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    Rollback {
        generation: u64,
        effect_id: EffectId,
        effect_generation: u64,
        outcome: ResponseRollbackOutcome,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: Option<LeaseOwnerId>,
        scheduler_fencing_token: u64,
        effect_transition_id: Option<RecordId>,
        prior_receipt_id: OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    Failed {
        generation: u64,
        from_state: ResponseState,
        to_state: ResponseState,
        error_code: ErrorCode,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: Option<LeaseOwnerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_fencing_token: Option<u64>,
        prior_receipt_id: OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
    Final {
        generation: u64,
        from_state: ResponseState,
        final_state: ResponseState,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_lease_owner_id: Option<LeaseOwnerId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        scheduler_fencing_token: Option<u64>,
        prior_receipt_id: OpaqueReceiptRef,
        occurred_at_unix_ms: u64,
    },
}

impl CanonicalMutationBody {
    const fn generation(&self) -> u64 {
        match self {
            Self::Transition { generation, .. }
            | Self::EffectRequested { generation, .. }
            | Self::EffectApplied { generation, .. }
            | Self::EffectFailed { generation, .. }
            | Self::Rollback { generation, .. }
            | Self::Failed { generation, .. }
            | Self::Final { generation, .. } => *generation,
        }
    }

    fn into_record(self, transition_id: RecordId) -> ResponseMutationRecord {
        match self {
            Self::Transition {
                generation,
                from_state,
                to_state,
                cause,
                applying_lease_expires_at_unix_ms,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Transition(ResponseTransitionRecord {
                transition_id,
                generation,
                from_state,
                to_state,
                cause,
                applying_lease_expires_at_unix_ms,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            }),
            Self::EffectRequested {
                generation,
                effect_id,
                effect_generation,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::EffectRequested(ResponseEffectRequestedRecord {
                transition_id,
                generation,
                effect_id,
                effect_generation,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            }),
            Self::EffectApplied {
                generation,
                effect_id,
                effect_generation,
                resulting_version_hash,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                effect_transition_id,
                prior_receipt_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::EffectApplied(ResponseEffectAppliedRecord {
                transition_id,
                generation,
                effect_id,
                effect_generation,
                resulting_version_hash,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                effect_transition_id,
                prior_receipt_id,
                occurred_at_unix_ms,
            }),
            Self::EffectFailed {
                generation,
                effect_id,
                effect_generation,
                error_code,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                effect_transition_id,
                prior_receipt_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::EffectFailed(ResponseEffectFailedRecord {
                transition_id,
                generation,
                effect_id,
                effect_generation,
                error_code,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                effect_transition_id,
                prior_receipt_id,
                occurred_at_unix_ms,
            }),
            Self::Rollback {
                generation,
                effect_id,
                effect_generation,
                outcome,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                effect_transition_id,
                prior_receipt_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Rollback(ResponseRollbackRecord {
                transition_id,
                generation,
                effect_id,
                effect_generation,
                outcome,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                effect_transition_id,
                prior_receipt_id,
                occurred_at_unix_ms,
            }),
            Self::Failed {
                generation,
                from_state,
                to_state,
                error_code,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Failed(ResponseFailureRecord {
                transition_id,
                generation,
                from_state,
                to_state,
                error_code,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            }),
            Self::Final {
                generation,
                from_state,
                final_state,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            } => ResponseMutationRecord::Final(ResponseFinalRecord {
                transition_id,
                generation,
                from_state,
                final_state,
                scheduler_lease_owner_id,
                scheduler_fencing_token,
                prior_receipt_id,
                occurred_at_unix_ms,
            }),
        }
    }
}

fn canonical_mutation_id(
    plan: &ResponsePlan,
    body: &CanonicalMutationBody,
) -> Result<RecordId, StateMachineError> {
    let expected_generation = body
        .generation()
        .checked_sub(1)
        .ok_or(StateMachineError::InvalidRecord)?;
    transition_id("mutation", plan, expected_generation, body)
}

fn finalize_mutation(
    plan: &ResponsePlan,
    body: CanonicalMutationBody,
) -> Result<ResponseMutationRecord, StateMachineError> {
    let transition_id = canonical_mutation_id(plan, &body)?;
    Ok(body.into_record(transition_id))
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest32, StateMachineError> {
    let canonical = canonical_json_bytes(value).map_err(|_| StateMachineError::Canonical)?;
    let mut input = Vec::with_capacity(domain.len() + canonical.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical);
    Ok(Digest32::new(*sha256(&input).as_bytes()))
}

fn error_code(value: &str) -> Result<ErrorCode, StateMachineError> {
    ErrorCode::new(value).map_err(|_| StateMachineError::Canonical)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("response canonicalization failed")]
    Canonical,
    #[error("response effect application is incomplete")]
    IncompleteApplication,
    #[error("response effect lifecycle transition is invalid")]
    InvalidEffectLifecycle,
    #[error("response failure record is invalid")]
    InvalidFailureRecord,
    #[error("response plan is invalid")]
    InvalidPlan,
    #[error("response dispatch authorization is invalid")]
    InvalidDispatch,
    #[error("response state record is invalid")]
    InvalidRecord,
    #[error("response transition timing is invalid")]
    InvalidTiming,
    #[error("response state transition is not permitted")]
    InvalidTransition,
    #[error("response mutation limit exceeded")]
    MutationLimit,
    #[error("response is not due")]
    NotDue,
    #[error("response generation overflow")]
    GenerationOverflow,
    #[error("response generation is stale")]
    StaleGeneration,
    #[error("response effect is unknown")]
    UnknownEffect,
    #[error("response still has unrestored reversible effects")]
    UnrestoredEffects,
    #[error("response plan shape is invalid: {0}")]
    Shape(#[from] ResponseShapeError),
    #[error("response store failed: {0}")]
    Store(#[from] PortError),
}
