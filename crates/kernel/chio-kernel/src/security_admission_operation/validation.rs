//! Field, state and transition checks shared by admission operation records.
use super::*;

pub(super) fn validate_cleanup_payload(
    payload_json: &str,
    payload_hash: &str,
) -> Result<(), AdmissionOperationError> {
    if payload_json.is_empty() || payload_json.len() > MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES {
        return Err(AdmissionOperationError::Invalid(format!(
            "persisted cleanup payload must be between 1 and {MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES} bytes"
        )));
    }
    validate_digest(payload_hash, "cleanup payload_hash")?;
    let value: serde_json::Value = chio_core::canonical::UntrustedJsonText::from_wire(
        (payload_json).as_bytes(),
        MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES,
    )
    .and_then(|input| input.decode_signed())
    .map_err(AdmissionOperationError::from)?;
    let canonical = canonical_json_bytes(&value).map_err(|error| {
        AdmissionOperationError::Invalid(format!(
            "persisted cleanup payload cannot be canonicalized: {error}"
        ))
    })?;
    if canonical != payload_json.as_bytes() {
        return Err(AdmissionOperationError::Invalid(
            "persisted cleanup payload is not canonical JSON".to_string(),
        ));
    }
    if sha256_hex(payload_json.as_bytes()) != payload_hash {
        return Err(AdmissionOperationError::Invalid(
            "persisted cleanup payload hash does not match its bytes".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_cleanup_claim(
    state: AdmissionCleanupActionState,
    claim_token: Option<&str>,
    claim_deadline_unix_ms: Option<u64>,
) -> Result<(), AdmissionOperationError> {
    match (state, claim_token, claim_deadline_unix_ms) {
        (AdmissionCleanupActionState::Claimed, Some(token), Some(deadline)) if deadline > 0 => {
            validate_identifier(token, "cleanup claim_token")
        }
        (
            AdmissionCleanupActionState::Pending | AdmissionCleanupActionState::Completed,
            None,
            None,
        ) => Ok(()),
        _ => Err(AdmissionOperationError::Invalid(
            "cleanup claim fields are inconsistent with action state".to_string(),
        )),
    }
}

pub(super) fn valid_state_transition(
    current: AdmissionOperationState,
    next: AdmissionOperationState,
    kind: AdmissionOperationKind,
) -> bool {
    use AdmissionOperationState as State;
    if current.is_terminal() {
        return false;
    }
    if next == State::CompensationPending {
        return !matches!(
            current,
            State::DispatchCommitted | State::CallerReserved | State::CompensationPending
        );
    }
    match (current, next) {
        (State::Prepared, State::BrokerAttemptRegistered) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        (State::Prepared, State::BudgetAuthorized)
        | (State::BrokerAttemptRegistered, State::BudgetAuthorized) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        (State::Prepared, State::ApprovalReserved) => {
            kind == AdmissionOperationKind::GovernedActiveResponse
        }
        (State::BudgetAuthorized, State::DelegatedBudgetReserved)
        | (State::DelegatedBudgetReserved, State::PaymentAuthorized)
        | (State::PaymentAuthorized, State::ApprovalReserved)
        | (State::BudgetAuthorized, State::ReadyToDispatch)
        | (State::ApprovalReserved, State::ReadyToDispatch)
        | (State::ReadyToDispatch, State::CapturePending)
        | (State::ReadyToDispatch, State::CallerReservationCapturePending) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        (State::ApprovalReserved, State::DispatchCommitted) => {
            kind == AdmissionOperationKind::GovernedActiveResponse
        }
        (State::CapturePending, State::DispatchCommitted)
        | (State::CallerReservationCapturePending, State::CallerReserved)
        | (State::CallerReservationCapturePending, State::OutcomeUnknownAfterDispatch)
        | (State::CallerReserved, State::Completed)
        | (State::CallerReserved, State::OutcomeUnknownAfterDispatch)
        | (State::CompensationPending, State::CompensatedBeforeDispatch)
        | (State::DispatchCommitted, State::Completed)
        | (State::DispatchCommitted, State::OutcomeUnknownAfterDispatch) => true,
        _ => false,
    }
}

pub(super) fn validate_state_dispatch_pair(
    state: AdmissionOperationState,
    dispatch_state: AdmissionDispatchState,
) -> Result<(), AdmissionOperationError> {
    let valid = match state {
        AdmissionOperationState::Prepared
        | AdmissionOperationState::BrokerAttemptRegistered
        | AdmissionOperationState::BudgetAuthorized
        | AdmissionOperationState::DelegatedBudgetReserved
        | AdmissionOperationState::PaymentAuthorized
        | AdmissionOperationState::ApprovalReserved
        | AdmissionOperationState::ReadyToDispatch
        | AdmissionOperationState::CapturePending
        | AdmissionOperationState::CallerReservationCapturePending
        | AdmissionOperationState::CompensationPending
        | AdmissionOperationState::CompensatedBeforeDispatch => {
            dispatch_state == AdmissionDispatchState::NotStarted
        }
        AdmissionOperationState::DispatchCommitted => {
            dispatch_state == AdmissionDispatchState::Committed
        }
        AdmissionOperationState::CallerReserved => {
            dispatch_state == AdmissionDispatchState::Committed
        }
        AdmissionOperationState::Completed => {
            dispatch_state == AdmissionDispatchState::EffectCompleted
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => {
            dispatch_state == AdmissionDispatchState::OutcomeUnknown
        }
    };
    if valid {
        Ok(())
    } else {
        Err(AdmissionOperationError::Invalid(
            "admission state and dispatch state are inconsistent".to_string(),
        ))
    }
}

pub(super) fn validate_kind_participants(
    kind: AdmissionOperationKind,
    broker_attempt_id: Option<&str>,
    budget_hold_id: Option<&str>,
    execution_nonce_id: Option<&str>,
    state: AdmissionOperationState,
) -> Result<(), AdmissionOperationError> {
    if kind == AdmissionOperationKind::GovernedActiveResponse {
        if broker_attempt_id.is_some() || budget_hold_id.is_some() || execution_nonce_id.is_some() {
            return Err(AdmissionOperationError::Invalid(
                "governed active response cannot bind budget, broker, or nonce participants"
                    .to_string(),
            ));
        }
        if matches!(
            state,
            AdmissionOperationState::BrokerAttemptRegistered
                | AdmissionOperationState::BudgetAuthorized
                | AdmissionOperationState::DelegatedBudgetReserved
                | AdmissionOperationState::PaymentAuthorized
                | AdmissionOperationState::ReadyToDispatch
                | AdmissionOperationState::CapturePending
                | AdmissionOperationState::CallerReservationCapturePending
                | AdmissionOperationState::CallerReserved
        ) {
            return Err(AdmissionOperationError::Invalid(
                "governed active response has a tool-dispatch-only state".to_string(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_identifier(
    value: &str,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    if value.is_empty()
        || value.len() > MAX_ADMISSION_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(AdmissionOperationError::Invalid(format!(
            "{label} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

pub(super) fn validate_optional_identifier(
    value: Option<&str>,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    value.map_or(Ok(()), |value| validate_identifier(value, label))
}

pub(super) fn validate_digest(
    value: &str,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AdmissionOperationError::Invalid(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

pub(super) fn validate_optional_digest(
    value: Option<&str>,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    value.map_or(Ok(()), |value| validate_digest(value, label))
}

pub(super) fn validate_last_error(value: Option<&str>) -> Result<(), AdmissionOperationError> {
    if value.is_some_and(|value| {
        value.is_empty()
            || value.len() > MAX_ADMISSION_ERROR_BYTES
            || value.bytes().any(|byte| byte == 0)
    }) {
        return Err(AdmissionOperationError::Invalid(
            "last_error is empty, oversized, or contains NUL".to_string(),
        ));
    }
    Ok(())
}
