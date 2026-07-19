impl AdmissionOperationStore for InMemoryAdmissionOperationStore {
    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        if operation.state != AdmissionOperationState::Prepared
            || operation.dispatch_state != AdmissionDispatchState::NotStarted
            || operation.version != 0
        {
            return Err(AdmissionOperationError::Invalid(
                "new admission operation is not Prepared at version zero".to_string(),
            ));
        }
        let mut state = self.lock()?;
        if let Some(existing) = state.operations.get(operation.operation_id()) {
            if !existing.has_same_prepared_binding(&operation) {
                return Err(AdmissionOperationError::Invalid(
                    "operation_id is already bound to different input".to_string(),
                ));
            }
            return Ok(AdmissionOperationCreateOutcome::Existing(existing.clone()));
        }
        state
            .operations
            .insert(operation.operation_id.clone(), operation.clone());
        Ok(AdmissionOperationCreateOutcome::Created(operation))
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        validate_identifier(operation_id, "operation_id")?;
        Ok(self.lock()?.operations.get(operation_id).cloned())
    }

    fn list_unresolved(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut operations = self
            .lock()?
            .operations
            .values()
            .filter(|operation| kind.is_none_or(|kind| operation.kind() == kind))
            .filter(|operation| {
                !matches!(
                    operation.state(),
                    AdmissionOperationState::Completed
                        | AdmissionOperationState::CompensatedBeforeDispatch
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        operations.sort_unstable_by(|left, right| left.operation_id().cmp(right.operation_id()));
        operations.truncate(limit);
        Ok(operations)
    }

    fn claim_recovery(
        &self,
        operation_id: &str,
        expected_version: u64,
        expected_coordinator_lease_epoch: u64,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        validate_identifier(operation_id, "operation_id")?;
        let mut state = self.lock()?;
        let Some(current) = state.operations.get(operation_id).cloned() else {
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != expected_coordinator_lease_epoch
        {
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        let claimed = current.claim_recovery_checked()?;
        state
            .operations
            .insert(operation_id.to_string(), claimed.clone());
        Ok(AdmissionOperationCasOutcome::Applied(claimed))
    }

    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError> {
        validate_identifier(coordinator_authority_id, "coordinator_authority_id")?;
        u64::try_from(
            self.lock()?
                .operations
                .values()
                .filter(|operation| {
                    operation.kind() == kind
                        && operation.coordinator_authority_id() == coordinator_authority_id
                        && !matches!(
                            operation.state(),
                            AdmissionOperationState::Completed
                                | AdmissionOperationState::CompensatedBeforeDispatch
                        )
                })
                .count(),
        )
        .map_err(|_| {
            AdmissionOperationError::Overflow("nonterminal operation count exceeds u64".to_string())
        })
    }

    fn count_unresolved(
        &self,
        kind: AdmissionOperationKind,
    ) -> Result<u64, AdmissionOperationError> {
        u64::try_from(
            self.lock()?
                .operations
                .values()
                .filter(|operation| {
                    operation.kind() == kind
                        && !matches!(
                            operation.state(),
                            AdmissionOperationState::Completed
                                | AdmissionOperationState::CompensatedBeforeDispatch
                        )
                })
                .count(),
        )
        .map_err(|_| {
            AdmissionOperationError::Overflow("nonterminal operation count exceeds u64".to_string())
        })
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if request.next_state == AdmissionOperationState::CompensationPending
            || request.next_state.is_terminal()
        {
            return Err(AdmissionOperationError::Invalid(
                "compensation and terminal admission transitions require an atomic terminal receipt action"
                    .to_string(),
            ));
        }
        let AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        } = request;
        validate_identifier(operation_id, "operation_id")?;
        let mut state = self.lock()?;
        let Some(current) = state.operations.get(operation_id).cloned() else {
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version != expected_version
            || current.coordinator_lease_epoch != coordinator_lease_epoch
        {
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        let next = current.transition_checked(
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )?;
        state
            .operations
            .insert(operation_id.to_string(), next.clone());
        Ok(AdmissionOperationCasOutcome::Applied(next))
    }

    fn compare_and_swap_with_cleanup_action(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if action.state() != AdmissionCleanupActionState::Pending || action.version() != 0 {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action is not Pending at version zero".to_string(),
            ));
        }
        let terminal_receipt_required = request.next_state
            == AdmissionOperationState::CompensationPending
            || request.next_state.is_terminal();
        if terminal_receipt_required
            != (action.kind() == AdmissionCleanupActionKind::TerminalReceipt)
        {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission transition has the wrong cleanup action kind for its target state"
                    .to_string(),
            ));
        }
        let AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        } = request;
        validate_identifier(operation_id, "operation_id")?;
        if action.operation_id() != operation_id {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action references a different operation".to_string(),
            ));
        }
        let mut state = self.lock()?;
        let Some(current) = state.operations.get(operation_id).cloned() else {
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != coordinator_lease_epoch
        {
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        if current.request_binding_hash() != action.request_binding_hash() {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action request binding differs from its operation"
                    .to_string(),
            ));
        }
        if let Some(existing) = state.cleanup_actions.values().find(|existing| {
            existing.operation_id() == operation_id && existing.kind() == action.kind()
        }) {
            if existing != &action {
                return Err(AdmissionOperationError::Invalid(
                    "atomic admission journal participant is already bound to a different payload"
                        .to_string(),
                ));
            }
        }
        let next = current.transition_checked(
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )?;
        state
            .cleanup_actions
            .entry(action.action_id().to_string())
            .or_insert(action);
        state
            .operations
            .insert(operation_id.to_string(), next.clone());
        Ok(AdmissionOperationCasOutcome::Applied(next))
    }

    fn create_cleanup_action(
        &self,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionCleanupActionCreateOutcome, AdmissionOperationError> {
        if action.state() != AdmissionCleanupActionState::Pending || action.version() != 0 {
            return Err(AdmissionOperationError::Invalid(
                "new admission cleanup action is not Pending at version zero".to_string(),
            ));
        }
        let mut state = self.lock()?;
        let operation = state.operations.get(action.operation_id()).ok_or_else(|| {
            AdmissionOperationError::Invalid(
                "cleanup action references a missing admission operation".to_string(),
            )
        })?;
        if operation.request_binding_hash() != action.request_binding_hash() {
            return Err(AdmissionOperationError::Invalid(
                "cleanup action request binding differs from its operation".to_string(),
            ));
        }
        if let Some(existing) = state
            .cleanup_actions
            .values()
            .find(|existing| {
                existing.operation_id() == action.operation_id() && existing.kind() == action.kind()
            })
            .cloned()
        {
            if existing != action {
                return Err(AdmissionOperationError::Invalid(
                    "cleanup participant is already bound to a different immutable projection"
                        .to_string(),
                ));
            }
            return Ok(AdmissionCleanupActionCreateOutcome::Existing(existing));
        }
        state
            .cleanup_actions
            .insert(action.action_id().to_string(), action.clone());
        Ok(AdmissionCleanupActionCreateOutcome::Created(action))
    }

    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        validate_digest(operation_id, "cleanup operation_id")?;
        let mut actions = self
            .lock()?
            .cleanup_actions
            .values()
            .filter(|action| action.operation_id() == operation_id)
            .cloned()
            .collect::<Vec<_>>();
        actions.sort_unstable_by_key(|action| action.kind().as_str());
        Ok(actions)
    }

    fn list_compensated_with_pending_cleanup(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut operation_ids = state
            .operations
            .values()
            .filter(|operation| {
                matches!(
                    operation.state(),
                    AdmissionOperationState::CompensationPending
                        | AdmissionOperationState::CompensatedBeforeDispatch
                )
                    && kind.is_none_or(|kind| operation.kind() == kind)
                    && state.cleanup_actions.values().any(|action| {
                        action.operation_id() == operation.operation_id()
                            && action.state() != AdmissionCleanupActionState::Completed
                    })
            })
            .map(|operation| operation.operation_id().to_string())
            .collect::<Vec<_>>();
        operation_ids.sort_unstable();
        operation_ids.truncate(limit);
        Ok(operation_ids)
    }

    fn list_operations_with_pending_cleanup_action(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut operation_ids = state
            .operations
            .values()
            .filter(|operation| operation.kind() == operation_kind)
            .filter(|operation| {
                state.cleanup_actions.values().any(|action| {
                    action.operation_id() == operation.operation_id()
                        && action.kind() == action_kind
                        && action.state() != AdmissionCleanupActionState::Completed
                })
            })
            .map(|operation| operation.operation_id().to_string())
            .collect::<Vec<_>>();
        operation_ids.sort_unstable();
        operation_ids.truncate(limit);
        Ok(operation_ids)
    }

    fn claim_cleanup_action(
        &self,
        action_id: &str,
        claim_token: &str,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<AdmissionCleanupActionClaimOutcome, AdmissionOperationError> {
        validate_digest(action_id, "cleanup action_id")?;
        validate_identifier(claim_token, "cleanup claim_token")?;
        let mut state = self.lock()?;
        let Some(current) = state.cleanup_actions.get(action_id).cloned() else {
            return Ok(AdmissionCleanupActionClaimOutcome::Missing);
        };
        if current.state() == AdmissionCleanupActionState::Completed {
            return Ok(AdmissionCleanupActionClaimOutcome::Completed(current));
        }
        if current.state() == AdmissionCleanupActionState::Claimed
            && current.claim_token() != Some(claim_token)
            && current
                .claim_deadline_unix_ms()
                .is_some_and(|deadline| deadline > now_unix_ms)
        {
            return Ok(AdmissionCleanupActionClaimOutcome::Busy(current));
        }
        if current.state() == AdmissionCleanupActionState::Claimed
            && current.claim_token() == Some(claim_token)
            && current
                .claim_deadline_unix_ms()
                .is_some_and(|deadline| deadline > now_unix_ms)
        {
            return Ok(AdmissionCleanupActionClaimOutcome::Claimed(current));
        }
        let next =
            current.claim_checked(claim_token.to_string(), now_unix_ms, claim_deadline_unix_ms)?;
        state
            .cleanup_actions
            .insert(action_id.to_string(), next.clone());
        Ok(AdmissionCleanupActionClaimOutcome::Claimed(next))
    }

    fn acknowledge_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        let mut state = self.lock()?;
        mutate_in_memory_cleanup_action(
            &mut state,
            action_id,
            expected_version,
            claim_token,
            AdmissionCleanupAction::acknowledge_checked,
        )
    }

    fn abandon_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
        last_error: String,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        let mut state = self.lock()?;
        mutate_in_memory_cleanup_action(
            &mut state,
            action_id,
            expected_version,
            claim_token,
            |action| action.abandon_checked(last_error),
        )
    }
}

pub fn derive_operation_id(
    kind: AdmissionOperationKind,
    coordinator_authority_id: &str,
    request_id: &str,
    capability_id: &str,
    authorization_capability_hash: &str,
    request_binding_hash: &str,
) -> Result<String, AdmissionOperationError> {
    validate_identifier(coordinator_authority_id, "coordinator_authority_id")?;
    validate_identifier(request_id, "request_id")?;
    validate_identifier(capability_id, "capability_id")?;
    validate_digest(
        authorization_capability_hash,
        "authorization_capability_hash",
    )?;
    validate_digest(request_binding_hash, "request_binding_hash")?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationIdentity<'a> {
        kind: AdmissionOperationKind,
        coordinator_authority_id: &'a str,
        request_id: &'a str,
        capability_id: &'a str,
        authorization_capability_hash: &'a str,
        request_binding_hash: &'a str,
    }
    let canonical = canonical_json_bytes(&OperationIdentity {
        kind,
        coordinator_authority_id,
        request_id,
        capability_id,
        authorization_capability_hash,
        request_binding_hash,
    })
    .map_err(|error| {
        AdmissionOperationError::Invalid(format!(
            "failed to canonicalize admission operation identity: {error}"
        ))
    })?;
    let mut bytes = Vec::with_capacity(ADMISSION_OPERATION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ADMISSION_OPERATION_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

pub fn derive_cleanup_action_id(
    operation_id: &str,
    request_binding_hash: &str,
    kind: AdmissionCleanupActionKind,
    payload_hash: &str,
) -> Result<String, AdmissionOperationError> {
    validate_digest(operation_id, "cleanup operation_id")?;
    validate_digest(request_binding_hash, "cleanup request_binding_hash")?;
    validate_digest(payload_hash, "cleanup payload_hash")?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CleanupIdentity<'a> {
        operation_id: &'a str,
        request_binding_hash: &'a str,
        kind: AdmissionCleanupActionKind,
        payload_hash: &'a str,
    }
    let canonical = canonical_json_bytes(&CleanupIdentity {
        operation_id,
        request_binding_hash,
        kind,
        payload_hash,
    })
    .map_err(|error| {
        AdmissionOperationError::Invalid(format!(
            "failed to canonicalize admission cleanup identity: {error}"
        ))
    })?;
    let mut bytes = Vec::with_capacity(ADMISSION_CLEANUP_ACTION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ADMISSION_CLEANUP_ACTION_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

fn validate_cleanup_payload(
    payload_json: &str,
    payload_hash: &str,
) -> Result<(), AdmissionOperationError> {
    if payload_json.is_empty() || payload_json.len() > MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES {
        return Err(AdmissionOperationError::Invalid(format!(
            "persisted cleanup payload must be between 1 and {MAX_ADMISSION_CLEANUP_PAYLOAD_BYTES} bytes"
        )));
    }
    validate_digest(payload_hash, "cleanup payload_hash")?;
    let value: serde_json::Value = serde_json::from_str(payload_json).map_err(|error| {
        AdmissionOperationError::Invalid(format!(
            "persisted cleanup payload is invalid JSON: {error}"
        ))
    })?;
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

fn validate_cleanup_claim(
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

fn mutate_in_memory_cleanup_action<F>(
    state: &mut InMemoryAdmissionOperationState,
    action_id: &str,
    expected_version: u64,
    claim_token: &str,
    mutation: F,
) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError>
where
    F: FnOnce(&AdmissionCleanupAction) -> Result<AdmissionCleanupAction, AdmissionOperationError>,
{
    validate_digest(action_id, "cleanup action_id")?;
    validate_identifier(claim_token, "cleanup claim_token")?;
    let Some(current) = state.cleanup_actions.get(action_id).cloned() else {
        return Ok(AdmissionCleanupActionCasOutcome::Missing);
    };
    if current.version() != expected_version || current.claim_token() != Some(claim_token) {
        return Ok(AdmissionCleanupActionCasOutcome::Conflict(current));
    }
    let next = mutation(&current)?;
    state
        .cleanup_actions
        .insert(action_id.to_string(), next.clone());
    Ok(AdmissionCleanupActionCasOutcome::Applied(next))
}

fn valid_state_transition(
    current: AdmissionOperationState,
    next: AdmissionOperationState,
    kind: AdmissionOperationKind,
) -> bool {
    use AdmissionOperationState as State;
    if current.is_terminal() {
        return false;
    }
    if next == State::CompensationPending {
        return !matches!(current, State::DispatchCommitted | State::CompensationPending);
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
        | (State::ReadyToDispatch, State::CapturePending) => {
            kind == AdmissionOperationKind::ToolDispatch
        }
        (State::ApprovalReserved, State::DispatchCommitted) => {
            kind == AdmissionOperationKind::GovernedActiveResponse
        }
        (State::CapturePending, State::DispatchCommitted)
        | (State::CompensationPending, State::CompensatedBeforeDispatch)
        | (State::DispatchCommitted, State::Completed)
        | (State::DispatchCommitted, State::OutcomeUnknownAfterDispatch) => true,
        _ => false,
    }
}

fn validate_state_dispatch_pair(
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
        | AdmissionOperationState::CompensationPending
        | AdmissionOperationState::CompensatedBeforeDispatch => {
            dispatch_state == AdmissionDispatchState::NotStarted
        }
        AdmissionOperationState::DispatchCommitted => {
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

fn validate_kind_participants(
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
        ) {
            return Err(AdmissionOperationError::Invalid(
                "governed active response has a tool-dispatch-only state".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), AdmissionOperationError> {
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

fn validate_optional_identifier(
    value: Option<&str>,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    value.map_or(Ok(()), |value| validate_identifier(value, label))
}

fn validate_digest(value: &str, label: &'static str) -> Result<(), AdmissionOperationError> {
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

fn validate_optional_digest(
    value: Option<&str>,
    label: &'static str,
) -> Result<(), AdmissionOperationError> {
    value.map_or(Ok(()), |value| validate_digest(value, label))
}

fn validate_last_error(value: Option<&str>) -> Result<(), AdmissionOperationError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cas_request<'a>(
        operation_id: &'a str,
        expected_version: u64,
        coordinator_lease_epoch: u64,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        next_coordinator_lease_epoch: u64,
        last_error: Option<String>,
    ) -> AdmissionOperationCompareAndSwap<'a> {
        AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        }
    }

    fn prepared(kind: AdmissionOperationKind) -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: "request-1".to_string(),
            capability_id: "capability-1".to_string(),
            authorization_capability_hash: "11".repeat(32),
            request_binding_hash: "22".repeat(32),
            policy_hash: "33".repeat(32),
            broker_attempt_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "attempt-1".to_string()),
            budget_hold_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "hold-1".to_string()),
            approval_set_hash: Some("44".repeat(32)),
            execution_nonce_id: (kind == AdmissionOperationKind::ToolDispatch)
                .then(|| "nonce-1".to_string()),
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    fn request_binding_parts() -> AdmissionRequestBindingParts {
        AdmissionRequestBindingParts {
            action_hash: "11".repeat(32),
            policy_hash: "77".repeat(32),
            governed_intent_hash: None,
            threshold_proposal_hash: Some("22".repeat(32)),
            verified_approval_set_hash: Some("33".repeat(32)),
            approval_token_digests: vec!["44".repeat(32), "55".repeat(32)],
            budget_hold_reference: Some("budget-hold-1".to_string()),
            supplemental_authorization_reference: Some("supplemental-1".to_string()),
            supplemental_authorization_digest: Some("66".repeat(32)),
            execution_nonce_reference: Some("nonce-1".to_string()),
        }
    }

    #[test]
    fn operation_id_is_fixed_and_identity_bound() {
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        assert_eq!(
            operation.operation_id(),
            "abb08f11721ae2dc1e0c5956c319971108ee2a6d0918f6dcacd162857fd2baf4"
        );
        assert_eq!(operation, prepared(AdmissionOperationKind::ToolDispatch));

        let mut changed = prepared(AdmissionOperationKind::ToolDispatch);
        changed.request_id = "request-2".to_string();
        assert_ne!(
            operation.operation_id(),
            derive_operation_id(
                changed.kind,
                &changed.coordinator_authority_id,
                &changed.request_id,
                &changed.capability_id,
                &changed.authorization_capability_hash,
                &changed.request_binding_hash,
            )
            .unwrap()
        );
    }

    #[test]
    fn approval_membership_order_cannot_change_request_binding() {
        let mut unordered = request_binding_parts();
        unordered.approval_token_digests.reverse();
        let left =
            AdmissionRequestBindingInput::from_unordered_approval_token_digests(unordered.clone())
                .unwrap();
        let right = AdmissionRequestBindingInput::new(request_binding_parts()).unwrap();
        assert_eq!(
            left.approval_token_digests(),
            right.approval_token_digests()
        );
        assert_eq!(left.derive_hash().unwrap(), right.derive_hash().unwrap());
        assert!(AdmissionRequestBindingInput::new(unordered).is_err());

        let mut changed_reference_parts = request_binding_parts();
        changed_reference_parts.supplemental_authorization_reference =
            Some("supplemental-2".to_string());
        let changed_reference = AdmissionRequestBindingInput::new(changed_reference_parts).unwrap();
        let mut changed_digest_parts = request_binding_parts();
        changed_digest_parts.supplemental_authorization_digest = Some("77".repeat(32));
        let changed_digest = AdmissionRequestBindingInput::new(changed_digest_parts).unwrap();
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_reference.derive_hash().unwrap()
        );
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_digest.derive_hash().unwrap()
        );
        let mut changed_budget = left.clone();
        changed_budget.budget_hold_reference = Some("budget-hold-2".to_string());
        let mut changed_policy = left.clone();
        changed_policy.policy_hash = "88".repeat(32);
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_budget.derive_hash().unwrap()
        );
        assert_ne!(
            left.derive_hash().unwrap(),
            changed_policy.derive_hash().unwrap()
        );
        let mut duplicate_parts = request_binding_parts();
        duplicate_parts.threshold_proposal_hash = None;
        duplicate_parts.verified_approval_set_hash = None;
        duplicate_parts.approval_token_digests = vec!["44".repeat(32), "44".repeat(32)];
        duplicate_parts.supplemental_authorization_reference = None;
        duplicate_parts.supplemental_authorization_digest = None;
        duplicate_parts.execution_nonce_reference = None;
        assert!(AdmissionRequestBindingInput::new(duplicate_parts).is_err());
    }

    #[test]
    fn compare_and_swap_is_versioned_and_lease_fenced() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let id = operation.operation_id().to_string();
        assert!(matches!(
            store.create_prepared(operation).unwrap(),
            AdmissionOperationCreateOutcome::Created(_)
        ));

        let applied = store
            .compare_and_swap(cas_request(
                &id,
                0,
                7,
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap();
        let AdmissionOperationCasOutcome::Applied(applied) = applied else {
            panic!("first transition should apply");
        };
        assert_eq!(applied.version(), 1);

        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &id,
                    1,
                    6,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
    }

    #[test]
    fn unresolved_count_includes_unknown_post_dispatch_outcomes() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::GovernedActiveResponse);
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        for (expected_version, state, dispatch) in [
            (
                0,
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
            ),
            (
                1,
                AdmissionOperationState::DispatchCommitted,
                AdmissionDispatchState::Committed,
            ),
            (
                2,
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                AdmissionDispatchState::OutcomeUnknown,
            ),
        ] {
            let outcome = if state.is_terminal() {
                let current = store.load(&id).unwrap().unwrap();
                let action = AdmissionCleanupAction::pending(
                    &current,
                    AdmissionCleanupActionKind::TerminalReceipt,
                    &serde_json::json!({"terminal": state.as_str()}),
                )
                .unwrap();
                store.compare_and_swap_with_cleanup_action(
                    cas_request(
                        &id,
                        expected_version,
                        7,
                        state,
                        dispatch,
                        7,
                        None,
                    ),
                    action,
                )
            } else {
                store.compare_and_swap(cas_request(
                    &id,
                    expected_version,
                    7,
                    state,
                    dispatch,
                    7,
                    None,
                ))
            };
            assert!(matches!(
                outcome.unwrap(),
                AdmissionOperationCasOutcome::Applied(_)
            ));
        }

        assert_eq!(
            store
                .count_unresolved_by_authority(
                    AdmissionOperationKind::GovernedActiveResponse,
                    "coordinator-1",
                )
                .unwrap(),
            1,
            "an unknown committed outcome still requires its original authority"
        );
    }

    #[test]
    fn recovery_inventory_is_bounded_and_claim_fences_stale_coordinators() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();

        assert!(store.list_unresolved(None, 0).unwrap().is_empty());
        assert_eq!(
            store
                .list_unresolved(Some(AdmissionOperationKind::ToolDispatch), 1)
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .list_unresolved(Some(AdmissionOperationKind::GovernedActiveResponse), 1,)
            .unwrap()
            .is_empty());

        let AdmissionOperationCasOutcome::Applied(claimed) =
            store.claim_recovery(&operation_id, 0, 7).unwrap()
        else {
            panic!("recovery claim should apply");
        };
        assert_eq!(claimed.state(), AdmissionOperationState::Prepared);
        assert_eq!(claimed.coordinator_lease_epoch(), 8);
        assert_eq!(claimed.version(), 1);
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &operation_id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));

        let terminal_action = AdmissionCleanupAction::pending(
            &claimed,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        let AdmissionOperationCasOutcome::Applied(compensation_pending) = store
            .compare_and_swap_with_cleanup_action(
                cas_request(
                    &operation_id,
                    claimed.version(),
                    claimed.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensationPending,
                    AdmissionDispatchState::NotStarted,
                    claimed.coordinator_lease_epoch(),
                    None,
                ),
                terminal_action.clone(),
            )
            .unwrap()
        else {
            panic!("compensation staging should apply");
        };
        assert!(matches!(
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        &operation_id,
                        compensation_pending.version(),
                        compensation_pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensatedBeforeDispatch,
                        AdmissionDispatchState::NotStarted,
                        compensation_pending.coordinator_lease_epoch(),
                        None,
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        assert!(store.list_unresolved(None, 1).unwrap().is_empty());
    }

    #[test]
    fn deterministic_create_recovers_an_advanced_operation() {
        let store = InMemoryAdmissionOperationStore::new();
        let prepared = prepared(AdmissionOperationKind::ToolDispatch);
        let operation_id = prepared.operation_id().to_string();
        store.create_prepared(prepared.clone()).unwrap();
        let advanced = match store
            .compare_and_swap(cas_request(
                &operation_id,
                0,
                7,
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap()
        {
            AdmissionOperationCasOutcome::Applied(operation) => operation,
            other => panic!("unexpected CAS outcome: {other:?}"),
        };
        assert!(matches!(
            store.create_prepared(prepared).unwrap(),
            AdmissionOperationCreateOutcome::Existing(existing) if existing == advanced
        ));
    }

    #[test]
    fn tool_dispatch_participant_stages_are_linear_and_parseable() {
        assert_eq!(
            AdmissionOperationState::parse("delegated_budget_reserved"),
            Some(AdmissionOperationState::DelegatedBudgetReserved)
        );
        assert_eq!(
            AdmissionOperationState::parse("payment_authorized"),
            Some(AdmissionOperationState::PaymentAuthorized)
        );
        assert_eq!(
            AdmissionOperationState::DelegatedBudgetReserved.as_str(),
            "delegated_budget_reserved"
        );
        assert_eq!(
            AdmissionOperationState::PaymentAuthorized.as_str(),
            "payment_authorized"
        );

        let budget_authorized = prepared(AdmissionOperationKind::ToolDispatch)
            .transition_checked(
                AdmissionOperationState::BudgetAuthorized,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(budget_authorized
            .transition_checked(
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .is_err());

        let delegated_budget_reserved = budget_authorized
            .transition_checked(
                AdmissionOperationState::DelegatedBudgetReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(delegated_budget_reserved
            .transition_checked(
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .is_err());

        let payment_authorized = delegated_budget_reserved
            .transition_checked(
                AdmissionOperationState::PaymentAuthorized,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(payment_authorized
            .transition_checked(
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .is_ok());
    }

    #[test]
    fn dispatch_commit_precedes_effect_terminal_states() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let mut version = 0;
        for state in [
            AdmissionOperationState::BrokerAttemptRegistered,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::DelegatedBudgetReserved,
            AdmissionOperationState::PaymentAuthorized,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::ReadyToDispatch,
            AdmissionOperationState::CapturePending,
        ] {
            let AdmissionOperationCasOutcome::Applied(applied) = store
                .compare_and_swap(cas_request(
                    &id,
                    version,
                    7,
                    state,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                ))
                .unwrap()
            else {
                panic!("transition should apply");
            };
            version = applied.version();
        }
        assert!(store
            .compare_and_swap(cas_request(
                &id,
                version,
                7,
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            ))
            .is_err());
        let AdmissionOperationCasOutcome::Applied(committed) = store
            .compare_and_swap(cas_request(
                &id,
                version,
                7,
                AdmissionOperationState::DispatchCommitted,
                AdmissionDispatchState::Committed,
                7,
                None,
            ))
            .unwrap()
        else {
            panic!("dispatch commit should apply");
        };
        assert!(matches!(
            store.compare_and_swap(cas_request(
                &id,
                committed.version(),
                7,
                AdmissionOperationState::Completed,
                AdmissionDispatchState::EffectCompleted,
                7,
                None,
            )),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let terminal_action = AdmissionCleanupAction::pending(
            &committed,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "completed"}),
        )
        .unwrap();
        assert!(matches!(
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        &id,
                        committed.version(),
                        7,
                        AdmissionOperationState::Completed,
                        AdmissionDispatchState::EffectCompleted,
                        7,
                        None,
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }

    #[test]
    fn dispatch_and_compensation_share_one_versioned_winner_fence() {
        fn capture_pending_store() -> (InMemoryAdmissionOperationStore, AdmissionOperation) {
            let store = InMemoryAdmissionOperationStore::new();
            let operation = prepared(AdmissionOperationKind::ToolDispatch);
            let id = operation.operation_id().to_string();
            store.create_prepared(operation).unwrap();
            let mut current = store.load(&id).unwrap().unwrap();
            for state in [
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionOperationState::BudgetAuthorized,
                AdmissionOperationState::DelegatedBudgetReserved,
                AdmissionOperationState::PaymentAuthorized,
                AdmissionOperationState::ApprovalReserved,
                AdmissionOperationState::ReadyToDispatch,
                AdmissionOperationState::CapturePending,
            ] {
                let AdmissionOperationCasOutcome::Applied(next) = store
                    .compare_and_swap(cas_request(
                        &id,
                        current.version(),
                        current.coordinator_lease_epoch(),
                        state,
                        AdmissionDispatchState::NotStarted,
                        current.coordinator_lease_epoch(),
                        None,
                    ))
                    .unwrap()
                else {
                    panic!("capture-pending setup should apply");
                };
                current = next;
            }
            (store, current)
        }

        let (dispatch_store, pending) = capture_pending_store();
        assert!(matches!(
            dispatch_store
                .compare_and_swap(cas_request(
                    pending.operation_id(),
                    pending.version(),
                    pending.coordinator_lease_epoch(),
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionDispatchState::Committed,
                    pending.coordinator_lease_epoch(),
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        let terminal_action = AdmissionCleanupAction::pending(
            &pending,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        assert!(matches!(
            dispatch_store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        pending.operation_id(),
                        pending.version(),
                        pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensationPending,
                        AdmissionDispatchState::NotStarted,
                        pending.coordinator_lease_epoch(),
                        Some("loser".to_string()),
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(current)
                if current.state() == AdmissionOperationState::DispatchCommitted
        ));

        let (compensation_store, pending) = capture_pending_store();
        let terminal_action = AdmissionCleanupAction::pending(
            &pending,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        let AdmissionOperationCasOutcome::Applied(compensation_pending) = compensation_store
            .compare_and_swap_with_cleanup_action(
                cas_request(
                    pending.operation_id(),
                    pending.version(),
                    pending.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensationPending,
                    AdmissionDispatchState::NotStarted,
                    pending.coordinator_lease_epoch(),
                    Some("winner".to_string()),
                ),
                terminal_action.clone(),
            )
            .unwrap()
        else {
            panic!("compensation staging should apply");
        };
        assert!(matches!(
            compensation_store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        compensation_pending.operation_id(),
                        compensation_pending.version(),
                        compensation_pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensatedBeforeDispatch,
                        AdmissionDispatchState::NotStarted,
                        compensation_pending.coordinator_lease_epoch(),
                        Some("winner".to_string()),
                    ),
                    terminal_action.clone(),
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        assert!(matches!(
            compensation_store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        pending.operation_id(),
                        pending.version(),
                        pending.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensatedBeforeDispatch,
                        AdmissionDispatchState::NotStarted,
                        pending.coordinator_lease_epoch(),
                        Some("second contender".to_string()),
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(current)
                if current.state() == AdmissionOperationState::CompensatedBeforeDispatch
        ));
        assert!(matches!(
            compensation_store
                .compare_and_swap(cas_request(
                    pending.operation_id(),
                    pending.version(),
                    pending.coordinator_lease_epoch(),
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionDispatchState::Committed,
                    pending.coordinator_lease_epoch(),
                    Some("second contender".to_string()),
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(current)
                if current.state() == AdmissionOperationState::CompensatedBeforeDispatch
        ));
    }

    #[test]
    fn approval_only_flow_omits_budget_and_dispatches_after_reservation() {
        let operation = prepared(AdmissionOperationKind::GovernedActiveResponse);
        assert!(operation.budget_hold_id().is_none());
        assert!(operation.execution_nonce_id().is_none());
        let store = InMemoryAdmissionOperationStore::new();
        let id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let AdmissionOperationCasOutcome::Applied(reserved) = store
            .compare_and_swap(cas_request(
                &id,
                0,
                7,
                AdmissionOperationState::ApprovalReserved,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            ))
            .unwrap()
        else {
            panic!("approval reservation should apply");
        };
        assert!(matches!(
            store
                .compare_and_swap(cas_request(
                    &id,
                    reserved.version(),
                    7,
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionDispatchState::Committed,
                    7,
                    None,
                ))
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
    }

    #[test]
    fn cleanup_action_retries_require_the_exact_payload_and_state() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        store.create_prepared(operation.clone()).unwrap();
        let original = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::Budget,
            &serde_json::json!({"participant": "budget", "value": 1}),
        )
        .unwrap();
        assert!(matches!(
            store.create_cleanup_action(original.clone()).unwrap(),
            AdmissionCleanupActionCreateOutcome::Created(_)
        ));

        let mut changed_payload = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::Budget,
            &serde_json::json!({"participant": "budget", "value": 2}),
        )
        .unwrap();
        changed_payload.action_id = original.action_id().to_string();
        assert!(matches!(
            store.create_cleanup_action(changed_payload.clone()),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    None,
                ),
                changed_payload,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert_eq!(store.load(operation.operation_id()).unwrap(), Some(operation.clone()));

        let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = store
            .claim_cleanup_action(original.action_id(), "worker", 100, 200)
            .unwrap()
        else {
            panic!("cleanup action should be claimable");
        };
        assert!(matches!(
            store
                .acknowledge_cleanup_action(claimed.action_id(), claimed.version(), "worker")
                .unwrap(),
            AdmissionCleanupActionCasOutcome::Applied(_)
        ));
        assert!(matches!(
            store.create_cleanup_action(original.clone()),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    None,
                ),
                original,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
    }

    #[test]
    fn completed_terminal_action_cannot_finalize_compensation_pending_operation() {
        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        store.create_prepared(operation.clone()).unwrap();
        let terminal_action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        let AdmissionOperationCasOutcome::Applied(compensation_pending) = store
            .compare_and_swap_with_cleanup_action(
                cas_request(
                    operation.operation_id(),
                    operation.version(),
                    operation.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensationPending,
                    AdmissionDispatchState::NotStarted,
                    operation.coordinator_lease_epoch(),
                    Some("deny".to_string()),
                ),
                terminal_action.clone(),
            )
            .unwrap()
        else {
            panic!("compensation staging should apply");
        };
        let AdmissionCleanupActionClaimOutcome::Claimed(claimed) = store
            .claim_cleanup_action(terminal_action.action_id(), "worker", 100, 200)
            .unwrap()
        else {
            panic!("terminal action should be claimable");
        };
        store
            .acknowledge_cleanup_action(claimed.action_id(), claimed.version(), "worker")
            .unwrap();
        assert!(matches!(
            store.compare_and_swap_with_cleanup_action(
                cas_request(
                    compensation_pending.operation_id(),
                    compensation_pending.version(),
                    compensation_pending.coordinator_lease_epoch(),
                    AdmissionOperationState::CompensatedBeforeDispatch,
                    AdmissionDispatchState::NotStarted,
                    compensation_pending.coordinator_lease_epoch(),
                    Some("deny".to_string()),
                ),
                terminal_action,
            ),
            Err(AdmissionOperationError::Invalid(_))
        ));
        assert_eq!(
            store.load(operation.operation_id()).unwrap(),
            Some(compensation_pending)
        );
    }

    #[test]
    fn cleanup_journal_recovers_every_participant_and_fences_two_workers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let store = InMemoryAdmissionOperationStore::new();
        let operation = prepared(AdmissionOperationKind::ToolDispatch);
        store.create_prepared(operation.clone()).unwrap();
        let kinds = [
            AdmissionCleanupActionKind::Budget,
            AdmissionCleanupActionKind::Payment,
            AdmissionCleanupActionKind::DelegatedBudget,
            AdmissionCleanupActionKind::Approval,
            AdmissionCleanupActionKind::ExecutionNonce,
            AdmissionCleanupActionKind::Broker,
        ];
        for kind in kinds {
            let action = AdmissionCleanupAction::pending(
                &operation,
                kind,
                &serde_json::json!({
                    "operationId": operation.operation_id(),
                    "participant": kind.as_str(),
                }),
            )
            .unwrap();
            assert!(matches!(
                store.create_cleanup_action(action).unwrap(),
                AdmissionCleanupActionCreateOutcome::Created(_)
            ));
        }
        let terminal_action = AdmissionCleanupAction::pending(
            &operation,
            AdmissionCleanupActionKind::TerminalReceipt,
            &serde_json::json!({"terminal": "compensated_before_dispatch"}),
        )
        .unwrap();
        assert!(matches!(
            store
                .compare_and_swap_with_cleanup_action(
                    cas_request(
                        operation.operation_id(),
                        operation.version(),
                        operation.coordinator_lease_epoch(),
                        AdmissionOperationState::CompensationPending,
                        AdmissionDispatchState::NotStarted,
                        operation.coordinator_lease_epoch(),
                        Some("deny".to_string()),
                    ),
                    terminal_action,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Applied(_)
        ));
        assert_eq!(
            store
                .list_compensated_with_pending_cleanup(None, 1)
                .unwrap(),
            vec![operation.operation_id().to_string()]
        );

        let releases = AtomicUsize::new(0);
        for action in store
            .load_cleanup_actions(operation.operation_id())
            .unwrap()
        {
            let AdmissionCleanupActionClaimOutcome::Claimed(crashed_claim) = store
                .claim_cleanup_action(action.action_id(), "crashed-worker", 100, 200)
                .unwrap()
            else {
                panic!("first worker should claim the participant");
            };
            assert!(matches!(
                store
                    .claim_cleanup_action(action.action_id(), "concurrent-worker", 150, 250)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Busy(current)
                    if current.version() == crashed_claim.version()
            ));
            let AdmissionCleanupActionClaimOutcome::Claimed(recovered_claim) = store
                .claim_cleanup_action(action.action_id(), "recovery-worker", 200, 300)
                .unwrap()
            else {
                panic!("expired crash claim should be recoverable");
            };
            releases.fetch_add(1, Ordering::SeqCst);

            // Model a successful participant release followed by loss of the
            // cleanup-state write acknowledgement. The durable state is
            // Completed, so exact retry observes completion and cannot run the
            // participant a second time.
            let acknowledged = store
                .acknowledge_cleanup_action(
                    recovered_claim.action_id(),
                    recovered_claim.version(),
                    "recovery-worker",
                )
                .unwrap();
            assert!(matches!(
                acknowledged,
                AdmissionCleanupActionCasOutcome::Applied(_)
            ));
            assert!(matches!(
                store
                    .acknowledge_cleanup_action(
                        recovered_claim.action_id(),
                        recovered_claim.version(),
                        "recovery-worker",
                    )
                    .unwrap(),
                AdmissionCleanupActionCasOutcome::Conflict(current)
                    if current.state() == AdmissionCleanupActionState::Completed
            ));
            assert!(matches!(
                store
                    .claim_cleanup_action(action.action_id(), "late-worker", 400, 500)
                    .unwrap(),
                AdmissionCleanupActionClaimOutcome::Completed(_)
            ));
        }
        assert_eq!(releases.load(Ordering::SeqCst), kinds.len() + 1);
        assert!(store
            .list_compensated_with_pending_cleanup(None, 8)
            .unwrap()
            .is_empty());
    }
}
