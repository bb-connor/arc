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
                return Err(AdmissionOperationError::Conflict(
                    "operation_id is already bound to different input".to_string(),
                ));
            }
            return Ok(AdmissionOperationCreateOutcome::Existing(existing.clone()));
        }
        if let Some(existing) = state.operations.values().find(|existing| {
            existing.kind() == operation.kind()
                && existing.request_id() == operation.request_id()
        }) {
            if existing.has_same_prepared_binding(&operation) {
                return Ok(AdmissionOperationCreateOutcome::Existing(existing.clone()));
            }
            return Err(AdmissionOperationError::Conflict(format!(
                "request_id `{}` is already owned by another {} operation",
                operation.request_id(),
                operation.kind().as_str()
            )));
        }
        if let Some(budget_hold_id) = operation.budget_hold_id() {
            if state.operations.values().any(|existing| {
                existing.budget_hold_id() == Some(budget_hold_id)
                    && existing.operation_id() != operation.operation_id()
            }) {
                return Err(AdmissionOperationError::Invalid(format!(
                    "budget_hold_id `{budget_hold_id}` is already owned by another admission operation"
                )));
            }
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

    fn load_by_request_id(
        &self,
        kind: AdmissionOperationKind,
        request_id: &str,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        validate_identifier(request_id, "request_id")?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut operations = self
            .lock()?
            .operations
            .values()
            .filter(|operation| {
                operation.kind() == kind && operation.request_id() == request_id
            })
            .cloned()
            .collect::<Vec<_>>();
        operations.sort_unstable_by(|left, right| left.operation_id().cmp(right.operation_id()));
        operations.truncate(limit);
        Ok(operations)
    }

    fn load_by_budget_hold_id(
        &self,
        budget_hold_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        validate_identifier(budget_hold_id, "budget_hold_id")?;
        let state = self.lock()?;
        let mut matches = state
            .operations
            .values()
            .filter(|operation| operation.budget_hold_id() == Some(budget_hold_id));
        let operation = matches.next().cloned();
        if matches.next().is_some() {
            return Err(AdmissionOperationError::Invalid(format!(
                "budget_hold_id `{budget_hold_id}` is owned by multiple admission operations"
            )));
        }
        Ok(operation)
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

    fn list_admission_recovery_candidates(
        &self,
        kind: AdmissionOperationKind,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut operations = state
            .operations
            .values()
            .filter(|operation| operation.kind() == kind)
            .filter(|operation| {
                !matches!(
                    operation.state(),
                    AdmissionOperationState::Completed
                        | AdmissionOperationState::CompensatedBeforeDispatch
                        | AdmissionOperationState::OutcomeUnknownAfterDispatch
                )
            })
            .map(|operation| {
                let priority = if operation.state() != AdmissionOperationState::CallerReserved {
                    0u8
                } else if state.cleanup_actions.values().any(|action| {
                    action.operation_id() == operation.operation_id()
                        && action.kind() == AdmissionCleanupActionKind::CallerReservationHandoff
                        && action.state() != AdmissionCleanupActionState::Completed
                }) {
                    1
                } else {
                    2
                };
                (priority, operation.clone())
            })
            .collect::<Vec<_>>();
        operations.sort_unstable_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.operation_id().cmp(right.1.operation_id()))
        });
        operations.truncate(limit);
        Ok(operations
            .into_iter()
            .map(|(_, operation)| operation)
            .collect())
    }

    fn list_caller_reservation_reap_candidates(
        &self,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let state = self.lock()?;
        let mut operations = state
            .operations
            .values()
            .filter(|operation| operation.kind() == AdmissionOperationKind::ToolDispatch)
            .filter(|operation| {
                matches!(
                    (operation.state(), operation.dispatch_state()),
                    (
                        AdmissionOperationState::CallerReserved,
                        AdmissionDispatchState::Committed
                    ) | (
                        AdmissionOperationState::CallerReservationCapturePending,
                        AdmissionDispatchState::NotStarted
                    )
                )
            })
            .filter(|operation| {
                after_operation_id.is_none_or(|after| operation.operation_id() > after)
            })
            .cloned()
            .collect::<Vec<_>>();
        operations.sort_unstable_by(|left, right| {
            left.operation_id().cmp(right.operation_id())
        });
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
            || request.next_state == AdmissionOperationState::CallerReserved
            || request.next_state.is_terminal()
        {
            return Err(AdmissionOperationError::Invalid(
                "compensation, caller-reserved, and terminal admission transitions require an atomic forward action"
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
        let required_action_kind = if request.next_state
            == AdmissionOperationState::CompensationPending
            || request.next_state.is_terminal()
        {
            Some(AdmissionCleanupActionKind::TerminalReceipt)
        } else if request.next_state == AdmissionOperationState::CallerReserved {
            Some(AdmissionCleanupActionKind::CallerReservationHandoff)
        } else {
            None
        };
        if required_action_kind != Some(action.kind()) {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission transition has the wrong forward action kind for its target state"
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
        if action.kind() == AdmissionCleanupActionKind::CallerReservationHandoff
            && (current.kind() != AdmissionOperationKind::ToolDispatch
                || current.state()
                    != AdmissionOperationState::CallerReservationCapturePending
                || current.dispatch_state() != AdmissionDispatchState::NotStarted
                || next_state != AdmissionOperationState::CallerReserved
                || next_dispatch_state != AdmissionDispatchState::Committed)
        {
            return Err(AdmissionOperationError::Invalid(
                "caller reservation handoff requires the exact capture-pending to caller-reserved edge"
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
        if action.kind() == AdmissionCleanupActionKind::CallerReservationHandoff {
            return Err(AdmissionOperationError::Invalid(
                "caller reservation final handoff must be inserted by its atomic state transition"
                    .to_string(),
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
        if action.kind() == AdmissionCleanupActionKind::CallerReservationHandoffIntent
            && (operation.kind() != AdmissionOperationKind::ToolDispatch
                || !matches!(
                    operation.state(),
                    AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::DelegatedBudgetReserved
                        | AdmissionOperationState::ReadyToDispatch
                )
                || operation.dispatch_state() != AdmissionDispatchState::NotStarted)
        {
            return Err(AdmissionOperationError::Invalid(
                "caller reservation handoff intent requires a pre-capture tool dispatch operation"
                    .to_string(),
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
                            && !matches!(
                                action.kind(),
                                AdmissionCleanupActionKind::CallerReservationHandoffIntent
                                    | AdmissionCleanupActionKind::CallerReservationHandoff
                            )
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
                action_kind != AdmissionCleanupActionKind::TerminalReceipt
                    || operation.state() != AdmissionOperationState::CompensationPending
            })
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
