impl ChioKernel {
    pub(super) fn drain_compensated_admission_operations_with_authorities(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        kind: Option<AdmissionOperationKind>,
    ) -> Result<usize, KernelError> {
        let scan_limit = MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION
            .checked_add(1)
            .ok_or_else(|| {
                KernelError::Internal("activation cleanup scan limit overflowed usize".to_string())
            })?;
        let mut operation_ids =
            operation_store.list_compensated_with_pending_cleanup(kind, scan_limit)?;
        let overflowed_bound =
            operation_ids.len() > MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION;
        operation_ids.truncate(MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION);
        self.recover_compensated_admission_operation_ids(
            operation_store,
            budget_store,
            approval_store,
            operation_ids,
            overflowed_bound,
        )
    }

    pub(super) fn recover_compensated_admission_operations_with_authorities(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<usize, KernelError> {
        let operation_ids = operation_store.list_compensated_with_pending_cleanup(kind, limit)?;
        self.recover_compensated_admission_operation_ids(
            operation_store,
            budget_store,
            approval_store,
            operation_ids,
            false,
        )
    }

    fn recover_compensated_admission_operation_ids(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation_ids: Vec<String>,
        overflowed_bound: bool,
    ) -> Result<usize, KernelError> {
        let mut completed = 0usize;
        let mut errors = Vec::new();
        for operation_id in operation_ids {
            match self.recover_compensated_admission_operation_with_authorities(
                operation_store,
                budget_store,
                approval_store,
                &operation_id,
            ) {
                Ok(true) => {
                    completed = completed.checked_add(1).ok_or_else(|| {
                        KernelError::Internal("cleanup recovery count overflowed usize".to_string())
                    })?;
                }
                Ok(false) => errors.push(format!(
                    "operation {operation_id} cleanup is owned by another recovery worker"
                )),
                Err(error) => errors.push(format!("operation {operation_id}: {error}")),
            }
        }
        if overflowed_bound {
            errors.push(format!(
                "activation cleanup backlog exceeds the bounded {MAX_ADMISSION_CLEANUP_RECOVERY_OPERATIONS_PER_ACTIVATION}-operation scan"
            ));
        }
        if errors.is_empty() {
            Ok(completed)
        } else {
            Err(KernelError::Internal(format!(
                "one or more admission cleanup operations remain unfinished: {}",
                errors.join("; ")
            )))
        }
    }

    pub(super) fn recover_compensated_admission_operation(
        &self,
        operation_id: &str,
    ) -> Result<bool, KernelError> {
        let store = self.admission_operation_store.as_ref().ok_or_else(|| {
            KernelError::Internal("durable admission operation store is unavailable".to_string())
        })?;
        self.recover_compensated_admission_operation_with_authorities(
            store.as_ref(),
            self.budget_store.as_ref(),
            self.approval_store.as_deref(),
            operation_id,
        )
    }

    fn recover_compensated_admission_operation_with_authorities(
        &self,
        operation_store: &dyn AdmissionOperationStore,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation_id: &str,
    ) -> Result<bool, KernelError> {
        let operation = operation_store.load(operation_id)?.ok_or_else(|| {
            KernelError::Internal(format!(
                "cleanup recovery operation {operation_id} disappeared"
            ))
        })?;
        if !matches!(
            operation.state(),
            AdmissionOperationState::CompensationPending
                | AdmissionOperationState::CompensatedBeforeDispatch
        ) {
            return Err(KernelError::Internal(format!(
                "cleanup recovery refused operation {} in {}",
                operation.operation_id(),
                operation.state().as_str()
            )));
        }
        let actions = operation_store.load_cleanup_actions(operation_id)?;
        let mut errors = Vec::new();
        for action in actions {
            if action.state() == AdmissionCleanupActionState::Completed {
                continue;
            }
            if action.kind() == AdmissionCleanupActionKind::TerminalReceipt {
                continue;
            }
            let now_unix_ms = match cleanup_unix_ms() {
                Ok(now_unix_ms) => now_unix_ms,
                Err(error) => {
                    errors.push(format!("action {}: {error}", action.action_id()));
                    continue;
                }
            };
            let Some(claim_deadline_unix_ms) = now_unix_ms.checked_add(CLEANUP_CLAIM_LEASE_MS)
            else {
                errors.push(format!(
                    "action {}: cleanup claim deadline overflowed u64",
                    action.action_id()
                ));
                continue;
            };
            let claim_token = uuid::Uuid::now_v7().to_string();
            let claim = operation_store.claim_cleanup_action(
                action.action_id(),
                &claim_token,
                now_unix_ms,
                claim_deadline_unix_ms,
            );
            let claimed = match claim {
                Ok(AdmissionCleanupActionClaimOutcome::Claimed(action)) => action,
                Ok(AdmissionCleanupActionClaimOutcome::Completed(_)) => continue,
                Ok(AdmissionCleanupActionClaimOutcome::Busy(_)) => continue,
                Ok(AdmissionCleanupActionClaimOutcome::Missing) => {
                    errors.push(format!(
                        "action {} disappeared during cleanup claim",
                        action.action_id()
                    ));
                    continue;
                }
                Err(error) => {
                    let recovered =
                        match operation_store.load_cleanup_actions(operation.operation_id()) {
                            Ok(actions) => actions
                                .into_iter()
                                .find(|current| current.action_id() == action.action_id()),
                            Err(reload_error) => {
                                errors.push(format!(
                                "action {} claim failed ({error}); reload failed: {reload_error}",
                                action.action_id()
                            ));
                                continue;
                            }
                        };
                    match recovered {
                        Some(current)
                            if current.state() == AdmissionCleanupActionState::Claimed
                                && current.claim_token() == Some(claim_token.as_str()) =>
                        {
                            current
                        }
                        Some(current)
                            if current.state() == AdmissionCleanupActionState::Completed =>
                        {
                            continue
                        }
                        _ => {
                            errors.push(format!(
                                "action {} cleanup claim acknowledgement is uncertain: {error}",
                                action.action_id()
                            ));
                            continue;
                        }
                    }
                }
            };
            if let Err(error) =
                self.execute_cleanup_action(budget_store, approval_store, &operation, &claimed)
            {
                let abandoned = operation_store.abandon_cleanup_action(
                    claimed.action_id(),
                    claimed.version(),
                    &claim_token,
                    error.to_string(),
                );
                match abandoned {
                    Ok(AdmissionCleanupActionCasOutcome::Applied(_)) => {
                        errors.push(format!(
                            "action {} cleanup participant failed: {error}",
                            claimed.action_id()
                        ));
                    }
                    Ok(AdmissionCleanupActionCasOutcome::Conflict(current))
                        if current.state() == AdmissionCleanupActionState::Completed => {}
                    Ok(AdmissionCleanupActionCasOutcome::Conflict(_)) => {
                        errors.push(format!(
                            "action {} cleanup participant failed ({error}); journal release conflicted",
                            claimed.action_id()
                        ));
                    }
                    Ok(AdmissionCleanupActionCasOutcome::Missing) => {
                        errors.push(format!(
                            "action {} cleanup participant failed ({error}); journal action disappeared",
                            claimed.action_id()
                        ));
                    }
                    Err(abandon_error) => {
                        errors.push(format!(
                            "action {} cleanup participant failed ({error}); journal release failed: {abandon_error}",
                            claimed.action_id()
                        ));
                    }
                }
                continue;
            }
            match operation_store.acknowledge_cleanup_action(
                claimed.action_id(),
                claimed.version(),
                &claim_token,
            ) {
                Ok(AdmissionCleanupActionCasOutcome::Applied(_)) => {}
                Ok(AdmissionCleanupActionCasOutcome::Conflict(current))
                    if current.state() == AdmissionCleanupActionState::Completed => {}
                Ok(AdmissionCleanupActionCasOutcome::Conflict(_)) => {}
                Ok(AdmissionCleanupActionCasOutcome::Missing) => {
                    errors.push(format!(
                        "action {} disappeared before cleanup acknowledgement",
                        claimed.action_id()
                    ));
                }
                Err(error) => {
                    let current = match operation_store
                        .load_cleanup_actions(operation.operation_id())
                    {
                        Ok(actions) => actions
                            .into_iter()
                            .find(|current| current.action_id() == claimed.action_id()),
                        Err(reload_error) => {
                            errors.push(format!(
                                "action {} acknowledgement failed ({error}); reload failed: {reload_error}",
                                claimed.action_id()
                            ));
                            continue;
                        }
                    };
                    if !current.is_some_and(|current| {
                        current.state() == AdmissionCleanupActionState::Completed
                    }) {
                        errors.push(format!(
                            "action {} cleanup acknowledgement is uncertain: {error}",
                            claimed.action_id()
                        ));
                    }
                }
            }
        }
        let participants_completed = match operation_store.load_cleanup_actions(operation_id) {
            Ok(actions) => actions.iter().all(|action| {
                action.kind() == AdmissionCleanupActionKind::TerminalReceipt
                    || action.state() == AdmissionCleanupActionState::Completed
            }),
            Err(error) => {
                errors.push(format!("final cleanup journal reload failed: {error}"));
                false
            }
        };
        if errors.is_empty() && participants_completed {
            let current = operation_store.load(operation_id)?.ok_or_else(|| {
                KernelError::Internal(
                    "compensation operation disappeared before terminal receipt commit".to_string(),
                )
            })?;
            match current.state() {
                AdmissionOperationState::CompensationPending => {
                    self.finalize_staged_compensation_terminal_receipt(operation_store, &current)?;
                }
                AdmissionOperationState::CompensatedBeforeDispatch => {
                    self.validate_terminal_receipt_binding_with_store(operation_store, &current)?;
                    self.recover_terminal_receipt_outboxes_with_store(
                        operation_store,
                        current.kind(),
                        Some(current.coordinator_authority_id()),
                    )?;
                }
                state => {
                    return Err(KernelError::Internal(format!(
                        "compensation operation changed to {} before terminal receipt commit",
                        state.as_str()
                    )))
                }
            }
            Ok(true)
        } else if errors.is_empty() {
            Ok(false)
        } else {
            Err(KernelError::Internal(format!(
                "admission operation {operation_id} cleanup remains unfinished: {}",
                errors.join("; ")
            )))
        }
    }

    fn execute_cleanup_action(
        &self,
        budget_store: &dyn BudgetStore,
        approval_store: Option<&dyn ApprovalStore>,
        operation: &AdmissionOperation,
        action: &AdmissionCleanupAction,
    ) -> Result<(), KernelError> {
        if action.operation_id() != operation.operation_id()
            || action.request_binding_hash() != operation.request_binding_hash()
        {
            return Err(KernelError::Internal(
                "cleanup action does not match its admission operation".to_string(),
            ));
        }
        match action.kind() {
            AdmissionCleanupActionKind::Budget => {
                let payload: BudgetCleanupPayload = parse_cleanup_payload(action)?;
                validate_schema(&payload.schema, BUDGET_CLEANUP_SCHEMA)?;
                if payload.authorization.operation_id() != operation.operation_id()
                    || payload.authorization.request_binding_hash()
                        != operation.request_binding_hash()
                    || payload.authorization.capability_id() != operation.capability_id()
                    || Some(payload.authorization.hold_id()) != operation.budget_hold_id()
                {
                    return Err(KernelError::Internal(
                        "budget cleanup payload has a different operation or participant binding"
                            .to_string(),
                    ));
                }
                self.execute_budget_cleanup(budget_store, payload.authorization)
            }
            AdmissionCleanupActionKind::Payment => {
                let payload: PaymentCleanupPayload = parse_cleanup_payload(action)?;
                validate_schema(&payload.schema, PAYMENT_CLEANUP_SCHEMA)?;
                self.execute_payment_cleanup(operation, payload)
            }
            AdmissionCleanupActionKind::DelegatedBudget => {
                let payload: DelegatedBudgetCleanupPayload = parse_cleanup_payload(action)?;
                validate_schema(&payload.schema, DELEGATED_BUDGET_CLEANUP_SCHEMA)?;
                self.execute_delegated_budget_cleanup(operation, payload)
            }
            AdmissionCleanupActionKind::Approval => {
                let payload = if operation.kind() == AdmissionOperationKind::GovernedActiveResponse
                {
                    let active: ActiveResponseApprovalCleanupPayload =
                        parse_cleanup_payload(action)?;
                    validate_schema(&active.schema, ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA)?;
                    if !active.dispatch_anchor.is_valid()
                        || !approval_set_input_is_valid(&active.approval_set)
                        || active.approval_set.approval_set_hash()
                            != active.dispatch_anchor.approval_set_hash
                    {
                        return Err(KernelError::Internal(
                            "active-response approval cleanup anchor is invalid".to_string(),
                        ));
                    }
                    ApprovalCleanupPayload {
                        schema: APPROVAL_CLEANUP_SCHEMA.to_string(),
                        operation_id: active.operation_id,
                        approval_set: active.approval_set,
                    }
                } else {
                    let payload: ApprovalCleanupPayload = parse_cleanup_payload(action)?;
                    validate_schema(&payload.schema, APPROVAL_CLEANUP_SCHEMA)?;
                    payload
                };
                self.execute_approval_cleanup(approval_store, operation, payload)
            }
            AdmissionCleanupActionKind::ExecutionNonce => {
                let payload: NonceCleanupPayload = parse_cleanup_payload(action)?;
                validate_schema(&payload.schema, NONCE_CLEANUP_SCHEMA)?;
                self.execute_nonce_cleanup(operation, payload)
            }
            AdmissionCleanupActionKind::Broker => {
                let payload: BrokerCleanupPayload = parse_cleanup_payload(action)?;
                validate_schema(&payload.schema, BROKER_CLEANUP_SCHEMA)?;
                self.execute_broker_cleanup(operation, payload)
            }
            AdmissionCleanupActionKind::TerminalReceipt => Err(KernelError::Internal(
                "terminal receipt outboxes must be replayed forward by terminal receipt recovery"
                    .to_string(),
            )),
        }
    }

    fn execute_budget_cleanup(
        &self,
        store: &dyn BudgetStore,
        snapshot: BudgetAuthorizationCleanupSnapshot,
    ) -> Result<(), KernelError> {
        let _guard = match self.budget_store_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        (|| {
            let authorization = snapshot.authorization_request()?;
            let expected_hold = authorization.hold_id.clone();
            let expected_authorize_event = authorization.event_id.clone().ok_or_else(|| {
                KernelError::Internal(
                    "budget cleanup authorization omitted its event identifier".to_string(),
                )
            })?;
            let expected_exposure = authorization.requested_exposure_units;
            let expected_authority = authorization.authority.clone();
            let expected_revocation_set = authorization.revocation_set().cloned();
            let expected_monetary_state = if authorization.requested_exposure_units > 0
                || authorization.max_cost_per_invocation.is_some()
                || authorization.max_total_cost_units.is_some()
            {
                BudgetMonetaryHoldState::Exposed
            } else {
                BudgetMonetaryHoldState::None
            };
            let decision = store
                .authorize_budget_hold(authorization.clone())
                .or_else(|_| store.authorize_budget_hold(authorization))?;
            let authorized = match decision {
                BudgetAuthorizeHoldDecision::Authorized(authorized) => authorized,
                BudgetAuthorizeHoldDecision::Denied(denied) => {
                    self.validate_budget_cleanup_denial(BudgetCleanupDenialValidation {
                        store,
                        denied: &denied,
                        expected_hold_id: expected_hold.as_deref(),
                        expected_exposure,
                        expected_event_id: &expected_authorize_event,
                        expected_authority: expected_authority.as_ref(),
                        expected_revocation_set: expected_revocation_set.as_ref(),
                    })?;
                    // A validated exact authoritative denial proves that this
                    // operation never acquired a hold. There is no effect to
                    // undo.
                    return Ok(());
                }
            };
            self.validate_hard_budget_commit_metadata_for_store(
                store,
                &authorized.metadata,
                &expected_authorize_event,
                expected_authority.as_ref(),
                None,
                "cleanup authorization replay",
            )?;
            if authorized.hold_id.as_deref() != expected_hold.as_deref()
                || authorized.authorized_exposure_units != expected_exposure
                || authorized.invocation_state != BudgetInvocationReservationState::Authorized
                || authorized.monetary_state != expected_monetary_state
                || authorized.revocation_set.as_ref() != expected_revocation_set.as_ref()
            {
                return Err(KernelError::Internal(
                    "budget cleanup authorization replay did not match the journaled effect"
                        .to_string(),
                ));
            }
            let authority =
                if store.budget_guarantee_level() == BudgetGuaranteeLevel::SingleNodeAtomic {
                    snapshot.requested_authority().cloned()
                } else {
                    authorized.metadata.authority.clone()
                };
            let reverse = snapshot.reverse_request(authority.clone())?;
            let expected_hold = reverse.hold_id.clone();
            let expected_event = reverse.event_id.clone().ok_or_else(|| {
                KernelError::Internal(
                    "budget cleanup reverse omitted its event identifier".to_string(),
                )
            })?;
            let reversed = store
                .reverse_budget_hold(reverse.clone())
                .or_else(|_| store.reverse_budget_hold(reverse))?;
            self.validate_hard_budget_commit_metadata_for_store(
                store,
                &reversed.metadata,
                &expected_event,
                authority.as_ref(),
                authorized.metadata.budget_commit_index,
                "cleanup reverse replay",
            )?;
            if reversed.hold_id != expected_hold
                || reversed.exposure_units != expected_exposure
                || reversed.realized_spend_units != 0
                || reversed.invocation_state != BudgetInvocationReservationState::Reversed
                || !matches!(
                    reversed.monetary_state,
                    BudgetMonetaryHoldState::None | BudgetMonetaryHoldState::Reversed
                )
                || reversed.revocation_set.as_ref() != expected_revocation_set.as_ref()
            {
                return Err(KernelError::Internal(
                    "budget cleanup acknowledgement did not match the exact reverse".to_string(),
                ));
            }
            Ok(())
        })()
    }

    fn validate_budget_cleanup_denial(
        &self,
        validation: BudgetCleanupDenialValidation<'_>,
    ) -> Result<(), KernelError> {
        let BudgetCleanupDenialValidation {
            store,
            denied,
            expected_hold_id,
            expected_exposure,
            expected_event_id,
            expected_authority,
            expected_revocation_set,
        } = validation;
        self.validate_budget_cleanup_denial_metadata(
            store,
            &denied.metadata,
            expected_event_id,
            expected_authority,
        )?;
        if denied.hold_id.as_deref() != expected_hold_id
            || denied.attempted_exposure_units != expected_exposure
            || denied.invocation_state != BudgetInvocationReservationState::Denied
            || denied.monetary_state != BudgetMonetaryHoldState::None
            || denied.revocation_set.as_ref() != expected_revocation_set
        {
            return Err(KernelError::Internal(
                "budget cleanup denial did not match the journaled authorization".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_budget_cleanup_denial_metadata(
        &self,
        store: &dyn BudgetStore,
        metadata: &BudgetCommitMetadata,
        expected_event_id: &str,
        expected_authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<(), KernelError> {
        let authority_is_valid = match metadata.guarantee_level {
            BudgetGuaranteeLevel::SingleNodeAtomic => {
                metadata.authority.as_ref() == expected_authority
            }
            BudgetGuaranteeLevel::HaLinearizable => {
                metadata.authority.as_ref().is_some_and(|authority| {
                    !authority.authority_id.is_empty()
                        && !authority.lease_id.is_empty()
                        && authority.lease_epoch > 0
                })
            }
            BudgetGuaranteeLevel::PartitionEscrowed | BudgetGuaranteeLevel::AdvisoryPosthoc => {
                false
            }
        };
        let commit_index_is_valid = match metadata.guarantee_level {
            BudgetGuaranteeLevel::SingleNodeAtomic => metadata.budget_commit_index.is_none(),
            BudgetGuaranteeLevel::HaLinearizable => metadata
                .budget_commit_index
                .is_some_and(|commit_index| commit_index > 0),
            BudgetGuaranteeLevel::PartitionEscrowed | BudgetGuaranteeLevel::AdvisoryPosthoc => {
                false
            }
        };
        if metadata.guarantee_level != store.budget_guarantee_level()
            || metadata.budget_profile != store.budget_authority_profile()
            || metadata.metering_profile != store.budget_metering_profile()
            || !metadata.guarantee_level.supports_hard_invocation_limit(
                store.authority_profile(),
                self.dispatch_worker_count,
            )
            || metadata.event_id.as_deref() != Some(expected_event_id)
            || metadata.authority.is_none()
            || !authority_is_valid
            || !commit_index_is_valid
        {
            return Err(KernelError::GuardDenied(
                "cleanup authorization denial omitted exact hard-budget authority evidence"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn execute_payment_cleanup(
        &self,
        operation: &AdmissionOperation,
        payload: PaymentCleanupPayload,
    ) -> Result<(), KernelError> {
        validate_payload_operation(
            operation,
            &payload.operation_id,
            Some(&payload.request_binding_hash),
        )?;
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "payment cleanup authority is unavailable for a journaled action".to_string(),
            )
        })?;
        let authorization = adapter
            .lookup_authorization_for_operation(
                operation.operation_id(),
                operation.request_binding_hash(),
            )
            .map_err(|error| {
                KernelError::Internal(format!(
                    "payment cleanup authorization lookup failed: {error}"
                ))
            })?;
        let Some(authorization) = authorization else {
            return Ok(());
        };
        let journal = self.payment_cleanup_journal(&payload.reference)?;
        if journal.is_none() {
            return Err(KernelError::Internal(
                "operation-owned payment cleanup is missing its durable payment journal"
                    .to_string(),
            ));
        }
        if let Some(record) = journal.as_ref() {
            self.validate_payment_cleanup_journal(
                operation,
                &payload,
                adapter.rail_id(),
                &authorization,
                record,
            )?;
        }
        let action = payment_cleanup_action(&authorization, journal.as_ref());
        if journal
            .as_ref()
            .is_some_and(|record| {
                payment_cleanup_is_completed(
                    record,
                    &authorization,
                    action,
                    payload.amount_units,
                )
            })
        {
            return Ok(());
        }
        let transaction_id = if action == PaymentSettleAction::Refund {
            Some(self.resolve_payment_cleanup_transaction_id(
                operation,
                &payload,
                &authorization,
                journal.as_ref(),
                adapter.as_ref(),
            )?)
        } else {
            None
        };
        let settle = PaymentSettleIntent {
            action,
            amount_units: (action == PaymentSettleAction::Refund)
                .then_some(payload.amount_units),
        };
        let staged = journal.as_ref().is_some_and(|record| {
            payment_cleanup_is_staged(
                record,
                &authorization,
                settle,
                transaction_id.as_deref(),
            )
        });
        if !staged {
            let expected = journal
                .as_ref()
                .map(|record| record.state)
                .unwrap_or(PaymentJournalState::Authorized);
            let stageable = matches!(
                expected,
                PaymentJournalState::HoldPlaced | PaymentJournalState::Authorized
            ) || (expected == PaymentJournalState::Settled
                && action == PaymentSettleAction::Refund);
            if journal.is_some() && !stageable {
                return Err(KernelError::Internal(
                    "payment cleanup journal has an incompatible in-flight settlement"
                        .to_string(),
                ));
            }
            let stage = self.advance_payment_cleanup_journal(
                journal.is_some(),
                &payload.reference,
                expected,
                PaymentJournalState::Settling,
                Some(&authorization.authorization_id),
                transaction_id.as_deref(),
                Some(settle),
            );
            if let Err(error) = stage {
                let readback = self.payment_cleanup_journal(&payload.reference)?;
                if !readback.as_ref().is_some_and(|record| {
                    payment_cleanup_is_staged(
                        record,
                        &authorization,
                        settle,
                        transaction_id.as_deref(),
                    )
                }) {
                    return Err(KernelError::Internal(format!(
                        "payment cleanup intent persistence failed: {error}"
                    )));
                }
            }
        }
        let cleanup = || {
            if let Some(transaction_id) = transaction_id.as_deref() {
                adapter.refund_for_operation(OperationPaymentRefundRequest {
                    operation_id: operation.operation_id(),
                    request_binding_hash: operation.request_binding_hash(),
                    transaction_id,
                    amount_units: payload.amount_units,
                    currency: &payload.currency,
                    reference: &payload.reference,
                })
            } else {
                adapter.release_for_operation(
                    operation.operation_id(),
                    operation.request_binding_hash(),
                    &authorization.authorization_id,
                    &payload.reference,
                )
            }
        };
        let result = cleanup()
            .or_else(|_| cleanup())
            .map_err(|error| KernelError::Internal(format!("payment cleanup failed: {error}")))?;
        let expected_status = if action == PaymentSettleAction::Refund {
            RailSettlementStatus::Refunded
        } else {
            RailSettlementStatus::Released
        };
        if result.settlement_status != expected_status
            || result.transaction_id.is_empty()
            || result.transaction_id.bytes().any(|byte| byte == 0)
        {
            return Err(KernelError::Internal(
                "payment cleanup acknowledgement has an invalid result or settlement state"
                    .to_string(),
            ));
        }
        let completed = self.advance_payment_cleanup_journal(
            journal.is_some(),
            &payload.reference,
            PaymentJournalState::Settling,
            PaymentJournalState::Settled,
            None,
            Some(&result.transaction_id),
            None,
        );
        if let Err(error) = completed {
            let readback = self.payment_cleanup_journal(&payload.reference)?;
            if !readback.as_ref().is_some_and(|record| {
                payment_cleanup_is_completed(
                    record,
                    &authorization,
                    action,
                    payload.amount_units,
                )
                    && record.transaction_id.as_deref() == Some(result.transaction_id.as_str())
            }) {
                return Err(KernelError::Internal(format!(
                    "payment cleanup result persistence failed: {error}"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn execute_reserved_payment_cleanup(
        &self,
        operation: &AdmissionOperation,
        amount_units: u64,
        currency: String,
        reference: String,
    ) -> Result<(), KernelError> {
        self.execute_payment_cleanup(
            operation,
            PaymentCleanupPayload {
                schema: PAYMENT_CLEANUP_SCHEMA.to_string(),
                operation_id: operation.operation_id().to_string(),
                request_binding_hash: operation.request_binding_hash().to_string(),
                amount_units,
                currency,
                reference,
            },
        )
    }

    fn payment_cleanup_journal(
        &self,
        reference: &str,
    ) -> Result<Option<PaymentJournalRecord>, KernelError> {
        self.with_budget_store(|store| {
            store
                .get_payment_journal(reference)
                .map_err(KernelError::from)
        })
    }

    fn advance_payment_cleanup_journal(
        &self,
        journaled: bool,
        reference: &str,
        expected: PaymentJournalState,
        next: PaymentJournalState,
        authorization_id: Option<&str>,
        transaction_id: Option<&str>,
        settle: Option<PaymentSettleIntent>,
    ) -> Result<(), KernelError> {
        if !journaled {
            return Ok(());
        }
        self.with_budget_store(|store| {
            store
                .advance_payment_journal(
                    reference,
                    expected,
                    next,
                    authorization_id,
                    transaction_id,
                    settle,
                )
                .map_err(KernelError::from)
        })
    }

    fn validate_payment_cleanup_journal(
        &self,
        operation: &AdmissionOperation,
        payload: &PaymentCleanupPayload,
        rail_id: &str,
        authorization: &PaymentAuthorization,
        record: &PaymentJournalRecord,
    ) -> Result<(), KernelError> {
        let binding = BudgetAdmissionOperationBinding::new(
            operation.operation_id().to_string(),
            operation.request_binding_hash().to_string(),
        )?;
        if record.request_id != payload.reference
            || record.capability_id != operation.capability_id()
            || record.admission_operation.as_ref() != Some(&binding)
            || record.hold_id.as_deref() != operation.budget_hold_id()
            || record.rail != rail_id
            || record.amount_units != payload.amount_units
            || record.currency != payload.currency
            || record.authorization_id.as_deref().is_some_and(|authorization_id| {
                authorization_id != authorization.authorization_id.as_str()
            })
        {
            return Err(KernelError::Internal(
                "payment cleanup journal does not match its operation and authorization"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn resolve_payment_cleanup_transaction_id(
        &self,
        operation: &AdmissionOperation,
        payload: &PaymentCleanupPayload,
        authorization: &PaymentAuthorization,
        journal: Option<&PaymentJournalRecord>,
        adapter: &dyn PaymentAdapter,
    ) -> Result<String, KernelError> {
        if let Some(transaction_id) = journal
            .and_then(|record| record.transaction_id.as_deref())
            .filter(|transaction_id| !transaction_id.is_empty())
        {
            return Ok(transaction_id.to_string());
        }
        match adapter.settlement_state_for_operation(
            operation.operation_id(),
            operation.request_binding_hash(),
            &payload.reference,
            Some(&authorization.authorization_id),
        ) {
            Ok(RailSettlementState::Settled {
                authorization_id,
                result,
            }) if authorization_id == authorization.authorization_id
                && !result.transaction_id.is_empty() =>
            {
                Ok(result.transaction_id)
            }
            Ok(_) => Err(KernelError::Internal(
                "settled payment cleanup has no exact transaction reference".to_string(),
            )),
            Err(error) => Err(KernelError::Internal(format!(
                "payment cleanup settlement lookup failed: {error}"
            ))),
        }
    }

    fn execute_delegated_budget_cleanup(
        &self,
        operation: &AdmissionOperation,
        payload: DelegatedBudgetCleanupPayload,
    ) -> Result<(), KernelError> {
        validate_payload_operation(
            operation,
            &payload.operation_id,
            Some(&payload.request_binding_hash),
        )?;
        if payload.child_capability_id != operation.capability_id() {
            return Err(KernelError::Internal(
                "delegated budget cleanup child does not match the operation".to_string(),
            ));
        }
        let mut leases = match self.threshold_delegated_budget_leases.lock() {
            Ok(leases) => leases,
            Err(poisoned) => poisoned.into_inner(),
        };
        let Some(existing) = leases.get(operation.operation_id()).cloned() else {
            return Ok(());
        };
        if existing.request_binding_hash != payload.request_binding_hash
            || existing.parent_capability_id != payload.parent_capability_id
            || existing.child_capability_id != payload.child_capability_id
            || existing.budget_share_bps != payload.budget_share_bps
        {
            return Err(KernelError::Internal(
                "delegated budget cleanup payload differs from the live lease".to_string(),
            ));
        }
        use chio_kernel_core::BudgetRegistry;
        let mut budgets = match self.budget_registry.lock() {
            Ok(budgets) => budgets,
            Err(poisoned) => poisoned.into_inner(),
        };
        budgets
            .release_child(
                &payload.parent_capability_id,
                &payload.child_capability_id,
                payload.budget_share_bps,
            )
            .map_err(|error| KernelError::DelegationInvalid(error.to_string()))?;
        leases.remove(operation.operation_id());
        Ok(())
    }

    fn execute_nonce_cleanup(
        &self,
        operation: &AdmissionOperation,
        payload: NonceCleanupPayload,
    ) -> Result<(), KernelError> {
        validate_payload_operation(operation, &payload.operation_id, None)?;
        if operation.execution_nonce_id() != Some(payload.nonce_id.as_str()) {
            return Err(KernelError::Internal(
                "nonce cleanup identity does not match the operation".to_string(),
            ));
        }
        let store = self.execution_nonce_store.as_ref().ok_or_else(|| {
            KernelError::Internal(
                "nonce cleanup authority is unavailable for a journaled action".to_string(),
            )
        })?;
        let reservation = store
            .get_nonce_reservation(operation.operation_id())
            .map_err(|error| {
                KernelError::Internal(format!("nonce cleanup lookup failed: {error}"))
            })?;
        let Some(reservation) = reservation else {
            return Ok(());
        };
        if reservation.nonce_id() != payload.nonce_id {
            return Err(KernelError::Internal(
                "nonce cleanup reservation has a different nonce".to_string(),
            ));
        }
        match reservation.state() {
            ReplayReservationState::Cancelled => Ok(()),
            ReplayReservationState::Reserved => {
                let cancelled = match store.cancel_nonce_reservation(operation.operation_id()) {
                    Ok(cancelled) => cancelled,
                    Err(error) => store
                        .get_nonce_reservation(operation.operation_id())
                        .ok()
                        .flatten()
                        .filter(|reservation| {
                            reservation.state() == ReplayReservationState::Cancelled
                                && reservation.nonce_id() == payload.nonce_id
                        })
                        .ok_or_else(|| {
                            KernelError::Internal(format!(
                                "nonce cleanup acknowledgement is uncertain: {error}"
                            ))
                        })?,
                };
                if cancelled.state() != ReplayReservationState::Cancelled {
                    return Err(KernelError::Internal(
                        "nonce cleanup acknowledgement is not cancelled".to_string(),
                    ));
                }
                Ok(())
            }
            // Replay protection is intentionally not reopened when a later
            // pre-dispatch step compensates the budget hold.
            ReplayReservationState::Committed => Ok(()),
        }
    }

    fn execute_broker_cleanup(
        &self,
        operation: &AdmissionOperation,
        payload: BrokerCleanupPayload,
    ) -> Result<(), KernelError> {
        validate_payload_operation(
            operation,
            &payload.operation_id,
            Some(&payload.request_binding_hash),
        )?;
        if operation.broker_attempt_id() != Some(payload.attempt_id.as_str()) {
            return Err(KernelError::Internal(
                "broker cleanup attempt does not match the operation".to_string(),
            ));
        }
        let registrar = self
            .supplemental_admission_registrar
            .as_ref()
            .ok_or_else(|| {
                KernelError::Internal(
                    "broker cleanup authority is unavailable for a journaled action".to_string(),
                )
            })?;
        registrar
            .release_admission(operation.operation_id())
            .or_else(|_| registrar.release_admission(operation.operation_id()))
            .map_err(|error| KernelError::Internal(format!("broker cleanup failed: {error}")))
    }
}

fn payment_cleanup_action(
    authorization: &PaymentAuthorization,
    journal: Option<&PaymentJournalRecord>,
) -> PaymentSettleAction {
    match journal.and_then(|record| record.settle_action) {
        Some(PaymentSettleAction::Refund) => PaymentSettleAction::Refund,
        Some(PaymentSettleAction::Release) => PaymentSettleAction::Release,
        Some(PaymentSettleAction::Capture) | None
            if authorization.settled
                || journal.is_some_and(|record| record.state == PaymentJournalState::Settled) =>
        {
            PaymentSettleAction::Refund
        }
        Some(PaymentSettleAction::Capture) | None => PaymentSettleAction::Release,
    }
}

fn payment_cleanup_is_staged(
    record: &PaymentJournalRecord,
    authorization: &PaymentAuthorization,
    settle: PaymentSettleIntent,
    transaction_id: Option<&str>,
) -> bool {
    record.state == PaymentJournalState::Settling
        && record.authorization_id.as_deref() == Some(authorization.authorization_id.as_str())
        && record.settle_action == Some(settle.action)
        && record.settle_amount_units == settle.amount_units
        && match settle.action {
            PaymentSettleAction::Refund => record.transaction_id.as_deref() == transaction_id,
            PaymentSettleAction::Release => record.transaction_id.is_none(),
            PaymentSettleAction::Capture => false,
        }
}

fn payment_cleanup_is_completed(
    record: &PaymentJournalRecord,
    authorization: &PaymentAuthorization,
    action: PaymentSettleAction,
    amount_units: u64,
) -> bool {
    record.state == PaymentJournalState::Settled
        && record.authorization_id.as_deref() == Some(authorization.authorization_id.as_str())
        && record.settle_action == Some(action)
        && record
            .transaction_id
            .as_deref()
            .is_some_and(|transaction_id| !transaction_id.is_empty())
        && match action {
            PaymentSettleAction::Refund => record.settle_amount_units == Some(amount_units),
            PaymentSettleAction::Release => record.settle_amount_units.is_none(),
            PaymentSettleAction::Capture => false,
        }
}
