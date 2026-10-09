#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use super::*;

/// Parameters of `settle_composite_hold_in_transaction`.
struct CompositeSettlement<'a> {
    capability_id: &'a str,
    grant_index: usize,
    exposed_units: u64,
    realized_units: u64,
    hold_id: &'a str,
    event_id: &'a str,
    authority: Option<&'a BudgetEventAuthority>,
    kind: BudgetMutationKind,
    monetary_after: BudgetMonetaryState,
}

impl SqliteBudgetStore {
    pub(crate) fn release_composite_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires event_id".to_string())
        })?;
        if request.released_exposure_units == 0 {
            return Err(BudgetStoreError::Invariant(
                "zero-unit monetary release is not a state transition".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            TransitionReplay {
                event_id,
                kind: BudgetMutationKind::ReleaseExposure,
                hold_id,
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                exposure_units: Some(request.released_exposure_units),
                realized_spend_units: Some(0),
                authority: request.authority.as_ref(),
                trusted_time: None,
                expected_cumulative_state: None,
            },
        )? {
            transaction.rollback()?;
            return Ok(decision);
        }
        let hold = load_structured_hold(&transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("unknown composite budget hold `{hold_id}`"))
        })?;
        validate_transition_identity(
            self,
            &transaction,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationState::Authorized {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` crossed the dispatch commitment fence"
            )));
        }
        if hold.monetary_state != BudgetMonetaryState::Exposed
            || hold.remaining_exposure < request.released_exposure_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary exposure is not releasable"
            )));
        }
        let quota_states = load_quota_states(&transaction, &hold)?;
        let cumulative = load_cumulative_snapshot(&transaction, &hold)?;
        let mut usage =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        let usage_before = usage.clone();
        if usage.total_cost_exposed < request.released_exposure_units {
            return Err(BudgetStoreError::Invariant(
                "cannot release more than total budget exposure".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        usage.total_cost_exposed = ExposureUnits::new(usage.total_cost_exposed)
            .try_sub(ExposureUnits::new(request.released_exposure_units))?
            .get();
        usage.seq = event_seq;
        usage.updated_at = self.unix_now()?;
        write_usage(&transaction, &usage_before, &usage)?;
        let remaining = ExposureUnits::new(hold.remaining_exposure)
            .try_sub(ExposureUnits::new(request.released_exposure_units))?
            .get();
        let monetary_after = if remaining == 0 {
            BudgetMonetaryState::Released
        } else {
            BudgetMonetaryState::Exposed
        };
        let authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = ?2, monetary_state = ?3,
                disposition = ?4, authority_id = ?5, lease_id = ?6,
                lease_epoch = ?7, updated_at = ?8
            WHERE hold_id = ?1 AND invocation_state = 'authorized'
              AND monetary_state = 'exposed' AND remaining_exposure_units >= ?9
              AND remaining_exposure_units - ?9 = ?2
            "#,
            params![
                hold_id,
                budget_u64_to_sqlite(remaining, "remaining_exposure_units")?,
                budget_monetary_state_text(monetary_after),
                if remaining == 0 { "released" } else { "open" },
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                self.unix_now()?,
                budget_u64_to_sqlite(request.released_exposure_units, "released_exposure_units",)?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget release compare-and-set failed".to_string(),
            ));
        }
        let event = self.append_mutation_event(
            &transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::ReleaseExposure,
            None,
            event_seq,
            Some(event_seq),
            request.released_exposure_units,
            0,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        let cumulative_snapshot =
            cumulative
                .as_ref()
                .map(|(request, state, account, _)| CumulativeSnapshot {
                    request,
                    state: *state,
                    account,
                });
        write_transition_projection(
            &transaction,
            TransitionProjection {
                event_id: &event.event_id,
                hold: &hold,
                authorization_outcome: None,
                invocation_before: hold.invocation_state,
                invocation_after: hold.invocation_state,
                monetary_before: hold.monetary_state,
                monetary_after,
                quota_before: &quota_states,
                quota_after: &quota_states,
                cumulative_before: cumulative_snapshot,
                cumulative_after: cumulative.as_ref().map(|(request, state, account, _)| {
                    CumulativeSnapshot {
                        request,
                        state: *state,
                        account,
                    }
                }),
                approval_set_digest: cumulative
                    .as_ref()
                    .and_then(|(_, _, _, digest)| digest.as_deref()),
                trusted_time: None,
                expected_cumulative_state: None,
            },
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(
            &transaction,
            BudgetMutationKind::ReleaseExposure,
            event_id,
            event_seq,
        )?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(decision)
    }

    pub(crate) fn reverse_composite_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        request.validate()?;
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reversal requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reversal requires event_id".to_string())
        })?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        let hold = load_structured_hold(&transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("unknown composite budget hold `{hold_id}`"))
        })?;
        let reverse_kind = if hold.quotas.is_empty() {
            BudgetMutationKind::ReverseExposure
        } else {
            BudgetMutationKind::ReverseInvocation
        };
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            TransitionReplay {
                event_id,
                kind: reverse_kind,
                hold_id,
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                exposure_units: Some(request.reversed_exposure_units),
                realized_spend_units: Some(0),
                authority: request.authority.as_ref(),
                trusted_time: None,
                expected_cumulative_state: request.expected_cumulative_approval_state,
            },
        )? {
            transaction.rollback()?;
            return Ok(decision);
        }
        validate_transition_identity(
            self,
            &transaction,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.invocation_state != BudgetInvocationState::Authorized
            || hold.remaining_exposure != request.reversed_exposure_units
            || (hold.remaining_exposure > 0 && hold.monetary_state != BudgetMonetaryState::Exposed)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` cannot be reversed in its current state"
            )));
        }
        let quota_before = load_quota_states(&transaction, &hold)?;
        let mut quota_after = quota_before.clone();
        for state in &mut quota_after {
            if state.reserved == 0 {
                return Err(BudgetStoreError::Invariant(
                    "invocation quota reservation is incomplete".to_string(),
                ));
            }
            state.reserved = InvocationCount::new(state.reserved)
                .try_sub(InvocationCount::new(1))?
                .get();
            state.version = state.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation quota version overflowed u64".to_string())
            })?;
        }
        let cumulative_before = load_cumulative_snapshot(&transaction, &hold)?;
        let cumulative_after = cumulative_before
            .as_ref()
            .map(|(cumulative, state, account, digest)| {
                if request
                    .expected_cumulative_approval_state
                    .is_some_and(|expected| expected != *state)
                    || !matches!(
                        state,
                        BudgetCumulativeApprovalState::PendingApproval
                            | BudgetCumulativeApprovalState::Authorized
                    )
                {
                    return Err(BudgetStoreError::Invariant(
                        "cumulative approval state changed before reversal".to_string(),
                    ));
                }
                if account.reserved < cumulative.requested_authorized.units {
                    return Err(BudgetStoreError::Invariant(
                        "cumulative approval reservation is incomplete".to_string(),
                    ));
                }
                let mut account = account.clone();
                account.reserved = ExposureUnits::new(account.reserved)
                    .try_sub(ExposureUnits::new(cumulative.requested_authorized.units))?
                    .get();
                account.version = account.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative approval version overflowed u64".to_string(),
                    )
                })?;
                Ok::<_, BudgetStoreError>((
                    cumulative.clone(),
                    BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                    account,
                    digest.clone(),
                ))
            })
            .transpose()?;
        if cumulative_before.is_none() && request.expected_cumulative_approval_state.is_some() {
            return Err(BudgetStoreError::Invariant(
                "budget hold has no cumulative approval participant".to_string(),
            ));
        }
        let mut usage =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        let usage_before = usage.clone();
        if usage.invocation_count == 0 || usage.total_cost_exposed < request.reversed_exposure_units
        {
            return Err(BudgetStoreError::Invariant(
                "budget usage has no reversible reservation".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        usage.invocation_count = InvocationCount::new(usage.invocation_count)
            .try_sub(InvocationCount::new(1))?
            .get();
        usage.total_cost_exposed = ExposureUnits::new(usage.total_cost_exposed)
            .try_sub(ExposureUnits::new(request.reversed_exposure_units))?
            .get();
        usage.seq = event_seq;
        usage.updated_at = self.unix_now()?;
        write_usage(&transaction, &usage_before, &usage)?;
        for state in &quota_after {
            write_quota_state(&transaction, state)?;
        }
        if let Some((cumulative, state, account, _)) = cumulative_after.as_ref() {
            write_cumulative_account(&transaction, account)?;
            let changed = transaction.execute(
                r#"
                UPDATE budget_cumulative_approval_operations
                SET state = ?2, account_version = ?3
                WHERE operation_id = ?1 AND hold_id = ?4
                  AND state IN ('pending_approval', 'authorized')
                "#,
                params![
                    &cumulative.operation_id,
                    cumulative_state_text(*state),
                    budget_u64_to_sqlite(account.version, "cumulative_account_version")?,
                    hold_id,
                ],
            )?;
            if changed != 1 {
                return Err(BudgetStoreError::Invariant(
                    "cumulative reversal compare-and-set failed".to_string(),
                ));
            }
        }
        let monetary_after = if request.reversed_exposure_units == 0 {
            hold.monetary_state
        } else {
            BudgetMonetaryState::Reversed
        };
        let authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = 0, invocation_captured = 0,
                invocation_state = 'reversed', monetary_state = ?2,
                disposition = 'reversed', authority_id = ?3, lease_id = ?4,
                lease_epoch = ?5, updated_at = ?6
            WHERE hold_id = ?1 AND invocation_state = 'authorized'
              AND remaining_exposure_units = ?7
            "#,
            params![
                hold_id,
                budget_monetary_state_text(monetary_after),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                self.unix_now()?,
                budget_u64_to_sqlite(hold.remaining_exposure, "previous_hold_exposure")?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget reversal compare-and-set failed".to_string(),
            ));
        }
        let event = self.append_mutation_event(
            &transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            reverse_kind,
            None,
            event_seq,
            Some(event_seq),
            request.reversed_exposure_units,
            0,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        write_transition_projection(
            &transaction,
            TransitionProjection {
                event_id: &event.event_id,
                hold: &hold,
                authorization_outcome: None,
                invocation_before: BudgetInvocationState::Authorized,
                invocation_after: BudgetInvocationState::Reversed,
                monetary_before: hold.monetary_state,
                monetary_after,
                quota_before: &quota_before,
                quota_after: &quota_after,
                cumulative_before: cumulative_before.as_ref().map(
                    |(request, state, account, _)| CumulativeSnapshot {
                        request,
                        state: *state,
                        account,
                    },
                ),
                cumulative_after: cumulative_after
                    .as_ref()
                    .map(|(request, state, account, _)| CumulativeSnapshot {
                        request,
                        state: *state,
                        account,
                    }),
                approval_set_digest: cumulative_after
                    .as_ref()
                    .and_then(|(_, _, _, digest)| digest.as_deref()),
                trusted_time: None,
                expected_cumulative_state: request.expected_cumulative_approval_state,
            },
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(&transaction, reverse_kind, event_id, event_seq)?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(decision)
    }

    pub(crate) fn cancel_captured_composite_hold(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        request.validate()?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        self.validate_joint_authority(request.authority.as_ref())?;
        if let Some(decision) = replay_transition(
            self,
            &transaction,
            TransitionReplay {
                event_id: &request.event_id,
                kind: BudgetMutationKind::CancelCapturedBeforeDispatch,
                hold_id: &request.hold_id,
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                exposure_units: None,
                realized_spend_units: Some(0),
                authority: request.authority.as_ref(),
                trusted_time: None,
                expected_cumulative_state: Some(BudgetCumulativeApprovalState::Captured),
            },
        )? {
            transaction.rollback()?;
            return Ok(
                BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(decision),
            );
        }
        let hold = load_structured_hold(&transaction, &request.hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "unknown composite budget hold `{}`",
                request.hold_id
            ))
        })?;
        validate_transition_identity(
            self,
            &transaction,
            &hold,
            &request.capability_id,
            request.grant_index,
            request.authority.as_ref(),
        )?;
        if hold.cumulative.is_none() {
            return Err(BudgetStoreError::Invariant(
                "captured composite invocation reservations are terminal".to_string(),
            ));
        }
        if hold.invocation_state != BudgetInvocationState::Captured
            || (hold.remaining_exposure > 0 && hold.monetary_state != BudgetMonetaryState::Exposed)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` cannot be cancelled before dispatch in its current state",
                request.hold_id
            )));
        }

        let quota_before = load_quota_states(&transaction, &hold)?;
        let mut quota_after = quota_before.clone();
        for state in &mut quota_after {
            if state.captured == 0 {
                return Err(BudgetStoreError::Invariant(
                    "captured invocation quota is incomplete".to_string(),
                ));
            }
            state.captured = InvocationCount::new(state.captured)
                .try_sub(InvocationCount::new(1))?
                .get();
            state.version = state.version.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation quota version overflowed u64".to_string())
            })?;
        }
        let cumulative_before = load_cumulative_snapshot(&transaction, &hold)?;
        let cumulative_after = cumulative_before
            .as_ref()
            .map(|(cumulative, state, account, digest)| {
                if *state != BudgetCumulativeApprovalState::Captured
                    || account.captured < cumulative.requested_authorized.units
                {
                    return Err(BudgetStoreError::Invariant(
                        "captured cumulative approval is incomplete".to_string(),
                    ));
                }
                let mut account = account.clone();
                account.captured = ExposureUnits::new(account.captured)
                    .try_sub(ExposureUnits::new(cumulative.requested_authorized.units))?
                    .get();
                account.version = account.version.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "cumulative approval version overflowed u64".to_string(),
                    )
                })?;
                Ok::<_, BudgetStoreError>((
                    cumulative.clone(),
                    BudgetCumulativeApprovalState::ReversedBeforeDispatch,
                    account,
                    digest.clone(),
                ))
            })
            .transpose()?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "captured cancellation requires a cumulative approval participant".to_string(),
                )
            })?;
        let mut usage =
            load_usage_or_default(&transaction, &request.capability_id, request.grant_index)?;
        let usage_before = usage.clone();
        if usage.invocation_count == 0 || usage.total_cost_exposed < hold.remaining_exposure {
            return Err(BudgetStoreError::Invariant(
                "budget usage has no captured reservation to cancel".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        usage.invocation_count = InvocationCount::new(usage.invocation_count)
            .try_sub(InvocationCount::new(1))?
            .get();
        usage.total_cost_exposed = ExposureUnits::new(usage.total_cost_exposed)
            .try_sub(ExposureUnits::new(hold.remaining_exposure))?
            .get();
        usage.seq = event_seq;
        usage.updated_at = self.unix_now()?;
        write_usage(&transaction, &usage_before, &usage)?;
        for state in &quota_after {
            write_quota_state(&transaction, state)?;
        }
        write_cumulative_account(&transaction, &cumulative_after.2)?;
        let changed = transaction.execute(
            r#"
            UPDATE budget_cumulative_approval_operations
            SET state = 'reversed_before_dispatch', account_version = ?2
            WHERE operation_id = ?1 AND hold_id = ?3 AND state = 'captured'
            "#,
            params![
                &cumulative_after.0.operation_id,
                budget_u64_to_sqlite(cumulative_after.2.version, "cumulative_account_version")?,
                &request.hold_id,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "cumulative cancellation compare-and-set failed".to_string(),
            ));
        }
        let monetary_after = if hold.remaining_exposure == 0 {
            hold.monetary_state
        } else {
            BudgetMonetaryState::Reversed
        };
        let authority = request.authority.as_ref().or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = 0, invocation_captured = 0,
                invocation_state = 'reversed', monetary_state = ?2,
                disposition = 'reversed', authority_id = ?3, lease_id = ?4,
                lease_epoch = ?5, updated_at = ?6
            WHERE hold_id = ?1 AND invocation_state = 'captured'
              AND remaining_exposure_units = ?7
            "#,
            params![
                &request.hold_id,
                budget_monetary_state_text(monetary_after),
                authority.map(|value| value.authority_id.as_str()),
                authority.map(|value| value.lease_id.as_str()),
                authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                self.unix_now()?,
                budget_u64_to_sqlite(hold.remaining_exposure, "previous_hold_exposure")?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "captured cancellation compare-and-set failed".to_string(),
            ));
        }
        let event = self.append_mutation_event(
            &transaction,
            Some(&request.event_id),
            Some(&request.hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            Some(true),
            event_seq,
            Some(event_seq),
            hold.remaining_exposure,
            0,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        write_transition_projection(
            &transaction,
            TransitionProjection {
                event_id: &event.event_id,
                hold: &hold,
                authorization_outcome: None,
                invocation_before: BudgetInvocationState::Captured,
                invocation_after: BudgetInvocationState::Reversed,
                monetary_before: hold.monetary_state,
                monetary_after,
                quota_before: &quota_before,
                quota_after: &quota_after,
                cumulative_before: cumulative_before.as_ref().map(
                    |(request, state, account, _)| CumulativeSnapshot {
                        request,
                        state: *state,
                        account,
                    },
                ),
                cumulative_after: Some(CumulativeSnapshot {
                    request: &cumulative_after.0,
                    state: cumulative_after.1,
                    account: &cumulative_after.2,
                }),
                approval_set_digest: cumulative_after.3.as_deref(),
                trusted_time: None,
                expected_cumulative_state: Some(BudgetCumulativeApprovalState::Captured),
            },
        )?;
        let decision = transition_decision_from_event(self, &transaction, event)?;
        self.append_joint_commit(
            &transaction,
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            &request.event_id,
            event_seq,
        )?;
        self.commit_joint_transaction(transaction)?;
        self.sync_joint_anchor(&connection)?;
        Ok(BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(
            decision,
        ))
    }

    fn settle_composite_hold(
        &self,
        settlement: CompositeSettlement<'_>,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let CompositeSettlement {
            capability_id,
            grant_index,
            exposed_units,
            realized_units,
            hold_id,
            event_id,
            authority,
            kind,
            monetary_after,
        } = settlement;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let (decision, changed) = self.settle_composite_hold_in_transaction(
            &transaction,
            CompositeSettlement {
                capability_id,
                grant_index,
                exposed_units,
                realized_units,
                hold_id,
                event_id,
                authority,
                kind,
                monetary_after,
            },
        )?;
        if changed {
            self.commit_joint_transaction(transaction)?;
            self.sync_joint_anchor(&connection)?;
        } else {
            transaction.rollback()?;
        }
        Ok(decision)
    }

    fn settle_composite_hold_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        settlement: CompositeSettlement<'_>,
    ) -> Result<(BudgetHoldMutationDecision, bool), BudgetStoreError> {
        let CompositeSettlement {
            capability_id,
            grant_index,
            exposed_units,
            realized_units,
            hold_id,
            event_id,
            authority,
            kind,
            monetary_after,
        } = settlement;
        if exposed_units == 0 || realized_units > exposed_units {
            return Err(BudgetStoreError::Invariant(
                "monetary settlement requires positive exposure and spend not above exposure"
                    .to_string(),
            ));
        }
        self.validate_joint_authority(authority)?;
        super::super::preflight::reject_preflight_capture(transaction, hold_id)?;
        if let Some(decision) = replay_transition(
            self,
            transaction,
            TransitionReplay {
                event_id,
                kind,
                hold_id,
                capability_id,
                grant_index,
                exposure_units: Some(exposed_units),
                realized_spend_units: Some(realized_units),
                authority,
                trusted_time: None,
                expected_cumulative_state: None,
            },
        )? {
            return Ok((decision, false));
        }
        let hold = load_structured_hold(transaction, hold_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!("unknown composite budget hold `{hold_id}`"))
        })?;
        validate_transition_identity(
            self,
            transaction,
            &hold,
            capability_id,
            grant_index,
            authority,
        )?;
        if hold.invocation_state != BudgetInvocationState::Captured
            || hold.monetary_state != BudgetMonetaryState::Exposed
            || hold.remaining_exposure != exposed_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is not dispatch-captured and settleable"
            )));
        }
        let quota_states = load_quota_states(transaction, &hold)?;
        let cumulative = load_cumulative_snapshot(transaction, &hold)?;
        let mut usage = load_usage_or_default(transaction, capability_id, grant_index)?;
        let usage_before = usage.clone();
        if usage.total_cost_exposed < exposed_units {
            return Err(BudgetStoreError::Invariant(
                "settlement exceeds total budget exposure".to_string(),
            ));
        }
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let balance =
            ExposureBalance::new(usage.total_cost_exposed, usage.total_cost_realized_spend)?
                .settle(
                    ExposureUnits::new(exposed_units),
                    ExposureUnits::new(realized_units),
                )?;
        usage.total_cost_exposed = balance.exposed();
        usage.total_cost_realized_spend = balance.spent();
        usage.seq = event_seq;
        usage.updated_at = self.unix_now()?;
        write_usage(transaction, &usage_before, &usage)?;
        let next_authority = authority.or(hold.authority.as_ref());
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET remaining_exposure_units = 0, monetary_state = ?2,
                disposition = 'reconciled', authority_id = ?3, lease_id = ?4,
                lease_epoch = ?5, updated_at = ?6
            WHERE hold_id = ?1 AND invocation_state = 'captured'
              AND monetary_state = 'exposed'
              AND remaining_exposure_units = ?7
            "#,
            params![
                hold_id,
                budget_monetary_state_text(monetary_after),
                next_authority.map(|value| value.authority_id.as_str()),
                next_authority.map(|value| value.lease_id.as_str()),
                next_authority
                    .map(|value| budget_u64_to_sqlite(value.lease_epoch, "lease_epoch"))
                    .transpose()?,
                self.unix_now()?,
                budget_u64_to_sqlite(hold.remaining_exposure, "previous_hold_exposure")?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget settlement compare-and-set failed".to_string(),
            ));
        }
        let event = self.append_mutation_event(
            transaction,
            Some(event_id),
            Some(hold_id),
            authority,
            capability_id,
            grant_index,
            kind,
            None,
            event_seq,
            Some(event_seq),
            exposed_units,
            realized_units,
            None,
            None,
            None,
            usage.invocation_count,
            usage.total_cost_exposed,
            usage.total_cost_realized_spend,
        )?;
        write_transition_projection(
            transaction,
            TransitionProjection {
                event_id: &event.event_id,
                hold: &hold,
                authorization_outcome: None,
                invocation_before: hold.invocation_state,
                invocation_after: hold.invocation_state,
                monetary_before: hold.monetary_state,
                monetary_after,
                quota_before: &quota_states,
                quota_after: &quota_states,
                cumulative_before: cumulative.as_ref().map(|(request, state, account, _)| {
                    CumulativeSnapshot {
                        request,
                        state: *state,
                        account,
                    }
                }),
                cumulative_after: cumulative.as_ref().map(|(request, state, account, _)| {
                    CumulativeSnapshot {
                        request,
                        state: *state,
                        account,
                    }
                }),
                approval_set_digest: cumulative
                    .as_ref()
                    .and_then(|(_, _, _, digest)| digest.as_deref()),
                trusted_time: None,
                expected_cumulative_state: None,
            },
        )?;
        let decision = transition_decision_from_event(self, transaction, event)?;
        self.append_joint_commit(transaction, kind, event_id, event_seq)?;
        Ok((decision, true))
    }

    pub(crate) fn reconcile_composite_hold_in_transaction(
        &self,
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetReconcileHoldRequest,
    ) -> Result<(BudgetReconcileHoldDecision, bool), BudgetStoreError> {
        request.validate()?;
        self.settle_composite_hold_in_transaction(
            transaction,
            CompositeSettlement {
                capability_id: &request.capability_id,
                grant_index: request.grant_index,
                exposed_units: request.exposed_cost_units,
                realized_units: request.realized_spend_units,
                hold_id: request.hold_id.as_deref().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "composite reconciliation requires hold_id".to_string(),
                    )
                })?,
                event_id: request.event_id.as_deref().ok_or_else(|| {
                    BudgetStoreError::Invariant(
                        "composite reconciliation requires event_id".to_string(),
                    )
                })?,
                authority: request.authority.as_ref(),
                kind: BudgetMutationKind::ReconcileSpend,
                monetary_after: BudgetMonetaryState::Reconciled,
            },
        )
    }

    pub(crate) fn reconcile_composite_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        request.validate()?;
        self.settle_composite_hold(CompositeSettlement {
            capability_id: &request.capability_id,
            grant_index: request.grant_index,
            exposed_units: request.exposed_cost_units,
            realized_units: request.realized_spend_units,
            hold_id: request.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant("composite reconciliation requires hold_id".to_string())
            })?,
            event_id: request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite reconciliation requires event_id".to_string(),
                )
            })?,
            authority: request.authority.as_ref(),
            kind: BudgetMutationKind::ReconcileSpend,
            monetary_after: BudgetMonetaryState::Reconciled,
        })
    }

    pub(crate) fn capture_composite_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        request.validate()?;
        self.settle_composite_hold(CompositeSettlement {
            capability_id: &request.capability_id,
            grant_index: request.grant_index,
            exposed_units: request.exposed_cost_units,
            realized_units: request.realized_spend_units,
            hold_id: request.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite monetary capture requires hold_id".to_string(),
                )
            })?,
            event_id: request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite monetary capture requires event_id".to_string(),
                )
            })?,
            authority: request.authority.as_ref(),
            kind: BudgetMutationKind::CaptureSpend,
            monetary_after: BudgetMonetaryState::Captured,
        })
    }
}
