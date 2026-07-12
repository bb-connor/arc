use super::*;

impl SqliteBudgetStore {
    pub(super) fn authorize_budget_hold_atomic(
        &self,
        request: &BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request_event = match request.event_id.as_deref() {
            Some(event_id) => Self::load_mutation_event(&transaction, event_id)?,
            None => None,
        };
        let rollback_retry = match request_event.as_ref() {
            Some(event) if event.kind == BudgetMutationKind::AuthorizeExposure => {
                Self::rollback_event_exists_for_generation(&transaction, event)?
                    || Self::legacy_latest_rollback_matches_reversed_hold(
                        &transaction,
                        &event.event_id,
                        request.hold_id.as_deref(),
                    )?
            }
            _ => false,
        };
        let existing = Self::existing_event_allowed(
            &transaction,
            request.event_id.as_deref(),
            BudgetMutationKind::AuthorizeExposure,
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.requested_exposure_units,
            0,
            request.max_invocations,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
        )?;

        if let Some(hold_id) = request.hold_id.as_deref() {
            if let Some(hold) = Self::load_hold(&transaction, hold_id)? {
                Self::validate_authorize_hold(
                    &transaction,
                    request,
                    &hold,
                    request_event.as_ref(),
                )?;
                if hold.invocation_captured {
                    let capture = Self::load_current_capture_event(&transaction, hold_id)?;
                    let decision = Self::captured_authorize_decision(self, hold, capture)?;
                    transaction.commit()?;
                    return Ok(decision);
                }
                if hold.disposition != HoldDisposition::Open && !rollback_retry {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` cannot be reopened by authorization"
                    )));
                }
            }
        }

        if existing.is_some() {
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "idempotent budget authorization is missing its event id".to_string(),
                )
            })?;
            let event = Self::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "budget authorization event disappeared during transaction".to_string(),
                )
            })?;
            let decision = Self::authorize_event_decision(self, event)?;
            transaction.commit()?;
            return Ok(decision);
        }

        let current = transaction
            .query_row(
                r#"
                SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![&request.capability_id, request.grant_index as i64],
                |row| {
                    Ok((
                        budget_u64_from_row(row, 0, "seq")?,
                        budget_u32_from_row(row, 1, "invocation_count")?,
                        budget_u64_from_row(row, 2, "total_cost_exposed")?,
                        budget_u64_from_row(row, 3, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?
            .unwrap_or((0, 0, 0, 0));

        if let Some(hold_id) = request.hold_id.as_deref() {
            if let Some(hold) = Self::load_hold(&transaction, hold_id)? {
                Self::validate_authorize_hold(
                    &transaction,
                    request,
                    &hold,
                    request_event.as_ref(),
                )?;
                let other_open_exposure = transaction.query_row(
                    r#"
                    SELECT COALESCE(SUM(remaining_exposure_units), 0)
                    FROM budget_authorization_holds
                    WHERE capability_id = ?1
                      AND grant_index = ?2
                      AND disposition = 'open'
                      AND hold_id != ?3
                    "#,
                    params![&request.capability_id, request.grant_index as i64, hold_id],
                    |row| budget_u64_from_row(row, 0, "remaining_exposure_units"),
                )?;
                let reflected_exposure = other_open_exposure
                    .checked_add(request.requested_exposure_units)
                    .ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "open hold exposure accounting overflowed u64".to_string(),
                        )
                    })?;
                let other_open_invocations = transaction.query_row(
                    r#"
                    SELECT COUNT(*)
                    FROM budget_authorization_holds
                    WHERE capability_id = ?1
                      AND grant_index = ?2
                      AND disposition = 'open'
                      AND invocation_count_debited = 1
                      AND hold_id != ?3
                    "#,
                    params![&request.capability_id, request.grant_index as i64, hold_id],
                    |row| budget_u32_from_row(row, 0, "invocation_count"),
                )?;
                let reflected_invocations =
                    other_open_invocations.checked_add(1).ok_or_else(|| {
                        BudgetStoreError::Overflow(
                            "open hold invocation accounting overflowed u32".to_string(),
                        )
                    })?;
                let matching_open = hold.disposition == HoldDisposition::Open
                    && !hold.invocation_captured
                    && hold.remaining_exposure_units == request.requested_exposure_units;
                if matching_open
                    && current.2 >= reflected_exposure
                    && current.1 >= reflected_invocations
                {
                    let event_seq = allocate_budget_replication_seq(&transaction)?;
                    let event = Self::append_mutation_event(
                        &transaction,
                        request.event_id.as_deref(),
                        Some(hold_id),
                        request.authority.as_ref(),
                        &request.capability_id,
                        request.grant_index,
                        BudgetMutationKind::AuthorizeExposure,
                        Some(true),
                        event_seq,
                        Some(current.0),
                        request.requested_exposure_units,
                        0,
                        request.max_invocations,
                        request.max_cost_per_invocation,
                        request.max_total_cost_units,
                        current.1,
                        current.2,
                        current.3,
                    )?;
                    let decision = Self::authorize_event_decision(self, event)?;
                    transaction.commit()?;
                    return Ok(decision);
                } else if matching_open
                    && request_event.is_none()
                    && Self::current_reverse_allows_orphan_recovery(
                        &transaction,
                        request,
                        &hold,
                        current,
                    )?
                    || rollback_retry && hold.disposition == HoldDisposition::Reversed
                {
                    Self::delete_hold_if_exists(&transaction, hold_id)?;
                } else {
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` cannot be reopened by authorization"
                    )));
                }
            }
        }

        let allowed = Self::authorize_limits_allow(request, current.1, current.2, current.3)?;
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        let (usage_seq, invocation_count_after, exposed_after, realized_after) = if allowed {
            let exposed_after = current
                .2
                .checked_add(request.requested_exposure_units)
                .ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + requested exposure overflowed u64".to_string(),
                    )
                })?;
            let invocation_count_after = current.1.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("invocation count overflowed u32".to_string())
            })?;
            transaction.execute(
                r#"
                INSERT INTO capability_grant_budgets (
                    capability_id, grant_index, invocation_count, updated_at, seq,
                    total_cost_exposed, total_cost_realized_spend
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                    invocation_count = excluded.invocation_count,
                    updated_at = excluded.updated_at,
                    seq = excluded.seq,
                    total_cost_exposed = excluded.total_cost_exposed,
                    total_cost_realized_spend = excluded.total_cost_realized_spend
                "#,
                params![
                    &request.capability_id,
                    request.grant_index as i64,
                    invocation_count_after as i64,
                    unix_now(),
                    event_seq as i64,
                    exposed_after as i64,
                    current.3 as i64,
                ],
            )?;
            if let Some(hold_id) = request.hold_id.as_deref() {
                Self::create_hold(
                    &transaction,
                    hold_id,
                    &request.capability_id,
                    request.grant_index,
                    request.requested_exposure_units,
                    request.authority.as_ref(),
                )?;
            }
            (
                Some(event_seq),
                invocation_count_after,
                exposed_after,
                current.3,
            )
        } else {
            (None, current.1, current.2, current.3)
        };
        let event = Self::append_mutation_event(
            &transaction,
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::AuthorizeExposure,
            Some(allowed),
            event_seq,
            usage_seq,
            request.requested_exposure_units,
            0,
            request.max_invocations,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            invocation_count_after,
            exposed_after,
            realized_after,
        )?;
        let decision = Self::authorize_event_decision(self, event)?;
        transaction.commit()?;
        Ok(decision)
    }

    fn current_reverse_allows_orphan_recovery(
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetAuthorizeHoldRequest,
        hold: &SqliteBudgetHold,
        current: (u64, u32, u64, u64),
    ) -> Result<bool, BudgetStoreError> {
        let Some(authorize_event_id) = request.event_id.as_deref() else {
            return Ok(false);
        };
        let reverse_event_id = transaction
            .query_row(
                r#"
                SELECT event_id FROM budget_mutation_events
                WHERE hold_id = ?1 AND kind = ?2
                ORDER BY event_seq DESC LIMIT 1
                "#,
                params![hold.hold_id, BudgetMutationKind::ReverseExposure.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(reverse_event_id) = reverse_event_id else {
            return Ok(false);
        };
        if !reverse_event_id.starts_with(&format!("{authorize_event_id}:rollback:")) {
            return Ok(false);
        }
        let Some(reverse) = Self::load_mutation_event(transaction, &reverse_event_id)? else {
            return Ok(false);
        };
        Ok(reverse.kind == BudgetMutationKind::ReverseExposure
            && reverse.hold_id.as_deref() == Some(hold.hold_id.as_str())
            && reverse.capability_id == request.capability_id
            && reverse.grant_index == request.grant_index as u32
            && reverse.allowed.is_none()
            && reverse.exposure_units == request.requested_exposure_units
            && reverse.realized_spend_units == 0
            && reverse.authority == hold.authority
            && reverse.usage_seq == Some(current.0)
            && reverse.invocation_count_after == current.1
            && reverse.total_cost_exposed_after == current.2
            && reverse.total_cost_realized_spend_after == current.3)
    }

    fn validate_authorize_hold(
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetAuthorizeHoldRequest,
        hold: &SqliteBudgetHold,
        request_event: Option<&BudgetMutationRecord>,
    ) -> Result<(), BudgetStoreError> {
        if hold.capability_id != request.capability_id
            || hold.grant_index != request.grant_index
            || hold.authorized_exposure_units != request.requested_exposure_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` was reused for a different authorization",
                hold.hold_id
            )));
        }
        let original = match request_event {
            Some(event) => event.clone(),
            None => {
                let original = transaction
                    .query_row(
                        r#"
                    SELECT event_id FROM budget_mutation_events
                    WHERE hold_id = ?1 AND kind = ?2
                    ORDER BY event_seq ASC LIMIT 1
                    "#,
                        params![
                            &hold.hold_id,
                            BudgetMutationKind::AuthorizeExposure.as_str()
                        ],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                let Some(original) = original else {
                    return Ok(());
                };
                Self::load_mutation_event(transaction, &original)?.ok_or_else(|| {
                    BudgetStoreError::Invariant("budget authorize event disappeared".to_string())
                })?
            }
        };
        if original.kind != BudgetMutationKind::AuthorizeExposure
            || original.capability_id != request.capability_id
            || original.grant_index != request.grant_index as u32
            || original.exposure_units != request.requested_exposure_units
            || original.max_invocations != request.max_invocations
            || original.max_cost_per_invocation != request.max_cost_per_invocation
            || original.max_total_cost_units != request.max_total_cost_units
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` authorization parameters changed",
                hold.hold_id
            )));
        }
        Ok(())
    }

    pub(super) fn load_current_capture_event(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
    ) -> Result<BudgetMutationRecord, BudgetStoreError> {
        let event_id = transaction
            .query_row(
                r#"
                SELECT event_id FROM budget_mutation_events
                WHERE hold_id = ?1
                  AND kind = ?2
                  AND event_seq > COALESCE((
                      SELECT MAX(event_seq) FROM budget_mutation_events
                      WHERE hold_id = ?1 AND kind = ?3
                  ), 0)
                ORDER BY event_seq DESC LIMIT 1
                "#,
                params![
                    hold_id,
                    BudgetMutationKind::CaptureInvocation.as_str(),
                    BudgetMutationKind::AuthorizeExposure.as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "captured budget hold `{hold_id}` has no capture event and is quarantined"
                ))
            })?;
        Self::load_mutation_event(transaction, &event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(
                "captured invocation event disappeared during authorization".to_string(),
            )
        })
    }

    fn authorize_limits_allow(
        request: &BudgetAuthorizeHoldRequest,
        invocation_count: u32,
        exposed: u64,
        realized: u64,
    ) -> Result<bool, BudgetStoreError> {
        if request
            .max_invocations
            .is_some_and(|max| invocation_count >= max)
            || request
                .max_cost_per_invocation
                .is_some_and(|max| request.requested_exposure_units > max)
        {
            return Ok(false);
        }
        let committed = checked_committed_cost_units(exposed, realized)?;
        let requested = committed
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        Ok(request
            .max_total_cost_units
            .is_none_or(|max| requested <= max))
    }

    fn authorize_event_decision(
        &self,
        event: BudgetMutationRecord,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let committed_cost_units_after = checked_committed_cost_units(
            event.total_cost_exposed_after,
            event.total_cost_realized_spend_after,
        )?;
        let metadata = BudgetCommitMetadata {
            authority: event.authority,
            guarantee_level: self.budget_guarantee_level(),
            budget_profile: self.budget_authority_profile(),
            metering_profile: self.budget_metering_profile(),
            budget_commit_index: event
                .allowed
                .and_then(|allowed| allowed.then_some(event.event_seq)),
            event_id: Some(event.event_id),
        };
        if event.allowed == Some(true) {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: event.hold_id,
                    authorized_exposure_units: event.exposure_units,
                    committed_cost_units_after,
                    invocation_count_after: event.invocation_count_after,
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: event.hold_id,
                attempted_exposure_units: event.exposure_units,
                committed_cost_units_after,
                invocation_count_after: event.invocation_count_after,
                metadata,
            }))
        }
    }

    fn captured_authorize_decision(
        &self,
        hold: SqliteBudgetHold,
        capture: BudgetMutationRecord,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        Ok(BudgetAuthorizeHoldDecision::AlreadyCaptured(
            BudgetHoldMutationDecision {
                hold_id: Some(hold.hold_id),
                exposure_units: hold.authorized_exposure_units,
                realized_spend_units: capture.realized_spend_units,
                committed_cost_units_after: checked_committed_cost_units(
                    capture.total_cost_exposed_after,
                    capture.total_cost_realized_spend_after,
                )?,
                invocation_count_after: capture.invocation_count_after,
                metadata: BudgetCommitMetadata {
                    authority: capture.authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(capture.event_seq),
                    event_id: Some(capture.event_id),
                },
            },
        ))
    }
}
