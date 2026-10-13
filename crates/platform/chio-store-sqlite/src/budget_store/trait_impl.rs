#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use super::*;

impl BudgetStore for SqliteBudgetStore {
    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        request.validate()?;
        if !request.invocation_quotas.is_empty()
            || request.cumulative_approval.is_some()
            || request.admission_binding.is_some()
        {
            return self.authorize_composite_hold(request);
        }
        self.require_standalone_mutation("unbound authorization")?;
        self.authorize_budget_hold_atomic(&request, None)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        validate_budget_grant_index(request.grant_index)?;
        request.validate()?;
        if self.is_structured_hold(&request.hold_id)? {
            return self.capture_composite_invocation(request);
        }
        self.require_standalone_mutation("unbound invocation capture")?;
        if request.trusted_time.is_some() {
            return Err(BudgetStoreError::Invariant(
                "trusted capture time is not supported by the sqlite budget store".to_string(),
            ));
        }
        if let Some(authority) = request.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_unbound_writer(
            &transaction,
            &request.hold_id,
            "invocation capture",
        )?;

        let existing_event =
            SqliteBudgetStore::load_mutation_event(&transaction, &request.event_id)?;
        let existing = SqliteBudgetStore::existing_event_allowed(
            &transaction,
            &request.event_id,
            BudgetMutationKind::CaptureInvocation,
            &request.capability_id,
            request.grant_index,
            Some(&request.hold_id),
            request.authority.as_ref(),
            existing_event
                .as_ref()
                .map_or(0, |event| event.exposure_units),
            0,
            None,
            None,
            None,
        )?;
        let usage = transaction
            .prepare_cached(
                r#"
                SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
            )?
            .query_row(
                params![
                    &request.capability_id,
                    crate::integer::checked::<_, i64>(request.grant_index)?
                ],
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
            .ok_or_else(|| BudgetStoreError::Invariant("missing charged budget row".to_string()))?;
        let mutation = |event_id: String,
                        event_seq,
                        authority: Option<BudgetEventAuthority>,
                        invocation_count_after,
                        total_cost_exposed_after,
                        total_cost_realized_spend_after,
                        exposure_units|
         -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
            Ok(BudgetHoldMutationDecision {
                hold_id: Some(request.hold_id.clone()),
                admission_binding: None,
                exposure_units,
                realized_spend_units: 0,
                committed_cost_units_after: checked_committed_cost_units(
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                )?,
                invocation_count_after,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Captured,
                monetary_state: if exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Exposed
                },
                metadata: BudgetCommitMetadata {
                    authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(event_seq),
                    event_id: Some(event_id),
                    recorded_at_unix_seconds: None,
                },
            })
        };

        if existing.is_some() {
            let hold =
                SqliteBudgetStore::load_hold(&transaction, &request.hold_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "captured budget hold `{}` disappeared",
                        request.hold_id
                    ))
                })?;
            if !hold.invocation_captured {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` invocation capture is no longer current",
                    request.hold_id
                )));
            }
            let original =
                SqliteBudgetStore::load_current_capture_event(&transaction, &request.hold_id)?;
            if original.event_id != request.event_id {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` invocation capture is no longer current",
                    request.hold_id
                )));
            }
            transaction.rollback()?;
            return Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(mutation(
                original.event_id,
                original.event_seq,
                original.authority,
                original.invocation_count_after,
                original.total_cost_exposed_after,
                original.total_cost_realized_spend_after,
                original.exposure_units,
            )?));
        }

        let hold = SqliteBudgetStore::ensure_open_hold(
            &transaction,
            &request.hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            &request.hold_id,
            hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        if !hold.invocation_count_debited {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has no invocation reservation to capture",
                request.hold_id
            )));
        }
        if hold.invocation_captured {
            let original =
                SqliteBudgetStore::load_current_capture_event(&transaction, &request.hold_id)?;
            if original.event_id != request.event_id {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{}` invocation was captured by a different event",
                    request.hold_id
                )));
            }
            transaction.rollback()?;
            return Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(mutation(
                original.event_id,
                original.event_seq,
                original.authority,
                original.invocation_count_after,
                original.total_cost_exposed_after,
                original.total_cost_realized_spend_after,
                original.exposure_units,
            )?));
        }

        let event_seq = allocate_budget_replication_seq(&transaction)?;
        let changed = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET invocation_captured = 1,
                disposition = CASE
                    WHEN remaining_exposure_units = 0 THEN 'reconciled'
                    ELSE disposition
                END,
                updated_at = ?2
            WHERE hold_id = ?1
              AND invocation_count_debited = 1
              AND invocation_captured = 0
            "#,
            params![&request.hold_id, self.unix_now()?],
        )?;
        if changed != 1 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` invocation capture compare-and-set failed",
                request.hold_id
            )));
        }

        self.append_mutation_event(
            &transaction,
            &request.event_id,
            Some(&request.hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CaptureInvocation,
            Some(true),
            event_seq,
            Some(usage.0),
            hold.remaining_exposure_units,
            0,
            None,
            None,
            None,
            usage.1,
            usage.2,
            usage.3,
        )?;
        transaction.commit()?;
        Ok(BudgetInvocationCaptureDecision::Captured(mutation(
            request.event_id,
            event_seq,
            request.authority,
            usage.1,
            usage.2,
            usage.3,
            hold.remaining_exposure_units,
        )?))
    }

    fn authorize_cumulative_approval(
        &self,
        request: BudgetAuthorizeCumulativeApprovalRequest,
    ) -> Result<BudgetCumulativeApprovalAuthorizationDecision, BudgetStoreError> {
        self.authorize_composite_cumulative_approval(request)
    }

    fn cancel_captured_before_dispatch(
        &self,
        request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        validate_budget_grant_index(request.grant_index)?;
        request.validate()?;
        if self.is_structured_hold(&request.hold_id)? {
            return self.cancel_captured_composite_hold(request);
        }
        self.require_standalone_mutation("captured invocation cancellation")?;
        if let Some(authority) = request.authority.as_ref() {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_unbound_writer(
            &transaction,
            &request.hold_id,
            "captured invocation cancellation",
        )?;

        if let Some(existing) =
            SqliteBudgetStore::load_mutation_event(&transaction, &request.event_id)?
        {
            SqliteBudgetStore::validate_replay_authority(
                &request.event_id,
                existing.authority.as_ref(),
                request.authority.as_ref(),
            )?;
            let matches = existing.kind == BudgetMutationKind::CancelCapturedBeforeDispatch
                && existing.hold_id.as_deref() == Some(request.hold_id.as_str())
                && existing.capability_id == request.capability_id
                && existing.grant_index == crate::integer::checked::<_, u32>(request.grant_index)?
                && existing.allowed == Some(true)
                && existing.realized_spend_units == 0
                && existing.max_invocations.is_none()
                && existing.max_cost_per_invocation.is_none()
                && existing.max_total_cost_units.is_none();
            if !matches {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget event_id `{}` was reused for a different mutation",
                    request.event_id
                )));
            }
            let mutation = BudgetHoldMutationDecision {
                hold_id: Some(request.hold_id),
                admission_binding: None,
                exposure_units: existing.exposure_units,
                realized_spend_units: 0,
                committed_cost_units_after: checked_committed_cost_units(
                    existing.total_cost_exposed_after,
                    existing.total_cost_realized_spend_after,
                )?,
                invocation_count_after: existing.invocation_count_after,
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Reversed,
                monetary_state: if existing.exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                },
                metadata: BudgetCommitMetadata {
                    authority: existing.authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(existing.event_seq),
                    event_id: Some(existing.event_id),
                    recorded_at_unix_seconds: u64::try_from(existing.recorded_at).ok(),
                },
            };
            transaction.rollback()?;
            return Ok(
                BudgetCapturedBeforeDispatchCancellationDecision::AlreadyCancelled(mutation),
            );
        }

        let hold = SqliteBudgetStore::ensure_open_hold(
            &transaction,
            &request.hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            &request.hold_id,
            hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        if !hold.invocation_count_debited || !hold.invocation_captured {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has no captured invocation to cancel before dispatch",
                request.hold_id
            )));
        }
        let capture =
            SqliteBudgetStore::load_current_capture_event(&transaction, &request.hold_id)?;
        if capture.capability_id != request.capability_id
            || capture.grant_index != crate::integer::checked::<_, u32>(request.grant_index)?
            || capture.allowed != Some(true)
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "captured budget hold `{}` has mismatched capture evidence",
                request.hold_id
            )));
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![
                    &request.capability_id,
                    crate::integer::checked::<_, i64>(request.grant_index)?
                ],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| BudgetStoreError::Invariant("missing charged budget row".to_string()))?;
        if hold.remaining_exposure_units != hold.authorized_exposure_units
            || current.0 == 0
            || current.1 < hold.authorized_exposure_units
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` does not match captured-before-dispatch cancellation",
                request.hold_id
            )));
        }

        let total_cost_exposed_after = ExposureUnits::new(current.1)
            .try_sub(ExposureUnits::new(hold.authorized_exposure_units))?
            .get();
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        let changed = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = ?3,
                updated_at = ?4,
                seq = ?5,
                total_cost_exposed = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
              AND invocation_count = ?7
              AND total_cost_exposed = ?8
              AND total_cost_realized_spend = ?9
            "#,
            params![
                &request.capability_id,
                crate::integer::checked::<_, i64>(request.grant_index)?,
                InvocationCount::new(current.0)
                    .try_sub(InvocationCount::new(1))?
                    .get(),
                self.unix_now()?,
                budget_u64_to_sqlite(event_seq, "seq")?,
                budget_u64_to_sqlite(total_cost_exposed_after, "total_cost_exposed")?,
                i64::from(current.0),
                budget_u64_to_sqlite(current.1, "previous_exposure")?,
                budget_u64_to_sqlite(current.2, "previous_spend")?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget usage compare-and-set failed".into(),
            ));
        }
        self.update_hold(
            &transaction,
            &request.hold_id,
            hold.authorized_exposure_units,
            0,
            HoldDisposition::Reversed,
            request.authority.as_ref().or(hold.authority.as_ref()),
        )?;
        transaction.execute(
            "UPDATE budget_authorization_holds SET invocation_captured = 0 WHERE hold_id = ?1",
            params![&request.hold_id],
        )?;
        self.append_mutation_event(
            &transaction,
            &request.event_id,
            Some(&request.hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CancelCapturedBeforeDispatch,
            Some(true),
            event_seq,
            Some(event_seq),
            hold.authorized_exposure_units,
            0,
            None,
            None,
            None,
            InvocationCount::new(current.0)
                .try_sub(InvocationCount::new(1))?
                .get(),
            total_cost_exposed_after,
            current.2,
        )?;
        transaction.commit()?;

        Ok(BudgetCapturedBeforeDispatchCancellationDecision::Cancelled(
            BudgetHoldMutationDecision {
                hold_id: Some(request.hold_id),
                admission_binding: None,
                exposure_units: hold.authorized_exposure_units,
                realized_spend_units: 0,
                committed_cost_units_after: checked_committed_cost_units(
                    total_cost_exposed_after,
                    current.2,
                )?,
                invocation_count_after: InvocationCount::new(current.0)
                    .try_sub(InvocationCount::new(1))?
                    .get(),
                invocation_quota_usages: Vec::new(),
                cumulative_approval: None,
                invocation_state: BudgetInvocationState::Reversed,
                monetary_state: if hold.authorized_exposure_units == 0 {
                    BudgetMonetaryState::None
                } else {
                    BudgetMonetaryState::Reversed
                },
                metadata: BudgetCommitMetadata {
                    authority: request.authority,
                    guarantee_level: self.budget_guarantee_level(),
                    budget_profile: self.budget_authority_profile(),
                    metering_profile: self.budget_metering_profile(),
                    budget_commit_index: Some(event_seq),
                    event_id: Some(request.event_id),
                    recorded_at_unix_seconds: None,
                },
            },
        ))
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        request.validate()?;
        if self.is_structured_hold(&request.hold_id)? {
            return self.release_composite_hold(request);
        }
        self.release_unbound_hold(&request)?;
        recorded_sqlite_hold_mutation(
            self,
            &request.hold_id,
            &request.event_id,
            BudgetMutationKind::ReleaseExposure,
        )
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        request.validate()?;
        if self.is_structured_hold(&request.hold_id)? {
            return self.reverse_composite_hold(request);
        }
        if request.expected_cumulative_approval_state.is_some() {
            return Err(BudgetStoreError::Invariant(
                "unbound sqlite budget holds do not support cumulative approval state fencing"
                    .to_string(),
            ));
        }
        self.reverse_unbound_hold(&request)?;
        recorded_sqlite_hold_mutation(
            self,
            &request.hold_id,
            &request.event_id,
            BudgetMutationKind::ReverseExposure,
        )
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        request.validate()?;
        if self.is_structured_hold(&request.hold_id)? {
            return self.reconcile_composite_hold(request);
        }
        self.reconcile_unbound_hold(&request)?;
        recorded_sqlite_hold_mutation(
            self,
            &request.hold_id,
            &request.event_id,
            BudgetMutationKind::ReconcileSpend,
        )
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        request.validate()?;
        if !self.is_structured_hold(&request.hold_id)? {
            return Err(BudgetStoreError::Invariant(
                "unbound sqlite budget holds do not support distinct monetary capture".to_string(),
            ));
        }
        self.capture_composite_hold(request)
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
            r#"
            SELECT
                capability_id,
                grant_index,
                invocation_count,
                updated_at,
                seq,
                total_cost_exposed,
                total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE (?1 IS NULL OR capability_id = ?1)
            ORDER BY updated_at DESC, capability_id ASC, grant_index ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(
            params![capability_id, crate::integer::checked::<_, i64>(limit)?],
            record_from_row,
        )?;
        let rows = rows.collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        transaction.rollback()?;
        Ok(rows)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        validate_budget_grant_index(grant_index)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let row = transaction
            .prepare_cached(
                r#"
                SELECT
                    capability_id,
                    grant_index,
                    invocation_count,
                    updated_at,
                    seq,
                    total_cost_exposed,
                    total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
            )?
            .query_row(
                params![
                    capability_id,
                    crate::integer::checked::<_, i64>(grant_index)?
                ],
                record_from_row,
            )
            .optional()?;
        transaction.rollback()?;
        Ok(row)
    }

    fn get_invocation_quota_usage(
        &self,
        key: &BudgetQuotaKey,
    ) -> Result<Option<BudgetInvocationQuotaUsage>, BudgetStoreError> {
        self.composite_quota_usage(key)
    }

    fn get_cumulative_approval_account_usage(
        &self,
        key: &BudgetCumulativeApprovalAccountKey,
    ) -> Result<Option<BudgetCumulativeApprovalAccountUsage>, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let row = transaction
            .query_row(
                r#"
                SELECT root_grant_hash, delegation_root_id, root_binding_digest,
                       currency, authority_threshold_units,
                       reserved_authorized_units, captured_authorized_units, version
                FROM budget_cumulative_approval_accounts
                WHERE authority_id = ?1 AND owner_id = ?2
                  AND approval_budget_id = ?3 AND approval_budget_epoch = ?4
                "#,
                params![
                    &key.authority_id,
                    &key.owner_id,
                    &key.approval_budget_id,
                    budget_u64_to_sqlite(key.approval_budget_epoch, "approval_budget_epoch")?,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        budget_u64_from_row(row, 4, "authority_threshold_units")?,
                        budget_u64_from_row(row, 5, "reserved_authorized_units")?,
                        budget_u64_from_row(row, 6, "captured_authorized_units")?,
                        budget_u64_from_row(row, 7, "version")?,
                    ))
                },
            )
            .optional()?;
        let Some(row) = row else {
            transaction.rollback()?;
            return Ok(None);
        };
        if row.0 != key.root_grant_hash
            || row.1 != key.delegation_root_id
            || row.2 != key.root_binding_digest
            || row.3 != key.currency
        {
            return Err(BudgetStoreError::Invariant(
                "cumulative approval account immutable identity changed".to_string(),
            ));
        }
        let amount = |units| MonetaryAmount {
            units,
            currency: key.currency.clone(),
        };
        let usage = BudgetCumulativeApprovalAccountUsage {
            account_key: key.clone(),
            authority_threshold: amount(row.4),
            reserved_authorized: amount(row.5),
            captured_authorized: amount(row.6),
            version: row.7,
        };
        transaction.rollback()?;
        Ok(Some(usage))
    }

    fn get_cumulative_approval_operation_usage(
        &self,
        operation_id: &str,
    ) -> Result<Option<BudgetCumulativeApprovalUsage>, BudgetStoreError> {
        self.composite_cumulative_operation_usage(operation_id)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        if let Some(grant_index) = grant_index {
            validate_budget_grant_index(grant_index)?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction.prepare(
            r#"
            SELECT event_id
            FROM budget_mutation_events
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR grant_index = ?2)
            ORDER BY event_seq ASC
            LIMIT ?3
            "#,
        )?;
        let event_ids = statement
            .query_map(
                params![
                    capability_id,
                    grant_index
                        .map(crate::integer::checked::<_, i64>)
                        .transpose()?,
                    crate::integer::checked::<_, i64>(limit)?
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let events = event_ids
            .iter()
            .map(|event_id| {
                Self::load_projected_mutation_event(&transaction, event_id)?.ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "budget mutation event `{event_id}` disappeared while listing"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.rollback()?;
        Ok(events)
    }

    fn reap_orphaned_holds(
        &self,
        realized_by_hold: &std::collections::HashMap<String, u64>,
    ) -> Result<(usize, usize), BudgetStoreError> {
        let summary = self.reap_holds_by_map(realized_by_hold)?;
        Ok((summary.reconciled, summary.reversed))
    }

    fn count_open_holds(&self) -> Result<usize, BudgetStoreError> {
        Ok(self.list_open_holds()?.len())
    }

    fn list_open_delegated_reserved_hold_ids(
        &self,
    ) -> Result<Option<Vec<String>>, BudgetStoreError> {
        Ok(Some(self.list_open_delegated_reserved_holds()?))
    }

    fn request_id_has_reserved_hold(
        &self,
        request_id: &str,
    ) -> Result<Option<bool>, BudgetStoreError> {
        Ok(Some(self.hold_exists_for_request_id(request_id)?))
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        self.budget_hold_snapshot(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.mark_hold_reserved_until(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        SqliteBudgetStore::reap_expired_reserved_holds(self, now_unix_secs)
    }
}

fn recorded_sqlite_hold_mutation(
    store: &SqliteBudgetStore,
    hold_id: &str,
    event_id: &str,
    expected_kind: BudgetMutationKind,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    let mut connection = store.connection()?;
    let transaction = store.begin_read(&mut connection)?;
    let event =
        SqliteBudgetStore::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "sqlite budget mutation event `{event_id}` disappeared"
            ))
        })?;
    if event.kind != expected_kind || event.hold_id.as_deref() != Some(hold_id) {
        return Err(BudgetStoreError::Invariant(format!(
            "sqlite budget mutation event `{event_id}` changed identity"
        )));
    }
    let (authorization_seq, authorized_exposure_units) = transaction
        .query_row(
            r#"
            SELECT event_seq, exposure_units
            FROM budget_mutation_events
            WHERE hold_id = ?1
              AND kind = ?2
              AND allowed = 1
              AND event_seq < ?3
            ORDER BY event_seq DESC LIMIT 1
            "#,
            params![
                hold_id,
                BudgetMutationKind::AuthorizeExposure.as_str(),
                budget_u64_to_sqlite(event.event_seq, "event_seq")?,
            ],
            |row| {
                Ok((
                    budget_u64_from_row(row, 0, "event_seq")?,
                    budget_u64_from_row(row, 1, "exposure_units")?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "sqlite budget hold `{hold_id}` has no authorization generation"
            ))
        })?;
    let invocation_captured = transaction.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM budget_mutation_events
            WHERE hold_id = ?1
              AND kind = ?2
              AND event_seq > ?3
              AND event_seq <= ?4
        )
        "#,
        params![
            hold_id,
            BudgetMutationKind::CaptureInvocation.as_str(),
            budget_u64_to_sqlite(authorization_seq, "authorization_seq")?,
            budget_u64_to_sqlite(event.event_seq, "event_seq")?,
        ],
        |row| Ok(row.get::<_, i64>(0)? != 0),
    )?;
    let invocation_state = if expected_kind == BudgetMutationKind::ReverseExposure {
        BudgetInvocationState::Reversed
    } else if invocation_captured {
        BudgetInvocationState::Captured
    } else {
        BudgetInvocationState::Authorized
    };
    let monetary_state = if expected_kind == BudgetMutationKind::ReverseExposure {
        if event.exposure_units == 0 {
            BudgetMonetaryState::None
        } else {
            BudgetMonetaryState::Reversed
        }
    } else if expected_kind == BudgetMutationKind::ReleaseExposure {
        let released_exposure_units = transaction.query_row(
            r#"
            SELECT COALESCE(SUM(exposure_units), 0)
            FROM budget_mutation_events
            WHERE hold_id = ?1
              AND kind = ?2
              AND event_seq > ?3
              AND event_seq <= ?4
            "#,
            params![
                hold_id,
                BudgetMutationKind::ReleaseExposure.as_str(),
                budget_u64_to_sqlite(authorization_seq, "authorization_seq")?,
                budget_u64_to_sqlite(event.event_seq, "event_seq")?,
            ],
            |row| budget_u64_from_row(row, 0, "released_exposure_units"),
        )?;
        let remaining_exposure_units = authorized_exposure_units
            .checked_sub(released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "sqlite budget hold `{hold_id}` release history exceeds authorization"
                ))
            })?;
        if authorized_exposure_units == 0 {
            BudgetMonetaryState::None
        } else if remaining_exposure_units == 0 {
            BudgetMonetaryState::Released
        } else {
            BudgetMonetaryState::Exposed
        }
    } else if event.exposure_units == 0 && event.realized_spend_units == 0 {
        BudgetMonetaryState::None
    } else {
        BudgetMonetaryState::Reconciled
    };
    let decision = BudgetHoldMutationDecision {
        hold_id: Some(hold_id.to_string()),
        admission_binding: None,
        exposure_units: event.exposure_units,
        realized_spend_units: event.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            event.total_cost_exposed_after,
            event.total_cost_realized_spend_after,
        )?,
        invocation_count_after: event.invocation_count_after,
        invocation_quota_usages: Vec::new(),
        cumulative_approval: None,
        invocation_state,
        monetary_state,
        metadata: BudgetCommitMetadata {
            authority: event.authority,
            guarantee_level: store.budget_guarantee_level(),
            budget_profile: store.budget_authority_profile(),
            metering_profile: store.budget_metering_profile(),
            budget_commit_index: Some(event.event_seq),
            event_id: Some(event.event_id),
            recorded_at_unix_seconds: u64::try_from(event.recorded_at).ok(),
        },
    };
    transaction.rollback()?;
    Ok(decision)
}
