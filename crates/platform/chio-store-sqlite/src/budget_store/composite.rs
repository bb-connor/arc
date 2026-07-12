use super::*;

#[derive(Debug)]
struct StoredCompositeAuthorization {
    hold_id: String,
    event_id: String,
    capability_id: String,
    grant_index: usize,
    requested_exposure_units: u64,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
    authority: Option<BudgetEventAuthority>,
    allowed: bool,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    revocation_set: CanonicalRevocationSet,
    committed_cost_units_after: u64,
    invocation_count_after: u32,
    event_seq: u64,
    invocation_counts_after: Vec<BudgetInvocationQuotaUsage>,
    authorization_artifact_digests: Vec<String>,
}

#[derive(Debug)]
struct StagedQuota {
    quota: BudgetInvocationQuota,
    reserved: u32,
    captured: u32,
    exists: bool,
}

#[derive(Debug)]
struct StoredCompositeHold {
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    revocation_set: CanonicalRevocationSet,
}

impl StoredCompositeAuthorization {
    fn matches(&self, request: &SqliteCompositeAuthorizeInput) -> bool {
        self.hold_id == request.hold_id
            && self.event_id == request.event_id
            && self.capability_id == request.capability_id
            && self.grant_index == request.grant_index
            && self.requested_exposure_units == request.requested_exposure_units
            && self.max_cost_per_invocation == request.max_cost_per_invocation
            && self.max_total_cost_units == request.max_total_cost_units
            && self.authority == request.authority
            && self.revocation_set == request.revocation_set
            && self.authorization_artifact_digests == request.authorization_artifact_digests
            && self
                .invocation_counts_after
                .iter()
                .map(|usage| &usage.quota)
                .eq(request.invocation_quotas.iter())
    }

    fn into_decision(self) -> BudgetAuthorizeHoldDecision {
        let metadata = composite_metadata(
            self.authority,
            self.allowed.then_some(self.event_seq),
            self.event_id,
        );
        if self.allowed {
            BudgetAuthorizeHoldDecision::Authorized(AuthorizedBudgetHold {
                hold_id: Some(self.hold_id),
                authorized_exposure_units: self.requested_exposure_units,
                committed_cost_units_after: self.committed_cost_units_after,
                invocation_count_after: self.invocation_count_after,
                invocation_counts_after: self.invocation_counts_after,
                invocation_state: self.invocation_state,
                monetary_state: self.monetary_state,
                revocation_set: Some(self.revocation_set),
                metadata,
            })
        } else {
            BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: Some(self.hold_id),
                attempted_exposure_units: self.requested_exposure_units,
                committed_cost_units_after: self.committed_cost_units_after,
                invocation_count_after: self.invocation_count_after,
                invocation_counts_after: self.invocation_counts_after,
                invocation_state: self.invocation_state,
                monetary_state: self.monetary_state,
                revocation_set: Some(self.revocation_set),
                metadata,
            })
        }
    }
}

fn with_composite_savepoint<T>(
    transaction: &rusqlite::Transaction<'_>,
    name: &str,
    apply: impl FnOnce() -> Result<T, BudgetStoreError>,
) -> Result<T, BudgetStoreError> {
    transaction.execute_batch(&format!("SAVEPOINT {name}"))?;
    match apply() {
        Ok(value) => {
            transaction.execute_batch(&format!("RELEASE {name}"))?;
            Ok(value)
        }
        Err(error) => {
            if let Err(rollback_error) =
                transaction.execute_batch(&format!("ROLLBACK TO {name}; RELEASE {name}"))
            {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget savepoint rollback failed after `{error}`: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

impl SqliteBudgetStore {
    pub fn mutation_event_for_event_id_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        event_id: &str,
    ) -> Result<Option<BudgetMutationRecord>, BudgetStoreError> {
        transaction
            .query_row(
                r#"
                SELECT
                    event_id,
                    hold_id,
                    capability_id,
                    grant_index,
                    kind,
                    allowed,
                    recorded_at,
                    event_seq,
                    usage_seq,
                    exposure_units,
                    realized_spend_units,
                    max_invocations,
                    max_exposure_per_invocation,
                    max_total_exposure_units,
                    invocation_count_after,
                    total_cost_exposed_after,
                    total_cost_realized_spend_after,
                    authority_id,
                    lease_id,
                    lease_epoch
                FROM budget_mutation_events
                WHERE event_id = ?1
                "#,
                params![event_id],
                mutation_record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(super) fn capture_composite_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision =
            Self::capture_invocation_reservations_in_transaction(&transaction, &request)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn capture_invocation_reservations_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_capture_invocations", || {
            let hold_id = request.hold_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant("invocation capture requires hold_id".to_string())
            })?;
            let artifact_count = transaction.query_row(
                "SELECT COUNT(*) FROM budget_composite_authorization_artifacts WHERE hold_id = ?1",
                params![hold_id],
                |row| budget_u64_from_row(row, 0, "authorization artifact count"),
            )?;
            if artifact_count > 0 {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{hold_id}` requires the combined admission capture authority"
                )));
            }
            Self::capture_composite_invocation_reservations_in_transaction_unchecked(
                transaction,
                request,
            )
        })
    }

    pub(crate) fn capture_composite_invocation_reservations_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: &BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("invocation capture requires event_id".to_string())
        })?;
        if hold_id.is_empty() || event_id.is_empty() {
            return Err(BudgetStoreError::Invariant(
                "invocation capture requires non-empty hold_id and event_id".to_string(),
            ));
        }

        if let Some(decision) = load_composite_capture_decision(transaction, event_id, request)? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` was not authorized"
            )));
        }
        if authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match capability/grant"
            )));
        }
        if authorization.authority.as_ref() != request.authority.as_ref() {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` authority does not match invocation capture"
            )));
        }
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        if current_hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` invocation reservation is not authorized"
            )));
        }
        let completed_monetary_disposition = match current_hold.monetary_state {
            BudgetMonetaryHoldState::Reconciled => Some(HoldDisposition::Reconciled),
            BudgetMonetaryHoldState::Released => Some(HoldDisposition::Released),
            BudgetMonetaryHoldState::Captured => Some(HoldDisposition::Captured),
            BudgetMonetaryHoldState::None => Some(HoldDisposition::Captured),
            BudgetMonetaryHoldState::Exposed => None,
            BudgetMonetaryHoldState::Reversed => {
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` has an authorized invocation reservation after reversal"
                )));
            }
        };
        if current_hold.revocation_set != authorization.revocation_set {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` revocation evidence diverged from authorization"
            )));
        }

        let mut staged = Vec::with_capacity(authorization.invocation_counts_after.len());
        for snapshot in &authorization.invocation_counts_after {
            let quota = &snapshot.quota;
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let (maximum, reserved, captured) = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key().owner_id()
                    ))
                })?;
            if maximum != quota.max_invocations() || reserved == 0 {
                return Err(BudgetStoreError::Conflict(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key().owner_id()
                )));
            }
            staged.push(StagedQuota {
                quota: quota.clone(),
                reserved: reserved - 1,
                captured: captured.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "captured invocation count overflowed u32".to_string(),
                    )
                })?,
                exists: true,
            });
        }
        let invocation_counts_after = staged
            .iter()
            .map(|entry| BudgetInvocationQuotaUsage {
                quota: entry.quota.clone(),
                reserved_invocations_after: entry.reserved,
                captured_invocations_after: entry.captured,
            })
            .collect::<Vec<_>>();
        for usage in &invocation_counts_after {
            usage.validate()?;
        }
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0 != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }

        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        persist_quota_rows(transaction, &staged, event_seq, now)?;
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3, seq = ?4
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET invocation_state = ?2, updated_at = ?3
            WHERE hold_id = ?1 AND invocation_state = ?4
            "#,
            params![
                hold_id,
                BudgetInvocationReservationState::Captured.as_str(),
                now,
                BudgetInvocationReservationState::Authorized.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state changed during capture"
            )));
        }
        if let Some(disposition) = completed_monetary_disposition {
            SqliteBudgetStore::update_hold(
                transaction,
                hold_id,
                base_hold.remaining_exposure_units,
                disposition,
                request.authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CaptureInvocations,
            None,
            event_seq,
            Some(event_seq),
            0,
            0,
            None,
            None,
            None,
            primary_count_after,
            legacy_usage.1,
            legacy_usage.2,
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            BudgetInvocationReservationState::Captured,
            current_hold.monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id.clone(),
            exposure_units: 0,
            realized_spend_units: 0,
            committed_cost_units_after: checked_committed_cost_units(
                legacy_usage.1,
                legacy_usage.2,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Captured,
            monetary_state: current_hold.monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(
                request.authority.clone(),
                Some(event_seq),
                event_id.to_string(),
            ),
        })
    }

    pub(super) fn reverse_composite_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision = Self::reverse_composite_budget_hold_in_transaction(&transaction, request)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn reverse_composite_budget_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_reverse_composite_hold", || {
            Self::reverse_composite_budget_hold_in_transaction_unchecked(transaction, request)
        })
    }

    fn reverse_composite_budget_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite reverse requires event_id".to_string())
        })?;
        if let Some(decision) = load_composite_transition_decision(
            transaction,
            event_id,
            BudgetMutationKind::ReverseInvocations,
            &request.capability_id,
            request.grant_index,
            hold_id,
            request.authority.as_ref(),
            request.reversed_exposure_units,
            0,
        )? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed
            || authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
            || authorization.authority.as_ref() != request.authority.as_ref()
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match the composite reverse"
            )));
        }
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        if current_hold.invocation_state != BudgetInvocationReservationState::Authorized {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` invocation reservation cannot be reversed"
            )));
        }
        let monetary_state = match current_hold.monetary_state {
            BudgetMonetaryHoldState::Exposed => {
                if base_hold.remaining_exposure_units != request.reversed_exposure_units {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` reverse amount does not match exposure"
                    )));
                }
                BudgetMonetaryHoldState::Reversed
            }
            BudgetMonetaryHoldState::None
            | BudgetMonetaryHoldState::Released
            | BudgetMonetaryHoldState::Reversed => {
                if request.reversed_exposure_units != 0 {
                    return Err(BudgetStoreError::Conflict(format!(
                        "budget hold `{hold_id}` has no reversible monetary exposure"
                    )));
                }
                current_hold.monetary_state
            }
            BudgetMonetaryHoldState::Reconciled | BudgetMonetaryHoldState::Captured => {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{hold_id}` monetary state cannot be reversed"
                )));
            }
        };

        let mut staged = Vec::with_capacity(authorization.invocation_counts_after.len());
        for snapshot in &authorization.invocation_counts_after {
            let quota = &snapshot.quota;
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let (maximum, reserved, captured) = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key().owner_id()
                    ))
                })?;
            if maximum != quota.max_invocations() || reserved == 0 {
                return Err(BudgetStoreError::Conflict(format!(
                    "invocation quota `{}` does not contain the reserved hold unit",
                    quota.key().owner_id()
                )));
            }
            staged.push(StagedQuota {
                quota: quota.clone(),
                reserved: reserved - 1,
                captured,
                exists: true,
            });
        }
        let invocation_counts_after = staged
            .iter()
            .map(|entry| BudgetInvocationQuotaUsage {
                quota: entry.quota.clone(),
                reserved_invocations_after: entry.reserved,
                captured_invocations_after: entry.captured,
            })
            .collect::<Vec<_>>();
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0
            != primary_count_after.checked_add(1).ok_or_else(|| {
                BudgetStoreError::Overflow("primary invocation count overflowed u32".to_string())
            })?
        {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let exposed_after = legacy_usage
            .1
            .checked_sub(request.reversed_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot reverse more than total exposed cost".to_string(),
                )
            })?;
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        persist_quota_rows(transaction, &staged, event_seq, now)?;
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = ?3, total_cost_exposed = ?4,
                updated_at = ?5, seq = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                i64::from(primary_count_after),
                sqlite_integer_from_u64(exposed_after, "composite exposed total")?,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET invocation_state = ?2, monetary_state = ?3,
                remaining_exposure_units = 0, updated_at = ?4
            WHERE hold_id = ?1 AND invocation_state = ?5
            "#,
            params![
                hold_id,
                BudgetInvocationReservationState::Reversed.as_str(),
                monetary_state.as_str(),
                now,
                BudgetInvocationReservationState::Authorized.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation state changed during reverse"
            )));
        }
        SqliteBudgetStore::update_hold(
            transaction,
            hold_id,
            0,
            HoldDisposition::Reversed,
            request.authority.as_ref(),
        )?;
        SqliteBudgetStore::append_mutation_event(
            transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::ReverseInvocations,
            None,
            event_seq,
            Some(event_seq),
            request.reversed_exposure_units,
            0,
            None,
            None,
            None,
            primary_count_after,
            exposed_after,
            legacy_usage.2,
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            BudgetInvocationReservationState::Reversed,
            monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.reversed_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: checked_committed_cost_units(
                exposed_after,
                legacy_usage.2,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: BudgetInvocationReservationState::Reversed,
            monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(request.authority, Some(event_seq), event_id.to_string()),
        })
    }

    pub(super) fn settle_composite_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision =
            Self::settle_composite_budget_hold_in_transaction(&transaction, request, capture)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn settle_composite_budget_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_settle_composite_hold", || {
            Self::settle_composite_budget_hold_in_transaction_unchecked(
                transaction,
                request,
                capture,
            )
        })
    }

    fn settle_composite_budget_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReconcileHoldRequest,
        capture: bool,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite settlement requires event_id".to_string())
        })?;
        if request.realized_spend_units > request.exposed_cost_units {
            return Err(BudgetStoreError::Conflict(
                "realized spend exceeds exposed cost".to_string(),
            ));
        }
        let kind = if capture {
            BudgetMutationKind::CaptureExposure
        } else {
            BudgetMutationKind::ReconcileSpend
        };
        let next_monetary_state = if capture {
            BudgetMonetaryHoldState::Captured
        } else {
            BudgetMonetaryHoldState::Reconciled
        };
        let terminal_disposition = if capture {
            HoldDisposition::Captured
        } else {
            HoldDisposition::Reconciled
        };

        if let Some(decision) = load_composite_transition_decision(
            transaction,
            event_id,
            kind,
            &request.capability_id,
            request.grant_index,
            hold_id,
            request.authority.as_ref(),
            request.exposed_cost_units,
            request.realized_spend_units,
        )? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed
            || authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
            || authorization.authority.as_ref() != request.authority.as_ref()
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match the composite settlement"
            )));
        }
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        if current_hold.monetary_state != BudgetMonetaryHoldState::Exposed
            || base_hold.remaining_exposure_units != request.exposed_cost_units
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not contain the settled exposure"
            )));
        }
        if matches!(
            current_hold.invocation_state,
            BudgetInvocationReservationState::Reversed
                | BudgetInvocationReservationState::Denied
                | BudgetInvocationReservationState::Absent
        ) {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` invocation state cannot settle monetary exposure"
            )));
        }
        let next_disposition =
            if current_hold.invocation_state == BudgetInvocationReservationState::Authorized {
                HoldDisposition::Open
            } else {
                terminal_disposition
            };

        let invocation_counts_after =
            load_live_quota_usages(transaction, &authorization.invocation_counts_after)?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0 != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let exposed_after = legacy_usage
            .1
            .checked_sub(request.exposed_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot settle more than total exposed cost".to_string(),
                )
            })?;
        let realized_after = legacy_usage
            .2
            .checked_add(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow("realized spend overflowed u64".to_string())
            })?;
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET total_cost_exposed = ?3, total_cost_realized_spend = ?4,
                updated_at = ?5, seq = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                sqlite_integer_from_u64(exposed_after, "composite exposed total")?,
                sqlite_integer_from_u64(realized_after, "composite realized-spend total")?,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET monetary_state = ?2, remaining_exposure_units = 0, updated_at = ?3
            WHERE hold_id = ?1 AND monetary_state = ?4
            "#,
            params![
                hold_id,
                next_monetary_state.as_str(),
                now,
                BudgetMonetaryHoldState::Exposed.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary state changed during settlement"
            )));
        }
        SqliteBudgetStore::update_hold(
            transaction,
            hold_id,
            0,
            next_disposition,
            request.authority.as_ref(),
        )?;
        SqliteBudgetStore::append_mutation_event(
            transaction,
            Some(event_id),
            Some(hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            kind,
            None,
            event_seq,
            Some(event_seq),
            request.exposed_cost_units,
            request.realized_spend_units,
            None,
            None,
            None,
            primary_count_after,
            exposed_after,
            realized_after,
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            current_hold.invocation_state,
            next_monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after: checked_committed_cost_units(
                exposed_after,
                realized_after,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: current_hold.invocation_state,
            monetary_state: next_monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(request.authority, Some(event_seq), event_id.to_string()),
        })
    }

    pub(super) fn release_composite_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision = Self::release_composite_budget_hold_in_transaction(&transaction, request)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn release_composite_budget_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_release_composite_hold", || {
            Self::release_composite_budget_hold_in_transaction_unchecked(transaction, request)
        })
    }

    fn release_composite_budget_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let hold_id = request.hold_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires hold_id".to_string())
        })?;
        let event_id = request.event_id.as_deref().ok_or_else(|| {
            BudgetStoreError::Invariant("composite release requires event_id".to_string())
        })?;
        if let Some(decision) = load_composite_transition_decision(
            transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            &request.capability_id,
            request.grant_index,
            hold_id,
            request.authority.as_ref(),
            request.released_exposure_units,
            0,
        )? {
            return Ok(decision);
        }

        let authorization =
            load_composite_authorization(transaction, hold_id)?.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "missing composite budget authorization for hold `{hold_id}`"
                ))
            })?;
        if !authorization.allowed
            || authorization.capability_id != request.capability_id
            || authorization.grant_index != request.grant_index
            || authorization.authority.as_ref() != request.authority.as_ref()
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` does not match the composite release"
            )));
        }
        let base_hold = SqliteBudgetStore::ensure_open_hold(
            transaction,
            hold_id,
            &request.capability_id,
            request.grant_index,
        )?;
        SqliteBudgetStore::validate_hold_authority(
            hold_id,
            base_hold.authority.as_ref(),
            request.authority.as_ref(),
        )?;
        let current_hold = load_composite_hold(transaction, hold_id)?;
        if current_hold.monetary_state != BudgetMonetaryHoldState::Exposed
            || request.released_exposure_units > base_hold.remaining_exposure_units
            || matches!(
                current_hold.invocation_state,
                BudgetInvocationReservationState::Reversed
                    | BudgetInvocationReservationState::Denied
                    | BudgetInvocationReservationState::Absent
            )
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget hold `{hold_id}` cannot release the requested exposure"
            )));
        }

        let invocation_counts_after =
            load_live_quota_usages(transaction, &authorization.invocation_counts_after)?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let legacy_usage = load_legacy_usage_for_identity(
            transaction,
            &request.capability_id,
            request.grant_index,
        )?;
        if legacy_usage.0 != primary_count_after {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite quota".to_string(),
            ));
        }
        let exposed_after = legacy_usage
            .1
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "cannot release more than total exposed cost".to_string(),
                )
            })?;
        let remaining_exposure = base_hold
            .remaining_exposure_units
            .checked_sub(request.released_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("cannot release more than hold exposure".to_string())
            })?;
        let next_monetary_state = if remaining_exposure == 0 {
            BudgetMonetaryHoldState::Released
        } else {
            BudgetMonetaryHoldState::Exposed
        };
        let next_disposition = if remaining_exposure == 0
            && current_hold.invocation_state == BudgetInvocationReservationState::Captured
        {
            HoldDisposition::Released
        } else {
            HoldDisposition::Open
        };
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();
        let updated_projection = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET total_cost_exposed = ?3, updated_at = ?4, seq = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                sqlite_integer_from_u64(exposed_after, "composite exposed total")?,
                now,
                sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            ],
        )?;
        if updated_projection != 1 {
            return Err(BudgetStoreError::Invariant(
                "missing composite budget usage row".to_string(),
            ));
        }
        let updated_hold = transaction.execute(
            r#"
            UPDATE budget_composite_holds
            SET monetary_state = ?2, remaining_exposure_units = ?3, updated_at = ?4
            WHERE hold_id = ?1 AND monetary_state = ?5
            "#,
            params![
                hold_id,
                next_monetary_state.as_str(),
                sqlite_integer_from_u64(remaining_exposure, "composite remaining exposure")?,
                now,
                BudgetMonetaryHoldState::Exposed.as_str(),
            ],
        )?;
        if updated_hold != 1 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` monetary state changed during release"
            )));
        }
        SqliteBudgetStore::update_hold(
            transaction,
            hold_id,
            remaining_exposure,
            next_disposition,
            request.authority.as_ref(),
        )?;
        SqliteBudgetStore::append_mutation_event(
            transaction,
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
            primary_count_after,
            exposed_after,
            legacy_usage.2,
        )?;
        persist_composite_mutation_snapshot(
            transaction,
            event_id,
            current_hold.invocation_state,
            next_monetary_state,
            &current_hold.revocation_set,
            &invocation_counts_after,
        )?;
        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.released_exposure_units,
            realized_spend_units: 0,
            committed_cost_units_after: checked_committed_cost_units(
                exposed_after,
                legacy_usage.2,
            )?,
            invocation_count_after: primary_count_after,
            invocation_counts_after,
            invocation_state: current_hold.invocation_state,
            monetary_state: next_monetary_state,
            revocation_set: Some(current_hold.revocation_set),
            metadata: composite_metadata(request.authority, Some(event_seq), event_id.to_string()),
        })
    }
}

impl SqliteBudgetStore {
    pub(super) fn has_composite_authorization(
        &self,
        hold_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let Some(hold_id) = hold_id else {
            return Ok(false);
        };
        Ok(self
            .connection()?
            .query_row(
                "SELECT 1 FROM budget_composite_authorizations WHERE hold_id = ?1",
                params![hold_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn authorize_composite_hold(
        &self,
        request: SqliteCompositeAuthorizeInput,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let decision = Self::authorize_composite_hold_in_transaction(&transaction, request)?;
        transaction.commit()?;
        Ok(decision)
    }

    pub fn authorize_composite_hold_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        request: SqliteCompositeAuthorizeInput,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        with_composite_savepoint(transaction, "chio_authorize_composite_hold", || {
            Self::authorize_composite_hold_in_transaction_unchecked(transaction, request)
        })
    }

    fn authorize_composite_hold_in_transaction_unchecked(
        transaction: &rusqlite::Transaction<'_>,
        request: SqliteCompositeAuthorizeInput,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        validate_composite_input(&request)?;

        if let Some(existing) = load_composite_authorization(transaction, &request.hold_id)? {
            if !existing.matches(&request) {
                return Err(BudgetStoreError::Conflict(format!(
                    "budget hold `{}` was reused for a different composite authorization",
                    request.hold_id
                )));
            }
            let decision = existing.into_decision();
            return Ok(decision);
        }
        if let Some(existing_hold_id) = transaction
            .query_row(
                "SELECT hold_id FROM budget_composite_authorizations WHERE event_id = ?1",
                params![request.event_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Err(BudgetStoreError::Conflict(format!(
                "budget event_id `{}` is already claimed by hold `{existing_hold_id}`",
                request.event_id
            )));
        }
        reject_legacy_namespace_collisions(transaction, &request)?;

        let legacy_usage = load_legacy_usage(transaction, &request)?;
        let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
        let mut staged = Vec::with_capacity(request.invocation_quotas.len());
        let mut quota_exhausted = false;
        for quota in &request.invocation_quotas {
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let stored = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?;
            let (reserved, captured, exists) = match stored {
                Some((maximum, reserved, captured)) => {
                    if maximum != quota.max_invocations() {
                        return Err(BudgetStoreError::Conflict(format!(
                            "invocation quota `{}` was presented with a different maximum",
                            quota.key().owner_id()
                        )));
                    }
                    (reserved, captured, true)
                }
                None => (
                    0,
                    if quota.key() == &primary_key {
                        legacy_usage.0
                    } else {
                        0
                    },
                    false,
                ),
            };
            let count = reserved.checked_add(captured).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "reserved invocations + captured invocations overflowed u32".to_string(),
                )
            })?;
            if count > quota.max_invocations() {
                return Err(BudgetStoreError::Conflict(format!(
                    "invocation quota `{}` maximum is below existing usage",
                    quota.key().owner_id()
                )));
            }
            if count == quota.max_invocations() {
                quota_exhausted = true;
            }
            staged.push(StagedQuota {
                quota: quota.clone(),
                reserved,
                captured,
                exists,
            });
        }
        let primary_before = staged
            .iter()
            .find(|entry| entry.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota counter".to_string())
            })?
            .reserved
            .checked_add(
                staged
                    .iter()
                    .find(|entry| entry.quota.key() == &primary_key)
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant("missing primary quota counter".to_string())
                    })?
                    .captured,
            )
            .ok_or_else(|| {
                BudgetStoreError::Overflow("primary invocation count overflowed u32".to_string())
            })?;
        if primary_before != legacy_usage.0 {
            return Err(BudgetStoreError::Invariant(
                "grant usage projection diverged from composite invocation quota".to_string(),
            ));
        }

        let committed_before = checked_committed_cost_units(legacy_usage.1, legacy_usage.2)?;
        let committed_if_allowed = committed_before
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "committed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let exposed_if_allowed = legacy_usage
            .1
            .checked_add(request.requested_exposure_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total exposed cost + requested exposure overflowed u64".to_string(),
                )
            })?;
        let monetary_denied = request
            .max_cost_per_invocation
            .is_some_and(|maximum| request.requested_exposure_units > maximum)
            || request
                .max_total_cost_units
                .is_some_and(|maximum| committed_if_allowed > maximum);
        let allowed = !quota_exhausted && !monetary_denied;
        let event_seq = allocate_budget_replication_seq(transaction)?;
        let now = unix_now();

        if allowed {
            for entry in &mut staged {
                entry.reserved = entry.reserved.checked_add(1).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "reserved invocation count overflowed u32".to_string(),
                    )
                })?;
            }
        }
        persist_quota_rows(transaction, &staged, event_seq, now)?;

        let invocation_counts_after = staged
            .iter()
            .map(|entry| BudgetInvocationQuotaUsage {
                quota: entry.quota.clone(),
                reserved_invocations_after: entry.reserved,
                captured_invocations_after: entry.captured,
            })
            .collect::<Vec<_>>();
        for usage in &invocation_counts_after {
            usage.validate()?;
        }
        let primary_count_after = invocation_counts_after
            .iter()
            .find(|usage| usage.quota.key() == &primary_key)
            .ok_or_else(|| {
                BudgetStoreError::Invariant("missing primary quota snapshot".to_string())
            })?
            .invocation_count_after()?;
        let invocation_state = if allowed {
            BudgetInvocationReservationState::Authorized
        } else {
            BudgetInvocationReservationState::Denied
        };
        let monetary_present = request.requested_exposure_units > 0
            || request.max_cost_per_invocation.is_some()
            || request.max_total_cost_units.is_some();
        let monetary_state = if allowed && monetary_present {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        let committed_cost_units_after = if allowed {
            committed_if_allowed
        } else {
            committed_before
        };
        let exposed_after = if allowed {
            exposed_if_allowed
        } else {
            legacy_usage.1
        };

        if allowed {
            upsert_legacy_projection(
                transaction,
                &request,
                primary_count_after,
                exposed_after,
                legacy_usage.2,
                event_seq,
                now,
            )?;
            SqliteBudgetStore::create_hold(
                transaction,
                &request.hold_id,
                &request.capability_id,
                request.grant_index,
                request.requested_exposure_units,
                request.authority.as_ref(),
            )?;
            transaction.execute(
                r#"
                INSERT INTO budget_composite_holds (
                    hold_id, invocation_state, monetary_state,
                    revocation_set_digest, revocation_ids_json,
                    remaining_exposure_units, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                "#,
                params![
                    request.hold_id,
                    invocation_state.as_str(),
                    monetary_state.as_str(),
                    request.revocation_set.digest(),
                    serde_json::to_string(request.revocation_set.ids()).map_err(|error| {
                        BudgetStoreError::Invariant(format!(
                            "failed to encode canonical revocation set: {error}"
                        ))
                    })?,
                    sqlite_integer_from_u64(
                        request.requested_exposure_units,
                        "composite remaining exposure"
                    )?,
                    now,
                ],
            )?;
        }

        SqliteBudgetStore::append_mutation_event(
            transaction,
            Some(&request.event_id),
            Some(&request.hold_id),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::ReserveInvocations,
            Some(allowed),
            event_seq,
            allowed.then_some(event_seq),
            request.requested_exposure_units,
            0,
            None,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            primary_count_after,
            exposed_after,
            legacy_usage.2,
        )?;
        persist_composite_authorization(
            transaction,
            &request,
            allowed,
            invocation_state,
            monetary_state,
            committed_cost_units_after,
            primary_count_after,
            event_seq,
            now,
            &invocation_counts_after,
        )?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_managed_grants (
                capability_id, grant_index, first_hold_id
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(capability_id, grant_index) DO NOTHING
            "#,
            params![
                request.capability_id,
                request.grant_index as i64,
                request.hold_id,
            ],
        )?;
        let metadata = composite_metadata(
            request.authority.clone(),
            allowed.then_some(event_seq),
            request.event_id.clone(),
        );
        if allowed {
            Ok(BudgetAuthorizeHoldDecision::Authorized(
                AuthorizedBudgetHold {
                    hold_id: Some(request.hold_id),
                    authorized_exposure_units: request.requested_exposure_units,
                    committed_cost_units_after,
                    invocation_count_after: primary_count_after,
                    invocation_counts_after,
                    invocation_state,
                    monetary_state,
                    revocation_set: Some(request.revocation_set),
                    metadata,
                },
            ))
        } else {
            Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
                hold_id: Some(request.hold_id),
                attempted_exposure_units: request.requested_exposure_units,
                committed_cost_units_after,
                invocation_count_after: primary_count_after,
                invocation_counts_after,
                invocation_state,
                monetary_state,
                revocation_set: Some(request.revocation_set),
                metadata,
            }))
        }
    }
}

fn validate_composite_input(
    request: &SqliteCompositeAuthorizeInput,
) -> Result<(), BudgetStoreError> {
    if request.hold_id.is_empty() || request.event_id.is_empty() {
        return Err(BudgetStoreError::Invariant(
            "composite budget authorization requires hold_id and event_id".to_string(),
        ));
    }
    if request.invocation_quotas.is_empty()
        || request.invocation_quotas.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION
    {
        return Err(BudgetStoreError::Invariant(format!(
            "composite budget authorization requires 1 to {MAX_INVOCATION_QUOTAS_PER_ADMISSION} invocation quotas"
        )));
    }
    let mut previous: Option<&BudgetQuotaKey> = None;
    let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
    let mut primary_count = 0usize;
    for quota in &request.invocation_quotas {
        quota.validate()?;
        if previous.is_some_and(|key| key >= quota.key()) {
            return Err(BudgetStoreError::Invariant(
                "budget invocation quotas must be strictly sorted without duplicate keys"
                    .to_string(),
            ));
        }
        previous = Some(quota.key());
        if quota.key().profile() == BudgetQuotaProfile::GrantInvocation {
            if quota.key() != &primary_key {
                return Err(BudgetStoreError::Invariant(
                    "composite budget hold has an ambiguous grant invocation quota".to_string(),
                ));
            }
            primary_count += 1;
        }
    }
    if primary_count != 1 {
        return Err(BudgetStoreError::Invariant(
            "composite budget hold requires exactly one matched grant invocation quota".to_string(),
        ));
    }
    request.revocation_set.validate().map_err(|error| {
        BudgetStoreError::Invariant(format!("invalid canonical revocation set: {error}"))
    })?;
    if request
        .revocation_set
        .ids()
        .binary_search(&request.capability_id)
        .is_err()
    {
        return Err(BudgetStoreError::Invariant(
            "canonical revocation set omits the leaf capability".to_string(),
        ));
    }
    sqlite_integer_from_u64(
        u64::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Overflow("composite grant index exceeds u64".to_string())
        })?,
        "composite grant index",
    )?;
    sqlite_integer_from_u64(request.requested_exposure_units, "composite exposure")?;
    request
        .max_cost_per_invocation
        .map(|value| sqlite_integer_from_u64(value, "composite per-invocation maximum"))
        .transpose()?;
    request
        .max_total_cost_units
        .map(|value| sqlite_integer_from_u64(value, "composite total maximum"))
        .transpose()?;
    if request.authorization_artifact_digests.len()
        > MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION
        || request.authorization_artifact_digests.iter().any(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        || request
            .authorization_artifact_digests
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(BudgetStoreError::Invariant(
            "authorization artifact digests are invalid, unsorted, or duplicated".to_string(),
        ));
    }
    if let Some(authority) = &request.authority {
        sqlite_integer_from_u64(authority.lease_epoch, "composite lease epoch")?;
    }
    Ok(())
}

fn reject_legacy_namespace_collisions(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
) -> Result<(), BudgetStoreError> {
    let hold_collision = transaction
        .query_row(
            r#"
            SELECT 1 FROM budget_authorization_claims WHERE hold_id = ?1
            UNION ALL
            SELECT 1 FROM budget_authorization_holds WHERE hold_id = ?1
            LIMIT 1
            "#,
            params![request.hold_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if hold_collision {
        return Err(BudgetStoreError::Conflict(format!(
            "budget hold `{}` collides with a legacy hold",
            request.hold_id
        )));
    }
    let event_collision = transaction
        .query_row(
            "SELECT 1 FROM budget_mutation_events WHERE event_id = ?1",
            params![request.event_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if event_collision {
        return Err(BudgetStoreError::Conflict(format!(
            "budget event_id `{}` collides with an existing event",
            request.event_id
        )));
    }
    Ok(())
}

fn load_legacy_usage(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
) -> Result<(u32, u64, u64), BudgetStoreError> {
    load_legacy_usage_for_identity(transaction, &request.capability_id, request.grant_index)
}

fn load_legacy_usage_for_identity(
    transaction: &rusqlite::Transaction<'_>,
    capability_id: &str,
    grant_index: usize,
) -> Result<(u32, u64, u64), BudgetStoreError> {
    Ok(transaction
        .query_row(
            r#"
            SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
            FROM capability_grant_budgets
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![capability_id, grant_index as i64],
            |row| {
                Ok((
                    budget_u32_from_row(row, 0, "invocation_count")?,
                    budget_u64_from_row(row, 1, "total_cost_exposed")?,
                    budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                ))
            },
        )
        .optional()?
        .unwrap_or((0, 0, 0)))
}

fn load_live_quota_usages(
    transaction: &rusqlite::Transaction<'_>,
    members: &[BudgetInvocationQuotaUsage],
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    members
        .iter()
        .map(|member| {
            let quota = &member.quota;
            let (profile, owner_id, grant_index_key) = quota_storage_key(quota.key())?;
            let (maximum, reserved, captured) = transaction
                .query_row(
                    r#"
                    SELECT max_invocations, reserved_invocations, captured_invocations
                    FROM budget_invocation_quota_usage
                    WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                    "#,
                    params![profile, owner_id, grant_index_key],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "quota max_invocations")?,
                            budget_u32_from_row(row, 1, "quota reserved_invocations")?,
                            budget_u32_from_row(row, 2, "quota captured_invocations")?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "missing invocation quota row for `{}`",
                        quota.key().owner_id()
                    ))
                })?;
            if maximum != quota.max_invocations() {
                return Err(BudgetStoreError::Invariant(format!(
                    "invocation quota `{}` maximum changed",
                    quota.key().owner_id()
                )));
            }
            let usage = BudgetInvocationQuotaUsage {
                quota: quota.clone(),
                reserved_invocations_after: reserved,
                captured_invocations_after: captured,
            };
            usage.validate()?;
            Ok(usage)
        })
        .collect()
}

fn quota_storage_key(key: &BudgetQuotaKey) -> Result<(&str, &str, i64), BudgetStoreError> {
    key.validate()?;
    let grant_index_key = key.grant_index().map_or(-1_i64, i64::from);
    Ok((key.profile().as_str(), key.owner_id(), grant_index_key))
}

fn persist_quota_rows(
    transaction: &rusqlite::Transaction<'_>,
    staged: &[StagedQuota],
    event_seq: u64,
    now: i64,
) -> Result<(), BudgetStoreError> {
    let event_seq = sqlite_integer_from_u64(event_seq, "composite quota sequence")?;
    for entry in staged {
        let (profile, owner_id, grant_index_key) = quota_storage_key(entry.quota.key())?;
        if entry.exists {
            transaction.execute(
                r#"
                UPDATE budget_invocation_quota_usage
                SET reserved_invocations = ?4,
                    captured_invocations = ?5,
                    updated_at = ?6,
                    seq = ?7
                WHERE profile = ?1 AND owner_id = ?2 AND grant_index_key = ?3
                "#,
                params![
                    profile,
                    owner_id,
                    grant_index_key,
                    i64::from(entry.reserved),
                    i64::from(entry.captured),
                    now,
                    event_seq,
                ],
            )?;
        } else {
            transaction.execute(
                r#"
                INSERT INTO budget_invocation_quota_usage (
                    profile, owner_id, grant_index_key, max_invocations,
                    reserved_invocations, captured_invocations, updated_at, seq
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    profile,
                    owner_id,
                    grant_index_key,
                    i64::from(entry.quota.max_invocations()),
                    i64::from(entry.reserved),
                    i64::from(entry.captured),
                    now,
                    event_seq,
                ],
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn upsert_legacy_projection(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
    invocation_count: u32,
    total_cost_exposed: u64,
    total_cost_realized_spend: u64,
    event_seq: u64,
    now: i64,
) -> Result<(), BudgetStoreError> {
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
            request.capability_id,
            request.grant_index as i64,
            i64::from(invocation_count),
            now,
            sqlite_integer_from_u64(event_seq, "composite projection sequence")?,
            sqlite_integer_from_u64(total_cost_exposed, "composite exposed total")?,
            sqlite_integer_from_u64(total_cost_realized_spend, "composite realized-spend total")?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_composite_authorization(
    transaction: &rusqlite::Transaction<'_>,
    request: &SqliteCompositeAuthorizeInput,
    allowed: bool,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    committed_cost_units_after: u64,
    invocation_count_after: u32,
    event_seq: u64,
    now: i64,
    usages: &[BudgetInvocationQuotaUsage],
) -> Result<(), BudgetStoreError> {
    let revocation_ids_json =
        serde_json::to_string(request.revocation_set.ids()).map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "failed to encode canonical revocation set: {error}"
            ))
        })?;
    transaction.execute(
        r#"
        INSERT INTO budget_composite_authorizations (
            hold_id, event_id, capability_id, grant_index,
            requested_exposure_units, max_cost_per_invocation, max_total_cost_units,
            authority_id, lease_id, lease_epoch, allowed,
            invocation_state, monetary_state,
            revocation_set_digest, revocation_ids_json,
            committed_cost_units_after, invocation_count_after,
            event_seq, created_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
            ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19
        )
        "#,
        params![
            request.hold_id,
            request.event_id,
            request.capability_id,
            request.grant_index as i64,
            sqlite_integer_from_u64(request.requested_exposure_units, "composite exposure")?,
            request
                .max_cost_per_invocation
                .map(|value| sqlite_integer_from_u64(value, "composite per-invocation maximum"))
                .transpose()?,
            request
                .max_total_cost_units
                .map(|value| sqlite_integer_from_u64(value, "composite total maximum"))
                .transpose()?,
            request
                .authority
                .as_ref()
                .map(|value| value.authority_id.as_str()),
            request
                .authority
                .as_ref()
                .map(|value| value.lease_id.as_str()),
            request
                .authority
                .as_ref()
                .map(|value| sqlite_integer_from_u64(value.lease_epoch, "composite lease epoch"))
                .transpose()?,
            if allowed { 1_i64 } else { 0_i64 },
            invocation_state.as_str(),
            monetary_state.as_str(),
            request.revocation_set.digest(),
            revocation_ids_json,
            sqlite_integer_from_u64(committed_cost_units_after, "composite committed cost total")?,
            i64::from(invocation_count_after),
            sqlite_integer_from_u64(event_seq, "composite event sequence")?,
            now,
        ],
    )?;
    for (position, usage) in usages.iter().enumerate() {
        let (profile, owner_id, grant_index_key) = quota_storage_key(usage.quota.key())?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_authorization_quotas (
                hold_id, position, profile, owner_id, grant_index_key,
                max_invocations, reserved_invocations_after,
                captured_invocations_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                request.hold_id,
                position as i64,
                profile,
                owner_id,
                grant_index_key,
                i64::from(usage.quota.max_invocations()),
                i64::from(usage.reserved_invocations_after),
                i64::from(usage.captured_invocations_after),
            ],
        )?;
    }
    for (position, digest) in request.authorization_artifact_digests.iter().enumerate() {
        transaction.execute(
            r#"
            INSERT INTO budget_composite_authorization_artifacts (
                hold_id, position, artifact_digest
            ) VALUES (?1, ?2, ?3)
            "#,
            params![request.hold_id, position as i64, digest],
        )?;
    }
    transaction.execute(
        r#"
        INSERT INTO budget_composite_mutation_snapshots (
            event_id, invocation_state, monetary_state,
            revocation_set_digest, revocation_ids_json
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            request.event_id,
            invocation_state.as_str(),
            monetary_state.as_str(),
            request.revocation_set.digest(),
            serde_json::to_string(request.revocation_set.ids()).map_err(|error| {
                BudgetStoreError::Invariant(format!(
                    "failed to encode canonical revocation set: {error}"
                ))
            })?,
        ],
    )?;
    for (position, usage) in usages.iter().enumerate() {
        let (profile, owner_id, grant_index_key) = quota_storage_key(usage.quota.key())?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_mutation_quota_snapshots (
                event_id, position, profile, owner_id, grant_index_key,
                max_invocations, reserved_invocations_after,
                captured_invocations_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                request.event_id,
                position as i64,
                profile,
                owner_id,
                grant_index_key,
                i64::from(usage.quota.max_invocations()),
                i64::from(usage.reserved_invocations_after),
                i64::from(usage.captured_invocations_after),
            ],
        )?;
    }
    Ok(())
}

fn persist_composite_mutation_snapshot(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
    invocation_state: BudgetInvocationReservationState,
    monetary_state: BudgetMonetaryHoldState,
    revocation_set: &CanonicalRevocationSet,
    usages: &[BudgetInvocationQuotaUsage],
) -> Result<(), BudgetStoreError> {
    let revocation_ids_json = serde_json::to_string(revocation_set.ids()).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "failed to encode canonical revocation set: {error}"
        ))
    })?;
    transaction.execute(
        r#"
        INSERT INTO budget_composite_mutation_snapshots (
            event_id, invocation_state, monetary_state,
            revocation_set_digest, revocation_ids_json
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            event_id,
            invocation_state.as_str(),
            monetary_state.as_str(),
            revocation_set.digest(),
            revocation_ids_json,
        ],
    )?;
    for (position, usage) in usages.iter().enumerate() {
        usage.validate()?;
        let (profile, owner_id, grant_index_key) = quota_storage_key(usage.quota.key())?;
        transaction.execute(
            r#"
            INSERT INTO budget_composite_mutation_quota_snapshots (
                event_id, position, profile, owner_id, grant_index_key,
                max_invocations, reserved_invocations_after,
                captured_invocations_after
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                event_id,
                position as i64,
                profile,
                owner_id,
                grant_index_key,
                i64::from(usage.quota.max_invocations()),
                i64::from(usage.reserved_invocations_after),
                i64::from(usage.captured_invocations_after),
            ],
        )?;
    }
    Ok(())
}

fn load_composite_capture_decision(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
    request: &BudgetCaptureInvocationRequest,
) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
    let Some(record) = SqliteBudgetStore::load_mutation_event(transaction, event_id)? else {
        return Ok(None);
    };
    if record.kind != BudgetMutationKind::CaptureInvocations
        || record.hold_id != request.hold_id
        || record.capability_id != request.capability_id
        || record.grant_index as usize != request.grant_index
        || record.authority != request.authority
        || record.allowed.is_some()
        || record.exposure_units != 0
        || record.realized_spend_units != 0
    {
        return Err(BudgetStoreError::Conflict(format!(
            "budget event_id `{event_id}` was reused for a different invocation capture"
        )));
    }
    let state = load_composite_mutation_state(transaction, event_id)?;
    if state.invocation_state != BudgetInvocationReservationState::Captured {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` has a non-captured invocation snapshot"
        )));
    }
    let invocation_counts_after = load_mutation_quota_snapshots(transaction, event_id)?;
    let primary_key = BudgetQuotaKey::grant(&request.capability_id, request.grant_index)?;
    let primary_count_after = invocation_counts_after
        .iter()
        .find(|usage| usage.quota.key() == &primary_key)
        .ok_or_else(|| BudgetStoreError::Invariant("missing primary quota snapshot".to_string()))?
        .invocation_count_after()?;
    if primary_count_after != record.invocation_count_after {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` primary quota snapshot diverged"
        )));
    }
    Ok(Some(BudgetHoldMutationDecision {
        hold_id: record.hold_id,
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            record.total_cost_exposed_after,
            record.total_cost_realized_spend_after,
        )?,
        invocation_count_after: record.invocation_count_after,
        invocation_counts_after,
        invocation_state: state.invocation_state,
        monetary_state: state.monetary_state,
        revocation_set: Some(state.revocation_set),
        metadata: composite_metadata(record.authority, Some(record.event_seq), record.event_id),
    }))
}

#[allow(clippy::too_many_arguments)]
fn load_composite_transition_decision(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
    expected_kind: BudgetMutationKind,
    capability_id: &str,
    grant_index: usize,
    hold_id: &str,
    authority: Option<&BudgetEventAuthority>,
    exposure_units: u64,
    realized_spend_units: u64,
) -> Result<Option<BudgetHoldMutationDecision>, BudgetStoreError> {
    let Some(record) = SqliteBudgetStore::load_mutation_event(transaction, event_id)? else {
        return Ok(None);
    };
    if record.kind != expected_kind
        || record.hold_id.as_deref() != Some(hold_id)
        || record.capability_id != capability_id
        || record.grant_index as usize != grant_index
        || record.authority.as_ref() != authority
        || record.allowed.is_some()
        || record.exposure_units != exposure_units
        || record.realized_spend_units != realized_spend_units
    {
        return Err(BudgetStoreError::Conflict(format!(
            "budget event_id `{event_id}` was reused for a different composite transition"
        )));
    }
    let state = load_composite_mutation_state(transaction, event_id)?;
    let invocation_counts_after = load_mutation_quota_snapshots(transaction, event_id)?;
    let primary_key = BudgetQuotaKey::grant(capability_id, grant_index)?;
    let primary_count_after = invocation_counts_after
        .iter()
        .find(|usage| usage.quota.key() == &primary_key)
        .ok_or_else(|| BudgetStoreError::Invariant("missing primary quota snapshot".to_string()))?
        .invocation_count_after()?;
    if primary_count_after != record.invocation_count_after {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{event_id}` primary quota snapshot diverged"
        )));
    }
    Ok(Some(BudgetHoldMutationDecision {
        hold_id: record.hold_id,
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            record.total_cost_exposed_after,
            record.total_cost_realized_spend_after,
        )?,
        invocation_count_after: record.invocation_count_after,
        invocation_counts_after,
        invocation_state: state.invocation_state,
        monetary_state: state.monetary_state,
        revocation_set: Some(state.revocation_set),
        metadata: composite_metadata(record.authority, record.usage_seq, record.event_id),
    }))
}

fn load_composite_hold(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<StoredCompositeHold, BudgetStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT invocation_state, monetary_state,
                   revocation_set_digest, revocation_ids_json
            FROM budget_composite_holds
            WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!("missing composite budget hold `{hold_id}`"))
        })?;
    stored_composite_state(row.0, row.1, row.2, row.3)
}

fn load_composite_mutation_state(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
) -> Result<StoredCompositeHold, BudgetStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT invocation_state, monetary_state,
                   revocation_set_digest, revocation_ids_json
            FROM budget_composite_mutation_snapshots
            WHERE event_id = ?1
            "#,
            params![event_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "missing composite state snapshot for event `{event_id}`"
            ))
        })?;
    stored_composite_state(row.0, row.1, row.2, row.3)
}

fn stored_composite_state(
    invocation_state: String,
    monetary_state: String,
    revocation_set_digest: String,
    revocation_ids_json: String,
) -> Result<StoredCompositeHold, BudgetStoreError> {
    let invocation_state =
        BudgetInvocationReservationState::parse(&invocation_state).ok_or_else(|| {
            BudgetStoreError::Invariant("unknown persisted invocation state".to_string())
        })?;
    let monetary_state = BudgetMonetaryHoldState::parse(&monetary_state).ok_or_else(|| {
        BudgetStoreError::Invariant("unknown persisted monetary state".to_string())
    })?;
    let ids = serde_json::from_str::<Vec<String>>(&revocation_ids_json).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "invalid persisted canonical revocation members: {error}"
        ))
    })?;
    let revocation_set = CanonicalRevocationSet::from_persisted_parts(ids, revocation_set_digest)
        .map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "invalid persisted canonical revocation set: {error}"
        ))
    })?;
    Ok(StoredCompositeHold {
        invocation_state,
        monetary_state,
        revocation_set,
    })
}

fn load_composite_authorization(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<Option<StoredCompositeAuthorization>, BudgetStoreError> {
    type StoredRow = (
        String,
        String,
        String,
        usize,
        u64,
        Option<u64>,
        Option<u64>,
        Option<BudgetEventAuthority>,
        bool,
        String,
        String,
        String,
        String,
        u64,
        u32,
        u64,
    );
    let row: Option<StoredRow> = transaction
        .query_row(
            r#"
            SELECT hold_id, event_id, capability_id, grant_index,
                   requested_exposure_units, max_cost_per_invocation,
                   max_total_cost_units, authority_id, lease_id, lease_epoch,
                   allowed, invocation_state, monetary_state,
                   revocation_set_digest, revocation_ids_json,
                   committed_cost_units_after, invocation_count_after, event_seq
            FROM budget_composite_authorizations
            WHERE hold_id = ?1
            "#,
            params![hold_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    budget_usize_from_row(row, 3, "composite grant_index")?,
                    budget_u64_from_row(row, 4, "composite requested_exposure_units")?,
                    optional_budget_u64_from_row(row, 5, "composite max_cost_per_invocation")?,
                    optional_budget_u64_from_row(row, 6, "composite max_total_cost_units")?,
                    sqlite_budget_event_authority(row.get(7)?, row.get(8)?, row.get(9)?)?,
                    row.get::<_, i64>(10)? != 0,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    budget_u64_from_row(row, 15, "composite committed_cost_units_after")?,
                    budget_u32_from_row(row, 16, "composite invocation_count_after")?,
                    budget_u64_from_row(row, 17, "composite event_seq")?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let invocation_state = BudgetInvocationReservationState::parse(&row.9).ok_or_else(|| {
        BudgetStoreError::Invariant(format!("unknown persisted invocation state `{}`", row.9))
    })?;
    let monetary_state = BudgetMonetaryHoldState::parse(&row.10).ok_or_else(|| {
        BudgetStoreError::Invariant(format!("unknown persisted monetary state `{}`", row.10))
    })?;
    let ids = serde_json::from_str::<Vec<String>>(&row.12).map_err(|error| {
        BudgetStoreError::Invariant(format!(
            "invalid persisted canonical revocation members: {error}"
        ))
    })?;
    let revocation_set =
        CanonicalRevocationSet::from_persisted_parts(ids, row.11).map_err(|error| {
            BudgetStoreError::Invariant(format!(
                "invalid persisted canonical revocation set: {error}"
            ))
        })?;
    let invocation_counts_after = load_authorization_quota_snapshots(transaction, hold_id)?;
    let authorization_artifact_digests = load_authorization_artifact_digests(transaction, hold_id)?;
    Ok(Some(StoredCompositeAuthorization {
        hold_id: row.0,
        event_id: row.1,
        capability_id: row.2,
        grant_index: row.3,
        requested_exposure_units: row.4,
        max_cost_per_invocation: row.5,
        max_total_cost_units: row.6,
        authority: row.7,
        allowed: row.8,
        invocation_state,
        monetary_state,
        revocation_set,
        committed_cost_units_after: row.13,
        invocation_count_after: row.14,
        event_seq: row.15,
        invocation_counts_after,
        authorization_artifact_digests,
    }))
}

fn load_authorization_artifact_digests(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<Vec<String>, BudgetStoreError> {
    let mut statement = transaction.prepare(
        r#"
        SELECT position, artifact_digest
        FROM budget_composite_authorization_artifacts
        WHERE hold_id = ?1
        ORDER BY position ASC
        "#,
    )?;
    let rows = statement
        .query_map(params![hold_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if rows.len() > MAX_AUTHORIZATION_ARTIFACT_DIGESTS_PER_ADMISSION {
        return Err(BudgetStoreError::Invariant(
            "persisted authorization artifact count exceeds the limit".to_string(),
        ));
    }
    let mut digests = Vec::with_capacity(rows.len());
    for (expected_position, (position, digest)) in rows.into_iter().enumerate() {
        if position != expected_position as i64
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(BudgetStoreError::Invariant(
                "persisted authorization artifacts are malformed".to_string(),
            ));
        }
        digests.push(digest);
    }
    if digests.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(BudgetStoreError::Invariant(
            "persisted authorization artifact digests are unsorted or duplicated".to_string(),
        ));
    }
    Ok(digests)
}

fn load_authorization_quota_snapshots(
    transaction: &rusqlite::Transaction<'_>,
    hold_id: &str,
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    type QuotaRow = (i64, String, String, i64, u32, u32, u32);
    let mut statement = transaction.prepare(
        r#"
        SELECT position, profile, owner_id, grant_index_key, max_invocations,
               reserved_invocations_after, captured_invocations_after
        FROM budget_composite_authorization_quotas
        WHERE hold_id = ?1
        ORDER BY position ASC
        "#,
    )?;
    let rows = statement
        .query_map(params![hold_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                budget_u32_from_row(row, 4, "snapshot max_invocations")?,
                budget_u32_from_row(row, 5, "snapshot reserved_invocations_after")?,
                budget_u32_from_row(row, 6, "snapshot captured_invocations_after")?,
            ))
        })?
        .collect::<Result<Vec<QuotaRow>, _>>()?;
    drop(statement);
    if rows.is_empty() || rows.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
        return Err(BudgetStoreError::Invariant(
            "persisted composite authorization has an invalid quota count".to_string(),
        ));
    }
    rows.into_iter()
        .enumerate()
        .map(
            |(
                expected_position,
                (position, profile, owner_id, grant_index_key, maximum, reserved, captured),
            )| {
                if position != expected_position as i64 {
                    return Err(BudgetStoreError::Invariant(
                        "persisted composite quota positions are not contiguous".to_string(),
                    ));
                }
                let profile = BudgetQuotaProfile::parse(&profile).ok_or_else(|| {
                    BudgetStoreError::Invariant("unknown persisted quota profile".to_string())
                })?;
                let grant_index = if grant_index_key == -1 {
                    None
                } else {
                    Some(u32::try_from(grant_index_key).map_err(|_| {
                        BudgetStoreError::Invariant(
                            "persisted quota grant index is out of range".to_string(),
                        )
                    })?)
                };
                let key = BudgetQuotaKey::from_persisted_parts(profile, owner_id, grant_index)?;
                let quota = BudgetInvocationQuota::from_persisted_parts(key, maximum)?;
                let usage = BudgetInvocationQuotaUsage {
                    quota,
                    reserved_invocations_after: reserved,
                    captured_invocations_after: captured,
                };
                usage.validate()?;
                Ok(usage)
            },
        )
        .collect()
}

fn load_mutation_quota_snapshots(
    transaction: &rusqlite::Transaction<'_>,
    event_id: &str,
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    type QuotaRow = (i64, String, String, i64, u32, u32, u32);
    let mut statement = transaction.prepare(
        r#"
        SELECT position, profile, owner_id, grant_index_key, max_invocations,
               reserved_invocations_after, captured_invocations_after
        FROM budget_composite_mutation_quota_snapshots
        WHERE event_id = ?1
        ORDER BY position ASC
        "#,
    )?;
    let rows = statement
        .query_map(params![event_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                budget_u32_from_row(row, 4, "snapshot max_invocations")?,
                budget_u32_from_row(row, 5, "snapshot reserved_invocations_after")?,
                budget_u32_from_row(row, 6, "snapshot captured_invocations_after")?,
            ))
        })?
        .collect::<Result<Vec<QuotaRow>, _>>()?;
    drop(statement);
    hydrate_quota_snapshot_rows(rows)
}

fn hydrate_quota_snapshot_rows(
    rows: Vec<(i64, String, String, i64, u32, u32, u32)>,
) -> Result<Vec<BudgetInvocationQuotaUsage>, BudgetStoreError> {
    if rows.is_empty() || rows.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION {
        return Err(BudgetStoreError::Invariant(
            "persisted composite mutation has an invalid quota count".to_string(),
        ));
    }
    rows.into_iter()
        .enumerate()
        .map(
            |(
                expected_position,
                (position, profile, owner_id, grant_index_key, maximum, reserved, captured),
            )| {
                if position != expected_position as i64 {
                    return Err(BudgetStoreError::Invariant(
                        "persisted composite quota positions are not contiguous".to_string(),
                    ));
                }
                let profile = BudgetQuotaProfile::parse(&profile).ok_or_else(|| {
                    BudgetStoreError::Invariant("unknown persisted quota profile".to_string())
                })?;
                let grant_index = if grant_index_key == -1 {
                    None
                } else {
                    Some(u32::try_from(grant_index_key).map_err(|_| {
                        BudgetStoreError::Invariant(
                            "persisted quota grant index is out of range".to_string(),
                        )
                    })?)
                };
                let key = BudgetQuotaKey::from_persisted_parts(profile, owner_id, grant_index)?;
                let quota = BudgetInvocationQuota::from_persisted_parts(key, maximum)?;
                let usage = BudgetInvocationQuotaUsage {
                    quota,
                    reserved_invocations_after: reserved,
                    captured_invocations_after: captured,
                };
                usage.validate()?;
                Ok(usage)
            },
        )
        .collect()
}

fn composite_metadata(
    authority: Option<BudgetEventAuthority>,
    budget_commit_index: Option<u64>,
    event_id: String,
) -> BudgetCommitMetadata {
    BudgetCommitMetadata {
        authority,
        guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
        budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
        metering_profile: BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
        budget_commit_index,
        event_id: Some(event_id),
    }
}
