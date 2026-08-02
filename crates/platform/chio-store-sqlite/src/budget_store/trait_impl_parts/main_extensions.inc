macro_rules! sqlite_budget_store_main_extensions {
    () => {
fn list_open_holds_older_than(
    &self,
    older_than_unix_ms: u64,
    limit: usize,
) -> Result<Vec<chio_kernel::budget_store::OpenHoldSummary>, BudgetStoreError> {
    let cutoff_secs = (older_than_unix_ms / 1_000).min(i64::MAX as u64) as i64;
    let connection = self.connection()?;
    let mut statement = connection.prepare(
        "SELECT hold_id, capability_id, grant_index, remaining_exposure_units, created_at \
         FROM budget_authorization_holds \
         WHERE disposition = 'open' AND created_at <= ?1 \
         ORDER BY created_at ASC LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![cutoff_secs, limit.min(i64::MAX as usize) as i64],
        |row| {
            Ok(chio_kernel::budget_store::OpenHoldSummary {
                hold_id: row.get(0)?,
                capability_id: row.get(1)?,
                grant_index: row.get::<_, i64>(2)?.clamp(0, i64::from(u32::MAX)) as u32,
                remaining_exposure_units: row.get::<_, i64>(3)?.max(0) as u64,
                created_at_unix_ms: (row.get::<_, i64>(4)?.max(0) as u64).saturating_mul(1_000),
            })
        },
    )?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn expire_open_hold(&self, hold_id: &str) -> Result<bool, BudgetStoreError> {
    let mut connection = self.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, i64, i64, bool)> = transaction
        .query_row(
            "SELECT capability_id, grant_index, remaining_exposure_units, \
                    invocation_count_debited \
             FROM budget_authorization_holds WHERE hold_id = ?1 AND disposition = 'open'",
            params![hold_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((capability_id, grant_index, remaining, invocation_count_debited)) = row else {
        return Ok(false);
    };
    let grant_index = usize::try_from(grant_index).map_err(|_| {
        BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` has an invalid grant index"
        ))
    })?;
    let remaining = u64::try_from(remaining).map_err(|_| {
        BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` has negative remaining exposure"
        ))
    })?;
    let current = transaction
        .query_row(
            r#"
            SELECT invocation_count, total_cost_exposed,
                   total_cost_realized_spend, seq
            FROM capability_grant_budgets
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![capability_id, grant_index as i64],
            |row| {
                Ok(SqliteLegacyProjectionState {
                    invocation_count: budget_u32_from_row(row, 0, "invocation_count")?,
                    total_cost_exposed: budget_u64_from_row(row, 1, "total_cost_exposed")?,
                    total_cost_realized_spend: budget_u64_from_row(
                        row,
                        2,
                        "total_cost_realized_spend",
                    )?,
                    seq: budget_u64_from_row(row, 3, "legacy projection sequence")?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` lost its legacy projection"
            ))
        })?;
    let exposed_after = current
        .total_cost_exposed
        .checked_sub(remaining)
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` exceeds its legacy exposure"
            ))
        })?;
    let now = unix_now();
    let event_seq = allocate_budget_replication_seq(&transaction)?;
    let invocation_count_after = if invocation_count_debited {
        if current.invocation_count == 0 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` lost its invocation debit"
            )));
        }
        let maximum = SqliteBudgetStore::compatibility_invocation_quota_maximum(
            &transaction,
            &capability_id,
            grant_index,
        )?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` lost its invocation quota"
            ))
        })?;
        let quota = BudgetInvocationQuota::from_persisted_parts(
            BudgetQuotaKey::grant(&capability_id, grant_index)?,
            maximum,
        )?;
        SqliteBudgetStore::compare_and_mutate_invocation_quotas(
            &transaction,
            std::slice::from_ref(&quota),
            quota.key(),
            current.invocation_count,
            SqliteInvocationQuotaMutationContext {
                mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                action: SqliteInvocationQuotaMutationAction::Replay,
                event_seq: current.seq,
                updated_at: now,
            },
        )?;
        SqliteBudgetStore::compare_and_mutate_invocation_quotas(
            &transaction,
            std::slice::from_ref(&quota),
            quota.key(),
            current.invocation_count,
            SqliteInvocationQuotaMutationContext {
                mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                action: SqliteInvocationQuotaMutationAction::Reverse,
                event_seq,
                updated_at: now,
            },
        )?
        .primary_count_after
    } else {
        current.invocation_count
    };
    SqliteBudgetStore::compare_and_persist_legacy_projection(
        &transaction,
        SqliteLegacyProjectionMutation {
            capability_id: &capability_id,
            grant_index,
            expected: Some(current),
            after: SqliteLegacyProjectionState {
                invocation_count: invocation_count_after,
                total_cost_exposed: exposed_after,
                total_cost_realized_spend: current.total_cost_realized_spend,
                seq: event_seq,
            },
            updated_at: now,
        },
    )?;
    let hold_changed = transaction.execute(
        "UPDATE budget_authorization_holds \
         SET disposition = 'expired', remaining_exposure_units = 0, updated_at = ?1 \
         WHERE hold_id = ?2 AND disposition = 'open'",
        params![now, hold_id],
    )?;
    if hold_changed != 1 {
        return Err(BudgetStoreError::Invariant(format!(
            "budget hold `{hold_id}` changed during expiry"
        )));
    }
    SqliteBudgetStore::append_mutation_event(
        &transaction,
        Some(&format!("{hold_id}:expire")),
        Some(hold_id),
        None,
        &capability_id,
        grant_index.max(0) as usize,
        BudgetMutationKind::ExpireHold,
        Some(true),
        event_seq,
        Some(event_seq),
        remaining,
        0,
        None,
        None,
        None,
        invocation_count_after,
        exposed_after,
        current.total_cost_realized_spend,
    )?;
    transaction.commit()?;
    Ok(true)
}

fn recover_unstamped_caller_reservations(&self) -> Result<usize, BudgetStoreError> {
    SqliteBudgetStore::recover_unstamped_caller_reservations(self)
}

fn open_hold_count(&self) -> Result<u64, BudgetStoreError> {
    let connection = self.connection()?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM budget_authorization_holds WHERE disposition = 'open'",
        [],
        |row| row.get(0),
    )?;
    Ok(count.max(0) as u64)
}

fn record_payment_journal(
    &self,
    entry: &chio_kernel::payment::PaymentJournalRecord,
) -> Result<(), BudgetStoreError> {
    let mut connection = self.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    insert_payment_journal_tx(&transaction, entry, false)?;
    transaction.commit()?;
    Ok(())
}

fn advance_payment_journal(
    &self,
    request_id: &str,
    expected: chio_kernel::payment::PaymentJournalState,
    next: chio_kernel::payment::PaymentJournalState,
    authorization_id: Option<&str>,
    transaction_id: Option<&str>,
    settle: Option<chio_kernel::payment::PaymentSettleIntent>,
) -> Result<(), BudgetStoreError> {
    use chio_kernel::payment::PaymentJournalState as State;
    if next == State::Settling && settle.is_none() {
        return Err(BudgetStoreError::Invariant(
            "advance to Settling requires a settle intent".to_string(),
        ));
    }
    if next != State::Settling && settle.is_some() {
        return Err(BudgetStoreError::Invariant(
            "settle intent is only valid on the Settling transition".to_string(),
        ));
    }
    if let Some(intent) = settle {
        match intent.action {
            chio_kernel::payment::PaymentSettleAction::Capture
            | chio_kernel::payment::PaymentSettleAction::Refund
                if intent.amount_units.is_none() =>
            {
                return Err(BudgetStoreError::Invariant(
                    "capture and refund settle intents require an exact amount".to_string(),
                ));
            }
            chio_kernel::payment::PaymentSettleAction::Release
                if intent.amount_units.is_some() =>
            {
                return Err(BudgetStoreError::Invariant(
                    "release settle intent cannot carry an amount".to_string(),
                ));
            }
            chio_kernel::payment::PaymentSettleAction::Refund if transaction_id.is_none() => {
                return Err(BudgetStoreError::Invariant(
                    "refund settle intent requires the captured transaction id".to_string(),
                ));
            }
            _ => {}
        }
    }
    let (settle_action, settle_amount) = match settle {
        Some(intent) => (
            Some(settle_action_str(intent.action)),
            optional_payment_journal_u64_to_sqlite(
                intent.amount_units,
                "payment settle_amount_units",
            )?,
        ),
        None => (None, None),
    };
    let mut connection = self.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = transaction.execute(
        "UPDATE payment_journal SET state = ?1, \
           authorization_id = COALESCE(?2, authorization_id), \
           transaction_id = CASE \
               WHEN ?1 = 'settling' AND ?4 = 'release' THEN NULL \
               ELSE COALESCE(?3, transaction_id) END, \
           settle_action = CASE WHEN ?1 = 'settling' THEN ?4 ELSE settle_action END, \
           settle_amount_units = CASE WHEN ?1 = 'settling' THEN ?5 ELSE settle_amount_units END, \
           updated_at = ?6 \
         WHERE request_id = ?7 AND state = ?8",
        params![
            journal_state_str(next), authorization_id, transaction_id, settle_action,
            settle_amount, journal_now_unix_ms(), request_id, journal_state_str(expected)
        ],
    )?;
    if changed == 0 {
        transaction.rollback()?;
        return Err(BudgetStoreError::Invariant(format!(
            "payment journal advance conflict for `{request_id}`"
        )));
    }
    transaction.commit()?;
    Ok(())
}

fn close_payment_journal(&self, request_id: &str) -> Result<bool, BudgetStoreError> {
    let mut connection = self.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = transaction.execute(
        "UPDATE payment_journal SET state = 'closed', updated_at = ?1 \
         WHERE request_id = ?2 AND state NOT IN ('closed', 'reconcile_failed')",
        params![journal_now_unix_ms(), request_id],
    )?;
    transaction.commit()?;
    Ok(changed > 0)
}

fn list_incomplete_payment_journal(
    &self,
    older_than_unix_ms: u64,
) -> Result<Vec<chio_kernel::payment::PaymentJournalRecord>, BudgetStoreError> {
    let connection = self.connection()?;
    let mut statement = connection.prepare(
        "SELECT request_id, capability_id, grant_index, operation_id, request_binding_hash, \
                authority_id, lease_id, lease_epoch, hold_id, rail, authorization_id, \
                transaction_id, budget_exposure_units, amount_units, settle_action, \
                settle_amount_units, currency, \
                state, created_at, tenant_id FROM payment_journal \
         WHERE state NOT IN ('closed', 'reconcile_failed') AND created_at <= ?1 \
         ORDER BY created_at ASC",
    )?;
    let cutoff = older_than_unix_ms.min(i64::MAX as u64) as i64;
    let rows = statement.query_map(params![cutoff], payment_journal_row)?;
    rows.map(|row| payment_journal_row_to_record(row?)).collect()
}

fn get_payment_journal(
    &self,
    request_id: &str,
) -> Result<Option<chio_kernel::payment::PaymentJournalRecord>, BudgetStoreError> {
    let connection = self.connection()?;
    let row = connection
        .query_row(
            "SELECT request_id, capability_id, grant_index, operation_id, request_binding_hash, \
                    authority_id, lease_id, lease_epoch, hold_id, rail, authorization_id, \
                    transaction_id, budget_exposure_units, amount_units, settle_action, \
                    settle_amount_units, currency, \
                    state, created_at, tenant_id FROM payment_journal \
             WHERE request_id = ?1 AND state NOT IN ('closed', 'reconcile_failed')",
            params![request_id],
            payment_journal_row,
        )
        .optional()?;
    row.map(payment_journal_row_to_record).transpose()
}

fn get_payment_journal_for_audit(
    &self,
    request_id: &str,
) -> Result<Option<chio_kernel::payment::PaymentJournalRecord>, BudgetStoreError> {
    let connection = self.connection()?;
    let row = connection
        .query_row(
            "SELECT request_id, capability_id, grant_index, operation_id, request_binding_hash, \
                    authority_id, lease_id, lease_epoch, hold_id, rail, authorization_id, \
                    transaction_id, budget_exposure_units, amount_units, settle_action, \
                    settle_amount_units, currency, \
                    state, created_at, tenant_id FROM payment_journal \
             WHERE request_id = ?1",
            params![request_id],
            payment_journal_row,
        )
        .optional()?;
    row.map(payment_journal_row_to_record).transpose()
}

fn payment_journal_reconcile_failed_rail(
    &self,
    request_id: &str,
) -> Result<Option<String>, BudgetStoreError> {
    self.connection()?
        .query_row(
            "SELECT rail FROM payment_journal WHERE request_id = ?1 AND state = 'reconcile_failed'",
            params![request_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
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

fn get_budget_hold(&self, hold_id: &str) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
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

fn mark_invocation_hold_reserved(
    &self,
    hold_id: &str,
    capability_id: &str,
    grant_index: usize,
    reserved_until_unix_secs: i64,
    envelope: &ReservedHoldEnvelope,
) -> Result<(), BudgetStoreError> {
    self.mark_invocation_hold_reserved_until(
        hold_id,
        capability_id,
        grant_index,
        reserved_until_unix_secs,
        envelope,
    )
}

fn mark_admission_operation_hold_reserved(
    &self,
    hold_id: &str,
    admission_operation: &BudgetAdmissionOperationBinding,
    reserved_until_unix_secs: i64,
    currency: Option<&str>,
    payment_reference: Option<&str>,
    envelope: &ReservedHoldEnvelope,
) -> Result<(), BudgetStoreError> {
    self.mark_admission_operation_hold_reserved_until(
        hold_id,
        admission_operation,
        reserved_until_unix_secs,
        currency,
        payment_reference,
        envelope,
    )
}

fn reserve_invocation_hold(
    &self,
    hold_id: &str,
    capability_id: &str,
    grant_index: usize,
    reserved_until_unix_secs: i64,
    envelope: &ReservedHoldEnvelope,
) -> Result<(), BudgetStoreError> {
    SqliteBudgetStore::reserve_invocation_hold(
        self,
        hold_id,
        capability_id,
        grant_index,
        reserved_until_unix_secs,
        envelope,
    )
}

fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
    SqliteBudgetStore::reap_expired_reserved_holds(self, now_unix_secs)
}
    };
}
