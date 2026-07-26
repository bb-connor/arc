use super::store::{
    SqliteInvocationQuotaMutationAction, SqliteInvocationQuotaMutationContext,
    SqliteInvocationQuotaMutationMode, SqliteLegacyProjectionMutation, SqliteLegacyProjectionState,
};
use super::*;

use std::collections::HashMap;

use chio_kernel::budget_store::{
    BudgetReconcileHoldRequest, BudgetReverseHoldRequest,
    CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX,
    CALLER_NO_PAYMENT_RESERVATION_RECOVERY_EVENT_SUFFIX,
};

fn admission_operation_binding(
    operation_id: Option<String>,
    request_binding_hash: Option<String>,
) -> Result<Option<BudgetAdmissionOperationBinding>, BudgetStoreError> {
    match (operation_id, request_binding_hash) {
        (None, None) => Ok(None),
        (Some(operation_id), Some(request_binding_hash)) => {
            BudgetAdmissionOperationBinding::new(operation_id, request_binding_hash).map(Some)
        }
        _ => Err(BudgetStoreError::Invariant(
            "budget hold has an incomplete admission operation binding".to_string(),
        )),
    }
}

/// Outcome of a startup reap pass over orphaned open holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapSummary {
    pub reconciled: usize,
    pub reversed: usize,
}

/// An open reserved hold past its TTL deadline.
struct ExpiredReservedHold {
    hold_id: String,
    capability_id: String,
    grant_index: u32,
    remaining_exposure_units: u64,
    authority: Option<BudgetEventAuthority>,
    admission_operation: Option<BudgetAdmissionOperationBinding>,
    composite: bool,
}

/// A hold still `open` at startup:
/// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority,
/// admission_operation)`.
type OpenHold = (
    String,
    String,
    u32,
    u64,
    Option<BudgetEventAuthority>,
    Option<BudgetAdmissionOperationBinding>,
);

impl SqliteBudgetStore {
    /// Reverse legacy no-payment caller reservations interrupted after their
    /// authorization transaction but before the nonce TTL stamp. The
    /// authorization event is the durable intent marker, so any rail-moving
    /// path, ordinary dispatch hold, or operation-owned composite hold is outside
    /// this recovery lane.
    pub fn recover_unstamped_caller_reservations(&self) -> Result<usize, BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidates = {
            let mut statement = transaction.prepare(
                "SELECT base.hold_id, base.capability_id, base.grant_index, \
                        base.remaining_exposure_units, base.invocation_count_debited, \
                        base.authority_id, base.lease_id, base.lease_epoch, event.event_seq \
                 FROM budget_authorization_holds AS base \
                 JOIN budget_mutation_events AS event \
                   ON event.hold_id = base.hold_id \
                  AND event.capability_id = base.capability_id \
                  AND event.grant_index = base.grant_index \
                  AND event.event_id = base.hold_id || ?1 \
                 WHERE base.disposition = 'open' AND base.reserved_until IS NULL \
                   AND base.operation_id IS NULL AND base.request_binding_hash IS NULL \
                   AND base.remaining_exposure_units = base.authorized_exposure_units \
                   AND base.invocation_count_debited = 1 \
                   AND NOT EXISTS (SELECT 1 FROM budget_composite_holds AS composite \
                                   WHERE composite.hold_id = base.hold_id) \
                   AND event.kind = ?2 AND event.allowed = 1 \
                   AND event.exposure_units = base.authorized_exposure_units \
                   AND event.realized_spend_units = 0 \
                   AND event.authority_id IS base.authority_id \
                   AND event.lease_id IS base.lease_id \
                   AND event.lease_epoch IS base.lease_epoch \
                 ORDER BY base.created_at ASC, base.hold_id ASC",
            )?;
            let rows = statement.query_map(
                params![
                    CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX,
                    BudgetMutationKind::AuthorizeExposure.as_str(),
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        budget_usize_from_row(row, 2, "caller reservation grant index")?,
                        budget_u64_from_row(row, 3, "caller reservation exposure")?,
                        row.get::<_, bool>(4)?,
                        sqlite_budget_event_authority(row.get(5)?, row.get(6)?, row.get(7)?)?,
                        budget_u64_from_row(row, 8, "caller reservation authorization sequence")?,
                    ))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };

        for (
            hold_id,
            capability_id,
            grant_index,
            remaining,
            invocation_count_debited,
            authority,
            authorize_event_seq,
        ) in &candidates
        {
            let grant_index_sql = i64::try_from(*grant_index).map_err(|_| {
                BudgetStoreError::Overflow(
                    "caller reservation recovery grant index exceeds SQLite INTEGER".to_string(),
                )
            })?;
            let current: Option<(u32, u64, u64, u64)> = transaction
                .query_row(
                    "SELECT invocation_count, total_cost_exposed, total_cost_realized_spend, seq \
                     FROM capability_grant_budgets \
                     WHERE capability_id = ?1 AND grant_index = ?2",
                    params![capability_id, grant_index_sql],
                    |row| {
                        Ok((
                            budget_u32_from_row(row, 0, "invocation_count")?,
                            budget_u64_from_row(row, 1, "total_cost_exposed")?,
                            budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                            budget_u64_from_row(row, 3, "legacy projection sequence")?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                invocation_count,
                total_cost_exposed,
                total_cost_realized_spend,
                projection_seq,
            )) = current
            else {
                return Err(BudgetStoreError::Invariant(format!(
                    "caller reservation hold `{hold_id}` lost its grant usage during recovery"
                )));
            };
            if *invocation_count_debited && invocation_count == 0 {
                return Err(BudgetStoreError::Invariant(format!(
                    "caller reservation hold `{hold_id}` lost its invocation debit during recovery"
                )));
            }
            let total_cost_exposed_after =
                total_cost_exposed.checked_sub(*remaining).ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "caller reservation hold `{hold_id}` exceeds its grant exposure during recovery"
                    ))
                })?;
            let compatibility_maximum = if *invocation_count_debited {
                Some(
                    SqliteBudgetStore::compatibility_invocation_quota_maximum(
                        &transaction,
                        capability_id,
                        *grant_index,
                    )?
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(format!(
                            "caller reservation hold `{hold_id}` lost its invocation quota during recovery"
                        ))
                    })?,
                )
            } else {
                None
            };
            let event_seq = allocate_budget_replication_seq(&transaction)?;
            let now = unix_now();
            let invocation_count_after = if let Some(maximum) = compatibility_maximum {
                let compatibility_quota = BudgetInvocationQuota::from_persisted_parts(
                    BudgetQuotaKey::grant(capability_id, *grant_index)?,
                    maximum,
                )?;
                SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                    &transaction,
                    std::slice::from_ref(&compatibility_quota),
                    compatibility_quota.key(),
                    invocation_count,
                    SqliteInvocationQuotaMutationContext {
                        mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                        action: SqliteInvocationQuotaMutationAction::Replay,
                        event_seq: projection_seq,
                        updated_at: now,
                    },
                )?;
                SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                    &transaction,
                    std::slice::from_ref(&compatibility_quota),
                    compatibility_quota.key(),
                    invocation_count,
                    SqliteInvocationQuotaMutationContext {
                        mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                        action: SqliteInvocationQuotaMutationAction::Reverse,
                        event_seq,
                        updated_at: now,
                    },
                )?
                .primary_count_after
            } else {
                invocation_count
            };
            SqliteBudgetStore::compare_and_persist_legacy_projection(
                &transaction,
                SqliteLegacyProjectionMutation {
                    capability_id,
                    grant_index: *grant_index,
                    expected: Some(SqliteLegacyProjectionState {
                        invocation_count,
                        total_cost_exposed,
                        total_cost_realized_spend,
                        seq: projection_seq,
                    }),
                    after: SqliteLegacyProjectionState {
                        invocation_count: invocation_count_after,
                        total_cost_exposed: total_cost_exposed_after,
                        total_cost_realized_spend,
                        seq: event_seq,
                    },
                    updated_at: now,
                },
            )?;
            let hold_changed = transaction.execute(
                "UPDATE budget_authorization_holds \
                 SET disposition = 'reversed', remaining_exposure_units = 0, updated_at = ?1 \
                 WHERE hold_id = ?2 AND disposition = 'open' AND reserved_until IS NULL \
                   AND operation_id IS NULL AND request_binding_hash IS NULL \
                   AND remaining_exposure_units = authorized_exposure_units \
                   AND invocation_count_debited = 1 \
                   AND NOT EXISTS (SELECT 1 FROM budget_composite_holds AS composite \
                                   WHERE composite.hold_id = budget_authorization_holds.hold_id)",
                params![now, hold_id],
            )?;
            if hold_changed != 1 {
                return Err(BudgetStoreError::Conflict(format!(
                    "caller reservation hold `{hold_id}` changed during startup recovery"
                )));
            }
            let recovery_event_id = format!(
                "{hold_id}{CALLER_NO_PAYMENT_RESERVATION_RECOVERY_EVENT_SUFFIX}{authorize_event_seq}"
            );
            SqliteBudgetStore::append_mutation_event(
                &transaction,
                Some(&recovery_event_id),
                Some(hold_id),
                authority.as_ref(),
                capability_id,
                *grant_index,
                BudgetMutationKind::ReverseExposure,
                None,
                event_seq,
                Some(event_seq),
                *remaining,
                0,
                None,
                None,
                None,
                invocation_count_after,
                total_cost_exposed_after,
                total_cost_realized_spend,
            )?;
        }
        transaction.commit()?;
        Ok(candidates.len())
    }

    /// Reconcile or reverse every hold still `open` at startup. Holds present in
    /// `realized_by_hold` (arbitrated by the ADR-0013 durable receipt log) are
    /// reconciled to their realized spend; holds absent from it (never durably
    /// admitted) are reversed. This is fail-closed against double-spend: a naive
    /// blanket release is never used.
    ///
    /// Called by the `BudgetStore` trait implementation of `reap_orphaned_holds`.
    pub fn reap_holds_by_map(
        &self,
        realized_by_hold: &HashMap<String, u64>,
    ) -> Result<ReapSummary, BudgetStoreError> {
        let open_holds = self.list_open_holds()?;
        let mut summary = ReapSummary {
            reconciled: 0,
            reversed: 0,
        };
        for (hold_id, capability_id, grant_index, exposure, authority, admission_operation) in
            open_holds
        {
            // Kernel-authored holds carry a BudgetEventAuthority lease that the
            // reconcile/reverse authority check enforces. Present each hold's stored
            // authority so orphaned kernel holds are reclaimed rather than rejected;
            // a hold whose authority columns cannot be loaded fails closed in
            // `list_open_holds` rather than silently reaping with no authority.
            match realized_by_hold.get(&hold_id) {
                Some(&realized) => {
                    self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        exposed_cost_units: exposure,
                        realized_spend_units: realized.min(exposure),
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reconcile")),
                        authority,
                        admission_operation,
                    })?;
                    summary.reconciled += 1;
                }
                None => {
                    self.reverse_budget_hold(BudgetReverseHoldRequest {
                        capability_id: capability_id.clone(),
                        grant_index: grant_index as usize,
                        reversed_exposure_units: exposure,
                        hold_id: Some(hold_id.clone()),
                        event_id: Some(format!("{hold_id}:reap-reverse")),
                        authority,
                        admission_operation,
                    })?;
                    summary.reversed += 1;
                }
            }
        }
        Ok(summary)
    }

    /// Settle every reserved hold that is still `open` and whose `reserved_until`
    /// deadline is at or before `now_unix_secs` at its reserved worst-case,
    /// forfeiting the reserved amount to realized spend. In the two-phase
    /// reserve/reconcile flow the only evidence a spend occurred is the caller's
    /// reconcile; an expired-and-unreconciled hold may correspond to a call that
    /// executed and spent, so releasing it (realized 0) would under-count real
    /// spend and fail open for a cumulative cap. The abandoning caller instead
    /// forfeits the worst-case (must reconcile before expiry to reclaim the
    /// difference). Fail-closed: only holds explicitly marked reserved (a non-NULL
    /// `reserved_until`) and past expiry are touched; a not-yet-expired reserved
    /// hold and any non-open hold are left alone. Idempotent (a settled hold is no
    /// longer open). Returns the number of holds settled.
    pub fn reap_expired_reserved_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<usize, BudgetStoreError> {
        let expired = self.list_expired_reserved_holds(now_unix_secs)?;
        let mut settled = 0usize;
        for hold in expired {
            if hold.composite {
                self.reap_expired_composite_hold(&hold, now_unix_secs)?;
            } else {
                self.reconcile_budget_hold(BudgetReconcileHoldRequest {
                    capability_id: hold.capability_id,
                    grant_index: hold.grant_index as usize,
                    exposed_cost_units: hold.remaining_exposure_units,
                    realized_spend_units: hold.remaining_exposure_units,
                    hold_id: Some(hold.hold_id.clone()),
                    event_id: Some(format!("{}:ttl-reap-settle", hold.hold_id)),
                    authority: hold.authority,
                    admission_operation: hold.admission_operation.clone(),
                })?;
                self.mark_hold_expired_after_worst_case(
                    &hold.hold_id,
                    now_unix_secs,
                    hold.admission_operation.as_ref(),
                    false,
                    false,
                )?;
            }
            settled += 1;
        }
        Ok(settled)
    }

    /// Settle a captured operation-owned reservation at worst-case and project
    /// its terminal `expired` disposition in one SQLite transaction. The kernel
    /// terminalizes `CallerReserved` only after observing `Expired`, so committing
    /// a merely `Reconciled` intermediate state would strand the operation after a
    /// process crash and prevent any later TTL pass from selecting the closed hold.
    fn reap_expired_composite_hold(
        &self,
        hold: &ExpiredReservedHold,
        now_unix_secs: i64,
    ) -> Result<(), BudgetStoreError> {
        let admission_operation = hold.admission_operation.as_ref().ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget hold `{}` omits admission ownership",
                hold.hold_id
            ))
        })?;
        let zero_exposure = hold.remaining_exposure_units == 0;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !zero_exposure {
            Self::settle_composite_budget_hold_in_transaction(
                &transaction,
                BudgetReconcileHoldRequest {
                    capability_id: hold.capability_id.clone(),
                    grant_index: hold.grant_index as usize,
                    exposed_cost_units: hold.remaining_exposure_units,
                    realized_spend_units: hold.remaining_exposure_units,
                    hold_id: Some(hold.hold_id.clone()),
                    event_id: Some(format!("{}:ttl-reap-settle", hold.hold_id)),
                    authority: hold.authority.clone(),
                    admission_operation: Some(admission_operation.clone()),
                },
                false,
            )?;
        }
        Self::mark_hold_expired_after_worst_case_in_transaction(
            &transaction,
            &hold.hold_id,
            now_unix_secs,
            Some(admission_operation),
            true,
            zero_exposure,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Open reserved holds past their expiry:
    /// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority,
    /// admission_operation)`.
    fn list_expired_reserved_holds(
        &self,
        now_unix_secs: i64,
    ) -> Result<Vec<ExpiredReservedHold>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT base.hold_id, base.capability_id, base.grant_index, \
                    base.remaining_exposure_units, base.authority_id, base.lease_id, \
                    base.lease_epoch, base.operation_id, base.request_binding_hash, \
                    CASE WHEN composite.hold_id IS NULL THEN 0 ELSE 1 END \
             FROM budget_authorization_holds AS base \
             LEFT JOIN budget_composite_holds AS composite ON composite.hold_id = base.hold_id \
             WHERE base.disposition = 'open' AND base.reserved_until IS NOT NULL \
               AND base.reserved_until <= ?1 \
               AND (composite.hold_id IS NULL OR composite.invocation_state = 'captured')",
        )?;
        let rows = statement.query_map([now_unix_secs], |row| {
            let authority = sqlite_budget_event_authority(row.get(4)?, row.get(5)?, row.get(6)?)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                budget_u32_from_row(row, 2, "grant_index")?,
                budget_u64_from_row(row, 3, "remaining_exposure_units")?,
                authority,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)? != 0,
            ))
        })?;
        let mut holds = Vec::new();
        for row in rows {
            let row = row?;
            let admission_operation = admission_operation_binding(row.5, row.6)?;
            if row.7 && admission_operation.is_none() {
                return Err(BudgetStoreError::Invariant(format!(
                    "composite budget hold `{}` omits admission ownership",
                    row.0
                )));
            }
            holds.push(ExpiredReservedHold {
                hold_id: row.0,
                capability_id: row.1,
                grant_index: row.2,
                remaining_exposure_units: row.3,
                authority: row.4,
                admission_operation,
                composite: row.7,
            });
        }
        Ok(holds)
    }

    fn mark_hold_expired_after_worst_case(
        &self,
        hold_id: &str,
        now_unix_secs: i64,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        composite: bool,
        was_zero_exposure_composite: bool,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::mark_hold_expired_after_worst_case_in_transaction(
            &transaction,
            hold_id,
            now_unix_secs,
            admission_operation,
            composite,
            was_zero_exposure_composite,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn mark_hold_expired_after_worst_case_in_transaction(
        transaction: &rusqlite::Transaction<'_>,
        hold_id: &str,
        now_unix_secs: i64,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        composite: bool,
        was_zero_exposure_composite: bool,
    ) -> Result<(), BudgetStoreError> {
        let expected_disposition = if was_zero_exposure_composite {
            "open"
        } else {
            "reconciled"
        };
        let updated_at = unix_now();
        let affected = transaction.execute(
            "UPDATE budget_authorization_holds SET disposition = 'expired', updated_at = ?4 \
             WHERE hold_id = ?1 AND disposition = ?2 AND reserved_until IS NOT NULL \
               AND reserved_until <= ?3",
            params![hold_id, expected_disposition, now_unix_secs, updated_at],
        )?;
        if affected != 1 {
            return Err(BudgetStoreError::Conflict(format!(
                "reserved budget hold `{hold_id}` changed during TTL reap"
            )));
        }
        if composite {
            let operation = admission_operation.ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "composite budget hold `{hold_id}` omits admission ownership"
                ))
            })?;
            let expected_monetary_state = if was_zero_exposure_composite {
                BudgetMonetaryHoldState::None
            } else {
                BudgetMonetaryHoldState::Reconciled
            };
            let affected = transaction.execute(
                "UPDATE budget_composite_holds SET updated_at = ?4 \
                 WHERE hold_id = ?1 AND operation_id = ?2 AND request_binding_hash = ?3 \
                   AND invocation_state = 'captured' AND monetary_state = ?5",
                params![
                    hold_id,
                    operation.operation_id(),
                    operation.request_binding_hash(),
                    updated_at,
                    expected_monetary_state.as_str(),
                ],
            )?;
            if affected != 1 {
                return Err(BudgetStoreError::Conflict(format!(
                    "composite budget hold `{hold_id}` changed during TTL reap"
                )));
            }
        }
        Ok(())
    }

    /// Stamp an open hold with a TTL reaper deadline, the grant currency, and the
    /// rail transaction id of a prepaid MustPrepay reservation (`None` when the
    /// reserve carried no prepayment). Errors fail-closed when the hold is missing
    /// or is no longer open.
    pub fn mark_hold_reserved_until(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let connection = self.connection()?;
        let affected = connection.execute(
            "UPDATE budget_authorization_holds \
             SET reserved_until = ?2, reserved_currency = ?3, reserved_payment_reference = ?4, \
                 reserved_budget_total = ?5, reserved_delegation_depth = ?6, \
                 reserved_root_budget_holder = ?7 \
             WHERE hold_id = ?1 AND disposition = 'open'",
            params![
                hold_id,
                reserved_until_unix_secs,
                currency,
                payment_reference,
                envelope.budget_total.map(|value| value as i64),
                envelope.delegation_depth as i64,
                envelope.root_budget_holder,
            ],
        )?;
        if affected == 0 {
            return Err(BudgetStoreError::Invariant(format!(
                "cannot mark budget hold `{hold_id}` reserved: missing or not open"
            )));
        }
        Ok(())
    }

    /// Stamp an existing atomic invocation-only hold with its caller nonce TTL.
    /// The authorization transaction already created the zero-exposure hold and
    /// debited the invocation, so this method only records reservation lineage.
    pub fn mark_invocation_hold_reserved_until(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        type InvocationReservationRow = (
            String,
            usize,
            u64,
            u64,
            bool,
            String,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        );

        if envelope.budget_total.is_some() {
            return Err(BudgetStoreError::Invariant(
                "invocation-only reservation must not carry a monetary budget total".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<InvocationReservationRow> = transaction
            .query_row(
                "SELECT capability_id, grant_index, authorized_exposure_units, \
                        remaining_exposure_units, invocation_count_debited, disposition, \
                        operation_id, request_binding_hash, reserved_until, reserved_currency, \
                        reserved_payment_reference, reserved_budget_total, \
                        reserved_delegation_depth, reserved_root_budget_holder \
                 FROM budget_authorization_holds WHERE hold_id = ?1",
                params![hold_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        budget_usize_from_row(row, 1, "invocation reservation grant index")?,
                        budget_u64_from_row(row, 2, "invocation reservation exposure")?,
                        budget_u64_from_row(row, 3, "invocation reservation remaining exposure")?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                    ))
                },
            )
            .optional()?;
        let Some(row) = row else {
            return Err(BudgetStoreError::Invariant(format!(
                "missing invocation budget hold `{hold_id}`"
            )));
        };
        if row.0 != capability_id || row.1 != grant_index {
            return Err(BudgetStoreError::Conflict(format!(
                "invocation budget hold `{hold_id}` belongs to a different capability or grant"
            )));
        }
        if row.2 != 0
            || row.3 != 0
            || !row.4
            || row.5 != "open"
            || row.6.is_some()
            || row.7.is_some()
        {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` is not an open zero-exposure invocation hold"
            )));
        }
        if row.9.is_some() || row.10.is_some() || row.11.is_some() {
            return Err(BudgetStoreError::Invariant(format!(
                "invocation budget hold `{hold_id}` carries monetary reservation metadata"
            )));
        }
        let delegation_depth = i64::from(envelope.delegation_depth);
        let exact_retry = row.8 == Some(reserved_until_unix_secs)
            && row.12 == Some(delegation_depth)
            && row.13.as_deref() == Some(envelope.root_budget_holder.as_str());
        if row.8.is_some() {
            if exact_retry {
                transaction.rollback()?;
                return Ok(());
            }
            return Err(BudgetStoreError::Conflict(format!(
                "invocation budget hold `{hold_id}` was already stamped with different reservation terms"
            )));
        }
        let grant_index = sqlite_integer_from_u64(
            u64::try_from(grant_index).map_err(|_| {
                BudgetStoreError::Overflow(
                    "invocation reservation grant index exceeds u64".to_string(),
                )
            })?,
            "invocation reservation grant index",
        )?;
        let affected = transaction.execute(
            "UPDATE budget_authorization_holds \
             SET reserved_until = ?4, reserved_currency = NULL, \
                 reserved_payment_reference = NULL, reserved_budget_total = NULL, \
                 reserved_delegation_depth = ?5, reserved_root_budget_holder = ?6 \
             WHERE hold_id = ?1 AND capability_id = ?2 AND grant_index = ?3 \
               AND authorized_exposure_units = 0 AND remaining_exposure_units = 0 \
               AND invocation_count_debited = 1 AND disposition = 'open' \
               AND operation_id IS NULL AND request_binding_hash IS NULL \
               AND reserved_until IS NULL",
            params![
                hold_id,
                capability_id,
                grant_index,
                reserved_until_unix_secs,
                delegation_depth,
                envelope.root_budget_holder,
            ],
        )?;
        if affected != 1 {
            return Err(BudgetStoreError::Conflict(format!(
                "invocation budget hold `{hold_id}` changed during reservation stamp"
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    /// Stamp an existing operation-owned composite hold without creating a
    /// compatibility hold or changing its immutable admission owner.
    pub fn mark_admission_operation_hold_reserved_until(
        &self,
        hold_id: &str,
        admission_operation: &BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        type ReservationRow = (
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
            i64,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        );

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<ReservationRow> = transaction
            .query_row(
                r#"
                SELECT authorization.operation_id, authorization.request_binding_hash,
                       composite.operation_id, composite.request_binding_hash,
                       base.operation_id, base.request_binding_hash,
                       composite.invocation_state, composite.monetary_state,
                       base.authorized_exposure_units, base.disposition,
                       base.reserved_until, base.reserved_currency,
                       base.reserved_payment_reference, base.reserved_budget_total,
                       base.reserved_delegation_depth, base.reserved_root_budget_holder
                FROM budget_composite_authorizations AS authorization
                JOIN budget_composite_holds AS composite
                  ON composite.hold_id = authorization.hold_id
                JOIN budget_authorization_holds AS base
                  ON base.hold_id = authorization.hold_id
                WHERE authorization.hold_id = ?1
                "#,
                params![hold_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                        row.get(14)?,
                        row.get(15)?,
                    ))
                },
            )
            .optional()?;
        let Some(row) = row else {
            return Err(BudgetStoreError::Invariant(format!(
                "missing operation-owned composite budget hold `{hold_id}`"
            )));
        };
        let operation_id = admission_operation.operation_id();
        let request_binding_hash = admission_operation.request_binding_hash();
        if row.0 != operation_id
            || row.1 != request_binding_hash
            || row.2 != operation_id
            || row.3 != request_binding_hash
            || row.4.as_deref() != Some(operation_id)
            || row.5.as_deref() != Some(request_binding_hash)
        {
            return Err(BudgetStoreError::Conflict(format!(
                "composite budget hold `{hold_id}` belongs to a different admission operation binding"
            )));
        }
        let invocation_state =
            BudgetInvocationReservationState::parse(&row.6).ok_or_else(|| {
                BudgetStoreError::Invariant(format!(
                    "composite budget hold `{hold_id}` has unknown invocation state `{}`",
                    row.6
                ))
            })?;
        let monetary_state = BudgetMonetaryHoldState::parse(&row.7).ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` has unknown monetary state `{}`",
                row.7
            ))
        })?;
        let authorized_exposure_units = u64::try_from(row.8).map_err(|_| {
            BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` has negative authorized exposure"
            ))
        })?;
        if !matches!(
            invocation_state,
            BudgetInvocationReservationState::Authorized
                | BudgetInvocationReservationState::Captured
        ) || !matches!(
            monetary_state,
            BudgetMonetaryHoldState::None | BudgetMonetaryHoldState::Exposed
        ) || row.9 != "open"
        {
            return Err(BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` is not open for caller reservation"
            )));
        }
        if (authorized_exposure_units == 0) != currency.is_none()
            || currency.is_some_and(str::is_empty)
        {
            return Err(BudgetStoreError::Invariant(format!(
                "composite budget hold `{hold_id}` has an invalid reserved currency"
            )));
        }
        let budget_total = envelope
            .budget_total
            .map(|value| sqlite_integer_from_u64(value, "reserved budget total"))
            .transpose()?;
        let delegation_depth = i64::from(envelope.delegation_depth);
        let exact_retry = row.10 == Some(reserved_until_unix_secs)
            && row.11.as_deref() == currency
            && row.12.as_deref() == payment_reference
            && row.13 == budget_total
            && row.14 == Some(delegation_depth)
            && row.15.as_deref() == Some(envelope.root_budget_holder.as_str());
        if row.10.is_some() {
            if exact_retry {
                transaction.rollback()?;
                return Ok(());
            }
            return Err(BudgetStoreError::Conflict(format!(
                "composite budget hold `{hold_id}` was already stamped with different reservation terms"
            )));
        }
        let affected = transaction.execute(
            r#"
            UPDATE budget_authorization_holds
            SET reserved_until = ?4, reserved_currency = ?5,
                reserved_payment_reference = ?6, reserved_budget_total = ?7,
                reserved_delegation_depth = ?8, reserved_root_budget_holder = ?9
            WHERE hold_id = ?1 AND operation_id = ?2 AND request_binding_hash = ?3
              AND disposition = 'open' AND reserved_until IS NULL
            "#,
            params![
                hold_id,
                operation_id,
                request_binding_hash,
                reserved_until_unix_secs,
                currency,
                payment_reference,
                budget_total,
                delegation_depth,
                envelope.root_budget_holder,
            ],
        )?;
        if affected != 1 {
            return Err(BudgetStoreError::Conflict(format!(
                "composite budget hold `{hold_id}` changed during reservation stamp"
            )));
        }
        transaction.commit()?;
        Ok(())
    }

    /// Adopt an already-debited invocation into a durable zero-exposure reserved
    /// hold, stamped with the TTL deadline and no currency. The invocation was
    /// already counted by `try_increment`, so this only records the open hold
    /// (never touching the invocation count); reversing it by hold id returns the
    /// invocation, while reconciling or reaping it keeps the invocation consumed.
    /// Fails closed when a hold already exists under the id.
    pub fn reserve_invocation_hold(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        let connection = self.connection()?;
        let now = unix_now();
        let inserted = connection.execute(
            "INSERT OR IGNORE INTO budget_authorization_holds ( \
                 hold_id, capability_id, grant_index, \
                 authorized_exposure_units, remaining_exposure_units, invocation_count_debited, \
                 disposition, authority_id, lease_id, lease_epoch, \
                 created_at, updated_at, reserved_until, reserved_currency, \
                 reserved_payment_reference, reserved_budget_total, \
                 reserved_delegation_depth, reserved_root_budget_holder \
             ) VALUES (?1, ?2, ?3, 0, 0, 1, 'open', NULL, NULL, NULL, ?4, ?4, ?5, NULL, NULL, \
                 ?6, ?7, ?8)",
            params![
                hold_id,
                capability_id,
                grant_index as i64,
                now,
                reserved_until_unix_secs,
                envelope.budget_total.map(|value| value as i64),
                envelope.delegation_depth as i64,
                envelope.root_budget_holder,
            ],
        )?;
        if inserted == 0 {
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` already exists"
            )));
        }
        Ok(())
    }

    /// Project a single hold by id, including its reserved-until deadline.
    pub fn budget_hold_snapshot(
        &self,
        hold_id: &str,
    ) -> Result<Option<BudgetHoldSnapshot>, BudgetStoreError> {
        let connection = self.connection()?;
        let partition_escrow_evidence =
            super::composite::load_partition_escrow_authorization_evidence(&connection, hold_id)?;
        connection
            .query_row(
                "SELECT hold.hold_id, hold.capability_id, hold.grant_index, \
                 hold.authorized_exposure_units, hold.remaining_exposure_units, \
                 hold.disposition, hold.reserved_until, hold.authority_id, \
                 hold.lease_id, hold.lease_epoch, hold.reserved_currency, \
                 hold.reserved_payment_reference, hold.reserved_budget_total, \
                 hold.reserved_delegation_depth, hold.reserved_root_budget_holder, \
                 authorization.event_id, authorization.event_seq \
                 FROM budget_authorization_holds AS hold \
                 LEFT JOIN budget_mutation_events AS authorization \
                   ON authorization.hold_id = hold.hold_id \
                  AND authorization.allowed = 1 \
                  AND authorization.kind IN (?2, ?3) \
                 WHERE hold.hold_id = ?1",
                params![
                    hold_id,
                    BudgetMutationKind::AuthorizeExposure.as_str(),
                    BudgetMutationKind::ReserveInvocations.as_str(),
                ],
                |row| {
                    let disposition = row.get::<_, String>(5)?;
                    let disposition = HoldDisposition::parse(&disposition)
                        .map(|value| match value {
                            HoldDisposition::Open => BudgetHoldDispositionView::Open,
                            HoldDisposition::Released => BudgetHoldDispositionView::Released,
                            HoldDisposition::Reversed => BudgetHoldDispositionView::Reversed,
                            HoldDisposition::Reconciled => BudgetHoldDispositionView::Reconciled,
                            HoldDisposition::Captured => BudgetHoldDispositionView::Captured,
                            HoldDisposition::Expired => BudgetHoldDispositionView::Expired,
                        })
                        .ok_or_else(|| {
                            rusqlite::Error::FromSqlConversionFailure(
                                5,
                                rusqlite::types::Type::Text,
                                Box::new(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("unknown hold disposition `{disposition}`"),
                                )),
                            )
                        })?;
                    let authority =
                        sqlite_budget_event_authority(row.get(7)?, row.get(8)?, row.get(9)?)?;
                    let authorization_event_id = row
                        .get::<_, Option<String>>(15)?
                        .unwrap_or_else(|| format!("{hold_id}:authorize"));
                    let authorization_commit_index =
                        optional_budget_u64_from_row(row, 16, "authorization event_seq")?;
                    Ok(BudgetHoldSnapshot {
                        hold_id: row.get::<_, String>(0)?,
                        capability_id: row.get::<_, String>(1)?,
                        grant_index: budget_usize_from_row(row, 2, "grant_index")?,
                        authorized_exposure_units: budget_u64_from_row(
                            row,
                            3,
                            "authorized_exposure_units",
                        )?,
                        remaining_exposure_units: budget_u64_from_row(
                            row,
                            4,
                            "remaining_exposure_units",
                        )?,
                        disposition,
                        reserved_until: row.get::<_, Option<i64>>(6)?,
                        reserved_currency: row.get::<_, Option<String>>(10)?,
                        reserved_payment_reference: row.get::<_, Option<String>>(11)?,
                        reserved_budget_total: optional_budget_u64_from_row(
                            row,
                            12,
                            "reserved_budget_total",
                        )?,
                        reserved_delegation_depth: optional_budget_u32_from_row(
                            row,
                            13,
                            "reserved_delegation_depth",
                        )?,
                        reserved_root_budget_holder: row.get::<_, Option<String>>(14)?,
                        authority: authority.clone(),
                        authorization_metadata: BudgetCommitMetadata {
                            authority,
                            guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
                            budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
                            metering_profile:
                                BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
                            budget_commit_index: authorization_commit_index,
                            event_id: Some(authorization_event_id),
                            partition_escrow_evidence: partition_escrow_evidence.clone(),
                        },
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Ids of holds still `open` that were stamped as delegated
    /// reserve-for-caller reservations: marked reserved (a non-NULL
    /// `reserved_until`) with a delegation depth of at least one. Such a hold
    /// keeps its delegated child's sibling-sum share admitted against the parent
    /// for as long as it stays open, so a freshly built mediation kernel drains
    /// exactly these holds before resuming delegated admission after a restart. A
    /// depth-zero or unstamped reserved hold carries no such share and is
    /// excluded, as is any non-open hold. Errors fail-closed rather than reporting
    /// a partial set, so the kernel aborts admission on a store read error.
    pub(super) fn list_open_delegated_reserved_holds(
        &self,
    ) -> Result<Vec<String>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT hold_id FROM budget_authorization_holds \
             WHERE disposition = 'open' AND reserved_until IS NOT NULL \
               AND reserved_delegation_depth IS NOT NULL AND reserved_delegation_depth >= 1",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }

    /// Whether any hold id begins with `budget-hold:{request_id}:`, except a
    /// startup-recovered caller reservation that never reached its TTL stamp. The
    /// mediated pre-execution gate derives each hold id from
    /// (request_id, capability id, grant index), so a replay of one request_id
    /// under a different capability token must still be seen as taken. `request_id`
    /// is caller-supplied, so its LIKE metacharacters (`%`, `_`, and the escape
    /// char) are escaped and the pattern is bound with an explicit ESCAPE clause,
    /// so a request_id containing `%` or `_` can neither widen nor narrow the match
    /// onto another caller's reservation.
    pub(super) fn hold_exists_for_request_id(
        &self,
        request_id: &str,
    ) -> Result<bool, BudgetStoreError> {
        let prefix = format!("budget-hold:{request_id}:");
        let pattern = Self::sqlite_like_prefix_pattern(&prefix);
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM budget_authorization_holds AS base \
                 WHERE base.hold_id LIKE ?1 ESCAPE '\\' \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM budget_mutation_events AS recovery \
                       WHERE recovery.hold_id = base.hold_id \
                         AND substr(recovery.event_id, 1, length(base.hold_id || ?2)) \
                             = base.hold_id || ?2 \
                         AND recovery.kind = ?3 AND recovery.allowed IS NULL \
                         AND NOT EXISTS ( \
                             SELECT 1 FROM budget_mutation_events AS reauthorization \
                             WHERE reauthorization.hold_id = base.hold_id \
                               AND reauthorization.event_id = base.hold_id || ?4 \
                               AND reauthorization.kind = ?5 \
                               AND reauthorization.allowed = 1 \
                               AND reauthorization.event_seq > recovery.event_seq \
                         ) \
                   ) \
                 LIMIT 1",
                params![
                    pattern,
                    CALLER_NO_PAYMENT_RESERVATION_RECOVERY_EVENT_SUFFIX,
                    BudgetMutationKind::ReverseExposure.as_str(),
                    CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX,
                    BudgetMutationKind::AuthorizeExposure.as_str(),
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Rows still `open`:
    /// `(hold_id, capability_id, grant_index, remaining_exposure_units, authority)`.
    /// A hold with inconsistent authority lease columns is rejected fail-closed.
    pub(super) fn list_open_holds(&self) -> Result<Vec<OpenHold>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT hold_id, capability_id, grant_index, remaining_exposure_units, \
             authority_id, lease_id, lease_epoch, operation_id, request_binding_hash \
             FROM budget_authorization_holds WHERE disposition = 'open'",
        )?;
        let rows = statement.query_map([], |row| {
            let authority = sqlite_budget_event_authority(row.get(4)?, row.get(5)?, row.get(6)?)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                budget_u32_from_row(row, 2, "grant_index")?,
                budget_u64_from_row(row, 3, "remaining_exposure_units")?,
                authority,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })?;
        let mut holds = Vec::new();
        for row in rows {
            let row = row?;
            holds.push((
                row.0,
                row.1,
                row.2,
                row.3,
                row.4,
                admission_operation_binding(row.5, row.6)?,
            ));
        }
        Ok(holds)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };
    use std::collections::HashMap;

    fn open_temp_store() -> SqliteBudgetStore {
        let dir = std::env::temp_dir().join(format!("chio-reaper-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap()
    }

    fn authorize(store: &SqliteBudgetStore, hold_id: &str, cap: &str) {
        authorize_with_authority(store, hold_id, cap, None);
    }

    fn authorize_with_authority(
        store: &SqliteBudgetStore,
        hold_id: &str,
        cap: &str,
        authority: Option<BudgetEventAuthority>,
    ) {
        let decision = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                cap.to_string(),
                0,
                Some(10),
                100,
                Some(100),
                Some(1000),
                Some(hold_id.to_string()),
                Some(format!("{hold_id}:authorize")),
                authority,
            ))
            .unwrap();
        assert!(matches!(
            decision,
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
    }

    #[test]
    fn ttl_reaper_settles_expired_unreconciled_reserved_holds_at_worst_case() {
        use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetReconcileHoldRequest};

        let store = open_temp_store();
        // Expired reserved hold.
        authorize(&store, "hold-expired", "cap-a");
        store
            .mark_hold_reserved_until(
                "hold-expired",
                100,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
        // Not-yet-expired reserved hold.
        authorize(&store, "hold-fresh", "cap-b");
        store
            .mark_hold_reserved_until(
                "hold-fresh",
                5_000,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
        // Reconciled reserved hold.
        authorize(&store, "hold-done", "cap-c");
        store
            .mark_hold_reserved_until(
                "hold-done",
                100,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-c".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 40,
                hold_id: Some("hold-done".to_string()),
                event_id: Some("hold-done:reconcile".to_string()),
                authority: None,
                admission_operation: None,
            })
            .unwrap();

        let settled = store.reap_expired_reserved_holds(1_000).unwrap();
        assert_eq!(settled, 1, "only the expired reserved hold is settled");

        // cap-a expired reserved hold SETTLED at worst-case: the reserved amount is
        // forfeited to realized spend (committed stays 100), not released to 0.
        let cap_a = store.get_usage("cap-a", 0).unwrap().unwrap();
        assert_eq!(
            cap_a.total_cost_realized_spend, 100,
            "the forfeited worst-case becomes realized spend"
        );
        assert_eq!(
            cap_a.committed_cost_units().unwrap(),
            100,
            "the reserved worst-case stays consumed, the freed difference is gone"
        );
        // A second reap is idempotent: the settled hold is no longer open.
        assert_eq!(store.reap_expired_reserved_holds(1_000).unwrap(), 0);
        assert_eq!(
            store
                .budget_hold_snapshot("hold-expired")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Expired
        );
        // cap-b not-yet-expired reserved hold untouched.
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-fresh")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Open
        );
        // cap-c reconciled hold untouched (realized 40).
        assert_eq!(
            store
                .get_usage("cap-c", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-done")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
    }

    #[test]
    fn budget_hold_snapshot_projects_reserved_hold() {
        use chio_kernel::budget_store::BudgetHoldDispositionView;

        let store = open_temp_store();
        authorize(&store, "hold-snap", "cap-snap");
        assert!(store
            .budget_hold_snapshot("hold-missing")
            .unwrap()
            .is_none());
        store
            .mark_hold_reserved_until(
                "hold-snap",
                4_242,
                "USD",
                Some("rail_txn_ref"),
                &ReservedHoldEnvelope {
                    budget_total: Some(1_000),
                    delegation_depth: 2,
                    root_budget_holder: "root-holder".to_string(),
                },
            )
            .unwrap();
        let snapshot = store.budget_hold_snapshot("hold-snap").unwrap().unwrap();
        assert_eq!(snapshot.capability_id, "cap-snap");
        assert_eq!(snapshot.remaining_exposure_units, 100);
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(4_242));
        assert_eq!(snapshot.reserved_currency.as_deref(), Some("USD"));
        assert_eq!(
            snapshot.reserved_payment_reference.as_deref(),
            Some("rail_txn_ref"),
            "a prepaid reservation records its rail transaction id durably"
        );
        assert_eq!(
            snapshot.reserved_budget_total,
            Some(1_000),
            "the grant ceiling is recorded durably on the reserved hold"
        );
        assert_eq!(snapshot.reserved_delegation_depth, Some(2));
        assert_eq!(
            snapshot.reserved_root_budget_holder.as_deref(),
            Some("root-holder"),
            "the delegation root is recorded durably on the reserved hold"
        );
    }

    #[test]
    fn mark_hold_reserved_on_missing_hold_fails_closed() {
        let store = open_temp_store();
        assert!(store
            .mark_hold_reserved_until("nope", 100, "USD", None, &ReservedHoldEnvelope::default())
            .is_err());
    }

    #[test]
    fn request_id_has_reserved_hold_matches_by_prefix_and_escapes_like_metacharacters() {
        let store = open_temp_store();
        // A reservation under capability A binds request_id `axc` to a hold whose
        // id embeds A. The reuse guard must report `axc` taken regardless of the
        // capability that opened it.
        authorize(&store, "budget-hold:axc:cap-a:0", "cap-a");

        assert_eq!(
            store.request_id_has_reserved_hold("axc").unwrap(),
            Some(true),
            "the request_id that backs the hold is reported taken"
        );
        assert_eq!(
            store.request_id_has_reserved_hold("other").unwrap(),
            Some(false),
            "a request_id with no hold is reported free"
        );
        // request_id is caller-supplied, so LIKE metacharacters in it must be
        // escaped: `_` (any single char) and `%` (any run) must not widen the
        // prefix onto the different stored request_id `axc`.
        assert_eq!(
            store.request_id_has_reserved_hold("a_c").unwrap(),
            Some(false),
            "an underscore in request_id must not match a different stored id"
        );
        assert_eq!(
            store.request_id_has_reserved_hold("a%c").unwrap(),
            Some(false),
            "a percent in request_id must not match a different stored id"
        );
    }

    #[test]
    fn reaper_reconciles_admitted_hold_and_reverses_orphan() {
        // SIGKILL after authorize commits but before reconcile. A naive
        // "release Open on restart" would enable double-spend; instead the
        // durable receipt log arbitrates.
        let store = open_temp_store();
        authorize(&store, "hold-admitted", "cap-a"); // durably admitted, realized 40
        authorize(&store, "hold-orphan", "cap-b"); // never admitted downstream
                                                   // Before reap both holds inflate committed_cost by their worst-case 100.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            100
        );

        let mut realized = HashMap::new();
        realized.insert("hold-admitted".to_string(), 40u64);
        let summary = store.reap_holds_by_map(&realized).unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 1);

        // cap-a reconciled down to realized 40; cap-b reversed back to 0.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            0
        );
    }

    #[test]
    fn reserve_invocation_hold_is_reversible_and_returns_the_invocation() {
        use chio_kernel::budget_store::{
            BudgetHoldDispositionView, BudgetReverseHoldRequest, BudgetStore,
        };

        let store = open_temp_store();
        // Debit the single invocation exactly as the reserve path does, then adopt
        // it into a durable zero-exposure reserved hold.
        assert!(store.try_increment("cap-inv", 0, Some(1)).unwrap());
        store
            .reserve_invocation_hold(
                "hold-inv",
                "cap-inv",
                0,
                4_242,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 1,
                    root_budget_holder: "inv-root".to_string(),
                },
            )
            .unwrap();

        let snapshot = store.budget_hold_snapshot("hold-inv").unwrap().unwrap();
        assert_eq!(snapshot.authorized_exposure_units, 0);
        assert_eq!(snapshot.remaining_exposure_units, 0);
        assert_eq!(snapshot.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(snapshot.reserved_until, Some(4_242));
        assert_eq!(
            snapshot.reserved_currency, None,
            "an invocation reservation records no currency"
        );
        assert_eq!(
            snapshot.reserved_budget_total, None,
            "an invocation reservation carries no monetary ceiling"
        );
        assert_eq!(snapshot.reserved_delegation_depth, Some(1));
        assert_eq!(
            snapshot.reserved_root_budget_holder.as_deref(),
            Some("inv-root"),
            "an invocation reservation still records its delegation root"
        );
        assert_eq!(
            store
                .get_usage("cap-inv", 0)
                .unwrap()
                .unwrap()
                .invocation_count,
            1
        );

        // Reversing the hold returns the invocation to the grant.
        store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: "cap-inv".to_string(),
                grant_index: 0,
                reversed_exposure_units: snapshot.remaining_exposure_units,
                hold_id: Some("hold-inv".to_string()),
                event_id: Some("hold-inv:reverse".to_string()),
                authority: snapshot.authority,
                admission_operation: None,
            })
            .unwrap();
        assert_eq!(
            store
                .get_usage("cap-inv", 0)
                .unwrap()
                .unwrap()
                .invocation_count,
            0,
            "reversing an invocation reservation returns the debited invocation"
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-inv")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reversed
        );

        // A duplicate reserve under the same id fails closed.
        assert!(store
            .reserve_invocation_hold(
                "hold-inv",
                "cap-inv",
                0,
                9_000,
                &ReservedHoldEnvelope::default()
            )
            .is_err());
    }

    #[test]
    fn reaper_forfeits_expired_invocation_reserve_keeping_it_consumed() {
        use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetStore};

        let store = open_temp_store();
        assert!(store.try_increment("cap-inv", 0, Some(1)).unwrap());
        store
            .reserve_invocation_hold(
                "hold-inv",
                "cap-inv",
                0,
                100,
                &ReservedHoldEnvelope::default(),
            )
            .unwrap();

        let settled = store.reap_expired_reserved_holds(1_000).unwrap();
        assert_eq!(settled, 1, "the expired invocation reservation is settled");
        assert_eq!(
            store
                .get_usage("cap-inv", 0)
                .unwrap()
                .unwrap()
                .invocation_count,
            1,
            "reaping forfeits the invocation (stays consumed), matching monetary reap"
        );
        assert_eq!(
            store
                .budget_hold_snapshot("hold-inv")
                .unwrap()
                .unwrap()
                .disposition,
            BudgetHoldDispositionView::Reconciled
        );
        // Idempotent: a settled hold is no longer open.
        assert_eq!(store.reap_expired_reserved_holds(1_000).unwrap(), 0);
    }

    #[test]
    fn reaper_reclaims_kernel_authored_holds_bearing_authority() {
        // Kernel-authored holds carry a BudgetEventAuthority lease. A crash after
        // authorize leaves them open; the reaper must load and present each hold's
        // stored authority so the store's authority check passes and the orphaned
        // holds are reclaimed rather than left reserved indefinitely.
        let store = open_temp_store();
        let authority = BudgetEventAuthority {
            authority_id: "kernel-authority".to_string(),
            lease_id: "lease-1".to_string(),
            lease_epoch: 0,
        };
        authorize_with_authority(&store, "hold-admitted", "cap-a", Some(authority.clone()));
        authorize_with_authority(&store, "hold-orphan", "cap-b", Some(authority));

        let mut realized = HashMap::new();
        realized.insert("hold-admitted".to_string(), 40u64);
        let summary = store.reap_holds_by_map(&realized).unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.reversed, 1);

        // cap-a reconciled to realized 40; cap-b orphan reversed to 0.
        assert_eq!(
            store
                .get_usage("cap-a", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            40
        );
        assert_eq!(
            store
                .get_usage("cap-b", 0)
                .unwrap()
                .unwrap()
                .committed_cost_units()
                .unwrap(),
            0
        );
    }

    #[test]
    fn list_open_delegated_reserved_hold_ids_enumerates_only_open_delegated_reserved() {
        use chio_kernel::budget_store::BudgetReconcileHoldRequest;

        let store = open_temp_store();

        // (a) Open delegated reserve-for-caller hold: reserved with delegation
        // depth one, so its child's sibling-sum share stays admitted against the
        // parent until it closes. The restart gate must drain exactly this hold.
        authorize(&store, "hold-a-delegated", "cap-a");
        store
            .mark_hold_reserved_until(
                "hold-a-delegated",
                4_242,
                "USD",
                None,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 1,
                    root_budget_holder: "root-a".to_string(),
                },
            )
            .unwrap();

        // (b) Open reserved hold at delegation depth zero: reserved but not
        // delegated, so it holds no sibling-sum share and must be excluded.
        authorize(&store, "hold-b-nondelegated", "cap-b");
        store
            .mark_hold_reserved_until(
                "hold-b-nondelegated",
                4_242,
                "USD",
                None,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 0,
                    root_budget_holder: "root-b".to_string(),
                },
            )
            .unwrap();

        // (c) Delegated hold that has since closed: reconciled, so no longer open
        // and no longer holds a share, and must be excluded.
        authorize(&store, "hold-c-closed", "cap-c");
        store
            .mark_hold_reserved_until(
                "hold-c-closed",
                4_242,
                "USD",
                None,
                &ReservedHoldEnvelope {
                    budget_total: None,
                    delegation_depth: 1,
                    root_budget_holder: "root-c".to_string(),
                },
            )
            .unwrap();
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: "cap-c".to_string(),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 40,
                hold_id: Some("hold-c-closed".to_string()),
                event_id: Some("hold-c-closed:reconcile".to_string()),
                authority: None,
                admission_operation: None,
            })
            .unwrap();

        // Some(..) switches the kernel onto the precise restart gate; the set
        // enumerates only the open delegated reserved hold.
        let ids = store.list_open_delegated_reserved_hold_ids().unwrap();
        assert_eq!(ids, Some(vec!["hold-a-delegated".to_string()]));
    }
}
