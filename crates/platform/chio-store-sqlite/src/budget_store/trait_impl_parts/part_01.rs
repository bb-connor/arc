use super::store::{
    SqliteInvocationQuotaMutationAction, SqliteInvocationQuotaMutationContext,
    SqliteInvocationQuotaMutationMode, SqliteLegacyProjectionMutation, SqliteLegacyProjectionState,
};
use super::*;
use chio_kernel::budget_store::{
    AuthorizedBudgetHold, BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest,
    BudgetReconcileHoldDecision, BudgetReconcileHoldRequest, BudgetReleaseHoldDecision,
    BudgetReleaseHoldRequest, BudgetReverseHoldDecision, BudgetReverseHoldRequest,
    DeniedBudgetHold,
};

impl SqliteBudgetStore {
    #[allow(clippy::too_many_arguments)]
    pub fn try_charge_cost_with_ids_and_authority_outcome(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<SqliteBudgetAuthorizationOutcome, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority_mode_outcome(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            SqliteBudgetAuthorizationAuthorityMode::CallerPinned(authority.cloned()),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn try_charge_cost_with_ids_authority_and_journal_outcome(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
        journal: Option<&chio_kernel::payment::PaymentJournalRecord>,
    ) -> Result<SqliteBudgetAuthorizationOutcome, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority_mode_outcome(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            SqliteBudgetAuthorizationAuthorityMode::CallerPinned(authority.cloned()),
            journal,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn try_charge_cost_with_ids_and_current_authority_outcome(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        current_authority: SqliteBudgetCurrentAuthority,
    ) -> Result<SqliteBudgetAuthorizationOutcome, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority_mode_outcome(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            SqliteBudgetAuthorizationAuthorityMode::ServerCurrent(current_authority),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_charge_cost_with_ids_and_authority_mode_outcome(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority_mode: SqliteBudgetAuthorizationAuthorityMode,
        journal: Option<&chio_kernel::payment::PaymentJournalRecord>,
    ) -> Result<SqliteBudgetAuthorizationOutcome, BudgetStoreError> {
        let effective_event_id = match event_id {
            Some(event_id) => Some(event_id.to_string()),
            None if hold_id.is_some() => Some(effective_hold_event_id(
                None,
                BudgetMutationKind::AuthorizeExposure,
            )),
            None => None,
        };
        let event_id = effective_event_id.as_deref();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let selected_authority = SqliteBudgetStore::authorization_authority_in_transaction(
            &transaction,
            hold_id,
            event_id,
            &authority_mode,
        )?;
        let authority = selected_authority.as_ref();

        let (prior_claim_decision, claim_follows_rollback) = match (hold_id, event_id) {
            (Some(hold_id), Some(event_id)) => SqliteBudgetStore::claim_authorization_attempt(
                &transaction,
                hold_id,
                event_id,
                capability_id,
                grant_index,
                cost_units,
                max_invocations,
                max_cost_per_invocation,
                max_total_cost_units,
                authority,
                None,
            )?,
            _ => (None, false),
        };

        let existing_allowed = SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::AuthorizeExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
        )?;
        let retry_follows_rollback = if claim_follows_rollback {
            true
        } else {
            event_id
                .map(|event_id| {
                    SqliteBudgetStore::rollback_event_exists(
                        &transaction,
                        event_id,
                        hold_id,
                        capability_id,
                        grant_index,
                        cost_units,
                        authority,
                    )
                })
                .transpose()?
                .unwrap_or(false)
        };
        if prior_claim_decision.is_some() && existing_allowed.is_none() && !retry_follows_rollback {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has a durable authorization claim but its event is missing",
                hold_id.unwrap_or("<missing>")
            )));
        }
        let row: Option<(u32, u64, u64, u64)> = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend, seq
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![capability_id, grant_index as i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                        budget_u64_from_row(row, 3, "usage sequence")?,
                    ))
                },
            )
            .optional()?;
        let expected_projection = row.map(
            |(invocation_count, total_cost_exposed, total_cost_realized_spend, seq)| {
                SqliteLegacyProjectionState {
                    invocation_count,
                    total_cost_exposed,
                    total_cost_realized_spend,
                    seq,
                }
            },
        );
        let (current_count, current_exposed, current_realized, current_usage_seq) =
            row.unwrap_or((0, 0, 0, 0));
        let existing_event_seq = if existing_allowed.is_some() {
            let event_id = event_id.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "persisted budget authorization is missing event_id".to_string(),
                )
            })?;
            Some(
                transaction
                    .query_row(
                        "SELECT event_seq FROM budget_mutation_events WHERE event_id = ?1",
                        params![event_id],
                        |row| budget_u64_from_row(row, 0, "authorization event sequence"),
                    )
                    .optional()?
                    .ok_or_else(|| {
                        BudgetStoreError::Invariant(
                            "persisted budget authorization event disappeared".to_string(),
                        )
                    })?,
            )
        } else {
            None
        };
        let compatibility_quota = BudgetInvocationQuota::from_persisted_parts(
            BudgetQuotaKey::grant(capability_id, grant_index)?,
            max_invocations.unwrap_or(u32::MAX),
        )?;
        SqliteBudgetStore::reject_composite_managed_grant(
            &transaction,
            capability_id,
            grant_index,
        )?;
        if let Some(existing_allowed) = existing_allowed {
            SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                &transaction,
                std::slice::from_ref(&compatibility_quota),
                compatibility_quota.key(),
                current_count,
                SqliteInvocationQuotaMutationContext {
                    mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                    action: SqliteInvocationQuotaMutationAction::Replay,
                    event_seq: existing_event_seq
                        .unwrap_or(current_usage_seq)
                        .max(current_usage_seq),
                    updated_at: unix_now(),
                },
            )?;
            let existing_allowed = existing_allowed.ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "persisted budget authorization is missing its frozen decision".to_string(),
                )
            })?;
            if prior_claim_decision
                .is_some_and(|claimed_allowed| claimed_allowed != existing_allowed)
            {
                return Err(BudgetStoreError::Invariant(
                    "persisted budget authorization conflicts with its durable claim".to_string(),
                ));
            }
            if existing_allowed {
                if let Some(journal) = journal {
                    insert_payment_journal_tx(&transaction, journal, true)?;
                }
            }
            transaction.commit()?;
            return Ok(SqliteBudgetAuthorizationOutcome {
                allowed: existing_allowed,
                event_created: false,
                authority: selected_authority,
            });
        }

        if let Some(hold_id) = hold_id {
            let retry_follows_rollback = if claim_follows_rollback {
                true
            } else {
                match event_id {
                    Some(event_id) => Self::rollback_event_exists(
                        &transaction,
                        event_id,
                        Some(hold_id),
                        capability_id,
                        grant_index,
                        cost_units,
                        authority,
                    )?,
                    None => false,
                }
            };
            if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                if hold.capability_id == capability_id
                    && hold.grant_index == grant_index
                    && hold.authorized_exposure_units == cost_units
                    && hold.remaining_exposure_units == cost_units
                    && hold.invocation_count_debited
                    && hold.disposition == HoldDisposition::Open
                    && current_exposed >= cost_units
                {
                    let current = transaction
                        .query_row(
                            r#"
                            SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                            FROM capability_grant_budgets
                            WHERE capability_id = ?1 AND grant_index = ?2
                            "#,
                            params![capability_id, grant_index as i64],
                            |row| {
                                Ok((
                                    budget_u64_from_row(row, 0, "seq")?,
                                    budget_u32_from_row(row, 1, "invocation_count")?,
                                    budget_u64_from_row(row, 2, "total_cost_exposed")?,
                                    budget_u64_from_row(
                                        row,
                                        3,
                                        "total_cost_realized_spend",
                                    )?,
                                ))
                            },
                        )
                        .optional()?;
                    if let Some((
                        usage_seq,
                        invocation_count_after,
                        total_cost_exposed_after,
                        total_cost_realized_spend_after,
                    )) = current
                    {
                        let event_seq = allocate_budget_replication_seq(&transaction)?;
                        if retry_follows_rollback {
                            SqliteBudgetStore::upsert_hold(
                                &transaction,
                                hold_id,
                                capability_id,
                                grant_index,
                                cost_units,
                                cost_units,
                                HoldDisposition::Open,
                                authority,
                            )?;
                        }
                        SqliteBudgetStore::claim_authorization_attempt(
                            &transaction,
                            hold_id,
                            event_id.ok_or_else(|| {
                                BudgetStoreError::Invariant(
                                    "claimed budget authorization is missing event_id".to_string(),
                                )
                            })?,
                            capability_id,
                            grant_index,
                            cost_units,
                            max_invocations,
                            max_cost_per_invocation,
                            max_total_cost_units,
                            authority,
                            Some(true),
                        )?;
                        SqliteBudgetStore::append_mutation_event(
                            &transaction,
                            event_id,
                            Some(hold_id),
                            authority,
                            capability_id,
                            grant_index,
                            BudgetMutationKind::AuthorizeExposure,
                            Some(true),
                            event_seq,
                            Some(usage_seq),
                            cost_units,
                            0,
                            max_invocations,
                            max_cost_per_invocation,
                            max_total_cost_units,
                            invocation_count_after,
                            total_cost_exposed_after,
                            total_cost_realized_spend_after,
                        )?;
                        SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                            &transaction,
                            std::slice::from_ref(&compatibility_quota),
                            compatibility_quota.key(),
                            invocation_count_after,
                            SqliteInvocationQuotaMutationContext {
                                mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                                action: SqliteInvocationQuotaMutationAction::Replay,
                                event_seq,
                                updated_at: unix_now(),
                            },
                        )?;
                        if let Some(journal) = journal {
                            insert_payment_journal_tx(&transaction, journal, true)?;
                        }
                        transaction.commit()?;
                        return Ok(SqliteBudgetAuthorizationOutcome {
                            allowed: true,
                            event_created: true,
                            authority: selected_authority,
                        });
                    }
                }
            }
            if retry_follows_rollback {
                Self::delete_hold_if_exists(&transaction, hold_id)?;
            }
        }

        let current_total = checked_committed_cost_units(current_exposed, current_realized)?;
        let committed_if_allowed = current_total.checked_add(cost_units);
        let monetary_denied = max_cost_per_invocation.is_some_and(|max| cost_units > max)
            || max_total_cost_units
                .is_some_and(|max| committed_if_allowed.is_none_or(|committed| committed > max));

        if !monetary_denied {
            if let Some(hold_id) = hold_id {
                let retry_follows_rollback = if claim_follows_rollback {
                    true
                } else {
                    match event_id {
                        Some(event_id) => Self::rollback_event_exists(
                            &transaction,
                            event_id,
                            Some(hold_id),
                            capability_id,
                            grant_index,
                            cost_units,
                            authority,
                        )?,
                        None => false,
                    }
                };
                if retry_follows_rollback {
                    if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                        if hold.capability_id == capability_id
                            && hold.grant_index == grant_index
                            && hold.authorized_exposure_units == cost_units
                            && hold.remaining_exposure_units == cost_units
                            && hold.invocation_count_debited
                            && hold.disposition == HoldDisposition::Open
                            && current_exposed >= cost_units
                        {
                            let current = transaction
                                .query_row(
                                    r#"
                                    SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                                    FROM capability_grant_budgets
                                    WHERE capability_id = ?1 AND grant_index = ?2
                                    "#,
                                    params![capability_id, grant_index as i64],
                                    |row| {
                                        Ok((
                                            budget_u64_from_row(row, 0, "seq")?,
                                            budget_u32_from_row(row, 1, "invocation_count")?,
                                            budget_u64_from_row(row, 2, "total_cost_exposed")?,
                                            budget_u64_from_row(
                                                row,
                                                3,
                                                "total_cost_realized_spend",
                                            )?,
                                        ))
                                    },
                                )
                                .optional()?;
                            if let Some((
                                usage_seq,
                                invocation_count_after,
                                total_cost_exposed_after,
                                total_cost_realized_spend_after,
                            )) = current
                            {
                                let event_seq = allocate_budget_replication_seq(&transaction)?;
                                SqliteBudgetStore::upsert_hold(
                                    &transaction,
                                    hold_id,
                                    capability_id,
                                    grant_index,
                                    cost_units,
                                    cost_units,
                                    HoldDisposition::Open,
                                    authority,
                                )?;
                                SqliteBudgetStore::append_mutation_event(
                                    &transaction,
                                    event_id,
                                    Some(hold_id),
                                    authority,
                                    capability_id,
                                    grant_index,
                                    BudgetMutationKind::AuthorizeExposure,
                                    Some(true),
                                    event_seq,
                                    Some(usage_seq),
                                    cost_units,
                                    0,
                                    max_invocations,
                                    max_cost_per_invocation,
                                    max_total_cost_units,
                                    invocation_count_after,
                                    total_cost_exposed_after,
                                    total_cost_realized_spend_after,
                                )?;
                                SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                                    &transaction,
                                    std::slice::from_ref(&compatibility_quota),
                                    compatibility_quota.key(),
                                    invocation_count_after,
                                    SqliteInvocationQuotaMutationContext {
                                        mode:
                                            SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                                        action: SqliteInvocationQuotaMutationAction::Replay,
                                        event_seq,
                                        updated_at: unix_now(),
                                    },
                                )?;
                                if let Some(journal) = journal {
                                    insert_payment_journal_tx(&transaction, journal, true)?;
                                }
                                transaction.commit()?;
                                return Ok(SqliteBudgetAuthorizationOutcome {
                                    allowed: true,
                                    event_created: true,
                                    authority: selected_authority,
                                });
                            }
                        }
                    }
                    Self::delete_hold_if_exists(&transaction, hold_id)?;
                } else if let Some(hold) = SqliteBudgetStore::load_hold(&transaction, hold_id)? {
                    if hold.capability_id == capability_id
                        && hold.grant_index == grant_index
                        && hold.authorized_exposure_units == cost_units
                        && hold.remaining_exposure_units == cost_units
                        && hold.invocation_count_debited
                        && hold.disposition == HoldDisposition::Open
                    {
                        let current = transaction
                            .query_row(
                                r#"
                                SELECT seq, invocation_count, total_cost_exposed, total_cost_realized_spend
                                FROM capability_grant_budgets
                                WHERE capability_id = ?1 AND grant_index = ?2
                                "#,
                                params![capability_id, grant_index as i64],
                                |row| {
                                    Ok((
                                        budget_u64_from_row(row, 0, "seq")?,
                                        budget_u32_from_row(row, 1, "invocation_count")?,
                                        budget_u64_from_row(row, 2, "total_cost_exposed")?,
                                        budget_u64_from_row(
                                            row,
                                            3,
                                            "total_cost_realized_spend",
                                        )?,
                                    ))
                                },
                            )
                            .optional()?;
                        if let Some((
                            seq,
                            invocation_count_after,
                            total_cost_exposed_after,
                            total_cost_realized_spend_after,
                        )) = current
                        {
                            if total_cost_exposed_after < cost_units {
                                transaction.rollback()?;
                                return Err(BudgetStoreError::Invariant(format!(
                                    "budget hold `{hold_id}` is not reflected in usage totals"
                                )));
                            }
                            SqliteBudgetStore::append_mutation_event(
                                &transaction,
                                event_id,
                                Some(hold_id),
                                authority,
                                capability_id,
                                grant_index,
                                BudgetMutationKind::AuthorizeExposure,
                                Some(true),
                                seq,
                                Some(seq),
                                cost_units,
                                0,
                                max_invocations,
                                max_cost_per_invocation,
                                max_total_cost_units,
                                invocation_count_after,
                                total_cost_exposed_after,
                                total_cost_realized_spend_after,
                            )?;
                            SqliteBudgetStore::compare_and_mutate_invocation_quotas(
                                &transaction,
                                std::slice::from_ref(&compatibility_quota),
                                compatibility_quota.key(),
                                invocation_count_after,
                                SqliteInvocationQuotaMutationContext {
                                    mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                                    action: SqliteInvocationQuotaMutationAction::Replay,
                                    event_seq: seq,
                                    updated_at: unix_now(),
                                },
                            )?;
                            if let Some(journal) = journal {
                                insert_payment_journal_tx(&transaction, journal, true)?;
                            }
                            transaction.commit()?;
                            return Ok(SqliteBudgetAuthorizationOutcome {
                                allowed: true,
                                event_created: true,
                                authority: selected_authority,
                            });
                        }
                    }
                    transaction.rollback()?;
                    return Err(BudgetStoreError::Invariant(format!(
                        "budget hold `{hold_id}` already exists"
                    )));
                }
            }
        }

        let updated_at = unix_now();
        let event_seq = allocate_budget_replication_seq(&transaction)?;
        let quota_mutation = SqliteBudgetStore::compare_and_mutate_invocation_quotas(
            &transaction,
            std::slice::from_ref(&compatibility_quota),
            compatibility_quota.key(),
            current_count,
            SqliteInvocationQuotaMutationContext {
                mode: SqliteInvocationQuotaMutationMode::CaptureCompatibility,
                action: SqliteInvocationQuotaMutationAction::Attempt {
                    external_denied: monetary_denied,
                },
                event_seq,
                updated_at,
            },
        )?;
        let allowed = quota_mutation.allowed;
        let persisted_cost_units =
            if quota_mutation.quota_exhausted && cost_units > i64::MAX as u64 {
                0
            } else {
                cost_units
            };
        let persisted_max_cost_per_invocation = if quota_mutation.quota_exhausted {
            max_cost_per_invocation.filter(|value| *value <= i64::MAX as u64)
        } else {
            max_cost_per_invocation
        };
        let persisted_max_total_cost_units = if quota_mutation.quota_exhausted {
            max_total_cost_units.filter(|value| *value <= i64::MAX as u64)
        } else {
            max_total_cost_units
        };
        if let (Some(hold_id), Some(event_id)) = (hold_id, event_id) {
            SqliteBudgetStore::claim_authorization_attempt(
                &transaction,
                hold_id,
                event_id,
                capability_id,
                grant_index,
                persisted_cost_units,
                max_invocations,
                persisted_max_cost_per_invocation,
                persisted_max_total_cost_units,
                authority,
                Some(allowed),
            )?;
        }
        let invocation_count_after = quota_mutation.primary_count_after;
        let (total_cost_exposed_after, total_cost_realized_spend_after, usage_seq) = if allowed {
            committed_if_allowed.ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "authorized exposure + cost_units overflowed u64".to_string(),
                )
            })?;
            let new_total_cost_exposed =
                current_exposed.checked_add(cost_units).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + cost_units overflowed u64".to_string(),
                    )
                })?;
            SqliteBudgetStore::compare_and_persist_legacy_projection(
                &transaction,
                SqliteLegacyProjectionMutation {
                    capability_id,
                    grant_index,
                    expected: expected_projection,
                    after: SqliteLegacyProjectionState {
                        invocation_count: invocation_count_after,
                        total_cost_exposed: new_total_cost_exposed,
                        total_cost_realized_spend: current_realized,
                        seq: event_seq,
                    },
                    updated_at,
                },
            )?;
            if let Some(hold_id) = hold_id {
                SqliteBudgetStore::create_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                    cost_units,
                    authority,
                )?;
            }
            (new_total_cost_exposed, current_realized, Some(event_seq))
        } else {
            (current_exposed, current_realized, None)
        };
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::AuthorizeExposure,
            Some(allowed),
            event_seq,
            usage_seq,
            persisted_cost_units,
            0,
            max_invocations,
            persisted_max_cost_per_invocation,
            persisted_max_total_cost_units,
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        if allowed {
            if let Some(journal) = journal {
                insert_payment_journal_tx(&transaction, journal, true)?;
            }
        }
        transaction.commit()?;
        Ok(SqliteBudgetAuthorizationOutcome {
            allowed,
            event_created: true,
            authority: selected_authority,
        })
    }
}
