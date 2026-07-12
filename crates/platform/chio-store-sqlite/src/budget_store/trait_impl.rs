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

        if let Some(existing_allowed) = SqliteBudgetStore::existing_event_allowed(
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
        )? {
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
            transaction.rollback()?;
            return Ok(SqliteBudgetAuthorizationOutcome {
                allowed: existing_allowed,
                event_created: false,
                authority: selected_authority,
            });
        }
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
        if prior_claim_decision.is_some() && !retry_follows_rollback {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{}` has a durable authorization claim but its event is missing",
                hold_id.unwrap_or("<missing>")
            )));
        }
        SqliteBudgetStore::reject_composite_managed_grant(
            &transaction,
            capability_id,
            grant_index,
        )?;

        let row: Option<(u32, u64, u64)> = transaction
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
            .optional()?;
        let (current_count, current_exposed, current_realized) = row.unwrap_or((0, 0, 0));

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

        let mut allowed = true;

        if let Some(max) = max_invocations {
            if current_count >= max {
                allowed = false;
            }
        }
        if let Some(max_per) = max_cost_per_invocation {
            if cost_units > max_per {
                allowed = false;
            }
        }
        if let Some(max_total) = max_total_cost_units {
            let current_total = checked_committed_cost_units(current_exposed, current_realized)?;
            let new_total = current_total.checked_add(cost_units).ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "authorized exposure + cost_units overflowed u64".to_string(),
                )
            })?;
            if new_total > max_total {
                allowed = false;
            }
        }
        if let (Some(hold_id), Some(event_id)) = (hold_id, event_id) {
            SqliteBudgetStore::claim_authorization_attempt(
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
                Some(allowed),
            )?;
        }

        let (
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
            event_seq,
            usage_seq,
        );
        if allowed {
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
            let new_total_cost_exposed =
                current_exposed.checked_add(cost_units).ok_or_else(|| {
                    BudgetStoreError::Overflow(
                        "total_cost_exposed + cost_units overflowed u64".to_string(),
                    )
                })?;
            let updated_at = unix_now();
            let seq = allocate_budget_replication_seq(&transaction)?;
            transaction.execute(
                r#"
                INSERT INTO capability_grant_budgets (
                    capability_id,
                    grant_index,
                    invocation_count,
                    updated_at,
                    seq,
                    total_cost_exposed,
                    total_cost_realized_spend
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                    invocation_count = excluded.invocation_count,
                    updated_at = excluded.updated_at,
                    seq = excluded.seq,
                    total_cost_exposed = excluded.total_cost_exposed,
                    total_cost_realized_spend = excluded.total_cost_realized_spend
                "#,
                params![
                    capability_id,
                    grant_index as i64,
                    (current_count.saturating_add(1)) as i64,
                    updated_at,
                    seq as i64,
                    new_total_cost_exposed as i64,
                    current_realized as i64,
                ],
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
            invocation_count_after = current_count.saturating_add(1);
            total_cost_exposed_after = new_total_cost_exposed;
            total_cost_realized_spend_after = current_realized;
            event_seq = seq;
            usage_seq = Some(seq);
        } else {
            event_seq = allocate_budget_replication_seq(&transaction)?;
            invocation_count_after = current_count;
            total_cost_exposed_after = current_exposed;
            total_cost_realized_spend_after = current_realized;
            usage_seq = None;
        }
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
            cost_units,
            0,
            max_invocations,
            max_cost_per_invocation,
            max_total_cost_units,
            invocation_count_after,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        transaction.commit()?;
        Ok(SqliteBudgetAuthorizationOutcome {
            allowed,
            event_created: true,
            authority: selected_authority,
        })
    }
}

impl BudgetStore for SqliteBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_increment_with_event_id(capability_id, grant_index, max_invocations, None)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            None,
            None,
        )
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn try_charge_cost_with_ids_and_authority(
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
    ) -> Result<bool, BudgetStoreError> {
        Ok(self
            .try_charge_cost_with_ids_and_authority_outcome(
                capability_id,
                grant_index,
                max_invocations,
                cost_units,
                max_cost_per_invocation,
                max_total_cost_units,
                hold_id,
                event_id,
                authority,
            )?
            .allowed)
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReverseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != cost_units || !hold.invocation_count_debited {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reverse amount"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
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
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reverse charge larger than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET invocation_count = ?3,
                updated_at = ?4,
                seq = ?5,
                total_cost_exposed = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                invocation_count - 1,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reversed,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReverseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            invocation_count - 1,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids(capability_id, grant_index, cost_units, None, None)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            capability_id,
            grant_index,
            hold_id,
            authority,
            cost_units,
            0,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units < cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` cannot release more than remaining exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
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
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if total_cost_exposed < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot reduce charge larger than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - cost_units;
        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
            let remaining = hold.remaining_exposure_units - cost_units;
            let disposition = if remaining == 0 {
                HoldDisposition::Released
            } else {
                HoldDisposition::Open
            };
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                remaining,
                disposition,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReleaseExposure,
            None,
            seq,
            Some(seq),
            cost_units,
            0,
            None,
            None,
            None,
            invocation_count,
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
        )
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            None,
        )
    }

    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReconcileSpend,
            capability_id,
            grant_index,
            hold_id,
            authority,
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
        )?
        .is_some()
        {
            transaction.rollback()?;
            return Ok(());
        }
        if let Some(hold_id) = hold_id {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                capability_id,
                grant_index,
            )?;
            if hold.remaining_exposure_units != exposed_cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match reconciled exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                authority,
            )?;
        }

        let current = transaction
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
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };

        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < exposed_cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot settle more exposure than total_cost_exposed".to_string(),
            ));
        }

        let new_total_cost_exposed = total_cost_exposed - exposed_cost_units;
        let new_total_cost_realized_spend = total_cost_realized_spend
            .checked_add(realized_cost_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_realized_spend + realized_cost_units overflowed u64".to_string(),
                )
            })?;

        let seq = allocate_budget_replication_seq(&transaction)?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5,
                total_cost_realized_spend = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                capability_id,
                grant_index as i64,
                unix_now(),
                seq as i64,
                new_total_cost_exposed as i64,
                new_total_cost_realized_spend as i64,
            ],
        )?;
        if let Some(hold_id) = hold_id {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    capability_id,
                    grant_index,
                )?
                .authority
                .as_ref(),
                authority,
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Reconciled,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            event_id,
            hold_id,
            authority,
            capability_id,
            grant_index,
            BudgetMutationKind::ReconcileSpend,
            None,
            seq,
            Some(seq),
            exposed_cost_units,
            realized_cost_units,
            None,
            None,
            None,
            invocation_count,
            new_total_cost_exposed,
            new_total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn authorize_budget_hold(
        &self,
        request: BudgetAuthorizeHoldRequest,
    ) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if !request.invocation_quotas().is_empty() || request.revocation_set().is_some() {
            if request.max_invocations.is_some() {
                return Err(BudgetStoreError::Invariant(
                    "composite budget hold must not also present legacy max_invocations"
                        .to_string(),
                ));
            }
            let invocation_quotas = request.invocation_quotas().to_vec();
            let revocation_set = request.revocation_set().cloned().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "composite budget hold requires a canonical revocation set".to_string(),
                )
            })?;
            let hold_id = request.hold_id.ok_or_else(|| {
                BudgetStoreError::Invariant("composite budget hold requires hold_id".to_string())
            })?;
            let event_id = request.event_id.ok_or_else(|| {
                BudgetStoreError::Invariant("composite budget hold requires event_id".to_string())
            })?;
            return self.authorize_composite_hold(SqliteCompositeAuthorizeInput {
                capability_id: request.capability_id,
                grant_index: request.grant_index,
                requested_exposure_units: request.requested_exposure_units,
                max_cost_per_invocation: request.max_cost_per_invocation,
                max_total_cost_units: request.max_total_cost_units,
                hold_id,
                event_id,
                authority: request.authority,
                invocation_quotas,
                revocation_set,
            });
        }
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::AuthorizeExposure,
        );
        self.try_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.max_invocations,
            request.requested_exposure_units,
            request.max_cost_per_invocation,
            request.max_total_cost_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
        )?;
        load_authorize_decision_for_event(self, &event_id)
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        self.capture_composite_invocation_reservations(request)
    }

    fn reverse_budget_hold(
        &self,
        request: BudgetReverseHoldRequest,
    ) -> Result<BudgetReverseHoldDecision, BudgetStoreError> {
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::ReverseExposure,
        );
        self.reverse_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.reversed_exposure_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
        )?;
        load_hold_decision_for_event(
            self,
            &event_id,
            BudgetMutationKind::ReverseExposure,
            BudgetMonetaryHoldState::Reversed,
        )
    }

    fn release_budget_hold(
        &self,
        request: BudgetReleaseHoldRequest,
    ) -> Result<BudgetReleaseHoldDecision, BudgetStoreError> {
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::ReleaseExposure,
        );
        self.reduce_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.released_exposure_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
        )?;
        load_hold_decision_for_event(
            self,
            &event_id,
            BudgetMutationKind::ReleaseExposure,
            BudgetMonetaryHoldState::Released,
        )
    }

    fn reconcile_budget_hold(
        &self,
        request: BudgetReconcileHoldRequest,
    ) -> Result<BudgetReconcileHoldDecision, BudgetStoreError> {
        let event_id = effective_hold_event_id(
            request.event_id.as_deref(),
            BudgetMutationKind::ReconcileSpend,
        );
        self.settle_charge_cost_with_ids_and_authority(
            &request.capability_id,
            request.grant_index,
            request.exposed_cost_units,
            request.realized_spend_units,
            request.hold_id.as_deref(),
            Some(&event_id),
            request.authority.as_ref(),
        )?;
        load_hold_decision_for_event(
            self,
            &event_id,
            BudgetMutationKind::ReconcileSpend,
            BudgetMonetaryHoldState::Reconciled,
        )
    }

    fn capture_budget_hold(
        &self,
        request: BudgetCaptureHoldRequest,
    ) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
        if request.realized_spend_units > request.exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        let grant_index_i64 = i64::try_from(request.grant_index).map_err(|_| {
            BudgetStoreError::Overflow("budget grant index exceeds SQLite INTEGER".to_string())
        })?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            request.event_id.as_deref(),
            BudgetMutationKind::CaptureExposure,
            &request.capability_id,
            request.grant_index,
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            request.exposed_cost_units,
            request.realized_spend_units,
            None,
            None,
            None,
        )?
        .is_some()
        {
            let event_id = request.event_id.as_deref().ok_or_else(|| {
                BudgetStoreError::Invariant(
                    "captured budget retry is missing its persisted event_id".to_string(),
                )
            })?;
            let record = SqliteBudgetStore::load_mutation_event(&transaction, event_id)?
                .ok_or_else(|| {
                    BudgetStoreError::Invariant(format!(
                        "captured budget event `{event_id}` disappeared during retry"
                    ))
                })?;
            transaction.rollback()?;
            return capture_decision_from_record(self, &record);
        }

        if let Some(hold_id) = request.hold_id.as_deref() {
            let hold = SqliteBudgetStore::ensure_open_hold(
                &transaction,
                hold_id,
                &request.capability_id,
                request.grant_index,
            )?;
            if hold.remaining_exposure_units != request.exposed_cost_units {
                transaction.rollback()?;
                return Err(BudgetStoreError::Invariant(format!(
                    "budget hold `{hold_id}` does not match captured exposure"
                )));
            }
            SqliteBudgetStore::validate_hold_authority(
                hold_id,
                hold.authority.as_ref(),
                request.authority.as_ref(),
            )?;
        }

        let current = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
                params![request.capability_id, grant_index_i64],
                |row| {
                    Ok((
                        budget_u32_from_row(row, 0, "invocation_count")?,
                        budget_u64_from_row(row, 1, "total_cost_exposed")?,
                        budget_u64_from_row(row, 2, "total_cost_realized_spend")?,
                    ))
                },
            )
            .optional()?;

        let Some((invocation_count, total_cost_exposed, total_cost_realized_spend)) = current
        else {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "missing charged budget row".to_string(),
            ));
        };
        if invocation_count == 0 {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot capture charge with zero invocation_count".to_string(),
            ));
        }
        if total_cost_exposed < request.exposed_cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(
                "cannot capture more exposure than total_cost_exposed".to_string(),
            ));
        }

        let total_cost_exposed_after = total_cost_exposed - request.exposed_cost_units;
        let total_cost_realized_spend_after = total_cost_realized_spend
            .checked_add(request.realized_spend_units)
            .ok_or_else(|| {
                BudgetStoreError::Overflow(
                    "total_cost_realized_spend + realized_spend_units overflowed u64".to_string(),
                )
            })?;
        let committed_cost_units_after = checked_committed_cost_units(
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        let seq = allocate_budget_replication_seq(&transaction)?;
        let seq_i64 = i64::try_from(seq).map_err(|_| {
            BudgetStoreError::Overflow("budget sequence exceeds SQLite INTEGER".to_string())
        })?;
        let total_cost_exposed_after_i64 =
            i64::try_from(total_cost_exposed_after).map_err(|_| {
                BudgetStoreError::Overflow(
                    "captured exposure total exceeds SQLite INTEGER".to_string(),
                )
            })?;
        let total_cost_realized_spend_after_i64 = i64::try_from(total_cost_realized_spend_after)
            .map_err(|_| {
                BudgetStoreError::Overflow(
                    "captured realized spend exceeds SQLite INTEGER".to_string(),
                )
            })?;
        transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5,
                total_cost_realized_spend = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
            "#,
            params![
                request.capability_id,
                grant_index_i64,
                unix_now(),
                seq_i64,
                total_cost_exposed_after_i64,
                total_cost_realized_spend_after_i64,
            ],
        )?;
        if let Some(hold_id) = request.hold_id.as_deref() {
            let next_authority = SqliteBudgetStore::validate_hold_authority(
                hold_id,
                SqliteBudgetStore::ensure_open_hold(
                    &transaction,
                    hold_id,
                    &request.capability_id,
                    request.grant_index,
                )?
                .authority
                .as_ref(),
                request.authority.as_ref(),
            )?;
            SqliteBudgetStore::update_hold(
                &transaction,
                hold_id,
                0,
                HoldDisposition::Captured,
                next_authority.as_ref(),
            )?;
        }
        SqliteBudgetStore::append_mutation_event(
            &transaction,
            request.event_id.as_deref(),
            request.hold_id.as_deref(),
            request.authority.as_ref(),
            &request.capability_id,
            request.grant_index,
            BudgetMutationKind::CaptureExposure,
            None,
            seq,
            Some(seq),
            request.exposed_cost_units,
            request.realized_spend_units,
            None,
            None,
            None,
            invocation_count,
            total_cost_exposed_after,
            total_cost_realized_spend_after,
        )?;
        transaction.commit()?;

        Ok(BudgetHoldMutationDecision {
            hold_id: request.hold_id,
            exposure_units: request.exposed_cost_units,
            realized_spend_units: request.realized_spend_units,
            committed_cost_units_after,
            invocation_count_after: invocation_count,
            invocation_counts_after: Vec::new(),
            invocation_state: BudgetInvocationReservationState::Absent,
            monetary_state: BudgetMonetaryHoldState::Captured,
            revocation_set: None,
            metadata: BudgetCommitMetadata {
                authority: request.authority,
                guarantee_level: self.budget_guarantee_level(),
                budget_profile: self.budget_authority_profile(),
                metering_profile: self.budget_metering_profile(),
                budget_commit_index: Some(seq),
                event_id: request.event_id,
            },
        })
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
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
        let rows = statement.query_map(params![capability_id, limit as i64], record_from_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.connection()?
            .query_row(
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
                params![capability_id, grant_index as i64],
                record_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
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
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR grant_index = ?2)
            ORDER BY event_seq ASC
            LIMIT ?3
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                grant_index.map(|value| value as i64),
                limit as i64
            ],
            mutation_record_from_row,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn effective_hold_event_id(requested: Option<&str>, kind: BudgetMutationKind) -> String {
    requested.map_or_else(
        || format!("sqlite-budget-{}-{}", kind.as_str(), uuid::Uuid::now_v7()),
        ToOwned::to_owned,
    )
}

fn load_authorize_decision_for_event(
    store: &SqliteBudgetStore,
    event_id: &str,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let record =
        SqliteBudgetStore::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` disappeared after authorization"
            ))
        })?;
    transaction.rollback()?;
    authorize_decision_from_record(store, &record)
}

fn authorize_decision_from_record(
    store: &SqliteBudgetStore,
    record: &BudgetMutationRecord,
) -> Result<BudgetAuthorizeHoldDecision, BudgetStoreError> {
    if record.kind != BudgetMutationKind::AuthorizeExposure {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{}` is not a persisted authorization",
            record.event_id
        )));
    }
    let allowed = record.allowed.ok_or_else(|| {
        BudgetStoreError::Invariant(format!(
            "budget authorization event `{}` is missing its frozen decision",
            record.event_id
        ))
    })?;
    let committed_cost_units_after = checked_committed_cost_units(
        record.total_cost_exposed_after,
        record.total_cost_realized_spend_after,
    )?;
    let metadata = BudgetCommitMetadata {
        authority: record.authority.clone(),
        guarantee_level: store.budget_guarantee_level(),
        budget_profile: store.budget_authority_profile(),
        metering_profile: store.budget_metering_profile(),
        budget_commit_index: record.usage_seq,
        event_id: Some(record.event_id.clone()),
    };
    if allowed {
        let monetary_state = if record.exposure_units > 0
            || record.max_cost_per_invocation.is_some()
            || record.max_total_cost_units.is_some()
        {
            BudgetMonetaryHoldState::Exposed
        } else {
            BudgetMonetaryHoldState::None
        };
        Ok(BudgetAuthorizeHoldDecision::Authorized(
            AuthorizedBudgetHold {
                hold_id: record.hold_id.clone(),
                authorized_exposure_units: record.exposure_units,
                committed_cost_units_after,
                invocation_count_after: record.invocation_count_after,
                invocation_counts_after: record.invocation_counts_after.clone(),
                invocation_state: BudgetInvocationReservationState::Absent,
                monetary_state,
                revocation_set: record.revocation_set.clone(),
                metadata,
            },
        ))
    } else {
        Ok(BudgetAuthorizeHoldDecision::Denied(DeniedBudgetHold {
            hold_id: record.hold_id.clone(),
            attempted_exposure_units: record.exposure_units,
            committed_cost_units_after,
            invocation_count_after: record.invocation_count_after,
            invocation_counts_after: record.invocation_counts_after.clone(),
            invocation_state: BudgetInvocationReservationState::Denied,
            monetary_state: BudgetMonetaryHoldState::None,
            revocation_set: record.revocation_set.clone(),
            metadata,
        }))
    }
}

fn load_hold_decision_for_event(
    store: &SqliteBudgetStore,
    event_id: &str,
    expected_kind: BudgetMutationKind,
    expected_monetary_state: BudgetMonetaryHoldState,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    let mut connection = store.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let record =
        SqliteBudgetStore::load_mutation_event(&transaction, event_id)?.ok_or_else(|| {
            BudgetStoreError::Invariant(format!(
                "budget event_id `{event_id}` disappeared after its hold transition"
            ))
        })?;
    transaction.rollback()?;
    hold_decision_from_record(store, &record, expected_kind, expected_monetary_state)
}

fn hold_decision_from_record(
    store: &SqliteBudgetStore,
    record: &BudgetMutationRecord,
    expected_kind: BudgetMutationKind,
    expected_monetary_state: BudgetMonetaryHoldState,
) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
    if record.kind != expected_kind || record.monetary_state != expected_monetary_state {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{}` is not the expected persisted hold transition",
            record.event_id
        )));
    }
    Ok(BudgetHoldMutationDecision {
        hold_id: record.hold_id.clone(),
        exposure_units: record.exposure_units,
        realized_spend_units: record.realized_spend_units,
        committed_cost_units_after: checked_committed_cost_units(
            record.total_cost_exposed_after,
            record.total_cost_realized_spend_after,
        )?,
        invocation_count_after: record.invocation_count_after,
        invocation_counts_after: record.invocation_counts_after.clone(),
        invocation_state: record.invocation_state,
        monetary_state: record.monetary_state,
        revocation_set: record.revocation_set.clone(),
        metadata: BudgetCommitMetadata {
            authority: record.authority.clone(),
            guarantee_level: store.budget_guarantee_level(),
            budget_profile: store.budget_authority_profile(),
            metering_profile: store.budget_metering_profile(),
            budget_commit_index: record.usage_seq,
            event_id: Some(record.event_id.clone()),
        },
    })
}

fn capture_decision_from_record(
    store: &SqliteBudgetStore,
    record: &BudgetMutationRecord,
) -> Result<BudgetCaptureHoldDecision, BudgetStoreError> {
    if record.kind != BudgetMutationKind::CaptureExposure
        || record.monetary_state != BudgetMonetaryHoldState::Captured
    {
        return Err(BudgetStoreError::Invariant(format!(
            "budget event_id `{}` is not a captured monetary hold",
            record.event_id
        )));
    }
    hold_decision_from_record(
        store,
        record,
        BudgetMutationKind::CaptureExposure,
        BudgetMonetaryHoldState::Captured,
    )
}
