#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
//! Terminal transitions for holds authorized without an admission binding.
use super::*;

impl SqliteBudgetStore {
    pub(super) fn reverse_unbound_hold(
        &self,
        request: &BudgetReverseHoldRequest,
    ) -> Result<(), BudgetStoreError> {
        let capability_id = request.capability_id.as_str();
        let grant_index = request.grant_index;
        let cost_units = request.reversed_exposure_units;
        let hold_id = request.hold_id.as_str();
        let event_id = request.event_id.as_str();
        let authority = request.authority.as_ref();
        self.require_standalone_mutation("unbound hold reversal")?;
        validate_budget_grant_index(grant_index)?;
        budget_u64_to_sqlite(cost_units, "exposure_units")?;
        if let Some(authority) = authority {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_unbound_writer(&transaction, hold_id, "hold reversal")?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReverseExposure,
            capability_id,
            grant_index,
            Some(hold_id),
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
        let hold =
            SqliteBudgetStore::ensure_open_hold(&transaction, hold_id, capability_id, grant_index)?;
        if hold.remaining_exposure_units != cost_units
            || !hold.invocation_count_debited
            || hold.invocation_captured
        {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match reverse amount"
            )));
        }
        let next_authority = SqliteBudgetStore::validate_hold_authority(
            hold_id,
            hold.authority.as_ref(),
            authority,
        )?;

        let current = transaction
            .prepare_cached(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
            )?
            .query_row(
                params![
                    capability_id,
                    crate::integer::checked::<_, i64>(grant_index)?
                ],
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

        let new_total_cost_exposed = ExposureUnits::new(total_cost_exposed)
            .try_sub(ExposureUnits::new(cost_units))?
            .get();
        let seq = allocate_budget_replication_seq(&transaction)?;
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
                capability_id,
                crate::integer::checked::<_, i64>(grant_index)?,
                InvocationCount::new(invocation_count)
                    .try_sub(InvocationCount::new(1))?
                    .get(),
                self.unix_now()?,
                budget_u64_to_sqlite(seq, "seq")?,
                budget_u64_to_sqlite(new_total_cost_exposed, "total_cost_exposed")?,
                i64::from(invocation_count),
                budget_u64_to_sqlite(total_cost_exposed, "previous_exposure")?,
                budget_u64_to_sqlite(total_cost_realized_spend, "previous_spend")?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget usage compare-and-set failed".into(),
            ));
        }
        self.update_hold(
            &transaction,
            hold_id,
            cost_units,
            0,
            HoldDisposition::Reversed,
            next_authority.as_ref(),
        )?;
        self.append_mutation_event(
            &transaction,
            event_id,
            Some(hold_id),
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
            InvocationCount::new(invocation_count)
                .try_sub(InvocationCount::new(1))?
                .get(),
            new_total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn release_unbound_hold(
        &self,
        request: &BudgetReleaseHoldRequest,
    ) -> Result<(), BudgetStoreError> {
        let capability_id = request.capability_id.as_str();
        let grant_index = request.grant_index;
        let cost_units = request.released_exposure_units;
        let hold_id = request.hold_id.as_str();
        let event_id = request.event_id.as_str();
        let authority = request.authority.as_ref();
        self.require_standalone_mutation("unbound hold release")?;
        validate_budget_grant_index(grant_index)?;
        budget_u64_to_sqlite(cost_units, "exposure_units")?;
        if let Some(authority) = authority {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_unbound_writer(&transaction, hold_id, "hold release")?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReleaseExposure,
            capability_id,
            grant_index,
            Some(hold_id),
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
        let hold =
            SqliteBudgetStore::ensure_open_hold(&transaction, hold_id, capability_id, grant_index)?;
        if hold.invocation_captured {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation was already captured"
            )));
        }
        if hold.remaining_exposure_units < cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` cannot release more than remaining exposure"
            )));
        }
        let next_authority = SqliteBudgetStore::validate_hold_authority(
            hold_id,
            hold.authority.as_ref(),
            authority,
        )?;

        let current = transaction
            .prepare_cached(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
            )?
            .query_row(
                params![
                    capability_id,
                    crate::integer::checked::<_, i64>(grant_index)?
                ],
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

        let new_total_cost_exposed = ExposureUnits::new(total_cost_exposed)
            .try_sub(ExposureUnits::new(cost_units))?
            .get();
        let seq = allocate_budget_replication_seq(&transaction)?;
        let changed = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5
            WHERE capability_id = ?1 AND grant_index = ?2
              AND invocation_count = ?6
              AND total_cost_exposed = ?7
              AND total_cost_realized_spend = ?8
            "#,
            params![
                capability_id,
                crate::integer::checked::<_, i64>(grant_index)?,
                self.unix_now()?,
                budget_u64_to_sqlite(seq, "seq")?,
                budget_u64_to_sqlite(new_total_cost_exposed, "total_cost_exposed")?,
                i64::from(invocation_count),
                budget_u64_to_sqlite(total_cost_exposed, "previous_exposure")?,
                budget_u64_to_sqlite(total_cost_realized_spend, "previous_spend")?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget usage compare-and-set failed".into(),
            ));
        }
        let remaining = ExposureUnits::new(hold.remaining_exposure_units)
            .try_sub(ExposureUnits::new(cost_units))?
            .get();
        let disposition = if remaining == 0 {
            HoldDisposition::Released
        } else {
            HoldDisposition::Open
        };
        self.update_hold(
            &transaction,
            hold_id,
            cost_units,
            remaining,
            disposition,
            next_authority.as_ref(),
        )?;
        self.append_mutation_event(
            &transaction,
            event_id,
            Some(hold_id),
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

    pub(super) fn reconcile_unbound_hold(
        &self,
        request: &BudgetReconcileHoldRequest,
    ) -> Result<(), BudgetStoreError> {
        let capability_id = request.capability_id.as_str();
        let grant_index = request.grant_index;
        let exposed_cost_units = request.exposed_cost_units;
        let realized_cost_units = request.realized_spend_units;
        let hold_id = request.hold_id.as_str();
        let event_id = request.event_id.as_str();
        let authority = request.authority.as_ref();
        self.require_standalone_mutation("unbound hold reconciliation")?;
        validate_budget_grant_index(grant_index)?;
        if realized_cost_units > exposed_cost_units {
            return Err(BudgetStoreError::Invariant(
                "cannot realize spend larger than exposed cost".to_string(),
            ));
        }
        budget_u64_to_sqlite(exposed_cost_units, "exposure_units")?;
        budget_u64_to_sqlite(realized_cost_units, "realized_spend_units")?;
        if let Some(authority) = authority {
            budget_u64_to_sqlite(authority.lease_epoch, "lease_epoch")?;
        }

        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_structured_hold_from_unbound_writer(
            &transaction,
            hold_id,
            "hold reconciliation",
        )?;

        if SqliteBudgetStore::existing_event_allowed(
            &transaction,
            event_id,
            BudgetMutationKind::ReconcileSpend,
            capability_id,
            grant_index,
            Some(hold_id),
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
        let hold =
            SqliteBudgetStore::ensure_open_hold(&transaction, hold_id, capability_id, grant_index)?;
        if !hold.invocation_captured {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` invocation was not captured before reconciliation"
            )));
        }
        if hold.remaining_exposure_units != exposed_cost_units {
            transaction.rollback()?;
            return Err(BudgetStoreError::Invariant(format!(
                "budget hold `{hold_id}` does not match reconciled exposure"
            )));
        }
        let next_authority = SqliteBudgetStore::validate_hold_authority(
            hold_id,
            hold.authority.as_ref(),
            authority,
        )?;

        let current = transaction
            .prepare_cached(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
            )?
            .query_row(
                params![
                    capability_id,
                    crate::integer::checked::<_, i64>(grant_index)?
                ],
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

        let balance = ExposureBalance::new(total_cost_exposed, total_cost_realized_spend)?.settle(
            ExposureUnits::new(exposed_cost_units),
            ExposureUnits::new(realized_cost_units),
        )?;
        let new_total_cost_exposed = balance.exposed();
        let new_total_cost_realized_spend = balance.spent();
        budget_u64_to_sqlite(new_total_cost_realized_spend, "total_cost_realized_spend")?;

        let seq = allocate_budget_replication_seq(&transaction)?;
        let changed = transaction.execute(
            r#"
            UPDATE capability_grant_budgets
            SET updated_at = ?3,
                seq = ?4,
                total_cost_exposed = ?5,
                total_cost_realized_spend = ?6
            WHERE capability_id = ?1 AND grant_index = ?2
              AND invocation_count = ?7
              AND total_cost_exposed = ?8
              AND total_cost_realized_spend = ?9
            "#,
            params![
                capability_id,
                crate::integer::checked::<_, i64>(grant_index)?,
                self.unix_now()?,
                budget_u64_to_sqlite(seq, "seq")?,
                budget_u64_to_sqlite(new_total_cost_exposed, "total_cost_exposed")?,
                budget_u64_to_sqlite(new_total_cost_realized_spend, "total_cost_realized_spend",)?,
                i64::from(invocation_count),
                budget_u64_to_sqlite(total_cost_exposed, "previous_exposure")?,
                budget_u64_to_sqlite(total_cost_realized_spend, "previous_spend")?,
            ],
        )?;
        if changed != 1 {
            return Err(BudgetStoreError::Invariant(
                "budget usage compare-and-set failed".into(),
            ));
        }
        self.update_hold(
            &transaction,
            hold_id,
            exposed_cost_units,
            0,
            HoldDisposition::Reconciled,
            next_authority.as_ref(),
        )?;
        self.append_mutation_event(
            &transaction,
            event_id,
            Some(hold_id),
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
}
