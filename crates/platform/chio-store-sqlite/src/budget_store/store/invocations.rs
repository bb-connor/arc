use super::*;

impl SqliteBudgetStore {
    pub fn try_increment_with_event_id(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.require_standalone_mutation("unbound invocation increment")?;
        validate_budget_grant_index(grant_index)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        Self::reject_legacy_admission_after_composite_history(
            &transaction,
            capability_id,
            grant_index,
        )?;

        if let Some(allowed) = SqliteBudgetStore::existing_increment_allowed(
            &transaction,
            event_id,
            capability_id,
            grant_index,
            max_invocations,
        )? {
            transaction.rollback()?;
            return Ok(allowed);
        }

        let current: Option<(u32, u64, u64)> = transaction
            .query_row(
                r#"
                SELECT invocation_count, total_cost_exposed, total_cost_realized_spend
                FROM capability_grant_budgets
                WHERE capability_id = ?1 AND grant_index = ?2
                "#,
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
        let (current, total_cost_exposed, total_cost_realized_spend) = current.unwrap_or((0, 0, 0));
        let updated_at = self.unix_now()?;

        let allowed = budget_increment_admits(current, max_invocations);
        if !allowed {
            let event_seq = allocate_budget_replication_seq(&transaction)?;
            self.append_mutation_event(
                &transaction,
                event_id,
                None,
                None,
                capability_id,
                grant_index,
                BudgetMutationKind::IncrementInvocation,
                Some(false),
                event_seq,
                None,
                0,
                0,
                max_invocations,
                None,
                None,
                current,
                total_cost_exposed,
                total_cost_realized_spend,
            )?;
            transaction.commit()?;
            return Ok(false);
        }

        let invocation_count_after = current.checked_add(1).ok_or_else(|| {
            BudgetStoreError::Overflow("invocation count overflowed u32".to_string())
        })?;
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
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)
            ON CONFLICT(capability_id, grant_index) DO UPDATE SET
                invocation_count = excluded.invocation_count,
                updated_at = excluded.updated_at,
                seq = excluded.seq
            "#,
            params![
                capability_id,
                crate::integer::checked::<_, i64>(grant_index)?,
                i64::from(invocation_count_after),
                updated_at,
                budget_u64_to_sqlite(seq, "seq")?,
            ],
        )?;
        self.append_mutation_event(
            &transaction,
            event_id,
            None,
            None,
            capability_id,
            grant_index,
            BudgetMutationKind::IncrementInvocation,
            Some(true),
            seq,
            Some(seq),
            0,
            0,
            max_invocations,
            None,
            None,
            invocation_count_after,
            total_cost_exposed,
            total_cost_realized_spend,
        )?;
        transaction.commit()?;
        Ok(true)
    }
}
