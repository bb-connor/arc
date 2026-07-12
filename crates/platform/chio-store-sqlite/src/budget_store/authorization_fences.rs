use super::*;

impl SqliteBudgetStore {
    pub(super) fn rollback_event_exists_for_generation(
        transaction: &rusqlite::Transaction<'_>,
        authorize: &BudgetMutationRecord,
    ) -> Result<bool, BudgetStoreError> {
        let rollback_event_id = format!("{}:rollback:{}", authorize.event_id, authorize.event_seq);
        let Some(rollback) = Self::load_mutation_event(transaction, &rollback_event_id)? else {
            return Ok(false);
        };
        let valid_disposition = match rollback.kind {
            BudgetMutationKind::ReverseExposure => rollback.allowed.is_none(),
            BudgetMutationKind::CancelCapturedBeforeDispatch => rollback.allowed == Some(true),
            _ => false,
        };
        Ok(valid_disposition
            && rollback.hold_id == authorize.hold_id
            && rollback.capability_id == authorize.capability_id
            && rollback.grant_index == authorize.grant_index
            && rollback.exposure_units == authorize.exposure_units
            && rollback.realized_spend_units == 0
            && rollback.event_seq > authorize.event_seq
            && rollback.authority == authorize.authority)
    }

    pub(super) fn legacy_latest_rollback_matches_reversed_hold(
        transaction: &rusqlite::Transaction<'_>,
        authorize_event_id: &str,
        hold_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        let Some(hold_id) = hold_id else {
            return Ok(false);
        };
        if !Self::load_hold(transaction, hold_id)?
            .is_some_and(|hold| hold.disposition == HoldDisposition::Reversed)
        {
            return Ok(false);
        }
        Self::latest_rollback_matches_authorize(transaction, authorize_event_id, hold_id)
    }

    fn latest_rollback_matches_authorize(
        transaction: &rusqlite::Transaction<'_>,
        authorize_event_id: &str,
        hold_id: &str,
    ) -> Result<bool, BudgetStoreError> {
        let Some(authorize) = Self::load_mutation_event(transaction, authorize_event_id)? else {
            return Ok(false);
        };
        let latest_reverse_id = transaction
            .query_row(
                r#"
                SELECT event_id FROM budget_mutation_events
                WHERE hold_id = ?1 AND kind = ?2
                ORDER BY event_seq DESC LIMIT 1
                "#,
                params![hold_id, BudgetMutationKind::ReverseExposure.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(latest_reverse_id) = latest_reverse_id else {
            return Ok(false);
        };
        let prefix = format!("{authorize_event_id}:rollback:");
        if !latest_reverse_id.starts_with(&prefix) {
            return Ok(false);
        }
        let Some(reverse) = Self::load_mutation_event(transaction, &latest_reverse_id)? else {
            return Ok(false);
        };
        Ok(reverse.kind == BudgetMutationKind::ReverseExposure
            && reverse.hold_id == authorize.hold_id
            && reverse.capability_id == authorize.capability_id
            && reverse.grant_index == authorize.grant_index
            && reverse.allowed.is_none()
            && reverse.exposure_units == authorize.exposure_units
            && reverse.realized_spend_units == 0
            && reverse.authority == authorize.authority
            && reverse.event_seq > authorize.event_seq)
    }

    pub(super) fn rolled_back_authorize_can_be_replaced(
        transaction: &rusqlite::Transaction<'_>,
        existing: &BudgetMutationRecord,
        replacement: &BudgetMutationRecord,
    ) -> Result<bool, BudgetStoreError> {
        if existing.kind != BudgetMutationKind::AuthorizeExposure
            || replacement.kind != BudgetMutationKind::AuthorizeExposure
            || existing.allowed != Some(true)
            || replacement.allowed != Some(true)
        {
            return Ok(false);
        }
        let same_mutation_scope = existing.hold_id == replacement.hold_id
            && existing.capability_id == replacement.capability_id
            && existing.grant_index == replacement.grant_index
            && existing.exposure_units == replacement.exposure_units
            && existing.realized_spend_units == replacement.realized_spend_units
            && existing.max_invocations == replacement.max_invocations
            && existing.max_cost_per_invocation == replacement.max_cost_per_invocation
            && existing.max_total_cost_units == replacement.max_total_cost_units;
        if !same_mutation_scope {
            return Ok(false);
        }
        Self::rollback_event_exists_for_generation(transaction, existing)
    }
}
