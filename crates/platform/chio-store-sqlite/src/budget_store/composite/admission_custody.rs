//! Read physical custody by the operation's own hold identity.
use super::*;
use crate::admission_operation_store::AdmissionBudgetCustodySnapshot;
use chio_kernel::admission_operation::AdmissionOperationV1;

impl SqliteBudgetStore {
    pub(crate) fn load_admission_budget_custody_tx(
        transaction: &Transaction<'_>,
        operation: &AdmissionOperationV1,
    ) -> Result<Option<AdmissionBudgetCustodySnapshot>, BudgetStoreError> {
        let Some(hold_id) = operation.budget_hold_id() else {
            return Ok(None);
        };
        let hold = load_structured_hold(transaction, hold_id.as_str())?.ok_or_else(|| {
            BudgetStoreError::Invariant("admission lost its physical composite hold".into())
        })?;
        if hold.hold_id != hold_id.as_str()
            || hold.capability_id != operation.binding().capability_id().as_str()
            || hold.admission.operation_id != operation.binding().operation_id().as_str()
        {
            return Err(BudgetStoreError::Invariant(
                "physical budget custody belongs to another admission".into(),
            ));
        }
        verify_committed_custody(transaction, &hold)?;
        Ok(Some(AdmissionBudgetCustodySnapshot {
            hold_id: hold.hold_id,
            capability_id: hold.capability_id,
            grant_index: hold.grant_index,
            admission: hold.admission,
            invocation_quotas: hold.quotas,
            invocation_state: hold.invocation_state,
            monetary_state: hold.monetary_state,
        }))
    }
}

fn verify_committed_custody(
    transaction: &Transaction<'_>,
    hold: &StructuredHold,
) -> Result<(), BudgetStoreError> {
    let mut statement = transaction.prepare(
        "WITH latest AS (
           SELECT * FROM budget_mutation_events
           WHERE hold_id = ?1 AND allowed IS NOT 0
           ORDER BY event_seq DESC LIMIT 1
         )
         SELECT CASE WHEN length(CAST(event.event_id AS BLOB)) BETWEEN 1 AND 1024
                     THEN event.event_id END,
                event.event_seq,
                CASE WHEN length(CAST(global.projection_reference_digest AS BLOB)) = 64
                     THEN global.projection_reference_digest END
         FROM latest AS event
         JOIN authority_global_commits AS global
           ON global.projection_kind = 'budget'
          AND global.projection_key = event.event_id
          AND global.projection_sequence = event.event_seq
          AND global.mutation_kind = event.kind
          AND global.store_uuid = event.authority_id
          AND global.store_lease_id = event.lease_id
          AND global.store_owner_epoch = event.lease_epoch
         LIMIT 2",
    )?;
    let mut rows = statement.query([&hold.hold_id])?;
    let row = rows
        .next()?
        .ok_or_else(|| invalid("missing original budget commitment"))?;
    let event_id = row
        .get::<_, Option<String>>(0)?
        .ok_or_else(|| invalid("invalid budget event identity"))?;
    let sequence = u64::try_from(row.get::<_, i64>(1)?)
        .map_err(|_| invalid("invalid budget event sequence"))?;
    let digest = row
        .get::<_, Option<String>>(2)?
        .ok_or_else(|| invalid("invalid budget event digest"))?;
    if sequence == 0 || rows.next()?.is_some() {
        return Err(invalid("ambiguous original budget commitment"));
    }
    drop(rows);
    drop(statement);
    let actual =
        crate::serving_owner::budget_event_reference_digest(transaction, &event_id, sequence)
            .map_err(|_| invalid("budget event is not authenticated"))?;
    if actual != digest {
        return Err(invalid("budget event differs from its commitment"));
    }
    let event = SqliteBudgetStore::load_projected_mutation_event(transaction, &event_id)?
        .ok_or_else(|| invalid("missing original budget event"))?;
    if event.hold_id.as_ref() != Some(&hold.hold_id)
        || event.capability_id != hold.capability_id
        || usize::try_from(event.grant_index).ok() != Some(hold.grant_index)
        || event.admission_binding.as_ref() != Some(&hold.admission)
        || event.authority != hold.authority
        || event.invocation_state_after != hold.invocation_state
        || event.monetary_state_after != hold.monetary_state
        || !hold.quotas.iter().eq(event
            .invocation_quota_usages
            .iter()
            .map(|usage| &usage.quota))
    {
        return Err(invalid(
            "physical custody differs from its committed budget event",
        ));
    }
    Ok(())
}

fn invalid(detail: &str) -> BudgetStoreError {
    BudgetStoreError::Invariant(format!("admission budget readback: {detail}"))
}
