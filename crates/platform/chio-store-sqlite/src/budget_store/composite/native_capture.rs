//! Bind historical capture accounting to the exact named admission commitment.
use super::*;
use chio_kernel::admission_operation::{AdmissionOperationV1, RetainedToolAdmissionRequestV1};

#[cfg(test)]
mod tests;

impl SqliteBudgetStore {
    pub(crate) fn load_native_capture_decision_tx(
        &self,
        transaction: &Transaction<'_>,
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
    ) -> Result<BudgetHoldMutationDecision, BudgetStoreError> {
        let dispatch = operation
            .dispatch_commit()
            .ok_or_else(|| invalid("missing dispatch commit"))?;
        let hold = operation
            .budget_hold_id()
            .ok_or_else(|| invalid("missing capture hold"))?;
        // Do not choose the latest event or trust the acknowledgement's event
        // identifier. Follow the named participant of this exact dispatch version.
        // LIMIT 2 detects ambiguous references without unbounded result allocation.
        let mut statement = transaction.prepare(
            "SELECT CASE WHEN length(CAST(budget.projection_key AS BLOB)) BETWEEN 1 AND 1024 THEN budget.projection_key END,
                    budget.projection_sequence,
                    CASE WHEN length(CAST(budget.projection_reference_digest AS BLOB)) = 64 THEN budget.projection_reference_digest END
             FROM admission_operation_commits AS admission
             JOIN authority_global_commits AS budget
               ON budget.projection_reference_digest = admission.participant_digest
              AND budget.projection_kind = 'budget'
             WHERE admission.operation_id = ?1 AND admission.operation_version = ?2
               AND admission.mutation_kind = 'compare_and_swap'
               AND budget.mutation_kind = 'capture_invocation'
               AND admission.store_uuid = ?3 AND admission.store_lease_id = ?4
               AND admission.store_owner_epoch = ?5
               AND budget.store_uuid = admission.store_uuid
               AND budget.store_lease_id = admission.store_lease_id
               AND budget.store_owner_epoch = admission.store_owner_epoch
             LIMIT 2",
        )?;
        let mut rows = statement.query(params![
            operation.binding().operation_id().as_str(),
            budget_u64_to_sqlite(dispatch.committed_version, "dispatch_version")?,
            dispatch.store_fence.store_uuid,
            dispatch.store_fence.lease_id,
            budget_u64_to_sqlite(dispatch.store_fence.owner_epoch, "dispatch_owner_epoch")?,
        ])?;
        let row = rows
            .next()?
            .ok_or_else(|| invalid("missing budget commitment"))?;
        let event_id: Option<String> = row.get(0)?;
        let event_id =
            event_id.ok_or_else(|| invalid("capture event identifier exceeds its bound"))?;
        let sequence: i64 = row.get(1)?;
        let sequence =
            u64::try_from(sequence).map_err(|_| invalid("invalid capture event sequence"))?;
        let digest: Option<String> = row.get(2)?;
        let digest =
            digest.ok_or_else(|| invalid("capture projection digest exceeds its bound"))?;
        if rows.next()?.is_some() {
            return Err(invalid("ambiguous capture budget commitment"));
        }
        drop(rows);
        drop(statement);
        let actual_digest =
            crate::serving_owner::budget_event_reference_digest(transaction, &event_id, sequence)
                .map_err(|error| BudgetStoreError::Invariant(error.to_string()))?;
        if actual_digest != digest {
            return Err(invalid(
                "capture budget projection differs from its admission commitment",
            ));
        }
        let event = Self::load_projected_mutation_event(transaction, &event_id)?
            .ok_or_else(|| invalid("missing committed capture event"))?;
        let physical_hold = load_structured_hold(transaction, hold.as_str())?
            .ok_or_else(|| invalid("missing physical capture hold"))?;
        let grant_index = usize::try_from(event.grant_index)
            .map_err(|_| invalid("capture grant index exceeds its bound"))?;
        let authority = BudgetEventAuthority {
            authority_id: dispatch.store_fence.store_uuid.clone(),
            lease_id: dispatch.store_fence.lease_id.clone(),
            lease_epoch: dispatch.store_fence.owner_epoch,
        };
        if event.kind != BudgetMutationKind::CaptureInvocation
            || event.allowed != Some(true)
            || event.event_id != event_id
            || event.hold_id.as_deref() != Some(hold.as_str())
            || event.capability_id != operation.binding().capability_id().as_str()
            || event.admission_binding.as_ref().is_none_or(|binding| {
                binding.operation_id != operation.binding().operation_id().as_str()
            })
            || original.retained_matching_grant(grant_index).is_none()
            || physical_hold.grant_index != grant_index
            || physical_hold.capability_id != event.capability_id
            || physical_hold.admission.operation_id != operation.binding().operation_id().as_str()
            || event.authority.as_ref() != Some(&authority)
            || event.invocation_state_before != BudgetInvocationState::Authorized
            || event.invocation_state_after != BudgetInvocationState::Captured
            || event.monetary_state_before != event.monetary_state_after
            || event.realized_spend_units != 0
            || event.event_seq == 0
            || event.event_seq != sequence
            || event.recorded_at < 0
        {
            return Err(invalid("capture event differs from its original dispatch"));
        }
        verify_capture_quota_delta(
            &event.invocation_quota_usages,
            &event.invocation_quota_mutations,
        )?;
        verify_capture_cumulative_delta(
            event.cumulative_approval.as_ref(),
            event.cumulative_approval_mutation.as_ref(),
        )?;
        transition_decision_from_event(self, transaction, event)
    }
}

fn verify_capture_quota_delta(
    usages: &[BudgetInvocationQuotaUsage],
    mutations: &[BudgetInvocationQuotaMutation],
) -> Result<(), BudgetStoreError> {
    if mutations.len() != usages.len()
        || usages.len() > chio_kernel::budget_store::MAX_INVOCATION_QUOTAS_PER_ADMISSION
    {
        return Err(invalid("capture quota projection is incomplete"));
    }
    let mut keys = std::collections::BTreeSet::new();
    for (mutation, usage) in mutations.iter().zip(usages) {
        usage.validate()?;
        if !keys.insert(&usage.quota.key)
            || mutation.quota != usage.quota
            || mutation.reserved_invocations_before.checked_sub(1)
                != Some(mutation.reserved_invocations_after)
            || mutation.captured_invocations_before.checked_add(1)
                != Some(mutation.captured_invocations_after)
            || usage.reserved_invocations != mutation.reserved_invocations_after
            || usage.captured_invocations != mutation.captured_invocations_after
        {
            return Err(invalid(
                "capture quota delta differs from one owned invocation",
            ));
        }
    }
    Ok(())
}

fn verify_capture_cumulative_delta(
    usage: Option<&BudgetCumulativeApprovalUsage>,
    mutation: Option<&BudgetCumulativeApprovalMutation>,
) -> Result<(), BudgetStoreError> {
    match (usage, mutation) {
        (None, None) => Ok(()),
        (Some(usage), Some(mutation)) => {
            let amount = &usage.requested_authorized;
            if usage.state != BudgetCumulativeApprovalState::Captured
                || amount.currency != usage.account_key.currency
                || mutation.state_before != Some(BudgetCumulativeApprovalState::Authorized)
                || mutation.state_after != BudgetCumulativeApprovalState::Captured
                || mutation.operation_id != usage.operation_id
                || mutation.account_key != usage.account_key
                || mutation.reserved_authorized_before.currency != amount.currency
                || mutation.captured_authorized_before.currency != amount.currency
                || mutation.reserved_authorized_after.currency != amount.currency
                || mutation.captured_authorized_after.currency != amount.currency
                || mutation
                    .reserved_authorized_before
                    .units
                    .checked_sub(amount.units)
                    != Some(mutation.reserved_authorized_after.units)
                || mutation
                    .captured_authorized_before
                    .units
                    .checked_add(amount.units)
                    != Some(mutation.captured_authorized_after.units)
                || mutation.version_before.checked_add(1) != Some(mutation.version_after)
                || usage.version != mutation.version_after
                || usage.reserved_authorized_after != mutation.reserved_authorized_after
                || usage.captured_authorized_after != mutation.captured_authorized_after
            {
                return Err(invalid("capture cumulative approval delta differs"));
            }
            Ok(())
        }
        _ => Err(invalid(
            "capture cumulative approval projection is incomplete",
        )),
    }
}

fn invalid(detail: &str) -> BudgetStoreError {
    BudgetStoreError::Invariant(format!("native capture readback: {detail}"))
}
