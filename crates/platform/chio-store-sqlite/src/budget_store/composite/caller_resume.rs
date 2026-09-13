//! Resume an approved caller reservation without replaying its superseded
//! pre-approval authorization event or acquiring another hold.
use super::*;
use chio_kernel::admission_operation::AdmissionOperationState;

impl SqliteBudgetStore {
    pub(super) fn resume_approved_caller_hold(
        &self,
        transaction: &Transaction<'_>,
        original_event: &BudgetMutationRecord,
        binding: AdmissionAuthorizationBinding<'_>,
    ) -> Result<Option<BudgetAuthorizeHoldDecision>, BudgetStoreError> {
        let operation = binding.operation;
        if operation.state() != AdmissionOperationState::ReadyToDispatch
            || !operation
                .provider_attempt()
                .is_some_and(|attempt| attempt.is_caller_report())
            || operation.approval_set_hash().is_none()
        {
            return Ok(None);
        }
        let requirements = operation.binding().participant_requirements();
        if requirements.payment != binding.payment_journal.is_some()
            || requirements.credit_exposure != binding.credit_exposure.is_some()
        {
            return Err(invalid(
                "caller authorization changed its economic participant selection",
            ));
        }
        // This read-only resume path has not qualified a combined threshold
        // approval and credit-facility reservation. Do not bypass the ordinary
        // credit binding and current-authority checks by replaying its budget.
        if requirements.credit_exposure {
            return Err(invalid(
                "approved caller credit exposure requires qualified resume custody",
            ));
        }
        if let Some(journal) = binding.payment_journal {
            let original =
                load_payment_journal(transaction, operation.binding().operation_id().as_str())?
                    .ok_or_else(|| {
                        invalid("caller authorization lost its original payment journal")
                    })?;
            if !original.matches_hold_replay(journal) {
                return Err(invalid(
                    "caller authorization changed its original payment journal",
                ));
            }
        }
        let hold_id = original_event
            .hold_id
            .as_deref()
            .ok_or_else(|| invalid("caller authorization lost hold identity"))?;
        let hold = load_structured_hold(transaction, hold_id)?
            .ok_or_else(|| invalid("caller authorization lost physical hold"))?;
        let Some((_, state, approval_digest)) = &hold.cumulative else {
            return Ok(None);
        };
        if *state != BudgetCumulativeApprovalState::Authorized
            || approval_digest.as_deref() != operation.approval_set_hash().map(|hash| hash.as_str())
            || hold.invocation_state != BudgetInvocationState::Authorized
            || hold.admission.operation_id != operation.binding().operation_id().as_str()
            || hold.capability_id != operation.binding().capability_id().as_str()
            || operation
                .budget_hold_id()
                .is_none_or(|id| id.as_str() != hold_id)
        {
            return Err(invalid(
                "caller authorization changed its approved physical custody",
            ));
        }
        // Replaying an already approved hold must preserve the same physical
        // participant checks as ordinary authorization. Kernel capture also
        // checks custody, but it is not a substitute for this store boundary.
        crate::admission_operation_store::verify_runtime_budget_selection_tx(
            transaction,
            operation,
            hold.grant_index,
            chio_kernel::admission_operation::runtime_participant::RuntimeParticipantPhase::Dispatch,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        crate::admission_operation_store::verify_approval_budget_selection_tx(
            transaction,
            operation,
            hold.grant_index,
            chio_kernel::admission_operation::governed_approval_claim::GovernedApprovalClaimPhase::Dispatch,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        crate::admission_operation_store::verify_dpop_budget_selection_tx(
            transaction,
            operation,
            hold.grant_index,
            chio_kernel::admission_operation::dpop_claim::DpopReplayClaimPhase::Dispatch,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        let owner = self
            .serving_owner
            .as_deref()
            .ok_or_else(|| invalid("caller authorization requires its serving owner"))?;
        crate::admission_operation_store::verify_participant_recovery_tx(
            transaction,
            owner,
            operation,
            binding.recovery_lease,
            binding.trusted_now_unix_ms,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        let event_id: String = transaction.query_row(
            "SELECT event_id FROM budget_mutation_events WHERE hold_id = ?1 ORDER BY event_seq DESC LIMIT 1",
            [hold_id], |row| row.get(0),
        )?;
        let latest = Self::load_mutation_event(transaction, &event_id)?
            .ok_or_else(|| invalid("caller approval event is missing"))?;
        if latest.kind != BudgetMutationKind::AuthorizeCumulativeApproval {
            return Err(invalid(
                "caller approval event was superseded by another transition",
            ));
        }
        let approved = transition_decision_from_event(self, transaction, latest)?;
        if approved.hold_id.as_deref() != Some(hold_id)
            || approved.admission_binding.as_ref() != Some(&hold.admission)
            || approved.invocation_state != BudgetInvocationState::Authorized
            || approved
                .cumulative_approval
                .as_ref()
                .is_none_or(|usage| usage.state != BudgetCumulativeApprovalState::Authorized)
        {
            return Err(invalid(
                "caller approval event does not prove current authorization",
            ));
        }
        Ok(Some(BudgetAuthorizeHoldDecision::Authorized(
            AuthorizedBudgetHold {
                hold_id: approved.hold_id,
                admission_binding: approved.admission_binding,
                authorized_exposure_units: hold.authorized_exposure,
                committed_cost_units_after: approved.committed_cost_units_after,
                invocation_count_after: approved.invocation_count_after,
                invocation_quota_usages: approved.invocation_quota_usages,
                cumulative_approval: approved.cumulative_approval,
                invocation_state: approved.invocation_state,
                monetary_state: approved.monetary_state,
                metadata: approved.metadata,
            },
        )))
    }
}

fn invalid(message: &str) -> BudgetStoreError {
    BudgetStoreError::Invariant(message.into())
}
