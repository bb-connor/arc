//! Startup recovery of retained admission operations.
//!
//! Every non-terminal operation left by a previous coordinator is either
//! terminalized with an unknown outcome, compensated before dispatch, or
//! finalized from its durable tool return. Nothing here redispatches.

use super::*;
use crate::budget_store::BudgetReverseHoldRequest;

impl ChioKernel {
    /// Reverse the executable budget hold a retained pre-dispatch operation still
    /// owns. A crash between authorization and the terminal projection leaves
    /// that hold reserved; compensation must release it physically before it can
    /// claim no effect. A hold the live path already reversed needs nothing, so
    /// repeated recovery is idempotent, and the recovery rollback event is
    /// deterministic for the same hold.
    pub(super) fn release_retained_executable_hold(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<(), KernelError> {
        let Some(hold_id) = operation.budget_hold_id() else {
            return Ok(());
        };
        if operation.dispatch_commit().is_some() {
            return Err(KernelError::DurableAdmission(
                "committed dispatch holds are never reversed by recovery".to_owned(),
            ));
        }
        let hold_id = hold_id.as_str().to_owned();
        let Some(snapshot) =
            self.with_budget_store(|store| Ok(store.get_budget_hold(&hold_id)?))?
        else {
            return Err(KernelError::DurableAdmission(
                "retained executable hold is absent from the budget authority".to_owned(),
            ));
        };
        if snapshot.capability_id != operation.binding().capability_id().as_str() {
            return Err(KernelError::DurableAdmission(
                "retained executable hold belongs to another capability".to_owned(),
            ));
        }
        if !snapshot.disposition.is_open() {
            return Ok(());
        }
        let authority = self.durable_runtime()?.authority();
        let request = BudgetReverseHoldRequest {
            capability_id: snapshot.capability_id.clone(),
            grant_index: snapshot.grant_index,
            reversed_exposure_units: snapshot.remaining_exposure_units,
            hold_id: Some(hold_id.clone()),
            event_id: Some(format!("{hold_id}:authorize:rollback:recovery")),
            expected_cumulative_approval_state: None,
            authority: Some(authority),
        };
        self.with_budget_store(|store| Ok(store.reverse_budget_hold(request)?))?;
        Ok(())
    }

    pub fn reconcile_durable_admission_startup(&self) -> Result<usize, KernelError> {
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(0);
        };
        let mut reconciled = runtime.startup_reconciled.lock().map_err(|_| {
            KernelError::DurableAdmission("startup reconciliation lock is poisoned".to_owned())
        })?;
        if *reconciled {
            return Ok(0);
        }
        let operation_count = self.reconcile_recoverable_admissions()?;
        let finding_pool_receipt_count = self.reconcile_finding_pool_mutation_receipts()?;
        let finding_pool_count = self.reconcile_finding_pool_terminal_claims()?;
        let receipt_count = self.reconcile_durable_admission_receipt_projections()?;
        let total = operation_count
            .checked_add(finding_pool_receipt_count)
            .and_then(|count| count.checked_add(finding_pool_count))
            .and_then(|count| count.checked_add(receipt_count))
            .ok_or_else(|| {
                KernelError::DurableAdmission("startup reconciliation count overflow".to_owned())
            })?;
        *reconciled = true;
        Ok(total)
    }

    pub fn reconcile_recoverable_admissions(&self) -> Result<usize, KernelError> {
        const PAGE_LIMIT: usize = 256;

        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(0);
        };
        let trusted_now_unix_ms = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let mut reconciled = 0_usize;
        // An operation that cannot be reconciled is recorded and skipped rather
        // than abandoning the sweep, so one wedged operation cannot hold up every
        // other recoverable operation. The first failure is still returned once
        // the sweep finishes, so callers keep failing closed on it.
        let mut deferred_failure: Option<KernelError> = None;
        loop {
            let recoverable = runtime
                .store
                .list_recoverable(trusted_now_unix_ms, PAGE_LIMIT)
                .map_err(durable_store_error)?;
            if recoverable.len() > PAGE_LIMIT {
                return Err(KernelError::DurableAdmission(
                    "admission recovery store exceeded the requested page limit".to_owned(),
                ));
            }
            if recoverable.is_empty() {
                break;
            }
            let reconciled_before_page = reconciled;
            for operation in recoverable {
                match operation.state() {
                    AdmissionOperationState::DispatchCommitted => {
                        if let Err(error) = self.terminalize_dispatch_committed_admission(
                            &operation,
                            trusted_now_unix_ms,
                        ) {
                            warn!(
                                operation_id = %operation.binding().operation_id().as_str(),
                                reason = %redacted!(&error),
                                audit_fault = "admission_recovery_terminalization_unresolved",
                                "failed to terminalize a dispatch-committed admission"
                            );
                            deferred_failure.get_or_insert(error);
                            continue;
                        }
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "admission recovery count overflow".to_owned(),
                            )
                        })?;
                    }
                    AdmissionOperationState::Prepared
                        if self
                            .durable_nonce_issuance_is_live(&operation, trusted_now_unix_ms)? =>
                    {
                        // A live issued nonce waits for its execution request.
                        // Compensation follows only once that nonce has expired.
                    }
                    AdmissionOperationState::ReadyToDispatch
                        if self.durable_caller_reservation_is_live(
                            &operation,
                            trusted_now_unix_ms,
                        )? =>
                    {
                        // A caller holds this reservation until its report
                        // arrives or the reserved nonce expires.
                    }
                    AdmissionOperationState::Prepared
                    | AdmissionOperationState::BrokerAttemptRegistered
                    | AdmissionOperationState::BudgetAuthorized
                    | AdmissionOperationState::ApprovalReserved
                    | AdmissionOperationState::ReadyToDispatch
                    | AdmissionOperationState::CapturePending => {
                        // One operation that cannot be compensated must not abandon
                        // the rest of the page: it stays recoverable for a later
                        // sweep, and the remaining operations still reconcile.
                        if let Err(error) = self.compensate_durable_admission_before_dispatch(
                            &operation,
                            serde_json::json!({
                                "authority": "startup-recovery",
                                "cause": "no-authoritative-budget-participant"
                            }),
                            trusted_now_unix_ms,
                            None,
                        ) {
                            warn!(
                                operation_id = %operation.binding().operation_id().as_str(),
                                reason = %redacted!(&error),
                                audit_fault = "admission_recovery_compensation_unresolved",
                                "failed to compensate a recoverable admission"
                            );
                            deferred_failure.get_or_insert(error);
                            continue;
                        }
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "admission recovery count overflow".to_owned(),
                            )
                        })?;
                    }
                    AdmissionOperationState::ApprovalRequired => {
                        let deadline_unix_ms = operation
                            .parked_approval_deadline_unix_ms()
                            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
                        let Some(deadline_unix_ms) =
                            deadline_unix_ms.filter(|deadline| *deadline <= trusted_now_unix_ms)
                        else {
                            deferred_failure.get_or_insert_with(|| {
                                KernelError::DurableAdmission(
                                    "admission recovery store returned a quiescent approval-required operation"
                                        .to_owned(),
                                )
                            });
                            continue;
                        };
                        if let Err(error) = self.compensate_durable_admission_before_dispatch(
                            &operation,
                            serde_json::json!({
                                "authority": "startup-recovery",
                                "cause": "approval-deadline-elapsed",
                                "proposal_deadline_unix_ms": deadline_unix_ms
                            }),
                            trusted_now_unix_ms,
                            None,
                        ) {
                            warn!(
                                operation_id = %operation.binding().operation_id().as_str(),
                                reason = %redacted!(&error),
                                audit_fault = "admission_recovery_retirement_unresolved",
                                "failed to retire an expired approval-required admission"
                            );
                            deferred_failure.get_or_insert(error);
                            continue;
                        }
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "admission recovery count overflow".to_owned(),
                            )
                        })?;
                    }
                    AdmissionOperationState::Finalizing => {
                        let mut admission = DurableToolAdmission {
                            operation,
                            aggregate_quota: None,
                            supplemental_quota: None,
                            retained_request: None,
                            issued_nonce: None,
                            nonce_preflight: None,
                        };
                        let tool_return = self.load_durable_tool_return(&admission)?;
                        let Some(request) =
                            tool_return.recovery_request().map_err(tool_outcome_error)?
                        else {
                            self.claim_admission_recovery(
                                &admission.operation,
                                trusted_now_unix_ms,
                            )?;
                            continue;
                        };
                        if let Err(error) = self.finalize_durable_tool_return(
                            &mut admission,
                            &request,
                            &tool_return,
                        ) {
                            warn!(
                                operation_id = %admission.operation.binding().operation_id().as_str(),
                                reason = %redacted!(&error),
                                audit_fault = "admission_recovery_finalization_unresolved",
                                "failed to finalize a recoverable admission"
                            );
                            deferred_failure.get_or_insert(error);
                            continue;
                        }
                        reconciled = reconciled.checked_add(1).ok_or_else(|| {
                            KernelError::DurableAdmission(
                                "admission recovery count overflow".to_owned(),
                            )
                        })?;
                    }
                    _ => {
                        self.claim_admission_recovery(&operation, trusted_now_unix_ms)?;
                    }
                }
            }
            if reconciled == reconciled_before_page {
                break;
            }
        }
        if let Some(error) = deferred_failure {
            return Err(error);
        }
        Ok(reconciled)
    }

    /// Retire a parked operation whose proposal deadline has elapsed. No token
    /// set can still deliver for it, so the retained hold is released now
    /// instead of waiting for the next startup sweep. A live deadline leaves
    /// the operation parked.
    pub(super) fn retire_expired_parked_admission(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let deadline_unix_ms = operation
            .parked_approval_deadline_unix_ms()
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let Some(deadline_unix_ms) =
            deadline_unix_ms.filter(|deadline| *deadline <= trusted_now_unix_ms)
        else {
            return Ok(());
        };
        self.compensate_durable_admission_before_dispatch(
            operation,
            serde_json::json!({
                "authority": "kernel-approval-retirement",
                "cause": "approval-deadline-elapsed",
                "proposal_deadline_unix_ms": deadline_unix_ms
            }),
            trusted_now_unix_ms,
            None,
        )
    }

    /// Terminalize a dispatch-committed admission whose outcome is unknown.
    ///
    /// Refuses when a durable tool outcome already exists, so this is a no-op on
    /// an operation whose return did land. Used both by startup recovery and by
    /// the post-dispatch drop path, where the evaluation future was cancelled
    /// after the dispatch commit and would otherwise strand the operation until
    /// the next process restart.
    pub(crate) fn terminalize_dispatch_committed_admission(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        if runtime
            .outcome_store
            .lookup_by_operation(operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .is_some()
        {
            return Err(KernelError::DurableAdmission(
                "dispatch-committed admission already has a durable tool outcome".to_owned(),
            ));
        }
        let lease = self.claim_admission_recovery(operation, trusted_now_unix_ms)?;
        let context = AdmissionProjectionContext {
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.binding().request_id().clone(),
            expected_operation_version: operation.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: runtime.fence.clone(),
        };
        let projection = verified_outcome_unknown_after_dispatch_projection(operation, context)?;
        self.finalize_finding_pool_claim_after_unknown_dispatch(
            operation.binding().operation_id().as_str(),
            trusted_now_unix_ms,
        )
        .map_err(|error| {
            KernelError::DurableAdmission(format!(
                "outcome-unknown finding pool finalization failed: {error}"
            ))
        })?;
        let terminal = runtime
            .store
            .commit_admission_projection(&projection)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        if terminal.operation_id != *operation.binding().operation_id()
            || terminal.state != AdmissionOperationState::OutcomeUnknownAfterDispatch
        {
            return Err(KernelError::DurableAdmission(
                "admission recovery committed a different terminal operation".to_owned(),
            ));
        }
        Ok(())
    }
}
