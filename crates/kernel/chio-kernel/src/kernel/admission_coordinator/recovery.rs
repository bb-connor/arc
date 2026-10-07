//! Startup recovery of retained admission operations.
//!
//! Every non-terminal operation left by a previous coordinator is either
//! terminalized with an unknown outcome, compensated before dispatch, or
//! finalized from its durable tool return. Nothing here redispatches.

use super::*;
use crate::budget_store::BudgetReverseHoldRequest;
use crate::kernel::kernel_scopes::RECEIPT_EVALUATION_SCOPE_KEY;

#[path = "recovery/batch.rs"]
mod batch;
#[path = "recovery/caller.rs"]
mod caller;
#[path = "recovery/deferral.rs"]
mod deferral;
#[path = "recovery/failure.rs"]
pub(crate) mod failure;
#[path = "recovery/operation.rs"]
mod operation;
#[path = "recovery/page.rs"]
mod page;

#[derive(Default)]
pub(super) struct AdmissionRecoveryBatchState {
    cursor: Option<crate::admission_operation::AdmissionOperationId>,
    running: bool,
}

impl ChioKernel {
    /// The recovery claim a durable step asks the store to persist with the
    /// mutation it protects.
    pub(super) fn recovery_claim_request<'a>(
        runtime: &'a DurableAdmissionRuntime,
        operation: &'a AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<RecoveryClaimRequest<'a>, KernelError> {
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_owned())
            })?;
        Ok(RecoveryClaimRequest {
            operation_id: operation.binding().operation_id(),
            expected_version: operation.version(),
            claimant_id: &runtime.claimant_id,
            expires_at_unix_ms,
            fence: &runtime.fence,
        })
    }

    pub(super) fn claim_admission_recovery(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::admission_operation::AdmissionRecoveryLease, KernelError> {
        let runtime = self.durable_runtime()?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_owned())
            })?;
        runtime
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)
    }

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
        if *runtime.startup_reconciled.lock().map_err(|_| {
            failure::operation_error(
                crate::admission_operation::AdmissionOperationError::MutationSequencerPoisoned,
            )
        })? {
            return Ok(0);
        }
        if runtime
            .startup_reconciliation_running
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return Err(KernelError::DurableAdmission(
                "startup recovery is already running".into(),
            ));
        }
        struct RunningGuard<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for RunningGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Release);
            }
        }
        let _running = RunningGuard(&runtime.startup_reconciliation_running);
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
        *runtime.startup_reconciled.lock().map_err(|_| {
            failure::operation_error(
                crate::admission_operation::AdmissionOperationError::MutationSequencerPoisoned,
            )
        })? = true;
        Ok(total)
    }

    pub fn reconcile_recoverable_admissions(&self) -> Result<usize, KernelError> {
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            return Ok(0);
        };
        let mut now = 0;
        let mut total = 0_usize;
        let mut cursor = None;
        loop {
            // The authority validates each page time against its own clock
            // when the page is read, so no page reuses an earlier sample.
            now = runtime.refresh_trusted_time(now)?;
            let (changed, next) =
                self.reconcile_admission_recovery_page(now, 256, cursor.as_ref())?;
            total = total.checked_add(changed).ok_or_else(|| {
                durable_store_error(
                    crate::admission_operation::AdmissionOperationStoreError::Invariant(
                        "recovery count overflow".into(),
                    ),
                )
            })?;
            match next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        Ok(total)
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
        // Dispatch may have advanced durable time since evaluation began.
        // Claim and project with one fresh authority observation under the lock.
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms)?;
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
