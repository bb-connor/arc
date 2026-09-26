//! Recover approval ownership from exact retained history. Cleanup does not
//! require an unexpired token, a legacy reservation ID, or a live verifier.

use super::*;
use crate::admission_operation::governed_approval_claim::{
    GovernedApprovalClaimDisposition as Disposition, GovernedApprovalClaimHistoryV1,
    MAX_GOVERNED_APPROVAL_CLAIM_EPISODES,
};
use crate::admission_operation::AdmissionRecoveryLease;

impl ChioKernel {
    /// The coordinator holds its mutation sequencer and an exact-version lease.
    /// A callback failure remains unknown until a later anchored history read.
    pub(super) fn release_retained_governed_approval(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        now: u64,
    ) -> Result<(), KernelError> {
        if operation.governed_approval_ledger_digest().is_none() {
            return Ok(());
        }
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(custody_error(
                "approval custody cannot be released after dispatch or termination",
            ));
        }
        let runtime = self.durable_runtime()?;
        let mut history = load_exact_history(runtime, operation, now)?;
        validate_recovery_history(operation, &history)?;
        let Some(index) = history
            .iter()
            .position(|claim| claim.disposition == Disposition::ReservedBeforeDispatch)
        else {
            return Ok(());
        };
        store_call("release", || {
            runtime.store.release_governed_approval(
                operation,
                lease,
                &history[index].reference,
                now,
            )
        })?;
        history[index].disposition = Disposition::ReleasedBeforeDispatch;
        if load_exact_history(runtime, operation, now)? != history {
            return Err(custody_error(
                "approval release did not preserve its exact ownership history",
            ));
        }
        Ok(())
    }
}

pub(super) fn store_call<T>(
    name: &str,
    call: impl FnOnce() -> Result<T, crate::admission_operation::AdmissionOperationStoreError>,
) -> Result<T, KernelError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
        .unwrap_or_else(|_| {
            Err(
                crate::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(format!(
                    "approval participant {name} callback panicked"
                )),
            )
        })
        .map_err(durable_store_error)
}

pub(super) fn load_exact_history(
    runtime: &DurableAdmissionRuntime,
    operation: &AdmissionOperationV1,
    now: u64,
) -> Result<Vec<GovernedApprovalClaimHistoryV1>, KernelError> {
    let (current, history) = store_call("history", || {
        runtime.store.load_governed_approval_claim_history(
            operation.binding().operation_id(),
            &runtime.fence,
            now,
        )
    })?
    .ok_or_else(|| custody_error("approval ownership disappeared during recovery"))?;
    if &current != operation {
        return Err(custody_error(
            "approval recovery returned a different operation",
        ));
    }
    Ok(history)
}

pub(super) fn validate_recovery_history(
    operation: &AdmissionOperationV1,
    history: &[GovernedApprovalClaimHistoryV1],
) -> Result<(), KernelError> {
    let Some(first) = history.first() else {
        return Err(custody_error(
            "approval ledger has no physical claim history",
        ));
    };
    if history.len() > MAX_GOVERNED_APPROVAL_CLAIM_EPISODES {
        return Err(custody_error("approval history exceeded its episode bound"));
    }
    let mut episodes = std::collections::BTreeSet::new();
    let mut live = false;
    for claim in history {
        claim.intent.validate().map_err(durable_store_error)?;
        if claim.reference.operation_id() != operation.binding().operation_id()
            || claim.reference.episode_id() != claim.intent.episode_id()
            || claim.intent.request_binding_hash() != operation.binding().request_binding_hash()
            || claim.intent.approval_authority_id() != first.intent.approval_authority_id()
            || claim.intent.expectation_id() != first.intent.expectation_id()
            || !episodes.insert(claim.reference.episode_id().as_str())
        {
            return Err(custody_error(
                "approval history changed its exact ownership binding",
            ));
        }
        match claim.disposition {
            Disposition::ReleasedBeforeDispatch => {}
            Disposition::ReservedBeforeDispatch if !live => live = true,
            _ => {
                return Err(custody_error(
                    "approval recovery history is not pre-dispatch custody",
                ))
            }
        }
    }
    Ok(())
}

fn custody_error(reason: &str) -> KernelError {
    KernelError::DurableAdmission(reason.into())
}
