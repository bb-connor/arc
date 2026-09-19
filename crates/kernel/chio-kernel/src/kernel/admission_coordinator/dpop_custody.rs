//! Recover DPoP ownership from exact retained history. Cleanup does not
//! require an unexpired token, a legacy reservation ID, or a live verifier.

use super::*;
use crate::admission_operation::dpop_claim::{
    DpopReplayClaimDisposition as Disposition, DpopReplayClaimHistoryV1, MAX_DPOP_CLAIM_EPISODES,
};
use crate::admission_operation::AdmissionRecoveryLease;

impl ChioKernel {
    /// The coordinator holds its mutation sequencer and an exact-version lease.
    /// A callback failure remains unknown until a later anchored history read.
    pub(super) fn release_retained_dpop(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        now: u64,
    ) -> Result<(), KernelError> {
        if operation.dpop_replay_ledger_digest().is_none() {
            return Ok(());
        }
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(custody_error(
                "DPoP custody cannot be released after dispatch or termination",
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
            runtime
                .store
                .release_dpop_replay(operation, lease, &history[index].reference, now)
        })?;
        history[index].disposition = Disposition::ReleasedBeforeDispatch;
        if load_exact_history(runtime, operation, now)? != history {
            return Err(custody_error(
                "DPoP release did not preserve its exact ownership history",
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
                    "DPoP participant {name} callback panicked"
                )),
            )
        })
        .map_err(durable_store_error)
}

pub(super) fn load_exact_history(
    runtime: &DurableAdmissionRuntime,
    operation: &AdmissionOperationV1,
    now: u64,
) -> Result<Vec<DpopReplayClaimHistoryV1>, KernelError> {
    let (current, history) = store_call("history", || {
        runtime.store.load_dpop_replay_claim_history(
            operation.binding().operation_id(),
            &runtime.fence,
            now,
        )
    })?
    .ok_or_else(|| custody_error("DPoP ownership disappeared during recovery"))?;
    if &current != operation {
        return Err(custody_error(
            "DPoP recovery returned a different operation",
        ));
    }
    Ok(history)
}

pub(super) fn validate_recovery_history(
    operation: &AdmissionOperationV1,
    history: &[DpopReplayClaimHistoryV1],
) -> Result<(), KernelError> {
    let Some(first) = history.first() else {
        return Err(custody_error("DPoP ledger has no physical claim history"));
    };
    if history.len() > MAX_DPOP_CLAIM_EPISODES {
        return Err(custody_error("DPoP history exceeded its episode bound"));
    }
    let mut episodes = std::collections::BTreeSet::new();
    let mut live = false;
    for claim in history {
        claim.intent.validate().map_err(durable_store_error)?;
        if claim.reference.operation_id() != operation.binding().operation_id()
            || claim.reference.episode_id() != claim.intent.episode_id()
            || claim.intent.request_binding_hash() != operation.binding().request_binding_hash()
            || claim.intent.credential().authority() != first.intent.credential().authority()
            || claim.intent.credential().capability_id()
                != operation.binding().capability_id().as_str()
            || !episodes.insert(claim.reference.episode_id().as_str())
        {
            return Err(custody_error(
                "DPoP history changed its exact ownership binding",
            ));
        }
        match claim.disposition {
            Disposition::ReleasedBeforeDispatch => {}
            Disposition::ReservedBeforeDispatch if !live => live = true,
            _ => {
                return Err(custody_error(
                    "DPoP recovery history is not pre-dispatch custody",
                ))
            }
        }
    }
    Ok(())
}

fn custody_error(reason: &str) -> KernelError {
    KernelError::DurableAdmission(reason.into())
}
