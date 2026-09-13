//! Recovery of operation-owned runtime replay custody. No request metadata or
//! fresh artifact preparation participates in release authority.

use super::*;
use crate::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantDisposition,
    MAX_RUNTIME_PARTICIPANT_EPISODES,
};
use crate::admission_operation::AdmissionRecoveryLease;

/// Catch participant panics before unwinding through the kernel sequencer.
/// A callback failure is unresolved authority, never evidence of no effect.
pub(super) fn store_call<T>(
    name: &str,
    call: impl FnOnce() -> Result<T, crate::admission_operation::AdmissionOperationStoreError>,
) -> Result<T, KernelError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
        .unwrap_or_else(|_| {
            Err(
                crate::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(format!(
                    "runtime participant {name} callback panicked"
                )),
            )
        })
        .map_err(durable_store_error)
}

impl ChioKernel {
    /// The caller holds the mutation sequencer and an exact-version lease.
    /// Releasing custody leaves that version unchanged. Unknown outcomes are
    /// never inferred to be success; a subsequent recovery attempt reads the
    /// durable disposition before deciding whether another release is needed.
    pub(super) fn release_retained_runtime_participants(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        if operation.runtime_participant_ledger_digest().is_none() {
            return Ok(());
        }
        if operation.dispatch_commit().is_some() || operation.state().is_terminal() {
            return Err(custody_error(
                "runtime replay custody cannot be released after dispatch commitment or termination",
            ));
        }
        let runtime = self.durable_runtime()?;
        let history = load_exact_history(runtime, operation, trusted_now_unix_ms)?;
        validate_recovery_history(operation, &history)?;
        let Some(live_index) = history.iter().position(|claim| {
            claim.disposition == RuntimeParticipantDisposition::ReservedBeforeDispatch
        }) else {
            return Ok(());
        };
        store_call("release", || {
            runtime.store.release_runtime_participants(
                operation,
                lease,
                &history[live_index].reference,
                trusted_now_unix_ms,
            )
        })?;

        // Do not treat an acknowledgement alone as proof of physical release.
        // Readback must preserve every reference and intent, including released
        // predecessors, and change only this episode's disposition.
        let mut expected = history;
        expected[live_index].disposition = RuntimeParticipantDisposition::ReleasedBeforeDispatch;
        if load_exact_history(runtime, operation, trusted_now_unix_ms)? != expected {
            return Err(custody_error(
                "runtime replay release did not retain the exact released history",
            ));
        }
        Ok(())
    }
}

fn load_exact_history(
    runtime: &DurableAdmissionRuntime,
    operation: &AdmissionOperationV1,
    trusted_now_unix_ms: u64,
) -> Result<Vec<RuntimeParticipantClaimHistoryV1>, KernelError> {
    let (current, history) = store_call("history", || {
        runtime.store.load_runtime_participant_history(
            operation.binding().operation_id(),
            &runtime.fence,
            trusted_now_unix_ms,
        )
    })?
    .ok_or_else(|| custody_error("runtime replay ownership disappeared during recovery"))?;
    if &current != operation {
        return Err(custody_error(
            "runtime replay recovery returned a different operation snapshot",
        ));
    }
    Ok(history)
}

pub(super) fn validate_recovery_history(
    operation: &AdmissionOperationV1,
    history: &[RuntimeParticipantClaimHistoryV1],
) -> Result<(), KernelError> {
    let Some(first) = history.first() else {
        return Err(custody_error(
            "runtime replay ledger has no physical claim history",
        ));
    };
    if history.len() > MAX_RUNTIME_PARTICIPANT_EPISODES {
        return Err(custody_error(
            "runtime replay history exceeded its episode bound",
        ));
    }
    let mut episodes = std::collections::BTreeSet::new();
    let mut live = false;
    for claim in history {
        claim.intent.validate().map_err(durable_store_error)?;
        if claim.reference.operation_id() != operation.binding().operation_id()
            || claim.reference.episode_id() != claim.intent.episode_id()
            || claim.intent.request_binding_hash() != operation.binding().request_binding_hash()
            || claim.intent.runtime_authority_id() != first.intent.runtime_authority_id()
            || claim.intent.expectation_id() != first.intent.expectation_id()
            || !episodes.insert(claim.reference.episode_id().as_str())
        {
            return Err(custody_error(
                "runtime replay history changed its ownership binding",
            ));
        }
        match claim.disposition {
            RuntimeParticipantDisposition::ReleasedBeforeDispatch => {}
            RuntimeParticipantDisposition::ReservedBeforeDispatch if !live => live = true,
            _ => {
                return Err(custody_error(
                    "runtime replay history is not pre-dispatch custody",
                ))
            }
        }
    }
    Ok(())
}

fn custody_error(reason: &str) -> KernelError {
    KernelError::DurableAdmission(reason.to_owned())
}
