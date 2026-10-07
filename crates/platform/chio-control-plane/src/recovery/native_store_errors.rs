//! Native policy categories stay separate from retained storage failures.
use super::RecoveryRuntimeError;
use chio_kernel::admission_operation::{AdmissionOperationError, AdmissionOperationStoreError};

pub(super) fn store_error(error: AdmissionOperationStoreError) -> RecoveryRuntimeError {
    match error {
        AdmissionOperationStoreError::RecoveryAuthorityDenied => {
            RecoveryRuntimeError::AuthorityDenied
        }
        AdmissionOperationStoreError::RecoveryMediationRequired => {
            RecoveryRuntimeError::UncoveredMediation
        }
        AdmissionOperationStoreError::Unavailable(_)
        | AdmissionOperationStoreError::OutcomeUnknown(_)
        | AdmissionOperationStoreError::Fenced
        | AdmissionOperationStoreError::Invariant(_)
        | AdmissionOperationStoreError::Operation(
            AdmissionOperationError::TerminalReplayMismatch,
        ) => RecoveryRuntimeError::Unavailable,
        AdmissionOperationStoreError::NotFound | AdmissionOperationStoreError::Operation(_) => {
            RecoveryRuntimeError::AuthorityDenied
        }
    }
}
