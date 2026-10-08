//! Only explicit item failure families can be deferred; unknown failures stay fatal.

use super::*;
use crate::admission_operation::{AdmissionRecoveryError, AdmissionRecoveryFailureKind};
use crate::disposition::Disposition;

pub(crate) fn item_failure(
    kind: AdmissionRecoveryFailureKind,
    detail: impl Into<String>,
) -> KernelError {
    KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::Item {
        kind,
        detail: detail.into(),
    }))
}

pub(super) fn classify(error: &KernelError) -> Option<AdmissionRecoveryFailureKind> {
    match error {
        KernelError::AdmissionRecovery(failure) => failure.failure_kind(),
        KernelError::FindingDenied(denial) => Some(match denial.code() {
            crate::finding_denial::FindingDenialCode::Unavailable => {
                AdmissionRecoveryFailureKind::ParticipantUnavailable
            }
            _ => AdmissionRecoveryFailureKind::OutputDenied,
        }),
        KernelError::GuardDenied(_) => Some(AdmissionRecoveryFailureKind::OutputDenied),
        KernelError::CapabilityRevoked(_) | KernelError::DelegationChainRevoked(_) => {
            Some(AdmissionRecoveryFailureKind::OutputDenied)
        }
        _ => None,
    }
}

/// How the recovery sweep handles one operation's failure. Only a failure
/// that belongs to that operation is item scoped; everything else is fatal.
pub(super) fn disposition(error: &KernelError) -> Disposition {
    classify(error).map_or(
        Disposition::Fatal,
        AdmissionRecoveryFailureKind::disposition,
    )
}

pub(crate) fn payment_store_error(
    error: crate::receipt_store::AdmissionPaymentJournalError,
) -> KernelError {
    KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::PaymentJournal(error)))
}

pub(crate) fn payment_record_error(error: crate::payment::PaymentJournalError) -> KernelError {
    KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::PaymentRecord(error)))
}

pub(crate) fn payment_error(source: crate::payment::PaymentError) -> KernelError {
    let kind = match source {
        crate::payment::PaymentError::RailError(_) => AdmissionRecoveryFailureKind::ContractChanged,
        _ => AdmissionRecoveryFailureKind::ParticipantUnavailable,
    };
    KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::Payment { kind, source }))
}

pub(crate) fn operation_error(
    error: crate::admission_operation::AdmissionOperationError,
) -> KernelError {
    KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::Operation(error)))
}

pub(crate) fn port_error(
    error: crate::admission_operation::AdmissionRecoveryPortError,
) -> KernelError {
    KernelError::AdmissionRecovery(Box::new(AdmissionRecoveryError::Port(error)))
}

#[cfg(test)]
#[path = "failure/tests.rs"]
mod tests;
