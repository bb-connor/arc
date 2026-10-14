use super::{IdentityDisposition, KernelError};

/// A refused admission and the identity state established at its storage boundary.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub(crate) struct AdmissionStartFailure {
    #[source]
    pub(in crate::kernel) error: Box<KernelError>,
    /// A live operation cannot produce a new terminal refusal.
    pub(in crate::kernel) receipt_disposition: Option<IdentityDisposition>,
}

impl KernelError {
    pub(in crate::kernel) fn durable_commit_outcome_is_unknown(&self) -> bool {
        matches!(
            self,
            Self::AdmissionRecovery(failure)
                if matches!(
                    failure.as_ref(),
                    crate::admission_operation::AdmissionRecoveryError::Store(
                        crate::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(_)
                    )
                )
        )
    }
}
