use super::*;

pub(super) fn map_budget_capture_error(error: BudgetStoreError) -> AdmissionCaptureError {
    match error {
        BudgetStoreError::Fenced { .. } => AdmissionCaptureError::Fenced,
        BudgetStoreError::OutcomeUnknown(detail) => AdmissionCaptureError::OutcomeUnknown(detail),
        error => AdmissionCaptureError::Invariant(error.to_string()),
    }
}

pub(super) fn map_payment_operation_error(
    error: AdmissionOperationStoreError,
) -> AdmissionPaymentJournalError {
    match error {
        AdmissionOperationStoreError::Fenced => AdmissionPaymentJournalError::Fenced,
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Unavailable(detail) => {
            AdmissionPaymentJournalError::Unavailable(detail)
        }
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

pub(super) fn map_payment_budget_error(error: BudgetStoreError) -> AdmissionPaymentJournalError {
    match error {
        BudgetStoreError::Fenced { .. } => AdmissionPaymentJournalError::Fenced,
        BudgetStoreError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        BudgetStoreError::Invariant(detail) => AdmissionPaymentJournalError::Conflict(detail),
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

pub(super) fn map_payment_owner_error(
    error: SqliteServingOwnerError,
) -> AdmissionPaymentJournalError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            AdmissionPaymentJournalError::OutcomeUnknown(detail)
        }
        error => AdmissionPaymentJournalError::Invariant(error.to_string()),
    }
}

/// A replay-migration record check either could not read its store or found
/// the retained records invalid. Only the second is an integrity failure.
#[derive(Debug, thiserror::Error)]
pub(super) enum RecordIntegrityError {
    #[error("record storage read failed: {0}")]
    Storage(#[source] rusqlite::Error),
    #[error("{0}")]
    Invalid(String),
}

impl RecordIntegrityError {
    pub(super) fn invalid(detail: impl std::fmt::Display) -> Self {
        Self::Invalid(detail.to_string())
    }

    /// Storage failures keep the outage-versus-corruption split of
    /// `sqlite_error`; invalid records become `invalid`'s invariant.
    pub(super) fn into_store_error(
        self,
        invalid: impl FnOnce(String) -> AdmissionOperationStoreError,
    ) -> AdmissionOperationStoreError {
        match self {
            Self::Storage(error) => sqlite_error(error),
            Self::Invalid(detail) => invalid(detail),
        }
    }
}

impl From<rusqlite::Error> for RecordIntegrityError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<String> for RecordIntegrityError {
    fn from(detail: String) -> Self {
        Self::Invalid(detail)
    }
}

impl From<&str> for RecordIntegrityError {
    fn from(detail: &str) -> Self {
        Self::Invalid(detail.to_owned())
    }
}

impl From<RecordIntegrityError> for AdmissionOperationStoreError {
    fn from(error: RecordIntegrityError) -> Self {
        error.into_store_error(invariant)
    }
}
