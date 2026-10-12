//! An append failure cannot erase whether the store may have committed.

use crate::KernelError;

pub(in crate::kernel) enum ReceiptAppendFailure {
    Refused(KernelError),
    OutcomeUnknown {
        receipt_id: String,
        source: KernelError,
    },
}

impl ReceiptAppendFailure {
    pub(in crate::kernel) fn unknown(receipt_id: &str, source: KernelError) -> Self {
        Self::OutcomeUnknown {
            receipt_id: receipt_id.to_owned(),
            source,
        }
    }
}

impl From<KernelError> for ReceiptAppendFailure {
    fn from(error: KernelError) -> Self {
        Self::Refused(error)
    }
}

impl From<ReceiptAppendFailure> for KernelError {
    fn from(error: ReceiptAppendFailure) -> Self {
        match error {
            ReceiptAppendFailure::Refused(error) => error,
            ReceiptAppendFailure::OutcomeUnknown { receipt_id, source } => {
                Self::ReceiptAppendOutcomeUnknown {
                    receipt_id,
                    source: Box::new(source),
                }
            }
        }
    }
}

/// Acknowledgement from the authoritative store, or the local log when no
/// store is installed. Later delivery work cannot revoke this acknowledgement.
pub(in crate::kernel) struct ReceiptCommit {
    pub receipt_id: String,
    pub projected: bool,
    pub trace_source_sequence: Result<Option<u64>, KernelError>,
    pub settlement_visible_at_ms: Option<u64>,
}
