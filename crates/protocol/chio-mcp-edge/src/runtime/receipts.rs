pub(super) fn record_receipt_write_error() {
    crate::metrics::record_receipt_write(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR);
}

pub(super) fn receipt_write_outcome_for_kernel_error(
    error: &chio_kernel::KernelError,
) -> Option<&'static str> {
    match error {
        chio_kernel::KernelError::RequestCancelled { .. }
        | chio_kernel::KernelError::UrlElicitationsRequired { .. } => None,
        _ => Some(crate::metrics::RECEIPT_WRITE_OUTCOME_ERROR),
    }
}

pub(super) fn record_receipt_write_kernel_error(error: &chio_kernel::KernelError) {
    if let Some(outcome) = receipt_write_outcome_for_kernel_error(error) {
        crate::metrics::record_receipt_write(outcome);
    }
}
