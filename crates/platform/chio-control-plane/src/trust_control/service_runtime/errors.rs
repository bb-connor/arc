use super::*;

/// A failed trust-control call reaches the store port as an IO fault; the
/// remote error text is logged here and never crosses the port.
fn remote_store_fault(store: &'static str, error: &CliError) -> chio_kernel::IoFault {
    tracing::error!(store, %error, "remote trust-control store call failed");
    chio_kernel::IoFault::Other
}

pub(super) fn into_receipt_store_error(error: CliError) -> ReceiptStoreError {
    ReceiptStoreError::Io(remote_store_fault("receipt", &error))
}

pub(super) fn into_revocation_store_error(error: CliError) -> RevocationStoreError {
    RevocationStoreError::Io(remote_store_fault("revocation", &error))
}

pub(super) fn into_budget_store_error(error: CliError) -> BudgetStoreError {
    BudgetStoreError::Io(remote_store_fault("budget", &error))
}
