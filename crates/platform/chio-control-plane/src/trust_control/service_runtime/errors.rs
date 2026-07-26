use super::*;

pub(super) fn into_receipt_store_error(error: CliError) -> ReceiptStoreError {
    ReceiptStoreError::Io(std::io::Error::other(error.to_string()))
}

pub(super) fn into_revocation_store_error(error: CliError) -> RevocationStoreError {
    RevocationStoreError::Io(std::io::Error::other(error.to_string()))
}

pub(super) fn into_budget_store_error(error: CliError) -> BudgetStoreError {
    BudgetStoreError::Io(std::io::Error::other(error.to_string()))
}

pub(super) fn into_replay_budget_store_error(error: CliError) -> BudgetStoreError {
    let message = error.to_string();
    if let Some((_, detail)) = message.split_once("budget_committed_replay_missing:") {
        return BudgetStoreError::MissingCommittedReplay(detail.trim().to_string());
    }
    if let Some((_, detail)) = message.split_once("budget_committed_replay_conflict:") {
        return BudgetStoreError::Conflict(detail.trim().to_string());
    }
    BudgetStoreError::Io(std::io::Error::other(message))
}
