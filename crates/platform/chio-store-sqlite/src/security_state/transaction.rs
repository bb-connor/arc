//! Owned security mutations for composition in one outer SQLite transaction.

use super::{participant_source, sqlite_error, PortError, PortResult, SecurityStateClock};
use rusqlite::{DropBehavior, Transaction, TransactionState};

/// No method commits independently. A mutation consumes this owner and returns
/// it only on success, so even a caller that catches an error cannot commit a
/// partially applied security mutation. Dropping the owner rolls back the whole
/// outer transaction, including earlier participant writes.
pub(super) struct SecurityStateWriteTransaction<'connection> {
    transaction: Transaction<'connection>,
}

impl<'connection> SecurityStateWriteTransaction<'connection> {
    pub(super) fn new(mut transaction: Transaction<'connection>) -> PortResult<Self> {
        // Do not inherit a caller's commit-on-drop configuration on error.
        transaction.set_drop_behavior(DropBehavior::Rollback);
        if transaction
            .transaction_state(Some("main"))
            .map_err(sqlite_error)?
            != TransactionState::Write
        {
            return Err(PortError::invalid_data());
        }
        participant_source::ensure_legacy_writable(&transaction)?;
        Ok(Self { transaction })
    }

    pub(super) fn transaction(&self) -> &Transaction<'connection> {
        &self.transaction
    }

    /// Return ownership for additional participant work or the outer commit.
    pub(super) fn into_transaction(self) -> Transaction<'connection> {
        self.transaction
    }
}

/// BEGIN DEFERRED alone has no snapshot. The retirement read must finish before
/// clock sampling; write callers must already hold the SQLite write transaction.
pub(super) fn trusted_time_in_transaction(
    transaction: &Transaction<'_>,
    clock: &dyn SecurityStateClock,
) -> PortResult<u64> {
    participant_source::ensure_legacy_writable(transaction)?;
    clock.now_unix_ms()
}
