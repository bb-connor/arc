//! Crate-internal store state read by the receipt query snapshot service.
use super::*;

impl SqliteReceiptStore {
    /// Wall time from the store's fenced clock, in Unix milliseconds.
    pub(crate) fn query_snapshot_unix_ms(&self) -> Result<u64, ReceiptStoreError> {
        Ok(self.clock.unix_millis()?.get())
    }

    /// True when the writer's own verification of the receipt chain failed and
    /// every append is refused until an operator reseeds the head.
    pub(crate) fn writer_head_poisoned(&self) -> bool {
        self.receipt_commit_actor
            .health
            .head_poisoned
            .load(Ordering::SeqCst)
    }
}
