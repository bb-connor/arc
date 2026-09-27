//! Limit SQLite work even when a filter returns few or no matching receipts.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PROGRESS_INTERVAL: i32 = 1_000;

pub(super) struct SqlWorkBudget<'connection> {
    connection: &'connection Connection,
    exhausted: Arc<AtomicBool>,
}

impl<'connection> SqlWorkBudget<'connection> {
    pub(super) fn new(
        connection: &'connection Connection,
        steps: u64,
    ) -> Result<Self, ReceiptStoreError> {
        let exhausted = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&exhausted);
        let mut remaining = steps;
        connection.progress_handler(
            PROGRESS_INTERVAL,
            Some(move || {
                // Exhaustion, including a partial final interval, must become
                // zero so this callback interrupts the query immediately.
                remaining = remaining.saturating_sub(PROGRESS_INTERVAL as u64);
                let stop = remaining == 0;
                if stop {
                    signal.store(true, Ordering::Relaxed);
                }
                stop
            }),
        )?;
        Ok(Self {
            connection,
            exhausted,
        })
    }

    pub(super) fn finish<T>(
        self,
        result: Result<T, ReceiptStoreError>,
    ) -> Result<T, ReceiptStoreError> {
        if self.exhausted.load(Ordering::Relaxed) {
            Err(ReceiptStoreError::ReadBoundary(
                "receipt analytics report exhausted its SQL work budget".to_owned(),
            ))
        } else {
            result
        }
    }
}

impl Drop for SqlWorkBudget<'_> {
    fn drop(&mut self) {
        // This guard is declared after the transaction: clear interruption
        // before transaction rollback and before returning the owned connection
        // to its pool. The only API failure here is a non-owned connection.
        let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
    }
}
