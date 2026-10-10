#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
//! Limit SQLite work even when a filter returns few or no matching receipts.

use chio_kernel::ReceiptStoreError;
use rusqlite::Connection;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PROGRESS_INTERVAL: i32 = 1_000;

pub(crate) struct SqlWorkBudget<'connection> {
    connection: &'connection Connection,
    exhausted: Arc<AtomicBool>,
    surface: &'static str,
}

impl<'connection> SqlWorkBudget<'connection> {
    pub(crate) fn new_for(
        connection: &'connection Connection,
        steps: u64,
        surface: &'static str,
    ) -> Result<Self, ReceiptStoreError> {
        let exhausted = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&exhausted);
        let mut remaining = steps;
        let interval = u64::try_from(PROGRESS_INTERVAL)
            .map_err(|_| ReceiptStoreError::ReadBoundary("invalid SQL progress interval".into()))?;
        connection.progress_handler(
            PROGRESS_INTERVAL,
            Some(move || {
                // Exhaustion, including a partial final interval, must become
                // zero so this callback interrupts the query immediately.
                remaining = remaining.saturating_sub(interval);
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
            surface,
        })
    }

    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Relaxed)
    }

    pub(crate) fn finish<T>(
        self,
        result: Result<T, ReceiptStoreError>,
    ) -> Result<T, ReceiptStoreError> {
        if self.exhausted.load(Ordering::Relaxed) {
            Err(ReceiptStoreError::ReadBoundary(format!(
                "{} exhausted its SQL work budget",
                self.surface
            )))
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
