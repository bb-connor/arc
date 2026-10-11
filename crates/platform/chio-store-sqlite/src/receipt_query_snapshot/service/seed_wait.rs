//! Reclamation while the walker waits for the writer seed.
//!
//! The seed wait has no deadline, and the first provisioning, which reclaims
//! too, runs only after it. Snapshot files abandoned by owners that died are
//! therefore reclaimed before the wait and again at a fixed interval of the
//! store's clock while it lasts. Each attempt is one bounded window and needs
//! no ready seed, no snapshot and no write to the receipt store.

use super::super::db::SnapshotDb;
use super::Inner;

/// Store-clock milliseconds between attempts during one seed wait.
const INTERVAL_MS: u64 = 30_000;

#[derive(Default)]
pub(super) struct SeedWaitReclaim {
    /// Store-clock reading of the last attempt, once one ran.
    last: Option<Option<u64>>,
}

impl SeedWaitReclaim {
    /// Reclaim when due: on the first poll of a wait, then once the store
    /// clock has moved by the interval.
    pub(super) fn poll(&mut self, inner: &Inner) {
        let now = inner.store.query_snapshot_unix_ms().ok();
        if due(self.last, now) {
            SnapshotDb::reclaim_abandoned(&inner.store);
            self.last = Some(now);
        }
    }
}

/// An unreadable clock defers every attempt after the first; a clock that
/// moved backwards is due at once.
fn due(last: Option<Option<u64>>, now: Option<u64>) -> bool {
    match (last, now) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(None), Some(_)) => true,
        (Some(Some(last)), Some(now)) => now < last || now - last >= INTERVAL_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::{due, INTERVAL_MS};

    #[test]
    fn the_first_poll_is_due_whatever_the_clock_reads() {
        assert!(due(None, Some(5)));
        assert!(due(None, None));
    }

    #[test]
    fn later_polls_are_due_only_after_the_interval_of_the_store_clock() {
        let start = 1_700_000_000_000;
        assert!(!due(Some(Some(start)), Some(start)));
        assert!(!due(Some(Some(start)), Some(start + INTERVAL_MS - 1)));
        assert!(due(Some(Some(start)), Some(start + INTERVAL_MS)));
        assert!(due(Some(Some(start)), Some(start - 1)));
    }

    #[test]
    fn an_unreadable_clock_defers_until_it_reads_again() {
        assert!(!due(Some(Some(5)), None));
        assert!(!due(Some(None), None));
        assert!(due(Some(None), Some(5)));
    }
}
