//! Serialize source-mutating migration workflows without holding a database
//! lock across a configured source callback.

use super::{AtomicBool, Ordering, SqliteServingOwner, SqliteServingOwnerError};

pub(crate) struct ReplaySourceMigrationGuard<'a> {
    in_flight: &'a AtomicBool,
}

impl Drop for ReplaySourceMigrationGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.store(false, Ordering::Release);
    }
}

impl SqliteServingOwner {
    pub(crate) fn begin_replay_source_migration(
        &self,
    ) -> Result<ReplaySourceMigrationGuard<'_>, SqliteServingOwnerError> {
        self.require_unpoisoned()?;
        self.replay_source_migration_in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| {
                SqliteServingOwnerError::Invalid(
                    "replay source migration is already in progress".to_string(),
                )
            })?;
        Ok(ReplaySourceMigrationGuard {
            in_flight: &self.replay_source_migration_in_flight,
        })
    }
}
