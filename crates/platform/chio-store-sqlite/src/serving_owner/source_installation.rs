//! Serialize source installation workflows without holding a database lock
//! across a configured source callback.

use super::{AtomicBool, Ordering, SqliteServingOwner, SqliteServingOwnerError};

pub(crate) struct SourceInstallationGuard<'a> {
    in_flight: &'a AtomicBool,
}

impl Drop for SourceInstallationGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.store(false, Ordering::Release);
    }
}

impl SqliteServingOwner {
    pub(crate) fn begin_source_installation(
        &self,
    ) -> Result<SourceInstallationGuard<'_>, SqliteServingOwnerError> {
        self.require_unpoisoned()?;
        self.source_installation_in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| {
                SqliteServingOwnerError::Invalid(
                    "source installation is already in progress".to_string(),
                )
            })?;
        Ok(SourceInstallationGuard {
            in_flight: &self.source_installation_in_flight,
        })
    }
}
