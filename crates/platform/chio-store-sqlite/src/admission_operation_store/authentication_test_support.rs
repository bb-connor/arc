//! Bounded genuine native read backlog with no writes or authority changes.
use super::*;
use std::{sync::mpsc, time::Duration};

impl SqliteAdmissionOperationStore {
    /// Hold the real shared connection after its current owner and rollback
    /// anchor have passed the same verification as ordinary native reads.
    /// This control is absent without the admission-test-support feature.
    pub fn hold_current_connection_for_authentication_test(
        &self,
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        entered
            .try_send(())
            .map_err(|_| invariant("authentication backlog observer unavailable"))?;
        release
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| invariant("authentication backlog release exceeded its bound"))?;
        transaction.rollback().map_err(sqlite_error)
    }
}
