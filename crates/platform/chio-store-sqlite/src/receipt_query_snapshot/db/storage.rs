//! Platform storage for a process-owned authenticated projection.
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use chio_kernel::ReceiptStoreError;
use rusqlite::Connection;

use super::SnapshotDbError;
#[cfg(target_os = "linux")]
use crate::receipt_query_snapshot_backing::{
    reclaim_abandoned as reclaim_backing, SnapshotBackingError, SnapshotFileBacking,
    SnapshotLocationRefusal,
};
use crate::receipt_store::SqliteReceiptStore;

pub(super) enum Storage {
    #[cfg(any(test, not(target_os = "linux")))]
    Memory(Connection),
    #[cfg(target_os = "linux")]
    File(SnapshotFileBacking),
}

impl Storage {
    /// Linux provisions a private file in `store`'s data directory, or under
    /// `/tmp` when the store is in memory. Another process holding the
    /// snapshot parent lock is contention, not unavailability.
    pub(super) fn create(store: &SqliteReceiptStore) -> Result<Self, SnapshotDbError> {
        #[cfg(target_os = "linux")]
        {
            let database = database_file(store)?;
            match SnapshotFileBacking::create(database.as_deref()) {
                Ok(backing) => Ok(Self::File(backing)),
                Err(error @ SnapshotBackingError::Unusable(SnapshotLocationRefusal::Contended)) => {
                    Err(SnapshotDbError::Contended(error.to_string()))
                }
                Err(error) => Err(backing_error(error).into()),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = store;
            Ok(Self::memory()?)
        }
    }

    #[cfg(any(test, not(target_os = "linux")))]
    pub(super) fn memory() -> Result<Self, ReceiptStoreError> {
        Ok(Self::Memory(Connection::open_in_memory()?))
    }

    pub(super) fn connection(&self) -> Result<&Connection, ReceiptStoreError> {
        match self {
            #[cfg(any(test, not(target_os = "linux")))]
            Self::Memory(connection) => Ok(connection),
            #[cfg(target_os = "linux")]
            Self::File(backing) => backing.checked_connection().map_err(backing_error),
        }
    }

    #[cfg(test)]
    pub(super) fn connection_mut(&mut self) -> Result<&mut Connection, ReceiptStoreError> {
        match self {
            Self::Memory(connection) => Ok(connection),
            #[cfg(target_os = "linux")]
            Self::File(backing) => backing.checked_connection_mut().map_err(backing_error),
        }
    }
}

/// Reclaim one bounded window of snapshot directories abandoned by owners
/// that died, where `create` would provision, without provisioning. Best
/// effort: a failure is logged and left to the next attempt.
pub(super) fn reclaim_abandoned(store: &SqliteReceiptStore) {
    #[cfg(target_os = "linux")]
    {
        let outcome = database_file(store)
            .and_then(|database| reclaim_backing(database.as_deref()).map_err(backing_error));
        if let Err(error) = outcome {
            tracing::warn!(%error, "receipt query snapshot reclamation did not run");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = store;
}

/// `store`'s main database file, as SQLite resolved it (absolute and without
/// links). The name is read as bytes, so a non-UTF-8 name is kept; only an
/// empty name, which SQLite reports for a database backed by no file, yields
/// `None`.
#[cfg(target_os = "linux")]
fn database_file(store: &SqliteReceiptStore) -> Result<Option<PathBuf>, ReceiptStoreError> {
    use std::os::unix::ffi::OsStrExt;
    let connection = store.connection()?;
    let file: Vec<u8> = connection.query_row(
        "SELECT file FROM pragma_database_list WHERE name = 'main'",
        [],
        |row| {
            row.get_ref(0)?
                .as_bytes()
                .map(<[u8]>::to_vec)
                .map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
        },
    )?;
    if file.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(&file))))
}

#[cfg(target_os = "linux")]
fn backing_error(error: SnapshotBackingError) -> ReceiptStoreError {
    use chio_kernel::receipt_query::ReceiptQuerySnapshotError;
    match error {
        SnapshotBackingError::Refused(_) | SnapshotBackingError::Descriptor(_) => {
            ReceiptQuerySnapshotError::Invalid(error.to_string()).into()
        }
        // Operational refusals of the location are retried resource outcomes.
        SnapshotBackingError::Io(_) | SnapshotBackingError::Unusable(_) => {
            ReceiptQuerySnapshotError::Unavailable(error.to_string()).into()
        }
        // Preserve interruption/busy codes for the enclosing SQL budget and
        // cancellation guard. A custody refusal never becomes a retryable SQL error.
        SnapshotBackingError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
    }
}
