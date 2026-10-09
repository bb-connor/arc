//! Platform storage for a process-owned authenticated projection.
use chio_kernel::ReceiptStoreError;
use rusqlite::Connection;

#[cfg(target_os = "linux")]
use crate::receipt_query_snapshot_backing::{SnapshotBackingError, SnapshotFileBacking};

pub(super) enum Storage {
    #[cfg(any(test, not(target_os = "linux")))]
    Memory(Connection),
    #[cfg(target_os = "linux")]
    File(SnapshotFileBacking),
}

impl Storage {
    pub(super) fn create() -> Result<Self, ReceiptStoreError> {
        #[cfg(target_os = "linux")]
        {
            SnapshotFileBacking::create()
                .map(Self::File)
                .map_err(backing_error)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::memory()
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

#[cfg(target_os = "linux")]
fn backing_error(error: SnapshotBackingError) -> ReceiptStoreError {
    use chio_kernel::receipt_query::ReceiptQuerySnapshotError;
    match error {
        SnapshotBackingError::Refused(_) | SnapshotBackingError::Descriptor(_) => {
            ReceiptQuerySnapshotError::Invalid(error.to_string()).into()
        }
        SnapshotBackingError::Io(_) => {
            ReceiptQuerySnapshotError::Unavailable(error.to_string()).into()
        }
        // Preserve interruption/busy codes for the enclosing SQL budget and
        // cancellation guard. A custody refusal never becomes a retryable SQL error.
        SnapshotBackingError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
    }
}
