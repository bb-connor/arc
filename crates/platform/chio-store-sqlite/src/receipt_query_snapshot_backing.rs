//! Linux custody for a named, process-private receipt query snapshot database.
//!
//! This component owns one connection, a private 0700 temporary directory and a
//! single-link 0600 main file. It grants checked borrows only while the held
//! directory/file identities, their no-follow entries, the configured path and
//! SQLite's actual descriptor agree. SQLite identity inspection reuses the
//! existing audited boundary; this module contains no unsafe code.
//!
//! The private directory is inside the snapshot trust boundary. These checks
//! detect substitutions between operations; they are not atomic protection
//! against same-UID/root filesystem or process-memory compromise. Such an actor
//! can race path checks, change file contents in place or access held descriptors.
//! Quota, authenticated projection and service wiring belong to the caller.

use std::path::Path;

use chio_sqlite_file_identity::SqliteFileIdentityInspectionError;
use rusqlite::{Connection, OpenFlags};

#[path = "receipt_query_snapshot_backing/custody.rs"]
mod custody;
#[path = "receipt_query_snapshot_backing/directory.rs"]
mod directory;

use custody::FileCustody;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SnapshotCustodyRefusal {
    #[error("connection is closed")]
    Closed,
    #[error("custody parent is missing")]
    MissingParent,
    #[error("custody directory name is missing")]
    MissingDirectoryName,
    #[error("custody parent must be absolute")]
    AbsoluteParent,
    #[error("custody parent must be normalized")]
    NormalizedParent,
    #[error("custody requires real directories")]
    NotDirectory,
    #[error("custody ancestor has unsafe ownership or permissions")]
    UnsafeAncestor,
    #[error("custody directory requires owner and mode 0700")]
    PrivateDirectory,
    #[error("directory identity changed")]
    DirectoryIdentity,
    #[error("directory entry is not the held directory")]
    DirectoryEntryIdentity,
    #[error("snapshot requires a single-link owner file with mode 0600")]
    PrivateFile,
    #[error("snapshot file identity changed")]
    FileIdentity,
    #[error("snapshot leaf is not the held private file")]
    LeafIdentity,
    #[error("SQLite descriptor is not the held snapshot file")]
    DescriptorIdentity,
    #[error("snapshot has an unexpected SQLite sidecar")]
    UnexpectedSidecar,
    #[error("snapshot requires MEMORY journal and MEMORY temp store")]
    MemorySettings,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotBackingError {
    #[error("receipt query snapshot custody refused: {0}")]
    Refused(SnapshotCustodyRefusal),
    #[error("receipt query snapshot filesystem failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("receipt query snapshot SQLite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("receipt query snapshot descriptor inspection failed: {0}")]
    Descriptor(#[from] SqliteFileIdentityInspectionError),
}

pub(crate) struct SnapshotFileBacking {
    // Drop must close SQLite before custody's held file descriptor, because
    // closing another descriptor of this inode can release SQLite's POSIX locks.
    connection: Option<Connection>,
    custody: FileCustody,
}

impl SnapshotFileBacking {
    /// Provision under Linux /tmp without consulting or changing SQLite's
    /// process-global temporary-directory settings.
    pub(crate) fn create() -> Result<Self, SnapshotBackingError> {
        Self::create_in(Path::new("/tmp"))
    }

    fn create_in(parent: &Path) -> Result<Self, SnapshotBackingError> {
        let custody = FileCustody::create_in(parent)?;
        custody.validate_filesystem()?;
        // NOFOLLOW protects the leaf only. The checks after open also compare
        // every held parent and the actual descriptor, before any SQLite SQL.
        // Omit CREATE and URI so a raced or configured name cannot create or
        // reinterpret a replacement source.
        let connection = Connection::open_with_flags(
            &custody.database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE,
        )?;
        let backing = Self {
            connection: Some(connection),
            custody,
        };
        let connection = backing.connection()?;
        backing.validate_connection(connection)?;
        // Mutating pragmas come only after the actual SQLite file is bound.
        connection.execute_batch("PRAGMA journal_mode=MEMORY; PRAGMA temp_store=MEMORY;")?;
        backing.checked_connection()?;
        Ok(backing)
    }

    /// The caller must keep its use within this borrow and request another
    /// checked borrow for each subsequent snapshot hold.
    pub(crate) fn checked_connection(&self) -> Result<&Connection, SnapshotBackingError> {
        let connection = self.connection()?;
        self.validate_connection(connection)?;
        validate_settings(connection)?;
        Ok(connection)
    }

    #[cfg(test)]
    pub(crate) fn checked_connection_mut(
        &mut self,
    ) -> Result<&mut Connection, SnapshotBackingError> {
        self.checked_connection()?;
        self.connection
            .as_mut()
            .ok_or(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::Closed,
            ))
    }

    /// Validate custody and the real SQLite descriptor without executing SQL.
    pub(crate) fn validate_connection(
        &self,
        connection: &Connection,
    ) -> Result<(), SnapshotBackingError> {
        self.custody.validate_connection(connection)
    }

    /// Close SQLite, then remove only still-bound custody entries. A refusal
    /// leaves substituted objects untouched and reports the cleanup failure.
    #[cfg(test)]
    pub(crate) fn close(mut self) -> Result<(), SnapshotBackingError> {
        self.close_connection()?;
        self.custody.cleanup()
    }

    fn connection(&self) -> Result<&Connection, SnapshotBackingError> {
        self.connection
            .as_ref()
            .ok_or(SnapshotBackingError::Refused(
                SnapshotCustodyRefusal::Closed,
            ))
    }

    #[cfg(test)]
    fn close_connection(&mut self) -> Result<(), SnapshotBackingError> {
        if let Some(connection) = self.connection.take() {
            if let Err((connection, error)) = connection.close() {
                self.connection = Some(connection);
                return Err(error.into());
            }
        }
        Ok(())
    }
}

impl Drop for SnapshotFileBacking {
    fn drop(&mut self) {
        // Connection::drop retries any remaining close before custody drops.
        drop(self.connection.take());
    }
}

fn validate_settings(connection: &Connection) -> Result<(), SnapshotBackingError> {
    let journal: String = connection.query_row("PRAGMA main.journal_mode", [], |row| row.get(0))?;
    let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    if journal != "memory" || temp_store != 2 {
        return Err(SnapshotBackingError::Refused(
            SnapshotCustodyRefusal::MemorySettings,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "receipt_query_snapshot_backing/tests.rs"]
mod tests;
