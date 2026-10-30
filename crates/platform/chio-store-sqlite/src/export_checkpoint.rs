//! Write-ahead log checkpoint of a stopped store file before it is copied.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CheckpointError {
    #[error("relocation checkpoint is busy")]
    Busy,
    #[error("relocation checkpoint failed")]
    Failed,
}

/// Folds a database's write-ahead log into its main file so the file is
/// complete on its own. A symlinked path is refused. The caller guarantees no
/// writer is live.
pub fn checkpoint_for_export(path: &Path) -> Result<(), CheckpointError> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| CheckpointError::Failed)?;
    db.busy_timeout(Duration::from_secs(5))
        .map_err(|_| CheckpointError::Failed)?;
    let busy: i64 = db
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(|_| CheckpointError::Failed)?;
    if busy != 0 {
        return Err(CheckpointError::Busy);
    }
    Ok(())
}
