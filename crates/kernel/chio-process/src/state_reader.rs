//! Trusted operator reads without opening a kernel, renewing authority or migrating state.

use std::path::Path;
use std::time::Duration;

use chio_core_types::crypto::sha256_hex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::{Checkpoint, ProcessError, MAX_STATE_BLOB_BYTES};

/// Read retained application data using the trusted host's filesystem access.
/// This is an administrative API, not a worker authentication mechanism. It
/// permits reads after process cancellation or capability expiry, never returns
/// capability/credential/signing material, and performs no schema migration.
pub struct ProcessStateReader {
    connection: Connection,
}

impl ProcessStateReader {
    /// Open an existing private process journal with SQLite read-only flags.
    /// Embedders must protect its containing directory and enforce their host
    /// ABI before calling this API. SQLite may maintain WAL reader bookkeeping.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProcessError> {
        let path = path.as_ref();
        let file = path.symlink_metadata()?;
        let parent = path
            .parent()
            .ok_or(ProcessError::Invalid("missing journal parent"))?;
        let directory = parent.metadata()?;
        if !file.is_file() || !directory.is_dir() {
            return Err(ProcessError::Configuration(
                "expected an existing regular process journal",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if (file.permissions().mode() | directory.permissions().mode()) & 0o077 != 0 {
                return Err(ProcessError::Configuration("process state must be private"));
            }
        }
        let path = std::fs::canonicalize(parent)?.join(
            path.file_name()
                .ok_or(ProcessError::Invalid("missing journal name"))?,
        );
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        let version: u32 = connection.query_row(
            "SELECT version FROM process_runtime WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if version != 1 {
            return Err(ProcessError::Configuration(
                "unsupported process journal version",
            ));
        }
        Ok(Self { connection })
    }

    /// Read a bounded checkpoint. No capability token is decoded or returned.
    pub fn checkpoint(&self, process: &str) -> Result<Checkpoint, ProcessError> {
        let row: Option<(i64, Option<String>)> = self
            .connection
            .query_row(
                "SELECT revision, CASE WHEN typeof(checkpoint)='text' AND
             length(CAST(checkpoint AS BLOB))<=1048576 THEN checkpoint ELSE NULL END
             FROM processes WHERE id=?1",
                [process],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (revision, value) = row.ok_or_else(|| ProcessError::NotFound(process.to_owned()))?;
        Ok(Checkpoint {
            revision: u64::try_from(revision)
                .map_err(|_| ProcessError::Invalid("invalid checkpoint revision"))?,
            value: serde_json::from_str(
                &value.ok_or(ProcessError::Invalid("invalid checkpoint value"))?,
            )?,
        })
    }

    /// Read one process's immutable blob, verifying its bounds and digest.
    pub fn blob(&self, process: &str, sha256: &str) -> Result<Vec<u8>, ProcessError> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProcessError::Invalid("invalid state blob digest"));
        }
        let row: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT CASE WHEN typeof(data)='blob' AND length(data)<=?3 THEN data ELSE NULL END
             FROM process_state_blobs WHERE process_id=?1 AND sha256=?2",
                params![process, sha256, MAX_STATE_BLOB_BYTES as i64],
                |row| row.get(0),
            )
            .optional()?;
        let bytes = row
            .ok_or(ProcessError::BlobMissing)?
            .ok_or(ProcessError::BlobCorrupt)?;
        if sha256_hex(&bytes) != sha256 {
            return Err(ProcessError::BlobCorrupt);
        }
        Ok(bytes)
    }
}
