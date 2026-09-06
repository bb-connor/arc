use chio_core_types::crypto::sha256_hex;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{read_process, require_running, Store};
use crate::{
    ProcessError, ProcessSnapshot, ProcessStorage, StateBlobRef, MAX_STATE_BLOB_BYTES,
    STATE_BLOB_PROTOCOL,
};

impl Store {
    pub fn put_blob(&mut self, id: &str, bytes: &[u8]) -> Result<StateBlobRef, ProcessError> {
        if bytes.len() > MAX_STATE_BLOB_BYTES {
            return Err(ProcessError::Invalid("state blob is too large"));
        }
        let sha256 = sha256_hex(bytes);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process =
            read_process(&tx, id)?.ok_or_else(|| ProcessError::NotFound(id.to_owned()))?;
        require_running(&process)?;
        if let Some(stored) = read_bytes(&tx, id, &sha256)? {
            if stored != bytes {
                return Err(ProcessError::BlobCorrupt);
            }
        } else {
            let storage = usage(&tx, &process)?;
            if storage.tree_bytes + bytes.len() as u64 > u64::from(storage.limits.max_bytes)
                || storage.tree_blobs >= u64::from(storage.limits.max_blobs)
            {
                return Err(ProcessError::Limit("immutable process state"));
            }
            tx.execute(
                "INSERT INTO process_state_blobs(process_id,sha256,data) VALUES(?1,?2,?3)",
                params![id, sha256, bytes],
            )?;
        }
        tx.commit()?;
        Ok(StateBlobRef {
            sha256,
            bytes: bytes.len() as u32,
        })
    }

    pub fn read_blob(&self, id: &str, sha256: &str) -> Result<Vec<u8>, ProcessError> {
        self.require_running(id)?;
        let bytes = read_bytes(&self.connection, id, sha256)?.ok_or(ProcessError::BlobMissing)?;
        if sha256_hex(&bytes) != sha256 {
            return Err(ProcessError::BlobCorrupt);
        }
        Ok(bytes)
    }

    pub fn storage(&self, id: &str) -> Result<ProcessStorage, ProcessError> {
        let process = self.process(id)?;
        require_running(&process)?;
        usage(&self.connection, &process)
    }
}

fn read_bytes(
    connection: &Connection,
    id: &str,
    sha256: &str,
) -> Result<Option<Vec<u8>>, ProcessError> {
    // Refuse oversized or non-blob rows before allocating their contents, including after corruption.
    let row: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN typeof(data)='blob' AND length(data)<=?3 THEN data ELSE NULL END
         FROM process_state_blobs WHERE process_id=?1 AND sha256=?2",
            params![id, sha256, MAX_STATE_BLOB_BYTES as i64],
            |row| row.get(0),
        )
        .optional()?;
    match row {
        Some(Some(bytes)) => Ok(Some(bytes)),
        Some(None) => Err(ProcessError::BlobCorrupt),
        None => Ok(None),
    }
}

fn usage(
    connection: &Connection,
    process: &ProcessSnapshot,
) -> Result<ProcessStorage, ProcessError> {
    let counts: [i64; 4] = connection.query_row(
        "SELECT COALESCE(SUM(CASE WHEN b.process_id=?1 THEN length(b.data) ELSE 0 END),0),
         COALESCE(SUM(CASE WHEN b.process_id=?1 THEN 1 ELSE 0 END),0), COALESCE(SUM(length(b.data)),0), COUNT(*)
         FROM process_state_blobs b JOIN processes p ON p.id=b.process_id WHERE p.root_id=?2",
        params![process.id, process.root_id], |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]))?;
    let checked = |value| u64::try_from(value).map_err(|_| ProcessError::BlobCorrupt);
    let [process_bytes, process_blobs, tree_bytes, tree_blobs] = counts;
    Ok(ProcessStorage {
        protocol: STATE_BLOB_PROTOCOL.to_owned(),
        max_blob_bytes: MAX_STATE_BLOB_BYTES as u32,
        limits: process.limits.state,
        process_bytes: checked(process_bytes)?,
        process_blobs: checked(process_blobs)?,
        tree_bytes: checked(tree_bytes)?,
        tree_blobs: checked(tree_blobs)?,
    })
}
