//! Commit a host-prepared invocation once, before it can cross admission.
use super::{read_process, require_running, Store};
use crate::{ProcessError, MAX_STATE_BLOB_BYTES};
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::{canonical_json_bytes, sha256_hex, Keypair};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::Value;

impl Store {
    pub fn prepare_invocation(
        &mut self,
        process_id: &str,
        operation_key: &str,
        binding: &str,
        prepare: impl FnOnce(&CapabilityToken, &Keypair) -> Result<Value, ProcessError>,
    ) -> Result<Value, ProcessError> {
        crate::validate_id(operation_key)?;
        if binding.len() != 64
            || !binding
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ProcessError::Invalid("invalid preparation binding"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process = read_process(&tx, process_id)?
            .ok_or_else(|| ProcessError::NotFound(process_id.into()))?;
        require_running(&process)?;
        let existing: Option<(String, String)> = tx.query_row(
            "SELECT binding, sha256 FROM process_prepared_invocations WHERE process_id=?1 AND operation_key=?2",
            params![process_id, operation_key], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if let Some((original, sha256)) = existing {
            if original != binding {
                return Err(ProcessError::Conflict);
            }
            let bytes = super::blobs::read_bytes(&tx, process_id, &sha256)?
                .ok_or(ProcessError::BlobMissing)?;
            if sha256_hex(&bytes) != sha256 {
                return Err(ProcessError::BlobCorrupt);
            }
            return Ok(serde_json::from_slice(&bytes)?);
        }
        let count: u32 = tx.query_row(
            "SELECT count(*) FROM process_prepared_invocations WHERE process_id=?1",
            [process_id],
            |row| row.get(0),
        )?;
        if count >= process.limits.max_calls {
            return Err(ProcessError::Limit("prepared invocations"));
        }
        let seed = zeroize::Zeroizing::new(tx.query_row(
            "SELECT seed_hex FROM process_delegation_keys WHERE process_id=?1",
            [process_id],
            |row| row.get::<_, String>(0),
        )?);
        let key = Keypair::from_seed_hex(&seed)?;
        if key.public_key() != process.capability.subject {
            return Err(ProcessError::Conflict);
        }
        let value = prepare(&process.capability, &key)?;
        let bytes = canonical_json_bytes(&value)?;
        if bytes.len() > MAX_STATE_BLOB_BYTES {
            return Err(ProcessError::Invalid("prepared invocation is too large"));
        }
        let sha256 = sha256_hex(&bytes);
        let storage = super::blobs::usage(&tx, &process)?;
        let size = u64::try_from(bytes.len())
            .map_err(|_| ProcessError::Invalid("prepared invocation size overflow"))?;
        if super::blobs::read_bytes(&tx, process_id, &sha256)?.is_none() {
            if storage
                .tree_bytes
                .checked_add(size)
                .is_none_or(|total| total > u64::from(storage.limits.max_bytes))
                || storage.tree_blobs >= u64::from(storage.limits.max_blobs)
            {
                return Err(ProcessError::Limit("immutable process state"));
            }
            tx.execute(
                "INSERT INTO process_state_blobs(process_id,sha256,data) VALUES(?1,?2,?3)",
                params![process_id, sha256, bytes],
            )?;
        }
        tx.execute("INSERT INTO process_prepared_invocations(process_id,operation_key,binding,sha256) VALUES(?1,?2,?3,?4)", params![process_id, operation_key, binding, sha256])?;
        tx.commit()?;
        Ok(value)
    }
}
