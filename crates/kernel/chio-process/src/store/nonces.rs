//! Retained transport material. The kernel owns nonce issuance and consumption.

use chio_kernel::execution_nonce::SignedExecutionNonce;

use super::*;
use crate::canonical_json_bytes;

const MAX_NONCE_BYTES: usize = 16_384;

impl Store {
    pub fn retained_nonce(
        &self,
        process: &str,
        key: &str,
        attempt: u32,
    ) -> Result<Option<SignedExecutionNonce>, ProcessError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT nonce_json FROM process_call_nonces WHERE process_id = ?1 AND operation_key = ?2 AND attempt = ?3",
                params![process, key, attempt],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                if bytes.is_empty() || bytes.len() > MAX_NONCE_BYTES {
                    return Err(ProcessError::Invalid("retained nonce exceeds its bound"));
                }
                let nonce: SignedExecutionNonce = serde_json::from_slice(&bytes)?;
                if canonical_json_bytes(&nonce)? != bytes {
                    return Err(ProcessError::Invalid("retained nonce is not canonical"));
                }
                Ok(nonce)
            })
            .transpose()
    }

    pub fn retain_nonce(
        &mut self,
        process: &str,
        key: &str,
        attempt: u32,
        request_hash: &str,
        nonce: &SignedExecutionNonce,
    ) -> Result<(), ProcessError> {
        let bytes = canonical_json_bytes(nonce)?;
        if bytes.is_empty() || bytes.len() > MAX_NONCE_BYTES {
            return Err(ProcessError::Invalid("execution nonce exceeds its bound"));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let snapshot = read_process(&transaction, process)?
            .ok_or_else(|| ProcessError::NotFound(process.to_owned()))?;
        require_running(&snapshot)?;
        let bound: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM process_calls WHERE process_id = ?1 AND operation_key = ?2 AND attempts = ?3 AND request_hash = ?4)",
            params![process, key, attempt, request_hash],
            |row| row.get(0),
        )?;
        if !bound {
            return Err(ProcessError::Conflict);
        }
        transaction.execute(
            "INSERT OR IGNORE INTO process_call_nonces(process_id, operation_key, attempt, nonce_json) VALUES (?1, ?2, ?3, ?4)",
            params![process, key, attempt, bytes],
        )?;
        let retained: Vec<u8> = transaction.query_row(
            "SELECT nonce_json FROM process_call_nonces WHERE process_id = ?1 AND operation_key = ?2 AND attempt = ?3",
            params![process, key, attempt],
            |row| row.get(0),
        )?;
        if retained != bytes {
            return Err(ProcessError::Conflict);
        }
        transaction.commit()?;
        Ok(())
    }
}
