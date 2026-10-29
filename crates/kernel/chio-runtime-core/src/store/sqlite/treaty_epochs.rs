use chio_core_types::PublicKey;
use chio_kernel::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{sqlite_error, SqliteRuntimeOrchestrationStore};
use crate::treaty_epoch::{
    treaty_epoch_from_wire, TreatyEpochError, VerifiedTreatyEpochUpdate, MAX_TREATY_EPOCH_BYTES,
};
use crate::ChioRuntimeError;

mod authorization;
mod storage;
use storage::*;

fn refusal(code: &'static str, detail: &str) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code,
        detail: detail.into(),
    }
}

fn epoch_error(error: TreatyEpochError) -> ChioRuntimeError {
    let code = match error {
        TreatyEpochError::AuthorityMismatch => "treaty_epoch_authority_mismatch",
        TreatyEpochError::InvalidSignature => "treaty_epoch_signature_invalid",
        TreatyEpochError::Revoked => "treaty_revoked",
        TreatyEpochError::Withdrawn => "treaty_withdrawn",
        TreatyEpochError::Stale => "treaty_epoch_expired",
        _ => "treaty_epoch_invalid",
    };
    ChioRuntimeError::Rejected {
        code,
        detail: error.to_string(),
    }
}

impl SqliteRuntimeOrchestrationStore {
    pub fn provision_treaty_epoch_authority(
        &self,
        verifier_id: AdmissionIdentifier,
        treaty_id: AdmissionIdentifier,
        authority: PublicKey,
    ) -> Result<(), ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        check_count(&tx, "runtime_treaty_epoch_pins", MAX_PINS, false)?;
        let pin = Pin {
            verifier_id,
            treaty_id,
            authority,
        };
        let key = authority_id(&pin.verifier_id, &pin.treaty_id)?;
        let bytes = encode(&pin)?;
        let existing = read_blob(&tx, "SELECT CASE WHEN typeof(canonical_bytes) = 'blob' AND length(canonical_bytes) BETWEEN 1 AND 1048576 THEN canonical_bytes END FROM runtime_treaty_epoch_pins WHERE authority_id = ?1", params![key])?;
        if let Some(existing) = existing {
            if existing != bytes {
                return Err(refusal(
                    "treaty_epoch_authority_mismatch",
                    "provisioned treaty authority cannot be replaced",
                ));
            }
        } else {
            check_count(&tx, "runtime_treaty_epoch_pins", MAX_PINS, true)?;
            tx.execute("INSERT INTO runtime_treaty_epoch_pins (authority_id, canonical_bytes) VALUES (?1, ?2)", params![key, bytes]).map_err(sqlite_error)?;
        }
        tx.commit().map_err(sqlite_error)
    }

    pub fn apply_treaty_epoch_update(
        &self,
        expected_head: Option<&AdmissionDigest>,
        update: &VerifiedTreatyEpochUpdate,
    ) -> Result<(), ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let body = update.body();
        let pin = load_pin(&tx, &body.verifier_id, &body.treaty_id)?;
        let bytes = encode(update.envelope())?;
        let verified = treaty_epoch_from_wire(&bytes, &pin.authority).map_err(epoch_error)?;
        if verified.body_digest() != update.body_digest() {
            return Err(refusal(
                "treaty_epoch_binding_mismatch",
                "verified update digest changed",
            ));
        }
        let key = authority_id(&body.verifier_id, &body.treaty_id)?;
        let head = load_head(&tx, &key)?;
        check_count(&tx, "runtime_treaty_epoch_records", MAX_RECORDS, false)?;
        if head.as_ref() == Some(update.body_digest()) {
            let retained = load_record(&tx, &pin, update.body_digest())?;
            if encode(retained.envelope())? != bytes
                || expected_head != body.previous_record_sha256.as_ref()
            {
                return Err(refusal(
                    "treaty_epoch_update_conflict",
                    "epoch retry differs from retained update",
                ));
            }
            return tx.commit().map_err(sqlite_error);
        }
        if head.as_ref() != expected_head || head.as_ref() != body.previous_record_sha256.as_ref() {
            return Err(refusal(
                "treaty_epoch_update_conflict",
                "epoch predecessor differs from current head",
            ));
        }
        let previous = head
            .as_ref()
            .map(|digest| load_record(&tx, &pin, digest))
            .transpose()?;
        let expected_sequence = previous
            .as_ref()
            .map_or(Some(1), |old| old.body().sequence.checked_add(1));
        if expected_sequence != Some(body.sequence) {
            return Err(refusal(
                "treaty_epoch_update_conflict",
                "epoch sequence does not advance current head",
            ));
        }
        let maximum: Option<i64> = tx
            .query_row(
                "SELECT MAX(sequence) FROM runtime_treaty_epoch_records WHERE authority_id = ?1",
                params![key],
                |r| r.get(0),
            )
            .map_err(sqlite_error)?;
        if maximum.and_then(|n| u64::try_from(n).ok())
            != previous.as_ref().map(|v| v.body().sequence)
        {
            return Err(refusal(
                "treaty_epoch_invalid",
                "epoch head does not identify latest retained history",
            ));
        }
        check_count(&tx, "runtime_treaty_epoch_records", MAX_RECORDS, true)?;
        if head.is_none() {
            check_count(&tx, "runtime_treaty_epoch_heads", MAX_PINS, true)?;
        }
        tx.execute("INSERT INTO runtime_treaty_epoch_records (authority_id, record_digest, sequence, canonical_bytes) VALUES (?1, ?2, ?3, ?4)", params![key, update.body_digest().as_str(), super::sqlite_i64(body.sequence, "treaty epoch sequence")?, bytes]).map_err(sqlite_error)?;
        tx.execute("INSERT INTO runtime_treaty_epoch_heads (authority_id, record_digest) VALUES (?1, ?2) ON CONFLICT(authority_id) DO UPDATE SET record_digest = excluded.record_digest", params![key, update.body_digest().as_str()]).map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)
    }
}

#[cfg(test)]
mod tests;
