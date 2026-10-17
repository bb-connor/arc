//! The single writer of protected recovery records. Each write changes one
//! current projection by an exact fresh INSERT or a version-guarded UPDATE,
//! appends the next local event and appends its global recovery commit, all
//! inside the caller's fenced owning transaction.

use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_security_types::recovery::RecoveryScopeV1;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Serialize;

use crate::serving_owner::SqliteServingOwner;

use super::digest::{
    event_digest, is_digest_hex, record_digest, EventDigestInput, RecordDigestInput,
};
use super::global_coverage::RECOVERY_MUTATION_KIND;
use super::history::current_event;
use super::record::{load_record, ProtectedRecord, RecordKind};
use super::{
    invariant, require_key, safe_integer, sqlite_error, sqlite_i64, stored_digest, stored_key,
    GENESIS_DIGEST, MAX_RECORD_PAYLOAD_BYTES, MAX_SAFE_INTEGER,
};

#[cfg(test)]
mod tests;

/// Record kinds this writer may create. A native workflow identity is never
/// minted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) enum ProtectedRecordKind {
    Deployment,
    Command,
}

impl ProtectedRecordKind {
    const fn record_kind(self) -> RecordKind {
        match self {
            Self::Deployment => RecordKind::Deployment,
            Self::Command => RecordKind::Command,
        }
    }
}

/// One exact projection a writer intends to retain.
#[derive(Clone, Copy)]
pub(in crate::admission_operation_store) struct ProtectedWrite<'a> {
    pub key: &'a str,
    pub scope: &'a str,
    pub kind: ProtectedRecordKind,
    pub payload: &'a [u8],
}

/// Canonical JSON bytes of `value`, refused when empty or above the record
/// payload bound.
pub(in crate::admission_operation_store) fn encode_protected<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| invariant(format!("recovery encoding refused: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(invariant("recovery resource exhausted"));
    }
    Ok(bytes)
}

/// The record scope key of a recovery scope: SHA-256 of its canonical bytes.
pub(in crate::admission_operation_store) fn protected_scope_key(
    scope: &RecoveryScopeV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode_protected(scope)?))
}

/// Persist `write` as the next version of its key and return that version.
/// A fresh key is an exact INSERT at version 1. An existing key keeps its
/// scope and kind and is an UPDATE guarded by its authenticated version.
pub(in crate::admission_operation_store) fn persist_protected_record(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    write: &ProtectedWrite<'_>,
) -> Result<u64, AdmissionOperationStoreError> {
    require_key(write.key)?;
    if !is_digest_hex(write.scope) {
        return Err(invariant("recovery record identity is not canonical"));
    }
    if write.payload.is_empty() || write.payload.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(invariant("recovery record quota exhausted"));
    }
    require_canonical_payload(write.payload)?;
    let kind = write.kind.record_kind();
    let version = match load_record(tx, write.key)? {
        None => {
            insert_fresh(tx, write, kind)?;
            1
        }
        Some(current) => {
            if current.scope != write.scope || current.kind != kind || current.native.is_some() {
                return Err(invariant("protected record ownership changed"));
            }
            let next = current
                .version
                .checked_add(1)
                .filter(|version| *version <= MAX_SAFE_INTEGER)
                .ok_or_else(|| invariant("recovery version exhausted"))?;
            update_current(tx, write, kind, current.version, next)?;
            next
        }
    };
    append_event(tx, owner, write, kind, version)?;
    owner
        .append_global_commit(tx, RECOVERY_MUTATION_KIND, "recovery", write.key, version)
        .map_err(crate::admission_operation_store::map_owner_error)?;
    Ok(version)
}

/// Refuse a source record that is not the latest head of both chains: its
/// authenticated latest event must have exactly one global recovery commit of
/// the recovery mutation kind at a safe commit sequence, and that commit must
/// be the key's latest global reference.
pub(in crate::admission_operation_store) fn require_latest_projection_head(
    tx: &Connection,
    record: &ProtectedRecord,
) -> Result<(), AdmissionOperationStoreError> {
    let version = sqlite_i64(record.version, "recovery record version")?;
    let lost = || invariant("historical deployment lost its global reference");
    let mut statement = tx
        .prepare(&format!(
            "SELECT
                CASE WHEN typeof(commit_sequence) = 'integer' THEN commit_sequence ELSE 0 END,
                CASE WHEN {} THEN projection_reference_digest END,
                CASE WHEN typeof(mutation_kind) = 'text' AND mutation_kind = ?3
                    THEN 1 ELSE 0 END
             FROM main.authority_global_commits
             WHERE projection_kind = 'recovery' AND projection_key = ?1
               AND projection_sequence = ?2
             ORDER BY commit_sequence LIMIT 2",
            stored_digest("projection_reference_digest")
        ))
        .map_err(sqlite_error)?;
    let references = statement
        .query_map(
            params![record.key, version, RECOVERY_MUTATION_KIND],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            },
        )
        .map_err(sqlite_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sqlite_error)?;
    let [(commit, reference, mutation_matches)] = references.as_slice() else {
        return Err(lost());
    };
    if !*mutation_matches {
        return Err(invariant("recovery global commit mutation kind differs"));
    }
    let Some(reference) = reference else {
        return Err(lost());
    };
    if *reference != record.event.event_digest {
        return Err(lost());
    }
    let commit = safe_integer(*commit, "recovery global commit sequence")?;
    let latest: Option<(i64, i64)> = tx
        .query_row(
            "SELECT
                CASE WHEN typeof(projection_sequence) = 'integer'
                    THEN projection_sequence ELSE 0 END,
                CASE WHEN typeof(commit_sequence) = 'integer' THEN commit_sequence ELSE 0 END
             FROM main.authority_global_commits
             WHERE projection_kind = 'recovery' AND projection_key = ?1
             ORDER BY projection_sequence DESC, commit_sequence DESC LIMIT 1",
            [&record.key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((latest_version, latest_commit)) = latest else {
        return Err(invariant(
            "protected source projection is not its latest head",
        ));
    };
    let latest_version =
        safe_integer(latest_version, "recovery latest global projection sequence")?;
    let latest_commit = safe_integer(latest_commit, "recovery latest global commit sequence")?;
    if (latest_version, latest_commit) != (record.version, commit) {
        return Err(invariant(
            "protected source projection is not its latest head",
        ));
    }
    Ok(())
}

/// Whether the retained version 1 event of `write.key` records exactly
/// `write` at version 1.
pub(in crate::admission_operation_store) fn first_version_retains(
    tx: &Connection,
    write: &ProtectedWrite<'_>,
) -> Result<bool, AdmissionOperationStoreError> {
    require_key(write.key)?;
    let expected = record_digest(&RecordDigestInput {
        key: write.key,
        scope: write.scope,
        kind: write.kind.record_kind(),
        version: 1,
        payload: write.payload,
        native: None,
    })?;
    let retained: Option<Option<String>> = tx
        .query_row(
            &format!(
                "SELECT CASE WHEN {} THEN record_digest END
                 FROM main.admission_operation_recovery_events
                 WHERE record_key = ?1 AND record_version = 1",
                stored_digest("record_digest")
            ),
            [write.key],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(retained.flatten().as_deref() == Some(expected.as_str()))
}

fn require_canonical_payload(payload: &[u8]) -> Result<(), AdmissionOperationStoreError> {
    let invalid = || invariant("recovery record payload is not canonical JSON");
    let value: serde_json::Value = serde_json::from_slice(payload).map_err(|_| invalid())?;
    if canonical_json_bytes(&value).map_err(|_| invalid())? != payload {
        return Err(invalid());
    }
    Ok(())
}

fn insert_fresh(
    tx: &Transaction<'_>,
    write: &ProtectedWrite<'_>,
    kind: RecordKind,
) -> Result<(), AdmissionOperationStoreError> {
    let inserted = tx
        .execute(
            "INSERT INTO main.admission_operation_recovery_records
             (record_key, scope_key, kind, version, payload)
             VALUES (?1, ?2, ?3, 1, ?4)",
            params![write.key, write.scope, kind.as_str(), write.payload],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant("protected record ownership changed"));
    }
    Ok(())
}

fn update_current(
    tx: &Transaction<'_>,
    write: &ProtectedWrite<'_>,
    kind: RecordKind,
    current: u64,
    next: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let updated = tx
        .execute(
            "UPDATE main.admission_operation_recovery_records
             SET version = ?2, payload = ?3
             WHERE record_key = ?1 AND version = ?4 AND scope_key = ?5 AND kind = ?6
               AND native_namespace IS NULL AND native_request IS NULL",
            params![
                write.key,
                sqlite_i64(next, "recovery record version")?,
                write.payload,
                sqlite_i64(current, "recovery record version")?,
                write.scope,
                kind.as_str()
            ],
        )
        .map_err(sqlite_error)?;
    if updated != 1 {
        return Err(invariant("protected record ownership changed"));
    }
    Ok(())
}

/// The authenticated chain head: the next sequence, the previous event
/// digest and the time floor every later event must not precede.
fn chain_head(tx: &Connection) -> Result<(u64, String, u64), AdmissionOperationStoreError> {
    let head: Option<(i64, Option<String>, i64)> = tx
        .query_row(
            &format!(
                "SELECT sequence, CASE WHEN {} THEN record_key END,
                        CASE WHEN typeof(record_version) = 'integer' THEN record_version ELSE 0 END
                 FROM main.admission_operation_recovery_events
                 ORDER BY sequence DESC LIMIT 1",
                stored_key("record_key")
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((sequence, key, version)) = head else {
        return Ok((1, GENESIS_DIGEST.to_owned(), 0));
    };
    let key = key.ok_or_else(|| invariant("recovery history event exceeds its bound"))?;
    let version = safe_integer(version, "recovery history event version")?;
    let event = current_event(tx, &key, version)?;
    if sqlite_i64(event.sequence, "recovery history sequence")? != sequence {
        return Err(invariant("recovery history head is not authenticated"));
    }
    let next = event
        .sequence
        .checked_add(1)
        .filter(|sequence| *sequence <= MAX_SAFE_INTEGER)
        .ok_or_else(|| invariant("recovery history exhausted"))?;
    Ok((next, event.event_digest, event.observed_at))
}

fn append_event(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    write: &ProtectedWrite<'_>,
    kind: RecordKind,
    version: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let (sequence, previous, floor) = chain_head(tx)?;
    let observed = crate::admission_operation_store::schema::observe_authority_time(tx, owner)?;
    if observed < floor {
        return Err(invariant("recovery history time regressed"));
    }
    let record = record_digest(&RecordDigestInput {
        key: write.key,
        scope: write.scope,
        kind,
        version,
        payload: write.payload,
        native: None,
    })?;
    let event = event_digest(&EventDigestInput {
        sequence,
        key: write.key,
        version,
        record_digest: &record,
        previous_digest: &previous,
        observed_at: observed,
    })?;
    tx.execute(
        "INSERT INTO main.admission_operation_recovery_events
         (sequence, record_key, record_version, record_digest, previous_digest,
          event_digest, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            sqlite_i64(sequence, "recovery history sequence")?,
            write.key,
            sqlite_i64(version, "recovery record version")?,
            record,
            previous,
            event,
            sqlite_i64(observed, "recovery history time")?
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}
