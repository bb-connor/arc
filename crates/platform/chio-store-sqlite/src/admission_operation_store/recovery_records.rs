//! Protected recovery record projections authenticated against their
//! immutable local event chain and, separately, the global commit chain.
//!
//! Startup order: `verify_local_history` needs only the record catalog and
//! runs before the global commit catalog is initialized.
//! `verify_global_coverage` is a mandatory later check of full-chain
//! validation and refuses when that catalog is absent.

use chio_kernel::admission_operation::AdmissionOperationStoreError;

use super::{invariant, sqlite_error, sqlite_i64, stored_u64};

mod digest;
mod global_coverage;
mod history;
mod record;
mod write;

#[cfg(test)]
mod tests;
#[cfg(test)]
use record::NativeIdentity;

pub(crate) use global_coverage::verify_global_coverage;
pub(crate) use history::projection_reference;
pub(in crate::admission_operation_store) use history::verify_local_history;
pub(in crate::admission_operation_store) use record::{
    decode_protected_payload, load_record, ProtectedRecord, RecordKind,
};
pub(in crate::admission_operation_store) use write::{
    encode_protected, first_version_retains, persist_protected_record, protected_scope_key,
    require_latest_projection_head, ProtectedRecordKind, ProtectedWrite,
};

const RECORDS_TABLE: &str = "admission_operation_recovery_records";
const EVENTS_TABLE: &str = "admission_operation_recovery_events";
const MAX_RECORD_KEY_CHARS: usize = 512;
const MAX_RECORD_KEY_BYTES: usize = 2048;
const MAX_RECORD_PAYLOAD_BYTES: usize = 262_144;
/// Characters of the longest record kind, `deployment`.
const MAX_RECORD_KIND_CHARS: usize = 10;
const MAX_NATIVE_REQUEST_CHARS: usize = 256;
const MAX_NATIVE_REQUEST_BYTES: usize = 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const GENESIS_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn require_key(key: &str) -> Result<(), AdmissionOperationStoreError> {
    if !key_within_bounds(key) {
        return Err(invariant("recovery record key exceeds its bound"));
    }
    Ok(())
}

fn key_within_bounds(key: &str) -> bool {
    let chars = key.chars().count();
    (1..=MAX_RECORD_KEY_CHARS).contains(&chars)
        && key.len() <= MAX_RECORD_KEY_BYTES
        && !key.contains('\0')
}

/// Character and NUL checks apply to every database encoding.
fn stored_text(column: &str, min_chars: usize, max_chars: usize) -> String {
    bounded_text(
        column,
        max_chars,
        &format!(
            "length({column}) BETWEEN {min_chars} AND {max_chars} \
             AND instr({column}, char(0)) = 0"
        ),
    )
}

/// Storage class and byte ceiling decide before `predicate` scans the value.
/// A direct column's `typeof` and `octet_length` read only its record header,
/// so a value beyond its ceiling is refused without being loaded, and four
/// bytes per character admits every valid UTF-8 and UTF-16 value.
fn bounded_text(column: &str, max_chars: usize, predicate: &str) -> String {
    let max_bytes = max_chars * 4;
    format!(
        "(CASE WHEN typeof({column}) = 'text' AND octet_length({column}) <= {max_bytes} \
         THEN {predicate} ELSE 0 END)"
    )
}

fn stored_key(column: &str) -> String {
    stored_text(column, 1, MAX_RECORD_KEY_CHARS)
}

fn stored_digest(column: &str) -> String {
    stored_text(column, 64, 64)
}

fn safe_integer(value: i64, field: &'static str) -> Result<u64, AdmissionOperationStoreError> {
    let value = stored_u64(value, field)?;
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(invariant(format!("{field} is out of range")));
    }
    Ok(value)
}

fn table_exists(
    connection: &rusqlite::Connection,
    name: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type = 'table' AND name = ?1)",
            [name],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}
