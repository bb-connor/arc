//! Protected setup custody installed with a recovery deployment: the unique
//! native routing context of each scope and the tenant setup requirement.

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{Connection, Transaction};

use crate::serving_owner::SqliteServingOwner;

use super::recovery_records::{
    load_record, persist_protected_record, require_latest_projection_head, ProtectedRecord,
    ProtectedRecordKind, ProtectedWrite,
};
use super::recovery_resources::{require_recovery_floor, RecoveryPressureStage};
use super::{invariant, sqlite_error};

mod context;

pub(super) use context::register_native_setup_context;

const CONTEXT_PREFIX: &str = "protected-setup-context:";
const TENANT_PREFIX: &str = "protected-setup-tenant:";
const FAMILY_BYTES: i64 = 48 * 1024 * 1024;
const FAMILY_EVENTS: i64 = 57344;

fn refused(_: impl core::fmt::Display) -> AdmissionOperationStoreError {
    invariant("protected recovery setup refused")
}

/// A current setup record that is the latest head of both chains.
fn authenticated_record(
    tx: &Connection,
    key: &str,
) -> Result<Option<ProtectedRecord>, AdmissionOperationStoreError> {
    let record = load_record(tx, key)?;
    if let Some(record) = &record {
        require_latest_projection_head(tx, record)?;
    }
    Ok(record)
}

/// Persist one setup record within the retained protected-setup family bound.
fn save_setup_record(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    write: &ProtectedWrite<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    if write.kind != ProtectedRecordKind::Command
        || !(write.key.starts_with(CONTEXT_PREFIX) || write.key.starts_with(TENANT_PREFIX))
    {
        return Err(invariant("protected record namespace or kind refused"));
    }
    require_recovery_floor(tx, RecoveryPressureStage::Intake)?;
    let existing = load_record(tx, write.key)?;
    let (retained, events): (i64, i64) = tx
        .query_row(
            "SELECT coalesce(sum(length(payload)), 0),
                    (SELECT count(*) FROM main.admission_operation_recovery_events
                     WHERE record_key GLOB 'protected-setup*')
             FROM main.admission_operation_recovery_records
             WHERE record_key GLOB 'protected-setup*'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    let replaced = existing
        .as_ref()
        .map_or(Ok(0), |record| i64::try_from(record.payload.len()))
        .map_err(|_| invariant("recovery retained bytes exhausted"))?;
    let added = i64::try_from(write.payload.len())
        .map_err(|_| invariant("recovery retained bytes exhausted"))?;
    let next = retained
        .checked_sub(replaced)
        .and_then(|bytes| bytes.checked_add(added))
        .ok_or_else(|| invariant("recovery retained bytes exhausted"))?;
    if next > FAMILY_BYTES || events >= FAMILY_EVENTS {
        return Err(invariant("recovery retained resource exhausted"));
    }
    persist_protected_record(tx, owner, write).map(|_| ())
}
