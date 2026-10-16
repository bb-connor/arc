//! Physical recovery pressure on one persistent WAL authority file.
//!
//! Pressure is the space available on the filesystem holding SQLite's open
//! main file and the committed WAL frames not yet checkpointed. Retained
//! database size and checkpointed WAL allocation are not quotas. Passing this
//! floor is not funding authorization.
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_sqlite_file_identity::{
    inspect_main_database_file_identity, main_database_available_bytes, SqliteAvailableSpaceError,
    SqliteFileIdentity, SqliteFileIdentityInspectionError,
};
use rusqlite::{Connection, OpenFlags};

use super::{invariant, sqlite_error};

const MIB: u64 = 1024 * 1024;
const INTAKE_WAL_LIMIT: u64 = 64 * MIB;
const INTAKE_FREE_FLOOR: u64 = 128 * MIB;
#[cfg(test)]
const PROGRESS_WAL_LIMIT: u64 = 128 * MIB;
#[cfg(test)]
const PROGRESS_FREE_FLOOR: u64 = 16 * MIB;
const PASSIVE_CHECKPOINT_BYTES: u64 = 32 * MIB;
const WAL_HEADER_BYTES: u64 = 32;
const WAL_FRAME_HEADER_BYTES: u64 = 24;

/// The work a write performs relative to work already owed on this file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoveryPressureStage {
    /// New recovery work keeps the reserve owed to admitted work.
    Intake,
    /// Already admitted work may spend the intake reserve.
    #[cfg(test)]
    OwedProgress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhysicalUsage {
    wal: u64,
    available: u64,
}

fn admits(usage: PhysicalUsage, stage: RecoveryPressureStage) -> bool {
    let (wal_limit, free_floor) = match stage {
        RecoveryPressureStage::Intake => (INTAKE_WAL_LIMIT, INTAKE_FREE_FLOOR),
        #[cfg(test)]
        RecoveryPressureStage::OwedProgress => (PROGRESS_WAL_LIMIT, PROGRESS_FREE_FLOOR),
    };
    usage.wal < wal_limit && usage.available >= free_floor
}

/// Refuse unless the file has headroom for `stage`. Nothing is checkpointed.
/// Inside a transaction the committed pressure is read through a separate
/// read-only observer whose main file must be the writer's own main file.
pub(super) fn require_recovery_floor(
    connection: &Connection,
    stage: RecoveryPressureStage,
) -> Result<(), AdmissionOperationStoreError> {
    require(connection, stage, false)
}

/// On an idle writer, run one nonblocking PASSIVE checkpoint once committed
/// frames reach 32 MiB, then apply the floor to the frames that remain.
pub(super) fn require_recovery_floor_before_transaction(
    connection: &Connection,
    stage: RecoveryPressureStage,
) -> Result<(), AdmissionOperationStoreError> {
    if !connection.is_autocommit() {
        return Err(invariant("recovery checkpoint requires an idle writer"));
    }
    require(connection, stage, true)
}

fn require(
    connection: &Connection,
    stage: RecoveryPressureStage,
    checkpoint: bool,
) -> Result<(), AdmissionOperationStoreError> {
    if !admits(physical_usage(connection, checkpoint)?, stage) {
        return Err(invariant("recovery disk headroom exhausted"));
    }
    Ok(())
}

fn physical_usage(
    connection: &Connection,
    checkpoint: bool,
) -> Result<PhysicalUsage, AdmissionOperationStoreError> {
    let path = connection
        .path()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| invariant("recovery requires a persistent authority"))?;
    let wal = if connection.is_autocommit() {
        wal_pressure(connection, checkpoint)?
    } else {
        // SQLite refuses checkpoints inside a transaction, and the writer must
        // not run another statement mid-transaction for this observation.
        wal_pressure(&authenticated_observer(connection, path)?, false)?
    };
    let available = main_database_available_bytes(connection).map_err(available_space_error)?;
    Ok(PhysicalUsage { wal, available })
}

/// A read-only, no-mutex, zero-busy-timeout connection to `path` whose open
/// main file is the writer's open main file. A missing path or one that now
/// names another file refuses, so free space and WAL pressure always describe
/// the same database.
fn authenticated_observer(
    writer: &Connection,
    path: &str,
) -> Result<Connection, AdmissionOperationStoreError> {
    let observer = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        AdmissionOperationStoreError::Unavailable("recovery WAL observer is unavailable".into())
    })?;
    observer
        .busy_timeout(std::time::Duration::ZERO)
        .map_err(sqlite_error)?;
    let held = file_identity(writer)?;
    let observed = file_identity(&observer)?;
    if (held.device, held.inode) != (observed.device, observed.inode) {
        return Err(invariant(
            "recovery WAL observer does not hold the writer's main file",
        ));
    }
    Ok(observer)
}

fn file_identity(
    connection: &Connection,
) -> Result<SqliteFileIdentity, AdmissionOperationStoreError> {
    inspect_main_database_file_identity(connection).map_err(identity_error)
}

fn identity_error(error: SqliteFileIdentityInspectionError) -> AdmissionOperationStoreError {
    match error {
        SqliteFileIdentityInspectionError::Io(source) => AdmissionOperationStoreError::Unavailable(
            format!("recovery file identity is unavailable: {source}"),
        ),
        SqliteFileIdentityInspectionError::Validation(message) => {
            invariant(format!("recovery file identity refused: {message}"))
        }
    }
}

fn available_space_error(error: SqliteAvailableSpaceError) -> AdmissionOperationStoreError {
    match error {
        SqliteAvailableSpaceError::Identity(error) => identity_error(error),
        SqliteAvailableSpaceError::Io(source) => AdmissionOperationStoreError::Unavailable(
            format!("recovery disk capacity is unavailable: {source}"),
        ),
        error @ (SqliteAvailableSpaceError::ZeroFragmentSize
        | SqliteAvailableSpaceError::CapacityOverflow) => {
            invariant(format!("recovery disk capacity refused: {error}"))
        }
    }
}

fn wal_pressure(
    connection: &Connection,
    checkpoint: bool,
) -> Result<u64, AdmissionOperationStoreError> {
    let mode: String = connection
        .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if mode != "wal" {
        return Err(invariant("recovery WAL profile is unsupported"));
    }
    let bytes = wal_backlog(connection, "PRAGMA main.wal_checkpoint(NOOP)")?;
    if checkpoint && bytes >= PASSIVE_CHECKPOINT_BYTES {
        // PASSIVE neither invokes the busy handler nor waits for readers. The
        // floor applies to the frames that remain after this one attempt.
        return wal_backlog(connection, "PRAGMA main.wal_checkpoint(PASSIVE)");
    }
    Ok(bytes)
}

fn wal_backlog(
    connection: &Connection,
    statement: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    let (busy, log, checkpointed): (i64, i64, i64) = connection
        .query_row(statement, [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(sqlite_error)?;
    let Some(frames) = backlog_frames(busy, log, checkpointed)? else {
        return Ok(0);
    };
    let page_size: i64 = connection
        .query_row("PRAGMA main.page_size", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    committed_wal_bytes(frames, page_size)
}

/// Uncheckpointed committed frames from one checkpoint result row, or `None`
/// when none remain. `(-1, -1)` without a busy flag is an unused WAL.
fn backlog_frames(
    busy: i64,
    log: i64,
    checkpointed: i64,
) -> Result<Option<u64>, AdmissionOperationStoreError> {
    if !matches!(busy, 0 | 1) {
        return Err(invariant("recovery WAL observation refused"));
    }
    if (log, checkpointed) == (-1, -1) {
        if busy != 0 {
            return Err(invariant("recovery WAL observation is unavailable"));
        }
        return Ok(None);
    }
    let frames = log
        .checked_sub(checkpointed)
        .filter(|_| log >= 0 && checkpointed >= 0)
        .and_then(|frames| u64::try_from(frames).ok())
        .ok_or_else(|| invariant("recovery WAL observation refused"))?;
    Ok((frames != 0).then_some(frames))
}

/// The WAL header plus `frames` frames, each a 24-byte header and one page.
fn committed_wal_bytes(frames: u64, page_size: i64) -> Result<u64, AdmissionOperationStoreError> {
    let page_size = u64::try_from(page_size)
        .ok()
        .filter(|size| (512..=65536).contains(size) && size.is_power_of_two())
        .ok_or_else(|| invariant("recovery WAL page size refused"))?;
    frames
        .checked_mul(page_size + WAL_FRAME_HEADER_BYTES)
        .and_then(|bytes| bytes.checked_add(WAL_HEADER_BYTES))
        .ok_or_else(|| invariant("recovery WAL capacity refused"))
}

#[cfg(test)]
mod tests;
