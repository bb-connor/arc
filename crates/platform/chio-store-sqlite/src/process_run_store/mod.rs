//! SQLite persistence for process-host run journals.
//!
//! Worker lifecycle rules live in `chio_process::run_journal`; this store
//! keeps the rows, the per-statement atomicity and the schema contract.

mod containers;
mod settlements;
mod sockets;
#[cfg(any(test, feature = "tamper-test-support"))]
pub mod tamper;
#[cfg(test)]
mod tests;
mod workers;

pub use sockets::{AbandonedSocketIntent, SocketIntentRetirement};

use crate::schema_version::{inspect_schema, SchemaState, SchemaTransaction, SchemaVersionError};
use chio_process::run_journal::{
    workers_within_capacity, JournalError, WorkerSeed, WorkerTransition,
};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

const SCHEMA: &str = include_str!("schema.sql");
const NAMESPACE: &str = "process_run_journal";
const INSERT_BINDING: &str = "INSERT OR IGNORE INTO run_binding VALUES(1, ?1)";
const READ_BINDING: &str = "SELECT binding FROM run_binding WHERE singleton=1";

/// How a host tool opens a journal the runner already created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Reads only, alongside a live runner.
    Read,
    /// Reads and writes alongside a live runner.
    Write,
    /// A stopped host's journal for relocation export. A symlinked journal is
    /// refused, and a journal the runner never initialized holds no intents.
    Export,
}

/// The scheduler's connection to one run journal.
pub struct SqliteRunJournal {
    db: Connection,
    initialized: bool,
}

/// A container's own connection, so engine I/O never blocks the scheduler
/// while the durable create/start boundary is still recorded per container.
pub struct SqliteContainerJournal {
    db: Connection,
}

fn connection(path: &Path, flags: OpenFlags) -> Result<Connection, JournalError> {
    let db = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(storage_error)?;
    db.busy_timeout(Duration::from_secs(5))
        .map_err(storage_error)?;
    Ok(db)
}

/// Opens a journal the runner created and checks it is the v1 schema. An
/// uninitialized journal is accepted only for export.
fn existing(path: &Path, access: Access) -> Result<(Connection, bool), JournalError> {
    let flags = match access {
        Access::Read => OpenFlags::SQLITE_OPEN_READ_ONLY,
        Access::Write => OpenFlags::SQLITE_OPEN_READ_WRITE,
        Access::Export => OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    };
    let db = connection(path, flags)?;
    if access != Access::Read {
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(storage_error)?;
    }
    match inspect_schema(&db, &[NAMESPACE]).map_err(schema_error)? {
        SchemaState::Empty if access == Access::Export => Ok((db, false)),
        SchemaState::Empty => Err(JournalError::Schema),
        SchemaState::Current => {
            crate::schema_version::validate_catalog(&db, SCHEMA).map_err(schema_error)?;
            Ok((db, true))
        }
    }
}

impl SqliteRunJournal {
    /// Opens the journal the runner owns, creating or checking the v1 schema
    /// and binding it to one plan and authority in one transaction. A journal
    /// bound to anything else is refused before any worker row is touched.
    pub fn open(path: &Path, binding: &str) -> Result<Self, JournalError> {
        let mut db = connection(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(storage_error)?;
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(storage_error)?;
        let creation = SchemaTransaction::begin(&mut db, &[NAMESPACE]).map_err(schema_error)?;
        if creation.is_fresh() {
            creation
                .connection()
                .execute_batch(SCHEMA)
                .map_err(storage_error)?;
            creation.stamp(NAMESPACE).map_err(schema_error)?;
        }
        creation.validate_catalog(SCHEMA).map_err(schema_error)?;
        let tx = creation.connection();
        tx.execute(INSERT_BINDING, [binding])
            .map_err(storage_error)?;
        let stored: String = tx
            .query_row(READ_BINDING, [], |row| row.get(0))
            .map_err(storage_error)?;
        if stored != binding {
            return Err(JournalError::Binding);
        }
        creation.commit().map_err(schema_error)?;
        Ok(Self {
            db,
            initialized: true,
        })
    }

    pub fn open_existing(path: &Path, access: Access) -> Result<Self, JournalError> {
        let (db, initialized) = existing(path, access)?;
        Ok(Self { db, initialized })
    }

    /// Seeds every known worker and returns interrupted attempts to pending,
    /// or to failed once their attempt budget is spent, in one transaction.
    pub fn recover(&mut self, workers: &[WorkerSeed<'_>]) -> Result<(), JournalError> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        for worker in workers {
            workers::ensure(&tx, worker.process)?;
            workers::transition(
                &tx,
                worker.process,
                WorkerTransition::Recover {
                    max_attempts: worker.max_attempts,
                },
            )?;
        }
        workers_within_capacity(workers::count(&tx)?)?;
        tx.commit().map_err(storage_error)
    }
}

impl SqliteContainerJournal {
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        Ok(Self {
            db: existing(path, Access::Write)?.0,
        })
    }
}

/// The LIMIT for a list read capped at `cap` rows. The extra row exposes a
/// journal holding more than its bound.
fn limit(cap: u32) -> u32 {
    cap.saturating_add(1)
}

/// Refuses a list read that returned more rows than its cap allows.
fn bounded<T>(rows: Vec<T>, cap: u32) -> Result<Vec<T>, JournalError> {
    if !u32::try_from(rows.len()).is_ok_and(|rows| rows <= cap) {
        return Err(JournalError::Integrity);
    }
    Ok(rows)
}

fn exactly_one(changed: usize, refusal: JournalError) -> Result<(), JournalError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(refusal)
    }
}

/// Takes the journal write lock before the first read, so every check a
/// caller makes inside the transaction still holds when it commits.
fn immediate(db: &Connection) -> Result<Transaction<'_>, JournalError> {
    Transaction::new_unchecked(db, TransactionBehavior::Immediate).map_err(storage_error)
}

fn storage_error(error: rusqlite::Error) -> JournalError {
    match error {
        rusqlite::Error::SqliteFailure(ref inner, _) => match inner.code {
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                JournalError::Busy
            }
            rusqlite::ErrorCode::DatabaseCorrupt
            | rusqlite::ErrorCode::NotADatabase
            | rusqlite::ErrorCode::ConstraintViolation => JournalError::Integrity,
            _ => JournalError::Persistence,
        },
        rusqlite::Error::QueryReturnedNoRows
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::FromSqlConversionFailure(..) => JournalError::Integrity,
        _ => JournalError::Persistence,
    }
}

fn schema_error(error: SchemaVersionError) -> JournalError {
    match error {
        SchemaVersionError::Sqlite(error) => storage_error(error),
        SchemaVersionError::Io(_) => JournalError::Persistence,
        _ => JournalError::Schema,
    }
}
