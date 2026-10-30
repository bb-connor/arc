use super::{bounded, immediate, limit, storage_error, SqliteRunJournal};
use chio_process::run_journal::{
    workers_within_capacity, JournalError, WorkerOutcome, WorkerRecord, WorkerState,
    WorkerTransition, MAX_WORKERS,
};
use rusqlite::{params, Connection, OptionalExtension};

const ENSURE: &str = "INSERT OR IGNORE INTO run_workers(process,state) VALUES(?1,'pending')";
const INSERT: &str = "INSERT INTO run_workers(process,state) VALUES(?1,'pending')";
const READ: &str = "SELECT process,state,attempts,suspensions,outcome,peak_resident_bytes,cpu_ms FROM run_workers WHERE process=?1";
pub(super) const LIST: &str = "SELECT process,state,attempts,suspensions,outcome,peak_resident_bytes,cpu_ms FROM run_workers ORDER BY process LIMIT ?1";
const COUNT: &str = "SELECT COUNT(*) FROM run_workers";
pub(super) const HAS_CONTAINER: &str =
    "SELECT EXISTS(SELECT 1 FROM run_containers WHERE process=?1)";
const WRITE: &str = "UPDATE run_workers SET state=?2,attempts=?3,suspensions=?4,outcome=?5,peak_resident_bytes=?6,cpu_ms=?7 WHERE process=?1";

/// A text column the journal domain refuses.
fn refused(column: usize, error: JournalError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(error))
}

fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkerRecord> {
    let state: String = row.get(1)?;
    let state = WorkerState::try_from(state.as_str()).map_err(|error| refused(1, error))?;
    let outcome = row.get::<_, Option<String>>(4)?;
    let outcome = outcome
        .map(|text| WorkerOutcome::parse(&text))
        .transpose()
        .map_err(|error| refused(4, error))?;
    let accounted = |column| -> rusqlite::Result<u64> {
        let value: i64 = row.get(column)?;
        u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
    };
    Ok(WorkerRecord {
        process: row.get(0)?,
        state,
        attempts: row.get(2)?,
        suspensions: row.get(3)?,
        outcome,
        peak_resident_bytes: accounted(5)?,
        cpu_ms: accounted(6)?,
    })
}

pub(super) fn read(db: &Connection, process: &str) -> Result<Option<WorkerRecord>, JournalError> {
    db.query_row(READ, [process], row)
        .optional()
        .map_err(storage_error)
}

pub(super) fn count(db: &Connection) -> Result<u32, JournalError> {
    db.query_row(COUNT, [], |row| row.get(0))
        .map_err(storage_error)
}

pub(super) fn ensure(db: &Connection, process: &str) -> Result<(), JournalError> {
    db.execute(ENSURE, [process]).map_err(storage_error)?;
    Ok(())
}

/// Applies a domain transition to the stored row. Callers own the
/// transaction so the read, container check and write commit together.
pub(super) fn transition(
    db: &Connection,
    process: &str,
    transition: WorkerTransition<'_>,
) -> Result<WorkerRecord, JournalError> {
    let current = read(db, process)?.ok_or(JournalError::MissingWorker)?;
    let has_container = matches!(transition, WorkerTransition::Unreserve)
        && db
            .query_row(HAS_CONTAINER, [process], |row| row.get::<_, bool>(0))
            .map_err(storage_error)?;
    let next = current.transition(transition, has_container)?;
    let peak = i64::try_from(next.peak_resident_bytes).map_err(|_| JournalError::Overflow)?;
    let cpu = i64::try_from(next.cpu_ms).map_err(|_| JournalError::Overflow)?;
    let written = db
        .execute(
            WRITE,
            params![
                next.process,
                next.state.as_str(),
                next.attempts,
                next.suspensions,
                next.outcome.as_ref().map(WorkerOutcome::as_str),
                peak,
                cpu
            ],
        )
        .map_err(storage_error)?;
    if written != 1 {
        return Err(JournalError::MissingWorker);
    }
    Ok(next)
}

impl SqliteRunJournal {
    /// Applies one transition atomically, including the container-intent
    /// check that guards `Unreserve`.
    pub fn transition(
        &self,
        process: &str,
        transition: WorkerTransition<'_>,
    ) -> Result<WorkerRecord, JournalError> {
        let tx = immediate(&self.db)?;
        let next = self::transition(&tx, process, transition)?;
        tx.commit().map_err(storage_error)?;
        Ok(next)
    }

    pub fn snapshots(&self) -> Result<Vec<WorkerRecord>, JournalError> {
        let rows = self
            .db
            .prepare(LIST)
            .map_err(storage_error)?
            .query_map([limit(MAX_WORKERS)], row)
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        bounded(rows, MAX_WORKERS)
    }

    /// Adds a discovered adaptive child within the run's worker bound. A
    /// second insert is an integrity fault.
    pub fn insert_worker(&self, process: &str) -> Result<(), JournalError> {
        let tx = immediate(&self.db)?;
        workers_within_capacity(count(&tx)?.saturating_add(1))?;
        tx.execute(INSERT, [process]).map_err(storage_error)?;
        tx.commit().map_err(storage_error)
    }

    /// Fails every listed pending worker, or none of them.
    pub fn fail_dependents(&self, processes: &[&str]) -> Result<(), JournalError> {
        let tx = immediate(&self.db)?;
        for process in processes {
            transition(&tx, process, WorkerTransition::DependencyFailed)?;
        }
        tx.commit().map_err(storage_error)
    }

    pub fn worker_state(&self, process: &str) -> Result<Option<WorkerState>, JournalError> {
        Ok(read(&self.db, process)?.map(|record| record.state))
    }
}
