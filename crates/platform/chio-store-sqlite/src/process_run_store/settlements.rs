use super::{bounded_rows, immediate, storage_error, workers, SqliteRunJournal};
use chio_process::run_journal::{settle, ChildSettlement, JournalError, WorkerRecord, MAX_WORKERS};
use rusqlite::params;

pub(super) const LIST: &str =
    "SELECT parent,child,request_id FROM run_child_settlements ORDER BY parent,child LIMIT ?1";
const RECORD: &str =
    "INSERT OR IGNORE INTO run_child_settlements(parent,child,request_id) VALUES(?1,?2,?3)";

impl SqliteRunJournal {
    /// Each child has one parent, so settlements share the worker bound.
    pub fn settlements(&self) -> Result<Vec<ChildSettlement>, JournalError> {
        bounded_rows(&self.db, LIST, MAX_WORKERS, |row| {
            Ok(ChildSettlement {
                parent: row.get(0)?,
                child: row.get(1)?,
                request_id: row.get(2)?,
            })
        })
    }

    /// Reads the awaited children and records the failures that
    /// [`settle`] selects under the settling request. A repeated settlement
    /// keeps the first request identity.
    pub fn settle_children(
        &self,
        parent: &str,
        children: &[String],
        request_id: &str,
    ) -> Result<Vec<WorkerRecord>, JournalError> {
        let tx = immediate(&self.db)?;
        let parent_state = workers::read(&tx, parent)?.map(|record| record.state);
        let outcomes = children
            .iter()
            .map(|child| {
                Ok(workers::read(&tx, child)?
                    .unwrap_or_else(|| WorkerRecord::pending(child.clone())))
            })
            .collect::<Result<Vec<_>, JournalError>>()?;
        for child in settle(parent_state, &outcomes)?.unwrap_or_default() {
            tx.execute(RECORD, params![parent, child, request_id])
                .map_err(storage_error)?;
        }
        tx.commit().map_err(storage_error)?;
        Ok(outcomes)
    }
}
