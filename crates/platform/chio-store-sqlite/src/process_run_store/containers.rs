use super::{
    bounded_rows, exactly_one, immediate, storage_error, workers, SqliteContainerJournal,
    SqliteRunJournal,
};
use chio_process::run_journal::{
    container_intent_admissible, ContainerIntent, JournalError, MAX_WORKERS,
};
use chio_process::SignedContainerLaunchRecord;
use rusqlite::params;

const RESERVE: &str =
    "INSERT INTO run_containers(owner,process,attempt,engine) VALUES(?1,?2,?3,?4)";
pub(super) const LIST: &str =
    "SELECT owner,engine,container_id,create_rejected FROM run_containers ORDER BY owner LIMIT ?1";
const COUNT: &str = "SELECT COUNT(*) FROM run_containers";
const ANY: &str = "SELECT EXISTS(SELECT 1 FROM run_containers)";
const REMOVE: &str = "DELETE FROM run_containers WHERE owner=?1";
const REJECT: &str =
    "UPDATE run_containers SET create_rejected=1 WHERE owner=?1 AND container_id IS NULL";
const CREATED: &str =
    "UPDATE run_containers SET container_id=?1 WHERE owner=?2 AND container_id IS NULL";
const RECORD_LAUNCH: &str =
    "INSERT INTO run_container_launches(process,attempt,record) VALUES(?1,?2,?3)";

impl SqliteRunJournal {
    /// Records a container intent for the worker's running attempt.
    pub fn reserve_container(
        &self,
        process: &str,
        attempt: u32,
        owner: &str,
        engine: &str,
    ) -> Result<(), JournalError> {
        let tx = immediate(&self.db)?;
        workers::read(&tx, process)?
            .ok_or(JournalError::ContainerIntent)?
            .bind_container(attempt)?;
        container_intent_admissible(
            tx.query_row(COUNT, [], |row| row.get(0))
                .map_err(storage_error)?,
        )?;
        tx.execute(RESERVE, params![owner, process, attempt, engine])
            .map_err(|error| {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    JournalError::ContainerIntent
                } else {
                    storage_error(error)
                }
            })?;
        tx.commit().map_err(storage_error)
    }

    pub fn containers(&self) -> Result<Vec<ContainerIntent>, JournalError> {
        bounded_rows(&self.db, LIST, MAX_WORKERS, |row| {
            Ok(ContainerIntent {
                owner: row.get(0)?,
                engine: row.get(1)?,
                id: row.get(2)?,
                create_rejected: row.get(3)?,
            })
        })
    }

    /// A journal that never reached its schema holds no container intents.
    pub fn has_container_intents(&self) -> Result<bool, JournalError> {
        Ok(self.initialized
            && self
                .db
                .query_row(ANY, [], |row| row.get(0))
                .map_err(storage_error)?)
    }

    pub fn container_removed(&self, owner: &str) -> Result<(), JournalError> {
        remove(&self.db, owner)
    }
}

impl SqliteContainerJournal {
    pub fn create_rejected(&self, owner: &str) -> Result<(), JournalError> {
        exactly_one(
            self.db.execute(REJECT, [owner]).map_err(storage_error)?,
            JournalError::ContainerIntent,
        )
    }

    pub fn created(&self, owner: &str, id: &str) -> Result<(), JournalError> {
        exactly_one(
            self.db
                .execute(CREATED, params![id, owner])
                .map_err(storage_error)?,
            JournalError::ContainerIntent,
        )
    }

    /// At most one signed launch record exists per worker attempt.
    pub fn launch_recorded(
        &self,
        signed: &SignedContainerLaunchRecord,
    ) -> Result<(), JournalError> {
        let record = serde_json::to_string(signed).map_err(|_| JournalError::Integrity)?;
        self.db
            .execute(
                RECORD_LAUNCH,
                params![signed.record.process_id, signed.record.attempt, record],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn removed(&self, owner: &str) -> Result<(), JournalError> {
        remove(&self.db, owner)
    }
}

/// Removal is idempotent: a restart may confirm a removal the previous host
/// already recorded.
fn remove(db: &rusqlite::Connection, owner: &str) -> Result<(), JournalError> {
    db.execute(REMOVE, [owner]).map_err(storage_error)?;
    Ok(())
}
