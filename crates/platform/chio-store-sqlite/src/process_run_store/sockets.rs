//! Write-ahead ownership of the runner's worker socket endpoint. Slot 1 is
//! the live intent; slots 2 to 9 retain abandoned intents until their
//! directories are positively absent.

use super::{bounded, exactly_one, immediate, limit, storage_error, SqliteRunJournal};
use chio_process::run_journal::{
    next_abandoned_slot, FileIdentity, JournalError, SocketLease, MAX_ABANDONED_SOCKET_INTENTS,
};
use rusqlite::{params, OptionalExtension, Transaction};

const READ_LIVE: &str = "SELECT name,directory_device,directory_inode,socket_device,socket_inode FROM run_socket_leases WHERE singleton=1";
const RECORD_INTENT: &str = "INSERT INTO run_socket_leases(singleton,name) VALUES(1,?1)";
const DIRECTORY_CREATED: &str = "UPDATE run_socket_leases SET directory_device=?1,directory_inode=?2 WHERE singleton=1 AND name=?3";
const SOCKET_BOUND: &str =
    "UPDATE run_socket_leases SET socket_device=?1,socket_inode=?2 WHERE singleton=1 AND name=?3";
const LAST_SLOT: &str = "SELECT COALESCE(MAX(singleton),1) FROM run_socket_leases";
const ABANDON: &str = "UPDATE run_socket_leases SET singleton=?1 WHERE singleton=1";
const FORGET_LIVE: &str = "DELETE FROM run_socket_leases WHERE singleton=1";
pub(super) const LIST_ABANDONED: &str =
    "SELECT singleton,name FROM run_socket_leases WHERE singleton>1 ORDER BY singleton LIMIT ?1";
const FORGET_ABANDONED: &str = "DELETE FROM run_socket_leases WHERE singleton=?1 AND name=?2";
const COUNT_ABANDONED: &str = "SELECT COUNT(*) FROM run_socket_leases WHERE singleton>1";
const ANY: &str = "SELECT EXISTS(SELECT 1 FROM run_socket_leases)";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbandonedSocketIntent {
    slot: u32,
    pub name: String,
}

/// Abandoned intents under the journal write lock. Dropping it without
/// [`Self::commit`] forgets nothing.
pub struct SocketIntentRetirement<'a> {
    tx: Transaction<'a>,
    intents: Vec<AbandonedSocketIntent>,
}

impl SocketIntentRetirement<'_> {
    pub fn intents(&self) -> &[AbandonedSocketIntent] {
        &self.intents
    }

    pub fn forget(&self, intent: &AbandonedSocketIntent) -> Result<(), JournalError> {
        self.tx
            .execute(FORGET_ABANDONED, params![intent.slot, intent.name])
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn commit(self) -> Result<(), JournalError> {
        self.tx.commit().map_err(storage_error)
    }
}

fn identity(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<FileIdentity>> {
    let device: Option<String> = row.get(index)?;
    let inode: Option<String> = row.get(index + 1)?;
    let parse = |value: String| {
        value.parse::<u64>().map_err(|failure| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(failure),
            )
        })
    };
    match (device, inode) {
        (Some(device), Some(inode)) => Ok(Some(FileIdentity {
            device: parse(device)?,
            inode: parse(inode)?,
        })),
        (None, None) => Ok(None),
        _ => Err(rusqlite::Error::InvalidColumnType(
            index,
            "identity".into(),
            rusqlite::types::Type::Null,
        )),
    }
}

impl SqliteRunJournal {
    pub fn socket_lease(&self) -> Result<Option<SocketLease>, JournalError> {
        self.db
            .query_row(READ_LIVE, [], |row| {
                Ok(SocketLease {
                    name: row.get(0)?,
                    directory: identity(row, 1)?,
                    socket: identity(row, 3)?,
                })
            })
            .optional()
            .map_err(storage_error)
    }

    pub fn record_socket_intent(&self, name: &str) -> Result<(), JournalError> {
        self.db
            .execute(RECORD_INTENT, [name])
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn socket_directory_created(
        &self,
        name: &str,
        directory: FileIdentity,
    ) -> Result<(), JournalError> {
        let changed = self
            .db
            .execute(
                DIRECTORY_CREATED,
                params![
                    directory.device.to_string(),
                    directory.inode.to_string(),
                    name
                ],
            )
            .map_err(storage_error)?;
        exactly_one(changed, JournalError::SocketIntent)
    }

    pub fn socket_bound(&self, name: &str, socket: FileIdentity) -> Result<(), JournalError> {
        let changed = self
            .db
            .execute(
                SOCKET_BOUND,
                params![socket.device.to_string(), socket.inode.to_string(), name],
            )
            .map_err(storage_error)?;
        exactly_one(changed, JournalError::SocketIntent)
    }

    /// Moves the live intent into the next history slot, preserving its row.
    pub fn abandon_socket_intent(&self) -> Result<(), JournalError> {
        let tx = immediate(&self.db)?;
        let last = tx
            .query_row(LAST_SLOT, [], |row| row.get(0))
            .map_err(storage_error)?;
        let changed = tx
            .execute(ABANDON, [next_abandoned_slot(last)?])
            .map_err(storage_error)?;
        exactly_one(changed, JournalError::SocketIntent)?;
        tx.commit().map_err(storage_error)
    }

    pub fn forget_socket_intent(&self) -> Result<(), JournalError> {
        self.db.execute(FORGET_LIVE, []).map_err(storage_error)?;
        Ok(())
    }

    pub fn retire_socket_intents(&self) -> Result<SocketIntentRetirement<'_>, JournalError> {
        let tx = immediate(&self.db)?;
        let intents = tx
            .prepare(LIST_ABANDONED)
            .map_err(storage_error)?
            .query_map([limit(MAX_ABANDONED_SOCKET_INTENTS)], |row| {
                Ok(AbandonedSocketIntent {
                    slot: row.get(0)?,
                    name: row.get(1)?,
                })
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        let intents = bounded(intents, MAX_ABANDONED_SOCKET_INTENTS)?;
        Ok(SocketIntentRetirement { tx, intents })
    }

    pub fn abandoned_socket_intents(&self) -> Result<u32, JournalError> {
        self.db
            .query_row(COUNT_ABANDONED, [], |row| row.get(0))
            .map_err(storage_error)
    }

    /// A journal that never reached its schema holds no socket intents.
    pub fn has_socket_intents(&self) -> Result<bool, JournalError> {
        Ok(self.initialized
            && self
                .db
                .query_row(ANY, [], |row| row.get(0))
                .map_err(storage_error)?)
    }
}
