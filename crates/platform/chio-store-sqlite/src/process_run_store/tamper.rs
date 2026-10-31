//! Typed corruption and observation of a runner journal for cross-crate
//! tests. No function here accepts SQL text.

use std::path::Path;

use chio_process::run_journal::JournalError;
use rusqlite::{params, OpenFlags};

use super::{connection, exactly_one, storage_error};

const FORGET_DIRECTORY: &str =
    "UPDATE run_socket_leases SET directory_device=NULL,directory_inode=NULL WHERE singleton=1";
const FORGET_SOCKET: &str =
    "UPDATE run_socket_leases SET socket_device=NULL,socket_inode=NULL WHERE singleton=1";
const RETAIN: &str = "INSERT INTO run_socket_leases(singleton,name) VALUES(?1,?2)";
const RENAME: &str = "UPDATE run_socket_leases SET name=?1";
const LAUNCHES: &str =
    "SELECT record FROM run_container_launches WHERE process=?1 ORDER BY attempt";

/// A persisted state a crash or a foreign writer can leave in a journal.
#[derive(Clone, Copy, Debug)]
pub enum JournalTamper<'a> {
    /// The live socket intent without its committed directory identity.
    LiveDirectoryUncommitted,
    /// The live socket intent without its committed socket identity.
    LiveSocketUncommitted,
    /// An abandoned socket intent retained at `slot`.
    AbandonedSocketIntent { slot: u32, name: &'a str },
    /// The journal's only socket intent under another name.
    SocketIntentRenamed(&'a str),
}

/// Applies one change, which must touch exactly one row.
pub fn tamper(path: &Path, change: JournalTamper<'_>) -> Result<(), JournalError> {
    let db = connection(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let changed = match change {
        JournalTamper::LiveDirectoryUncommitted => db.execute(FORGET_DIRECTORY, []),
        JournalTamper::LiveSocketUncommitted => db.execute(FORGET_SOCKET, []),
        JournalTamper::AbandonedSocketIntent { slot, name } => {
            db.execute(RETAIN, params![slot, name])
        }
        JournalTamper::SocketIntentRenamed(name) => db.execute(RENAME, [name]),
    }
    .map_err(storage_error)?;
    exactly_one(changed, JournalError::Integrity)
}

/// The stored JSON of every signed launch record of `process`, in attempt
/// order, for the test to decode and verify.
pub fn launch_records(path: &Path, process: &str) -> Result<Vec<String>, JournalError> {
    connection(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?
        .prepare(LAUNCHES)
        .map_err(storage_error)?
        .query_map([process], |row| row.get(0))
        .map_err(storage_error)?
        .collect::<Result<_, _>>()
        .map_err(storage_error)
}
