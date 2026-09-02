//! Bounded pool of read-only companion connections.
//!
//! Discovery reads run on a companion rather than the authority's write
//! connection so they never queue behind a write transaction. A single
//! companion behind a mutex moved the queue rather than removing it: two
//! concurrent status reads still serialised against each other.
//!
//! The pool hands each reader its own connection, opening up to a bound and
//! reusing them afterwards. Every connection is opened read-only with
//! `query_only`, so a leased connection cannot write whatever a caller does
//! with it, and the bound keeps a burst of readers from opening file
//! descriptors without limit.

use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};

use rusqlite::Connection;

use crate::serving_owner::SqliteServingOwnerError;

/// How many companion connections one authority may hold open.
///
/// The single-operator profile serves discovery from one process, so this
/// bounds descriptors for a read burst rather than sizing a fleet.
const MAX_READ_COMPANIONS: usize = 8;

/// The connections currently idle, and how many exist at all.
struct PoolState {
    idle: Vec<Connection>,
    opened: usize,
}

/// A pool of read-only connections to one authority database.
pub(crate) struct ReadCompanionPool {
    path: PathBuf,
    state: Mutex<PoolState>,
    returned: Condvar,
    capacity: usize,
}

impl ReadCompanionPool {
    /// Open a pool against `path`, proving at construction that a
    /// read-only companion can be opened at all.
    pub(crate) fn open(path: &Path) -> Result<Self, SqliteServingOwnerError> {
        let first = open_read_companion(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(PoolState {
                idle: vec![first],
                opened: 1,
            }),
            returned: Condvar::new(),
            capacity: MAX_READ_COMPANIONS,
        })
    }

    /// Lease a connection, opening one if the pool is below its bound and
    /// waiting for a return if it is not.
    pub(crate) fn lease(&self) -> Result<ReadCompanion<'_>, SqliteServingOwnerError> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        loop {
            if let Some(connection) = state.idle.pop() {
                return Ok(ReadCompanion {
                    pool: self,
                    connection: Some(connection),
                });
            }
            if state.opened < self.capacity {
                // Count the connection before opening it so a failed open
                // cannot leave the pool believing it has capacity it does
                // not, and uncount it if the open fails.
                state.opened += 1;
                drop(state);
                let opened = open_read_companion(&self.path);
                let mut state = self.state.lock().map_err(|_| poisoned())?;
                match opened {
                    Ok(connection) => {
                        return Ok(ReadCompanion {
                            pool: self,
                            connection: Some(connection),
                        })
                    }
                    Err(error) => {
                        state.opened -= 1;
                        self.returned.notify_one();
                        return Err(error);
                    }
                }
            }
            state = self.returned.wait(state).map_err(|_| poisoned())?;
        }
    }

    fn release(&self, connection: Connection) {
        if let Ok(mut state) = self.state.lock() {
            state.idle.push(connection);
            self.returned.notify_one();
        }
        // A poisoned pool drops the connection rather than resurrecting
        // state another thread panicked inside; the next lease reports the
        // poisoning.
    }
}

/// A leased read-only connection, returned to its pool on drop.
pub(crate) struct ReadCompanion<'a> {
    pool: &'a ReadCompanionPool,
    connection: Option<Connection>,
}

impl ReadCompanion<'_> {
    /// The leased connection.
    pub(crate) fn connection(&mut self) -> &mut Connection {
        self.connection
            .as_mut()
            .unwrap_or_else(|| unreachable!("a leased companion always holds its connection"))
    }
}

impl Drop for ReadCompanion<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            self.pool.release(connection);
        }
    }
}

fn poisoned() -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid("sqlite read companion pool is poisoned".to_owned())
}

fn open_read_companion(path: &Path) -> Result<Connection, SqliteServingOwnerError> {
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.execute_batch("PRAGMA query_only = ON; PRAGMA busy_timeout = 5000;")?;
    Ok(connection)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn database(directory: &Path) -> PathBuf {
        let path = directory.join("companion.sqlite3");
        let connection = Connection::open(&path).expect("create database");
        connection
            .execute_batch("CREATE TABLE probe (id INTEGER PRIMARY KEY);")
            .expect("create table");
        path
    }

    #[test]
    fn concurrent_readers_hold_separate_connections() {
        let directory = tempfile::tempdir().expect("tempdir");
        let pool = ReadCompanionPool::open(&database(directory.path())).expect("open pool");
        let mut first = pool.lease().expect("first lease");
        let mut second = pool.lease().expect("second lease");
        // Two live leases at once is the property a single mutex-held
        // companion could not provide.
        for companion in [&mut first, &mut second] {
            companion
                .connection()
                .query_row("SELECT COUNT(*) FROM probe", [], |row| row.get::<_, i64>(0))
                .expect("read through the lease");
        }
    }

    #[test]
    fn a_returned_connection_is_reused_rather_than_reopened() {
        let directory = tempfile::tempdir().expect("tempdir");
        let pool = ReadCompanionPool::open(&database(directory.path())).expect("open pool");
        drop(pool.lease().expect("first lease"));
        drop(pool.lease().expect("second lease"));
        let state = pool.state.lock().expect("pool state");
        assert_eq!(state.opened, 1, "a reused lease must not open a connection");
        assert_eq!(state.idle.len(), 1);
    }

    #[test]
    fn a_reader_waits_for_a_return_once_the_bound_is_reached() {
        let directory = tempfile::tempdir().expect("tempdir");
        let pool = Arc::new(ReadCompanionPool::open(&database(directory.path())).expect("open"));
        let held = (0..MAX_READ_COMPANIONS)
            .map(|_| pool.lease().expect("lease to the bound"))
            .collect::<Vec<_>>();
        assert_eq!(
            pool.state.lock().expect("state").opened,
            MAX_READ_COMPANIONS
        );

        let waiting = Arc::clone(&pool);
        let reader = std::thread::spawn(move || {
            let mut companion = waiting.lease().expect("lease after a return");
            companion
                .connection()
                .query_row("SELECT COUNT(*) FROM probe", [], |row| row.get::<_, i64>(0))
                .expect("read after waiting")
        });
        // The waiting reader cannot proceed until one lease is returned.
        drop(held);
        assert_eq!(reader.join().expect("reader thread"), 0);
    }
}
