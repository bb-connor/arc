//! Reuse of `sqlite_schema` catalog reads while a store connection is held.
//!
//! A held store connection is registered here until its lock is released.
//! Every commit, rollback and mutable borrow of it discards what was read, so a
//! read is reused only inside the transaction that took it. It is reused only
//! while `schema_version` and `data_version`, read inside that transaction,
//! equal the values it was taken under: schema changes on this connection
//! advance `schema_version`, and commits by any other connection advance
//! `data_version`. Everywhere else each read scans the live catalog.

use std::any::Any;
use std::cell::RefCell;
use std::marker::PhantomData;

use rusqlite::Connection;

type Stamp = (i64, i64);

struct Held {
    connection: usize,
    stamp: Option<Stamp>,
    reads: Vec<(&'static str, Box<dyn Any>)>,
}

thread_local! {
    static HELD: RefCell<Vec<Held>> = const { RefCell::new(Vec::new()) };
}

fn address(connection: &Connection) -> usize {
    std::ptr::from_ref(connection).addr()
}

fn discard(connection: usize) {
    with_held(connection, |entry| {
        entry.stamp = None;
        entry.reads.clear();
    });
}

fn with_held<R>(connection: usize, update: impl FnOnce(&mut Held) -> R) -> Option<R> {
    HELD.try_with(|held| {
        held.try_borrow_mut()
            .ok()?
            .iter_mut()
            .find(|entry| entry.connection == connection)
            .map(update)
    })
    .ok()
    .flatten()
}

/// Registration of one connection for the lifetime of its store lock. The
/// connection must stay at one address and be used only on this thread while
/// the registration lives.
pub(crate) struct Hold {
    connection: usize,
    _thread_bound: PhantomData<*const ()>,
}

impl Hold {
    /// Register `connection` and end its reads at every commit and rollback.
    /// Without both hooks nothing is registered and every read scans.
    pub(crate) fn new(connection: &Connection) -> Option<Self> {
        let key = address(connection);
        let hooked = connection
            .commit_hook(Some(move || {
                discard(key);
                false
            }))
            .and_then(|()| connection.rollback_hook(Some(move || discard(key))));
        if hooked.is_err() {
            Self::unhook(connection);
            return None;
        }
        let _ = HELD.try_with(|held| {
            if let Ok(mut held) = held.try_borrow_mut() {
                held.retain(|entry| entry.connection != key);
                held.push(Held {
                    connection: key,
                    stamp: None,
                    reads: Vec::new(),
                });
            }
        });
        Some(Self {
            connection: key,
            _thread_bound: PhantomData,
        })
    }

    /// Forget every read. A mutable borrow can begin a transaction or replace
    /// the connection, so nothing read before it is trusted after it.
    pub(crate) fn discard(&self) {
        discard(self.connection);
    }

    /// Unregister before the connection lock is released.
    pub(crate) fn release(self, connection: &Connection) {
        Self::unhook(connection);
    }

    fn unhook(connection: &Connection) {
        let _ = connection.commit_hook(None::<fn() -> bool>);
        let _ = connection.rollback_hook(None::<fn()>);
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let _ = HELD.try_with(|held| {
            if let Ok(mut held) = held.try_borrow_mut() {
                held.retain(|entry| entry.connection != self.connection);
            }
        });
    }
}

fn stamp(connection: &Connection) -> rusqlite::Result<Stamp> {
    connection
        .prepare_cached(
            "SELECT schema_version, data_version FROM pragma_schema_version, pragma_data_version",
        )?
        .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
}

/// Read one catalog `kind` with `scan`, reusing an earlier successful scan of
/// the same kind under the rules in the module documentation. Failed scans are
/// never retained.
pub(crate) fn read<T: Clone + 'static, E>(
    connection: &Connection,
    kind: &'static str,
    sqlite_error: impl FnOnce(rusqlite::Error) -> E,
    scan: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let key = address(connection);
    if connection.is_autocommit() || with_held(key, |_| ()).is_none() {
        return observed(connection, kind, sqlite_error, scan);
    }
    let current = match stamp(connection) {
        Ok(current) => current,
        Err(error) => return Err(sqlite_error(error)),
    };
    let reused = with_held(key, |entry| {
        if entry.stamp != Some(current) {
            entry.stamp = Some(current);
            entry.reads.clear();
            return None;
        }
        entry
            .reads
            .iter()
            .find(|(read, _)| *read == kind)
            .and_then(|(_, value)| value.downcast_ref::<T>())
            .cloned()
    })
    .flatten();
    if let Some(value) = reused {
        return Ok(value);
    }
    let value = observed(connection, kind, sqlite_error, scan)?;
    with_held(key, |entry| {
        if entry.stamp == Some(current) {
            entry.reads.retain(|(read, _)| *read != kind);
            entry.reads.push((kind, Box::new(value.clone())));
        }
    });
    Ok(value)
}

#[cfg(not(feature = "admission-test-support"))]
fn observed<T, E>(
    _connection: &Connection,
    _kind: &'static str,
    _sqlite_error: impl FnOnce(rusqlite::Error) -> E,
    scan: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    scan()
}

#[cfg(feature = "admission-test-support")]
pub(crate) const SCAN_PROBE: &str = "native_catalog_scan_probe";

#[cfg(feature = "admission-test-support")]
fn observed<T, E>(
    connection: &Connection,
    kind: &'static str,
    sqlite_error: impl FnOnce(rusqlite::Error) -> E,
    scan: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let report = || -> rusqlite::Result<()> {
        let installed: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_function_list WHERE name = ?1)",
            [SCAN_PROBE],
            |row| row.get(0),
        )?;
        if installed {
            connection.query_row(&format!("SELECT {SCAN_PROBE}(?1)"), [kind], |_| Ok(()))?;
        }
        Ok(())
    };
    if let Err(error) = report() {
        return Err(sqlite_error(error));
    }
    scan()
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test and proof fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use std::cell::Cell;

    use rusqlite::Connection;

    use crate::store_connection::StoreConnection;

    fn store(directory: &tempfile::TempDir) -> StoreConnection {
        let connection = Connection::open(directory.path().join("memo.db")).expect("open");
        connection
            .execute_batch("CREATE TABLE memo_probe (value INTEGER NOT NULL);")
            .expect("schema");
        StoreConnection::transaction_only("memo", connection)
    }

    fn tables(connection: &Connection, scans: &Cell<u32>) -> i64 {
        super::read(
            connection,
            "memo_probe",
            |error| error,
            || {
                scans.set(scans.get() + 1);
                connection.query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))
            },
        )
        .expect("catalog read")
    }

    #[test]
    fn a_read_is_reused_only_inside_one_held_transaction() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = store(&directory);
        let scans = Cell::new(0);
        let mut guard = store.lock().expect("lock");
        tables(&guard, &scans);
        tables(&guard, &scans);
        assert_eq!(scans.get(), 2, "autocommit reads always scan");
        let transaction = guard.transaction().expect("begin");
        assert_eq!(tables(&transaction, &scans), 1);
        assert_eq!(tables(&transaction, &scans), 1);
        assert_eq!(scans.get(), 3);
        transaction.commit().expect("commit");
        let transaction = guard.transaction().expect("begin");
        tables(&transaction, &scans);
        assert_eq!(scans.get(), 4, "a mutable borrow discards earlier reads");
    }

    #[test]
    fn a_schema_change_in_the_transaction_forces_a_scan() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = store(&directory);
        let scans = Cell::new(0);
        let mut guard = store.lock().expect("lock");
        let transaction = guard.transaction().expect("begin");
        assert_eq!(tables(&transaction, &scans), 1);
        transaction
            .execute_batch("CREATE TABLE memo_added (value INTEGER);")
            .expect("ddl");
        assert_eq!(tables(&transaction, &scans), 2);
        assert_eq!(scans.get(), 2);
    }

    #[test]
    fn another_connection_commit_forces_a_scan() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = store(&directory);
        let scans = Cell::new(0);
        let guard = store.lock().expect("lock");
        let first = guard.unchecked_transaction().expect("begin");
        tables(&first, &scans);
        first.commit().expect("commit");
        let before = scans.get();
        Connection::open(directory.path().join("memo.db"))
            .expect("other")
            .execute_batch("CREATE TABLE memo_other (value INTEGER);")
            .expect("other ddl");
        let second = guard.unchecked_transaction().expect("begin");
        assert_eq!(tables(&second, &scans), 2);
        assert_eq!(scans.get(), before + 1);
    }

    #[test]
    fn a_rolled_back_schema_change_is_not_reused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = store(&directory);
        let scans = Cell::new(0);
        let names = |connection: &Connection| -> String {
            super::read(
                connection,
                "memo_names",
                |error| error,
                || {
                    scans.set(scans.get() + 1);
                    connection.query_row(
                        "SELECT group_concat(name, ',') FROM (SELECT name FROM sqlite_schema ORDER BY name)",
                        [],
                        |row| row.get(0),
                    )
                },
            )
            .expect("catalog read")
        };
        let guard = store.lock().expect("lock");
        let first = guard.unchecked_transaction().expect("begin");
        first
            .execute_batch("CREATE TABLE memo_first (value INTEGER);")
            .expect("ddl");
        assert_eq!(names(&first), "memo_first,memo_probe");
        first.rollback().expect("rollback");
        // The same schema_version now names a different catalog.
        let second = guard.unchecked_transaction().expect("begin");
        second
            .execute_batch("CREATE TABLE memo_second (value INTEGER);")
            .expect("ddl");
        assert_eq!(names(&second), "memo_probe,memo_second");
        assert_eq!(scans.get(), 2);
    }

    #[test]
    fn a_released_lock_keeps_nothing() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = store(&directory);
        let scans = Cell::new(0);
        for _ in 0..2 {
            let guard = store.lock().expect("lock");
            let transaction = guard.unchecked_transaction().expect("begin");
            tables(&transaction, &scans);
        }
        assert_eq!(scans.get(), 2);
        let connection = Connection::open(directory.path().join("memo.db")).expect("open");
        let transaction = connection.unchecked_transaction().expect("begin");
        tables(&transaction, &scans);
        tables(&transaction, &scans);
        assert_eq!(scans.get(), 4, "an unregistered connection always scans");
    }
}
