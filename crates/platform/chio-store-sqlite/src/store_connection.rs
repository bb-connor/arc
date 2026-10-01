//! Lock-poison recovery for the stores that guard one SQLite connection with a
//! `std::sync::Mutex`.
//!
//! A panic inside a store's critical section poisons the mutex. Recovering the
//! mutex proves nothing about the connection behind it: `rusqlite::Transaction`
//! attempts a rollback when it is dropped and discards the result, so the
//! recovered connection can still be inside the interrupted transaction with its
//! uncommitted writes readable on that connection. And a commit may have landed
//! while the artifact that is written after every commit (the serving owner's
//! rollback anchor) has not, in which case the database is ahead of the record
//! that vouches for it.
//!
//! [`StoreConnection`] therefore decides recovery by the durable phase the panic
//! left the connection in, and verifies rather than assumes: it rolls back an
//! open transaction explicitly, checks that the rollback took, then runs the
//! consistency check the connection was built with. Where any step fails, the
//! connection is fenced with a named reason and stays fenced until the store is
//! reopened. Fail closed, with a reason.

use std::error::Error;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use rusqlite::Connection;

/// Proves that the artifact paired with this connection's commits agrees with
/// the database head. It runs on a recovered connection before the connection
/// serves again.
pub(crate) type ConsistencyCheck =
    dyn Fn(&Connection) -> Result<(), Box<dyn Error + Send + Sync>> + Send + Sync;

/// A store's single SQLite connection, with the recovery contract it was
/// classified under.
pub(crate) struct StoreConnection {
    store: &'static str,
    connection: Mutex<Connection>,
    consistency: Option<Box<ConsistencyCheck>>,
    fence: OnceLock<ConnectionFenced>,
}

/// The connection could not be returned to a verified state after a panic and
/// refuses every operation until the store is reopened.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{store} connection is fenced until it is reopened: {reason}")]
pub(crate) struct ConnectionFenced {
    pub(crate) store: &'static str,
    #[source]
    pub(crate) reason: FenceReason,
}

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum FenceReason {
    #[error("rollback of the transaction the panic interrupted failed: {0}")]
    RollbackFailed(#[source] Arc<rusqlite::Error>),
    #[error("the connection stayed inside a transaction after rollback")]
    TransactionStillOpen,
    #[error("consistency with the database head could not be verified: {0}")]
    ConsistencyCheckFailed(#[source] Arc<dyn Error + Send + Sync>),
}

impl StoreConnection {
    /// A connection whose commits pair with nothing outside the database and
    /// whose writes all run inside RAII transactions. After a verified rollback
    /// the last commit is the only state there is, so the connection serves
    /// again.
    pub(crate) fn transaction_only(store: &'static str, connection: Connection) -> Self {
        Self::new(store, connection, None)
    }

    /// A connection whose every commit is followed by a write to an artifact
    /// outside the database. `verify` must prove that artifact agrees with the
    /// database head; a recovered connection serves only once it does, because
    /// a panic between the commit and the artifact write leaves the database
    /// ahead of the record that vouches for it.
    pub(crate) fn anchored(
        store: &'static str,
        connection: Connection,
        verify: impl Fn(&Connection) -> Result<(), Box<dyn Error + Send + Sync>> + Send + Sync + 'static,
    ) -> Self {
        Self::new(store, connection, Some(Box::new(verify)))
    }

    fn new(
        store: &'static str,
        connection: Connection,
        consistency: Option<Box<ConsistencyCheck>>,
    ) -> Self {
        Self {
            store,
            connection: Mutex::new(connection),
            consistency,
            fence: OnceLock::new(),
        }
    }

    /// Acquire the connection. A lock another thread poisoned is recovered
    /// only after the connection's state is re-established and verified; a
    /// fenced connection is refused without being touched.
    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, Connection>, ConnectionFenced> {
        if let Some(fenced) = self.fence.get() {
            return Err(fenced.clone());
        }
        let guard = match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => self.recover(poisoned.into_inner())?,
        };
        match self.fence.get() {
            Some(fenced) => Err(fenced.clone()),
            None => Ok(guard),
        }
    }

    /// The reason this connection refuses to serve, once it does.
    #[cfg(test)]
    pub(crate) fn fence(&self) -> Option<&ConnectionFenced> {
        self.fence.get()
    }

    /// Whether commits on this connection are paired with an external artifact.
    pub(crate) fn is_anchored(&self) -> bool {
        self.consistency.is_some()
    }

    /// The raw non-blocking acquire, for test doubles that assert a store is not
    /// holding its connection while it calls back into them.
    #[cfg(test)]
    pub(crate) fn try_lock(
        &self,
    ) -> Result<MutexGuard<'_, Connection>, std::sync::TryLockError<MutexGuard<'_, Connection>>>
    {
        self.connection.try_lock()
    }

    fn recover<'a>(
        &self,
        guard: MutexGuard<'a, Connection>,
    ) -> Result<MutexGuard<'a, Connection>, ConnectionFenced> {
        match self.reestablish(&guard) {
            Ok(()) => {
                self.connection.clear_poison();
                tracing::error!(
                    store = self.store,
                    outcome = "recovered",
                    "a panic poisoned the sqlite connection lock; the connection was verified and returned to service"
                );
                Ok(guard)
            }
            Err(reason) => {
                let fenced = self
                    .fence
                    .get_or_init(|| ConnectionFenced {
                        store: self.store,
                        reason,
                    })
                    .clone();
                tracing::error!(
                    store = self.store,
                    outcome = "fenced",
                    reason = %fenced.reason,
                    "a panic poisoned the sqlite connection lock and the connection's state could not be re-established; it is fenced until the store is reopened"
                );
                Err(fenced)
            }
        }
    }

    fn reestablish(&self, connection: &Connection) -> Result<(), FenceReason> {
        if !connection.is_autocommit() {
            connection
                .execute_batch("ROLLBACK")
                .map_err(|error| FenceReason::RollbackFailed(Arc::new(error)))?;
            if !connection.is_autocommit() {
                return Err(FenceReason::TransactionStillOpen);
            }
        }
        if let Some(verify) = &self.consistency {
            verify(connection)
                .map_err(|error| FenceReason::ConsistencyCheckFailed(Arc::from(error)))?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for StoreConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreConnection")
            .field("store", &self.store)
            .field("anchored", &self.is_anchored())
            .field("fence", &self.fence.get())
            .finish_non_exhaustive()
    }
}

/// Drivers that leave a connection in each durable phase a panic can leave it
/// in, and a subscriber that records what recovery decided.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use rusqlite::{Connection, Transaction, TransactionBehavior};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    use super::StoreConnection;

    /// Run `critical_section` on another thread while holding the connection
    /// lock. The closure must panic, as a fault inside a store's critical
    /// section would, so the lock is left poisoned.
    pub(crate) fn panic_while_holding(
        connection: &StoreConnection,
        critical_section: impl FnOnce(&mut Connection) + Send,
    ) {
        let returned = AtomicBool::new(false);
        let outcome = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mut guard = connection
                        .connection
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    critical_section(&mut guard);
                    returned.store(true, Ordering::SeqCst);
                })
                .join()
        });
        assert!(
            !returned.load(Ordering::SeqCst),
            "the injected critical section must panic while holding the lock"
        );
        assert!(outcome.is_err());
        assert!(connection.connection.is_poisoned());
    }

    /// Panic inside an open transaction after `write`. The transaction's drop
    /// rolls back during unwinding.
    pub(crate) fn panic_before_commit(
        connection: &StoreConnection,
        write: impl FnOnce(&Transaction<'_>) + Send,
    ) {
        panic_while_holding(connection, |connection| {
            let transaction = immediate(connection);
            write(&transaction);
            panic!("injected panic before commit");
        });
    }

    /// Panic inside an open transaction after `write`, with `ROLLBACK` denied
    /// on this connection, so neither the transaction's drop nor the recovery
    /// path can end the transaction.
    pub(crate) fn panic_with_rollback_denied(
        connection: &StoreConnection,
        write: impl FnOnce(&Transaction<'_>) + Send,
    ) {
        panic_while_holding(connection, |connection| {
            deny_rollback(connection);
            let transaction = immediate(connection);
            write(&transaction);
            panic!("injected panic before commit, with rollback denied");
        });
    }

    /// Commit `write`, run `after_commit` on the connection, then panic.
    /// With a no-op `after_commit` this is the phase between a commit and the
    /// artifact write that follows it; with the artifact write it is the phase
    /// between that write and the caller's acknowledgement.
    pub(crate) fn panic_after_commit(
        connection: &StoreConnection,
        write: impl FnOnce(&Transaction<'_>) + Send,
        after_commit: impl FnOnce(&Connection) + Send,
    ) {
        panic_while_holding(connection, |connection| {
            let transaction = immediate(connection);
            write(&transaction);
            transaction.commit().expect("commit the injected write");
            after_commit(connection);
            panic!("injected panic after commit");
        });
    }

    fn immediate(connection: &mut Connection) -> Transaction<'_> {
        connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin the injected transaction")
    }

    /// SQLite's authorizer refuses `ROLLBACK` for the rest of this connection's
    /// life. It is a fault-injection mechanism, not an exposed endpoint.
    fn deny_rollback(connection: &Connection) {
        connection
            .authorizer(Some(|context: AuthContext<'_>| {
                if matches!(
                    context.action,
                    AuthAction::Transaction {
                        operation: TransactionOperation::Rollback
                    }
                ) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }))
            .expect("install the rollback-denying authorizer");
    }

    /// The `user_version` header field: transactional, unread by these stores,
    /// and visible to any connection once committed.
    pub(crate) const PROBE_USER_VERSION: i64 = 7;

    pub(crate) fn write_probe_user_version(transaction: &Transaction<'_>) {
        transaction
            .pragma_update(None, "user_version", PROBE_USER_VERSION)
            .expect("write the probe user_version");
    }

    pub(crate) fn user_version(connection: &Connection) -> i64 {
        connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read user_version")
    }

    /// What recovery decided for one connection, as it was logged.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct RecoveryEvent {
        pub(crate) store: String,
        pub(crate) outcome: String,
    }

    pub(crate) fn recovered(store: &str) -> RecoveryEvent {
        RecoveryEvent {
            store: store.to_owned(),
            outcome: "recovered".to_owned(),
        }
    }

    pub(crate) fn fenced(store: &str) -> RecoveryEvent {
        RecoveryEvent {
            store: store.to_owned(),
            outcome: "fenced".to_owned(),
        }
    }

    /// Run `operation` with a subscriber that records every recovery decision
    /// logged on this thread.
    pub(crate) fn recovery_events_during<R>(
        operation: impl FnOnce() -> R,
    ) -> (R, Vec<RecoveryEvent>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let result = tracing::subscriber::with_default(RecoveryLog(events.clone()), operation);
        let events = events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        (result, events)
    }

    struct RecoveryLog(Arc<Mutex<Vec<RecoveryEvent>>>);

    impl Subscriber for RecoveryLog {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            metadata.fields().field("outcome").is_some()
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = RecoveryFields::default();
            event.record(&mut fields);
            if let (Some(store), Some(outcome)) = (fields.store, fields.outcome) {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(RecoveryEvent { store, outcome });
            }
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    #[derive(Default)]
    struct RecoveryFields {
        store: Option<String>,
        outcome: Option<String>,
    }

    impl Visit for RecoveryFields {
        fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}

        fn record_str(&mut self, field: &Field, value: &str) {
            match field.name() {
                "store" => self.store = Some(value.to_owned()),
                "outcome" => self.outcome = Some(value.to_owned()),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rusqlite::Connection;

    use super::test_support::{
        fenced, panic_after_commit, panic_before_commit, panic_with_rollback_denied, recovered,
        recovery_events_during, user_version, write_probe_user_version, PROBE_USER_VERSION,
    };
    use super::{FenceReason, StoreConnection};

    fn probe_store(directory: &tempfile::TempDir) -> StoreConnection {
        let connection = Connection::open(directory.path().join("probe.db")).expect("open");
        connection
            .execute_batch(
                "CREATE TABLE probe (value INTEGER NOT NULL); INSERT INTO probe VALUES (1);",
            )
            .expect("seed");
        StoreConnection::transaction_only("probe", connection)
    }

    fn read_value(connection: &Connection) -> i64 {
        connection
            .query_row("SELECT value FROM probe", [], |row| row.get(0))
            .expect("read the probe value")
    }

    fn write_value(transaction: &rusqlite::Transaction<'_>) {
        transaction
            .execute("UPDATE probe SET value = 2", [])
            .expect("update the probe value");
    }

    fn fresh_reader(directory: &tempfile::TempDir) -> Connection {
        Connection::open(directory.path().join("probe.db")).expect("open a second connection")
    }

    #[test]
    fn a_healthy_lock_is_handed_out_without_recovery() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = probe_store(&directory);
        let (value, events) = recovery_events_during(|| read_value(&store.lock().expect("lock")));
        assert_eq!(value, 1);
        assert!(events.is_empty());
        assert!(store.fence().is_none());
    }

    #[test]
    fn a_panic_before_commit_is_rolled_back_and_the_lock_recovers_once() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = probe_store(&directory);
        panic_before_commit(&store, write_value);

        let (value, events) = recovery_events_during(|| {
            let guard = store.lock().expect("recovered lock");
            assert!(guard.is_autocommit());
            read_value(&guard)
        });
        assert_eq!(value, 1, "the interrupted update must have rolled back");
        assert_eq!(events, [recovered("probe")]);
        assert!(
            !store.connection.is_poisoned(),
            "a verified recovery clears the poison"
        );

        let (_, later) = recovery_events_during(|| drop(store.lock().expect("clean lock")));
        assert!(
            later.is_empty(),
            "recovery is logged once, not on every later lock"
        );
    }

    #[test]
    fn a_denied_rollback_fences_the_connection_and_hides_the_uncommitted_write() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = probe_store(&directory);
        panic_with_rollback_denied(&store, write_value);

        let (result, events) =
            recovery_events_during(|| store.lock().map(|guard| read_value(&guard)));
        let error = result.expect_err("the connection must be fenced");
        assert_eq!(error.store, "probe");
        assert!(
            matches!(error.reason, FenceReason::RollbackFailed(_)),
            "{error:?}"
        );
        assert_eq!(events, [fenced("probe")]);
        assert_eq!(store.fence().map(|fence| fence.store), Some("probe"));
        assert_eq!(
            read_value(&fresh_reader(&directory)),
            1,
            "the uncommitted update is never visible outside the interrupted transaction"
        );

        let (result, later) = recovery_events_during(|| store.lock().map(|_| ()));
        assert!(matches!(result, Err(fence) if fence.to_string() == error.to_string()));
        assert!(
            later.is_empty(),
            "a fenced connection is refused without another recovery attempt"
        );
        assert!(
            store.connection.is_poisoned(),
            "a fenced connection stays poisoned"
        );
    }

    #[test]
    fn a_panic_after_commit_recovers_with_the_committed_write_visible() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = probe_store(&directory);
        panic_after_commit(&store, write_value, |_| {});

        let (value, events) =
            recovery_events_during(|| read_value(&store.lock().expect("recovered lock")));
        assert_eq!(value, 2, "the committed update is durable");
        assert_eq!(events, [recovered("probe")]);
    }

    #[test]
    fn an_anchored_connection_runs_its_consistency_check_before_serving() {
        let directory = tempfile::tempdir().expect("tempdir");
        let connection = Connection::open(directory.path().join("probe.db")).expect("open");
        connection
            .execute_batch(
                "CREATE TABLE probe (value INTEGER NOT NULL); INSERT INTO probe VALUES (1);",
            )
            .expect("seed");
        let checks = Arc::new(AtomicUsize::new(0));
        let store = StoreConnection::anchored("anchored-probe", connection, {
            let checks = checks.clone();
            move |connection| {
                checks.fetch_add(1, Ordering::SeqCst);
                if read_value(connection) == 1 {
                    Ok(())
                } else {
                    Err("the anchor records value 1 while the database head holds another".into())
                }
            }
        });
        assert!(store.is_anchored());

        panic_before_commit(&store, write_value);
        let (result, events) =
            recovery_events_during(|| store.lock().map(|guard| read_value(&guard)));
        assert_eq!(
            result.expect("a rolled-back connection agrees with its anchor"),
            1
        );
        assert_eq!(events, [recovered("anchored-probe")]);
        assert_eq!(
            checks.load(Ordering::SeqCst),
            1,
            "the check runs on recovery, not on a healthy lock"
        );

        panic_after_commit(&store, write_value, |_| {});
        let (result, events) = recovery_events_during(|| store.lock().map(|_| ()));
        let error = result.expect_err("a database ahead of its anchor must be fenced");
        assert!(
            matches!(error.reason, FenceReason::ConsistencyCheckFailed(_)),
            "{error:?}"
        );
        assert_eq!(events, [fenced("anchored-probe")]);
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn the_user_version_probe_is_transactional() {
        let directory = tempfile::tempdir().expect("tempdir");
        let store = probe_store(&directory);
        panic_before_commit(&store, write_probe_user_version);
        assert_eq!(user_version(&store.lock().expect("recovered lock")), 0);
        panic_after_commit(&store, write_probe_user_version, |_| {});
        assert_eq!(user_version(&fresh_reader(&directory)), PROBE_USER_VERSION);
    }
}
