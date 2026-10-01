//! Recovery of the authority connection after a panic inside a critical
//! section. Fifteen stores share this one connection and its serving owner,
//! so the durable phase a panic leaves it in is a property of the connection,
//! not of the store whose section panicked: each phase is induced here through
//! one real chain-advancing write (a revocation, the smallest one), and every
//! sharing store asserts its own outcome against these drivers.

use std::path::PathBuf;

use chio_kernel::{RevocationStore, RevocationStoreError};
use rusqlite::{params, Connection};
use tempfile::TempDir;

use super::tests::{create_lock_root, secure_directory};
use super::{SqliteAuthorityStore, SqliteServingOwnerError};
use crate::revocation_store::write_probe_revocation;
use crate::store_connection::test_support::{self, fenced, recovered, recovery_events_during};
use crate::store_connection::FenceReason;

pub(crate) const PROBE_CAPABILITY: &str = "capability-under-recovery";

pub(crate) struct ProvisionedAuthority {
    _temp: TempDir,
    pub(crate) database: PathBuf,
    pub(crate) lock_root: PathBuf,
    pub(crate) authority: SqliteAuthorityStore,
}

impl ProvisionedAuthority {
    pub(crate) fn open() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        secure_directory(temp.path());
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        create_lock_root(&lock_root);
        SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
        Self {
            _temp: temp,
            database,
            lock_root,
            authority,
        }
    }

    /// Release the serving lease and open a fresh serving owner, the only path
    /// that reconciles the rollback anchor with the database. Every store
    /// opened from the previous authority must have been dropped first.
    pub(crate) fn reopen(self) -> Self {
        let Self {
            _temp,
            database,
            lock_root,
            authority,
        } = self;
        drop(authority);
        let authority =
            SqliteAuthorityStore::open_serving(&database, &lock_root).expect("reopen authority");
        Self {
            _temp,
            database,
            lock_root,
            authority,
        }
    }

    /// Whether the probe revocation is durable, read through a connection that
    /// took no part in the interrupted transaction.
    pub(crate) fn probe_revocation_is_durable(&self) -> bool {
        Connection::open(&self.database)
            .expect("open an independent reader")
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
                params![PROBE_CAPABILITY],
                |row| row.get(0),
            )
            .expect("read the probe revocation")
    }

    pub(crate) fn anchor_generation(&self) -> u64 {
        self.authority
            .anchor_generation()
            .expect("read the anchor generation")
    }
}

/// The panic lands inside the transaction, before its commit.
pub(crate) fn authority_panics_before_commit(authority: &SqliteAuthorityStore) {
    let revocations = authority.revocation_store();
    test_support::panic_before_commit(&authority.connection, |transaction| {
        write_probe_revocation(&revocations, transaction)
    });
}

/// The panic lands inside the transaction and the rollback that should end it
/// is refused.
pub(crate) fn authority_panics_with_rollback_denied(authority: &SqliteAuthorityStore) {
    let revocations = authority.revocation_store();
    test_support::panic_with_rollback_denied(&authority.connection, |transaction| {
        write_probe_revocation(&revocations, transaction)
    });
}

/// The commit landed and the panic pre-empted the anchor sync that follows
/// every commit, leaving the database one commit ahead of its anchor.
pub(crate) fn authority_panics_after_commit_before_anchor(authority: &SqliteAuthorityStore) {
    let revocations = authority.revocation_store();
    test_support::panic_after_commit(
        &authority.connection,
        |transaction| write_probe_revocation(&revocations, transaction),
        |_| {},
    );
}

/// Commit and anchor sync both landed; the panic pre-empted the caller's
/// acknowledgement.
pub(crate) fn authority_panics_after_anchor(authority: &SqliteAuthorityStore) {
    let revocations = authority.revocation_store();
    test_support::panic_after_commit(
        &authority.connection,
        |transaction| write_probe_revocation(&revocations, transaction),
        |connection| {
            authority
                .owner
                .sync_authority_anchor(connection)
                .expect("sync the anchor after the probe commit");
        },
    );
}

#[test]
fn a_panic_before_commit_rolls_back_and_the_authority_serves() {
    let fixture = ProvisionedAuthority::open();
    let generation = fixture.anchor_generation();
    authority_panics_before_commit(&fixture.authority);

    let (result, events) =
        recovery_events_during(|| fixture.authority.verify_database_path(&fixture.database));
    result.expect("the authority serves after a verified rollback");
    assert_eq!(events, [recovered("authority")]);
    assert!(!fixture.probe_revocation_is_durable());
    assert!(!fixture
        .authority
        .revocation_store()
        .is_revoked(PROBE_CAPABILITY)
        .expect("read the revocation"));
    assert_eq!(fixture.anchor_generation(), generation);
}

#[test]
fn a_denied_rollback_fences_the_authority_connection_for_every_store() {
    let fixture = ProvisionedAuthority::open();
    authority_panics_with_rollback_denied(&fixture.authority);

    let (result, events) =
        recovery_events_during(|| fixture.authority.verify_database_path(&fixture.database));
    let fence = fixture
        .authority
        .connection
        .fence()
        .expect("the connection is fenced");
    assert!(
        matches!(fence.reason, FenceReason::RollbackFailed(_)),
        "{fence:?}"
    );
    assert!(
        matches!(result, Err(SqliteServingOwnerError::Invalid(ref detail)) if *detail == fence.to_string()),
        "{result:?}"
    );
    assert_eq!(events, [fenced("authority")]);
    assert!(
        !fixture.probe_revocation_is_durable(),
        "the uncommitted revocation is never read"
    );
    assert!(
        matches!(
            fixture.authority.revocation_store().is_revoked(PROBE_CAPABILITY),
            Err(RevocationStoreError::Sync(ref detail)) if *detail == fence.to_string()
        ),
        "a store sharing the connection is refused with the same fence"
    );
}

#[test]
fn a_panic_between_commit_and_anchor_sync_fences_until_a_reopen_reconciles() {
    let fixture = ProvisionedAuthority::open();
    let generation = fixture.anchor_generation();
    authority_panics_after_commit_before_anchor(&fixture.authority);

    let (result, events) =
        recovery_events_during(|| fixture.authority.verify_database_path(&fixture.database));
    let fence = fixture
        .authority
        .connection
        .fence()
        .expect("the connection is fenced");
    assert!(
        matches!(fence.reason, FenceReason::ConsistencyCheckFailed(_)),
        "{fence:?}"
    );
    assert!(
        matches!(result, Err(SqliteServingOwnerError::Invalid(ref detail)) if *detail == fence.to_string()),
        "{result:?}"
    );
    assert_eq!(events, [fenced("authority")]);
    assert!(
        fixture.probe_revocation_is_durable(),
        "the commit landed before the panic"
    );
    assert_eq!(
        fixture.anchor_generation(),
        generation,
        "the anchor was never advanced past the commit"
    );

    let reopened = fixture.reopen();
    reopened
        .authority
        .verify_database_path(&reopened.database)
        .expect("reopening reconciles the anchor with the database head");
    assert!(
        reopened.anchor_generation() > generation,
        "the reopen wrote the anchor forward over the stranded commit"
    );
    assert!(reopened
        .authority
        .revocation_store()
        .is_revoked(PROBE_CAPABILITY)
        .expect("read the revocation"));
}

#[test]
fn a_panic_after_anchor_sync_recovers_with_the_commit_visible() {
    let fixture = ProvisionedAuthority::open();
    let generation = fixture.anchor_generation();
    authority_panics_after_anchor(&fixture.authority);

    let (result, events) =
        recovery_events_during(|| fixture.authority.verify_database_path(&fixture.database));
    result.expect("the authority serves once the anchor matches the database");
    assert_eq!(events, [recovered("authority")]);
    assert!(fixture.probe_revocation_is_durable());
    assert!(fixture
        .authority
        .revocation_store()
        .is_revoked(PROBE_CAPABILITY)
        .expect("read the revocation"));
    assert_eq!(fixture.anchor_generation(), generation + 1);
}
