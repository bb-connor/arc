use std::cell::Cell;
use std::sync::Arc;

use chio_federation::issuance_requests::conformance;
use chio_test_support::clock::ClockScope;
use chio_test_support::prelude::*;

use super::*;

struct Fixture {
    dir: tempfile::TempDir,
    opened: Cell<usize>,
    _clock: ClockScope,
}

impl Fixture {
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(format!("{name}.sqlite3"))
    }

    fn fresh(&self, pending_cap: usize) -> SqliteIssuanceRequestStore {
        let n = self.opened.get();
        self.opened.set(n + 1);
        SqliteIssuanceRequestStore::open(self.path(&format!("issuance-{n}")))
            .test_unwrap()
            .with_pending_cap(pending_cap)
    }
}

fn fixture() -> Fixture {
    let clock = chio_test_support::clock::scope_unix_secs(1_000);
    Fixture {
        dir: tempfile::tempdir().test_unwrap(),
        opened: Cell::new(0),
        _clock: clock,
    }
}

fn record(id: &str, expires_at: u64) -> IssuanceRequestRecord {
    IssuanceRequestRecord {
        challenge_id: id.into(),
        subject: "did:chio:abc".into(),
        verifier: "https://b.example".into(),
        presentation_json: "{\"presentation\":true}".into(),
        challenge_json: "{\"challenge\":true}".into(),
        submitted_at: 100,
        expires_at,
        status: IssuanceRequestStatus::Pending,
        decided_at: None,
        capability_id: None,
        decision_reason: None,
    }
}

fn all(store: &SqliteIssuanceRequestStore) -> Result<IssuanceRequestPage, IssuanceStoreError> {
    store.list(
        IssuanceListQuery {
            status: None,
            after: None,
            limit: 10,
        },
        150,
    )
}

#[test]
fn sqlite_store_conforms() {
    let fixture = fixture();
    conformance::all(&|pending_cap| {
        Arc::new(fixture.fresh(pending_cap)) as Arc<dyn IssuanceRequestRepository>
    });
}

#[test]
fn requests_survive_reopen() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    store.submit(&record("kept", 1_000), 100).test_unwrap();
    drop(store);
    let reopened = SqliteIssuanceRequestStore::open(fixture.path("issuance-0")).test_unwrap();
    assert_eq!(
        reopened.get("kept").test_unwrap().map(|kept| kept.status),
        Some(IssuanceRequestStatus::Pending)
    );
}

#[test]
fn a_tampered_status_is_an_integrity_failure() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    store.submit(&record("c9", 1_000), 100).test_unwrap();
    let raw = Connection::open(fixture.path("issuance-0")).test_unwrap();
    raw.pragma_update(None, "ignore_check_constraints", true)
        .test_unwrap();
    raw.execute(
        "UPDATE federation_issuance_requests SET status = 'expired' WHERE challenge_id = 'c9'",
        [],
    )
    .test_unwrap();
    drop(raw);
    assert_eq!(store.get("c9"), Err(IssuanceStoreError::Integrity));
    assert_eq!(all(&store), Err(IssuanceStoreError::Integrity));
}

#[test]
fn a_held_write_lock_is_busy_and_writes_nothing() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    let mut raw = Connection::open(fixture.path("issuance-0")).test_unwrap();
    let holder = raw
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .test_unwrap();
    assert_eq!(
        store.submit(&record("blocked", 1_000), 100),
        Err(IssuanceStoreError::Busy)
    );
    drop(holder);
    assert_eq!(store.get("blocked"), Ok(None));
}

#[test]
fn an_out_of_range_timestamp_is_refused_without_a_row() {
    let fixture = fixture();
    let store = fixture.fresh(MAX_PENDING_ISSUANCE_REQUESTS);
    assert_eq!(
        store.submit(&record("far", u64::MAX), 100),
        Err(IssuanceStoreError::InvalidTimestamp)
    );
    assert_eq!(store.get("far"), Ok(None));
    assert_eq!(
        store.claim("far", u64::MAX),
        Err(IssuanceStoreError::InvalidTimestamp)
    );
}

#[test]
fn an_in_memory_path_is_refused() {
    assert!(matches!(
        SqliteIssuanceRequestStore::open(":memory:"),
        Err(IssuanceRequestStoreOpenError::InvalidPath)
    ));
}
